pulseaudio-mixer-cli: interactive ncurses ui to control volume of pulse streams
--------------------

Kinda like alsamixer, but focused not on sink volume levels (which can actually
be controlled via alsamixer, with alsa-pulse plugin), but rather on volume of
individual streams, so you can turn down the music to hear the stuff from game,
mumble, skype or flash.

Control over individual process streams seem to be almost unique to pulseaudio,
pity there aren't much tools built to harness it. This one tries to fill the gap
a bit.

Initially wrote it to scratch my own itch in 2010, haven't changed pretty much
anything since then.

A bit more info:
http://blog.fraggod.net/2010/12/Commandline-pulseaudio-mixer-tool


Installation
--------------------

Just copy the script to wherever is convenient (~/bin or /usr/local/bin comes to
mind), do a "chmod +x" on it, run.

### Requirements

* Python 2.7
* dbus-python (standard python dbus bindings)

Also, make sure you have `load-module module-dbus-protocol` line in
/etc/pulse/default.pa (or /etc/pulse/system.pa, if system-wide daemon is used).


Usage
--------------------

	% ./pulseaudio-mixer-cli.py -h
	usage: pulseaudio-mixer-cli.py [-h] [-a ADJUST_STEP] [-l MAX_LEVEL] [-v]
	                               [--debug]

	Pulseaudio sound level control tool.

	optional arguments:
	  -h, --help            show this help message and exit
	  -a ADJUST_STEP, --adjust-step ADJUST_STEP
	                        Adjustment for a single keypress in interactive mode
	                        (0-100%, default: 5%).
	  -l MAX_LEVEL, --max-level MAX_LEVEL
	                        Value to treat as max (default: 65536).
	  -v, --verbose         Dont close stderr to see any sort of errors (which
	                        mess up curses interface, thus silenced that way by
	                        default).
	  --debug               Verbose operation mode.

That's basically how it looks (sink levels always displayed on top):

	ALC269VB Analog (analog-stereo@snd_hda_intel)            [ ############################------------ ]
	ALSA plug-in [plugin-container] (fraggod@sacrilege:2914) [ ##################---------------------- ]
	MPlayer (fraggod@sacrilege:5686)                         [ ############---------------------------- ]


Internals
--------------------

Since I wasn't able to easily couple ncurses eventloop with glib/dbus one (which
should poll for async signals), I settled on splitting glib loop into it's own
process.
Both loops communicate via pipes, opened before fork(), waking each other up
from the respective loop (to process data being sent via pipes) when necessary
with POSIX signals.

Pulseaudio dbus interface was introduced in 1.0-dev branch (which is actually
fairly old), but merged recently (mid-2011) into mainline versions.
More documentation on it can be found via introspection or on [PA
wiki](http://pulseaudio.org/wiki/DBusInterface).

Since interface processes signals about new/removed streams and sinks, and not
just polls the data on some intervals, it should be fairly responsive to these
changes.
There are signals for volume updates, but they aren't processed just for the
sake of simplicity. Volume levels are polled on occasional changes anyway, so
they should be updated on the ui update events.

DBus reconnection is built-in, so there's no problem with transient pulseaudio
processes, although the fact that the client is connected via dbus interface
will keep them alive indefinitely.

Starting the mixer should also trigger pulseaudio start, if proper dbus
autolaunch service descriptions are installed in the system.

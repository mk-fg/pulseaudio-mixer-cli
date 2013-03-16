pulseaudio-mixer-cli
--------------------

Interactive ncurses UI to control volume of pulse streams.

Kinda like alsamixer, but focused not on sink volume levels (which can actually
be controlled via alsamixer, with alsa-pulse plugin), but rather on volume of
individual streams, so you can turn down the music to hear the stuff from game,
mumble, skype or flash.

Control over individual process streams seem to be almost unique to pulseaudio,
pity there aren't much tools built to harness it (at least weren't,
initially). This one tries to fill the gap a bit.

Thanks to the most awesome contributors, the tool is now useable with
system-wide pulseaudio instance, can mute streams/sinks, works with vi-style
keys as well as cursor and has many other fixes and features.


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
	usage: pulseaudio-mixer-cli.py [-h] [-a step] [-l level] [-v] [--debug]

	Pulseaudio sound level control tool.

	optional arguments:
	  -h, --help            show this help message and exit
	  -a step, --adjust-step step
	                        Adjustment for a single keypress in interactive mode
	                        (0-100%, default: 5%).
	  -l level, --max-level level
	                        Value to treat as max (default: 65536).
	  -v, --verbose         Dont close stderr to see any sort of errors (which
	                        mess up curses interface, thus silenced that way by
	                        default).
	  --debug               Verbose operation mode.

That's basically how it looks (sink levels always displayed on top):

	ALC269VB Analog (analog-stereo@snd_hda_intel)            - [ ############################---------- ]
	ALSA plug-in [plugin-container] (fraggod@sacrilege:2914) - [ ##################-------------------- ]
	MPlayer (fraggod@sacrilege:5686)                         - [ ############-------------------------- ]

Script can read simple ini-like config from "~/.pulseauido-mixer-cli.cfg" (see
[ConfigParser docs](http://docs.python.org/2/library/configparser.html) for more
details on format), which may contain definitions for any options, allowed on
the command line in the "[default]" section.

For example:

	[default]
	adjust-step: 2
	max-level: 131072

Such config is totally optional, and might be useful in case default options
aren't suitable for a specific setup and creating a shell alias or wrapper is
too much trouble.
Commandline values override the ones defined in a config file.


Internals
--------------------

Since I wasn't able to easily couple ncurses eventloop with glib/dbus one (which
should poll for async signals), I settled on splitting glib loop into it's own
process.
Both loops communicate via pipes, opened before fork(), waking each other up
from the respective loop (to process data being sent via pipes) when necessary
with POSIX signals.

Pulseaudio dbus interface was introduced in 1.0-dev branch (which is actually
fairly old), but was merged mid-2011 into mainline versions.
More documentation on it can be found via introspection or on [PA
wiki](http://pulseaudio.org/wiki/DBusInterface).

Since interface processes signals about new/removed streams and sinks, and not
just polls the data on some intervals, it should be fairly responsive to these
changes.
There are signals for volume updates, but they aren't processed just for the
sake of simplicity. Volume levels are polled on occasional changes anyway, so
they should be updated on the ui update events.

DBus reconnection (sometimes via re-exec, because python-dbus seem to cache more
stuff than it probably should) is built-in, so there's no problem with transient
pulseaudio processes, although the fact that the client is connected via dbus
interface will keep them alive indefinitely.

Starting the mixer should also trigger pulseaudio start, if proper dbus
autolaunch service descriptions are installed in the system.

It should also work with system-wide pulseaudio daemon (usage of which is
[highly discouraged by
developers](http://www.freedesktop.org/wiki/Software/PulseAudio/Documentation/User/WhatIsWrongWithSystemWide),
btw) - in that case neither dbus system nor session bus is accessed, since
ServerLookup interface doesn't seem to be available on either one (at least in
2.1), and pa-private bus is accessed via well-known socket location at
/run/pulse/dbus-socket (see also #4).

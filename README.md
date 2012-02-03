pulseaudio-mixer-cli: ncurses ui to control volume of pulse streams (per-process)
--------------------

Kinda like alsamixer, but focused not on sink volume levels (which can actually
be controlled via alsamixer, with alsa-pulse plugin), but rather on volume of
individual streams, so you can turn down the music to hear the stuff from game,
mumble, skype or flash.

Control over individual process streams is kinda unique to pulseaudio, pity
there aren't much tools built to harness it. This one tries to fill the gap a
bit.

Initially wrote it to scratch my own itch in 2010, haven't changed pretty much
anything since then.

A bit more info:
http://blog.fraggod.net/2010/12/Commandline-pulseaudio-mixer-tool


Requirements
-------------------

* Python 2.7
* dbus-python (standard python dbus bindings)

And that's it.


Installation
--------------------

Just copy the script to wherever is convenient (~/bin or /usr/local/bin comes to
mind), do a "chmod +x" on it, run.


Operation
--------------------

usage: pulseaudio-mixer-cli.py [-h] [-l MAX_LEVEL] [-s SINK_NAME]
                               [--list-sinks] [-i] [-a ADJUST_STEP] [--debug]
                               [level]

Pulseaudio sound level control tool.

positional arguments:
  level                 Set (just number in range of 0-100) or adjust (+/-
                        number), followed by optional % sign.

optional arguments:
  -h, --help            show this help message and exit
  -l MAX_LEVEL, --max-level MAX_LEVEL
                        Value to treat as max (default: 65536).
  -s SINK_NAME, --sink-name SINK_NAME
                        Exact name of the sink to apply adjustments to (as
                        printed by --list-sinks, first available sink is used
                        by default).
  --list-sinks          Show the list of sinks, registered in pa.
  -i, --interactive     Adjust per-client volume levels via curses interface.
                        Implied if no other action is specified.
  -a ADJUST_STEP, --adjust-step ADJUST_STEP
                        Adjustment for a single keypress in interactive mode
                        (0-100%, default: 10%).
  --debug               Verbose operation mode.


Internals
--------------------

Since I wasn't able to easily couple ncurses eventloop with glib/dbus one (which
should poll for async signals), I settled on splitting each loop into it's own
process.

Both communicate via pipes, opened before fork(), waking each other up from the
respective loop (to process data being sent via pipes) when necessary with POSIX
signals.

Pulseaudio dbus interface was introduced in 1.0-dev branch (which is actually
fairly old), but merged recently (mid-2011) into mainline versions.
More documentation on it can be found via introspection or on PA wiki:
http://pulseaudio.org/wiki/DBusInterface

Since interface processes signals about new/removed streams, and not just polls
the data on some intervals, it should be fairly responsive to changes.

DBus reconnection is built-in, so there's no problem with transient pulseaudio
processes, although the fact that the client is connected via dbus interface
will keep them alive indefinitely.

Starting the mixer should also trigger pulseaudio start, if proper dbus
autolaunch service descriptions are installed in the system.

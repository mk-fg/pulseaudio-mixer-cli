pulseaudio-mixer-cli
--------------------

Interactive ncurses UI to control volume of pulse streams.

Kinda like alsamixer, but focused not on sink volume levels (which can actually
be controlled via alsamixer, with alsa-pulse plugin), but rather on volume of
individual streams, so you can turn down the music to hear the stuff from games,
mumble, skype or browser.

Control over individual process streams seem to be almost unique to pulseaudio,
pity there aren't much tools built to harness it (at least weren't, initially).
This one tries to fill the gap a bit.

Thanks to the most awesome contributors, the tool is now useable with
system-wide pulseaudio instance, can mute streams/sinks, works with vi-style
keys as well as cursor and has many other fixes and features.



Installation
--------------------

Just copy the script to wherever is convenient (~/bin or /usr/local/bin comes to
mind), do a "chmod +x" on it, run.

Make sure you have `load-module module-dbus-protocol` line in
/etc/pulse/default.pa (or /etc/pulse/system.pa, if system-wide daemon is used),
especially on Ubuntu, where it seem to be disabled by default
(see [#1](https://github.com/mk-fg/pulseaudio-mixer-cli/issues/1)).

There is now also "pa-mixer-mk2.py" script in the repo, which is a rewrite of
the original version, and might have some extra features and/or bugs.

### Warning

As of pulseaudio-6.0, loading module-dbus-protocol issues following warnings:

	[pulseaudio] module-dbus-protocol.c: module-dbus-protocol is
	  currently unsupported, and can sometimes cause PulseAudio crashes.
	[pulseaudio] module-dbus-protocol.c: The most popular use
	  cases for module-dbus-protocol are related to changing equalizer
	  settings and LADSPA plugin parameters at runtime.
	[pulseaudio] module-dbus-protocol.c: If you don't use such
	  functionality, it's possible that you don't actually need this module.

I haven't experienced any crashes with newer PA versions first-hand,
and killing/restarting PA seem to only cause a brief sound disruption, but if
that is indeed a problem, currently there is no way to use this script without
the module (though probably not hard to rewrite it to use PA protocol instead,
patches welcome!).

For the list of similar tools that don't use dbus, see [Links](#links) section
below.

### Requirements

* Python 2.7
* dbus-python (standard python dbus bindings)
* PyGObject (aka PyGI, likely installed if dbus-python is)
* PulseAudio 1.0+



Usage
--------------------

Run the script (either "pulseaudio-mixer-cli.py" or "pa-mixer-mk2.py") with "-h"
or "--help" option to see various other options, but there aren't that many -
most stuff is configurable via config file (described below).

That's basically how it looks... in an overly narrow terminal (to fit on a github
page), and without "inverted row" selection visible:

	[++] Jack sink (PulseAudio JACK Sink)                  M [ ########################## ]
	[++] HDMI 0 (hdmi-stereo@snd_hda_intel)                M [ ########################## ]
	[81] ID 440 Analog (analog-stereo@snd_hda_intel)       - [ #####################----- ]
	[35] mpv - Bax - Perceptions 206 on ETN.fm Jan-22-2015 - [ #########----------------- ]
	[38] VLC media player (fraggod@malediction:24321)      - [ ##########---------------- ]
	[54] Skype (fraggod@malediction:24202)                 - [ ##############------------ ]
	[27] ALSA plug-in [PillarsOfEternity]                  - [ #######------------------- ]

Sink levels always displayed on top, "M" or "-" to the left of the bar is a mute
indicator. Stuff that one never expects to use can be hidden (see below).

### Controls

Controls are:

* Arrow keys (including numpad) or their vi/emacs-style counterparts to pick row
  and adjust bars left and right.

  Vi keys: "k" - up, "j" - down, "h" - left, "l" - right.

  Emacs keys: "p" - up, "n" - down, "b" - left, "f" - right.

* "m" or "space" to toggle mute for selected sink or stream.

* "q" to quit.

* "1" through "0" (number row keys) to set specific level.

  "1" - 10%, "2" - 20%, "3" - 30%, ..., "9" - 90%, "0" - 100%.

  These are only available in pa-mixer-mk2.

Supposed to mimic ones in alsamixer and be somewhat intuitive, hardcoded.

### Config file

Script can read simple ini-like config from "~/.pulseauido-mixer-cli.cfg".
See [RawConfigParser docs](http://docs.python.org/2/library/configparser.html)
for more details on format of that file.

For example:

	[default]
	adjust-step: 2
	max-level: 131072
	use-media-name: true
	focus-default: last
	focus-new-items: false

Such config is totally optional, and might be useful in case default options
aren't suitable for a specific setup.
See [pa-mixer.example.cfg](pa-mixer.example.cfg) for the full list of these.

Commandline values (where available) override the ones defined in the config file.

There is a shiny rewritten "pa-mixer-mk2.py" script version, which is probably
way less tested, but have some extra features, which I can't be bothered to
add/test for an old one, so maybe take a look at that one as well.

Config for mk2 script can also contain sections for applying stuff (hide, volume
min/max/set, sink ports, and such) to individual sinks/streams, for example:

	[stream-sink-hdmi]
	match[alsa.id]: ^HDMI\b
	hidden: true

This will hide any HDMI sinks, matching their "alsa.id" parameter by regexp.

Running `./pa-mixer-mk2.py --dump-stream-parameters 2>stream_params.txt` will
dump such parameters for all seen streams to "stream_params.txt", so that it'd
be easy to choose how to match these.

See more info on stream matching and parameters in
[pa-mixer.example.cfg](pa-mixer.example.cfg).

### Other misc usage hints

* Running the thing in a drop-down terminal ("quake console" like guake,
  yakuake, tilda, terra, yeahconsole) makes it into something like a keyboard
  version of regular "tray volume app".



Debugging errors
--------------------

Run `./pa-mixer-mk2.py --debug --fatal --debug-pipes 2>pa-mixer.log` until
whatever werid bug happens, then look into produced "pa-mixer.log".

`--fatal` and `--debug-pipes` can probably be omitted in most cases, main point
there is a `--debug` option, enabling output to stderr and then redirecting that
to a file, so that it won't mess up the ui (as terminals show both stdout and
stderr interleaved).



Links
--------------------

* [pulsemixer](https://github.com/GeorgeFilipkin/pulsemixer/)

  Similar Python-3-based mixer with more colorful and comprehensive UI and no
  dbus dependency (uses libpulse via ctypes) or any extra deps at all.

  Should be more future-proof, given python-3 and that dbus module in pulse seem
  to be deprecated and unmaintained.

* [pamixer](https://github.com/valodim/pamixer)



Internals
--------------------

Since I wasn't able to easily couple ncurses eventloop with glib/dbus one (which
should poll for async signals), and python-dbus doesn't seem to handle
reconnects well, I settled on splitting glib loop into it's own process (which
can just be restarted when/if dbus fails).

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
stuff than it probably should) is built-in, so there should be no problem with
transient pulseaudio processes, although the fact that the client is connected
via dbus interface might keep them alive indefinitely.

Starting the mixer should also trigger pulseaudio start, if proper dbus
autolaunch service descriptions are installed in the system.

Script should also work with system-wide pulseaudio daemon (usage of which is
[highly discouraged by developers](http://www.freedesktop.org/wiki/Software/PulseAudio/Documentation/User/WhatIsWrongWithSystemWide),
btw) - in that case neither dbus system nor session bus is accessed, since
ServerLookup interface doesn't seem to be available on either one (at least in
2.1), and pa-private bus is accessed via well-known socket location at
/run/pulse/dbus-socket (see also [#4](https://github.com/mk-fg/pulseaudio-mixer-cli/issues/4)).

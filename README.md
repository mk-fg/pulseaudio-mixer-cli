pulseaudio-mixer-cli
--------------------

Interactive ncurses UI to control volume of pulse streams.

Kinda like alsamixer, focused not on sink volume levels (which can actually be
controlled via alsamixer, with alsa-pulse plugin), but rather on volume of
individual streams, so you can turn down the music to hear the stuff from games,
mumble, skype or browser.

In addition to interactive UI, script allows to match and configure sink/stream
parameters via config file, so that when specific sink or stream appears,
e.g. its volume can be capped, port changed, UI title adjusted, be hidden in UI,
stuff like that.

Control over individual process streams seem to be almost unique to pulseaudio,
pity there aren't much tools built to harness it (at least weren't, initially).
This one tries to fill the gap a bit.

Thanks to the most awesome contributors, the tool is now useable with
system-wide pulseaudio instance, can mute streams/sinks, works with vi-style
keys as well as cursor and has many other fixes and features.



Installation
--------------------

Copy one of the scripts (`pa-mixer-mk3.py` is the latest one) to wherever is
convenient (~/bin or /usr/local/bin comes to mind), do a "chmod +x" on it, run.

There are three scripts:

* `pulseaudio-mixer-cli.py` - initial version, uses semi-isolated dbus
  subprocess, Python-2.7 only.

* `pa-mixer-mk2.py` - rewrite, with separate dbus/glib subprocess and more
  features, also Python-2.7.

* `pa-mixer-mk3.py` - same as mk2, but for Python-3.x and uses
  [pulsectl module](https://github.com/mk-fg/python-pulse-control)
  (libpulse wrapper) to communicate with pulseaudio daemon (from a thread)
  instead of dbus.

Only latest script is updated. Older ones are left in the repo just in case.

If `pa-mixer-mk3.py` (latest) script version will be used,
[pulsectl](https://github.com/mk-fg/python-pulse-control) python module must be
installed (either via OS packaging system, or e.g. `pip install --user pulsectl`).

If using older scripts with dbus interface, make sure you have `load-module
module-dbus-protocol` line in /etc/pulse/default.pa (or /etc/pulse/system.pa, if
system-wide daemon is used) and dbus-python package installed.

### Requirements (pa-mixer-mk3.py)

* Python 3.x
* [pulsectl](https://github.com/mk-fg/python-pulse-control) python module
* PulseAudio 1.0+



Usage
--------------------

Run the script with "-h" or "--help" option to see various parameters, but there
aren't that many - most stuff is configurable via config file (described below).

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

Supposed to mimic ones in alsamixer and be somewhat intuitive, hardcoded.

### Config file

Script can read simple ini-like config from "~/.pulseauido-mixer-cli.cfg".
See [RawConfigParser docs](http://docs.python.org/2/library/configparser.html)
for more details on format of that file.

For example:

	[default]
	adjust-step: 2
	max-volume: 1.3
	use-media-name: true
	focus-default: last
	focus-new-items: false

Such config is totally optional, and might be useful in case default options
aren't suitable for a specific setup.
See [pa-mixer.example.cfg](pa-mixer.example.cfg) for the full list of these.

Commandline values (where available) override the ones defined in the config file.

Config can also contain sections for applying stuff (hide, volume min/max/set,
sink ports, and such) to individual sinks/streams, for example:

	[stream-sink-hdmi]
	match[alsa.id]: ^HDMI\b
	hidden: true

	[stream-firefox-media]
	equals[application.name]: CubebUtils
	name: firefox
	volume-max: 0.2

This will hide any HDMI sinks, matching their "alsa.id" parameter by regexp,
match sound from firefox by "application.name" and set more descriptive name
there, as well as cap initial volume level for these at "0.2" (lower to this
value if it is set higher initially).

Running `./pa-mixer-mk3.py --dump-stream-parameters 2>stream_params.txt` will
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

Run `./pa-mixer-mk3.py --debug --fatal 2>pa-mixer.log` until whatever werid bug
happens, then look into produced "pa-mixer.log".

`--fatal` can probably be omitted in most cases, main point there is a `--debug`
option, enabling output to stderr and then redirecting that to a file, so that
it won't mess up the ui (as terminals show both stdout and stderr interleaved).



Other similar projects
--------------------

* [pulsemixer](https://github.com/GeorgeFilipkin/pulsemixer/)

  Similar Python-3-based pulse mixer with way more colorful UI, individual
  channel volumes, source volume and port control, and without any extra deps.

* [pamixer](https://github.com/valodim/pamixer)

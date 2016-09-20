======================
 pulseaudio-mixer-cli
======================
-----------------------------------------------------------
 Interactive ncurses UI to control volume of pulse streams
-----------------------------------------------------------

.. contents::
  :backlinks: none



Description
-----------

Kinda like alsamixer, focused not on sink volume levels (which can actually be
controlled via alsamixer, with alsa-pulse plugin), but rather on volume of
individual streams, so you can tune down the music to hear the stuff from games,
mumble, skype or browser.

In addition to interactive UI, script allows to match and configure sink/stream
parameters via config file, so that when specific sink or stream appears,
e.g. its volume can be capped, port changed, UI title adjusted, hidden - stuff
like that.

Easy control over audio streams that pulseaudio provides seem to be almost
unique to it, pity there aren't many tools built to harness it (at least
weren't, initially). This one tries to fill the gap a bit.


How it looks
````````````

...in a rather narrow terminal (to fit well on a github page), and without
"inverted row" selection visible::

  [++] Jack sink (PulseAudio JACK Sink)                  M [ ########################## ]
  [++] HDMI 0 (hdmi-stereo@snd_hda_intel)                M [ ########################## ]
  [81] ID 440 Analog (analog-stereo@snd_hda_intel)       - [ #####################----- ]
  [35] mpv - Bax - Perceptions 206 on ETN.fm Jan-22-2015 - [ #########----------------- ]
  [38] VLC media player (fraggod@malediction:24321)      - [ ##########---------------- ]
  [54] Skype (fraggod@malediction:24202)                 - [ ##############------------ ]
  [27] ALSA plug-in [PillarsOfEternity]                  - [ #######------------------- ]

Sink levels always sorted/displayed on top, "M" or "-" to the left of the bar is
a mute indicator.

Stuff that's rarely or never used (e.g. Jack/HDMI sink levels) can be hidden (see below).

There's also a separate list of module-stream-restore volumes, accessible via "x" key.


Features (pa-mixer-mk3.py)
``````````````````````````

- Terminal app, very simple ascii tui, basic controls, output volumes and mute only.

- Listens and reacts to events from pulse, i.e. any stream/volume changes on the
  server will be reflected in the UI immediately.

- Robust - should work with any kind of terminal types/sizes and events, any
  number of pulse streams or event floods, pulse server dying and restarting, etc.

- Configurable UI behavior (e.g. focus policy, names, etc), volume range to
  control, adjustment step.

- Automation features (through config file) for matching streams and
  auto-adjusting/limiting their volume, sink ports, rename/hide in the UI,
  and such.

- Ability to tweak volumes for audio roles (e.g. all "event" sounds) and
  streams/apps that are not currently running via module-stream-restore api,
  if available.

- Uses libpulse and its "native" protocol.

- Extensive debug logging, if enabled.


Limitations (pa-mixer-mk3.py)
`````````````````````````````

- Very basic and dull UI, no colors, fancy unicode or anything.

- Only volumes for sinks and sink-inputs are displayed/controllable via UI - no
  sources, source-inputs, cards, modules, equalizers, etc.

- No control over per-channel volume levels, always sets same level for all
  channels.

- Flat menu - doesn't reflect relations between sink-inputs and sinks they
  belong to, not very suitable for multi-sink setups.

- No options/controls to migrate streams between sinks/sources, kill/suspend
  stuff, or any pactl-like actions like that.

- Interactive mode only, no "oneshot" operation.

- Not a self-contained script, depends on extra py module.

See links section below for some of the good alternatives.



Installation
------------

Copy one of the scripts (`pa-mixer-mk3.py`_ is the latest one) to wherever is
convenient (~/bin or /usr/local/bin comes to mind), do a ``chmod +x`` on it, run.

There are three scripts:

- `pulseaudio-mixer-cli.py`_ - initial version, uses semi-isolated dbus
  subprocess, Python-2.7 only.

- `pa-mixer-mk2.py`_ - rewrite, with separate dbus/glib subprocess and more
  features, also Python-2.7.

- `pa-mixer-mk3.py`_ - same as mk2, but for Python-3.x and uses pulsectl_ module
  (libpulse wrapper) to communicate with pulseaudio daemon (from a thread)
  instead of dbus.

Only latest script is updated. Older ones are left in the repo just in case.

If `pa-mixer-mk3.py`_ (latest) script version will be used, pulsectl_ python
module must be installed (either via OS packaging system, or e.g. ``pip
install --user pulsectl``).

If using older scripts with dbus interface, make sure you have ``load-module
module-dbus-protocol`` line in /etc/pulse/default.pa (or ``/etc/pulse/system.pa``,
if system-wide daemon is used) and dbus-python package installed.

Requirements (pa-mixer-mk3.py)
``````````````````````````````

- Python 3.x
- pulsectl_ python module
- PulseAudio 1.0+

.. _pulseaudio-mixer-cli.py: pulseaudio-mixer-cli.py
.. _pa-mixer-mk2.py: pa-mixer-mk2.py
.. _pa-mixer-mk3.py: pa-mixer-mk3.py
.. _pulsectl: https://github.com/mk-fg/python-pulse-control



Usage
-----

Run the script with "-h" or "--help" option to see various parameters, but there
aren't that many - most stuff is configurable via config file (described below).


Controls
````````

Keyboard controls are:

- Arrow keys (including numpad) or their vi/emacs-style counterparts to pick row
  and adjust bars left and right.

  Vi keys: "k" - up, "j" - down, "h" - left, "l" - right.

  Emacs keys: "p" - up, "n" - down, "b" - left, "f" - right.

  | "Page Up" / "Page Down" to skip over visible number of rows up/down.
  | "Home" / "End" to select first/last item, respectively.

- "m" or "space" to toggle mute for selected sink or stream.

- "1" through "0" (number row keys) to set specific level.

  "1" - 10%, "2" - 20%, "3" - 30%, ..., "9" - 90%, "0" - 100%.

- "q" to quit.

- "x" to toggle display between current sink/stream volumes and ones in
  module-stream-restore db (if used/accessible).

Supposed to mimic ones in alsamixer and be somewhat intuitive, hardcoded.


Config file
```````````

Script can read simple ini-like config from "~/.pulseauido-mixer-cli.cfg"
(or whatever is specified via --conf option).

See `RawConfigParser docs <http://docs.python.org/2/library/configparser.html>`_
for more details on format of that file.

For example::

  [default]
  adjust-step: 2
  max-volume: 1.3
  use-media-name: true
  focus-default: last
  focus-new-items: false
  show-controls: false

Such config is totally optional, and might be useful in case default options
aren't suitable for a specific setup.
See `pa-mixer.example.cfg`_ for the full list of these.

Commandline values (where available) override the ones defined in the config file.

Config can also contain sections for applying stuff (hide, volume min/max/set,
sink ports, and such) to individual sinks/streams, for example::

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

Running ``./pa-mixer-mk3.py --dump-stream-parameters 2>stream_params.txt`` will
dump such parameters for all seen streams to "stream_params.txt", so that it'd
be easy to choose how to match these.

See more info on stream matching and parameters in `pa-mixer.example.cfg`_.

.. _pa-mixer.example.cfg: pa-mixer.example.cfg


Misc hints
``````````

- Running the thing in a drop-down terminal ("quake console" like guake,
  yakuake, tilda, terra, yeahconsole) makes it into something like a keyboard
  version of regular "tray volume app".

- To set volume for very transient sounds (e.g. notification "blips") that are
  too quick to disappear or adjust them in any way, there are two options:

  - If module-stream-restore is loaded (usually is by default), use "x" key to
    adjust all volumes that are stored there.

  - ``--dump-stream-parameters`` option and volume setting through config file
    can be used (see "Config file" section above for details).

- Clients/apps that change their volume can be forced to have fixed volume level
  or min/max thresholds by using "volume-..." settings and "reapply: true" (to
  enforce these on every volume-change event).



Debugging errors
----------------

Run ``./pa-mixer-mk3.py --debug --fatal 2>pa-mixer.log`` until whatever werid
bug happens, then look into produced "pa-mixer.log".

"--fatal" can probably be omitted in most cases, main point there is a "--debug"
option, enabling output to stderr and then redirecting that to a file, so that
it won't mess up the ui (as terminals show both stdout and stderr interleaved).



Other similar projects
----------------------

- `pulsemixer <https://github.com/GeorgeFilipkin/pulsemixer/>`_

  Similar Python-3-based pulse mixer with way more colorful UI, individual
  channel volumes, source volume and port control, and without any extra deps.

- `pamixer <https://github.com/valodim/pamixer>`_

  Seem to be abandoned since the time of pulseaudio-0.9.22 release (5+ years ago).

- `ponymix <https://github.com/falconindy/ponymix>`_

  Nice C++ non-interactive control tool.

- pavucontrol that comes with pulse has good GUI (for GNOME/X11 and such).

Not an exhaustive list by any means.

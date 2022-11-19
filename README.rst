======================
 pulseaudio-mixer-cli
======================
-----------------------------------------------------------
 Interactive ncurses UI to control volume of pulse streams
-----------------------------------------------------------

.. contents::
  :backlinks: none

Repository URLs:

- https://github.com/mk-fg/pulseaudio-mixer-cli
- https://codeberg.org/mk-fg/pulseaudio-mixer-cli
- https://fraggod.net/code/git/pulseaudio-mixer-cli



Description
-----------

Kinda like alsamixer, focused not on sink volume levels (which can be also
controlled via alsamixer, with alsa-pulse plugin), but rather on volume of
individual streams, so you can tune down the music to hear notifications,
games, chats, browser or other media over each other.
Both current and stored volume levels can be adjusted.

In addition to interactive UI, script allows to match and configure sink/stream
parameters via config file, so that when specific sink or stream appears,
e.g. its volume can be capped, port changed, UI title adjusted, hidden - stuff
like that - which is useful to override pulse's "stream_restore" values to avoid
blowing your ears out when starting media player with stored 100% volume from
some earlier adjustment.


How it looks
````````````

...in a rather narrow terminal (to fit well on html page), and without
"inverted row" selection visible::

  [++] Jack sink (PulseAudio JACK Sink)                  M [ ########################## ]
  [++] HDMI 0 (hdmi-stereo@snd_hda_intel)                M [ ########################## ]
  [81] ID 440 Analog (analog-stereo@snd_hda_intel)       - [ #####################----- ]
  [35] mpv - Bax - Perceptions 206 on ETN.fm Jan-22-2015 - [ #########----------------- ]
  [38] VLC media player                                  - [ ##########---------------- ]
  [54] Skype                                             - [ ##############------------ ]
  [27] ALSA plug-in [PillarsOfEternity]                  - [ #######------------------- ]

Sink levels always sorted/displayed on top, "M" or "-" to the left of the bar is
a mute indicator.

Stuff that's rarely or never used (e.g. Jack/HDMI sink levels) can be hidden (see below).

There's also a separate list of module-stream-restore volumes, accessible via "x" key.


Features
````````

- Terminal app, very simple ascii TUI, basic controls, output volumes and mute only.

- Listens and reacts to events from pulse, i.e. any stream/volume changes on the
  server will be reflected in the UI immediately.

- Robust - should work with any kind of terminal types/sizes and events, any
  number of pulse streams or event floods, pulse server dying and restarting, etc.

- Configurable UI behavior (e.g. focus policy, names, etc), volume range to
  control, adjustment step, non-linear adjustment.

- Automation features (through config file) for matching streams and
  auto-adjusting/limiting their volume, sink ports, rename/hide in the UI,
  and such.

- Ability to tweak volumes for audio roles (e.g. all "event" sounds) and
  streams/apps that are not currently running via module-stream-restore api,
  if available.

- Uses libpulse and its "native" protocol.

- Extensive debug logging, if enabled.


Limitations
```````````

- Very basic and dull UI, no colors, fancy unicode or anything like that.

- Only volumes for sinks and sink-inputs are displayed/controllable via UI -
  no sources, source-inputs, cards, modules, equalizers, etc.

- No control over per-channel volume levels, always sets same level for all channels.

- Flat menu - doesn't reflect relations between sink-inputs and sinks they
  belong to, not very suitable for multi-sink setups.

- No options/controls to migrate streams between sinks/sources, kill/suspend stuff,
  or any pactl-like actions like that.

- Interactive/automation mode only, no "oneshot" operation.

- Not a self-contained script, depends on extra python module.

See links section below for some of the good alternatives.



Installation
------------

pulsectl_ python module must be installed in order for this script to work
first, which can be done either via OS packaging system, or ``pip install pulsectl``.
See also instructions in `pulsectl repository`_ for other install options.

After that, copy `pa-mixer.py`_ to wherever is convenient (``~/bin`` or
``/usr/local/bin`` comes to mind), do a ``chmod +x`` on it, run it.

Older python2/dbus versions of the tool can be found in the git repository
history, but shouldn't be relevant by now.

.. _pulsectl: https://pypi.org/project/pulsectl/
.. _pulsectl repository: https://github.com/mk-fg/python-pulse-control
.. _pa-mixer.py: pa-mixer.py



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

- Current volumes tab only:

  - "i" to show proplist for the selected item, i.e. stuff that can be used to
    match it via config file.

- module-stream-restore tab only:

  - "d" to remove (i.e. forget) stored value for stream/role.

  - "enter" to apply selected value to active streams.

Keys for rare/special actions (such as "x", "i", "d" and such) should also be
shown at the bottom line, unless disabled via config ("show-controls" option).

Supposed to mimic controls in alsamixer and be somewhat intuitive, hardcoded.



Config file
```````````

Script can read simple ini-like config from ``~/.pa-mixer.cfg`` or
``~/.pulseauido-mixer-cli.cfg`` (or whatever is specified via --conf option),
with "key = value" or "key: value" lines under section names in square brackets.

For example::

  [default]
  adjust-step: 2
  max-volume: 1.3
  use-media-name: yes
  focus-default: last
  focus-new-items: no
  show-controls: no

Such config is optional, and useful in case default options aren't suitable for
a specific setup or to match streams and automate some changes.
See `pa-mixer.example.cfg`_ for full list of options in that file and an extended example.

Command-line values (where available) override ones defined in the file.

Config can also contain sections for changing stream parameters for individual
sinks/streams automatically (e.g. hide, volume min/max/set, sink ports, and such),
for example::

  [stream-sink-hdmi]
  match[alsa.id]: ^HDMI\b
  hidden: yes

  [stream-firefox-media]
  equals[application.name]: Firefox
  name: firefox
  volume-max: 0.2

This example will hide HDMI sinks, matching their "alsa.id" parameter by regexp,
match sound from firefox by "application.name" and set more descriptive name
there, as well as cap initial volume level for these at "0.2" (lower to this
value if it is set higher initially).

Pressing "i" key will show all parameters (pulse proplist) for selected item.

Running ``./pa-mixer.py --dump-stream-parameters 2>stream_params.txt`` can
also be used to dump such parameters for all streams to "stream_params.txt",
to inspect and choose how to match these, and will catch any transient streams.

See more info on stream matching and parameters in `pa-mixer.example.cfg`_
and comments there.

.. _pa-mixer.example.cfg: pa-mixer.example.cfg



Misc hints
``````````

- Running the thing in a drop-down terminal ("quake console" like guake,
  yakuake, tilda, terra, yeahconsole) makes it into something like a keyboard
  version of regular "tray volume app".

- To set volume for very transient sounds (e.g. notification "blips") that are
  too quick to disappear or adjust them in any way, there are two options:

  - If module-stream-restore is loaded (should be by default), use "x" key to
    adjust all volumes that are stored there.

  - ``--dump-stream-parameters`` option and volume setting through config file
    can be used (see "Config file" section above for details).

- Stream id under which pulseaudio module-stream-restore saves volume can be
  easily controlled by using e.g. ``env PULSE_PROP_media.role=music mpv ...``,
  so that volume for app instance ("mpv" in that example) started like this
  stored separately from any other instances.

  Can be useful if same player is being run for many different purposes with
  inherently different volume levels/requirements (e.g. same mpv/vlc/etc for
  music, podcasts and movies).

- Clients/apps that change their volume can be forced to have fixed volume level
  or min/max thresholds by using "volume-..." settings and ``reapply: true``,
  to enforce these again on every volume-change event.

- ``/etc/pulse/daemon.conf`` has important "flat-volumes" option that controls
  whether to use same scale for all volume bars ("yes") or apply them on top of
  each other ("no"), which usually has distro-specific default value.

  That option is the reason why sink volume might be increased automatically
  when adjusting level for specific stream/app.

- To have more precise control over lower end of specified volume range without
  having to limit the range itself, ``volume-type = log`` option
  (base=e logarithmic scale) can be used, with higher-base values ("log-N")
  giving even more control there.

  | With e.g. ``volume-type = log-15``, 50% volume will be at ``[ ############--- ]``
  | See `pa-mixer.example.cfg`_ for more details.

- ``volume-after-max = yes`` can be used to allow effectively infinite volume range,
  if source is occasionally way too low for any reasonable min/max settings
  and has to be boosted like that.



Debugging errors
----------------

Run ``./pa-mixer.py --debug --fatal 2>pa-mixer.log`` until whatever werid
bug happens, then look into produced "pa-mixer.log".

"--fatal" can probably be omitted in most cases, main thing there is a "--debug"
option, enabling output to stderr and then redirecting that to a file, so that
it won't mess up the UI (as terminals show both stdout and stderr interleaved).



Other similar projects
----------------------

- `pulsemixer <https://github.com/GeorgeFilipkin/pulsemixer/>`_

  Similar Python-3-based pulse mixer with way more colorful UI, individual
  channel volumes, source volume and port control, and without any extra deps.

- `ponymix <https://github.com/falconindy/ponymix>`_ - nice C++ non-interactive control tool.

- `pavucontrol <https://freedesktop.org/software/pulseaudio/pavucontrol/>`_ -
  good GUI (for GNOME/X11/Wayland desktops) that usually comes with pulseaudio itself.

- `pamixer <https://github.com/valodim/pamixer>`_ -
  seem to be abandoned since the time of pulseaudio-0.9.22 (years ago).

Not an exhaustive list by any means.

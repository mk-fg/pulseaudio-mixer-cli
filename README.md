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


Requirements
-------------------

* Python 2.7
* dbus-python (standard python dbus bindings)

And that's it.


Installation
--------------------

Just copy the script to wherever is convenient (~/bin or /usr/local/bin comes to
mind), do a "chmod +x" on it, run.

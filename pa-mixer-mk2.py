#!/usr/bin/python
# -*- coding: utf-8 -*-
from __future__ import print_function

import itertools as it, operator as op, functools as ft
from collections import deque
import ConfigParser as configparser
import os, sys, io, re, time, types, subprocess, signal


conf_defaults = {
	'adjust-step': 5, 'max-level': 2 ** 16, 'encoding': 'utf-8',
	'use-media-name': False, 'verbose': False, 'debug': False }

def update_conf_from_file(conf, path_or_file):
	if isinstance(path_or_file, types.StringTypes): path_or_file = io.open(path_or_file)
	with path_or_file as src:
		config = configparser.SafeConfigParser(allow_no_value=True)
		config.readfp(src)
	for k, v in conf.viewitems():
		get_val = config.getint if not isinstance(v, bool) else config.getboolean
		try: defaults[k] = get_val('default', k)
		except configparser.Error: pass


class PAMixerDBusBridgeError(Exception): pass

class PAMixerDBusBridge(object):
	'''Class to import/spawn glib/dbus eventloop in a
			subprocess and communicate with it via signals and pipes.
		Presents async kinda-rpc interface to a dbus loop running in separate pid.
		Comm protocol is json lines, with signal sent to parent pid on any dbus async event.'''

	signal = signal.SIGUSR1 # used to break curses loop in the parent pid

	def __init__(self, child_cmd=None):
		self.child_cmd, self.core_pid = child_cmd, os.getppid()
		self.child_sigs, self.child_calls, self._child = deque(), dict(), None


	def _child_readline(self, wait_for_cid=None, one_signal=False, init_line=False):
		while True:
			if wait_for_cid and cid in self.child_calls:
				line = self.child_calls[cid]
				self.child_calls.clear()
				return line
			line = self._child.stdout.readline().strip()
			if init_line:
				assert line.strip() == 'ready', repr(line)
				break
			line = json.loads(line)
			if line['t'] == 'signal':
				self.child_sigs.append(line)
				if one_signal: break
			elif line['t'] == 'call': self.child_calls[cid] = line

	def call(self, func, *args):
		self.child_check_restart()
		cid = os.urandom(4)
		call = json.dumps(dict(t='call', cid=cid, func=func, args=args))
		assert '\n' not in call, repr(call)
		self._child.stdin.write('{}\n'.format(call))
		return self._child_readline(wait_for_cid=cid)['value']


	def install_signal_handler(self, func):
		self.signal_func = func
		signal.signal(self.signal, self.signal_handler)

	def signal_handler(self, sig=None, frm=None):
		if not self.child_sigs: self._child_readline(one_signal=True)
		while self.child_sigs:
			line = self.child_sigs.popleft()
			self.signal_func(line['name'], line['obj'])


	def child_start(self, gc_old_one=False):
		if self._child and gc_old_one:
			self._child.wait()
			self._child = None
		if not self.child_cmd or self._child: return
		self._child = subprocess.Popen( self.child_cmd,
			stdout=subprocess.PIPE, stdin=subprocess.PIPE, close_fds=True )
		self._child_readline(init_line=True) # wait until it's ready

	def child_check_restart(self):
		self.child_start()
		if not self._child: return # can't be started
		if self._child.poll() is not None:
			log.debug('glib/dbus child pid (%s) died. restarting it', self._child.pid)
			self.child_start(gc_old_one=True)

	def _get_bus_address(self):
		srv_addr = os.environ.get('PULSE_DBUS_SERVER')
		if not srv_addr and os.access('/run/pulse/dbus-socket', os.R_OK | os.W_OK):
			srv_addr = 'unix:path=/run/pulse/dbus-socket' # well-known system-wide daemon socket
		if not srv_addr:
			srv_addr = self._dbus.SessionBus()\
				.get_object('org.PulseAudio1', '/org/pulseaudio/server_lookup1')\
				.Get( 'org.PulseAudio.ServerLookup1',
						'Address', dbus_interface='org.freedesktop.DBus.Properties' )
		return srv_addr

	def _get_bus(self, srv_addr=None, dont_start=False):
		while not srv_addr:
			try:
				srv_addr = self._get_bus_address()
				log.debug('Got pa-server bus from dbus: %s', srv_addr)
			except self._dbus.exceptions.DBusException as err:
				if dont_start or srv_addr is False or\
						err.get_dbus_name() != 'org.freedesktop.DBus.Error.ServiceUnknown':
					raise
				subprocess.Popen(
					['pulseaudio', '--start', '--log-target=syslog'],
					stdout=open('/dev/null', 'wb'), stderr=STDOUT ).wait()
				log.debug('Started new pa-server instance')
				# from time import sleep
				# sleep(1) # XXX: still needed?
				srv_addr = False # to avoid endless loop
		return self._dbus.connection.Connection(srv_addr)

	def _core_notify(self, path, op):
		try:
			os.kill(self.core_pid, self.signal)
			self.stdout.write('{} {}\n'.format(op, path))
		except: loop.quit()

	def child_run(self):
		from dbus.mainloop.glib import DBusGMainLoop
		from gi.repository import GLib
		import dbus

		self._dbus = dbus

		# Disable stdin/stdout buffering
		sys.stdout = io.open(sys.stdout.fileno(), 'wb', buffering=0)
		sys.stdin = io.open(sys.stdin.fileno(), 'rb', buffering=0)

		sys.stdout.write('ready\n') # wait for main process to get ready, signal readiness
		log.debug('DBus signal handler thread started')

		DBusGMainLoop(set_as_default=True)
		loop = GLib.MainLoop()

		while True:
			bus = self._get_bus()
			core = bus.get_object(object_path='/org/pulseaudio/core1')
			# XXX: import stdin fd here, add rpc handling of lines there
			# XXX: self._core_notify
			for sig_name, sig_handler in (
					('NewSink', ft.partial(notify, op='^')),
					('SinkRemoved', ft.partial(notify, op='v')),
					('NewPlaybackStream', ft.partial(notify, op='+')),
					('PlaybackStreamRemoved', ft.partial(notify, op='-'))):
				bus.add_signal_receiver(sig_handler, sig_name)
				core.ListenForSignal(
					'org.PulseAudio.Core1.{}'.format(sig_name), dbus.Array(signature='o') )
			loop.run()

		raise RuntimeError('Child code broke out of the loop, this is a bug.')



class PAMixerMenuItem(object):

	@property
	def muted(self): bool

	@muted.setter
	def muted(self, flag): None

	@property
	def volume(self): float

	@volume.setter
	def volume(self, level): None

	def volume_change(self, delta): float

	def pick_next(self): PAMixerMenuItem
	def pick_prev(self): PAMixerMenuItem


class PAMixerMenu(object):

	@property
	def max_key_len(self): int

	def item_list(self): iterable

	def update_signal(self, name, obj): None





class PAMixerUIUpdate(Exception): pass # XXX: not needed here?

class PAMixerUI(object):

	item_len_min = 10
	bar_len_min = 10
	bar_caps_func = lambda bar='': ' [ ' + bar + ' ]'
	border = 1

	def __init__(self, menu):
		self.menu = menu

	def c_win_init(self):
		win = self.c.newwin(*self.c_win_size())
		win.keypad(True)
		return win

	def c_win_size(self):
		'Returns "nlines, ncols, begin_y, begin_x" for e.g. newwin(), taking border into account.'
		size = self.c_stdscr.getmaxyx()
		nlines, ncols = max(1, size[0] - 2 * self.border), max(1, size[1] - 2 * self.border)
		return nlines, ncols, min(self.border, size[0]), min(self.border, size[1])

	def c_win_draw(self, win, items, hl=None):
		win_rows, win_len = win.getmaxyx()
		if win_len <= 1: return

		item_len_max = items.max_key_len
		mute_button_len = 2
		bar_len = win_len - item_len_max - mute_button_len - len(self.bar_caps_func())
		if bar_len < self.bar_len_min:
			item_len_max = max(self.item_len_min, item_len_max + bar_len - self.bar_len_min)
			bar_len = win_len - item_len_max - mute_button_len - len(self.bar_caps_func())
			if bar_len <= 0: item_len_max = win_len # just draw labels
			if self.item_len_max < self.item_len_min: item_len_max = min(items.max_key_len, win_len)

		win.erase() # cleanup old entries
		for row, item in enumerate(items):
			if row >= win_rows - 1: break # not sure why bottom window row seem to be unusable

			attrs = self.c.A_REVERSE if item == hl else self.c.A_NORMAL

			win.addstr(row, 0, item[:item_len_max].encode(optz.encoding), attrs)
			if win_len > item_len_max + mute_button_len:
				if items.get_mute(item): mute_button = " M"
				else: mute_button = " -"
				win.addstr(row, item_len_max, mute_button)

				if bar_len > 0:
					bar_fill = int(round(items.get_volume(item) * bar_len))
					bar = self.bar_caps_func('#' * bar_fill + '-' * (bar_len - bar_fill))
					win.addstr(row, item_len_max + mute_button_len, bar)

	def c_key(self, k):
		if len(k) == 1: return ord(k)
		return getattr(self.c, 'key_{}'.format(k).upper())

	def _run(self, stdscr): # XXX: convert "items" to whatever self.menu interface
		c, k, self.c_stdscr = self.c, self.c_key, stdscr

		c.curs_set(0)
		c.use_default_colors()

		win = self.c_win_init()
		hl = next(iter(items)) if items else '' # XXX: still use something like items object?
		optz.adjust_step /= 100.0

		while True:
			glib_thing.child_check_restart() # XXX: proxy via menu? do it there implicitly?

			try: self.c_win_draw(win, items, hl=hl) # XXX: pass iter here, or don't pass menu obj at all
			except PAMixerUIUpdate: continue # XXX: not needed anymore?

			try: key = win.getch()
			except c.error: continue
			log.debug('Keypress event: %s', key)

			try:
				# XXX: add 1-0 keys' handling to set level here
				if key in [k('down'), k('j'), k('n')]: hl = items.next_key(hl)
				elif key in (c.KEY_UP, ord('k'), ord('p')): hl = items.prev_key(hl)
				elif key in (c.KEY_LEFT, ord('h'), ord('b')):
					items.set_volume(hl, items.get_volume(hl) - optz.adjust_step)
				elif key in (c.KEY_RIGHT, ord('l'), ord('f')):
					items.set_volume(hl, items.get_volume(hl) + optz.adjust_step)
				elif key in (ord(' '), ord('m')):
					items.set_mute(hl, not items.get_mute(hl))
				elif key < 255 and key > 0 and chr(key) == 'q': sys.exit(0)
				elif key in (c.KEY_RESIZE, ord('\f')):
					c.endwin()
					stdscr.refresh()
					win = self.c_win_init()
			except PAMixerUIUpdate: continue


	def run(self, items):
		import curses # has a ton of global state
		self.c = curses
		self.c.wrapper(self._run, items=items)



def self_exec_cmd(*args):
	'Returns list of [binary, args ...] to run this script with provided args.'
	args = [__file__] + list(args)
	if os.access(__file__, os.X_OK): return args
	return [sys.executable or 'python'] + args

def main(args=None):
	import argparse
	parser = argparse.ArgumentParser(description='Command-line PulseAudio mixer tool.')

	# parser.add_argument('-a', '--adjust-step',
	# 	action='store', type=int, metavar='step', default=defaults['adjust-step'],
	# 	help='Adjustment for a single keypress in interactive mode (0-100%%, default: %(default)s%%).')
	# parser.add_argument('-l', '--max-level',
	# 	action='store', type=int, metavar='level', default=defaults['max-level'],
	# 	help='Value to treat as max (default: %(default)s).')
	# parser.add_argument('-n', '--use-media-name',
	# 	action='store_true', default=defaults['use-media-name'],
	# 	help='Display streams by "media.name" property, if possible.'
	# 		' Default is to prefer application name and process properties.')
	# parser.add_argument('-e', '--encoding',
	# 	metavar='enc', default=defaults['encoding'],
	# 	help='Encoding to enforce for the output. Any non-decodeable bytes will be stripped.'
	# 		' Mostly useful with --use-media-name. Default: %(default)s.')
	# parser.add_argument('-v', '--verbose',
	# 	action='store_true', default=defaults['verbose'],
	# 	help='Dont close stderr to see any sort of errors (which'
	# 		' mess up curses interface, thus silenced that way by default).')

	parser.add_argument('--debug', action='store_true',
		default=defaults['debug'], help='Verbose operation mode.')
	parser.add_argument('--child-pid-do-not-use', action='store_true',
		help='Used internally to spawn dbus sub-pid, should not be used directly.')

	opts = parser.parse_args(sys.argv[1:] if args is None else args)

	if opts.child_pid_do_not_use:
		try: PAMixerDBusBridge().child_run()
		except PAMixerDBusBridgeError:
			argv = self_exec_cmd(sys.argv)
			os.closerange(3, max(map(int, os.listdir('/proc/self/fd'))) + 1)
			os.execvp(argv[0], argv)
		raise RuntimeError( 'PAMixerDBusBridge.child_run() has'
			' returned unexpectedly (should be an endless loop or exception).' )

	global log
	logging.basicConfig(level=logging.DEBUG if opts.debug else logging.WARNING)
	log = logging.getLogger()

	conf = conf_defaults.copy()
	conf_file = os.path.expanduser('~/.pulseaudio-mixer-cli.cfg')
	try: conf_file = io.open(conf_file)
	except (OSError, IOError) as err:
		log.debug('Not processing config file %r: %s %s', conf_file, type(err), err)
	else: update_conf_from_file(conf, conf_file)

	dbus_bridge = PAMixerDBusBridge(self_exec_cmd('--child-pid-do-not-use'])
	menu = PAMixerMenu(dbus_bridge)

	dbus_bridge.install_signal_handler(menu.update_signal)
	dbus_bridge.child_start()

	ui = PAMixerUI(menu)



if __name__ == '__main__': sys.exit(main())

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


class PAMixerGlibLoopError(Exception): pass

class PAMixerGlibLoop(object):
	'''Class to import/spawn glib/dbus eventloop in a
			subprocess and communicate with it through signals and pipes.
		Should ideally be started as soon as possible,
			to avoid carrying whatever baggage from parent pid after fork.'''

	def __init__(self, sig=signal.SIGUSR1):
		self.signal, self._pipe = sig, None


	def child_start(self):
		signal.signal(self.signal, signal.SIG_IGN)
		if self._pipe: self._pipe.close()
		fd_out, fd_in = os.pipe()
		self.core_pid = os.getpid()
		self.child_pid = os.fork()

		if not self.child_pid:
			try: self._child_run() # returns only on errors
			except Exception as err:
				log.exception('Unexpectedly broke out of glib loop due to exception: %s', err)
			raise PAMixerGlibLoopError()

		else:
			os.close(fd_in)
			self._pipe = io.open(fd_out, 'rb', buffering=0)

	def child_check_restart(self):
		if os.waitpid(child_pid, os.WNOHANG)[0]:
			log.debug('glib/dbus child pid died. restarting it')
			self.child_start()


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
					stdout=open('/dev/null', 'w'), stderr=STDOUT ).wait()
				log.debug('Started new pa-server instance')
				# from time import sleep
				# sleep(1) # XXX: still needed?
				srv_addr = False # to avoid endless loop
		return self._dbus.connection.Connection(srv_addr)

	def _core_notify(self, path, op):
		try:
			os.kill(self.core_pid, self.signal)
			self._pipe.write('{} {}\n'.format(op, path))
		except: loop.quit()

	def _child_run(self):
		from dbus.mainloop.glib import DBusGMainLoop
		from gi.repository import GLib
		import dbus

		self._dbus = dbus

		os.close(fd_out)
		self._pipe = io.open(fd_in, 'wb', buffering=0)
		self._pipe.write('\n') # wait for main process to get ready
		log.debug('DBus signal handler thread started')

		DBusGMainLoop(set_as_default=True)
		loop = GLib.MainLoop()
		signal.signal(self.signal, lambda sig, frm: loop.quit())

		# XXX: also need pipe in other direction with its fd in glib loop
		while True:
			bus = self._get_bus()
			core = bus.get_object(object_path='/org/pulseaudio/core1')
			for sig_name, sig_handler in (
					('NewSink', ft.partial(notify, op='^')),
					('SinkRemoved', ft.partial(notify, op='v')),
					('NewPlaybackStream', ft.partial(notify, op='+')),
					('PlaybackStreamRemoved', ft.partial(notify, op='-'))):
				bus.add_signal_receiver(sig_handler, sig_name)
				core.ListenForSignal(
					'org.PulseAudio.Core1.{}'.format(sig_name), dbus.Array(signature='o') )
			loop.run()

		raise RuntimeError('Child code broke out of the loop') # should never get here



class PAMixerUIUpdate(Exception): pass # XXX: not needed here?

class PAMixerUI(object): pass

	item_len_min = 10
	bar_len_min = 10
	bar_caps_func = lambda bar='': ' [ ' + bar + ' ]'

	def __init__(self): pass


	# All things curses

	def c_win_init(self):
		win = self.c.newwin(*self.c_win_size())
		win.keypad(True)
		return win

	def c_win_size(self, border):
		'Returns "nlines, ncols, begin_y, begin_x" for e.g. newwin(), taking border into account.'
		size = self.c_stdscr.getmaxyx()
		nlines, ncols = max(1, size[0] - 2 * border), max(1, size[1] - 2 * border)
		return nlines, ncols, min(border, size[0]), min(border, size[1])

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


	def _run(self, stdscr, items, border):
		c, self.c_stdscr = self.c, stdscr

		c.curs_set(0)
		c.use_default_colors()

		win = self.c_win_init()
		hl = next(iter(items)) if items else '' # XXX: still use something like items object?
		optz.adjust_step /= 100.0

		while True:
			self.child_check_restart()

			while items.updates: items.update()
			if not items: items.refresh()
			try: self.c_win_draw(win, items, hl=hl)
			except PAMixerUIUpdate: continue
			if items.updates: continue

			try: key = win.getch()
			except c.error: continue
			log.debug('Keypress event: %s', key)

			try:
				if key in (c.KEY_DOWN, ord('j'), ord('n')): hl = items.next_key(hl)
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


	def run(self, stdscr, items, border=1):
		import curses # has a ton of global state
		self.c = curses
		self.c.wrapper(self._run, items=items, border=border)



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

	opts = parser.parse_args(sys.argv[1:] if args is None else args)

	global log
	logging.basicConfig(level=logging.DEBUG if opts.debug else logging.WARNING)
	log = logging.getLogger()

	conf = conf_defaults.copy()
	conf_file = os.path.expanduser('~/.pulseaudio-mixer-cli.cfg')
	try: conf_file = io.open(conf_file)
	except (OSError, IOError) as err:
		log.debug('Not processing config file %r: %s %s', conf_file, type(err), err)
	else: update_conf_from_file(conf, conf_file)



if __name__ == '__main__': sys.exit(main())

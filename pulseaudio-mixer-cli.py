#!/usr/bin/python
from __future__ import unicode_literals, print_function

import argparse
parser = argparse.ArgumentParser(description='Pulseaudio sound level control tool.')
parser.add_argument('level', action='store', type=str, nargs='?',
	help='Set (just number in range of 0-100) or adjust (+/- number), followed by optional %% sign.')
parser.add_argument('-l', '--max-level', action='store', type=int,
	default=2**16, help='Value to treat as max (default: %(default)s).')
parser.add_argument('-s', '--sink-name', action='store', type=str,
	help='Exact name of the sink to apply adjustments to'
		' (as printed by --list-sinks, first available sink is used by default).')
parser.add_argument('--list-sinks',
	action='store_true', help='Show the list of sinks, registered in pa.')
parser.add_argument('-i', '--interactive',
	action='store_true', help='Adjust per-client volume levels'
		' via curses interface. Implied if no other action is specified.')
parser.add_argument('-a', '--adjust-step', action='store', type=int, default=10,
	help='Adjustment for a single keypress in interactive mode (0-100%%, default: %(default)s%%).')
parser.add_argument('--debug', action='store_true', help='Verbose operation mode.')
argz = parser.parse_args()

import logging
logging.basicConfig(level=logging.DEBUG if argz.debug else logging.INFO)
log = logging.getLogger()


import itertools as it, operator as op, functools as ft
from subprocess import Popen, PIPE, STDOUT
import os, sys, dbus

_sbus = dbus.SessionBus()

def check_bus():
	bus = srv_addr = os.environ.get('PULSE_DBUS_SERVER')
	if not srv_addr:
		srv_addr = _sbus.get_object('org.PulseAudio1', '/org/pulseaudio/server_lookup1')\
			.Get('org.PulseAudio.ServerLookup1', 'Address', dbus_interface='org.freedesktop.DBus.Properties')
	return srv_addr

def get_bus(srv_addr=None, dont_start=False):
	while not srv_addr:
		try:
			srv_addr = check_bus()
			log.debug('Got pa-server bus from dbus: {}'.format(srv_addr))
		except dbus.exceptions.DBusException as err:
			if dont_start or srv_addr is False or\
				err.get_dbus_name() != 'org.freedesktop.DBus.Error.ServiceUnknown': raise
			Popen(['pulseaudio', '--start', '--log-target=syslog'], stdout=open('/dev/null', 'w'), stderr=STDOUT).wait()
			log.debug('Started new pa-server instance')
			## Contrary to docs, "pulseaudio --start" does not mean shit ;(
			from time import sleep
			sleep(1)
			srv_addr = False # to avoid endless loop
	# print(dbus.connection.Connection(srv_addr)\
	# 	.get_object(object_path='/org/pulseaudio/core1')\
	# 	.Introspect(dbus_interface='org.freedesktop.DBus.Introspectable'))
	return dbus.connection.Connection(srv_addr)



if argz.level or argz.list_sinks:
	bus = get_bus()
	sinks = ( dbus.Interface( bus.get_object(object_path=path),
			dbus_interface='org.freedesktop.DBus.Properties' ) for path in bus\
		.get_object(object_path='/org/pulseaudio/core1').Get(
			'org.PulseAudio.Core1', 'Sinks', dbus_interface='org.freedesktop.DBus.Properties' ) )

	if argz.sink_name or argz.list_sinks:
		sinks = dict((sink.Get('org.PulseAudio.Core1.Device', 'Name'), sink) for sink in sinks)
		sink = sinks[argz.sink_name] if argz.sink_name else None
		if argz.list_sinks:
			if sink: log.info(argz.sink_name)
			else:
				for name in sinks: log.info(name)
	else:
		try: sink = next(sinks)
		except StopIteration: sink = None


	if sink and argz.level:
		adj = argz.level.strip('%')
		if not adj: pass
		elif adj[0] in '+-':
			adj = -float(adj[1:]) if adj[0] == '-' else float(adj[1:])
			vols = list(
				max(0, min(1, op.truediv(vol, argz.max_level) + adj / 100))
				for vol in sink.Get('org.PulseAudio.Core1.Device', 'Volume') )
		else: vols = [max(0, min(100, float(adj))) / 100.0]*2

		log.debug('Resulting levels: {:.2f}L {:.2f}R'.format(*vols))
		vols = list(dbus.UInt32(vol * argz.max_level) for vol in vols)

		log.debug('DBus level values: {}'.format(vols))
		sink.Set( 'org.PulseAudio.Core1.Device', 'Volume', vols,
			dbus_interface='org.freedesktop.DBus.Properties' )



if argz.interactive or not (argz.level or argz.list_sinks):
	### Stream changes monitoring thread
	# ...implemented as a subprocess
	# glib loop doesn't seem to release GIL and I don't know
	#  how to combine curses-input and glib loops otherwise

	from io import open
	import signal

	signal.signal(signal.SIGUSR1, signal.SIG_IGN)
	fd_out, fd_in = os.pipe()
	core_pid = os.getpid()
	child_pid = os.fork()

	if not child_pid:
		from dbus.mainloop.glib import DBusGMainLoop
		import gobject

		os.close(fd_out)
		pipe = open(fd_in, 'wb', buffering=0)
		pipe.write('\n') # wait for main process to get ready
		log.debug('Signal handler thread started')

		DBusGMainLoop(set_as_default=True)
		loop = gobject.MainLoop()
		signal.signal(signal.SIGUSR1, lambda sig,frm: loop.quit())

		def notify(path, op):
			os.kill(core_pid, signal.SIGUSR1)
			try: pipe.write('{} {}\n'.format(op, path))
			except: loop.quit()

		while True:
			bus = get_bus()
			core = bus.get_object(object_path='/org/pulseaudio/core1')
			for sig_name, sig_handler in (
					('NewPlaybackStream', ft.partial(notify, op='+')),
					('PlaybackStreamRemoved', ft.partial(notify, op='-')) ):
				bus.add_signal_receiver(sig_handler, sig_name)
				core.ListenForSignal( 'org.PulseAudio.Core1.{}'\
					.format(sig_name), dbus.Array(signature='o') )
			loop.run()

	else:
		os.close(fd_in)
		pipe = open(fd_out, 'rb', buffering=0)


	### UI backend

	from collections import deque
	from time import time
	import re # for some templating

	class PAUpdate(Exception): pass

	class PAMenu(dict):
		# OrderedDict doesn't seem to handle clear+update correctly in py2.7
		updates = deque()
		_val_cache = dict()

		def __init__(self, cache_time=2):
			self._cache_time = cache_time
			super(PAMenu, self).__init__()
			self.refresh(soft=False)
			signal.signal(signal.SIGUSR1, self.update_handler)
			pipe.readline() # unblock child


		def _dbus_dec(self, prop): return unicode(bytearray(it.ifilter(None, prop)))
		def _client_name(self, props):
			name = self._dbus_dec(props['application.name'])
			ext = '({application.process.user}@'\
				'{application.process.host}:{application.process.id})'
			try:
				name = '{} {}'.format( name, re.sub(r'\{([^}]+)\}', r'{}', ext)\
					.format(*it.imap(self._dbus_dec, op.itemgetter(*re.findall(r'\{([^}]+)\}', ext))(props))) )
			except KeyError: pass
			return name

		def add(self, path):
			stream = dbus.Interface(
				self.bus.get_object(object_path=path),
				dbus_interface='org.freedesktop.DBus.Properties' )
			name = self._client_name(dict(stream.Get(
				'org.PulseAudio.Core1.Stream', 'PropertyList' )))
			self[name] = stream
			if len(name) > self.max_key_len: self.max_key_len = len(name)
			return name

		def remove(self, path):
			for name,stream in self.viewitems():
				if stream.object_path == path: break
			else: return
			del self[name]
			if len(name) == self.max_key_len:
				self.max_key_len = max(it.imap(len, self)) if self else 0

		def refresh(self, soft=True):
			log.debug('PA-refresh initiated')
			if not soft:
				self.clear()
				self.bus = get_bus()
			self._val_cache.clear()
			self.max_key_len = 0 # should be recalculated from these entries only
			try:
				new_names = set(it.imap( self.add, self.bus\
					.get_object(object_path='/org/pulseaudio/core1')\
					.Get( 'org.PulseAudio.Core1', 'PlaybackStreams',
						dbus_interface='org.freedesktop.DBus.Properties' ) ))
			except dbus.exceptions.DBusException: # bus is probably abandoned
				if soft: self.refresh(soft=False)
				else: raise
			else:
				if not soft: os.kill(child_pid, signal.SIGUSR1) # break glib loop to reacquire the bus
				else:
					# self.remove checks are not needed here
					for name in new_names.difference(self): del self[name]

		def update(self):
			while self.updates:
				action, path = self.updates.popleft()
				(self.add if action == '+' else self.remove)(path)

		def update_handler(self, sig, frm):
			self.updates.append(pipe.readline().strip().split(' ', 1))


		def _get(self, item):
			return self[item].Get('org.PulseAudio.Core1.Stream', 'Volume')
		def get(self, item, raw=False):
			try: val, ts = self._val_cache[item]
			except KeyError: val = None
			ts_chk = time()
			if val is None or ts < ts_chk - self._cache_time:
				try:
					try: val = self._get(item)
					except dbus.exceptions.DBusException:
						self.refresh()
						val = self._get(item)
				except KeyError: raise PAUpdate
				val = tuple(op.truediv(val, argz.max_level) for val in val)
				self._val_cache[item] = val, ts_chk
			return (sum(val) / len(val)) if not raw else val # average of channels

		def _set(self, item, val):
			return self[item].Set( 'org.PulseAudio.Core1.Stream',
				'Volume', val, dbus_interface='org.freedesktop.DBus.Properties' )
		def set(self, item, val):
			val = [max(0, min(1, val))] * len(self.get(item, raw=True)) # all channels to the same level
			val_dbus = list(dbus.UInt32(round(val * argz.max_level)) for val in val)
			try:
				try: self._set(item, val_dbus)
				except dbus.exceptions.DBusException:
					self.refresh()
					self._set(item, val_dbus)
			except KeyError: raise PAUpdate
			self._val_cache[item] = val, time()


		def next_key(self, item):
			try: return list(it.dropwhile(lambda k: k != item, self))[1]
			except IndexError: return next(iter(self)) if self else ''
		def prev_key(self, item):
			try: return list(it.dropwhile(lambda k: k != item, reversed(self)))[1]
			except IndexError: return next(reversed(self)) if self else ''

		def __iter__(self, reverse=False):
			return iter(sorted(self.viewkeys(), reverse=reverse, key=op.itemgetter(0)))
		def __reversed__(self): return self.__iter__(reverse=True)

		def __del__(self):
			try: os.kill(child_pid, signal.SIGTERM)
			except OSError: pass


	### UI rendering / input loop

	from curses.wrapper import wrapper
	import curses

	def cli_draw(win, items, hl=None):
		win.erase() # remove old lines
		for row,item in enumerate(items):
			attrs = curses.A_REVERSE if item == hl else curses.A_NORMAL
			win.addstr(row, 0, item, attrs)

			bar_canvas = lambda bar='': ' [ ' + bar + ' ]'
			bar_len = win.getmaxyx()[1] - items.max_key_len - len(bar_canvas())
			bar_fill = int(round(items.get(item) * bar_len))
			bar = bar_canvas('#'*bar_fill + '-'*(bar_len-bar_fill))
			win.addstr(row, items.max_key_len, bar)

	def interactive_cli(stdscr, items, border=0):
		curses.curs_set(0)
		curses.use_default_colors()

		win_geom = stdscr.getmaxyx()
		win_geom = win_geom[0] - 2*border, win_geom[1] - 2*border, border, border
		win = curses.newwin(*win_geom)
		win.keypad(True)

		hl = next(iter(items)) if items else ''
		argz.adjust_step /= 100.0

		while True:
			if os.waitpid(child_pid, os.WNOHANG)[0]:
				log.fatal('DBus signal monitor died unexpectedly')
				sys.exit(1)

			while items.updates: items.update()
			if not items: items.refresh()

			try: cli_draw(win, items, hl=hl)
			except PAUpdate: continue

			if items.updates: continue

			try: key = win.getch()
			except curses.error: continue
			log.debug('Keypress event: {}'.format(key))

			try:
				if key in (curses.KEY_DOWN, curses.KEY_UP):
					hl = (items.next_key if key == curses.KEY_DOWN else items.prev_key)(hl)
				elif key in (curses.KEY_LEFT, curses.KEY_RIGHT):
					adj = (1 if key == curses.KEY_RIGHT else -1) * argz.adjust_step
					items.set(hl, items.get(hl) + adj)
				elif key < 255 and key > 0 and chr(key) == 'q': exit()
			except PAUpdate: continue

	wrapper(interactive_cli, items=PAMenu(), border=1)



log.debug('Finished')

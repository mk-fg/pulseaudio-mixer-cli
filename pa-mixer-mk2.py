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
		self.signal = sig


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


	def start(self):
		signal.signal(self.signal, signal.SIG_IGN)
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



class PAMixerUIUpdate(Exception): pass

class PAMixerUI(object): pass







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

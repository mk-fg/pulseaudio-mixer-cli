#!/usr/bin/python
# -*- coding: utf-8 -*-
from __future__ import print_function

import itertools as it, operator as op, functools as ft
from collections import deque, OrderedDict
import ConfigParser as configparser
import os, sys, io, logging, re, time, types, string
import json, subprocess, signal, fcntl, base64, hashlib


class Conf(object):

	adjust_step = 5
	max_level = 2 ** 16
	use_media_name = False
	verbose = False
	debug = False

def update_conf_from_file(conf, path_or_file):
	if isinstance(path_or_file, types.StringTypes): path_or_file = io.open(path_or_file)
	with path_or_file as src:
		config = configparser.SafeConfigParser(allow_no_value=True)
		config.readfp(src)
	for k in dir(conf):
		if k.startswith('_'): continue
		v = getattr(conf, k)
		get_val = config.getint if not isinstance(v, bool) else config.getboolean
		for k in k, k.replace('_', '-'):
			try: setattr(conf, k, get_val('default', k))
			except configparser.Error: pass


dbus_abbrevs = dict(
	pulse='org.PulseAudio.Core1',
	props='org.freedesktop.DBus.Properties' )
dbus_abbrev = lambda k: dbus_abbrevs.get(k, k)
dbus_join = lambda *parts: '.'.join(map(dbus_abbrev, parts[:-1]) + parts[-1])


def dbus_bytes(dbus_arr, strip='\0' + string.whitespace):
	return bytes(bytearray(dbus_arr).strip(strip))

def strip_dbus_types(data):
	# Necessary because dbus types subclass python types,
	#  yet don't serialize in the same way - e.g. str(dbus.Byte(1)) is '\x01'
	#  (and not '1') - which messes up simple serializers like "json" module.
	sdt = strip_dbus_types
	if isinstance(data, dict): return dict((sdt(k), sdt(v)) for k,v in data.viewitems())
	elif isinstance(data, (list, tuple)):
		if data.signature == 'y': return dbus_bytes(data)
		return map(sdt, data)
	elif isinstance(data, types.NoneType): return data
	for t in int, long, unicode, bytes, bool:
		if isinstance(data, t): return t(data)
	raise ValueError(( 'Failed to sanitize data type:'
		' {} (mro: {}, value: {})' ).format(type(data), type(data).mro(), data))


def uid_str(seed=None, length=4):
	seed_bytes = length * 6 / 8
	assert seed_bytes * 8 / 6 == length, [length, seed_bytes]
	if seed is None: seed = os.urandom(seed_bytes)
	else: seed = hashlib.sha256(seed).digest()[:seed_bytes]
	return base64.urlsafe_b64encode(seed)

def force_bytes(bytes_or_unicode, encoding='utf-8', errors='backslashreplace'):
	if isinstance(bytes_or_unicode, bytes): return bytes_or_unicode
	return bytes_or_unicode.encode(encoding, errors)

def force_unicode(bytes_or_unicode, encoding='utf-8', errors='replace'):
	if isinstance(bytes_or_unicode, unicode): return bytes_or_unicode
	return bytes_or_unicode.decode(encoding, errors)

def to_bytes(obj, **conv_kws):
	if not isinstance(obj, types.StringTypes): obj = bytes(obj)
	return force_bytes(obj)


class PAMixerDBusBridgeError(Exception): pass
class PAMixerDBusError(Exception): pass

class PAMixerDBusBridge(object):
	'''Class to import/spawn glib/dbus eventloop in a
			subprocess and communicate with it via signals and pipes.
		Presents async kinda-rpc interface to a dbus loop running in separate pid.
		Protocol is json lines over stdin/stdout pipes,
			with signal sent to parent pid on any dbus async event (e.g. signal) from child.'''

	signal = signal.SIGUSR1 # used to break curses loop in the parent pid

	def __init__(self, child_cmd=None, fatal=False):
		self.child_cmd, self.core_pid, self.fatal = child_cmd, os.getppid(), fatal
		self.child_sigs, self.child_calls, self._child, self._child_gc = deque(), dict(), None, set()


	def _child_readline(self, wait_for_cid=None, one_signal=False, init_line=False):
		while True:
			if wait_for_cid and wait_for_cid in self.child_calls:
				# XXX: check for errors indicating that dbus is gone here?
				line = self.child_calls[wait_for_cid]
				self.child_calls.clear()
				return line
			line = self._child.stdout.readline().strip()
			if init_line:
				assert line.strip() == 'ready', repr(line)
				break
			log.debug('rpc-parent << %r', line)
			line = json.loads(line)
			if line['t'] == 'signal':
				self.child_sigs.append(line)
				if one_signal: break
			elif line['t'] in ['call_result', 'call_error']: self.child_calls[line['cid']] = line

	def call(self, func, args, **call_kws):
		self.child_check_restart()
		cid = uid_str()
		call = dict(t='call', cid=cid, func=func, args=args, **call_kws)
		try: call = json.dumps(call)
		except Exception as err:
			log.exception('Failed to encode data to json (error: %s), returning None: %r', err, call)
			return None
		assert '\n' not in call, repr(call)
		for n in xrange(2): # even 2 is kinda generous - likely to be some bug
			try:
				log.debug('rpc-parent >> %r', call)
				self._child.stdin.write('{}\n'.format(call))
				res = self._child_readline(wait_for_cid=cid)
			except Exception as err:
				log.exception('Failure communicating with child pid, restarting it: %s', err)
				if self.fatal: break
				self.child_kill()
				self.child_check_restart()
			else: break
		else: raise PAMixerDBusBridgeError('Failed to communicate with child pid')
		if res['t'] == 'call_error': raise PAMixerDBusError(res['err_type'], res['err_msg'])
		assert res['t'] == 'call_result', res
		return res['val']


	def install_signal_handler(self, func):
		self.signal_func = func
		signal.signal(self.signal, self.signal_handler)
		# Async signals also require async detection of when child died
		signal.signal(signal.SIGCHLD, self.child_check_restart)

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

	def child_kill(self):
		if self._child:
			child, self._child = self._child, None
			self._child_gc.append(child.pid)
			try: child.kill() # no need to be nice here
			except OSError: pass

	def child_check_restart(self, sig=None, frm=None): # XXX: call implicitly on and comm errors
		if self._child_gc: # these are cleaned-up just to avoid keeping zombies around
			for pid in list(self._child_gc):
				try: res = os.waitpid(pid, os.WNOHANG)
				except OSError: res = pid, None
				if res and res[0]: self._child_gc.remove(pid)
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


	def _loop_exc_stop(self, exc_info=None):
		self.loop_exc = exc_info or sys.exc_info()
		assert self.loop_exc
		self.loop.quit()

	def _glib_err_wrap(func):
		@ft.wraps(func)
		def _wrapper(self, *args, **kws):
			try: func(self, *args, **kws)
			except Exception as err:
				exc_info = sys.exc_info()
				log.exception('glib handler failed: %s', err)
				self._loop_exc_stop(exc_info)
			return True # glib disables event handler otherwise
		return _wrapper

	@_glib_err_wrap
	def _core_notify(self, _signal=False, **kws):
		chunk = dict(**kws)
		log.debug('rpc-child >> %s', chunk)
		chunk = json.dumps(chunk)
		assert '\n' not in chunk, chunk
		try:
			if _signal: os.kill(self.core_pid, self.signal)
			self.stdout.write('{}\n'.format(chunk))
		except (OSError, IOError):
			return self.loop.quit() # parent is gone, we're done too

	@_glib_err_wrap
	def _rpc_call(self, buff, stream=None, ev=None):
		assert stream is self.stdin, [stream, self.stdin]

		if ev is None: ev = self._gobj.IO_IN
		if ev & (self._gobj.IO_ERR | self._gobj.IO_HUP):
			return self.loop.quit() # parent is gone, we're done too
		elif ev & self._gobj.IO_IN:
			while True:
				chunk = self.stdin.read(2**20)
				if not chunk: break
				# log.debug('rpc-child-raw << %r', chunk)
				buff.append(chunk)
			while True:
				# Detect if there are any full requests buffered
				for n, chunk in enumerate(buff):
					if '\n' in chunk: break
				else: break # no more full requests

				# Read/decode next request from buffer
				req = list()
				for m in xrange(n+1):
					chunk = buff.popleft()
					if m == n:
						chunk, chunk_next = chunk.split('\n', 1)
						buff.appendleft(chunk_next)
					assert '\n' not in chunk, chunk
					req.append(chunk)
				req = json.loads(''.join(req))
				log.debug('rpc-child << %s', req)

				# Run dbus call and return the result, synchronously
				assert req['t'] == 'call', req
				func, kws = req['func'], dict()
				obj_path, iface = req.get('obj'), req.get('iface')
				if iface: kws['dbus_interface'] = dbus_abbrev(iface)
				obj = self.core if not obj_path\
					else self.bus.get_object(object_path=obj_path) # XXX: bus gone handling
				try: res = getattr(obj, func)(*req['args'], **kws)
				except self._dbus.exceptions.DBusException as err:
					self._core_notify( t='call_error', cid=req['cid'],
						err_type=err.get_dbus_name(), err_msg=err.message )
				else:
					res = strip_dbus_types(res)
					self._core_notify(t='call_result', cid=req['cid'], val=res)
		else:
			log.warn('Unrecognized event type from glib: %r', ev)

	@_glib_err_wrap
	def _relay_signal(self, obj_path, sig_name):
		self._core_notify(_signal=True, t='signal', sig_name=sig_name, obj=obj_path)


	def child_run(self):
		from dbus.mainloop.glib import DBusGMainLoop
		from gi.repository import GLib, GObject
		import dbus

		def excepthook(t, v, tb, hook=sys.excepthook):
			time.sleep(0.2) # to dump parent/child tracebacks non-interleaved
			return hook(t, v, tb)
		sys.excepthook = excepthook

		self._dbus, self._gobj = dbus, GObject

		# Disable stdin/stdout buffering
		self.stdout = io.open(sys.stdout.fileno(), 'wb', buffering=0)
		self.stdin = io.open(sys.stdin.fileno(), 'rb', buffering=0)

		self.stdout.write('ready\n') # wait for main process to get ready, signal readiness
		log.debug('DBus signal handler thread started')

		DBusGMainLoop(set_as_default=True)
		self.loop, self.loop_exc = GLib.MainLoop(), None

		self.bus = self._get_bus() # XXX: bus gone handling
		self.core = self.bus.get_object(object_path='/org/pulseaudio/core1')

		rpc_buffer = deque()
		flags = fcntl.fcntl(self.stdin, fcntl.F_GETFL)
		fcntl.fcntl(self.stdin, fcntl.F_SETFL, flags | os.O_NONBLOCK)
		self._gobj.io_add_watch( self.stdin,
			self._gobj.IO_IN | self._gobj.IO_ERR | self._gobj.IO_HUP,
			ft.partial(self._rpc_call, rpc_buffer) )

		for sig_name in [
				'NewSink', 'SinkRemoved', 'NewPlaybackStream', 'PlaybackStreamRemoved']:
			self.bus.add_signal_receiver(ft.partial(self._relay_signal, sig_name=sig_name), sig_name)
			self.core.ListenForSignal(
				'org.PulseAudio.Core1.{}'.format(sig_name), self._dbus.Array(signature='o') )
		self.loop.run()
		# XXX: wrapper loop here, in case of *clean* loop.quit() yet dbus not being dead
		if self.loop_exc: raise self.loop_exc[0], self.loop_exc[1], self.loop_exc[2]



class PAMixerMenuItem(object):

	dbus_types = dict(sink='Device', stream='Stream')

	def __init__(self, menu, obj_type, obj_path):
		self.menu, self.t, self.conf, self.call = menu, obj_type, menu.conf, menu.call
		self.dbus_path, self.dbus_type = obj_path, dbus_join('pulse', [self.dbus_types[self.t]])
		self.name = self._get_name()

	def __repr__(self):
		return '<{}[{:x}] {}[{}]: {}>'.format(
			self.__class__.__name__, id(self), self.t, uid_str(self.dbus_path), self.name )


	def _get_name_unique(self, name):
		return '{} #{}'.format(force_bytes(name), uid_str())

	def _get_name_descriptive(self):
		'Can probably fail with KeyError if something is really wrong with stream/device props.'
		props = self.call('Get', [self.dbus_type, 'PropertyList'], obj=self.dbus_path, iface='props')

		if self.t == 'stream':
			if self.conf.use_media_name:
				name = props.get('media.name')
				if name and name not in self.conf.placeholder_media_names: return name
			try: name = props['application.name']
			except KeyError: # some synthetic stream with non-descriptive name
				name = self._get_name_unique(props['media.name'])
			ext = '({application.process.user}@'\
				'{application.process.host}:{application.process.id})'

		elif self.t == 'sink':
			name = props.get('alsa.id')
			if not name:
				try: name = '{}.{}'.format(props['device.api'], props['device.string'])
				except KeyError:
					self._get_name_unique(props['device.description'])
			ext = '({device.profile.name}@{alsa.driver_name})'

		else: raise KeyError('Unknown menu-item type (for naming): {}'.format(self.t))

		try:
			name = '{} {}'.format( name,
				re.sub(r'\{([^}]+)\}', r'{}', ext).format(
					*op.itemgetter(*re.findall(r'\{([^}]+)\}', ext))(props) ) )
		except KeyError as err:
			log.debug( 'Unable to get extended descriptive name'
				' (trype: %r, path: %s) due to missing key: %s', self.t, self.dbus_path, err )
		return name

	def _get_name(self):
		try: return self._get_name_descriptive()
		except Exception as err:
			if self.menu.fatal: raise
			log.info('Failed to get descriptive name for %r: %s', self.t, self.dbus_path)
		return self._get_name_unique(self.t)


	def _dbus_prop(name, dbus_name=None):
		dbus_name = dbus_name or name.title()
		def dbus_prop_get(self):
			return self.call('Get', [self.dbus_type, dbus_name], obj=self.dbus_path, iface='props')
		def dbus_prop_set(self, val):
			return self.call('Set', [self.dbus_type, dbus_name, val], obj=self.dbus_path, iface='props')
		return property( dbus_prop_get, dbus_prop_set,
			lambda: None, 'DBus {} property proxy'.format(dbus_name) )

	muted = _dbus_prop('mute')
	volume = _dbus_prop('volume')

	def volume_change(self, delta): self.volume += delta


	def pick_next(self): PAMixerMenuItem # XXX
	def pick_prev(self): PAMixerMenuItem # XXX


class PAMixerMenu(object):

	def __init__(self, dbus_bridge, conf=None, fatal=False):
		self.call, self.fatal = dbus_bridge.call, fatal
		self.conf, self.items = conf or Conf(), OrderedDict()

	def update_signal(self, name, obj):
		log.debug('update_signal << %s %s', name, obj)

	@property
	def item_list(self):
		for obj_type, prop in [('sink', 'Sinks'), ('stream', 'PlaybackStreams')]:
			'Get', [dbus_abbrev('pulse'), prop], 'props'
			for obj_path in self.call('Get', [dbus_abbrev('pulse'), prop], iface='props'):
				self.items[obj_path] = PAMixerMenuItem(self, obj_type, obj_path)
		return self.items.values()

	@property
	def item_len_max(self):
		return max(len(item.name) for item in self.item_list)





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
	conf = Conf()
	conf_file = os.path.expanduser('~/.pulseaudio-mixer-cli.cfg')
	try: conf_file = io.open(conf_file)
	except (OSError, IOError) as err: pass
	else: update_conf_from_file(conf, conf_file)

	import argparse
	parser = argparse.ArgumentParser(description='Command-line PulseAudio mixer tool.')

	parser.add_argument('-a', '--adjust-step',
		action='store', type=int, metavar='step', default=conf.adjust_step,
		help='Adjustment for a single keypress in interactive mode (0-100%%, default: %(default)s%%).')
	parser.add_argument('-l', '--max-level',
		action='store', type=int, metavar='level', default=conf.max_level,
		help='Value to treat as max (default: %(default)s).')
	parser.add_argument('-n', '--use-media-name',
		action='store_true', default=conf.use_media_name,
		help='Display streams by "media.name" property, if possible.'
			' Default is to prefer application name and process properties.')

	parser.add_argument('-v', '--verbose',
		action='store_true', default=conf.verbose,
		help='Dont close stderr to see any sort of errors (which'
			' mess up curses interface, thus silenced that way by default).')
	parser.add_argument('--debug', action='store_true',
		default=conf.debug, help='Verbose operation mode.')
	parser.add_argument('--fatal', action='store_true',
		help='Dont try too hard to recover from errors. For debugging purposes only.')

	parser.add_argument('--child-pid-do-not-use', action='store_true',
		help='Used internally to spawn dbus sub-pid, should not be used directly.')
	opts = parser.parse_args(sys.argv[1:] if args is None else args)

	global log
	logging.basicConfig(level=logging.DEBUG if opts.debug else logging.WARNING)
	log = logging.getLogger()

	if opts.child_pid_do_not_use:
		global print
		print = ft.partial(print, file=sys.stderr)
		try: return PAMixerDBusBridge().child_run()
		except PAMixerDBusBridgeError as err:
			log.info('PAMixerDBusBridgeError event in a child pid: %s', err)
			argv = self_exec_cmd(sys.argv)
			os.closerange(3, max(map(int, os.listdir('/proc/self/fd'))) + 1)
			os.execvp(*argv)

	dbus_bridge = ['--child-pid-do-not-use']
	if opts.debug: dbus_bridge += ['--debug']
	dbus_bridge = PAMixerDBusBridge(self_exec_cmd(*dbus_bridge), fatal=opts.fatal)
	menu = PAMixerMenu(dbus_bridge, conf, fatal=opts.fatal)
	dbus_bridge.install_signal_handler(menu.update_signal)
	dbus_bridge.child_start()
	curses_ui = PAMixerUI(menu)

	log.debug('Starting curses ui loop...')
	curses_ui.run()
	log.debug('Finished')


if __name__ == '__main__': sys.exit(main())

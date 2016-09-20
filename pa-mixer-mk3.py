#!/usr/bin/env python3

import itertools as it, operator as op, functools as ft
from collections import OrderedDict, defaultdict, deque
from contextlib import contextmanager
import os, sys, re, time, logging, configparser
import base64, hashlib, unicodedata
import signal, threading

from pulsectl import Pulse, PulseLoopStop, PulseDisconnected, PulseIndexError


class LogMessage(object):
	def __init__(self, fmt, a, k): self.fmt, self.a, self.k = fmt, a, k
	def __str__(self): return self.fmt.format(*self.a, **self.k) if self.a or self.k else self.fmt

class LogStyleAdapter(logging.LoggerAdapter):
	def __init__(self, logger, extra=None):
		super(LogStyleAdapter, self).__init__(logger, extra or {})
	def log(self, level, msg, *args, **kws):
		if not self.isEnabledFor(level): return
		log_kws = {} if 'exc_info' not in kws else dict(exc_info=kws.pop('exc_info'))
		msg, kws = self.process(msg, kws)
		self.logger._log(level, LogMessage(msg, args, kws), (), log_kws)

get_logger = lambda name: LogStyleAdapter(logging.getLogger(name))


def uid_str( seed=None, length=4,
		_seed_gen=it.chain.from_iterable(map(range, it.repeat(2**30))) ):
	seed_bytes = length * 6 // 8
	assert seed_bytes * 8 // 6 == length, [length, seed_bytes]
	if seed is None: seed = '\0\0\0{:08x}'.format(next(_seed_gen))
	seed = hashlib.sha256(bytes(seed, encoding='utf-8')).digest()[:seed_bytes]
	return base64.urlsafe_b64encode(seed).decode()


class Conf(object):
	def __repr__(self): return repr(vars(self))

	adjust_step = 5.0 # percent, 0-100
	# Volume values are relative to "normal" (non-soft-boosted) pulseaudio volume
	max_volume = 1.0 # relative value, displayed as "100%"
	min_volume = 0.01 # relative value, displayed as "0%"

	use_device_name = False
	use_media_name = False
	placeholder_media_names = 'audio stream', 'AudioStream', 'Output', 'ALSA Playback'
	name_len_max = 100
	name_cut_from = 'left' # "left" or "right"
	name_show_level = True

	overkill_redraw = False # if terminal gets resized often, might cause noticeable flickering
	verbose = False
	reconnect = True
	show_stored_values = True
	show_controls = True

	stream_params = None
	broken_chars_replace = '_'
	focus_default = 'first' # either "first" or "last"
	focus_new_items = True
	focus_new_items_delay = 5.0 # min seconds since last focus change to trigger this

	# Whether to wrap focus when going past first/last item
	focus_wrap_first = False
	focus_wrap_last = False

	@staticmethod
	def parse_bool(val, _states={
			'1': True, 'yes': True, 'true': True, 'on': True,
			'0': False, 'no': False, 'false': False, 'off': False }):
		try: return _states[val.lower()]
		except KeyError: raise ValueError(val)


def conf_read(path=None, base=None):
	conf, conf_file = base or Conf(),\
		os.path.expanduser(path or conf_read.path_default)
	try: conf_file = open(conf_file)
	except (OSError, IOError) as err: pass
	else: conf_update_from_file(conf, conf_file)
	return conf
conf_read.path_default = '~/.pulseaudio-mixer-cli.cfg'

def conf_update_from_file(conf, path_or_file):
	if isinstance(path_or_file, str): path_or_file = open(path_or_file)
	with path_or_file as src:
		config = configparser.RawConfigParser(
			allow_no_value=True, inline_comment_prefixes=(';',) )
		config.readfp(src)

	for k in dir(conf):
		if k.startswith('_'): continue
		v = getattr(conf, k)
		if isinstance(v, str): get_val = lambda *a: str(config.get(*a))
		elif isinstance(v, bool): get_val = config.getboolean
		elif isinstance(v, int): get_val = config.getint
		elif isinstance(v, float): get_val = lambda *a: float(config.get(*a))
		else: continue # values with other types cannot be specified in config
		for k_conf in k, k.replace('_', '-'):
			try: setattr(conf, k, get_val('default', k_conf))
			except configparser.Error: pass

	conf.stream_params = OrderedDict(conf.stream_params or dict())
	conf.stream_params_reapply = list() # ones to re-apply on every event
	for sec in config.sections():
		if not re.search(r'^stream\b.', sec): continue
		params = list()
		for k, v in config.items(sec):
			match = re.search(r'^(match|equals)\[(.*)\]$', k)
			if match:
				v = re.compile(r'^{}$'.format(re.escape(v)) if match.group(1) == 'equals' else v)
				params.append(('match', match.group(2), v))
			else: params.append(('set', k, v))
			if k == 'reapply' and conf.parse_bool(v):
				conf.stream_params_reapply.append(sec)
		conf.stream_params[sec] = params


class PAMixerMenu(object):

	items, conf = tuple(), Conf()

	def update(self): return

	@property
	def item_list(self): return list(self.items)

	def item_default(self):
		items = self.item_list
		if not items: return
		return items[0]

	def item_newer(self, ts): return

	def item_id(self, item): return item.uid

	def item_after(self, item=None):
		if item:
			for item2 in self.items:
				if item is StopIteration: return item2
				if self.item_id(item2) == self.item_id(item): item = StopIteration
			if item == StopIteration:
				return self.items[0] if self.conf.focus_wrap_last else item2
		return self.item_default()

	def item_before(self, item=None):
		if item:
			item_prev = None
			for item2 in self.items:
				if self.item_id(item2) == self.item_id(item):
					if not item_prev:
						return self.items[-1] if self.conf.focus_wrap_first else item2
						break
					return item_prev
				item_prev = item2
		return self.item_default()


class PAMixerReconnect(Exception): pass

class PAMixerEvent(object):
	__slots__ = 'obj_type obj_index t'.split()
	pulsectl_facility_map = dict(sink='sink', sink_input='stream')
	@classmethod
	def from_pulsectl_ev(cls, ev):
		obj_type = cls.pulsectl_facility_map.get(ev.facility)
		if not obj_type: return
		return cls(obj_type, ev.index, ev.t)
	def __init__(self, obj_type, obj_index, t=None):
		self.obj_type, self.obj_index, self.t = obj_type, obj_index, t
	def __str__(self): return repr(dict((k, getattr(self, k)) for k in self.__slots__))

class PAMixerStreamsItem(object):

	def __init__(self, streams, obj_t, obj_id, obj):
		self.streams, self.conf = streams, streams.conf
		self.t, self.uid = obj_t, obj_id
		self.hidden = self.name_custom = False
		self.created_ts = time.monotonic()
		self.update(obj)

		if self.conf.dump_stream_params:
			from pprint import pprint
			dump = OrderedDict(uid=self.uid, name=self.name)
			dump['props'] = sorted(self.obj.proplist.items())
			pprint(dump, sys.stderr)

	def __repr__(self):
		return '<{}[{:x}] {}[{}]: {}>'.format(
			self.__class__.__name__, id(self), self.t, self.uid, self.name )

	def update(self, obj=None):
		if obj: self.obj = obj
		if not self.name_custom: self.name_update()

	def name_update(self, name=None):
		if not name: name = self._get_name() or 'knob'
		else: self.name_custom = True
		self.name_base = self.name = name

	def _get_name(self):
		try: return self._get_name_descriptive()
		except Exception as err:
			if self.streams.fatal: raise
			log.info('Failed to get descriptive name for {!r} ({}): {}', self.t, self.uid, err)
		return self.t

	def _get_name_descriptive(self):
		'Can probably fail with KeyError if something is really wrong with stream/device props.'
		ext, props = None, dict(
			(k, self._strip_noise_bytes(v, self.conf.broken_chars_replace))
			for k, v in self.obj.proplist.items() )

		if self.t == 'stream':
			if self.conf.use_media_name:
				name = props.get('media.name')
				if name and name not in self.conf.placeholder_media_names: return name
			try: name = props['application.name']
			except KeyError: name = props['media.name'] # some synthetic stream with non-descriptive name
			ext = '({application.process.user}@'\
				'{application.process.host}:{application.process.id})'

		elif self.t == 'sink':
			if self.conf.use_device_name: name = self.obj.name
			else:
				name = props.get('alsa.id')\
					or props.get('device.description') or props.get('device.api')
				if not name:
					try: name = '{}.{}'.format(props['device.api'], props['device.string'])
					except KeyError: name = props['device.description']
				ext = '({device.profile.name}@{alsa.driver_name})'

		else: raise KeyError('Unknown streams-item type (for naming): {}'.format(self.t))

		if ext:
			try:
				name = '{} {}'.format( name,
					re.sub(r'\{([^}]+)\}', r'{}', ext).format(
						*op.itemgetter(*re.findall(r'\{([^}]+)\}', ext))(props) ) )
			except KeyError as err:
				log.debug( 'Unable to get extended descriptive name'
					' (type: {!r}, uid: {}) due to missing key: {}', self.t, self.uid, err )
		return name

	def _strip_noise_bytes(self, obj, replace='_'):
		'''Make sure there arent any random weird chars that dont belong to any alphabet.
			Only ascii non-letters are allowed, as fancy symbols don't seem to work well with curses.'''
		if not isinstance(obj, str): obj = str(obj)
		obj_ucs = list()
		for uc in obj:
			try:
				unicodedata.name(uc)
				if unicodedata.category(uc) != 'Ll': uc.encode('ascii')
			except (ValueError, UnicodeEncodeError):
				if replace: obj_ucs.append(replace)
			else: obj_ucs.append(uc)
		return ''.join(obj_ucs)

	@property
	def muted(self):
		return bool(self.obj.mute)
	@muted.setter
	def muted(self, val):
		self.obj.mute = int(val)
		with self.streams.update_wakeup() as pulse: pulse.mute(self.obj, self.obj.mute)

	@property
	def volume(self):
		'Volume as one float in 0-1 range.'
		return min(1.0, max(0,
			self.obj.volume.value_flat - self.conf.min_volume ) / float(self.conf.max_volume))
	@volume.setter
	def volume(self, val):
		val_pulse = min(1.0, max(0, val)) * self.conf.max_volume + self.conf.min_volume
		log.debug('Setting volume: {} (pulse: {}) for {}', val, val_pulse, self)
		with self.streams.update_wakeup() as pulse: pulse.volume_set_all_chans(self.obj, val_pulse)

	@property
	def port(self):
		if self.t != 'sink': return
		return self.obj.port_active
	@port.setter
	def port(self, name):
		if self.t != 'sink':
			log.warning( 'Setting ports is only'
				' available for {!r}-type streams, not {!r}-type', 'sink', self.t )
		with self.streams.update_wakeup() as pulse: pulse.port_set(self.obj, name)


	def muted_toggle(self): self.muted = not self.muted
	def volume_change(self, delta):
		log.debug('Volume update: {} -> {} [{}]', self.volume, self.volume + delta, delta)
		self.volume += delta

	def get_next(self): return self.streams.item_after(self)
	def get_prev(self): return self.streams.item_before(self)


class PAMixerStreams(PAMixerMenu):

	focus_policies = dict(first=op.itemgetter(0), last=op.itemgetter(-1))

	def __init__(self, pulse, conf=None, fatal=False):
		self.pulse, self.fatal, self.conf = pulse, fatal, conf or Conf()
		self.items, self.item_objs = list(), OrderedDict()
		self.connected, self._updates = None, deque()
		self._pulse_hold, self._pulse_lock = threading.Lock(), threading.Lock()

	def update(self):
		while True:
			try: ev = self._updates.popleft()
			except: ev = None

			# Restarts whole thing with new pulse connection
			if self.connected is False: raise PAMixerReconnect()

			# Add/remove/update items
			obj_new, obj_gone = set(), set()
			obj_id_func = lambda t,index: '{}-{}'.format(t, index)
			if not ev: obj_gone.update(self.item_objs) # i.e. replace whole list
			with self.update_wakeup(trap_errors=False) as pulse:
				for obj_t, obj_list_func, obj_info_func in\
						[ ('sink', pulse.sink_list, pulse.sink_info),
							('stream', pulse.sink_input_list, pulse.sink_input_info) ]:

					obj_list_full = obj_list = None # "replace all" vs "new/update X"
					if not ev: obj_list_full = obj_list_func()
					elif ev.obj_type != obj_t: continue
					elif ev.t == 'remove': obj_gone.add(obj_id_func(obj_t, ev.obj_index))
					else:
						try: obj_list = [obj_info_func(ev.obj_index)]
						except PulseIndexError: continue # likely already gone

					for obj in obj_list or obj_list_full or list(): # new/updated
						obj_id = obj_id_func(obj_t, obj.index)
						if obj_id not in self.item_objs:
							obj_new.add(obj_id)
							self.item_objs[obj_id] = PAMixerStreamsItem(self, obj_t, obj_id, obj)
						elif obj_list_full is None: self.item_objs[obj_id].update(obj)
						obj_gone.discard(obj_id)

			for obj_id in obj_gone: self.item_objs.pop(obj_id, None)
			for obj_id, item in self.item_objs.items():
				try: self.apply_stream_params(item, reapply=obj_id not in obj_new)
				except Exception as err:
					log.exception(
						'Failed to apply stream parameters for {}, skipping: <{}> {}',
						item, err.__class__.__name__, err )

			# Sort sinks to be always on top
			sinks, streams, ordered = list(), list(), True
			for obj_id, item in self.item_objs.items():
				if item.t == 'sink':
					if streams: ordered = False
					sinks.append((obj_id, item))
				else: streams.append((obj_id, item))
			if not ordered:
				self.item_objs.clear()
				for obj_id, item in it.chain(sinks, streams): self.item_objs[obj_id] = item

			# Make item names unique
			items_uniq = defaultdict(list)
			for item in self.item_objs.values(): items_uniq[item.name_base].append(item)
			for items in items_uniq.values():
				if len(items) <= 1: continue
				for item in items:
					if item.name != item.name_base: continue
					item.name = '{} #{}'.format(item.name_base, uid_str())

			self.items = list(item for item in self.item_objs.values() if not item.hidden)
			if not self._updates: break

	_update_wakeup_break = None
	@contextmanager
	def update_wakeup_poller( self, wakeup_handler,
			wakeup_pid=None, wakeup_sig=signal.SIGUSR1 ):
		if wakeup_pid is None: wakeup_pid = os.getpid()
		def ev_sig_handler(sig=None, frm=None):
			while True:
				try: ev = ev_queue.popleft()
				except IndexError: break
				wakeup_handler(ev)
		def ev_cb(ev_pulse=None):
			if not ev_pulse:
				log.debug('pulsectl disconnected')
				wakeup_handler(disconnected=True)
			else: log.debug('pulsectl event: {} {} {}', ev_pulse.facility, ev_pulse.t, ev_pulse.index)
			if not poller_thread: return
			ev = ev_pulse and PAMixerEvent.from_pulsectl_ev(ev_pulse)
			if not ev: return
			ev_queue.append(ev)
			if poller_thread is threading.current_thread(): os.kill(wakeup_pid, wakeup_sig)
			else: ev_sig_handler()
		def poller():
			self.pulse.event_mask_set('sink', 'sink_input')
			self.pulse.event_callback_set(ev_cb)
			while True:
				with self._pulse_hold: self._pulse_lock.acquire() # ...threads ;(
				if self._update_wakeup_break:
					log.error('Stopping poller due to update_wakeup_break')
					break
				try: self.pulse.event_listen()
				except PulseDisconnected:
					ev_cb()
					break
				finally: self._pulse_lock.release()
				if not poller_thread: break
		ev_queue = deque()
		signal.signal(wakeup_sig, ev_sig_handler)
		poller_thread = threading.Thread(target=poller, name='pulsectl', daemon=True)
		try: yield poller_thread
		finally:
			self.pulse.event_listen_stop()
			poller_thread, t = None, poller_thread
			# if t.is_alive(): t.join()
			# time.sleep(0.5)

	@contextmanager
	def update_wakeup(self, trap_errors=True, loop_interval=0.03):
		'Anything pulse-related MUST be done in this context.'
		with self._pulse_hold:
			for n in range(int(5.0 / loop_interval)):
				# wakeup only works when loop is actually started,
				#  which might not be the case regardless of any locks.
				self.pulse.event_listen_stop()
				if self._pulse_lock.acquire(timeout=loop_interval): break
			else:
				raise RuntimeError('poll_wakeup() hangs, likely locking issue')
			try: yield self.pulse
			except Exception as err:
				if not trap_errors:
					self._update_wakeup_break = True
					raise
				log.exception('Pulse interaction failure, skipping: <{}> {}', err.__class__.__name__, err)
			finally: self._pulse_lock.release()

	def update_wakeup_handler(self, ev=None, disconnected=False):
		if disconnected:
			self.connected = False
			signal.pthread_kill(threading.main_thread().ident, signal.SIGWINCH)
		elif self.connected is None: self.connected = True
		self._updates.append(ev)

	def apply_stream_params(self, item, reapply=False):
		if reapply and not self.conf.stream_params_reapply: return
		rulesets = (self.conf.stream_params or dict()).items() if not reapply else\
			((k, self.conf.stream_params[k]) for k in self.conf.stream_params_reapply)
		for sec, checks in rulesets:
			match, params = True, OrderedDict()
			for t, k, v in checks:
				if t == 'match':
					if match and not v.search(item.obj.proplist.get(k, '')): match = False
				elif t == 'set': params[k] = v
				else: raise ValueError((t, k, v))
			if match:
				log.debug( 'Matched stream {!r} (name: {!r})'
					' to config section: {}', item, item.name, sec )
				for k, v in params.items():
					m = re.search(r'^volume-(min|max|set)$', k)
					if m:
						vol = float(v)
						if m.group(1) == 'max':
							if item.volume > vol: item.volume = vol
						elif m.group(1) == 'min':
							if item.volume < vol: item.volume = vol
						elif m.group(1) == 'set': item.volume = vol
					elif k == 'hidden': item.hidden = self.conf.parse_bool(v)
					elif k == 'port':
						try: item.port = v
						except PAMixerInvalidAction as err:
							log.error( 'Unable to set port for stream {!r}'
								' (name: {!r}, config section: {}): {}', item, item.name, sec, err )
					elif k == 'name': item.name_update(v)
					elif k == 'reapply': pass
					else:
						log.debug( 'Unrecognized stream'
							' parameter (section: {!r}): {!r} (value: {!r})', sec, k, v )

	@property
	def item_list(self):
		self.update()
		return self.items

	def item_default(self):
		if not self.items: return
		func = self.focus_policies[self.conf.focus_default]
		return func(self.items)

	def item_newer(self, ts):
		items = sorted(self.items, key=op.attrgetter('created_ts'), reverse=True)
		if items and items[0].created_ts > ts: return items[0]


class PAMixerAtticItem(object):

	name_prefix_subst = {
		'application-name': 'app-name' }

	def __init__(self, attic, obj):
		self.attic, self.conf, self.obj = attic, attic.conf, obj
		self.uid = n = self.obj.name
		if n.startswith('sink-input-by-'): n = n[14:]
		if ':' in n:
			n_pre, n = n.split(':', 1)
			n_pre = self.name_prefix_subst.get(n_pre, n_pre)
			n = '{}:{}'.format(n_pre, n)
		self.name = n

	@property
	def muted(self):
		return bool(self.obj.mute)
	@muted.setter
	def muted(self, val):
		self.obj.mute = int(val)
		with self.attic.pulse_ctx() as pulse:
			pulse.stream_restore_write(self.obj, mode='replace')

	@property
	def volume(self):
		'Volume as one float in 0-1 range.'
		return min(1.0, max(0,
			self.obj.volume.value_flat - self.conf.min_volume ) / float(self.conf.max_volume))
	@volume.setter
	def volume(self, val):
		val_pulse = min(1.0, max(0, val)) * self.conf.max_volume + self.conf.min_volume
		self.obj.volume.value_flat = val_pulse
		with self.attic.pulse_ctx() as pulse:
			pulse.stream_restore_write(self.obj, mode='replace')

	def muted_toggle(self): self.muted = not self.muted
	def volume_change(self, delta): self.volume += delta

	def get_next(self): return self.attic.item_after(self)
	def get_prev(self): return self.attic.item_before(self)


class PAMixerAttic(PAMixerMenu):

	def __init__(self, pulse_ctx, conf=None, fatal=False):
		self.pulse_ctx, self.fatal, self.conf = pulse_ctx, fatal, conf or Conf()
		self.update()

	def update(self):
		with self.pulse_ctx(trap_errors=False) as pulse: sr_list = pulse.stream_restore_list()
		items = list()
		for sr in sr_list:
			if sr.name.startswith('source-output-by-'): continue
			if sr.channel_count == 0: continue
			items.append(PAMixerAtticItem(self, sr))
		self.items = sorted(items, key=op.attrgetter('name'))



class PAMixerUI(object):

	item_len_min = 10
	bar_len_min = 10
	bar_caps_func = staticmethod(lambda bar='': ' [ ' + bar + ' ]')
	border = 1
	name_cut_funcs = dict(left=lambda n,c: n[max(0, len(n) - c):], right=lambda n,c: n[:c])
	mode_opts = {'streams', 'attic'}
	mode_desc = dict(streams='active sinks/streams', attic='stored stream volumes')

	def __init__(self, streams, attic, conf=None):
		self.streams, self.attic, self.conf = streams, attic, conf or Conf()
		self.mode = 'streams'

	def __enter__(self):
		self.c = None
		return self

	def __exit__(self, exc_t, exc_val, exc_tb):
		if self.c:
			self.c.endwin()
			self.c = None


	def c_key(self, k):
		if len(k) == 1: return ord(k)
		return getattr(self.c, 'key_{}'.format(k).upper())

	def c_win_init(self):
		# Used to create a window with borders here,
		#  but these borders don't seem to be cleared properly.
		# So using stdscr now, and painting borders in the app.
		win = self.c_stdscr
		win.keypad(True)
		win.bkgdset(' ')
		return win

	def c_win_size(self, win):
		'Returns "nlines, ncols, begin_y, begin_x", taking border into account.'
		size = win.getmaxyx()
		nlines, ncols = max(1, size[0] - 2 * self.border), max(1, size[1] - 2 * self.border)
		return nlines, ncols, min(self.border, size[0]), min(self.border, size[1])

	def c_win_add(self, win, *args, test=False):
		try: win.addstr(*args)
		except self.c.error as err:
			if not test: log.debug('curses addstr() returned error ({}), args: {}', err, args)
		else: return True

	def c_win_draw(self, win, items, item_hl):
		win.erase()
		if not items: return

		win_rows, win_len, pad_x, pad_y = self.c_win_size(win)
		draw_controls = self.conf.show_controls and self.attic and win_rows > 5
		win_rows_reserved = 0 if draw_controls else 1
		if win_len <= 3: return # nothing fits, don't even bother
		addstr = ft.partial(self.c_win_add, win)

		## Fit stuff vertically
		if win_rows < len(items) + win_rows_reserved:
			# Pick/display items near highlighted one
			pos, offset = items.index(item_hl), 1
			items, items_fit = dict(enumerate(items)), {pos: items[pos]}
			while True:
				ps = list(p for p in [pos + offset, pos - offset] if p in items)
				if not ps: break
				for p in ps:
					items_fit[p] = items[p]
					if win_rows <= len(items_fit) + win_rows_reserved: break
				else:
					offset += 1
					continue
				break
			assert not items_fit or pos in items_fit
			items = list(map(op.itemgetter(1), sorted(items_fit.items(), key=op.itemgetter(0))))

		## Fit stuff horizontally
		mute_button_len, level_len = 2, 5
		item_len_max = max(len(item.name) for item in items)
		if self.conf.name_show_level: item_len_max += level_len
		if self.conf.name_len_max:
			item_len_max = min(item_len_max, self.conf.name_len_max)
		bar_len = win_len - item_len_max - mute_button_len - len(self.bar_caps_func())
		if bar_len < self.bar_len_min:
			item_len_max = max(self.item_len_min, item_len_max + bar_len - self.bar_len_min)
			bar_len = win_len - item_len_max - mute_button_len - len(self.bar_caps_func())
			if bar_len <= 0: item_len_max = win_len # just draw labels
			if item_len_max < self.item_len_min: item_len_max = max(len(item.name) for item in items)

		## Output stuff
		for row, item in enumerate(items):
			if row >= win_rows: break
			row += pad_y
			if not addstr(row, 0, ' ', test=True): break

			attrs = self.c.A_REVERSE if item is item_hl else self.c.A_NORMAL
			name_len = item_len_max - bool(self.conf.name_show_level) * level_len
			name = self.name_cut_funcs[self.conf.name_cut_from](item.name, name_len)

			if self.conf.name_show_level:
				level = max(0, min(100, int(round(item.volume * 100))))
				if level == 0: level = '--'
				elif level == 100: level = '++'
				else: level = '{:>2d}'.format(level)
				name = '[{}] {}'.format(level, name)

			addstr(row, 0, ' ' * pad_x)
			addstr(row, pad_x, name, attrs)
			item_name_end = item_len_max + pad_x
			if win_len > item_name_end + mute_button_len:
				if item.muted: mute_button = ' M'
				else: mute_button = ' -'
				addstr(row, item_name_end, mute_button)

				if bar_len > 0:
					bar_fill = int(round(item.volume * bar_len))
					bar = self.bar_caps_func('#' * bar_fill + '-' * (bar_len - bar_fill))
					addstr(row, item_name_end + mute_button_len, bar)

		if draw_controls:
			addstr(win_rows, pad_x, ' ')
			addstr('x', self.c.A_REVERSE)
			(y, x), mode_desc = win.getyx(), self.mode_desc[self.mode_switch(dry_run=True)]
			addstr(' - show {}'.format(mode_desc)[:win_len-x])


	_item_hl = _item_hl_ts = None

	def mode_switch(self, dry_run=False):
		mode = self.mode_opts.difference([self.mode]).pop()
		if not dry_run and getattr(self, mode, None):
			log.debug('Switching display mode: {} -> {}', self.mode, mode)
			self.mode = mode
			self.menu.update()
		return mode

	@property
	def menu(self): return getattr(self, self.mode)

	@property
	def item_hl(self):
		if self._item_hl and self.conf.focus_new_items:
			ts = self._item_hl_ts
			if ts: ts += self.conf.focus_new_items_delay or 0
			item = self.menu.item_newer(ts)
			if item: self._item_hl = item
		return self._item_hl

	@item_hl.setter
	def item_hl(self, item):
		self._item_hl, self._item_hl_ts = item, time.monotonic()


	def _run(self, stdscr):
		c, self.c_stdscr = self.c, stdscr
		key_match = lambda key,*choices: key in map(self.c_key, choices)

		c.curs_set(0)
		c.use_default_colors()

		win = self.c_win_init()
		adjust_step = self.conf.adjust_step / 100.0

		while True:
			items, item_hl = self.menu.item_list, self.item_hl
			if item_hl is None: item_hl = self.item_hl = self.menu.item_default()
			if item_hl not in items: item_hl = self.menu.item_default()
			self.c_win_draw(win, items, item_hl)

			key = None
			while True:
				try: key = win.getch()
				except KeyboardInterrupt: key = self.c_key('q')
				except c.error: break
				try: key_name = c.keyname(key)
				except ValueError: key_name = 'unknown' # e.g. "-1"
				break
			if key is None: continue
			log.debug('Keypress event: {} ({!r})', key, key_name)

			if item_hl:
				if key_match(key, 'up', 'k', 'p'): self.item_hl = item_hl.get_prev()
				elif key_match(key, 'down', 'j', 'n'): self.item_hl = item_hl.get_next()
				elif key_match(key, 'left', 'h', 'b'): item_hl.volume_change(-adjust_step)
				elif key_match(key, 'right', 'l', 'f'): item_hl.volume_change(adjust_step)
				elif key_match(key, ' ', 'm'): item_hl.muted_toggle()
				elif key_match(key, 'x'): self.mode_switch()
				elif key_name.isdigit(): # 1-0 keyboard row
					item_hl.volume = (float(key_name) or 10.0) / 10 # 0 is 100%

			if key_match(key, 'resize'):
				if self.conf.overkill_redraw:
					c.endwin()
					stdscr.refresh()
					win = self.c_win_init()
				else:
					win.resize(*win.getmaxyx())
			elif key_match(key, 'q'): break

	def run(self):
		import locale, curses # has a ton of global state
		locale.setlocale(locale.LC_ALL, '') # see top of "curses" module doc for rationale
		self.c = curses
		self.c.wrapper(self._run)


def main(args=None):
	conf = conf_read()

	import argparse
	parser = argparse.ArgumentParser(description='Command-line PulseAudio mixer tool.')

	parser.add_argument('-c', '--conf',
		action='store', metavar='path', default=conf_read.path_default,
		help='Path to configuration file to use instead'
			' of the default one (%(default)s), can be missing or empty.')

	parser.add_argument('-a', '--adjust-step',
		type=int, metavar='step', default=conf.adjust_step,
		help='Adjustment for a single keypress in interactive mode (0-100%%, default: %(default)s%%).')
	parser.add_argument('-l', '--max-level',
		type=float, metavar='volume', default=conf.max_volume,
		help='Relative volume level to treat as max (default: %(default)s).')
	parser.add_argument('-n', '--use-media-name',
		action='store_true', default=conf.use_media_name,
		help='Display streams by "media.name" property, if possible.'
			' Default is to prefer application name and process properties.')
	parser.add_argument('--no-reconnect',
		action='store_false', dest='reconnect', default=conf.reconnect,
		help='Exit when pulseaudio server connection goes down.'
			' Default is to reconnect endlessly, i.e. run until manual exit.')

	parser.add_argument('-v', '--verbose',
		action='store_true', default=conf.verbose,
		help='Dont close stderr to see any sort of errors (which'
			' mess up curses interface, thus silenced that way by default).')
	parser.add_argument('--dump-stream-params',
		action='store_true', help='Dump all parameters for each stream to stderr.')
	parser.add_argument('--debug', action='store_true', help='Verbose operation mode.')
	parser.add_argument('--fatal', action='store_true',
		help='Dont try too hard to recover from errors. For debugging purposes only.')

	args = sys.argv[1:] if args is None else args
	opts = parser.parse_args(args)

	if opts.conf: conf = conf_read(opts.conf)
	for k,v in vars(opts).items(): setattr(conf, k, v)
	del opts

	global log, print
	logging.basicConfig(
		level=logging.DEBUG if conf.debug else logging.WARNING,
		format='%(asctime)s :: %(threadName)s %(levelname)s :: %(message)s',
		datefmt='%Y-%m-%d %H:%M:%S' )
	log = get_logger('main')
	print = ft.partial(print, file=sys.stderr, flush=True) # stdout is used by curses
	log.debug('Initializing...')

	while True:
		with Pulse('pa-mixer-mk3', connect=False, threading_lock=True) as pulse:
			pulse.connect(wait=conf.reconnect)

			wakeup_pid = os.getpid()
			attic, streams = None, PAMixerStreams(pulse, conf, fatal=conf.fatal)
			if conf.show_stored_values and pulse.stream_restore_test() is not None:
				attic = PAMixerAttic(streams.update_wakeup, conf, fatal=conf.fatal)

			with streams.update_wakeup_poller(streams.update_wakeup_handler) as poller_thread:
				log.debug('Starting pulsectl event poller thread...')
				poller_thread.start()

				with PAMixerUI(streams, attic, conf) as curses_ui:
					# Any output will mess-up curses ui, so try to close sys.stderr if possible
					if not conf.verbose and not conf.debug and not conf.dump_stream_params:
						sys.stderr.flush()
						fd = os.open(os.devnull, os.O_WRONLY)
						os.dup2(fd, sys.stderr.fileno())
						os.close(fd)
					log.debug('Entering curses ui loop...')
					try: curses_ui.run()
					except PAMixerReconnect:
						if conf.reconnect: log.debug('Reconnecting to pulse server...')
						else:
							log.debug('Disconnected from pulse server, exiting...')
							break
					else: break

	log.debug('Finished')

if __name__ == '__main__': sys.exit(main())

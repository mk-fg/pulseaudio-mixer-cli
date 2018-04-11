#!/usr/bin/env python3

import itertools as it, operator as op, functools as ft
from collections import OrderedDict, defaultdict, deque, namedtuple
from contextlib import contextmanager
import os, sys, io, re, time, logging, configparser
import base64, hashlib, unicodedata, math
import signal, threading

from pulsectl import (
	Pulse,
	PulseEventTypeEnum as ev_t, PulseEventFacilityEnum as ev_fac, PulseEventMaskEnum as ev_m,
	PulseLoopStop, PulseDisconnected, PulseIndexError )


class LogMessage:
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


class Conf:
	def __repr__(self): return repr(vars(self))

	adjust_step = 5.0 # percent, 0-100
	# Volume values are relative to "normal" (non-soft-boosted) pulseaudio volume
	max_volume = 1.0 # relative value, displayed as "100%"
	min_volume = 0.01 # relative value, displayed as "0%"
	volume_type = 'flat' # 'flat', 'log' (base=e) or 'log-N' where N is logarithm base (int/float)

	use_device_name = False
	use_media_name = False
	placeholder_media_names = [ # avoid displaying these, as they're not informative
		'audio stream', 'AudioStream', 'Output', 'ALSA Playback', 'Simple DirectMedia Layer' ]
	name_len_max = 100
	name_cut_from = 'left' # "left" or "right"
	name_show_level = True

	overkill_redraw = False # if terminal gets resized often, might cause noticeable flickering
	overkill_updates = False # always refresh lists of sinks/streams from scratch
	verbose = False
	reconnect = True
	show_stored_values = True
	show_controls = True

	stream_params = stream_params_reapply = None
	broken_chars_replace = '_'
	focus_default = 'first' # either "first" or "last"
	focus_new_items = True
	focus_new_items_delay = 5.0 # min seconds since last focus change to trigger this
	event_proc_delay = 0.0 # 0 - disable
	force_refresh_interval = 0.0 # 0 or negative - disable

	# Whether to wrap focus when going past first/last item
	focus_wrap_first = False
	focus_wrap_last = False

	# These are set for volume_type
	_vol_set = _vol_get = staticmethod(lambda v: min(1.0, max(0, v)))

	@staticmethod
	def parse_bool(val, _states={
			'1': True, 'yes': True, 'true': True, 'on': True,
			'0': False, 'no': False, 'false': False, 'off': False }):
		try: return _states[val.lower()]
		except KeyError: raise ValueError(val)


def conf_read(path=None, base=None, **overrides):
	conf, conf_file = base or Conf(),\
		os.path.expanduser(path or conf_read.path_default)
	try: conf_file = open(conf_file)
	except (OSError, IOError) as err: pass
	else: conf_update_from_file(conf, conf_file, overrides)
	return conf
conf_read.path_default = '~/.pulseaudio-mixer-cli.cfg'

def conf_update_from_file(conf, path_or_file, overrides):
	if isinstance(path_or_file, str): path_or_file = open(path_or_file)
	with path_or_file as src:
		config = configparser.RawConfigParser(
			allow_no_value=True, inline_comment_prefixes=(';',) )
		try: config.readfp(src)
		except configparser.MissingSectionHeaderError:
			src.seek(0)
			src = src.read()
			src = io.StringIO('[default]' + ('\r\n' if '\r\n' in src else '\n') + src)
			config.readfp(src)

	for k in dir(conf):
		if k.startswith('_'): continue
		v = getattr(conf, k)
		if k in overrides:
			setattr(conf, k, overrides[k])
			continue
		if isinstance(v, str): get_val = lambda *a: str(config.get(*a))
		elif isinstance(v, bool): get_val = config.getboolean
		elif isinstance(v, int): get_val = config.getint
		elif isinstance(v, float): get_val = lambda *a: float(config.get(*a))
		else: continue # values with other types cannot be specified in config
		for k_conf in k, k.replace('_', '-'):
			try: setattr(conf, k, get_val('default', k_conf))
			except configparser.Error: pass

	if conf.volume_type != 'flat':
		if conf.volume_type == 'log': vol_log_base = math.e
		elif conf.volume_type.startswith('log-'):
			vol_log_base = max(1.0000001, float(conf.volume_type.split('-', 1)[-1]))
		else: raise ValueError(f'Unrecognized volume_type value: {conf.volume_type!r}')
		_vol_cap = conf._vol_get
		conf._vol_get = lambda v,b=vol_log_base,c=_vol_cap: c(math.log(v * (b - 1) + 1, b))
		conf._vol_set = lambda v,b=vol_log_base,c=_vol_cap: (b ** c(v) - 1) / (b - 1)

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


class PAMixerMenuItem:

	name, volume, muted = '', 0, False
	menu = uid = text = None

	def muted_toggle(self): self.muted = not self.muted
	def volume_change(self, delta):
		log.debug('Volume update: {} -> {} [{}]', self.volume, self.volume + delta, delta)
		self.volume += delta
	def special_action(self, key, key_match): pass

	def get_next(self, m=1):
		return self.menu.item_after(self, m=m) if self.menu else self
	def get_prev(self, m=1):
		return self.menu.item_before(self, m=m) if self.menu else self

class PAMixerMenu:

	focus_policies = dict(first=op.itemgetter(0), last=op.itemgetter(-1))
	items, controls, conf = tuple(), OrderedDict(), Conf()

	def update(self, incremental=False): return

	@property
	def item_list(self): return list(self.items) # for display only

	def item_default(self, n=None):
		items = self.item_list
		if not items: return
		idx = None
		if n is not None: idx = max(0, min(n, len(items)-1))
		return items[idx] if idx is not None\
			else self.focus_policies[self.conf.focus_default](items)

	def item_newer(self, ts): return

	def item_id(self, item): return item.uid

	def item_shift(self, item=None, m=0, t=None):
		if t and self.items:
			n = dict(first=0, last=len(self.items)-1).get(t)
			assert n is not None, t
			return self.items[n]
		if item:
			for n, item2 in enumerate(self.items):
				if self.item_id(item2) == self.item_id(item):
					n_max, n = len(self.items) - 1, n + m
					if m > 0 and n > n_max: n = 0 if self.conf.focus_wrap_last else n_max
					elif m < 0 and n < 0: n = n_max if self.conf.focus_wrap_first else 0
					return self.items[n]
		return self.item_default()

	def item_after(self, item=None, m=1):
		return self.item_shift(item=item, m=m)
	def item_before(self, item=None, m=1):
		return self.item_shift(item=item, m=-m)


class PAMixerReconnect(Exception): pass

class PAMixerEvent:
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

class PAMixerStreamsItem(PAMixerMenuItem):

	name = '???'

	def __init__(self, streams, obj_t, obj_id, obj):
		self.menu, self.conf = streams, streams.conf
		self.t, self.uid = obj_t, obj_id
		self.hidden = self.name_custom = False
		self.created_ts = time.monotonic()
		self.update(obj)

		if self.conf.dump_stream_params:
			from pprint import pprint
			dump = OrderedDict(uid=self.uid, name=self.name)
			dump['props'] = sorted(self.obj.proplist.items())
			pprint(dump, sys.stderr)
			sys.stderr.flush()

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
			if self.menu.fatal: raise
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
		with self.menu.update_wakeup() as pulse: pulse.mute(self.obj, self.obj.mute)

	@property
	def volume(self):
		'Volume as one float in 0-1 range.'
		val_pulse = (self.obj.volume.value_flat - self.conf.min_volume) / float(self.conf.max_volume)
		return self.conf._vol_get(val_pulse)
	@volume.setter
	def volume(self, val):
		val_pulse = self.conf._vol_set(val) * self.conf.max_volume + self.conf.min_volume
		log.debug('Setting volume: {} (pulse: {}) for {}', val, val_pulse, self)
		with self.menu.update_wakeup() as pulse: pulse.volume_set_all_chans(self.obj, val_pulse)

	def special_action(self, ui, key):
		if ui.key_match(key, 'i'):
			with self.menu.update_wakeup() as pulse:
				ui.info = PAMixerStreamInfo(self.obj.proplist)
			ui.mode_switch('info')

	@property
	def port(self):
		if self.t != 'sink': return
		return self.obj.port_active
	@port.setter
	def port(self, name):
		if self.t != 'sink':
			log.warning( 'Setting ports is only'
				' available for {!r}-type streams, not {!r}-type', 'sink', self.t )
		with self.menu.update_wakeup() as pulse: pulse.port_set(self.obj, name)


class PAMixerStreams(PAMixerMenu):

	controls = dict(i='show item info')

	def __init__(self, pulse, conf=None, fatal=False):
		self.pulse, self.fatal, self.conf = pulse, fatal, conf or Conf()
		self.items, self.item_objs = list(), OrderedDict()
		self.connected, self._updates = None, deque()
		self._pulse_hold, self._pulse_lock = threading.Lock(), threading.Lock()

	def update(self, incremental=False):
		while True:
			try: ev = self._updates.popleft()
			except: ev = None

			# Restarts whole thing with new pulse connection
			if self.connected is False: raise PAMixerReconnect()

			# Add/remove/update items
			if not self.conf.overkill_updates and incremental and not ev: break
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
						else: self.item_objs[obj_id].update(obj)
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
	def update_wakeup_poller(self, wakeup_handler):
		'''Context that runs `wakeup_handler` for pulse sink/sink-input events.
			Implemented via pulse-event-listener daemon
				thread which interrupts main one via timer signals.
			`conf.event_proc_delay` and timer signals (instead of os.kill) are to avoid
				calling handler for very transient sink-inputs (e.g. many few-ms click sounds).'''
		wakeup_pid, wakeup_sig = os.getpid(), signal.SIGALRM
		ev_queue, ev_timer_delay, ev_timer_set = deque(), self.conf.event_proc_delay or 0, False

		def ev_queue_cleanup(ev_queue):
			'''Discard/dedup new-change-remove event sequences for same object(s).
				This is optimization for transient sink-inputs,
					which are shorter than `conf.event_proc_delay` and multiple changes.'''
			ev_buff = OrderedDict()
			while ev_queue:
				try: ev = ev_queue.popleft()
				except IndexError: break
				if ev.t == ev_t.remove and ev_buff.pop(
						(ev_t.new, ev.obj_type, ev.obj_index), False ):
					ev_buff.pop((ev_t.change, ev.obj_type, ev.obj_index), None)
				else: ev_buff[ev.t, ev.obj_type, ev.obj_index] = ev
			return list(ev_buff.values())

		def ev_sig_handler(sig=None, frm=None):
			nonlocal ev_timer_set
			if sig is not None: ev_timer_set = False
			while ev_queue:
				ev_buff = ev_queue_cleanup(ev_queue)
				if not ev_buff: break
				for ev in ev_buff: wakeup_handler(ev)

		def ev_cb(ev_pulse=None):
			nonlocal ev_timer_set
			if ev_pulse:
				log.debug( 'pulsectl event: {} {} {}',
					ev_pulse.facility, ev_pulse.t, ev_pulse.index )
			if not poller_thread: return
			ev = ev_pulse and PAMixerEvent.from_pulsectl_ev(ev_pulse)
			if ev: ev_queue.append(ev)
			if poller_thread is threading.current_thread():
				if not ev_timer_delay: os.kill(wakeup_pid, wakeup_sig)
				elif not ev_timer_set:
					signal.setitimer(signal.ITIMER_REAL, ev_timer_delay)
					ev_timer_set = True
			else: ev_sig_handler()

		def cb_delay_iter(func, interval):
			'Helper to run callback with specified time intervals, yielding poll delays.'
			if not interval or interval <= 0: ts_next = None
			else: ts_next = time.monotonic() + interval
			while True:
				if not ts_next:
					yield None
					continue
				yield max(0, ts_next - time.monotonic())
				ts = time.monotonic()
				if ts > ts_next:
					while ts > ts_next: ts_next += interval
					func()

		def poller():
			self.pulse.event_mask_set(ev_m.sink, ev_m.sink_input)
			self.pulse.event_callback_set(ev_cb)
			delay_iter = cb_delay_iter(ev_cb, self.conf.force_refresh_interval)
			while True:
				with self._pulse_hold: self._pulse_lock.acquire() # ...threads ;(
				if self._update_wakeup_break:
					log.error('Stopping poller due to update_wakeup_break')
					break
				try: self.pulse.event_listen(next(delay_iter))
				except PulseDisconnected:
					log.debug('pulsectl disconnected')
					wakeup_handler(disconnected=True)
					break
				finally: self._pulse_lock.release()
				if not poller_thread: break

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
		self.update(incremental=True)
		return self.items

	def item_newer(self, ts):
		items = sorted(self.items, key=op.attrgetter('created_ts'), reverse=True)
		if items and items[0].created_ts > ts: return items[0]


class PAMixerAtticItem(PAMixerMenuItem):

	name, name_prefix_subst = '???', {'application-name': 'app-name'}

	def __init__(self, attic, obj):
		self.menu, self.conf, self.obj = attic, attic.conf, obj
		self.uid = n = self.obj.name
		if n.startswith('sink-input-by-'): n = n[14:]
		if ':' in n:
			n_pre, n = n.split(':', 1)
			n_pre = self.name_prefix_subst.get(n_pre, n_pre)
			n = '{}:{}'.format(n_pre, n)
		self.name = n

	def __repr__(self):
		return '<{}[{:x}] stream_restore: {}>'.format(self.__class__.__name__, id(self), self.name)

	def init_channels(self, obj, value=0):
		if obj.volume.values: return
		obj.channel_list, obj.volume.values = ['mono'], [value]

	@property
	def muted(self):
		return bool(self.obj.mute)
	@muted.setter
	def muted(self, val):
		self.obj.mute = int(val)
		with self.menu.pulse_ctx() as pulse:
			pulse.stream_restore_write(self.obj, mode='replace')

	@property
	def volume(self):
		'Volume as one float in 0-1 range.'
		self.init_channels(self.obj)
		val_pulse = (self.obj.volume.value_flat - self.conf.min_volume) / float(self.conf.max_volume)
		return self.conf._vol_get(val_pulse)
	@volume.setter
	def volume(self, val):
		self.init_channels(self.obj)
		val_pulse = self.conf._vol_set(val) * self.conf.max_volume + self.conf.min_volume
		log.debug('Setting stream_restore volume: {} (pulse: {}) for {}', val, val_pulse, self)
		self.obj.volume.value_flat = val_pulse
		with self.menu.pulse_ctx() as pulse: pulse.stream_restore_write(self.obj, mode='replace')

	def special_action(self, ui, key):
		if ui.key_match(key, 'enter', '\n'):
			log.debug('Applying stream_restore volume for: {}', self)
			with self.menu.pulse_ctx() as pulse:
				pulse.stream_restore_write(self.obj, mode='replace', apply_immediately=True)
		if ui.key_match(key, 'd'):
			with self.menu.pulse_ctx() as pulse:
				pulse.stream_restore_delete(self.obj.name)
			del self.menu.item_dict[self.name]


class PAMixerAttic(PAMixerMenu):

	controls = dict( d='delete entry',
		enter='apply selected level to active streams' )

	def __init__(self, pulse_ctx, conf=None, fatal=False):
		self.pulse_ctx, self.fatal, self.conf = pulse_ctx, fatal, conf or Conf()
		self.update()

	def update(self, incremental=False):
		if incremental: return
		with self.pulse_ctx(trap_errors=False) as pulse: sr_list = pulse.stream_restore_list()
		items = list()
		for sr in sr_list:
			if sr.name.startswith('source-output-by-'): continue
			items.append(PAMixerAtticItem(self, sr))
		self.item_dict = OrderedDict(
			(item.name, item) for item in sorted(items, key=op.attrgetter('name')) )

	@property
	def items(self):
		return list(self.item_dict.values())


class PAMixerInfoItem(PAMixerMenuItem):

	def __init__(self, menu, n=0, name='', text=''):
		self.menu, self.uid, self.name, self.text = menu, n, name, text
	def __hash__(self): return hash(f'<InfoItem:{self.uid}>')
	def __eq__(self, o): return isinstance(o, PAMixerInfoItem) and self.uid == o.uid

	def special_action(self, ui, key):
		if ui.key_match(key, 'i'): ui.mode_switch()


class PAMixerStreamInfo(PAMixerMenu):

	controls = dict(i='back')

	def __init__(self, proplist):
		self.pos, self.proplist = 0, proplist
		self.items = list()
		for n, (k, v) in enumerate(sorted(self.proplist.items())):
			self.items.append(PAMixerInfoItem(self, n, k, v))



PAMixerUIFit = namedtuple('PAMixerUIFit', 'rows controls')

class PAMixerUI:

	item_len_min = 10
	bar_len_min = 10
	bar_caps_func = staticmethod(lambda bar='': ' [ ' + bar + ' ]')
	border = 1
	name_cut_funcs = dict(left=lambda n,c: n[max(0, len(n) - c):], right=lambda n,c: n[:c])
	mode_opts = ['streams', 'attic']
	mode_desc = dict(streams='active sinks/streams', attic='stored stream volumes')

	def __init__(self, streams, attic, conf=None):
		self.streams, self.attic, self.info, self.conf = streams, attic, None, conf or Conf()
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

	def c_win_draw(self, win, items, item_hl, controls):
		win.erase()
		if not items: return

		win_rows, win_len, pad_x, pad_y = self.c_win_size(win)
		draw_controls = controls and win_rows > 5
		win_rows_reserved = 1 if draw_controls else 2
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
			text_item = item.text is not None

			if not item.name and text_item:
				addstr(row, 0, ' ' * pad_x)
				addstr(row, pad_x, item.text[:win_len], attrs)
				continue

			if self.conf.name_show_level and not text_item:
				level = max(0, min(100, int(round(item.volume * 100))))
				if level == 0: level = '--'
				elif level == 100: level = '++'
				else: level = '{:>2d}'.format(level)
				name = '[{}] {}'.format(level, name)

			addstr(row, 0, ' ' * pad_x)
			addstr(row, pad_x, name, attrs)
			item_name_end = item_len_max + pad_x

			if text_item:
				text = item.text[:max(0, win_len - item_name_end)]
				addstr(row, item_name_end, text, attrs)
				continue

			if win_len > item_name_end + mute_button_len:
				if item.muted: mute_button = ' M'
				else: mute_button = ' -'
				addstr(row, item_name_end, mute_button)
				if bar_len <= 0: continue

			bar_fill = int(round(item.volume * bar_len))
			bar = self.bar_caps_func('#' * bar_fill + '-' * (bar_len - bar_fill))
			addstr(row, item_name_end + mute_button_len, bar)

		if draw_controls:
			addstr(win_rows, pad_x, '')
			for key, desc in controls.items():
				addstr(' ')
				addstr(key, self.c.A_REVERSE)
				addstr(' - ')
				desc_max_len = win_len - win.getyx()[1] - 1
				addstr((desc + ' ')[:desc_max_len])
				if len(desc) >= desc_max_len: break

		return PAMixerUIFit(len(items), draw_controls)


	_item_hl = _item_hl_ts = None

	def mode_switch(self, mode=None, dry_run=False):
		if not mode:
			for mode in self.mode_opts:
				if mode != self.mode: break
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


	def key_match(self, key,*choices):
		return key in map(self.c_key, choices)

	def _run(self, stdscr):
		c, self.c_stdscr = self.c, stdscr

		c.curs_set(0)
		c.use_default_colors()

		win = self.c_win_init()
		adjust_step = self.conf.adjust_step / 100.0

		self.mode_switch('streams')
		item_hl_n = dict()
		while True:
			items, item_hl = self.menu.item_list, self.item_hl
			if item_hl:
				try: item_hl_n[self.mode]= items.index(item_hl)
				except ValueError: item_hl = None
			if not item_hl:
				item_hl = self.item_hl = self.menu.item_default(item_hl_n.get(self.mode))
				if item_hl: item_hl_n[self.mode] = items.index(item_hl)

			controls = OrderedDict()
			if self.conf.show_controls:
				if self.attic:
					controls['x'] = 'show {}'.format(
						self.mode_desc[self.mode_switch(dry_run=True)] )
				controls.update(self.menu.controls or dict())

			fit = self.c_win_draw(win, items, item_hl, controls)

			key = None
			while True:
				try: key = win.getch()
				except KeyboardInterrupt: key = self.c_key('q')
				except c.error: break
				try: key_name = c.keyname(key)
				except ValueError: key_name = 'unknown' # e.g. "-1"
				break
			if key is None: continue
			if key != -1: log.debug('Keypress event: {} ({!r})', key, key_name)
			key_match = lambda *choices: self.key_match(key, *choices)

			if item_hl: # item-specific actions
				if key_match('up', 'k', 'p'): self.item_hl = item_hl.get_prev()
				elif key_match('down', 'j', 'n'): self.item_hl = item_hl.get_next()
				elif key_match('left', 'h', 'b'): item_hl.volume_change(-adjust_step)
				elif key_match('right', 'l', 'f'): item_hl.volume_change(adjust_step)
				elif key_match('ppage'): self.item_hl = item_hl.get_prev(fit.rows)
				elif key_match('npage'): self.item_hl = item_hl.get_next(fit.rows)
				elif key_match('home'): self.item_hl = self.menu.item_shift(t='first')
				elif key_match('end'): self.item_hl = self.menu.item_shift(t='last')
				elif key_match(' ', 'm'): item_hl.muted_toggle()
				elif key_name.isdigit(): # 1-0 keyboard row
					item_hl.volume = (float(key_name) or 10.0) / 10 # 0 is 100%
				elif key > 0: item_hl.special_action(self, key) # usually no-op

			if key_match('resize'):
				if self.conf.overkill_redraw:
					c.endwin()
					stdscr.refresh()
					win = self.c_win_init()
				else:
					win.resize(*win.getmaxyx())
			elif key_match('x'): self.mode_switch()
			elif key_match('q'): break
			elif key < 0: # signal - usually from pulse events
				for menu in set([self.menu, *(getattr(self, k) for k in self.mode_opts)]):
					if menu: menu.update(incremental=True)


	def run(self):
		import locale, curses # has a ton of global state
		locale.setlocale(locale.LC_ALL, '') # see top of "curses" module doc for rationale
		self.c = curses
		self.c.wrapper(self._run)


def main(args=None):
	conf = conf_read()

	import argparse
	parser = argparse.ArgumentParser(description='Command-line PulseAudio mixer tool.')

	group = parser.add_argument_group('Configuration file')
	group.add_argument('-c', '--conf',
		action='store', metavar='path', default=conf_read.path_default,
		help='Path to configuration file to use instead'
			' of the default one (%(default)s), can be missing or empty.')

	group = parser.add_argument_group('Configuration overrides')
	group.add_argument('-a', '--adjust-step',
		type=int, metavar='step', default=conf.adjust_step,
		help='Adjustment for a single keypress in interactive mode (0-100%%, default: %(default)s%%).')
	group.add_argument('-l', '--max-level',
		type=float, metavar='volume', default=conf.max_volume,
		help='Relative volume level to treat as max (default: %(default)s).')
	group.add_argument('-n', '--use-media-name',
		action='store_true', default=conf.use_media_name,
		help='Display streams by "media.name" property, if possible.'
			' Default is to prefer application name and process properties.')
	group.add_argument('--no-reconnect',
		action='store_false', dest='reconnect', default=conf.reconnect,
		help='Exit when pulseaudio server connection goes down.'
			' Default is to reconnect endlessly, i.e. run until manual exit.')

	group = parser.add_argument_group('Logarithmic scale conversion helpers')
	group.add_argument('-i', '--flat-to-log', metavar='(log-base:)value',
		help='Print value converted from flat to log (with specified base or e) scale and exit.')
	group.add_argument('-j', '--log-to-flat', metavar='(log-base:)value',
		help='Print value converted from log-scale (with specified base or e) to flat and exit.')

	group = parser.add_argument_group('Misc/debug')
	group.add_argument('-v', '--verbose',
		action='store_true', default=conf.verbose,
		help='Dont close stderr to see any sort of errors (which'
			' mess up curses interface, thus silenced that way by default).')
	group.add_argument('--dump-stream-params',
		action='store_true', help='Dump all parameters for each stream to stderr.')
	group.add_argument('--debug', action='store_true', help='Verbose operation mode.')
	group.add_argument('--fatal', action='store_true',
		help='Dont try too hard to recover from errors. For debugging purposes only.')

	args = sys.argv[1:] if args is None else args
	opts = parser.parse_args(args)

	global log, print

	conv = opts.flat_to_log or opts.log_to_flat
	if conv:
		vt, val = ('log-' + conv).split(':', 1) if ':' in conv else ('log', conv)
		val = float(val)
		conf = conf_read(volume_type=vt)
		func = conf._vol_get if opts.flat_to_log else conf._vol_set
		func_label = 'flat-to-log' if opts.flat_to_log else 'log-to-flat'
		return print(f'{func_label} (type={vt}): {val:.2f} -> {func(val):.2f}')

	if opts.conf: conf = conf_read(opts.conf)
	for k,v in vars(opts).items(): setattr(conf, k, v)
	del opts

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
					# else: break

	log.debug('Finished')

if __name__ == '__main__': sys.exit(main())

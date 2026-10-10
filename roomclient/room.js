// The room client: meet other devices on the LAN by a 4-letter code, then talk to them directly (WebRTC data channels) or, when that cannot connect, through the box. Plain script, no
// dependencies, served at /room/room.js. The box side is room.go; read its header for the wire format.
//
//   const room = new Room({name: 'Pixel', code: ''});     // '' creates a room, 'ABCD' joins one
//   room.on('ready',    r => ...)   // {id, code, resumed, peers}   fires again after every reconnect
//   room.on('peer',     p => ...)   // someone joined: {id, name, state}
//   room.on('peerleft', p => ...)
//   room.on('link',     p => ...)   // a peer's route changed: p.state is 'connecting' | 'direct' | 'relay' | 'away'
//   room.on('message',  m => ...)   // {from, data, via: 'direct' | 'relay'}; data is whatever the sender gave (JSON-able, or an ArrayBuffer)
//   room.on('status',   s => ...)   // 'connecting' | 'online' | 'reconnecting' (this page's own socket to the box)
//   room.on('closed',   c => ...)   // {reason}: the room ended, was full, or this page left; the object is finished
//   room.send(id, data, {unreliable})   -> 'direct' | 'relay' | false     (unreliable: unordered, may be dropped; for game input)
//   room.broadcast(data, opts)
//   room.rtt(id, 'direct' | 'relay' | 'box', n)  -> Promise<{n, lost, min, med, p95}>
//   room.leave()
//   Room.saved() -> {code, id, token} | null    what this tab remembers, so a reload comes back to the same place
//
// Direct is used whenever the data channel is open. Otherwise messages go through the box, where strings, numbers and objects work as they are and binary is limited to maxRelayBytes.
// A page that loses its socket reconnects by itself and keeps its place for the box's grace period; direct channels that stayed up carry on without it.
'use strict';
(function () {
  var ICE_WAIT = 6000, PING = 25000, DEAD = 65000, REOFFER = 3000, MAX_REOFFER = 3;
  var KEY = 'room:last';

  function num(id) { return parseInt(String(id).slice(1), 10) || 0; }
  function stats(a, lost) {
    if (!a.length) return { n: 0, lost: lost, min: null, med: null, p95: null };
    var s = a.slice().sort(function (x, y) { return x - y; });
    var r = function (v) { return Math.round(v * 10) / 10; };
    return { n: a.length, lost: lost, min: r(s[0]), med: r(s[s.length >> 1]), p95: r(s[Math.min(s.length - 1, Math.floor(s.length * 0.95))]) };
  }
  function b64(buf) {
    var u = buf instanceof ArrayBuffer ? new Uint8Array(buf) : new Uint8Array(buf.buffer, buf.byteOffset, buf.byteLength), s = '';
    for (var i = 0; i < u.length; i += 0x8000) s += String.fromCharCode.apply(null, u.subarray(i, i + 0x8000));
    return btoa(s);
  }
  function unb64(s) {
    var r = atob(s), u = new Uint8Array(r.length);
    for (var i = 0; i < r.length; i++) u[i] = r.charCodeAt(i);
    return u.buffer;
  }
  var isBin = function (d) { return d instanceof ArrayBuffer || ArrayBuffer.isView(d); };

  function Room(o) {
    o = o || {};
    this.name = o.name || 'device';
    this.code = String(o.code || '').toUpperCase();
    this.rtc = o.rtc !== false && typeof RTCPeerConnection !== 'undefined';
    this.persist = o.persist !== false;
    this.url = o.url || ((location.protocol === 'https:' ? 'wss://' : 'ws://') + location.host + '/api/room');
    this.maxRelayBytes = 8 * 1024;
    this.id = ''; this.token = ''; this.status = 'connecting';
    this.peers = new Map();
    this._h = {}; this._ws = null; this._tries = 0; this._closed = false; this._fatal = false; this._seen = 0;
    this._wait = {}; this._k = 0; this._timers = {};
    var s = this.persist && Room.saved();
    if (s && this.code && s.code === this.code) { this.id = s.id; this.token = s.token; }
    var self = this;
    this._wake = function () { self._onWake(); };
    if (typeof window !== 'undefined') {
      window.addEventListener('online', this._wake);
      window.addEventListener('pageshow', this._wake);
      document.addEventListener('visibilitychange', function () { if (document.visibilityState === 'visible') self._wake(); });
    }
    this._connect();
  }
  Room.saved = function () {
    try { var s = JSON.parse(sessionStorage.getItem(KEY) || 'null'); return s && s.code && s.id && s.token ? s : null; } catch (e) { return null; }
  };

  var P = Room.prototype;
  P.on = function (ev, fn) { (this._h[ev] || (this._h[ev] = [])).push(fn); return this; };
  P._emit = function (ev, a) { (this._h[ev] || []).slice().forEach(function (f) { try { f(a); } catch (e) { console.error(e); } }); };
  P._setStatus = function (s) { if (this.status !== s) { this.status = s; this._emit('status', s); } };
  P._save = function () { if (this.persist) try { sessionStorage.setItem(KEY, JSON.stringify({ code: this.code, id: this.id, token: this.token })); } catch (e) { /* storage blocked */ } };
  P._forget = function () { try { sessionStorage.removeItem(KEY); } catch (e) { /* storage blocked */ } };

  // ---- the socket to the box ----
  P._box = function (to, d) {
    var ws = this._ws;
    if (!ws || ws.readyState !== 1) return false;
    ws.send(JSON.stringify({ t: 'to', to: to, d: d }));
    return true;
  };
  P._connect = function () {
    if (this._closed) return;
    var self = this, ws;
    this._setStatus(this.id ? 'reconnecting' : 'connecting');
    try { ws = new WebSocket(this.url); } catch (e) { return this._retry(); }
    this._ws = ws; this._seen = Date.now();
    ws.onopen = function () {
      var j = { t: 'join', room: self.code, name: self.name };
      if (self.id && self.token && self.code) { j.id = self.id; j.token = self.token; }
      ws.send(JSON.stringify(j));
    };
    ws.onmessage = function (e) {
      self._seen = Date.now();
      var m; try { m = JSON.parse(e.data); } catch (_) { return; }
      self._onBox(m);
    };
    ws.onclose = function () {
      if (self._ws !== ws) return;
      self._ws = null; clearInterval(self._hb);
      if (self._closed || self._fatal) return;
      self._setStatus('reconnecting');
      self._retry();
    };
    ws.onerror = function () { /* onclose follows */ };
  };
  P._retry = function (now) {
    var self = this;
    clearTimeout(this._rt);
    if (this._closed || this._fatal) return;
    var d = now ? 0 : Math.min(5000, 500 * Math.pow(2, this._tries++)) * (0.75 + Math.random() * 0.5);
    this._rt = setTimeout(function () { if (!self._ws) self._connect(); }, d);
  };
  P._onWake = function () {
    var self = this;
    if (this._closed || this._fatal) return;
    if (!this._ws) { this._tries = 0; this._retry(true); return; }
    var ws = this._ws;
    if (ws.readyState !== 1) return;
    var t0 = Date.now();
    ws.send('{"t":"ping"}'); // a socket that died while the page slept answers nothing: replace it
    setTimeout(function () { if (ws === self._ws && self._seen < t0) ws.close(); }, 4000);
  };
  P._startBeat = function () {
    var self = this;
    clearInterval(this._hb);
    this._hb = setInterval(function () {
      var ws = self._ws;
      if (!ws || ws.readyState !== 1) return;
      if (Date.now() - self._seen > DEAD) { ws.close(); return; }
      ws.send('{"t":"ping"}');
    }, PING);
  };

  P._onBox = function (m) {
    var p;
    switch (m.t) {
      case 'hello': return this._hello(m);
      case 'join':
        p = this._peer(m.id, m.name); p.away = false;
        this._emit('peer', this._pub(p)); this._ensureLink(p);
        return;
      case 'leave':
        p = this.peers.get(m.id);
        if (p) { this._drop(p); this.peers.delete(m.id); this._emit('peerleft', { id: p.id, name: p.name }); }
        return;
      case 'away':
        p = this.peers.get(m.id);
        if (p) { p.away = true; this._link(p); }
        return;
      case 'back':
        p = this.peers.get(m.id);
        if (p) { p.away = false; this._link(p); if (!this._direct(p)) this._ensureLink(p, true); }
        return;
      case 'from': return this._from(m.from, m.d || {});
      case 'err':
        if (m.m === 'expired') { var self = this; this.id = ''; this.token = ''; this._forget(); this._tries = 0; this.peers.forEach(function (p) { self._drop(p); }); return; } // the socket closes next; _connect joins afresh with the same code
        this._fatal = true; this._finish(m.m || 'error');
        return;
    }
  };
  P._hello = function (m) {
    var self = this, seen = {};
    this.id = m.id; this.token = m.token; this.code = m.room; this._tries = 0;
    this._save(); this._startBeat();
    (m.peers || []).forEach(function (i) {
      var isNew = !self.peers.has(i.id), p = self._peer(i.id, i.name);
      p.away = !!i.away; seen[i.id] = 1;
      if (isNew) self._emit('peer', self._pub(p));
    });
    this.peers.forEach(function (p, id) {
      if (!seen[id]) { self._drop(p); self.peers.delete(id); self._emit('peerleft', { id: id, name: p.name }); }
    });
    this._setStatus('online');
    this._emit('ready', { id: this.id, code: this.code, resumed: !!m.resumed, peers: this._list() });
    this.peers.forEach(function (p) { if (!self._direct(p)) self._ensureLink(p, true); else self._link(p); });
  };

  // ---- peers and their links ----
  P._peer = function (id, name) {
    var p = this.peers.get(id);
    if (!p) { p = { id: id, name: name || '', away: false, pc: null, chR: null, chU: null, g: 0, q: Promise.resolve(), relay: false, tries: 0, state: '' }; this.peers.set(id, p); }
    else if (name) p.name = name;
    return p;
  };
  P._direct = function (p) { return !!(p.chR && p.chR.readyState === 'open'); };
  P._state = function (p) { return this._direct(p) ? 'direct' : p.away ? 'away' : p.relay || !this.rtc ? 'relay' : 'connecting'; };
  P._pub = function (p) { return { id: p.id, name: p.name, state: this._state(p), away: p.away }; };
  P._list = function () { var self = this, a = []; this.peers.forEach(function (p) { a.push(self._pub(p)); }); return a; };
  P._link = function (p) {
    var s = this._state(p);
    if (s !== p.state) { p.state = s; this._emit('link', this._pub(p)); }
  };
  P._drop = function (p) {
    clearTimeout(p.timer);
    var pc = p.pc;
    p.pc = null; p.chR = null; p.chU = null; p.relay = false; p.state = '';
    if (pc) { pc.onicecandidate = pc.onconnectionstatechange = pc.ondatachannel = null; try { pc.close(); } catch (e) { /* closed */ } }
  };
  P._ensureLink = function (p, force) {
    var self = this;
    if (!this.rtc) { p.relay = true; this._link(p); return; }
    if (this._direct(p) && !force) { this._link(p); return; }
    clearTimeout(p.timer);
    p.timer = setTimeout(function () { if (!self._direct(p) && !p.away) { p.relay = true; self._link(p); } }, ICE_WAIT);
    if (num(this.id) > num(p.id)) { if (!p.pc || force) this._offer(p); } // the newer page makes the offer, so two pages never both do
    this._link(p);
  };
  P._pc = function (p, g) {
    var self = this, pc = new RTCPeerConnection({ iceServers: [] }); // the LAN only: no STUN, and the box may have no internet
    pc.onicecandidate = function (e) { if (e.candidate && p.pc === pc) self._box(p.id, { g: g, ice: e.candidate }); };
    pc.onconnectionstatechange = function () {
      if (p.pc !== pc) return;
      if (pc.connectionState === 'failed' || pc.connectionState === 'closed') { p.relay = true; self._link(p); self._reoffer(p); }
      else if (pc.connectionState === 'disconnected') setTimeout(function () { if (p.pc === pc && pc.connectionState === 'disconnected') { self._link(p); self._reoffer(p); } }, 2000);
    };
    pc.ondatachannel = function (e) { if (e.channel.label === 'r') p.chR = e.channel; else p.chU = e.channel; self._wire(p, e.channel); };
    return pc;
  };
  P._reoffer = function (p) {
    var self = this;
    if (this._closed || p.away || p.tries >= MAX_REOFFER || num(this.id) <= num(p.id)) return;
    p.tries++;
    clearTimeout(p.rt);
    p.rt = setTimeout(function () { if (!self._direct(p) && self.peers.get(p.id) === p) self._offer(p); }, REOFFER);
  };
  P._offer = function (p) {
    var self = this, g = Date.now();
    if (g <= p.g) g = p.g + 1;
    var old = p.pc; p.pc = null; if (old) { old.onicecandidate = old.onconnectionstatechange = old.ondatachannel = null; try { old.close(); } catch (e) { /* closed */ } }
    p.g = g; p.chR = null; p.chU = null;
    var pc = p.pc = this._pc(p, g);
    p.chR = pc.createDataChannel('r', { ordered: true });
    p.chU = pc.createDataChannel('u', { ordered: false, maxRetransmits: 0 });
    this._wire(p, p.chR); this._wire(p, p.chU);
    p.q = p.q.then(function () { return pc.createOffer(); }).then(function (o) { return pc.setLocalDescription(o); })
      .then(function () { self._box(p.id, { g: g, sdp: pc.localDescription }); }).catch(function () { p.relay = true; self._link(p); });
  };
  P._wire = function (p, ch) {
    var self = this;
    ch.binaryType = 'arraybuffer';
    ch.onopen = function () { if (ch === p.chR) { p.relay = false; p.tries = 0; clearTimeout(p.timer); } self._link(p); };
    ch.onclose = function () { if (ch === p.chR) { self._link(p); self._reoffer(p); } };
    ch.onmessage = function (e) { self._chan(p, e.data); };
  };
  P._signal = function (p, d) {
    var self = this, pc;
    if (!this.rtc) return;
    if (d.sdp && d.sdp.type === 'offer') {
      if (d.g <= p.g) return; // an old or repeated offer
      this._drop(p); p.g = d.g; pc = p.pc = this._pc(p, d.g);
      p.q = p.q.then(function () { return pc.setRemoteDescription(d.sdp); }).then(function () { return pc.createAnswer(); })
        .then(function (a) { return pc.setLocalDescription(a); }).then(function () { self._box(p.id, { g: d.g, sdp: pc.localDescription }); })
        .catch(function () { p.relay = true; self._link(p); });
      clearTimeout(p.timer);
      p.timer = setTimeout(function () { if (!self._direct(p) && !p.away) { p.relay = true; self._link(p); } }, ICE_WAIT);
    } else if (d.g === p.g && p.pc) {
      pc = p.pc;
      if (d.sdp) p.q = p.q.then(function () { return pc.setRemoteDescription(d.sdp); }).catch(function () { /* the next offer starts over */ });
      else if (d.ice) p.q = p.q.then(function () { return pc.addIceCandidate(d.ice); }).catch(function () { /* a candidate for a link that is gone */ });
    }
  };

  // ---- messages ----
  P._from = function (from, d) {
    var p = this.peers.get(from);
    if (from === this.id) { if (d.c === 'q') this._pong('box', d.k); return; }
    if (!p) return;
    if (d.g !== undefined && (d.sdp || d.ice)) return this._signal(p, d);
    if (d.c) return this._ctl(p, d, 'relay');
    if (d.b !== undefined) this._emit('message', { from: from, data: unb64(d.b), via: 'relay' });
    else if ('m' in d) this._emit('message', { from: from, data: d.m, via: 'relay' });
  };
  P._chan = function (p, raw) {
    if (typeof raw !== 'string') { this._emit('message', { from: p.id, data: raw, via: 'direct' }); return; }
    var d; try { d = JSON.parse(raw); } catch (e) { return; }
    if (d.c) this._ctl(p, d, 'direct');
    else if ('m' in d) this._emit('message', { from: p.id, data: d.m, via: 'direct' });
  };
  P._ctl = function (p, d, via) {
    if (d.c === 'p') { // a ping: answer by the way it came
      if (via === 'direct' && p.chU && p.chU.readyState === 'open') p.chU.send(JSON.stringify({ c: 'q', k: d.k }));
      else this._box(p.id, { c: 'q', k: d.k, v: via });
    } else if (d.c === 'q') this._pong(via, d.k);
  };
  P._pong = function (via, k) { var w = this._wait[via + k]; if (w) { delete this._wait[via + k]; w(performance.now()); } };

  P.send = function (to, data, o) {
    var p = this.peers.get(to);
    if (!p) return false;
    var ch = o && o.unreliable ? p.chU : p.chR;
    if (this._direct(p) && ch && ch.readyState === 'open') {
      ch.send(isBin(data) ? data : JSON.stringify({ m: data }));
      return 'direct';
    }
    if (p.away) return false;
    if (isBin(data)) {
      if (data.byteLength > this.maxRelayBytes) throw new Error('too big for the box relay (' + this.maxRelayBytes + ' bytes)');
      return this._box(to, { b: b64(data) }) ? 'relay' : false;
    }
    return this._box(to, { m: data }) ? 'relay' : false;
  };
  P.broadcast = function (data, o) {
    var self = this, n = 0;
    this.peers.forEach(function (p) { if (self.send(p.id, data, o)) n++; });
    return n;
  };
  P.buffered = function (id) { var p = this.peers.get(id); return p && p.chR ? p.chR.bufferedAmount : 0; };

  // Round trips: 'direct' over the data channel, 'relay' to that peer through the box and back, 'box' to the box and back to yourself.
  P.rtt = function (id, via, n) {
    var self = this, p = this.peers.get(id), out = [], lost = 0, i = 0;
    n = n || 20;
    return new Promise(function (done) {
      (function next() {
        if (i >= n) return done(stats(out, lost));
        var k = ++self._k, key = via + k, t0 = performance.now(), sent = false;
        if (via === 'direct') { if (p && p.chU && p.chU.readyState === 'open') { p.chU.send(JSON.stringify({ c: 'p', k: k })); sent = true; } }
        else if (via === 'relay') sent = self._box(id, { c: 'p', k: k });
        else sent = self._box(self.id, { c: 'q', k: k });
        i++;
        if (!sent) { lost++; return setTimeout(next, 60); }
        var timer = setTimeout(function () { delete self._wait[key]; lost++; next(); }, via === 'direct' ? 800 : 1500);
        self._wait[key] = function (t) { clearTimeout(timer); out.push(t - t0); setTimeout(next, 60); };
      })();
    });
  };

  // ---- ending ----
  P._finish = function (reason) {
    if (this._closed) return;
    this._closed = true;
    var self = this;
    clearInterval(this._hb); clearTimeout(this._rt);
    this.peers.forEach(function (p) { self._drop(p); clearTimeout(p.rt); });
    if (typeof window !== 'undefined') { window.removeEventListener('online', this._wake); window.removeEventListener('pageshow', this._wake); }
    var ws = this._ws; this._ws = null;
    if (ws) try { ws.close(); } catch (e) { /* closed */ }
    this._forget();
    this._setStatus('closed');
    this._emit('closed', { reason: reason });
  };
  P.leave = function () {
    var ws = this._ws;
    if (ws && ws.readyState === 1) try { ws.send('{"t":"bye"}'); } catch (e) { /* closed */ }
    this._finish('left');
  };

  window.Room = Room;
})();

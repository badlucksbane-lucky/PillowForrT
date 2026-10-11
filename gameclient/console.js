// The game console (the screen): owns the room, the players, the game loop and the pause rule. Plain script, depends on room.js. Served at /game/console.js.
// Protocol and widget set: docs/GAMES.md. A game registers itself with Games.register({...}) and is created with a ctx:
//
//   Games.register({id, name, players: {min, max}, widgets: [{type:'stick'|'dpad'|'buttons'|'pointer'|'tilt', names?}], orientation: 'any'|'portrait'|'landscape',
//     create(ctx) -> {onJoin(p), onLeave(p), onButton(p, name, down), onPick(p, panelId, index), onPointer(p, x, y, down), tick(dt), render(g, w, h)}})
//   ctx: {players: () => connected players, send panel: panel(p, {id, title, items}) / panel(p, null), rumble(p, ms), audio: AudioContext|null, end()}
//   a player p: {id, slot, name, color, away, stick: {x, y}, ptr: {x, y, down}, tilt: {b, g}, btn: {A: bool, ...}}
'use strict';
(function () {
  var COLORS = ['#e6492d', '#2f7de1', '#2e9e4f', '#e0a800', '#8e4fd1', '#14a3a3', '#e0589a', '#7a8a99'];
  var STALE = 4000; // a player silent this long (the phone sends a heartbeat every second) counts as away, even while the browser still shows the data channel open: it can take half a minute to notice
  var DEADMAN = 600; // a stick that has gone quiet this long while held is let go: its release may have been dropped on the unordered channel
  var Games = { list: {}, register: function (g) { this.list[g.id] = g; } };

  function Console(o) {
    var self = this;
    this.canvas = o.canvas; this.g = o.canvas.getContext('2d');
    this.players = new Map(); // peer id -> player
    this.game = null; this.inst = null; this.state = 'lobby'; // lobby | play | paused
    this.audio = null; this.staleMs = STALE; this.onUpdate = o.onUpdate || function () {};
    var saved = Room.saved();
    this.room = new Room({ name: 'screen', code: o.code || (saved && saved.code) || '', joinPath: '/pad' });
    this.room.on('ready', function () { self.players.forEach(function (p) { self._layout(p); }); self.onUpdate(); })
      .on('peerleft', function (p) { self._leave(p.id); })
      .on('link', function (p) { self._link(p); })
      .on('message', function (m) { self._msg(m); })
      .on('status', function () { self.onUpdate(); })
      .on('closed', function (c) { self.closed = c.reason; self.onUpdate(); });
    this._last = performance.now();
    this._frame = function (t) { self._tick(t); requestAnimationFrame(self._frame); };
    requestAnimationFrame(this._frame);
    this._dead = setInterval(function () { self._deadman(); }, 200);
    this._wake();
  }
  var P = Console.prototype;

  // ---- players ----
  P._free = function () { var used = {}; this.players.forEach(function (p) { used[p.slot] = 1; }); for (var i = 0; ; i++) if (!used[i]) return i; };
  P._maxPlayers = function () { return this.game ? this.game.players.max : 8; };
  P._msg = function (m) {
    var d = m.data, p = this.players.get(m.from);
    if (!d || typeof d !== 'object') return;
    if (p) { p.heard = performance.now(); if (p.stale) { p.stale = false; this._away(p); } }
    if (d.t === 'hb') return;
    if (d.t === 'hello') { // a controller says hello again after every reconnect and reload: its input counters start over
      if (!p) {
        if (this.players.size >= this._maxPlayers()) { this.room.send(m.from, { t: 'layout', state: 'full', msg: 'Room is full' }); return; }
        var slot = this._free();
        p = { id: m.from, slot: slot, name: String(d.name || 'Player').slice(0, 16), color: COLORS[slot % COLORS.length], away: false, gone: false, stale: false, heard: performance.now(), seq: {}, seen: 0,
          stick: { x: 0, y: 0 }, ptr: { x: 0, y: 0, down: false }, tilt: { b: 0, g: 0 }, btn: {} };
        this.players.set(m.from, p);
        if (this.inst && this.inst.onJoin) this.inst.onJoin(p);
      } else { p.name = String(d.name || p.name).slice(0, 16); p.seq = {}; }
      this._layout(p); this.onUpdate();
      return;
    }
    if (!p) return;
    switch (d.t) {
      case 'in': // continuous input; stale sequence numbers (the unordered channel may reorder) are dropped
        var kind = d.k || 'stick';
        if (typeof d.s === 'number') { if (d.s <= (p.seq[kind] === undefined ? -1 : p.seq[kind])) return; p.seq[kind] = d.s; }
        p.seen = performance.now();
        if (kind === 'tilt') { p.tilt.b = +d.b || 0; p.tilt.g = +d.g || 0; return; }
        if (kind === 'ptr') {
          var was = p.ptr.down; p.ptr.x = +d.x || 0; p.ptr.y = +d.y || 0; p.ptr.down = !!d.d;
          if (this.state === 'play' && this.inst && this.inst.onPointer && (p.ptr.down || was)) this.inst.onPointer(p, p.ptr.x, p.ptr.y, p.ptr.down);
          return;
        }
        p.stick.x = clamp(+d.x || 0); p.stick.y = clamp(+d.y || 0);
        return;
      case 'b':
        p.btn[d.b] = !!d.d;
        if (this.state === 'play' && this.inst && this.inst.onButton) this.inst.onButton(p, String(d.b), !!d.d);
        return;
      case 'pick':
        if (this.state === 'play' && this.inst && this.inst.onPick) this.inst.onPick(p, d.id, d.i | 0);
        return;
    }
  };
  function clamp(v) { return v < -1 ? -1 : v > 1 ? 1 : v; }
  P._deadman = function () {
    var now = performance.now(), self = this;
    this.players.forEach(function (p) {
      if ((p.stick.x || p.stick.y) && now - p.seen > DEADMAN) { p.stick.x = 0; p.stick.y = 0; }
      if (!p.stale && now - p.heard > self.staleMs) { p.stale = true; self._away(p); }
    });
  };
  P._leave = function (id) {
    var p = this.players.get(id);
    if (!p) return;
    this.players.delete(id);
    if (this.inst && this.inst.onLeave) this.inst.onLeave(p);
    this._resumeIfReady(); this.onUpdate();
  };
  P.drop = function (id) { this._leave(id); }; // "continue without": the screen gives up waiting for a player who is away
  P._link = function (peer) {
    var p = this.players.get(peer.id);
    if (!p) return;
    p.gone = peer.state === 'away';
    this._away(p);
  };
  // a player is away when the box says so or when they have gone silent; either pauses the game until they are back (or are dropped)
  P._away = function (p) {
    p.away = p.gone || p.stale;
    if (p.away) { p.stick.x = p.stick.y = 0; p.btn = {}; if (this.state === 'play') { this.state = 'paused'; this._state(); } }
    else this._resumeIfReady();
    this.onUpdate();
  };
  P.awayPlayers = function () { var a = []; this.players.forEach(function (p) { if (p.away) a.push(p); }); return a; };
  P._resumeIfReady = function () { if (this.state === 'paused' && !this.awayPlayers().length) { this.state = 'play'; this._state(); } };

  // ---- what each phone shows ----
  P._layout = function (p) {
    var g = this.game, playing = g && this.state !== 'lobby';
    this.room.send(p.id, { t: 'layout', state: this.state, slot: p.slot, color: p.color, name: p.name, game: g ? g.name : '',
      widgets: playing ? g.widgets : [], orientation: playing ? g.orientation || 'any' : 'any',
      msg: this.state === 'lobby' ? 'Look at the screen' : this.state === 'paused' ? 'Paused' : '' });
  };
  P._state = function () { var self = this; this.players.forEach(function (p) { self._layout(p); }); this.onUpdate(); };

  // ---- games ----
  P.select = function (id) { if (this.state === 'lobby') { this.game = Games.list[id] || null; this._state(); } };
  P.canStart = function () { return !!this.game && this.state === 'lobby' && this.players.size >= this.game.players.min && this.players.size <= this.game.players.max; };
  P.start = function () { // from a tap, so the audio context may start
    if (!this.canStart()) return false;
    var self = this;
    try { this.audio = this.audio || new (window.AudioContext || window.webkitAudioContext)(); if (this.audio.state === 'suspended') this.audio.resume(); } catch (e) { /* no audio */ }
    var ctx = {
      players: function () { return Array.from(self.players.values()); },
      panel: function (p, panel) { self.room.send(p.id, { t: 'panel', panel: panel }); },
      rumble: function (p, ms) { self.room.send(p.id, { t: 'rumble', ms: ms }); },
      audio: this.audio, end: function () { self.stop(); }
    };
    this.inst = this.game.create(ctx);
    this.state = 'play';
    this.players.forEach(function (p) { if (self.inst.onJoin) self.inst.onJoin(p); });
    this._state();
    return true;
  };
  P.stop = function () {
    if (this.state === 'lobby') return;
    this.state = 'lobby'; this.inst = null;
    this.players.forEach(function (p) { p.stick.x = p.stick.y = 0; p.btn = {}; p.ptr.down = false; });
    this._state();
  };
  P._tick = function (t) {
    var dt = Math.min(0.05, (t - this._last) / 1000); this._last = t;
    var c = this.canvas, dpr = window.devicePixelRatio || 1, w = c.clientWidth, h = c.clientHeight;
    if (c.width !== Math.round(w * dpr) || c.height !== Math.round(h * dpr)) { c.width = Math.round(w * dpr); c.height = Math.round(h * dpr); }
    var g = this.g; g.setTransform(dpr, 0, 0, dpr, 0, 0);
    if (this.state === 'play' && this.inst) { if (this.inst.tick) this.inst.tick(dt); }
    g.fillStyle = '#16140f'; g.fillRect(0, 0, w, h);
    if (this.inst && this.state !== 'lobby' && this.inst.render) this.inst.render(g, w, h);
  };

  // keep the screen on; browsers release it when the tab is hidden, so ask again when it is back
  P._wake = function () {
    var self = this;
    var ask = function () { try { if (navigator.wakeLock && document.visibilityState === 'visible') navigator.wakeLock.request('screen').then(function (l) { self._lock = l; }, function () {}); } catch (e) { /* unsupported */ } };
    document.addEventListener('visibilitychange', ask); ask();
  };
  P.joinUrl = function () { return this.room.joinUrl('/pad'); };

  window.Games = Games; window.GameConsole = Console;
})();

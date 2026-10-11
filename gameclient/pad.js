// The controller (the phone): joins the screen's room, builds the widgets the game asks for, and sends input. Plain script, depends on room.js. Served at /game/pad.js.
// Protocol: docs/GAMES.md. Coordinates: stick x right and y down, both -1..1 (0 inside the dead zone); pointer x and y 0..1 inside its area; tilt beta and gamma in degrees.
//   const pad = new Pad({root: element, name: 'Ben', code: 'ABCD'});   pad.room is the Room; pad.layout is the last layout from the screen
'use strict';
(function () {
  var RATE = 33, REPEAT = 100, DEAD = 0.12;

  function el(tag, cls, text) { var e = document.createElement(tag); if (cls) e.className = cls; if (text) e.textContent = text; return e; }

  function Pad(o) {
    var self = this;
    this.root = o.root; this.name = o.name || 'Player';
    this.layout = null; this.screen = ''; this.seq = 0; this.veil = null;
    this.st = { stick: { x: 0, y: 0, dirty: false, at: 0 }, ptr: { x: 0, y: 0, d: 0, dirty: false, at: 0 }, tilt: { b: 0, g: 0, dirty: false, at: 0, on: false } };
    this.room = new Room({ name: this.name, code: o.code || '', joinPath: '/pad' });
    window.room = this.room;
    this.room.on('ready', function () { self._hello(); self._paint(); })
      .on('peer', function (p) { self._hello(p.id); })
      .on('peerleft', function (p) { if (p.id === self.screen) { self.screen = ''; self.layout = null; self._paint(); } })
      .on('link', function (p) { if (p.id === self.screen && p.state !== 'away') self._hello(p.id); self._paint(); })
      .on('message', function (m) { self._msg(m); })
      .on('status', function () { self._paint(); })
      .on('closed', function (c) { self.closed = c.reason; self._paint(); });
    this._tm = setInterval(function () { self._flush(); }, RATE);
    this._hb = setInterval(function () { self._to({ t: 'hb' }, { unreliable: true }); }, 1000); // lets the screen tell a phone that went to sleep from one that is just still
    this._hl = setInterval(function () { if (!self.layout && self.room.status === 'online') self._hello(); }, 1500); // until a screen answers
    window.addEventListener('resize', function () { self._paint(); }); // an orientation hint is re-checked
    this._wake(); this._paint();
  }
  var P = Pad.prototype;

  P._hello = function (to) { var m = { t: 'hello', name: this.name }; if (to) this.room.send(to, m); else this.room.broadcast(m); };
  P._msg = function (m) {
    var d = m.data;
    if (!d || typeof d !== 'object') return;
    if (d.t === 'layout') { this.screen = m.from; this.layout = d; this._build(); if (d.state === 'lobby' || d.state === 'full') this.panelData = null; else if (this.panelData) this._panel(this.panelData); this._paint(); } // a pause or resume rebuilds the page, so a private panel is put back
    else if (m.from !== this.screen) return;
    else if (d.t === 'panel') this._panel(d.panel);
    else if (d.t === 'rumble') this.vibrate(d.ms);
  };
  P.vibrate = function (ms) { try { if (navigator.vibrate) navigator.vibrate(Math.min(+ms || 0, 1000)); } catch (e) { /* none */ } }; // not on iOS

  // ---- sending ----
  P._to = function (data, o) { if (this.screen) this.room.send(this.screen, data, o); };
  P._in = function (k, fields, both) {
    var d = { t: 'in', k: k, s: ++this.seq }; for (var f in fields) d[f] = fields[f];
    this._to(d, { unreliable: true });
    if (both) this._to(d); // a release goes on the reliable channel as well, so a dropped packet cannot leave a stick held
  };
  P._flush = function () {
    var now = performance.now(), s = this.st;
    if (s.stick.dirty || ((s.stick.x || s.stick.y) && now - s.stick.at > REPEAT)) { s.stick.dirty = false; s.stick.at = now; this._in('stick', { x: s.stick.x, y: s.stick.y }, !s.stick.x && !s.stick.y); }
    if (s.ptr.dirty) { s.ptr.dirty = false; this._in('ptr', { x: s.ptr.x, y: s.ptr.y, d: s.ptr.d }, !s.ptr.d); }
    if (s.tilt.dirty && s.tilt.on) { s.tilt.dirty = false; this._in('tilt', { b: s.tilt.b, g: s.tilt.g }); }
  };
  P.button = function (name, down) { this._to({ t: 'b', b: name, d: down ? 1 : 0 }); if (down) this.vibrate(12); };

  // ---- widgets ----
  P._build = function () {
    var L = this.layout, r = this.root, self = this;
    r.replaceChildren();
    var top = el('div', 'top'), dot = el('span', 'dot'), who = el('b', '', L.name || this.name);
    dot.style.background = L.color || '#888';
    top.append(dot, who, el('span', 'mut', L.game || ''));
    var area = el('div', 'area'), left = el('div', 'left'), right = el('div', 'right');
    (L.widgets || []).forEach(function (w) {
      if (w.type === 'stick' || w.type === 'dpad') left.append(self._stick(w.type === 'dpad'));
      else if (w.type === 'pointer') left.append(self._pointer());
      else if (w.type === 'buttons') right.append(self._buttons(w.names || ['A']));
      else if (w.type === 'tilt') right.append(self._tilt());
    });
    area.append(left, right);
    if (!right.children.length) area.classList.add('solo'); // only a left widget: it takes the whole width
    if (left.querySelector('.pointer')) area.classList.add('ptr');
    this.panelEl = el('div', 'panel'); this.panelEl.hidden = true;
    this.veil = el('div', 'veil'); this.veil.hidden = true;
    r.append(top, area, this.panelEl, this.veil);
  };
  P._stick = function (dpad) {
    var self = this, base = el('div', 'stick' + (dpad ? ' dpad' : '')), knob = el('div', 'knob'), pid = null;
    base.append(knob);
    var set = function (x, y) {
      var s = self.st.stick; if (s.x === x && s.y === y) return;
      var edge = !(s.x || s.y) !== !(x || y); // starting or stopping: send at once, not at the next tick
      s.x = x; s.y = y; s.dirty = true;
      if (edge) self._flush();
    };
    var move = function (e) {
      var b = base.getBoundingClientRect(), rad = b.width / 2, dx = (e.clientX - (b.left + rad)) / rad, dy = (e.clientY - (b.top + rad)) / rad, v = Math.hypot(dx, dy);
      if (v > 1) { dx /= v; dy /= v; v = 1; }
      knob.style.transform = 'translate(' + dx * rad * 0.55 + 'px,' + dy * rad * 0.55 + 'px)';
      if (v < DEAD) return set(0, 0);
      if (dpad) { if (v < 0.35) return set(0, 0); if (Math.abs(dx) > Math.abs(dy)) return set(dx > 0 ? 1 : -1, 0); return set(0, dy > 0 ? 1 : -1); }
      set(Math.round(dx * 100) / 100, Math.round(dy * 100) / 100);
    };
    var up = function (e) { if (e.pointerId !== pid) return; pid = null; knob.style.transform = ''; set(0, 0); self._flush(); };
    base.addEventListener('pointerdown', function (e) { if (pid !== null) return; pid = e.pointerId; try { base.setPointerCapture(pid); } catch (x) { /* gone */ } move(e); e.preventDefault(); });
    base.addEventListener('pointermove', function (e) { if (e.pointerId === pid) move(e); });
    base.addEventListener('pointerup', up); base.addEventListener('pointercancel', up);
    return base;
  };
  P._pointer = function () {
    var self = this, area = el('div', 'pointer', 'touch'), pid = null;
    var at = function (e, d) {
      var b = area.getBoundingClientRect(), s = self.st.ptr;
      var edge = s.d !== d; // a touch or a release is sent at once, so a quick tap is not lost between ticks
      s.x = Math.min(1, Math.max(0, (e.clientX - b.left) / b.width)); s.y = Math.min(1, Math.max(0, (e.clientY - b.top) / b.height)); s.d = d; s.dirty = true;
      if (edge) self._flush();
    };
    var up = function (e) { if (e.pointerId !== pid) return; pid = null; at(e, 0); self._flush(); };
    area.addEventListener('pointerdown', function (e) { if (pid !== null) return; pid = e.pointerId; try { area.setPointerCapture(pid); } catch (x) { /* gone */ } at(e, 1); e.preventDefault(); });
    area.addEventListener('pointermove', function (e) { if (e.pointerId === pid) at(e, 1); });
    area.addEventListener('pointerup', up); area.addEventListener('pointercancel', up);
    return area;
  };
  P._buttons = function (names) {
    var self = this, box = el('div', 'buttons n' + names.length);
    names.forEach(function (n) {
      var b = el('button', 'btn', n), pid = null;
      var up = function (e) { if (e.pointerId !== pid) return; pid = null; b.classList.remove('on'); self.button(n, false); };
      b.addEventListener('pointerdown', function (e) { if (pid !== null) return; pid = e.pointerId; try { b.setPointerCapture(pid); } catch (x) { /* gone */ } b.classList.add('on'); self.button(n, true); e.preventDefault(); });
      b.addEventListener('pointerup', up); b.addEventListener('pointercancel', up);
      b.addEventListener('contextmenu', function (e) { e.preventDefault(); });
      box.append(b);
    });
    return box;
  };
  // Tilt: iOS asks for permission, and only from a tap; Android just starts. Sends beta and gamma in degrees.
  P._tilt = function () {
    var self = this, b = el('button', 'tiltbtn', 'Enable tilt');
    var on = function () {
      window.addEventListener('deviceorientation', function (e) {
        if (e.beta == null && e.gamma == null) return; // a browser with no sensor still fires one empty event
        var s = self.st.tilt, nb = Math.round((e.beta || 0) * 2) / 2, ng = Math.round((e.gamma || 0) * 2) / 2;
        if (nb !== s.b || ng !== s.g) { s.b = nb; s.g = ng; s.dirty = true; }
      });
      self.st.tilt.on = true; b.hidden = true;
    };
    b.onclick = function () {
      var D = window.DeviceOrientationEvent;
      if (D && typeof D.requestPermission === 'function') D.requestPermission().then(function (r) { if (r === 'granted') on(); else b.textContent = 'Tilt blocked'; }, function () { b.textContent = 'Tilt blocked'; });
      else on();
    };
    return b;
  };
  // A private panel: a title and a list of choices that only this phone sees; the answer is the index. After a pick the others grey out until the next panel.
  P._panel = function (d) {
    var self = this, pn = this.panelEl;
    this.panelData = d;
    if (!pn) return;
    pn.replaceChildren();
    if (!d) { pn.hidden = true; return; }
    pn.hidden = false;
    if (d.title) pn.append(el('div', 'ptitle', d.title));
    (d.items || []).forEach(function (t, i) {
      var b = el('button', 'pick', String(t));
      b.onclick = function () { self._to({ t: 'pick', id: d.id, i: i }); self.vibrate(10); Array.prototype.forEach.call(pn.querySelectorAll('.pick'), function (x) { x.disabled = true; }); b.classList.add('chosen'); };
      pn.append(b);
    });
  };

  // ---- status overlay ----
  P._paint = function () {
    var r = this.root, L = this.layout, msg = '';
    if (this.closed) msg = this.closed === 'left' ? 'You left' : this.closed;
    else if (this.room.status !== 'online') msg = 'Reconnecting…';
    else if (!this.screen) msg = 'Looking for the screen…';
    else if (L && L.state === 'full') msg = 'Room is full';
    else if (L && L.state === 'paused') msg = 'Paused';
    else if (L && L.state === 'lobby') msg = L.msg || '';
    else if (L && L.orientation && L.orientation !== 'any' && (window.innerWidth > window.innerHeight ? 'landscape' : 'portrait') !== L.orientation) msg = 'Turn your phone to ' + L.orientation;
    if (!this.veil) { this.veil = el('div', 'veil'); this.veil.hidden = true; r.append(this.veil); }
    this.veil.hidden = !msg; this.veil.textContent = msg;
    if (L && L.color) this.veil.style.borderColor = L.color;
  };

  P._wake = function () {
    var ask = function () { try { if (navigator.wakeLock && document.visibilityState === 'visible') navigator.wakeLock.request('screen').catch(function () {}); } catch (e) { /* unsupported */ } };
    document.addEventListener('visibilitychange', ask); ask();
  };
  P.leave = function () { clearInterval(this._tm); clearInterval(this._hl); clearInterval(this._hb); this.room.leave(); };

  window.Pad = Pad;
})();

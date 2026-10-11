// Sumo Push: 2 to 7 players on a round arena that slowly shrinks. The stick pushes your disc around, A is a dash (heavier for a moment, so it hits harder) with a cooldown; whoever is pushed
// off the edge is out, the last one on gets the round, first to 3 rounds wins. The screen owns everything. The rules are in step() and use no drawing or DOM, so scripts/dev/sumo-unit.mjs
// runs them without a browser. (7, not 8: a room has 8 places and the screen takes one.)
'use strict';
Games.register({
  id: 'sumopush', name: 'Sumo Push', players: { min: 2, max: 7 }, orientation: 'any',
  widgets: [{ type: 'stick' }, { type: 'buttons', names: ['A'] }],
  create: function (ctx) {
    var W = 800, H = 450, CX = W / 2, CY = H / 2;
    var R0 = 205, RMIN = 95, SHRINK_AT = 6, SHRINK = 5; // arena radius, its floor, when it starts closing (s into the round) and how fast (px/s)
    var BR = 22, ACC = 700, FRIC = 2.0, E = 0.9, VMAX = 900; // body radius, stick acceleration, drag, bounciness, speed cap
    var DASH_V = 520, DASH_T = 0.35, DASH_CD = 1.6, DASH_MASS = 2.2;
    var COUNT = 3, REST = 2.5, WINS = 3;
    var s = { phase: 'count', t: COUNT, round: 0, R: R0, clock: 0, bodies: [], wins: {}, winner: null, lastWinner: null };
    var byId = {};

    function beep(freq, ms) { // sound is on the screen only, and only once the audio context was started from a tap
      var a = ctx.audio;
      if (!a || a.state !== 'running') return;
      try { var o = a.createOscillator(), g = a.createGain(); o.frequency.value = freq; g.gain.value = 0.06; o.connect(g); g.connect(a.destination); o.start(); o.stop(a.currentTime + ms / 1000); } catch (e) { /* no audio */ }
    }
    function newRound() {
      var ps = ctx.players().slice().sort(function (a, b) { return a.slot - b.slot; }), n = ps.length;
      s.bodies = []; byId = {}; s.R = R0; s.clock = 0; s.phase = 'count'; s.t = COUNT; s.round++;
      ps.forEach(function (p, i) {
        var a = (i / n) * Math.PI * 2 - Math.PI / 2, b = { p: p, id: p.id, x: CX + Math.cos(a) * R0 * 0.6, y: CY + Math.sin(a) * R0 * 0.6, vx: 0, vy: 0, face: a + Math.PI, dash: 0, cd: 0, alive: true, fall: 0 };
        s.bodies.push(b); byId[p.id] = b; if (s.wins[p.id] === undefined) s.wins[p.id] = 0;
      });
    }
    function alive() { return s.bodies.filter(function (b) { return b.alive; }); }
    function out(b) {
      b.alive = false; b.fall = 0.01; b.vx *= 0.5; b.vy *= 0.5;
      ctx.rumble(b.p, 150); beep(150, 220);
    }
    function endRound() {
      var left = alive();
      s.lastWinner = left.length ? left[0] : null;
      if (s.lastWinner) {
        var id = s.lastWinner.id; s.wins[id]++;
        if (s.wins[id] >= WINS) { s.phase = 'over'; s.winner = s.lastWinner; beep(660, 400); return; }
      }
      s.phase = 'rest'; s.t = REST;
    }
    function collide(a, b) {
      var dx = b.x - a.x, dy = b.y - a.y, d = Math.hypot(dx, dy), min = BR * 2;
      if (d >= min) return;
      if (d < 1e-6) { dx = 1; dy = 0; d = 1; }
      var nx = dx / d, ny = dy / d, ma = a.dash > 0 ? DASH_MASS : 1, mb = b.dash > 0 ? DASH_MASS : 1, over = min - d;
      a.x -= nx * over * mb / (ma + mb); a.y -= ny * over * mb / (ma + mb); b.x += nx * over * ma / (ma + mb); b.y += ny * over * ma / (ma + mb);
      var vn = (b.vx - a.vx) * nx + (b.vy - a.vy) * ny;
      if (vn >= 0) return; // already moving apart
      var j = -(1 + E) * vn / (1 / ma + 1 / mb);
      a.vx -= j * nx / ma; a.vy -= j * ny / ma; b.vx += j * nx / mb; b.vy += j * ny / mb;
      if (-vn > 120) { var ms = Math.min(60, Math.round(-vn / 8)); ctx.rumble(a.p, ms); ctx.rumble(b.p, ms); beep(200 + Math.min(300, -vn / 2), 40); }
    }
    function step(dt) {
      if (s.phase === 'over') return;
      if (s.phase === 'count' || s.phase === 'rest') {
        s.t -= dt;
        if (s.t <= 0) { if (s.phase === 'count') { s.phase = 'play'; beep(520, 150); } else newRound(); }
        if (s.phase !== 'play') { fall(dt); return; }
      }
      s.clock += dt;
      if (s.clock > SHRINK_AT) s.R = Math.max(RMIN, s.R - SHRINK * dt);
      var vmax = 0;
      s.bodies.forEach(function (b) {
        if (!b.alive) return;
        var st = b.p.stick, m = Math.hypot(st.x, st.y);
        if (m > 0.2) b.face = Math.atan2(st.y, st.x);
        b.vx += st.x * ACC * dt; b.vy += st.y * ACC * dt;
        var f = Math.exp(-FRIC * dt); b.vx *= f; b.vy *= f;
        var sp = Math.hypot(b.vx, b.vy); if (sp > VMAX) { b.vx *= VMAX / sp; b.vy *= VMAX / sp; }
        if (sp > vmax) vmax = sp;
        b.dash = Math.max(0, b.dash - dt); b.cd = Math.max(0, b.cd - dt);
      });
      var n = Math.max(1, Math.ceil(vmax * dt / 10)), h = dt / n; // steps of at most 10 px: nothing passes through anything
      for (var k = 0; k < n; k++) {
        s.bodies.forEach(function (b) { if (b.alive) { b.x += b.vx * h; b.y += b.vy * h; } });
        for (var i = 0; i < s.bodies.length; i++) for (var j = i + 1; j < s.bodies.length; j++) if (s.bodies[i].alive && s.bodies[j].alive) collide(s.bodies[i], s.bodies[j]);
      }
      s.bodies.forEach(function (b) { if (b.alive && Math.hypot(b.x - CX, b.y - CY) > s.R) out(b); });
      fall(dt);
      if (s.phase === 'play' && alive().length <= 1) endRound();
    }
    function fall(dt) { s.bodies.forEach(function (b) { if (!b.alive && b.fall > 0 && b.fall < 1) { b.fall = Math.min(1, b.fall + dt * 2.5); b.x += b.vx * dt; b.y += b.vy * dt; } }); }
    function button(p, name, down) {
      if (name !== 'A' || !down) return;
      if (s.phase === 'over') { s.wins = {}; s.winner = null; s.round = 0; newRound(); return; }
      if (s.phase !== 'play') return;
      var b = byId[p.id];
      if (!b || !b.alive || b.cd > 0) return;
      var st = p.stick, m = Math.hypot(st.x, st.y), sp = Math.hypot(b.vx, b.vy);
      var ang = m > 0.2 ? Math.atan2(st.y, st.x) : sp > 30 ? Math.atan2(b.vy, b.vx) : b.face;
      b.face = ang; b.vx += Math.cos(ang) * DASH_V; b.vy += Math.sin(ang) * DASH_V; b.dash = DASH_T; b.cd = DASH_CD;
      ctx.rumble(p, 30); beep(380, 60);
    }
    function render(g, w, h) {
      var k = Math.min(w / W, h / H), ox = (w - W * k) / 2, oy = (h - H * k) / 2;
      g.save(); g.translate(ox, oy); g.scale(k, k);
      g.fillStyle = '#1d1a14'; g.fillRect(0, 0, W, H);
      g.beginPath(); g.arc(CX, CY, s.R, 0, 7); g.fillStyle = '#2c261b'; g.fill(); g.lineWidth = 6; g.strokeStyle = '#6b5a3a'; g.stroke();
      g.textAlign = 'center';
      s.bodies.forEach(function (b) {
        var sc = b.alive ? 1 : Math.max(0, 1 - b.fall);
        if (sc <= 0) return;
        g.globalAlpha = b.alive ? 1 : 0.6;
        g.fillStyle = b.p.color; g.beginPath(); g.arc(b.x, b.y, BR * sc * (b.dash > 0 ? 1.15 : 1), 0, 7); g.fill();
        g.fillStyle = 'rgba(0,0,0,.35)'; g.beginPath(); g.arc(b.x + Math.cos(b.face) * BR * 0.55 * sc, b.y + Math.sin(b.face) * BR * 0.55 * sc, 5 * sc, 0, 7); g.fill();
        if (b.alive && b.cd > 0) { g.strokeStyle = '#f1ebde'; g.lineWidth = 3; g.beginPath(); g.arc(b.x, b.y, BR + 5, -Math.PI / 2, -Math.PI / 2 + (1 - b.cd / DASH_CD) * Math.PI * 2); g.stroke(); }
        g.globalAlpha = 1;
        g.font = '600 13px system-ui, sans-serif'; g.fillStyle = '#f1ebde'; g.fillText(b.p.name, b.x, b.y - BR - 9);
      });
      var x = 16; g.textAlign = 'left'; g.font = '700 15px system-ui, sans-serif'; // the score along the top: a pip for each round won
      s.bodies.forEach(function (b) {
        g.fillStyle = b.p.color; g.fillRect(x, 14, 10, 10); g.fillStyle = '#f1ebde'; g.fillText(b.p.name, x + 16, 24);
        var wd = g.measureText(b.p.name).width; for (var i = 0; i < (s.wins[b.id] || 0); i++) { g.fillStyle = '#d9b27a'; g.beginPath(); g.arc(x + 24 + wd + i * 14, 19, 5, 0, 7); g.fill(); }
        x += 40 + wd + WINS * 14;
      });
      g.textAlign = 'center'; g.font = '800 72px system-ui, sans-serif'; g.fillStyle = '#d9b27a';
      if (s.phase === 'count') g.fillText(String(Math.ceil(s.t)), CX, CY + 24);
      g.font = '700 28px system-ui, sans-serif';
      if (s.phase === 'rest') g.fillText(s.lastWinner ? s.lastWinner.p.name + ' takes the round' : 'Nobody takes it', CX, H - 28);
      if (s.phase === 'over') { g.fillStyle = 'rgba(22,20,15,.8)'; g.fillRect(0, CY - 60, W, 120); g.fillStyle = '#d9b27a'; g.fillText(s.winner.p.name + ' wins. A for a rematch', CX, CY + 10); }
      g.restore();
    }
    newRound();
    return {
      s: s, step: step,
      onJoin: function () {}, // someone who arrives mid-round watches and is in from the next one
      onLeave: function (p) { // a disc whose player has gone is out; with fewer than two players left there is no game
        var b = byId[p.id]; if (b && b.alive) { b.alive = false; b.fall = 0.01; }
        if (ctx.players().length < 2) ctx.end();
      },
      onButton: button, tick: step, render: render
    };
  }
});

// Fort Pong: two players, one stick each (up and down moves the paddle) and one button (A serves). First to 7. The screen owns everything; the phones only send their stick and button.
// The rules are in step(), which the unit test (scripts/dev/pong-unit.mjs) runs without a browser: it needs only Games.register, so keep step() free of drawing and of the DOM.
'use strict';
Games.register({
  id: 'fortpong', name: 'Fort Pong', players: { min: 2, max: 2 }, orientation: 'any',
  widgets: [{ type: 'stick' }, { type: 'buttons', names: ['A'] }],
  create: function (ctx) {
    var W = 800, H = 450, PW = 14, PH = 90, PX = 36, R = 8, WIN = 7;
    var PSPEED = 460, V0 = 330, VMAX = 760, GAIN = 1.07, MAXANG = 55 * Math.PI / 180;
    var s = { phase: 'serve', server: 0, score: [0, 0], py: [H / 2, H / 2], ball: { x: 0, y: H / 2, vx: 0, vy: 0 }, winner: -1, hits: 0, t: 0 };
    var who = {}; // player id -> side (0 left, 1 right), the player's slot
    var names = ['', ''], colors = ['#e6492d', '#2f7de1'], ps = [null, null];

    function beep(freq, ms) { // sound is on the screen only; there is none until the audio context was started from a tap
      var a = ctx.audio;
      if (!a || a.state !== 'running') return;
      try { var o = a.createOscillator(), g = a.createGain(); o.frequency.value = freq; g.gain.value = 0.08; o.connect(g); g.connect(a.destination); o.start(); o.stop(a.currentTime + ms / 1000); } catch (e) { /* no audio */ }
    }
    function sit() { // who plays which side: by slot, so a player who returns keeps theirs
      ctx.players().forEach(function (p) { if (p.slot < 2) { ps[p.slot] = p; names[p.slot] = p.name; colors[p.slot] = p.color; } });
    }
    function rest() { // the ball waits in front of the server's paddle
      s.ball.x = s.server === 0 ? PX + PW / 2 + R + 2 : W - PX - PW / 2 - R - 2; s.ball.y = s.py[s.server]; s.ball.vx = s.ball.vy = 0;
    }
    function launch() {
      var dir = s.server === 0 ? 1 : -1, ang = (Math.random() - 0.5) * 0.7;
      s.ball.vx = dir * V0 * Math.cos(ang); s.ball.vy = V0 * Math.sin(ang); s.phase = 'play'; s.hits = 0;
    }
    function point(side) { // side scored
      s.score[side]++;
      var lost = 1 - side;
      if (ps[lost]) ctx.rumble(ps[lost], 120);
      beep(180, 200);
      if (s.score[side] >= WIN) { s.phase = 'over'; s.winner = side; return; }
      s.server = lost; s.phase = 'serve'; rest();
    }
    function bounce(side) { // the ball met paddle `side`
      var sp = Math.min(VMAX, Math.hypot(s.ball.vx, s.ball.vy) * GAIN);
      var off = Math.max(-1, Math.min(1, (s.ball.y - s.py[side]) / (PH / 2 + R))), ang = off * MAXANG;
      s.ball.vx = (side === 0 ? 1 : -1) * sp * Math.cos(ang); s.ball.vy = sp * Math.sin(ang);
      s.ball.x = side === 0 ? PX + PW / 2 + R : W - PX - PW / 2 - R;
      s.hits++;
      if (ps[side]) ctx.rumble(ps[side], 30);
      beep(side === 0 ? 440 : 520, 50);
    }
    function step(dt) {
      s.t += dt;
      for (var i = 0; i < 2; i++) {
        var sy = ps[i] ? ps[i].stick.y : 0;
        s.py[i] = Math.max(PH / 2, Math.min(H - PH / 2, s.py[i] + sy * PSPEED * dt));
      }
      if (s.phase === 'serve') { rest(); return; }
      if (s.phase !== 'play') return;
      var b = s.ball, dist = Math.hypot(b.vx, b.vy) * dt, n = Math.max(1, Math.ceil(dist / 6)), h = dt / n; // small steps: a fast ball must not skip a paddle
      for (var k = 0; k < n && s.phase === 'play'; k++) {
        b.x += b.vx * h; b.y += b.vy * h;
        if (b.y < R) { b.y = R; b.vy = Math.abs(b.vy); }
        else if (b.y > H - R) { b.y = H - R; b.vy = -Math.abs(b.vy); }
        if (b.vx < 0 && b.x - R <= PX + PW / 2 && b.x + R >= PX - PW / 2 && Math.abs(b.y - s.py[0]) <= PH / 2 + R) bounce(0);
        else if (b.vx > 0 && b.x + R >= W - PX - PW / 2 && b.x - R <= W - PX + PW / 2 && Math.abs(b.y - s.py[1]) <= PH / 2 + R) bounce(1);
        else if (b.x < -R) point(1);
        else if (b.x > W + R) point(0);
      }
    }
    function button(p, name, down) {
      if (name !== 'A' || !down) return;
      if (s.phase === 'serve' && p.slot === s.server) launch();
      else if (s.phase === 'over') { s.score = [0, 0]; s.winner = -1; s.server = 1 - s.server; s.phase = 'serve'; rest(); }
    }
    function render(g, w, h) {
      var k = Math.min(w / W, h / H), ox = (w - W * k) / 2, oy = (h - H * k) / 2;
      g.save(); g.translate(ox, oy); g.scale(k, k);
      g.fillStyle = '#1d1a14'; g.fillRect(0, 0, W, H);
      g.fillStyle = '#3a3226'; for (var x = 0; x < W; x += 40) { g.fillRect(x + 6, 0, 28, 10); g.fillRect(x + 6, H - 10, 28, 10); } // battlements
      g.fillStyle = '#2a2519'; for (var y = 18; y < H - 18; y += 26) g.fillRect(W / 2 - 2, y, 4, 14);
      g.font = '800 64px system-ui, sans-serif'; g.textAlign = 'center'; g.fillStyle = '#f1ebde';
      g.fillText(s.score[0], W / 2 - 80, 80); g.fillText(s.score[1], W / 2 + 80, 80);
      g.font = '600 16px system-ui, sans-serif'; g.fillStyle = colors[0]; g.fillText(names[0], W / 4, 110); g.fillStyle = colors[1]; g.fillText(names[1], 3 * W / 4, 110);
      g.fillStyle = colors[0]; g.fillRect(PX - PW / 2, s.py[0] - PH / 2, PW, PH);
      g.fillStyle = colors[1]; g.fillRect(W - PX - PW / 2, s.py[1] - PH / 2, PW, PH);
      g.fillStyle = '#f1ebde'; g.beginPath(); g.arc(s.ball.x, s.ball.y, R, 0, 7); g.fill();
      g.font = '700 26px system-ui, sans-serif'; g.fillStyle = '#d9b27a';
      if (s.phase === 'serve') g.fillText(names[s.server] + ': press A to serve', W / 2, H - 40);
      if (s.phase === 'over') g.fillText(names[s.winner] + ' wins. A for a rematch', W / 2, H / 2 + 8);
      g.restore();
    }
    sit(); rest();
    return {
      s: s, step: step,
      onJoin: function (p) { sit(); },
      onLeave: function (p) { if (p.slot < 2) ps[p.slot] = null; ctx.end(); }, // a game of two cannot go on with one
      onButton: button, tick: step, render: render
    };
  }
});

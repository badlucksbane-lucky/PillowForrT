// Pad test: not a real game. Every player is a dot that follows their stick; A makes it flash and buzz the phone, B sends that phone a private panel and the answer is written beside the dot.
// It exercises every widget (stick, buttons, pointer, tilt, panel) end to end, so a new phone or browser can be checked before a real game is trusted.
'use strict';
Games.register({
  id: 'padtest', name: 'Pad test', players: { min: 1, max: 8 }, orientation: 'any',
  widgets: [{ type: 'stick' }, { type: 'buttons', names: ['A', 'B'] }],
  create: function (ctx) {
    var d = new Map(); // player id -> {x, y, flash, says}
    var get = function (p, w, h) { var s = d.get(p.id); if (!s) { s = { x: w ? w / 2 : 300, y: h ? h / 2 : 200, flash: 0, says: '' }; d.set(p.id, s); } return s; };
    var size = { w: 800, h: 450 };
    return {
      onJoin: function (p) { get(p, size.w, size.h); },
      onLeave: function (p) { d.delete(p.id); },
      onButton: function (p, name, down) {
        var s = get(p, size.w, size.h);
        if (!down) return;
        if (name === 'A') { s.flash = 1; ctx.rumble(p, 80); }
        if (name === 'B') ctx.panel(p, { id: 'color', title: 'Pick one', items: ['Red', 'Green', 'Blue'] });
      },
      onPick: function (p, id, i) { get(p, size.w, size.h).says = ['Red', 'Green', 'Blue'][i] || '?'; ctx.panel(p, null); },
      tick: function (dt) {
        ctx.players().forEach(function (p) {
          var s = get(p, size.w, size.h);
          s.x = Math.min(size.w - 20, Math.max(20, s.x + p.stick.x * 300 * dt)); s.y = Math.min(size.h - 20, Math.max(20, s.y + p.stick.y * 300 * dt));
          s.flash = Math.max(0, s.flash - dt * 2);
        });
      },
      render: function (g, w, h) {
        size.w = w; size.h = h;
        g.font = '600 18px system-ui, sans-serif'; g.textAlign = 'center';
        ctx.players().forEach(function (p) {
          var s = get(p, w, h);
          g.fillStyle = p.color; g.beginPath(); g.arc(s.x, s.y, 20 + s.flash * 14, 0, 7); g.fill();
          g.fillStyle = '#f1ebde'; g.fillText(p.name + (s.says ? ': ' + s.says : ''), s.x, s.y - 30 - s.flash * 14);
        });
      }
    };
  }
});

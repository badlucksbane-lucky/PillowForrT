// Tests the rules of Sumo Push (gameclient/sumopush.js) without a browser: step() is driven with made-up players and a fixed clock. Checks the countdown, stick speed and drag, the shrinking arena,
// ring-outs, rounds and the match, collisions (momentum kept, no overlap, no tunnelling), the dash and its cooldown, a draw, a player leaving, one arriving mid-round, and seven discs fitting on the start ring.
// Usage: node sumo-unit.mjs   Exit code 1 on failure.
import fs from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
const src = fs.readFileSync(path.join(path.dirname(fileURLToPath(import.meta.url)), '../../gameclient/sumopush.js'), 'utf8');
let game; new Function('Games', src)({ register: g => { game = g; } });
const fails = [];
const check = (name, ok, got) => { console.log((ok ? 'ok   ' : 'FAIL ') + name + (ok ? '' : '  got: ' + JSON.stringify(got))); if (!ok) fails.push(name); };

const mk = n => {
  const P = Array.from({ length: n }, (_, i) => ({ id: 'p' + i, slot: i, name: 'P' + i, color: '#fff', stick: { x: 0, y: 0 }, btn: {} }));
  const log = { rumble: [], ended: 0 };
  const inst = game.create({ players: () => P, rumble: (p, ms) => log.rumble.push([p.id, ms]), panel() {}, audio: null, end: () => log.ended++ });
  const g = { P, inst, s: inst.s, log, run: (sec, dt = 1 / 60) => { for (let t = 0; t < sec - 1e-9; t += dt) inst.step(dt); }, body: i => inst.s.bodies[i] };
  g.go = () => { g.run(3.05); }; // through the countdown
  return g;
};
const dist = (a, b) => Math.hypot(a.x - b.x, a.y - b.y);

check('2 to 7 players, a stick and button A', game.players.min === 2 && game.players.max === 7 && game.widgets[0].type === 'stick' && game.widgets[1].names[0] === 'A', game);
{ // countdown
  const g = mk(3); g.P[0].stick.x = 1; const x0 = g.body(0).x; g.run(2);
  check('nobody moves during the countdown', g.s.phase === 'count' && g.body(0).x === x0, [g.s.phase, g.body(0).x, x0]);
  g.inst.onButton(g.P[0], 'A', true);
  check('a dash does nothing during it', g.body(0).dash === 0 && g.body(0).vx === 0, g.body(0));
  g.run(1.1);
  check('then the round starts', g.s.phase === 'play' && g.s.round === 1, g.s.phase);
}
{ // speed and drag
  const g = mk(2); g.go(); g.s.R = 1e6; g.body(0).x = 400; g.body(0).y = 225; g.body(1).x = 5000; g.body(1).y = 5000;
  g.P[0].stick.x = 1; g.run(4);
  const sp = Math.hypot(g.body(0).vx, g.body(0).vy);
  check('a full stick settles at about 350 px/s (acceleration over drag)', sp > 330 && sp < 360, sp);
  g.P[0].stick.x = 0; g.run(2);
  check('and with the stick released the disc slows to a near stop', Math.hypot(g.body(0).vx, g.body(0).vy) < 8, g.body(0));
  g.P[0].stick.y = -1; g.run(0.1);
  check('the stick up is up (y falls) and the nose turns that way', g.body(0).vy < 0 && Math.abs(g.body(0).face + Math.PI / 2) < 0.01, g.body(0));
}
{ // shrinking
  const g = mk(2); g.go(); g.run(5);
  check('the arena holds its size for the first 6 seconds', g.s.R === 205, g.s.R);
  g.s.bodies.forEach(b => { b.x = 400; b.y = 225; b.vx = b.vy = 0; }); g.s.bodies[1].x = 460;
  g.run(10);
  check('then closes at 5 px/s', Math.abs(g.s.R - (205 - 5 * 9)) < 3, g.s.R);
  g.s.R = 96; g.run(5);
  check('and stops at 95', g.s.R === 95, g.s.R);
}
{ // ring-out, rounds, match
  const g = mk(3); g.go();
  g.body(1).x = 400 + g.s.R + 5; g.body(1).y = 225; g.run(0.05);
  check('a disc past the edge is out and its phone buzzes', !g.body(1).alive && g.log.rumble.some(r => r[0] === 'p1' && r[1] === 150), g.log.rumble);
  check('the round goes on with two left', g.s.phase === 'play', g.s.phase);
  g.body(2).x = 400 - g.s.R - 5; g.body(2).y = 225; g.run(0.05);
  check('the last one on takes the round', g.s.phase === 'rest' && g.s.lastWinner.id === 'p0' && g.s.wins.p0 === 1, [g.s.phase, g.s.wins]);
  g.run(2.6);
  check('after a rest a new round starts with everyone back and the arena reset', g.s.phase === 'count' && g.s.round === 2 && g.s.bodies.every(b => b.alive) && g.s.R === 205, [g.s.phase, g.s.round, g.s.R]);
  g.s.wins.p0 = 2; g.go(); g.body(1).x = 1000; g.body(2).x = 1000; g.run(0.1);
  check('the third round won wins the match', g.s.phase === 'over' && g.s.winner.id === 'p0' && g.s.wins.p0 === 3, [g.s.phase, g.s.wins]);
  const before = JSON.stringify(g.s.bodies.map(b => [b.x, b.y])); g.P[0].stick.x = 1; g.run(1);
  check('nothing moves once it is over', JSON.stringify(g.s.bodies.map(b => [b.x, b.y])) === before, null);
  g.inst.onButton(g.P[1], 'A', true);
  check('A starts a rematch: wins cleared, round 1 again, counting down', g.s.phase === 'count' && g.s.round === 1 && g.s.wins.p0 === 0 && g.s.winner === null, [g.s.phase, g.s.round, g.s.wins]);
}
{ // draw
  const g = mk(2); g.go(); g.s.bodies.forEach(b => { b.x = 2000; }); g.run(0.05);
  check('two discs out in the same moment is a draw: nobody scores, a new round follows', g.s.phase === 'rest' && g.s.lastWinner === null && !g.s.wins.p0 && !g.s.wins.p1, [g.s.phase, g.s.wins]);
}
{ // collisions
  const g = mk(2); g.go(); g.s.R = 5000;
  const a = g.body(0), b = g.body(1); a.x = 300; a.y = 225; a.vx = 200; a.vy = 0; b.x = 360; b.y = 225; b.vx = -200; b.vy = 0;
  const m0 = a.vx + b.vx; g.run(0.5);
  check('a head-on hit sends them back, momentum kept, no overlap', a.vx < 0 && b.vx > 0 && Math.abs(a.vx + b.vx - m0) < 1 && dist(a, b) >= 43.9, [a.vx, b.vx, dist(a, b)]);
  check('both phones buzz for a hard hit', g.log.rumble.filter(r => r[0] === 'p0' || r[0] === 'p1').length >= 2, g.log.rumble);
  const c = mk(2); c.go(); c.s.R = 5000; const p = c.body(0), q = c.body(1); p.x = 100; p.y = 225; q.x = 300; q.y = 225; q.vx = q.vy = 0;
  p.vx = 900; c.run(0.5);
  check('a disc at top speed does not pass through another', p.x < q.x, [p.x, q.x]);
  const d = mk(2); d.go(); d.s.R = 5000; const u = d.body(0), v = d.body(1); u.x = 400; u.y = 225; v.x = 400.0000001; v.y = 225; u.vx = u.vy = v.vx = v.vy = 0; d.run(0.1);
  check('two discs on the same spot are pushed apart (no division by zero)', Number.isFinite(u.x) && Number.isFinite(v.x) && dist(u, v) >= 43.9, [u.x, v.x]);
}
{ // dash
  const g = mk(2); g.go(); g.s.R = 1e6; const a = g.body(0); a.x = 400; a.y = 225; g.body(1).x = 4000; g.body(1).y = 4000;
  g.P[0].stick.x = 0; g.P[0].stick.y = 1; g.inst.onButton(g.P[0], 'A', true);
  check('A dashes the way the stick points, with a cooldown and a buzz', a.vy > 500 && Math.abs(a.vx) < 1 && a.cd > 1.5 && a.dash > 0.3 && g.log.rumble.some(r => r[0] === 'p0' && r[1] === 30), a);
  const vy = a.vy; g.inst.onButton(g.P[0], 'A', true);
  check('a second A inside the cooldown does nothing', a.vy === vy, a.vy);
  g.inst.onButton(g.P[0], 'A', false);
  g.P[0].stick.y = 0; g.run(1.7); g.P[0].stick.x = 0; a.vx = a.vy = 0; g.inst.onButton(g.P[0], 'A', true);
  check('after the cooldown it works again; with no stick and no movement it goes the way the nose points', Math.hypot(a.vx, a.vy) > 500 && a.cd > 1.5, a);
  // a dashing disc hits harder
  const mkHit = dashing => { const h = mk(2); h.go(); h.s.R = 5000; const x = h.body(0), y = h.body(1); x.x = 300; x.y = 225; y.x = 400; y.y = 225; x.vx = 400; x.vy = 0; y.vx = y.vy = 0; if (dashing) x.dash = 0.3; h.run(0.3); return y.vx; };
  check('the same hit sends the target faster when the attacker is mid-dash', mkHit(true) > mkHit(false) * 1.15, [mkHit(true), mkHit(false)]);
}
{ // leaving, arriving, seven
  const g = mk(3); g.go(); const gone = g.P.splice(1, 1)[0]; g.inst.onLeave(gone);
  check('a player who leaves is out and the game goes on with two', !g.body(1).alive && g.log.ended === 0, g.log);
  g.P.splice(1, 1); g.inst.onLeave({ id: 'p2' });
  check('with fewer than two players the game ends', g.log.ended === 1, g.log);
  const h = mk(3); h.go(); h.P.push({ id: 'p9', slot: 3, name: 'Late', color: '#fff', stick: { x: 0, y: 0 }, btn: {} }); h.inst.onJoin(h.P[3]); h.run(0.1);
  check('someone who arrives mid-round is not a disc until the next one', h.s.bodies.length === 3, h.s.bodies.length);
  h.s.bodies[1].x = 5000; h.s.bodies[2].x = 5000; h.run(3); h.inst; h.run(0.1);
  check('and is in from the next round', h.s.bodies.length === 4 && h.s.bodies.some(b => b.id === 'p9'), h.s.bodies.length);
  const s7 = mk(7);
  let min = 1e9; for (let i = 0; i < 7; i++) for (let j = i + 1; j < 7; j++) min = Math.min(min, dist(s7.body(i), s7.body(j)));
  check('seven discs start apart from each other, inside the arena', min > 60 && s7.s.bodies.every(b => dist(b, { x: 400, y: 225 }) < 205 - 22), min);
}
console.log(fails.length ? `\n${fails.length} FAILED` : '\nall ok');
process.exit(fails.length ? 1 : 0);

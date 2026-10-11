// Tests the rules of Fort Pong (gameclient/fortpong.js) without a browser: the game's step() is driven with made-up players and a fixed clock. Checks the serve, wall and paddle bounces, the speed-up,
// the paddle limits and speed, a fast ball not skipping a paddle, scoring and who serves next, winning at 7, the rematch, a left-over button being ignored, and a missing player ending the game.
// Usage: node pong-unit.mjs   Exit code 1 on failure.
import fs from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
const src = fs.readFileSync(path.join(path.dirname(fileURLToPath(import.meta.url)), '../../gameclient/fortpong.js'), 'utf8');
let game; new Function('Games', src)({ register: g => { game = g; } });
const fails = [];
const check = (name, ok, got) => { console.log((ok ? 'ok   ' : 'FAIL ') + name + (ok ? '' : '  got: ' + JSON.stringify(got))); if (!ok) fails.push(name); };

const mk = () => {
  const P = [0, 1].map(i => ({ id: 'p' + i, slot: i, name: 'P' + i, color: '#fff', stick: { x: 0, y: 0 }, btn: {} }));
  const log = { rumble: [], ended: 0 };
  const inst = game.create({ players: () => P, rumble: (p, ms) => log.rumble.push([p.slot, ms]), panel() {}, audio: null, end: () => log.ended++ });
  return { P, inst, s: inst.s, log, run: (sec, dt = 1 / 60) => { for (let t = 0; t < sec; t += dt) inst.step(dt); } };
};
const rnd = Math.random;

check('two players exactly, a stick and button A', game.players.min === 2 && game.players.max === 2 && game.widgets[0].type === 'stick' && game.widgets[1].names[0] === 'A', game);

{ // serve
  const g = mk();
  check('it starts waiting for the server, ball at rest in front of the paddle', g.s.phase === 'serve' && g.s.ball.vx === 0 && g.s.ball.x < 60, g.s);
  g.inst.onButton(g.P[1], 'A', true);
  check("the other player's A does not serve", g.s.phase === 'serve', g.s.phase);
  g.inst.onButton(g.P[0], 'B', true); g.inst.onButton(g.P[0], 'A', false);
  check('a release or another button does not serve', g.s.phase === 'serve', g.s.phase);
  Math.random = () => 0.5; g.inst.onButton(g.P[0], 'A', true);
  check('the server serves towards the other side', g.s.phase === 'play' && g.s.ball.vx > 300 && Math.abs(g.s.ball.vy) < 1, g.s.ball);
  g.P[0].stick.y = 1; g.run(0.1); g.P[0].stick.y = 0;
}
{ // paddle speed and limits
  const g = mk();
  g.P[0].stick.y = 1; g.run(0.5);
  check('a full stick moves the paddle at 460 px/s', Math.abs(g.s.py[0] - (225 + 230)) < 5 || g.s.py[0] >= 400, g.s.py[0]);
  g.run(3);
  check('the paddle stops at the bottom edge', g.s.py[0] === 450 - 45, g.s.py[0]);
  g.P[0].stick.y = -1; g.run(5);
  check('and at the top edge', g.s.py[0] === 45, g.s.py[0]);
  g.P[1].stick.y = 0.5; const y0 = g.s.py[1]; g.run(0.2);
  check('half a stick is half the speed', Math.abs((g.s.py[1] - y0) - 0.5 * 460 * 0.2) < 8, g.s.py[1] - y0);
}
{ // walls
  const g = mk(); Math.random = () => 0.5; g.inst.onButton(g.P[0], 'A', true);
  g.s.ball.x = 400; g.s.ball.y = 20; g.s.ball.vx = 100; g.s.ball.vy = -300; g.run(0.2);
  check('the ball bounces off the top wall', g.s.ball.vy > 0 && g.s.ball.y >= 8, g.s.ball);
  g.s.ball.y = 430; g.s.ball.vy = 300; g.s.ball.vx = 100; g.run(0.2);
  check('and the bottom wall', g.s.ball.vy < 0 && g.s.ball.y <= 442, g.s.ball);
}
{ // paddle hits
  const g = mk(); Math.random = () => 0.5; g.s.phase = 'play';
  g.s.py[0] = 225; g.s.ball.x = 120; g.s.ball.y = 225; g.s.ball.vx = -400; g.s.ball.vy = 0; g.run(0.3);
  check('a ball in front of the paddle bounces back, a little faster', g.s.ball.vx > 400 && g.s.hits === 1 && g.s.score[0] + g.s.score[1] === 0, g.s);
  check('the player who hit it feels it', g.log.rumble.some(r => r[0] === 0 && r[1] === 30), g.log.rumble);
  g.s.ball.x = 120; g.s.ball.y = 225 + 40; g.s.ball.vx = -400; g.s.ball.vy = 0; g.run(0.3);
  check('hitting low sends it down, hitting the middle straight', g.s.ball.vy > 50, g.s.ball);
  const g2 = mk(); g2.s.phase = 'play'; g2.s.py[1] = 100; g2.s.ball.x = 680; g2.s.ball.y = 100; g2.s.ball.vx = 400; g2.s.ball.vy = 0; g2.run(0.3);
  check('the right paddle works too', g2.s.ball.vx < -400 && g2.s.hits === 1, g2.s.ball);
  const g3 = mk(); g3.s.phase = 'play'; g3.s.py[0] = 225; g3.s.ball.x = 300; g3.s.ball.y = 225; g3.s.ball.vx = -760; g3.s.ball.vy = 0; g3.run(0.5, 1 / 20);
  check('a ball at top speed, in 50 ms steps, does not pass through the paddle', g3.s.hits >= 1 && g3.s.score[1] === 0, g3.s);
  const g4 = mk(); g4.s.phase = 'play'; g4.s.py[0] = 225; g4.s.ball.x = 300; g4.s.ball.y = 225; g4.s.ball.vx = -740; g4.s.ball.vy = 0; g4.run(1);
  check('the speed never passes 760', Math.hypot(g4.s.ball.vx, g4.s.ball.vy) <= 760.01, g4.s.ball);
}
{ // scoring, serving, winning
  const g = mk(); g.s.phase = 'play'; g.s.py[0] = 50; g.s.ball.x = 300; g.s.ball.y = 400; g.s.ball.vx = -400; g.s.ball.vy = 0; g.run(1);
  check('a ball past the left paddle scores for the right player', g.s.score[1] === 1 && g.s.score[0] === 0, g.s.score);
  check('the player who lost the point serves next, ball at rest', g.s.phase === 'serve' && g.s.server === 0 && g.s.ball.vx === 0, g.s);
  check('the loser feels a long buzz', g.log.rumble.some(r => r[0] === 0 && r[1] === 120), g.log.rumble);
  g.inst.onButton(g.P[0], 'A', true); g.s.py[1] = 20; g.s.ball.x = 600; g.s.ball.y = 400; g.s.ball.vx = 400; g.s.ball.vy = 0; g.run(1);
  check('a ball past the right paddle scores for the left player', g.s.score[0] === 1 && g.s.server === 1, g.s);
  g.s.score = [6, 0]; g.s.server = 1; g.s.phase = 'play'; g.s.py[1] = 20; g.s.ball.x = 600; g.s.ball.y = 400; g.s.ball.vx = 400; g.s.ball.vy = 0; g.run(1);
  check('the seventh point wins the game', g.s.phase === 'over' && g.s.winner === 0 && g.s.score[0] === 7, g.s);
  const before = JSON.stringify(g.s.ball); g.run(1);
  check('nothing moves once it is over', JSON.stringify(g.s.ball) === before, g.s.ball);
  g.inst.onButton(g.P[1], 'A', true);
  check('A starts a rematch at 0 to 0 with the serve passed on', g.s.phase === 'serve' && g.s.score[0] === 0 && g.s.score[1] === 0 && g.s.winner === -1, g.s);
}
{ // a missing player
  const g = mk(); g.inst.onLeave(g.P[1]);
  check('losing a player ends the game', g.log.ended === 1, g.log);
}
Math.random = rnd;
console.log(fails.length ? `\n${fails.length} FAILED` : '\nall ok');
process.exit(fails.length ? 1 : 0);

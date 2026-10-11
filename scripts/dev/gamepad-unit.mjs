// Tests LocalPads (gameclient/gamepad.js) without a browser: a fake navigator.getGamepads() stands in for real hardware.
// Checks standard-mapping filtering, button mapping, d-pad overriding the stick, the dead zone, add/remove detection across polls, and the onButton edges
// (press, release, no refire while held, and a release synthesized for anything still held when the pad disconnects) that both console.js and pad.js rely on.
// Usage: node gamepad-unit.mjs   Exit code 1 on failure.
import fs from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
const src = fs.readFileSync(path.join(path.dirname(fileURLToPath(import.meta.url)), '../../gameclient/gamepad.js'), 'utf8');
const win = {};
new Function('window', 'navigator', src)(win, { getGamepads: () => pads });
const LocalPads = win.LocalPads;
const fails = [];
const check = (name, ok, got) => { console.log((ok ? 'ok   ' : 'FAIL ') + name + (ok ? '' : '  got: ' + JSON.stringify(got))); if (!ok) fails.push(name); };

const btn = (pressed) => ({ pressed });
const pad = (o = {}) => ({ connected: true, mapping: 'standard', id: 'Fake Pad', axes: [0, 0], buttons: Array.from({ length: 16 }, () => btn(false)), index: 0, ...o });

let pads = [];
const log = [];
const btnLog = [];
const poll = (lp) => lp.poll(p => log.push(['add', p.id]), p => log.push(['remove', p.id]), (p, name, down) => btnLog.push([p.id, name, down]));

{ // a non-standard or disconnected pad is ignored outright
  const lp = new LocalPads();
  pads = [pad({ mapping: 'xinput' }), null, pad({ connected: false })];
  poll(lp);
  check('no player added for a non-standard or disconnected pad', lp.list.size === 0, lp.list.size);
}

{ // connecting fires onAdd once, with the player shape a game expects
  const lp = new LocalPads();
  pads = [pad()];
  poll(lp);
  check('onAdd fired once with gp:0', log.length === 1 && log[0][0] === 'add' && log[0][1] === 'gp:0', log);
  const p = lp.list.get(0);
  check('player shape has stick, btn, ptr, tilt, local:true', p.local === true && 'x' in p.stick && 'A' in p.btn, p);
  log.length = 0;
  poll(lp);
  check('a second poll of the same pad does not re-fire onAdd', log.length === 0, log);
}

{ // button mapping: standard index 0 -> A, 9 -> Start, others follow the same table
  const lp = new LocalPads();
  const bs = Array.from({ length: 16 }, () => btn(false)); bs[0] = btn(true); bs[9] = btn(true);
  pads = [pad({ buttons: bs })];
  poll(lp);
  const p = lp.list.get(0);
  check('button 0 -> A', p.btn.A === true, p.btn);
  check('button 9 -> Start, others false', p.btn.Start === true && p.btn.B === false && p.btn.L === false, p.btn);
}

{ // the stick axes map x right, y down, with a dead zone
  const lp = new LocalPads();
  pads = [pad({ axes: [0.05, -0.05] })];
  poll(lp);
  check('inside the dead zone reads as centered', lp.list.get(0).stick.x === 0 && lp.list.get(0).stick.y === 0, lp.list.get(0).stick);
  pads = [pad({ axes: [0.9, -0.9] })];
  poll(lp);
  check('past the dead zone passes through', lp.list.get(0).stick.x === 0.9 && lp.list.get(0).stick.y === -0.9, lp.list.get(0).stick);
}

{ // the d-pad (buttons 12-15) overrides the stick axes while held, matching retro.js's up=-y convention
  const lp = new LocalPads();
  const bs = Array.from({ length: 16 }, () => btn(false)); bs[12] = btn(true); // d-pad up
  pads = [pad({ axes: [0.9, 0.9], buttons: bs })];
  poll(lp);
  check('d-pad up forces y to -1 regardless of the stick', lp.list.get(0).stick.y === -1, lp.list.get(0).stick);
}

{ // unplugging fires onRemove and drops it from the list; replugging is a fresh onAdd
  const lp = new LocalPads();
  pads = [pad()];
  poll(lp);
  pads = [];
  poll(lp);
  check('onRemove fired and the list is empty', log.pop()[0] === 'remove' && lp.list.size === 0, lp.list.size);
  pads = [pad()];
  log.length = 0;
  poll(lp);
  check('replugging fires onAdd again', log.length === 1 && log[0][0] === 'add', log);
}

{ // onButton: a press fires once, holding does not refire, releasing fires once, and a disconnect while held synthesizes a release
  const lp = new LocalPads();
  const bs = Array.from({ length: 16 }, () => btn(false));
  pads = [pad({ buttons: bs })];
  btnLog.length = 0; poll(lp);
  check('no button held yet, nothing fires', btnLog.length === 0, btnLog);
  bs[0] = btn(true);
  btnLog.length = 0; poll(lp);
  check('pressing A fires one onButton(gp:0, A, true)', btnLog.length === 1 && btnLog[0][0] === 'gp:0' && btnLog[0][1] === 'A' && btnLog[0][2] === true, btnLog);
  btnLog.length = 0; poll(lp);
  check('holding it does not refire', btnLog.length === 0, btnLog);
  bs[0] = btn(false);
  btnLog.length = 0; poll(lp);
  check('releasing fires onButton(gp:0, A, false)', btnLog.length === 1 && btnLog[0][2] === false, btnLog);
  bs[0] = btn(true); bs[1] = btn(true);
  btnLog.length = 0; poll(lp);
  pads = [];
  btnLog.length = 0; poll(lp);
  check('unplugging while A and B are held releases both', btnLog.length === 2 && btnLog.every(e => e[2] === false) && btnLog.some(e => e[1] === 'A') && btnLog.some(e => e[1] === 'B'), btnLog);
}

console.log(fails.length ? '\n' + fails.length + ' failing' : '\nall passing');
process.exit(fails.length ? 1 : 0);

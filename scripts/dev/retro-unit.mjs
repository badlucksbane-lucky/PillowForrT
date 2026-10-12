// Tests the Retro game (gameclient/retro.js) against a fake libretro core, without a browser: the host (callbacks, pixel formats, input bits, audio, geometry, closing)
// and the game around it (menu, loading, joypad masks from the phones, pacing, a failed load, destroy). The real cores are checked by retro-core-spike.cjs.
// Usage: node retro-unit.mjs   Exit code 1 on failure.
import fs from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
const src = fs.readFileSync(path.join(path.dirname(fileURLToPath(import.meta.url)), '../../gameclient/retro.js'), 'utf8');
let game; new Function('Games', src)({ register: g => { game = g; } });
const fails = [];
const check = (name, ok, got) => { console.log((ok ? 'ok   ' : 'FAIL ') + name + (ok ? '' : '  got: ' + JSON.stringify(got))); if (!ok) fails.push(name); };
const tick = () => new Promise(r => setTimeout(r, 0));

// A fake core with the same shape as an Emscripten libretro build: memory, a function table, the retro_* exports. What it hands the frontend each frame is set from outside.
function fakeCore(o = {}) {
  const mem = new ArrayBuffer(1 << 20), dv = new DataView(mem), HEAPU8 = new Uint8Array(mem);
  let brk = 4096; const table = [null], files = {}, M = { calls: [], files, table, seen: [], envResults: {} };
  const cb = {}, cstrAt = p => { let s = ''; while (HEAPU8[p]) s += String.fromCharCode(HEAPU8[p++]); return s; };
  Object.assign(M, {
    HEAPU8, HEAPU32: new Uint32Array(mem), HEAP32: new Int32Array(mem), HEAPU16: new Uint16Array(mem),
    _malloc: n => { const p = brk; brk += (n + 15) & ~15; return p; }, _free() {},
    addFunction: f => table.push(f) - 1, removeFunction: p => { table[p] = null; }, UTF8ToString: cstrAt,
    FS: { writeFile: (p, d) => { files[p] = d; } },
    _retro_set_environment: p => { cb.env = p; }, _retro_set_video_refresh: p => { cb.video = p; }, _retro_set_audio_sample: p => { cb.a1 = p; }, _retro_set_audio_sample_batch: p => { cb.ab = p; },
    _retro_set_input_poll: p => { cb.poll = p; }, _retro_set_input_state: p => { cb.input = p; },
    _retro_init: () => { M.calls.push('init'); const f = M._malloc(4); dv.setInt32(f, o.fmt ?? 1, true); M.envResults.fmt = table[cb.env](10, f); const d = M._malloc(4); table[cb.env](3 | 0x10000, d); M.envResults.dupe = HEAPU8[d]; M.envResults.unknown = table[cb.env](9999, 0); },
    _retro_load_game: gi => { M.calls.push('load'); M.gamePath = cstrAt(dv.getUint32(gi, true)); M.gameSize = dv.getUint32(gi + 8, true); return o.reject ? 0 : 1; },
    _retro_get_system_av_info: p => { dv.setUint32(p, o.w ?? 2, true); dv.setUint32(p + 4, o.h ?? 1, true); dv.setUint32(p + 8, 4, true); dv.setUint32(p + 12, 4, true); dv.setFloat32(p + 16, o.aspect ?? 2, true); dv.setFloat64(p + 24, o.fps ?? 60, true); dv.setFloat64(p + 32, o.rate ?? 32768, true); },
    _retro_run: () => {
      M.calls.push('run'); table[cb.poll]();
      M.seen.push([0, 1, 2, 3].map(port => table[cb.input](port, 1, 0, 256))); // the whole mask for each port
      M.bitDown = table[cb.input](0, 1, 0, 8); M.bitUp = table[cb.input](0, 1, 0, 4); M.notPad = table[cb.input](0, 2, 0, 8); M.port9 = table[cb.input](9, 1, 0, 8);
      if (o.frame) { const fb = M._malloc(o.frame.bytes.length); HEAPU8.set(o.frame.bytes, fb); table[cb.video](o.dupe ? 0 : fb, o.frame.w, o.frame.h, o.frame.pitch); }
      else table[cb.video](0, 0, 0, 0);
      if (o.audio) { const ap = M._malloc(o.audio.length * 2); new Int16Array(mem, ap, o.audio.length).set(o.audio); table[cb.ab](ap, o.audio.length / 2); }
      if (o.single) table[cb.a1](o.single[0], o.single[1]);
    },
    _retro_reset: () => M.calls.push('reset'), _retro_unload_game: () => M.calls.push('unload'), _retro_deinit: () => M.calls.push('deinit'),
    _retro_serialize_size: () => o.stateSize ?? 4,
    _retro_serialize: (p, n) => { M.calls.push('serialize'); for (let i = 0; i < n; i++) HEAPU8[p + i] = o.stateByte ?? 7; return o.serializeOk === false ? 0 : 1; },
    _retro_unserialize: (p, n) => { M.calls.push('unserialize'); M.lastUnserialize = HEAPU8.slice(p, p + n); return o.unserializeOk === false ? 0 : 1; },
    _retro_get_memory_size: id => id === 0 ? (o.sramSize ?? 0) : 0,
    _retro_get_memory_data: id => { if (id !== 0 || !(o.sramSize ?? 0)) return 0; if (!M.sramPtr) M.sramPtr = M._malloc(o.sramSize); return M.sramPtr; },
    env: (cmd, v) => { const d = M._malloc(64); if (v) v(dv, d); const r = table[cb.env](cmd, d); return { r, d }; }, dv
  });
  return M;
}
const px = (v) => { const b = new Uint8Array(4); new DataView(b.buffer).setUint32(0, v, true); return b; };
const hostOf = (M, io = {}) => { let h; new Function('Games', src)({ register: g => { h = g.create({ players: () => [], retro: { index: () => new Promise(() => {}) } }); } }); return h.host(M, io); };

// ---- the host ----
{
  const M = fakeCore(), got = []; const h = hostOf(M, { onFrame: (w, hh, p) => got.push([w, hh, Array.from(p)]) });
  check('it asked for the core to be set up in order: init after set_environment, formats and dupe answered', M.calls[0] === 'init' && M.envResults.fmt === 1 && M.envResults.dupe === 1, M);
  check('an unknown environment command is refused', M.envResults.unknown === 0, M.envResults);
  check('a ROM is loaded by path and by data', h.load(new Uint8Array(10), 'GB') && M.gamePath === '/game.GB' && M.files['/game.GB'].length === 10 && M.gameSize === 10, { p: M.gamePath, s: M.gameSize });
  check('the geometry and timing are read from the core', h.w === 2 && h.h === 1 && h.aspect === 2 && h.fps === 60 && h.rate === 32768, h);
  const bad = hostOf(fakeCore({ reject: true }));
  check('a core that refuses the ROM reports it', bad.load(new Uint8Array(4), 'nes') === false && bad.loaded === false, bad.loaded);
  bad.close();
}
{ // pixel formats
  const run = (o, fmt) => { const M = fakeCore({ ...o, fmt }); const got = []; const h = hostOf(M, { onFrame: (w, hh, p) => got.push([w, hh, Array.from(p)]) }); h.load(new Uint8Array(4), 'x'); h.run(); return got[0]; };
  const x = run({ frame: { w: 2, h: 1, pitch: 16, bytes: new Uint8Array([...px(0x00112233), ...px(0x00ffeedd), 0, 0, 0, 0, 0, 0, 0, 0]) } }, 1);
  check('XRGB8888 becomes RGBA, rows read by their pitch', x && x[0] === 2 && x[1] === 1 && x[2].join() === [0x11, 0x22, 0x33, 255, 0xff, 0xee, 0xdd, 255].join(), x);
  const b = new Uint8Array(12); new DataView(b.buffer).setUint16(0, 0xF800, true); new DataView(b.buffer).setUint16(2, 0x07E0, true); new DataView(b.buffer).setUint16(8, 0x001F, true); new DataView(b.buffer).setUint16(10, 0xFFFF, true);
  const r = run({ frame: { w: 2, h: 2, pitch: 8, bytes: b } }, 2);
  check('RGB565 red, green, blue and white fill the whole channel', r && r[2].join() === [255, 0, 0, 255, 0, 255, 0, 255, 0, 0, 255, 255, 255, 255, 255, 255].join(), r);
  const f = new Uint8Array(4); new DataView(f.buffer).setUint16(0, 0x7C00, true); new DataView(f.buffer).setUint16(2, 0x03E0, true);
  const z = run({ frame: { w: 2, h: 1, pitch: 4, bytes: f } }, 0);
  check('0RGB1555 red and green', z && z[2].join() === [255, 0, 0, 255, 0, 255, 0, 255].join(), z);
  const d = run({ frame: { w: 2, h: 1, pitch: 8, bytes: new Uint8Array(8) }, dupe: true }, 1);
  check('a duplicate frame (no data) draws nothing new', d === undefined, d);
}
{ // input
  const M = fakeCore(); const h = hostOf(M); h.load(new Uint8Array(4), 'x');
  h.mask = [0x0100 | 0x0010, 0x8, 0, 0]; h.run();
  check('the mask for each port reaches the core (one call asks for all bits)', M.seen[0].join() === [0x110, 8, 0, 0].join(), M.seen);
  check('single bits agree with the mask: A (id 8) down, Up (id 4) down, non-joypad and port 9 give 0', M.bitDown === 1 && M.bitUp === 1 && M.notPad === 0 && M.port9 === 0, [M.bitDown, M.bitUp, M.notPad, M.port9]);
}
{ // audio and geometry changes
  const M = fakeCore({ audio: new Int16Array([1, -1, 2, -2, 3, -3]), single: [7, 8] }); const a = []; const h = hostOf(M, { onAudio: x => a.push(Array.from(x)) }); h.load(new Uint8Array(4), 'x'); h.run();
  check('a batch of samples is copied out as interleaved stereo, single samples follow once per run', a.length === 2 && a[0].join() === '1,-1,2,-2,3,-3' && a[1].join() === '7,8', a);
  const g = M.env(37, (dv, d) => { dv.setUint32(d, 160, true); dv.setUint32(d + 4, 144, true); dv.setFloat32(d + 16, 10 / 9, true); });
  check('SET_GEOMETRY changes the picture size and aspect', g.r === 1 && h.w === 160 && h.h === 144 && Math.abs(h.aspect - 10 / 9) < 1e-6, h);
  const av = M.env(32, (dv, d) => { dv.setUint32(d, 256, true); dv.setUint32(d + 4, 240, true); dv.setFloat32(d + 16, 4 / 3, true); dv.setFloat64(d + 24, 50, true); dv.setFloat64(d + 32, 44100, true); });
  check('SET_SYSTEM_AV_INFO changes fps and sample rate', av.r === 1 && h.fps === 50 && h.rate === 44100, h);
  const before = M.table.filter(Boolean).length;
  h.close();
  check('closing unloads, deinits and frees every callback', M.calls.slice(-2).join() === 'unload,deinit' && M.table.filter(Boolean).length === 0 && before > 5, [M.calls, before]);
}
{ // savestates and battery saves
  const M = fakeCore({ stateSize: 4, stateByte: 7, sramSize: 4 }); const h = hostOf(M); h.load(new Uint8Array(4), 'x');
  const st = h.saveState();
  check('a savestate is read out at its serialize size', st && st.length === 4 && Array.from(st).every(b => b === 7), st);
  check('a savestate is restored by unserialize', h.loadState(new Uint8Array([9, 9, 9, 9])) === true && Array.from(M.lastUnserialize).join() === '9,9,9,9', M.lastUnserialize);
  check('sram starts out zeroed at its memory size', (() => { const e = h.saveSram(); return e && e.length === 4 && e.every(b => b === 0); })());
  check('sram is written back by get_memory_data', h.loadSram(new Uint8Array([1, 2, 3, 4])) === true && Array.from(h.saveSram()).join() === '1,2,3,4', h.saveSram());
  const none = hostOf(fakeCore({ stateSize: 0, sramSize: 0 })); none.load(new Uint8Array(4), 'x');
  check('no serialize support (size 0) reports null, and nothing is freed twice', none.saveState() === null && none.loadState(new Uint8Array([1])) === false, none.saveState());
  check('no memory support (size 0) reports null/false', none.saveSram() === null && none.loadSram(new Uint8Array([1])) === false, none.saveSram());
}

// ---- the game around it ----
const players = [0, 1].map(i => ({ id: 'p' + i, slot: i, name: 'P' + i, stick: { x: 0, y: 0 }, btn: {} }));
const mk = (coreOpts, loaderOver = {}) => {
  const M = fakeCore(coreOpts), log = { cores: [], roms: [] }, saves = {}, setLog = [];
  const store = { get: k => Promise.resolve(saves[k] ?? null), set: (k, v) => { saves[k] = v; setLog.push(k); return Promise.resolve(); } };
  const loader = {
    index: () => Promise.resolve({ cores: [{ id: 'fake', name: 'Fake' }], roms: [{ file: 'a.nes', core: 'fake', name: 'a' }, { file: 'b.gb', core: 'fake', name: 'b' }, { file: 'c.gb', core: 'fake', name: 'c' }] }),
    core: id => { log.cores.push(id); return Promise.resolve(M); }, rom: f => { log.roms.push(f); return Promise.resolve(new Uint8Array(8)); }, store, ...loaderOver
  };
  players.forEach(p => { p.stick.x = p.stick.y = 0; p.btn = {}; });
  const inst = game.create({ players: () => players, retro: loader, audio: null, rumble() {}, panel() {}, end() {} });
  return { M, inst, log, s: inst.s, saves, setLog };
};
const now = Date.now; let clock = 1000; Date.now = () => clock;
{
  const g = mk({ fps: 60 }); await tick();
  check('the menu lists the ROMs the box offers', g.s.phase === 'menu' && g.s.list.length === 3 && g.s.list[1].file === 'b.gb' && g.s.list[1].system === 'Fake' && g.s.msg === '', g.s);
  players[0].stick.y = 1; g.inst.tick(0.016);
  check('the lead stick down moves the cursor', g.s.cur === 1, g.s.cur);
  clock += 100; g.inst.tick(0.016);
  check('held, it does not run away at once', g.s.cur === 1, g.s.cur);
  clock += 250; g.inst.tick(0.016);
  check('held longer, it repeats', g.s.cur === 2, g.s.cur);
  players[0].stick.y = 0; g.inst.tick(0.016); players[0].stick.y = 1; clock += 10; g.inst.tick(0.016);
  check('the cursor wraps from the last back to the first', g.s.cur === 0, g.s.cur);
  players[0].stick.y = 0; g.inst.tick(0.016);
  g.inst.onButton(players[1], 'A', true);
  check("another player's A does not start anything", g.s.phase === 'menu' && g.log.cores.length === 0, g.s.phase);
  g.inst.onButton(players[0], 'B', true); g.inst.onButton(players[0], 'A', false);
  check('a release or another button does not start anything', g.s.phase === 'menu', g.s.phase);
  g.inst.onButton(players[0], 'A', true);
  check('the lead player\'s A starts loading the chosen game', g.s.phase === 'loading' && g.s.title === 'a', g.s.phase);
  await tick(); await tick();
  check('then the core and ROM load and it runs', g.s.phase === 'run' && g.log.cores[0] === 'fake' && g.log.roms[0] === 'a.nes' && g.M.gamePath === '/game.nes', [g.s.phase, g.M.gamePath]);

  g.M.calls.length = 0; for (let i = 0; i < 60; i++) g.inst.tick(1 / 60);
  const n = g.M.calls.filter(c => c === 'run').length;
  check('60 ticks of 1/60 s run the core about 60 frames', n >= 59 && n <= 60, n);
  g.M.calls.length = 0; g.inst.tick(1);
  check('a stall of a whole second runs at most 4 frames, and does not owe them afterwards', g.M.calls.filter(c => c === 'run').length === 4, g.M.calls.length);
  g.M.calls.length = 0; g.inst.tick(1 / 60);
  check('the next tick is back to normal pace', g.M.calls.filter(c => c === 'run').length === 1, g.M.calls.length);

  players[0].stick.x = 1; players[0].stick.y = -1; players[0].btn = { A: true, Start: true, Bogus: true }; players[1].btn = { B: true, Select: true }; players[1].stick.x = 0.3;
  g.M.seen.length = 0; g.inst.tick(1 / 60);
  const bit = b => 1 << b;
  check('player 1 stick and buttons become that port\'s mask; unknown buttons and a weak stick are ignored',
    g.M.seen[0][0] === (bit(7) | bit(4) | bit(8) | bit(3)) && g.M.seen[0][1] === (bit(0) | bit(2)) && g.M.seen[0][2] === 0, g.M.seen[0]);
  g.inst.destroy();
  check('leaving the game closes the core', g.M.calls.slice(-2).join() === 'unload,deinit', g.M.calls);
  g.M.calls.length = 0; g.inst.tick(1); check('and nothing runs afterwards', !g.M.calls.includes('run'), g.M.calls);
}
{ // battery saves, savestates and the pause menu
  const g = mk({ fps: 60, sramSize: 4 }); await tick();
  g.saves['sram:a.nes'] = new Uint8Array([5, 6, 7, 8]);
  g.inst.onButton(players[0], 'A', true); await tick(); await tick(); await tick();
  check('a stored battery save is restored into sram on load', g.s.phase === 'run' && Array.from(g.M.HEAPU8.slice(g.M.sramPtr, g.M.sramPtr + 4)).join() === '5,6,7,8', g.s.phase);

  g.setLog.length = 0; for (let i = 0; i < 4; i++) g.inst.tick(1); // SRAM_PERIOD is 3s, so four 1s ticks cross it once
  check('sram autosaves periodically while running', g.setLog.filter(k => k === 'sram:a.nes').length === 1 && g.saves['sram:a.nes'].join() === '5,6,7,8', g.setLog);

  g.inst.onButton(players[0], 'Select', true);
  check('Select opens the pause menu over the running frame', g.s.phase === 'pause' && g.s.pcur === 0, g.s.phase);
  players[0].stick.y = 1; g.inst.tick(0.016);
  check('the pause menu is navigated by stick like the ROM menu', g.s.pcur === 1, g.s.pcur); // 1: Save State
  players[0].stick.y = 0; g.inst.tick(0.016);
  g.inst.onButton(players[0], 'A', true);
  check('Save State writes a state entry and reports it', g.s.pmsg === 'Saved' && g.saves['state:a.nes'] && g.saves['state:a.nes'].length === 4, [g.s.pmsg, g.saves['state:a.nes']]);
  players[0].stick.y = 1; g.inst.tick(0.016); players[0].stick.y = 0; g.inst.tick(0.016); // 2: Load State
  check('moved to Load State', g.s.pcur === 2, g.s.pcur);
  g.inst.onButton(players[0], 'A', true); await tick();
  check('Load State restores the saved state and reports it', g.s.pmsg === 'Loaded' && g.M.lastUnserialize && Array.from(g.M.lastUnserialize).every(b => b === 7), g.M.lastUnserialize);
  g.inst.onButton(players[0], 'Select', true);
  check('Select again resumes the game', g.s.phase === 'run', g.s.phase);

  g.inst.onButton(players[0], 'Select', true);
  for (let i = 0; i < 3; i++) { players[0].stick.y = 1; g.inst.tick(0.016); players[0].stick.y = 0; g.inst.tick(0.016); } // Resume -> Save -> Load -> Quit
  check('navigated to Quit', g.s.pcur === 3, g.s.pcur);
  g.setLog.length = 0; g.inst.onButton(players[0], 'A', true);
  check('Quit closes the core, saves sram once more and returns to the menu', g.s.phase === 'menu' && g.inst.hs === null && g.setLog.includes('sram:a.nes'), g.s.phase);
}
{ // destroy() also flushes a final battery save
  const g = mk({ fps: 60, sramSize: 4 }); await tick();
  g.inst.onButton(players[0], 'A', true); await tick(); await tick(); await tick();
  g.inst.destroy();
  check('destroy() saves sram one last time', g.saves['sram:a.nes'] && g.saves['sram:a.nes'].length === 4, g.saves);
}
{
  const g = mk({ reject: true }); await tick();
  g.inst.onButton(players[0], 'A', true); await tick(); await tick();
  check('a core that will not load the ROM sends you back to the menu with the reason', g.s.phase === 'menu' && /would not load/.test(g.s.msg), [g.s.phase, g.s.msg]);
  const e = mk({}, { rom: () => Promise.reject(new Error('HTTP 404')) }); await tick();
  e.inst.onButton(players[0], 'A', true); await tick(); await tick();
  check('a missing ROM file does the same', e.s.phase === 'menu' && /404/.test(e.s.msg), [e.s.phase, e.s.msg]);
  const none = mk({}, { index: () => Promise.resolve({ cores: [], roms: [] }) }); await tick();
  check('an empty box says so and A does nothing', none.s.list.length === 0 && /No games/.test(none.s.msg) && (none.inst.onButton(players[0], 'A', true), none.s.phase === 'menu'), none.s);
  const bad = mk({}, { index: () => Promise.reject(new Error('x')) }); await tick();
  check('an unreadable list is reported', /Could not read/.test(bad.s.msg), bad.s.msg);
}
{ // drawing: the menu and a frame, with a stub canvas
  const calls = []; const g = { fillStyle: '', font: '', textAlign: '', fillRect: (...a) => calls.push(['rect', ...a]), fillText: (t) => calls.push(['text', t]), drawImage: (...a) => calls.push(['image', ...a.slice(1)]) };
  globalThis.ImageData = class { constructor(p, w, h) { this.p = p; this.w = w; this.h = h; } };
  const cv = { getContext: () => ({ putImageData: () => calls.push(['put']) }) };
  const M = fakeCore({ frame: { w: 2, h: 1, pitch: 8, bytes: new Uint8Array(8) }, aspect: 2 });
  const inst = game.create({ players: () => players, retro: { index: () => Promise.resolve({ cores: [{ id: 'fake' }], roms: [{ file: 'a.nes', core: 'fake' }] }), core: () => Promise.resolve(M), rom: () => Promise.resolve(new Uint8Array(4)) }, makeCanvas: () => cv });
  await tick(); inst.render(g, 800, 450);
  check('the menu draws the game names', calls.some(c => c[0] === 'text' && c[1] === 'a.nes') && calls.some(c => c[0] === 'text' && c[1] === 'Retro'), calls.slice(0, 6));
  players[0].stick.y = 0; inst.onButton(players[0], 'A', true); await tick(); await tick(); calls.length = 0; inst.tick(1 / 60); inst.render(g, 800, 450);
  const im = calls.find(c => c[0] === 'image');
  check('a running game puts the frame on the canvas, centred, at the core\'s aspect ratio', calls.some(c => c[0] === 'put') && im && im[1] === 0 && im[2] === 25 && im[3] === 800 && im[4] === 400, im);
}
Date.now = now;
console.log(fails.length ? '\n' + fails.length + ' failed' : '\nall passed'); process.exit(fails.length ? 1 : 0);

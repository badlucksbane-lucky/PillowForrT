// Spike: minimal libretro frontend in node, proves a built core runs. Usage: node scripts/dev/retro-core-spike.cjs <dir with fceumm.js> [frames]
// Usage: node scripts/dev/retro-core-spike.cjs <dir> [frames] [fceumm|gambatte]   (loads a hand-made NES or Game Boy ROM; see scripts/retro/build-core.sh)
const path = require('path');
const dir = path.resolve(process.argv[2]);
const FRAMES = +process.argv[3] || 120;
const CORE = process.argv[4] || 'fceumm';
const createCore = require(path.join(dir, CORE + '.js'));

// Tiny NES ROM: set backdrop palette entry to $21, enable rendering, loop.
function makeGbRom() { // jump from the entry point to an infinite loop
  const r = Buffer.alloc(32768); Buffer.from([0xC3, 0x50, 0x01]).copy(r, 0x100); Buffer.from([0x18, 0xFE]).copy(r, 0x150); return r;
}
function makeRom() {
  if (CORE === 'gambatte') return makeGbRom();
  const prg = Buffer.alloc(16384, 0xea);
  const code = [0xA9,0x3F,0x8D,0x06,0x20, 0xA9,0x00,0x8D,0x06,0x20, 0xA9,0x21,0x8D,0x07,0x20,
                0xA9,0x0A,0x8D,0x01,0x20, 0x4C,0x14,0xC0];
  Buffer.from(code).copy(prg, 0);
  prg.writeUInt16LE(0xC000, 0x3FFA); prg.writeUInt16LE(0xC000, 0x3FFC); prg.writeUInt16LE(0xC000, 0x3FFE);
  const hdr = Buffer.from([0x4E,0x45,0x53,0x1A, 1, 1, 0, 0, 0,0,0,0,0,0,0,0]);
  return Buffer.concat([hdr, prg, Buffer.alloc(8192)]);
}

(async () => {
  const M = await createCore();
  const cstr = s => { const n = Buffer.byteLength(s) + 1; const p = M._malloc(n); M.HEAPU8.set(Buffer.from(s + '\0'), p); return p; };
  const stats = { frames: 0, audioFrames: 0, w: 0, h: 0, fmt: -1, pitch: 0, px: 0, envUnknown: new Set() };
  let fmt = 0;

  const logfn = M.addFunction((lvl, fmt, va) => { console.log('[core log ' + lvl + ']', M.UTF8ToString(fmt).trimEnd(), fmt && M.UTF8ToString(fmt).includes('%s') ? M.UTF8ToString(M.HEAPU32[va >> 2]) : ''); }, 'viii');
  const env = M.addFunction((cmd, data) => {
    cmd &= 0xffff; // strip RETRO_ENVIRONMENT_EXPERIMENTAL/PRIVATE flags
    switch (cmd) {
      case 3: M.HEAPU8[data] = 1; return 1;                                // GET_CAN_DUPE
      case 10: fmt = M.HEAP32[data >> 2]; stats.fmt = fmt; return 1;      // SET_PIXEL_FORMAT
      case 16: return 1;                                                   // SET_VARIABLES
      case 11: return 1;                                                   // SET_INPUT_DESCRIPTORS
      case 15: return 0;                                                   // GET_VARIABLE: use core defaults
      case 17: M.HEAPU8[data] = 0; return 1;                               // GET_VARIABLE_UPDATE
      case 27: M.HEAPU32[data >> 2] = logfn; return 1;                     // GET_LOG_INTERFACE
      case 9: case 31: M.HEAPU32[data >> 2] = cstr('/'); return 1;         // system/save dir
      default: stats.envUnknown.add(cmd); return 0;
    }
  }, 'iii');
  const video = M.addFunction((data, w, h, pitch) => {
    stats.frames++; stats.w = w; stats.h = h; stats.pitch = pitch;
    if (data) stats.px = fmt === 1 ? M.HEAPU32[(data + (120 * pitch) + 128 * 4) >> 2] : M.HEAPU16[(data + 120 * pitch + 128 * 2) >> 1];
  }, 'viiii');
  const audioBatch = M.addFunction((ptr, frames) => { stats.audioFrames += frames; return frames; }, 'iii');
  const audio1 = M.addFunction(() => {}, 'vii');
  const poll = M.addFunction(() => {}, 'v');
  const input = M.addFunction(() => 0, 'iiiii');

  M._retro_set_environment(env);
  M._retro_init();
  M._retro_set_video_refresh(video); M._retro_set_audio_sample(audio1); M._retro_set_audio_sample_batch(audioBatch);
  M._retro_set_input_poll(poll); M._retro_set_input_state(input);

  const rom = makeRom();
  const rp = M._malloc(rom.length); M.HEAPU8.set(rom, rp);
  const gi = M._malloc(16); M.HEAPU32[gi >> 2] = cstr(CORE === "gambatte" ? "/rom.gb" : "/rom.nes"); M.HEAPU32[(gi + 4) >> 2] = rp; M.HEAPU32[(gi + 8) >> 2] = rom.length; M.HEAPU32[(gi + 12) >> 2] = 0;
  M.FS.writeFile(CORE === "gambatte" ? "/rom.gb" : "/rom.nes", rom);
  const ok = M._retro_load_game(gi);
  const av = M._malloc(40); M._retro_get_system_av_info(av);
  const fps = new Float64Array(M.HEAPU8.buffer.slice(av + 24, av + 40));
  console.log('load', !!ok, 'av', { base: [M.HEAPU32[av >> 2], M.HEAPU32[(av + 4) >> 2]], fps: fps[0], rate: fps[1] });

  const t0 = process.hrtime.bigint();
  for (let i = 0; i < FRAMES; i++) M._retro_run();
  const ms = Number(process.hrtime.bigint() - t0) / 1e6;
  console.log('ran', FRAMES, 'frames in', ms.toFixed(1), 'ms =', (ms / FRAMES).toFixed(2), 'ms/frame (budget', (1000 / fps[0]).toFixed(2), ')');
  console.log('video frames', stats.frames, 'size', stats.w + 'x' + stats.h, 'fmt', stats.fmt, 'pitch', stats.pitch, 'centre px 0x' + (stats.px >>> 0).toString(16));
  console.log('audio frames', stats.audioFrames, '(expect ~', Math.round(FRAMES * fps[1] / fps[0]), ')');
  console.log('unhandled env cmds', [...stats.envUnknown]);

  const sz = M._retro_serialize_size(); const sp = M._malloc(sz);
  console.log('savestate size', sz, 'serialize ok', !!M._retro_serialize(sp, sz), 'unserialize ok', !!M._retro_unserialize(sp, sz));
})();

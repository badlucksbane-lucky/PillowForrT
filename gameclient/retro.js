// Retro: runs a libretro core on the screen. The cores are built by scripts/retro/build-core.sh (no RetroArch): this file is the frontend that loads one, feeds it the phones as joypads,
// draws its video on our canvas and plays its audio through retro-worklet.js. The rules live in host() and create(), which scripts/dev/retro-unit.mjs runs against a fake core without a browser.
// Cores and ROMs are files on the box (see retro.go): /retro/index.json lists them, /retro/cores/<id>.js|.wasm and /retro/roms/<file> serve them.
'use strict';
Games.register({
  id: 'retro', name: 'Retro', players: { min: 1, max: 4 }, orientation: 'landscape',
  widgets: [{ type: 'dpad' }, { type: 'buttons', names: ['A', 'B', 'Select', 'Start'] }],
  create: function (ctx) {
    // libretro joypad ids (RETRO_DEVICE_ID_JOYPAD_*): the face buttons are named by position on a SNES pad, so NES/GB "A" is id 8 and "B" is id 0
    var BIT = { B: 0, Y: 1, Select: 2, Start: 3, Up: 4, Down: 5, Left: 6, Right: 7, A: 8, X: 9, L: 10, R: 11 };
    var MAXFRAMES = 4; // frames run for one screen tick at most, so a slow tab catches up a little and never spirals

    // ---- the libretro host: one core, its callbacks and its state ----
    // M is the Emscripten module of a core; io.onFrame(w, h, rgba), io.onAudio(Int16Array of interleaved stereo), io.log(text) are optional.
    function host(M, io) {
      var h = { fmt: 0, w: 0, h: 0, aspect: 4 / 3, fps: 60, rate: 48000, mask: [0, 0, 0, 0], frames: 0, loaded: false };
      var fns = [], one = [], rgba = null, out32 = null;
      function fn(f, sig) { var p = M.addFunction(f, sig); fns.push(p); return p; }
      function cstr(s) { var n = s.length * 3 + 1, p = M._malloc(n); M.HEAPU8.set(new TextEncoder().encode(s + '\0'), p); return p; }
      function readAv(p) { // retro_system_av_info: geometry {base_w, base_h, max_w, max_h, aspect f32}, then timing {fps f64, sample_rate f64} at +24
        var u = new Uint32Array(M.HEAPU8.buffer.slice(p, p + 20)), f = new Float64Array(M.HEAPU8.buffer.slice(p + 24, p + 40));
        h.w = u[0]; h.h = u[1]; h.aspect = new Float32Array(M.HEAPU8.buffer.slice(p + 16, p + 20))[0] || (h.w / h.h || 4 / 3); h.fps = f[0] > 1 ? f[0] : 60; h.rate = f[1] > 1000 ? f[1] : 48000;
      }
      var env = fn(function (cmd, data) {
        switch (cmd & 0xffff) { // the high bits mark experimental and private commands
          case 3: M.HEAPU8[data] = 1; return 1; // GET_CAN_DUPE: a frame with no data means "same as last" (gambatte refuses to load without it)
          case 10: h.fmt = M.HEAP32[data >> 2]; return h.fmt >= 0 && h.fmt <= 2 ? 1 : 0; // SET_PIXEL_FORMAT: 0 is 0RGB1555, 1 XRGB8888, 2 RGB565
          case 9: case 31: M.HEAPU32[data >> 2] = h.dir || (h.dir = cstr('/')); return 1; // system and save directory
          case 11: case 16: return 1; // SET_INPUT_DESCRIPTORS, SET_VARIABLES: nothing to show
          case 15: return 0; // GET_VARIABLE: every option stays at the core's default
          case 17: M.HEAPU8[data] = 0; return 1; // GET_VARIABLE_UPDATE: nothing changed
          case 27: M.HEAPU32[data >> 2] = logfn; return 1; // GET_LOG_INTERFACE
          case 32: readAv(data); return 1; // SET_SYSTEM_AV_INFO
          case 37: // SET_GEOMETRY: base size and aspect may change while running
            h.w = M.HEAPU32[data >> 2]; h.h = M.HEAPU32[(data + 4) >> 2]; h.aspect = new Float32Array(M.HEAPU8.buffer.slice(data + 16, data + 20))[0] || h.w / h.h; return 1;
          default: return 0;
        }
      }, 'iii');
      var logfn = fn(function (lvl, fmtp, va) { // varargs come as one pointer; the first is almost always a %s
        if (lvl < 3 || !io.log) return;
        var f = M.UTF8ToString(fmtp); io.log(f.indexOf('%s') >= 0 ? f.replace('%s', M.UTF8ToString(M.HEAPU32[va >> 2])) : f);
      }, 'viii');
      var video = fn(function (data, w, hh, pitch) {
        h.frames++;
        if (!data) return; // a duplicate: keep showing the last one
        if (!rgba || h.vw !== w || h.vh !== hh) { rgba = new Uint8ClampedArray(w * hh * 4); out32 = new Uint32Array(rgba.buffer); h.vw = w; h.vh = hh; }
        var i = 0, x, y, v;
        if (h.fmt === 1) { // XRGB8888 is B,G,R,X in memory
          for (y = 0; y < hh; y++) { var s32 = new Uint32Array(M.HEAPU8.buffer, data + y * pitch, w); for (x = 0; x < w; x++) { v = s32[x]; out32[i++] = 0xff000000 | ((v & 0xff) << 16) | (v & 0xff00) | ((v >> 16) & 0xff); } }
        } else {
          for (y = 0; y < hh; y++) {
            var s16 = new Uint16Array(M.HEAPU8.buffer, data + y * pitch, w);
            for (x = 0; x < w; x++) {
              v = s16[x];
              var r, g, b;
              if (h.fmt === 2) { r = (v >> 11) & 31; g = (v >> 5) & 63; b = v & 31; r = (r << 3) | (r >> 2); g = (g << 2) | (g >> 4); b = (b << 3) | (b >> 2); }
              else { r = (v >> 10) & 31; g = (v >> 5) & 31; b = v & 31; r = (r << 3) | (r >> 2); g = (g << 3) | (g >> 2); b = (b << 3) | (b >> 2); }
              out32[i++] = 0xff000000 | (b << 16) | (g << 8) | r;
            }
          }
        }
        if (io.onFrame) io.onFrame(w, hh, rgba);
      }, 'viiii');
      var audioBatch = fn(function (ptr, frames) { if (io.onAudio) io.onAudio(new Int16Array(M.HEAPU8.buffer.slice(ptr, ptr + frames * 4))); return frames; }, 'iii');
      var audio1 = fn(function (l, r) { one.push(l, r); }, 'vii');
      var poll = fn(function () {}, 'v'); // the masks are set before each retro_run
      var input = fn(function (port, device, index, id) {
        if ((device & 0xff) !== 1 || port > 3) return 0; // RETRO_DEVICE_JOYPAD only
        return id === 256 ? h.mask[port] : (h.mask[port] >> id) & 1; // 256 asks for all the buttons at once
      }, 'iiiii');

      M._retro_set_environment(env);
      M._retro_init();
      M._retro_set_video_refresh(video); M._retro_set_audio_sample(audio1); M._retro_set_audio_sample_batch(audioBatch);
      M._retro_set_input_poll(poll); M._retro_set_input_state(input);

      h.load = function (rom, ext) { // rom: Uint8Array. Cores such as fceumm open the file by path even when handed the data, so it goes in the core's memory filesystem too.
        var path = '/game.' + ext.replace(/[^a-z0-9]/gi, '');
        M.FS.writeFile(path, rom);
        var rp = M._malloc(rom.length); M.HEAPU8.set(rom, rp);
        var gi = M._malloc(16); M.HEAPU32[gi >> 2] = cstr(path); M.HEAPU32[(gi + 4) >> 2] = rp; M.HEAPU32[(gi + 8) >> 2] = rom.length; M.HEAPU32[(gi + 12) >> 2] = 0;
        h.loaded = !!M._retro_load_game(gi);
        if (h.loaded) { var av = M._malloc(40); M._retro_get_system_av_info(av); readAv(av); M._free(av); }
        return h.loaded;
      };
      h.run = function () {
        M._retro_run();
        if (one.length && io.onAudio) { io.onAudio(Int16Array.from(one)); }
        one.length = 0;
      };
      h.reset = function () { M._retro_reset(); };
      h.close = function () {
        try { if (h.loaded) M._retro_unload_game(); M._retro_deinit(); } catch (e) { /* a core that fails to close is dropped anyway */ }
        fns.forEach(function (p) { try { M.removeFunction(p); } catch (e) { /* gone */ } });
        fns.length = 0; h.loaded = false;
      };
      return h;
    }

    function defaultLoader() { // in the browser: scripts and files from the box
      function ok(r) { if (!r.ok) throw new Error('HTTP ' + r.status); return r; }
      return {
        index: function () { return fetch('/retro/index.json').then(ok).then(function (r) { return r.json(); }); },
        core: function (id) {
          return new Promise(function (res, rej) {
            var s = document.createElement('script'); s.src = '/retro/cores/' + id + '.js';
            s.onload = function () { window.createCore({ locateFile: function (f) { return '/retro/cores/' + f; } }).then(res, rej); }; // each core script defines createCore; use it now, before another replaces it
            s.onerror = function () { rej(new Error('core ' + id + ' not found')); };
            document.head.append(s);
          });
        },
        rom: function (file) { return fetch('/retro/roms/' + encodeURIComponent(file)).then(ok).then(function (r) { return r.arrayBuffer(); }).then(function (b) { return new Uint8Array(b); }); }
      };
    }

    // ---- the game ----
    var loader = ctx.retro || defaultLoader();
    var s = { phase: 'menu', list: [], cur: 0, msg: 'Looking for games…', title: '', sound: false };
    var core = null, hs = null, acc = 0, frame = null, canvas = null, node = null, navAt = 0, navDir = 0, gone = false;
    var makeCanvas = ctx.makeCanvas || function () { return document.createElement('canvas'); };

    loader.index().then(function (ix) {
      if (gone) return;
      var names = {}; (ix.cores || []).forEach(function (c) { names[c.id] = c.name || c.id; });
      s.list = (ix.roms || []).map(function (r) { return { file: r.file, core: r.core, name: r.name || r.file, system: names[r.core] || r.core }; });
      s.msg = s.list.length ? '' : 'No games on the box yet. Put ROMs in the roms folder.';
    }, function () { if (!gone) s.msg = 'Could not read the game list.'; });

    function sink() { // the audio worklet takes the core's samples; without an audio context (or before the tap) the game is silent
      var a = ctx.audio;
      if (!a || !a.audioWorklet || typeof AudioWorkletNode === 'undefined') return;
      a.audioWorklet.addModule('/game/retro-worklet.js').then(function () {
        if (gone) return;
        node = new AudioWorkletNode(a, 'retro-sink', { outputChannelCount: [2] });
        node.connect(a.destination); node.port.postMessage({ rate: hs ? hs.rate : 48000 }); s.sound = true;
      }, function () { /* no worklet: no sound */ });
    }
    function play(item) {
      s.phase = 'loading'; s.title = item.name;
      var ext = (item.file.split('.').pop() || '').toLowerCase();
      Promise.all([loader.core(item.core), loader.rom(item.file)]).then(function (r) {
        if (gone) return;
        core = r[0];
        hs = host(core, {
          onFrame: function (w, hh, px) { frame = { w: w, h: hh, px: px, fresh: true }; },
          onAudio: function (a) { if (node) node.port.postMessage(a.buffer, [a.buffer]); },
          log: function (t) { if (typeof console !== 'undefined') console.log('[retro] ' + t); }
        });
        if (!hs.load(r[1], ext)) throw new Error('The core would not load ' + item.file);
        if (node) node.port.postMessage({ rate: hs.rate }); else sink();
        acc = 0; s.phase = 'run';
      }).catch(function (e) { if (gone) return; if (hs) { hs.close(); hs = null; } s.phase = 'menu'; s.msg = String(e && e.message || e); });
    }

    function maskFor(p) {
      var m = 0, k = p.stick || { x: 0, y: 0 }, b = p.btn || {};
      if (k.y < -0.5) m |= 1 << BIT.Up; if (k.y > 0.5) m |= 1 << BIT.Down; if (k.x < -0.5) m |= 1 << BIT.Left; if (k.x > 0.5) m |= 1 << BIT.Right;
      for (var n in b) if (b[n] && BIT[n] !== undefined) m |= 1 << BIT[n];
      return m;
    }
    function lead() { var best = null; ctx.players().forEach(function (p) { if (!best || p.slot < best.slot) best = p; }); return best; }

    function tick(dt) {
      if (s.phase === 'menu') { // the lowest player's stick moves the cursor, held it repeats
        var p = lead(), d = p && p.stick.y < -0.5 ? -1 : p && p.stick.y > 0.5 ? 1 : 0, now = Date.now();
        if (d && s.list.length && (d !== navDir || now - navAt > 220)) { s.cur = (s.cur + d + s.list.length) % s.list.length; navAt = now; }
        navDir = d; return;
      }
      if (s.phase !== 'run' || !hs) return;
      var m = [0, 0, 0, 0]; ctx.players().forEach(function (q) { if (q.slot < 4) m[q.slot] = maskFor(q); }); hs.mask = m;
      acc += dt; var spf = 1 / hs.fps, n = 0;
      while (acc >= spf && n < MAXFRAMES) { hs.run(); acc -= spf; n++; }
      if (acc > spf * MAXFRAMES) acc = 0;
    }
    function onButton(p, name, down) {
      if (!down || s.phase !== 'menu' || !s.list.length) return;
      if (name === 'A' && lead() === p) play(s.list[s.cur]);
    }
    function render(g, w, h) {
      g.fillStyle = '#000'; g.fillRect(0, 0, w, h);
      g.textAlign = 'center';
      if (s.phase === 'run' && frame) {
        if (!canvas) canvas = makeCanvas();
        if (frame.fresh) { canvas.width = frame.w; canvas.height = frame.h; canvas.getContext('2d').putImageData(new ImageData(frame.px, frame.w, frame.h), 0, 0); frame.fresh = false; }
        var asp = hs && hs.aspect > 0 ? hs.aspect : frame.w / frame.h, dh = Math.min(h, w / asp), dw = dh * asp;
        g.imageSmoothingEnabled = false; g.drawImage(canvas, (w - dw) / 2, (h - dh) / 2, dw, dh);
        return;
      }
      g.fillStyle = '#f1ebde'; g.font = '800 40px system-ui, sans-serif'; g.fillText('Retro', w / 2, 70);
      g.font = '500 18px system-ui, sans-serif'; g.fillStyle = '#9b9384';
      if (s.phase === 'loading') { g.fillStyle = '#d9b27a'; g.font = '700 28px system-ui, sans-serif'; g.fillText('Loading ' + s.title + '…', w / 2, h / 2); return; }
      if (s.msg) { g.fillText(s.msg, w / 2, 110); }
      var rows = Math.max(1, Math.floor((h - 190) / 36)), top = Math.max(0, Math.min(s.cur - (rows >> 1), s.list.length - rows));
      for (var i = top; i < Math.min(s.list.length, top + rows); i++) {
        var y = 160 + (i - top) * 36, sel = i === s.cur;
        if (sel) { g.fillStyle = '#352f23'; g.fillRect(w / 2 - 260, y - 24, 520, 32); }
        g.fillStyle = sel ? '#d9b27a' : '#f1ebde'; g.font = (sel ? '700 ' : '500 ') + '20px system-ui, sans-serif'; g.textAlign = 'left'; g.fillText(s.list[i].name, w / 2 - 248, y - 1);
        g.fillStyle = '#9b9384'; g.font = '500 14px system-ui, sans-serif'; g.textAlign = 'right'; g.fillText(s.list[i].system, w / 2 + 248, y - 1); g.textAlign = 'center';
      }
      if (s.list.length) { g.fillStyle = '#9b9384'; g.font = '500 16px system-ui, sans-serif'; g.fillText('Stick: choose   A: play', w / 2, h - 24); }
    }
    function destroy() { gone = true; if (hs) { hs.close(); hs = null; } if (node) { try { node.disconnect(); } catch (e) { /* gone */ } node = null; } }

    return {
      s: s, host: host, maskFor: maskFor, tick: tick, render: render, onButton: onButton, destroy: destroy,
      get hs() { return hs; }
    };
  }
});

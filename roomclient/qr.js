// A small QR code encoder for join links: byte mode, versions 1 to 10 (up to 213 bytes at level M, 271 at L), no dependencies, served at /room/qr.js.
//
//   QR.svg('https://pillowforrt.lan/room-test#ABCD')      -> '<svg ...>' dark modules on a light tile with the required quiet zone, so it scans in dark mode too
//   QR.svg(text, {ecl: 'L', scale: 6, margin: 4})          ecl 'M' (default) survives some damage; 'L' is smaller
//   QR.matrix(text, {ecl})                                 -> {size, ver, mask, get(x, y)}   true is a dark module
//
// The layout follows ISO/IEC 18004 (finder, timing and alignment patterns, Reed-Solomon over GF(256) with 0x11D, the eight masks with the standard penalty rules, format and version
// bits). scripts/dev/qr-test.mjs decodes what it makes with an independent decoder.
'use strict';
(function () {
  // per version 1..10: error-correction codewords in each block, and the number of blocks
  var ECC_PER_BLOCK = { L: [7, 10, 15, 20, 26, 18, 20, 24, 30, 18], M: [10, 16, 26, 18, 24, 16, 18, 22, 22, 26] };
  var NUM_BLOCKS = { L: [1, 1, 1, 1, 1, 2, 2, 2, 2, 4], M: [1, 1, 1, 2, 2, 4, 4, 4, 5, 5] };
  var FORMAT_BITS = { L: 1, M: 0 };
  var MAX_VER = 10;

  function rawModules(ver) {
    var r = (16 * ver + 128) * ver + 64;
    if (ver >= 2) { var n = Math.floor(ver / 7) + 2; r -= (25 * n - 10) * n - 55; if (ver >= 7) r -= 36; }
    return r;
  }
  var rawCodewords = function (ver) { return Math.floor(rawModules(ver) / 8); };
  var dataCodewords = function (ver, ecl) { return rawCodewords(ver) - ECC_PER_BLOCK[ecl][ver - 1] * NUM_BLOCKS[ecl][ver - 1]; };

  function utf8(s) {
    if (typeof TextEncoder !== 'undefined') return Array.from(new TextEncoder().encode(s));
    var out = [], e = unescape(encodeURIComponent(s));
    for (var i = 0; i < e.length; i++) out.push(e.charCodeAt(i));
    return out;
  }

  // ---- Reed-Solomon over GF(256), reducing polynomial x^8 + x^4 + x^3 + x^2 + 1 ----
  function gmul(x, y) {
    var z = 0;
    for (var i = 7; i >= 0; i--) { z = (z << 1) ^ ((z >>> 7) * 0x11D); z ^= ((y >>> i) & 1) * x; }
    return z;
  }
  function rsDivisor(degree) {
    var r = [], i, j, root = 1;
    for (i = 0; i < degree - 1; i++) r.push(0);
    r.push(1);
    for (i = 0; i < degree; i++) {
      for (j = 0; j < r.length; j++) { r[j] = gmul(r[j], root); if (j + 1 < r.length) r[j] ^= r[j + 1]; }
      root = gmul(root, 2);
    }
    return r;
  }
  function rsRemainder(data, div) {
    var r = div.map(function () { return 0; });
    data.forEach(function (b) {
      var f = b ^ r.shift();
      r.push(0);
      div.forEach(function (c, i) { r[i] ^= gmul(c, f); });
    });
    return r;
  }

  // ---- the data: mode, length, bytes, terminator, padding, then blocks with their error correction, interleaved ----
  function buildCodewords(bytes, ver, ecl) {
    var cap = dataCodewords(ver, ecl), bits = [];
    var put = function (v, n) { for (var i = n - 1; i >= 0; i--) bits.push((v >>> i) & 1); };
    put(4, 4); put(bytes.length, ver >= 10 ? 16 : 8);
    bytes.forEach(function (b) { put(b, 8); });
    put(0, Math.min(4, cap * 8 - bits.length));
    put(0, (8 - bits.length % 8) % 8);
    var data = [];
    for (var i = 0; i < bits.length; i += 8) { var v = 0; for (var j = 0; j < 8; j++) v = (v << 1) | bits[i + j]; data.push(v); }
    for (var pad = 0xEC; data.length < cap; pad ^= 0xEC ^ 0x11) data.push(pad);

    var nb = NUM_BLOCKS[ecl][ver - 1], el = ECC_PER_BLOCK[ecl][ver - 1], raw = rawCodewords(ver);
    var nShort = nb - raw % nb, shortLen = Math.floor(raw / nb), div = rsDivisor(el), blocks = [], k = 0;
    for (i = 0; i < nb; i++) {
      var dat = data.slice(k, k + shortLen - el + (i < nShort ? 0 : 1));
      k += dat.length;
      var ecc = rsRemainder(dat, div);
      if (i < nShort) dat.push(0); // a placeholder so short blocks line up; it is skipped below
      blocks.push(dat.concat(ecc));
    }
    var out = [];
    for (i = 0; i < blocks[0].length; i++) blocks.forEach(function (b, j) { if (i !== shortLen - el || j >= nShort) out.push(b[i]); });
    return out;
  }

  // ---- the matrix ----
  function alignPositions(ver) {
    if (ver === 1) return [];
    var n = Math.floor(ver / 7) + 2, size = ver * 4 + 17;
    var step = ver === 32 ? 26 : Math.ceil((ver * 4 + 4) / (n * 2 - 2)) * 2, r = [6];
    for (var pos = size - 7; r.length < n; pos -= step) r.splice(1, 0, pos);
    return r;
  }
  var bit = function (x, i) { return ((x >>> i) & 1) !== 0; };

  function layout(ver) {
    var size = ver * 4 + 17, mod = [], fn = [], y, x;
    for (y = 0; y < size; y++) { mod.push(new Array(size).fill(false)); fn.push(new Array(size).fill(false)); }
    var set = function (x, y, dark) { mod[y][x] = dark; fn[y][x] = true; };
    for (var i = 0; i < size; i++) { set(6, i, i % 2 === 0); set(i, 6, i % 2 === 0); }
    var finder = function (cx, cy) {
      for (var dy = -4; dy <= 4; dy++) for (var dx = -4; dx <= 4; dx++) {
        var d = Math.max(Math.abs(dx), Math.abs(dy)), xx = cx + dx, yy = cy + dy;
        if (xx >= 0 && xx < size && yy >= 0 && yy < size) set(xx, yy, d !== 2 && d !== 4);
      }
    };
    finder(3, 3); finder(size - 4, 3); finder(3, size - 4);
    var ap = alignPositions(ver), n = ap.length;
    for (i = 0; i < n; i++) for (var j = 0; j < n; j++) {
      if ((i === 0 && j === 0) || (i === 0 && j === n - 1) || (i === n - 1 && j === 0)) continue;
      for (var dy = -2; dy <= 2; dy++) for (var dx = -2; dx <= 2; dx++) set(ap[i] + dx, ap[j] + dy, Math.max(Math.abs(dx), Math.abs(dy)) !== 1);
    }
    drawFormat(mod, fn, size, 'L', 0, true); // reserve the format area; the real bits are written once the mask is chosen
    if (ver >= 7) {
      var rem = ver;
      for (i = 0; i < 12; i++) rem = (rem << 1) ^ ((rem >>> 11) * 0x1F25);
      var bits = (ver << 12) | rem;
      for (i = 0; i < 18; i++) { var a = size - 11 + i % 3, b = Math.floor(i / 3); set(a, b, bit(bits, i)); set(b, a, bit(bits, i)); }
    }
    return { size: size, mod: mod, fn: fn };
  }

  function drawFormat(mod, fn, size, ecl, mask, reserve) {
    var data = (FORMAT_BITS[ecl] << 3) | mask, rem = data, i;
    for (i = 0; i < 10; i++) rem = (rem << 1) ^ ((rem >>> 9) * 0x537);
    var bits = ((data << 10) | rem) ^ 0x5412;
    var set = function (x, y, dark) { mod[y][x] = reserve ? false : dark; fn[y][x] = true; };
    for (i = 0; i <= 5; i++) set(8, i, bit(bits, i));
    set(8, 7, bit(bits, 6)); set(8, 8, bit(bits, 7)); set(7, 8, bit(bits, 8));
    for (i = 9; i < 15; i++) set(14 - i, 8, bit(bits, i));
    for (i = 0; i < 8; i++) set(size - 1 - i, 8, bit(bits, i));
    for (i = 8; i < 15; i++) set(8, size - 15 + i, bit(bits, i));
    mod[size - 8][8] = true; fn[size - 8][8] = true; // the always-dark module
  }

  function place(L, codewords) {
    var size = L.size, i = 0;
    for (var right = size - 1; right >= 1; right -= 2) {
      if (right === 6) right = 5;
      for (var vert = 0; vert < size; vert++) for (var j = 0; j < 2; j++) {
        var x = right - j, y = ((right + 1) & 2) === 0 ? size - 1 - vert : vert;
        if (!L.fn[y][x] && i < codewords.length * 8) { L.mod[y][x] = bit(codewords[i >>> 3], 7 - (i & 7)); i++; }
      }
    }
  }

  var MASKS = [
    function (x, y) { return (x + y) % 2 === 0; },
    function (x, y) { return y % 2 === 0; },
    function (x, y) { return x % 3 === 0; },
    function (x, y) { return (x + y) % 3 === 0; },
    function (x, y) { return (Math.floor(x / 3) + Math.floor(y / 2)) % 2 === 0; },
    function (x, y) { return x * y % 2 + x * y % 3 === 0; },
    function (x, y) { return (x * y % 2 + x * y % 3) % 2 === 0; },
    function (x, y) { return ((x + y) % 2 + x * y % 3) % 2 === 0; }
  ];
  function applyMask(L, m) {
    for (var y = 0; y < L.size; y++) for (var x = 0; x < L.size; x++) if (!L.fn[y][x] && MASKS[m](x, y)) L.mod[y][x] = !L.mod[y][x];
  }

  // the four standard penalty rules: runs of five or more, 2x2 blocks, finder-like patterns, dark/light balance
  function penalty(mod, size) {
    var score = 0, x, y, run, line, dark = 0;
    var P1 = [1, 0, 1, 1, 1, 0, 1, 0, 0, 0, 0], P2 = [0, 0, 0, 0, 1, 0, 1, 1, 1, 0, 1];
    var scan = function (get) {
      var last = null;
      run = 0;
      for (var k = 0; k < size; k++) {
        var v = get(k);
        if (v === last) { run++; if (run === 5) score += 3; else if (run > 5) score++; } else { last = v; run = 1; }
      }
      for (k = 0; k + 11 <= size; k++) {
        var a = true, b = true;
        for (var q = 0; q < 11; q++) { var w = get(k + q) ? 1 : 0; if (w !== P1[q]) a = false; if (w !== P2[q]) b = false; }
        if (a || b) score += 40;
      }
    };
    for (y = 0; y < size; y++) { line = mod[y]; scan(function (k) { return line[k]; }); }
    for (x = 0; x < size; x++) scan(function (k) { return mod[k][x]; });
    for (y = 0; y < size; y++) for (x = 0; x < size; x++) {
      if (mod[y][x]) dark++;
      if (x + 1 < size && y + 1 < size && mod[y][x] === mod[y][x + 1] && mod[y][x] === mod[y + 1][x] && mod[y][x] === mod[y + 1][x + 1]) score += 3;
    }
    var total = size * size;
    score += (Math.ceil(Math.abs(dark * 20 - total * 10) / total) - 1) * 10;
    return score;
  }

  function matrix(text, o) {
    o = o || {};
    var ecl = o.ecl === 'L' ? 'L' : 'M', bytes = utf8(String(text)), ver;
    for (ver = 1; ver <= MAX_VER; ver++) {
      var cap = dataCodewords(ver, ecl) * 8, need = 4 + (ver >= 10 ? 16 : 8) + bytes.length * 8;
      if (need <= cap) break;
    }
    if (ver > MAX_VER) throw new Error('too long for a QR code here (' + bytes.length + ' bytes; the limit is about ' + (dataCodewords(MAX_VER, ecl) - 3) + ')');
    var codewords = buildCodewords(bytes, ver, ecl), best = null, bestMask = 0, bestScore = Infinity;
    for (var m = 0; m < 8; m++) {
      var L = layout(ver);
      place(L, codewords); applyMask(L, m); drawFormat(L.mod, L.fn, L.size, ecl, m, false);
      var s = penalty(L.mod, L.size);
      if (s < bestScore) { bestScore = s; best = L; bestMask = m; }
    }
    var mod = best.mod;
    return { size: best.size, ver: ver, mask: bestMask, get: function (x, y) { return x >= 0 && y >= 0 && x < best.size && y < best.size && mod[y][x]; } };
  }

  function svg(text, o) {
    o = o || {};
    var mx = matrix(text, o), margin = o.margin === undefined ? 4 : o.margin, scale = o.scale || 6, n = mx.size + margin * 2, d = '', y, x, x0;
    for (y = 0; y < mx.size; y++) {
      for (x = 0; x < mx.size; x++) {
        if (!mx.get(x, y)) continue;
        x0 = x;
        while (x + 1 < mx.size && mx.get(x + 1, y)) x++;
        d += 'M' + (x0 + margin) + ' ' + (y + margin) + 'h' + (x - x0 + 1) + 'v1h-' + (x - x0 + 1) + 'z';
      }
    }
    return '<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 ' + n + ' ' + n + '" width="' + n * scale + '" height="' + n * scale + '" shape-rendering="crispEdges" role="img" aria-label="QR code">' +
      '<rect width="' + n + '" height="' + n + '" fill="#fff"/><path d="' + d + '" fill="#000"/></svg>';
  }

  window.QR = { matrix: matrix, svg: svg };
})();

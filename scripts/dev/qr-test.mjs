// Decodes what roomclient/qr.js makes with an independent decoder (jsQR), over every version it supports (1 to 10), both error-correction levels, the join-link shapes, UTF-8 and random
// lengths, and checks the SVG output and the size limit. jsQR is not a dependency of this repo: install it anywhere and point at it, e.g.
//   npm install --ignore-scripts --prefix /tmp/qrcheck jsqr && JSQR_DIR=/tmp/qrcheck node scripts/dev/qr-test.mjs
// Usage: node qr-test.mjs   (Node 22; a few seconds)   Exit code 1 if anything fails, 2 if jsQR is missing.
import { createRequire } from 'node:module';
import path from 'node:path';
import { fileURLToPath, pathToFileURL } from 'node:url';
const here = path.dirname(fileURLToPath(import.meta.url));
let jsQR;
try { jsQR = createRequire(path.join(process.env.JSQR_DIR || here, 'x.js'))('jsqr'); } catch (e) { console.error('jsqr not found: ' + e.message + '\nnpm install --ignore-scripts --prefix /tmp/qrcheck jsqr && JSQR_DIR=/tmp/qrcheck node scripts/dev/qr-test.mjs'); process.exit(2); }
globalThis.window = globalThis;
await import(pathToFileURL(path.join(here, '../../roomclient/qr.js')).href);

const fails = [];
const check = (name, ok, got) => { console.log((ok ? 'ok   ' : 'FAIL ') + name + (ok ? '' : '  got: ' + JSON.stringify(got))); if (!ok) fails.push(name); };

// the matrix as a picture: dark modules on white with a 4-module quiet zone
function render(mx, scale = 4, margin = 4) {
  const n = (mx.size + margin * 2) * scale, px = new Uint8ClampedArray(n * n * 4).fill(255);
  for (let y = 0; y < mx.size; y++) for (let x = 0; x < mx.size; x++) if (mx.get(x, y))
    for (let dy = 0; dy < scale; dy++) for (let dx = 0; dx < scale; dx++) { const i = (((y + margin) * scale + dy) * n + (x + margin) * scale + dx) * 4; px[i] = px[i + 1] = px[i + 2] = 0; }
  return { px, n };
}
const decode = (text, o) => { const mx = QR.matrix(text, o), { px, n } = render(mx), r = jsQR(px, n, n, { inversionAttempts: 'dontInvert' }); return { mx, text: r && r.data, ver: r && r.version }; };

let bad = [], count = 0;
const versionsSeen = { L: new Set(), M: new Set() };
for (const ecl of ['L', 'M']) {
  for (let len = 1; len <= (ecl === 'M' ? 213 : 271); len++) {
    const s = Array.from({ length: len }, (_, i) => String.fromCharCode(33 + ((i * 7 + len * 13) % 90))).join('');
    const r = decode(s, { ecl }); count++; versionsSeen[ecl].add(r.mx.ver);
    if (r.text !== s) bad.push([ecl, len, r.mx.ver, r.mx.mask, r.text && r.text.length]);
  }
}
check(`${count} strings of every length decode back exactly (levels L and M)`, bad.length === 0, bad.slice(0, 5));
check('every version 1 to 10 was exercised at both levels', [...versionsSeen.L].length === 10 && [...versionsSeen.M].length === 10, [[...versionsSeen.L], [...versionsSeen.M]]);

const urls = ['https://pillowforrt.lan/room-test#ABCD', 'https://192.168.1.254/room-test#NEDX', 'https://pillowforrt.lan:3129/room-test#AAAK', 'http://127.0.0.1:43691/room-test#WXYZ', 'ABCD', ''];
for (const u of urls) { const r = decode(u || 'x'); check('join link decodes: ' + (u || 'x'), r.text === (u || 'x'), r.text); }
const u8 = 'Fort Drop · café ☕ 日本語 🛏️'; check('UTF-8 decodes', decode(u8).text === u8, decode(u8).text);

// random content, including bytes that look like format and padding patterns
let rbad = 0;
for (let t = 0; t < 300; t++) { const len = 1 + Math.floor(Math.random() * 150), s = Array.from({ length: len }, () => String.fromCharCode(32 + Math.floor(Math.random() * 95))).join(''); if (decode(s, { ecl: Math.random() < .5 ? 'L' : 'M' }).text !== s) rbad++; }
check('300 random strings decode', rbad === 0, rbad);

// every mask the encoder can choose is valid: force each by trying many inputs and recording which masks were picked
const masks = new Set(); for (let len = 1; len <= 120; len++) masks.add(QR.matrix('m'.repeat(len) + len).mask);
check('several different masks get chosen (and decode, above)', masks.size >= 4, [...masks]);

const sv = QR.svg(urls[0]);
check('svg is well formed with a viewBox, quiet zone and one path', /^<svg [^>]*viewBox="0 0 (\d+) \1"/.test(sv) && (sv.match(/<path /g) || []).length === 1 && sv.includes('fill="#fff"'), sv.slice(0, 120));
let threw = ''; try { QR.matrix('x'.repeat(300)); } catch (e) { threw = e.message; }
check('too much data is refused with a message', /too long/.test(threw), threw);
console.log(fails.length ? '\n' + fails.length + ' FAILED' : '\nall passed');
process.exit(fails.length ? 1 : 0);

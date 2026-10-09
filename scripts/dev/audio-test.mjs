// Plays a local file whose audio is E-AC-3 / AC-3 through btclient/audio.js in desktop Chromium and checks that sound comes out: a peak meter on the gain node, before and after a seek.
// Usage: node audio-test.mjs file.mkv   (make one: ffmpeg -f lavfi -i testsrc=d=20 -f lavfi -i sine=d=20 -c:v libvpx -c:a eac3 t.mkv)
// The page is served with the same script-src / worker-src additions as browse.go (wasm-unsafe-eval, blob: workers), so a CSP regression shows up here.
import http from 'node:http';
import fs from 'node:fs';
import path from 'node:path';
import { spawn } from 'node:child_process';
import { fileURLToPath } from 'node:url';
const here = path.dirname(fileURLToPath(import.meta.url));
const file = process.argv[2];
if (!file) { console.error('usage: node audio-test.mjs file'); process.exit(2); }
const audioJS = fs.readFileSync(path.join(here, '../../btclient/audio.js'));
const csp = "default-src 'self'; script-src 'self' 'unsafe-inline' 'wasm-unsafe-eval'; worker-src 'self' blob:; media-src 'self'";
const page = `<!doctype html><meta charset=utf-8><video id=v src="/media" muted=false playsinline></video><script src="/audio.js"></script><script>
window.peak=0;const mk=AudioContext.prototype.createGain;AudioContext.prototype.createGain=function(){const g=mk.call(this),a=this.createAnalyser();a.fftSize=2048;g.connect(a);const d=new Float32Array(2048);
setInterval(()=>{a.getFloatTimeDomainData(d);let m=0;for(const x of d)m=Math.max(m,Math.abs(x));window.peak=Math.max(window.peak,m)},50);return g};
window.resetPeak=()=>{window.peak=0};
</script>`;
const srv = http.createServer((req, res) => {
  const h = { 'Content-Security-Policy': csp };
  if (req.url === '/') { res.writeHead(200, { ...h, 'Content-Type': 'text/html' }); return res.end(page); }
  if (req.url === '/audio.js') { res.writeHead(200, { ...h, 'Content-Type': 'text/javascript' }); return res.end(audioJS); }
  if (req.url === '/media') {
    const size = fs.statSync(file).size, m = /bytes=(\d+)-(\d*)/.exec(req.headers.range || '');
    const a = m ? +m[1] : 0, b = m && m[2] ? Math.min(+m[2], size - 1) : size - 1;
    res.writeHead(m ? 206 : 200, { 'Content-Type': file.endsWith('.mp4') ? 'video/mp4' : 'video/x-matroska', 'Accept-Ranges': 'bytes', 'Content-Length': b - a + 1, ...(m ? { 'Content-Range': `bytes ${a}-${b}/${size}` } : {}) });
    return fs.createReadStream(file, { start: a, end: b }).pipe(res);
  }
  res.writeHead(404).end();
});
await new Promise(r => srv.listen(0, '127.0.0.1', r));
const port = srv.address().port, dbg = 9400 + Math.floor(Math.random() * 400);
process.env.CDP_PORT = dbg;
const { connect } = await import('./cdp.mjs');
const chrome = spawn('chromium', ['--headless=new', '--no-sandbox', `--remote-debugging-port=${dbg}`, '--autoplay-policy=no-user-gesture-required', 'about:blank'], { stdio: 'ignore' });
let fail = 0;
const check = (ok, msg) => { console.log((ok ? 'ok   ' : 'FAIL ') + msg); if (!ok) fail++; };
try {
  for (let i = 0; i < 50; i++) { try { await fetch(`http://127.0.0.1:${dbg}/json/version`); break; } catch (e) { await new Promise(r => setTimeout(r, 200)); } }
  const c = await connect();
  await c.goto(`http://127.0.0.1:${port}/`);
  await c.until('document.readyState==="complete"');
  const why = await c.ev(`(async()=>{const v=document.getElementById('v');await new Promise(r=>{v.onloadedmetadata=r;v.load()});window.h=await PFAudio.attach(v,m=>console.error(m));v.muted=false;v.volume=1;await v.play();return 'attached'})().catch(e=>'ERR '+e.message)`);
  check(why === 'attached', 'attach: ' + why);
  await c.wait(3000);
  const t1 = await c.ev('document.getElementById("v").currentTime');
  const p1 = await c.ev('window.peak');
  check(t1 > 1.5, `video advanced to ${t1.toFixed(2)} s`);
  check(p1 > 0.03, `sound after start, peak ${p1.toFixed(3)}`);
  await c.ev('window.resetPeak();document.getElementById("v").currentTime=10');
  await c.wait(3000);
  const p2 = await c.ev('window.peak'), t2 = await c.ev('document.getElementById("v").currentTime');
  check(t2 > 11, `video after seek at ${t2.toFixed(2)} s`);
  check(p2 > 0.03, `sound after seek, peak ${p2.toFixed(3)}`);
  await c.ev('document.getElementById("v").pause()');
  await c.wait(600); await c.ev('window.resetPeak()'); await c.wait(1500);
  const p3 = await c.ev('window.peak');
  check(p3 < 0.01, `silent when paused, peak ${p3.toFixed(3)}`);
  await c.ev('window.h.dispose()');
  if (c.logs.length) console.log(c.logs.join('\n'));
  c.close();
} catch (e) { console.log('FAIL ' + e.message); fail++; }
chrome.kill(); srv.close();
process.exit(fail ? 1 : 0);

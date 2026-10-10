// Opens the real /room-test page (roomtest.html) in two headless Chromium tabs against the real room channel (room.go, started from `go test` as TestRoomServeForJS, plain HTTP on loopback)
// and checks: a room is created and its code shown, the second tab joins and both list each other, the WebRTC data channel connects directly and measures a round trip, the box relay
// measures one too, and a tab leaving is noticed. It says nothing about a real phone on the Orbic's Wi-Fi: that is the point of the page. Usage: node room-test.mjs   (Node 22, chromium on the PATH or CHROMIUM=/path)   Exit code 1 if anything fails.
import { spawn } from 'node:child_process';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
const here = path.dirname(fileURLToPath(import.meta.url));
const root = path.join(here, '../..');
process.env.CDP_PORT = process.env.CDP_PORT || String(9300 + Math.floor(Math.random() * 500));
const { connect } = await import(path.join(here, 'cdp.mjs'));

const go = spawn('go', ['test', '-count=1', '-run', 'TestRoomServeForJS', '-v', '.'], { cwd: root, env: { ...process.env, ROOM_SERVE: '1' }, stdio: ['ignore', 'pipe', 'inherit'] });
const info = await new Promise((resolve, reject) => {
  let buf = '';
  go.stdout.on('data', d => { buf += d; const line = buf.split('\n').find(l => l.startsWith('{')); if (line) resolve(JSON.parse(line)); });
  go.on('exit', c => reject(new Error('go test ended early, code ' + c + '\n' + buf)));
});
const fails = [];
const check = (name, ok, got) => { console.log((ok ? 'ok   ' : 'FAIL ') + name + (ok ? '' : '  got: ' + JSON.stringify(got))); if (!ok) fails.push(name); };

const prof = fs.mkdtempSync(path.join(os.tmpdir(), 'room-test-'));
const cr = spawn(process.env.CHROMIUM || 'chromium', ['--headless=new', '--no-sandbox', '--disable-gpu', '--remote-debugging-port=' + process.env.CDP_PORT, '--user-data-dir=' + prof, '--disable-background-networking', '--disable-features=WebRtcHideLocalIpsWithMdns', 'about:blank'], { stdio: 'ignore', detached: true });
const exited = new Promise(r => cr.once('exit', r));
const done = async code => {
  try { await fetch(info.url + '/quit'); } catch (e) { /* already gone */ }
  try { process.kill(-cr.pid, 'SIGTERM'); } catch (e) { /* already gone */ }
  await Promise.race([exited, new Promise(r => setTimeout(r, 3000))]);
  await new Promise(r => setTimeout(r, 500));
  try { process.kill(-cr.pid, 'SIGKILL'); } catch (e) { /* none left */ }
  try { fs.rmSync(prof, { recursive: true, force: true, maxRetries: 5, retryDelay: 200 }); } catch (e) { /* a temp directory */ }
  process.exit(code);
};
for (let i = 0; ; i++) { try { await fetch(`http://127.0.0.1:${process.env.CDP_PORT}/json/version`); break; } catch (e) { if (i > 50) { console.error('chromium did not start'); done(2); } await new Promise(r => setTimeout(r, 200)); } }

const a = await connect(), b = await connect();
await a.goto(info.url + '/room-test'); await b.goto(info.url + '/room-test');
await a.until(`!!document.querySelector('#mk')`); await b.until(`!!document.querySelector('#mk')`);
await a.ev(`document.querySelector('#nm').value='TV';document.querySelector('#mk').click()`);
check('a room is created and its code shown', await a.until(`/^[A-Z]{4}$/.test(document.querySelector('#code').textContent)`), await a.ev(`document.querySelector('#code').textContent`));
const code = await a.ev(`document.querySelector('#code').textContent`);
await b.ev(`document.querySelector('#nm').value='Pixel';document.querySelector('#cd').value=${JSON.stringify(code)};document.querySelector('#jn').click()`);
check('the second tab joins the same room', await b.until(`document.querySelector('#code').textContent===${JSON.stringify(code)}`), null);
check('each lists the other', await a.until(`document.querySelector('#peers').textContent.includes('Pixel')`) && await b.until(`document.querySelector('#peers').textContent.includes('TV')`), await a.ev(`document.querySelector('#peers').textContent`));
const rep = async c => JSON.parse(await c.ev(`document.querySelector('#rep').textContent`));
check('the data channel connects directly', await b.until(`JSON.parse(document.querySelector('#rep').textContent).peers.some(p=>p.state==='connected')`, 15000), await rep(b));
check('a direct round trip is measured', await b.until(`JSON.parse(document.querySelector('#rep').textContent).peers.some(p=>p.direct&&p.direct.med>=0)`, 15000), await rep(b));
check('a round trip through the box is measured', await b.until(`JSON.parse(document.querySelector('#rep').textContent).peers.some(p=>p.viaBox&&p.viaBox.med>=0)`, 15000), await rep(b));
const r = await rep(b);
console.log('     ', JSON.stringify(r.peers.map(p => ({ state: p.state, connectMs: p.connectMs, pair: p.pair, candidates: p.candidates, direct: p.direct, viaBox: p.viaBox }))));
await b.ev(`location.href='about:blank'`);
check('a tab leaving is noticed', await a.until(`!document.querySelector('#peers').textContent.includes('Pixel')`, 8000), await a.ev(`document.querySelector('#peers').textContent`));
for (const [n, c] of [['a', a], ['b', b]]) if (c.logs.length) console.log('     ' + n + ' console:', c.logs.slice(0, 5));
console.log(fails.length ? '\n' + fails.length + ' FAILED' : '\nall passed');
done(fails.length ? 1 : 0);

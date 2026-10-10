// Drives the browser's net shim (btclient/net-shim.js) against the real multiplexed bridge (btmux.go): the Go side is started from `go test` (TestMuxServeForJS) with made-up peers on
// 127.0.0.1, so no box, tunnel or internet is involved. Checks that many peers share ONE WebSocket, bytes stay with their own stream, a peer ending or refused is reported, closing
// one stream leaves the others, and the socket closes when the last peer is gone and reopens for the next. Needs `npm ci` in btclient/ (for streamx). Node 22 (global WebSocket).
// Usage: node mux-test.mjs   (about 25 s, mostly waiting for the idle close and the retry pause)   Exit code 1 if anything fails.
import { spawn } from 'node:child_process';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import crypto from 'node:crypto';
const here = path.dirname(fileURLToPath(import.meta.url));
const root = path.join(here, '../..');

const go = spawn('go', ['test', '-count=1', '-run', 'TestMuxServeForJS', '-v', '.'], { cwd: root, env: { ...process.env, MUX_SERVE: '1' }, stdio: ['ignore', 'pipe', 'inherit'] });
const info = await new Promise((resolve, reject) => {
  let buf = '';
  go.stdout.on('data', d => { buf += d; const line = buf.split('\n').find(l => l.startsWith('{')); if (line) resolve(JSON.parse(line)); });
  go.on('exit', c => reject(new Error('go test ended early, code ' + c + '\n' + buf)));
});
globalThis.BT_BRIDGE = info.url.replace(/^http/, 'ws') + '/api/bt/mux';
const { connect } = await import(path.join(root, 'btclient/net-shim.js'));

const fails = [];
const check = (name, ok, got) => { console.log((ok ? 'ok   ' : 'FAIL ') + name + (ok ? '' : '  got: ' + JSON.stringify(got))); if (!ok) fails.push(name); };
const stats = async () => (await fetch(info.url + '/stats')).json();
const sleep = ms => new Promise(r => setTimeout(r, ms));
const addr = a => { const [host, port] = a.split(':'); return { host, port: +port }; };
const until = async (f, ms = 5000) => { for (let t = 0; t < ms; t += 50) { if (await f()) return true; await sleep(50); } return false; };

// connect() and collect everything it receives
function peer(a) {
  const s = connect(addr(a)), r = { s, got: [], len: 0, connected: false, ended: false, err: null };
  s.on('connect', () => { r.connected = true; });
  s.on('data', d => { r.got.push(Buffer.from(d)); r.len += d.length; });
  s.on('end', () => { r.ended = true; });
  s.on('error', e => { r.err = e; });
  return r;
}
const bytes = r => Buffer.concat(r.got);

try {
  // two echo peers at once, with different data, on one socket
  const A = peer(info.echoA), B = peer(info.echoB);
  const ma = crypto.randomBytes(50000), mb = crypto.randomBytes(30000);
  await until(() => A.connected && B.connected);
  check('both peers report connect', A.connected && B.connected);
  A.s.write(ma); B.s.write(mb);
  await until(() => A.len >= ma.length && B.len >= mb.length);
  check('peer A gets back exactly what it sent', bytes(A).equals(ma), A.len);
  check('peer B gets back exactly what it sent', bytes(B).equals(mb), B.len);
  let st = await stats();
  check('two peers share one WebSocket', st.muxes === 1 && st.conns === 2, st);

  // a peer that says goodbye and hangs up
  const Y = peer(info.bye);
  await until(() => Y.ended);
  check('a peer ending is delivered, then the stream ends', bytes(Y).toString() === 'bye' && Y.ended, [bytes(Y).toString(), Y.ended]);

  // a peer the box did not hand out
  const X = peer(info.offList);
  await until(() => X.err);
  check('a refused peer is an error on its own stream', X.err && /bridge connection failed/.test(X.err.message), X.err && X.err.message);
  check('the other peers are untouched by it', !A.err && !B.err);

  // closing one leaves the other
  A.s.destroy();
  await until(async () => (await stats()).conns === 1);
  B.s.write(Buffer.from('still here'));
  await until(() => B.len >= mb.length + 10);
  check('closing one stream frees its slot and the other carries on', bytes(B).subarray(mb.length).toString() === 'still here', bytes(B).subarray(mb.length).toString());
  st = await stats();
  check('still one WebSocket', st.muxes === 1 && st.conns === 1, st);

  // the socket goes when the last peer does, and comes back for the next
  B.s.destroy();
  await until(async () => (await stats()).conns === 0);
  check('no peers left, no slots held', (await stats()).conns === 0);
  check('the WebSocket closes when idle', await until(async () => (await stats()).muxes === 0, 15000), await stats());
  const C = peer(info.echoA);
  C.s.write(Buffer.from('again'));
  await until(() => C.len >= 5);
  check('a later peer opens a new WebSocket and works', bytes(C).toString() === 'again' && (await stats()).muxes === 1, [bytes(C).toString(), await stats()]);
  C.s.destroy();

  // the box refusing the socket: peers fail, and new ones fail at once for a few seconds instead of each opening a socket
  await until(async () => (await stats()).muxes === 0, 15000);
  const good = globalThis.BT_BRIDGE;
  globalThis.BT_BRIDGE = good.replace(/\/api\/bt\/mux$/, '/nothing-here');
  const R1 = peer(info.echoA);
  await until(() => R1.err);
  check('a refused WebSocket fails the peer', R1.err && /bridge connection failed/.test(R1.err.message), R1.err && R1.err.message);
  globalThis.BT_BRIDGE = good;
  const R2 = peer(info.echoA);
  await sleep(100);
  check('right after a refusal a new peer fails at once without trying', R2.err && /bridge unavailable/.test(R2.err.message) && (await stats()).muxes === 0, [R2.err && R2.err.message, await stats()]);
  await sleep(5000);
  const R3 = peer(info.echoA);
  R3.s.write(Buffer.from('back'));
  await until(() => R3.len >= 4);
  check('after the pause it connects again', bytes(R3).toString() === 'back', bytes(R3).toString());
  R3.s.destroy();
} catch (e) {
  console.error(e);
  fails.push('exception');
}
await fetch(info.url + '/quit').catch(() => {});
await sleep(300);
go.kill();
console.log(fails.length ? `\n${fails.length} failed` : '\nall passed');
process.exit(fails.length ? 1 : 0);

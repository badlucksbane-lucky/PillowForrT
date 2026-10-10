// Tests the room client (roomclient/room.js, the library behind /room-test) in headless Chromium against the real room channel (room.go, started from `go test` as TestRoomServeForJS, plain HTTP on
// loopback, with a 4 s grace period). Checks: create and join; a direct WebRTC link; every kind of message over it (string, object, unordered, binary); round trips; the box relay as the
// fallback (a third page with WebRTC off) including binary and its size limit; a dropped socket that reconnects to the same place with the direct link untouched; a place that expires and is
// re-joined afresh; a reload that returns to the same place; leaving. It says nothing about a phone on the Orbic's Wi-Fi: that is what /room-test is for.
// Usage: node room-test.mjs   (Node 22, chromium on the PATH or CHROMIUM=/path; about 40 s)   Exit code 1 if anything fails.
import { spawn } from 'node:child_process';
import fs from 'node:fs';
import os from 'node:os';
import { createRequire } from 'node:module';
import http from 'node:http';
import net from 'node:net';
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
// optional: with jsqr and pngjs available (JSQR_DIR, see qr-test.mjs) the QR code on the page is photographed and decoded
let jsQR = null, PNG = null;
try { const req = createRequire(path.join(process.env.JSQR_DIR || here, 'x.js')); jsQR = req('jsqr'); PNG = req('pngjs').PNG; } catch (e) { /* the scan check is skipped */ }
const fails = [];
const check = (name, ok, got) => { console.log((ok ? 'ok   ' : 'FAIL ') + name + (ok ? '' : '  got: ' + JSON.stringify(got))); if (!ok) fails.push(name); };

const prof = fs.mkdtempSync(path.join(os.tmpdir(), 'room-test-'));
const cr = spawn(process.env.CHROMIUM || 'chromium', ['--headless=new', '--no-sandbox', '--disable-gpu', '--remote-debugging-port=' + process.env.CDP_PORT, '--user-data-dir=' + prof, '--disable-background-networking', '--disable-features=WebRtcHideLocalIpsWithMdns', '--disable-background-timer-throttling', '--disable-renderer-backgrounding', 'about:blank'], { stdio: 'ignore', detached: true });
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

const J = JSON.stringify;
const sleep = ms => new Promise(r => setTimeout(r, ms));
// listeners every page gets: what arrived, and what happened, as plain data
const HOOK = r => `window.T={got:[],ev:[]};(${r}).on('message',m=>T.got.push({from:m.from,via:m.via,data:m.data instanceof ArrayBuffer?{bin:[...new Uint8Array(m.data)].slice(0,6),len:m.data.byteLength}:m.data}))
  .on('peerleft',p=>T.ev.push('left:'+p.id)).on('peer',p=>T.ev.push('peer:'+p.id)).on('ready',x=>T.ev.push('ready:'+x.id+':'+x.resumed)).on('status',s=>T.ev.push('status:'+s));1`;
const page = async () => { const c = await connect(); await c.goto(info.url + '/room-test'); await c.until(`!!document.querySelector('#mk')`); return c; };
const peerState = (c, id) => c.ev(`(window.room.peers.get(${J(id)})||{}).state||null`);
const waitState = (c, id, st, ms = 15000) => c.until(`(window.room.peers.get(${J(id)})||{}).state===${J(st)}`, ms);
const got = c => c.ev(`J=JSON.stringify;J(T.got)`).then(JSON.parse);

const a = await page(), b = await page();
await a.ev(`document.querySelector('#nm').value='A';document.querySelector('#mk').click();1`);
check('a room is created', await a.until(`window.room&&room.status==='online'&&/^[A-Z]{4}$/.test(room.code)`), null);
const code = await a.ev(`room.code`), aId = await a.ev(`room.id`);
const jl = await a.ev(`JSON.stringify([
  Room.joinLink({protocol:'https:',host:'pillowforrt.lan',hostname:'pillowforrt.lan',port:''},'192.168.1.254','/room-test','ABCD'),
  Room.joinLink({protocol:'https:',host:'pillowforrt.lan:3129',hostname:'pillowforrt.lan',port:'3129'},'192.168.1.254','/room-test','ABCD'),
  Room.joinLink({protocol:'https:',host:'192.168.1.254',hostname:'192.168.1.254',port:''},'10.0.0.5','/room-test','ABCD'),
  Room.joinLink({protocol:'https:',host:'pillowforrt.lan',hostname:'pillowforrt.lan',port:''},'','/room-test','ABCD'),
  Room.joinLink({protocol:'http:',host:'localhost:8080',hostname:'localhost',port:'8080'},'192.168.1.254','/x','WXYZ')])`).then(JSON.parse);
check('the join link uses the box LAN address when the page was opened by name (not when by IP, localhost, or with no address known)',
  jl[0] === 'https://192.168.1.254/room-test#ABCD' && jl[1] === 'https://192.168.1.254:3129/room-test#ABCD' && jl[2] === 'https://192.168.1.254/room-test#ABCD' && jl[3] === 'https://pillowforrt.lan/room-test#ABCD' && jl[4] === 'http://localhost:8080/x#WXYZ', jl);
check('the page shows a QR code, a copy button, and the room link', await a.until(`!!document.querySelector('#qr #tile svg')&&!!document.querySelector('#copylink')`, 3000) && (await a.ev(`room.joinUrl()`)).endsWith('/room-test#' + code), await a.ev(`room.joinUrl()`));
if (jsQR) {
  const r = await a.ev(`(()=>{const b=document.querySelector('#tile svg').getBoundingClientRect();return {x:b.x+scrollX,y:b.y+scrollY,w:b.width,h:b.height}})()`);
  const shot = await a.send('Page.captureScreenshot', { format: 'png', clip: { x: r.x, y: r.y, width: r.w, height: r.h, scale: 3 } });
  const png = PNG.sync.read(Buffer.from(shot.data, 'base64')), res = jsQR(new Uint8ClampedArray(png.data), png.width, png.height);
  check('the QR code on the page decodes to the join link', !!res && res.data === await a.ev(`room.joinUrl()`), res && res.data);
} else console.log('skip  QR scan check (jsqr not found; set JSQR_DIR)');
await a.ev(HOOK('window.room'));
await b.ev(`document.querySelector('#nm').value='B';document.querySelector('#cd').value=${J(code)};document.querySelector('#jn').click();1`);
check('the second page joins', await b.until(`window.room&&room.status==='online'&&room.code===${J(code)}`), null);
await b.ev(HOOK('window.room'));
const bId = await b.ev(`room.id`);
check('each lists the other', await a.until(`room.peers.has(${J(bId)})`) && await b.until(`room.peers.has(${J(aId)})`), null);
check('the link becomes direct on both sides', await waitState(a, bId, 'direct') && await waitState(b, aId, 'direct'), [await peerState(a, bId), await peerState(b, aId)]);

const e = await connect(); await e.goto(info.url + '/room-test#' + code); // a scanned link: joins at once, no tapping
check('opening the join link joins the room at once', await e.until(`window.room&&room.status==='online'&&room.code===${J(code)}`, 8000), await e.ev(`window.room&&[room.status,room.code]`));
check('and the code is dropped from the address', await e.ev(`location.hash===''`), await e.ev(`location.href`));
await e.ev(`room.leave();1`); e.close();

const f = await connect(); await f.goto(info.url + '/room-test'); await f.until(`!!document.querySelector('#mk')`); // a tab already on the page only gets a new fragment: no reload
await f.ev(`document.querySelector('#mk').click();1`);
await f.until(`window.room&&room.status==='online'`);
const codeX = await f.ev(`room.code`);
await f.ev(`location.hash='#'+${J(code)};1`);
check('a link opened on a page that is already in another room switches rooms', codeX !== code && await f.until(`window.room&&room.code===${J(code)}&&room.status==='online'`, 8000), [codeX, await f.ev(`window.room&&window.room.code`)]);
await f.ev(`room.leave();1`); f.close();

// messages over the direct link
await b.ev(`room.send(${J(aId)},'hello');room.send(${J(aId)},{x:[1,2,3]});room.send(${J(aId)},'fast',{unreliable:true});room.send(${J(aId)},new Uint8Array([9,8,7,6,5,4,3,2,1,0]).buffer)`);
await a.until(`T.got.length>=4`, 5000);
const g1 = await got(a);
check('a string, an object, an unordered message and binary arrive directly', g1.length === 4 && g1.every(m => m.via === 'direct' && m.from === bId) && g1.some(m => m.data === 'hello') && g1.some(m => m.data?.x?.[2] === 3) && g1.some(m => m.data === 'fast') && g1.some(m => m.data?.len === 10 && m.data.bin[0] === 9), g1);
check('send says which way it went', await b.ev(`room.send(${J(aId)},'x')`) === 'direct', null);
for (const via of ['direct', 'relay', 'box']) {
  const r = await a.ev(`room.rtt(${J(bId)},${J(via)},5)`);
  check('round trip ' + via + ' measured (5 of 5)', r.n === 5 && r.lost === 0 && r.med !== null, r);
}

// the box as the fallback: a third page with WebRTC off
const c = await page();
await c.ev(`window.r2=new Room({name:'C',code:${J(code)},rtc:false,persist:false});1`);
await c.until(`r2.status==='online'`);
await c.ev(HOOK('window.r2'));
const cId = await c.ev(`r2.id`);
check('a page with WebRTC off is listed and uses the relay', await a.until(`room.peers.has(${J(cId)})`) && await c.until(`r2.peers.size===2`) && await c.ev(`r2.peers.get(${J(aId)}).state`) === 'relay', null);
const via = await a.ev(`[room.send(${J(cId)},{r:1}),room.send(${J(cId)},new Uint8Array(4000).fill(7).buffer)]`);
check('send to it goes through the box', via[0] === 'relay' && via[1] === 'relay', via);
await c.until(`T.got.length>=2`, 5000);
const g2 = await got(c);
check('string and 4000 bytes of binary arrive through the box', g2.length === 2 && g2.every(m => m.via === 'relay') && g2.some(m => m.data?.r === 1) && g2.some(m => m.data?.len === 4000 && m.data.bin[0] === 7), g2);
check('binary over the relay is limited', await a.ev(`try{room.send(${J(cId)},new Uint8Array(9000).buffer);'sent'}catch(e){'refused'}`) === 'refused', null);
await c.ev(`r2.send(${J(aId)},'back');1`);
check('and it can answer', await a.until(`T.got.some(m=>m.data==='back'&&m.via==='relay')`, 5000), null);
const rr = await a.ev(`room.rtt(${J(cId)},'relay',5)`);
check('a relay round trip to it is measured', rr.n === 5 && rr.lost === 0, rr);
await c.ev(`r2.leave();1`);
check('leaving is seen at once', await a.until(`T.ev.includes('left:${cId}')`, 3000), await a.ev(`T.ev`));
await c.ev(`location.href='about:blank'`);

// a dropped socket: back to the same place, and the direct link is untouched
await a.ev(`T.ev.length=0;room._ws.close();1`);
check('a dropped socket reconnects to the same place', await a.until(`T.ev.some(e=>e==='ready:${aId}:true')`, 8000), await a.ev(`T.ev`));
check('the direct link stayed up through it', await peerState(a, bId) === 'direct' && await peerState(b, aId) === 'direct', null);
check('the other page never saw it leave', !(await b.ev(`T.ev`)).includes('left:' + aId), await b.ev(`T.ev`));
await a.ev(`T.got.length=0;1`); await b.ev(`room.send(${J(aId)},'still here');1`);
check('messages still flow', await a.until(`T.got.some(m=>m.data==='still here')`, 4000), null);

// a place that expires: away longer than the grace period, then joins afresh
await a.ev(`T.ev.length=0;window._r=room._retry;room._retry=function(){};room._ws.close();1`);
check('the other page is told once the grace period ends', await b.until(`T.ev.includes('left:${aId}')`, 9000), await b.ev(`T.ev`));
await a.ev(`room._retry=window._r;room._retry(true);1`);
check('the returning page joins afresh with a new id', await a.until(`T.ev.some(e=>/^ready:p\\d+:false$/.test(e))`, 8000), await a.ev(`T.ev`));
const a2 = await a.ev(`room.id`);
check('the new id differs', a2 !== aId, [a2, aId]);
check('and the link is direct again', await waitState(a, bId, 'direct') && await waitState(b, a2, 'direct'), [await peerState(a, bId), await peerState(b, a2)]);

// a reload comes back to the same place
await b.ev(`T.ev.length=0;1`);
await a.ev(`T.ev.length=0;1`);
await b.send('Page.reload', {});
check('a reloaded page returns to its place', await b.until(`window.room&&room.status==='online'&&room.id===${J(bId)}`, 10000), await b.ev(`window.room&&room.id`));
await b.ev(HOOK('window.room'));
check('and the link is direct again', await waitState(b, a2, 'direct', 20000) && await waitState(a, bId, 'direct', 20000), [await peerState(b, a2), await peerState(a, bId)]);
await b.ev(`document.querySelector('#leave').click();1`);
check('leaving is seen at once by the other page', await a.until(`!room.peers.has(${J(bId)})`, 3000), null);

// a socket that hangs (a phone's Wi-Fi was asleep when it connected): abandoned after connectTimeout, then recovered once a real address works
const black = net.createServer(() => {}); // accepts and never answers the upgrade
await new Promise(r => black.listen(0, '127.0.0.1', r));
const d = await page();
await d.ev(`window.r3=new Room({name:'D',code:'',persist:false,connectTimeout:1200,url:'ws://127.0.0.1:${black.address().port}/api/room'});1`);
await d.until(`r3.attempts>=3`, 9000);
check('a hung connection is abandoned and tried again', await d.ev(`r3.attempts>=3&&r3.status!=='online'`), await d.ev(`[r3.attempts,r3.status]`));
await d.ev(`r3.url=(location.protocol==='https:'?'wss://':'ws://')+location.host+'/api/room';1`);
check('and it connects once the address works', await d.until(`r3.status==='online'&&/^[A-Z]{4}$/.test(r3.code)`, 8000), await d.ev(`[r3.attempts,r3.status]`));
await d.ev(`r3.leave();1`); black.close();

// a link from another site (a camera app, a message): the session cookie is SameSite=Strict, so it is left off that navigation. localhost and 127.0.0.1 are different sites.
const other = http.createServer((q, r) => { r.writeHead(200, { 'content-type': 'text/html' }); r.end(`<a id=g href="${info.url}/guarded#${code}">g</a> <a id=n href="${info.url}/nobounce#${code}">n</a>`); });
await new Promise(r => other.listen(0, r));
const otherUrl = `http://localhost:${other.address().port}/`;
const g = await connect();
await g.goto(info.url + '/fake-login'); await g.until(`document.body.innerText.includes('signed in')`, 5000);
await g.goto(otherUrl); await g.until(`!!document.getElementById('n')`, 5000);
await g.ev(`document.getElementById('n').click();1`); await sleep(1500);
check('control: a link from another site arrives WITHOUT the cookie (so without the bounce it lands on the login page)', await g.ev(`location.pathname`) === '/login', await g.ev(`location.href`));
await g.goto(otherUrl); await g.until(`!!document.getElementById('g')`, 5000);
await g.ev(`document.getElementById('g').click();1`);
check('with the bounce the same kind of link gets the page and joins the room', await g.until(`window.room&&window.room.status==='online'&&window.room.code===${J(code)}`, 10000), await g.ev(`location.href`));
check('and ends on the page itself with the code and the bounce marker dropped from the address', await g.ev(`location.pathname`) === '/guarded' && await g.ev(`location.search===''&&location.hash===''`), await g.ev(`location.href`));
await g.ev(`window.room&&window.room.leave&&window.room.leave();1`); g.close(); other.close();

for (const [n, p] of [['a', a], ['b', b]]) { const l = p.logs.filter(x => !/favicon/.test(x)); if (l.length) console.log('     ' + n + ' console:', l.slice(0, 5)); }
console.log(fails.length ? '\n' + fails.length + ' FAILED' : '\nall passed');
done(fails.length ? 1 : 0);

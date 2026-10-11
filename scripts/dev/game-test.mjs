// Tests the game shell (play.html, pad.html, gameclient/*.js) in headless Chromium against the real room channel (room.go, started from `go test` as TestRoomServeForJS): a screen page and
// phone-sized controller pages join by code, the screen picks a game and starts it, the controllers build the widgets the game asks for and their input arrives (stick, buttons, pointer,
// tilt, a private panel), stale and lost input is handled, a full room turns people away, and a controller that vanishes pauses the game and gets the same place back.
// Loopback only: it says nothing about a real phone (that is what the phone pass is for). Usage: node game-test.mjs   (Node 22, chromium on the PATH or CHROMIUM=/path)   Exit code 1 on failure.
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
const T0 = Date.now();
const check = (name, ok, got) => { console.log(String(Math.round((Date.now() - T0) / 1000)).padStart(3) + 's ' + (ok ? 'ok   ' : 'FAIL ') + name + (ok ? '' : '  got: ' + JSON.stringify(got))); if (!ok) fails.push(name); };

const prof = fs.mkdtempSync(path.join(os.tmpdir(), 'game-test-'));
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
const pads = [];
const padPage = async (name, code) => {
  const c = await connect(); await c.mobile(); pads.push(c);
  await c.goto(info.url + '/pad' + (code ? '#' + code : '')); await c.until(`document.readyState==='complete'&&!!window.Pad`); // the page fills in the saved name when its script runs
  await c.ev(`document.querySelector('#nm').value=${J(name)};window.buzz=[];navigator.vibrate=ms=>{buzz.push(ms);return true};1`);
  return c;
};
// a tab behind the others never answers a touch, so each touch brings its page to the front first
const touch = async (c, type, pts) => { await c.send('Page.bringToFront'); await c.send('Input.dispatchTouchEvent', { type, touchPoints: pts }); };
const center = (c, sel) => c.ev(`(()=>{const b=document.querySelector(${J(sel)}).getBoundingClientRect();return {x:b.x+b.width/2,y:b.y+b.height/2,w:b.width,h:b.height}})()`);
const pl = (s, i = 0) => s.ev(`JSON.stringify([...gc.players.values()][${i}]||null)`).then(JSON.parse);

// the screen
const s = await connect(); await s.desktop(); await s.goto(info.url + '/play');
check('the screen creates a room and shows its code', await s.until(`window.gc&&gc.room.status==='online'&&/^[A-Z]{4}$/.test(gc.room.code)&&document.querySelector('#code').textContent===gc.room.code`), null);
const code = await s.ev(`gc.room.code`);
check('it shows a QR code for the pad page', await s.until(`!!document.querySelector('#qr svg')`, 3000) && (await s.ev(`gc.joinUrl()`)).endsWith('/pad#' + code), await s.ev(`gc.joinUrl()`));
check('Start is off with no players and no game', await s.ev(`document.querySelector('#start').disabled`), null);

// a phone follows the link
const p1 = await padPage('Ann', code);
check('the link fills in the code and drops it from the address', await p1.ev(`document.querySelector('#cd').value`) === code && await p1.ev(`location.hash===''`), await p1.ev(`location.href`));
await p1.ev(`document.querySelector('#go').click();1`);
check('the screen lists the player with a slot and a colour', await s.until(`gc.players.size===1`) && (await pl(s)).name === 'Ann' && (await pl(s)).slot === 0, await pl(s));
check('the lobby tells the phone to look at the screen', await p1.until(`document.querySelector('.veil')&&!document.querySelector('.veil').hidden&&/screen/.test(document.querySelector('.veil').textContent)`, 5000), await p1.ev(`document.body.innerText`));
check('Start stays off until a game is picked', await s.ev(`document.querySelector('#start').disabled`), null);
await s.ev(`document.querySelector('#games button').click();1`);
check('picking a game and one player enables Start', await s.until(`!document.querySelector('#start').disabled`, 3000), null);
if (process.env.SHOTS) { await s.send('Page.bringToFront'); await s.shot('play-lobby'); } // SHOTS=dir keeps a few screenshots to look at
await s.ev(`document.querySelector('#start').click();1`);
check('the game starts and the lobby goes away', await s.until(`gc.state==='play'&&document.querySelector('#lobby').hidden`, 3000), await s.ev(`gc.state`));
check('the phone builds a stick and two buttons', await p1.until(`!!document.querySelector('.stick')&&document.querySelectorAll('.btn').length===2&&document.querySelector('.veil').hidden`, 5000), await p1.ev(`document.body.innerText`));
await p1.until(`pad.room.peers.get(pad.screen)&&pad.room.peers.get(pad.screen).state==='direct'`, 10000);

if (process.env.SHOTS) { await p1.send('Page.bringToFront'); await p1.shot('pad-portrait'); }
// stick
let c = await center(p1, '.stick');
await touch(p1, 'touchStart', [{ x: c.x + c.w * 0.45, y: c.y, id: 1 }]);
check('a stick pushed right arrives as x near 1', await s.until(`gc.players.values().next().value.stick.x>0.7`, 3000), await pl(s));
await touch(p1, 'touchMove', [{ x: c.x, y: c.y + c.h * 0.45, id: 1 }]);
check('then down: x near 0, y near 1', await s.until(`(p=>Math.abs(p.stick.x)<0.2&&p.stick.y>0.7)(gc.players.values().next().value)`, 3000), (await pl(s)).stick);
await touch(p1, 'touchEnd', []);
check('letting go returns the stick to zero', await s.until(`(p=>!p.stick.x&&!p.stick.y)(gc.players.values().next().value)`, 3000), (await pl(s)).stick);

// buttons and vibration
const bA = await center(p1, '.btn');
await touch(p1, 'touchStart', [{ x: bA.x, y: bA.y, id: 2 }]);
check('button A down arrives, and the phone buzzes back when the screen asks', await s.until(`gc.players.values().next().value.btn.A===true`, 3000) && await p1.until(`buzz.some(x=>x>=50)`, 3000), [await pl(s), await p1.ev(`buzz`)]);
await touch(p1, 'touchEnd', []);
check('button A up arrives', await s.until(`gc.players.values().next().value.btn.A===false`, 3000), (await pl(s)).btn);
// two touches at once: the stick held while a button is pressed
await touch(p1, 'touchStart', [{ x: c.x + c.w * 0.45, y: c.y, id: 1 }, { x: bA.x, y: bA.y, id: 2 }]);
check('a stick and a button work at the same time', await s.until(`(p=>p.stick.x>0.7&&p.btn.A)(gc.players.values().next().value)`, 3000), await pl(s));
await touch(p1, 'touchEnd', []);
await s.until(`(p=>!p.stick.x&&!p.btn.A)(gc.players.values().next().value)`, 3000);

// the private panel
const bB = (await p1.ev(`JSON.stringify([...document.querySelectorAll('.btn')].map(b=>{const r=b.getBoundingClientRect();return {x:r.x+r.width/2,y:r.y+r.height/2}}))`).then(JSON.parse))[1];
await touch(p1, 'touchStart', [{ x: bB.x, y: bB.y, id: 3 }]); await touch(p1, 'touchEnd', []);
check('button B opens a private panel on that phone', await p1.until(`!document.querySelector('.panel').hidden&&document.querySelectorAll('.pick').length===3`, 4000), await p1.ev(`document.body.innerText`));
const pk = await center(p1, '.pick:nth-of-type(3)'); // the first child is the title
await touch(p1, 'touchStart', [{ x: pk.x, y: pk.y, id: 4 }]); await touch(p1, 'touchEnd', []);
check('the choice reaches the game and the panel closes', await p1.until(`document.querySelector('.panel').hidden`, 4000) && await s.until(`1`) , null);

if (process.env.SHOTS) { await s.send('Page.bringToFront'); await s.shot('play-game'); }
// a second phone: separate slot, separate input
const p2 = await padPage('Bo', code); await p2.ev(`document.querySelector('#go').click();1`);
check('a second player gets the next slot and another colour', await s.until(`gc.players.size===2`) && (await pl(s, 1)).slot === 1 && (await pl(s, 1)).color !== (await pl(s, 0)).color, [await pl(s, 0), await pl(s, 1)]);
await p2.until(`!!document.querySelector('.stick')`, 5000);
const c2 = await center(p2, '.stick');
await touch(p2, 'touchStart', [{ x: c2.x - c2.w * 0.45, y: c2.y, id: 1 }]);
check("one player's stick does not move the other's", await s.until(`(a=>a[1].stick.x<-0.7&&a[0].stick.x===0)([...gc.players.values()])`, 3000), [await pl(s, 0), await pl(s, 1)]);
await touch(p2, 'touchEnd', []);

// stale and lost input
const id1 = (await pl(s, 0)).id;
await s.ev(`gc._msg({from:${J(id1)},data:{t:'in',k:'stick',s:900,x:1,y:0}});gc._msg({from:${J(id1)},data:{t:'in',k:'stick',s:800,x:-1,y:0}});1`);
check('an input that arrives out of order is ignored', await s.ev(`[...gc.players.values()][0].stick.x`) === 1, await pl(s));
await s.ev(`[...gc.players.values()][0].seen=performance.now()-1000;1`);
check('a stick that has gone quiet while held is let go', await s.until(`[...gc.players.values()][0].stick.x===0`, 2000), await pl(s));
await s.ev(`gc._msg({from:${J(id1)},data:{t:'hello',name:'Ann'}});1`);
await s.ev(`gc._msg({from:${J(id1)},data:{t:'in',k:'stick',s:1,x:1,y:0}});1`);
check('after a hello the input counters start over', await s.ev(`[...gc.players.values()][0].stick.x`) === 1, await pl(s));
await s.ev(`[...gc.players.values()][0].stick.x=0;1`);

// pointer and tilt, from a game registered by the test
await s.ev(`gc.stop();Games.register({id:'ptr',name:'Ptr',players:{min:1,max:2},orientation:'any',widgets:[{type:'pointer'},{type:'tilt'}],create(ctx){window.ev=[];return{onPointer(p,x,y,d){ev.push([+x.toFixed(2),+y.toFixed(2),d])},render(){}}}});gc.select('ptr');gc.start()`);
check('a pointer pad and a tilt button are built', await p1.until(`!!document.querySelector('.pointer')&&!!document.querySelector('.tiltbtn')`, 5000), await p1.ev(`document.body.innerText`));
const pp = await center(p1, '.pointer');
await touch(p1, 'touchStart', [{ x: pp.x - pp.w / 4, y: pp.y, id: 1 }]);
await touch(p1, 'touchEnd', []);
check('a pointer touch arrives as 0..1 coordinates, then a release', await s.until(`ev.length>=2&&ev[0][2]===true&&Math.abs(ev[0][0]-0.25)<0.05&&ev[ev.length-1][2]===false`, 3000), await s.ev(`ev`));
await p1.send('Page.bringToFront'); // a page behind the others has its timers held back, and input goes out on a timer
await p1.ev(`document.querySelector('.tiltbtn').click();1`);
await p1.until(`pad.st.tilt.on`, 3000); await sleep(300); // permission is asked first where the browser has it (iOS), so the listener starts a moment later
await p1.ev(`dispatchEvent(new DeviceOrientationEvent('deviceorientation',{beta:30,gamma:-12}));1`);
check('tilt arrives as beta and gamma', await s.until(`gc.players.values().next().value.tilt.b===30&&gc.players.values().next().value.tilt.g===-12`, 3000), (await pl(s)).tilt);

// a full room
await s.ev(`gc.stop();gc.select('ptr');1`);
await p2.ev(`pad.leave();1`);
await s.until(`gc.players.size===1`, 5000);
await s.ev(`Games.register({id:'solo',name:'Solo',players:{min:1,max:1},orientation:'portrait',widgets:[{type:'dpad'}],create(){return{render(){}}}});gc.select('solo');1`);
const p3 = await padPage('Cy', code); await p3.ev(`document.querySelector('#go').click();1`);
check('a controller that arrives when the game is full is told so', await p3.until(`/full/.test(document.querySelector('.veil').textContent)`, 6000) && (await s.ev(`gc.players.size`)) === 1, await p3.ev(`document.body.innerText`));
await p3.ev(`pad.leave();1`);
await s.ev(`gc.start()`);
check('a game that wants portrait says so on a landscape phone', true, null);
check('a d-pad is built for it', await p1.until(`!!document.querySelector('.stick.dpad')`, 5000), await p1.ev(`document.body.innerText`));

// Fort Pong with two real pages: the stick's vertical axis moves that player's paddle, A serves
await s.ev(`gc.stop();gc.select('fortpong');1`);
const q1 = p1, q2 = await padPage('Bo', code); // Ann (p1) is still in the room
await q2.ev(`document.querySelector('#go').click();1`);
check('two players enable Start for Fort Pong', await s.until(`gc.players.size===2&&gc.canStart()`, 8000), await s.ev(`[gc.players.size,gc.canStart()]`));
await s.ev(`gc.start()`);
check('the phones get a stick and one button', await q1.until(`!!document.querySelector('.stick')&&document.querySelectorAll('.btn').length===1`, 5000) && await q2.until(`!!document.querySelector('.stick')`, 5000), await q1.ev(`document.body.innerText`));
check('the game waits for the server', await s.ev(`gc.inst.s.phase==='serve'`), await s.ev(`gc.inst.s`));
await q2.until(`pad.room.peers.get(pad.screen)&&pad.room.peers.get(pad.screen).state==='direct'`, 10000); await q1.until(`pad.room.peers.get(pad.screen)&&pad.room.peers.get(pad.screen).state==='direct'`, 10000);
const side = async (c, p) => { const r = await center(c, '.stick'); return { r, p }; };
const sa = (await side(q1)).r, sb = (await side(q2)).r;
const py0 = await s.ev(`[...gc.inst.s.py]`);
// the screen tab is behind the phones' tabs here, and a hidden tab gets no animation frames, so the game is advanced by hand: half a second of play at 60 steps a second
const adv = n => s.ev(`for(let i=0;i<${n};i++)gc.inst.tick(1/60);1`);
await touch(q1, 'touchStart', [{ x: sa.x, y: sa.y + sa.h * 0.45, id: 1 }]);
await sleep(300); await adv(30);
check("pushing Ann's stick down moves her paddle down and not Bo's", await s.ev(`gc.inst.s.py[0]>${py0[0] + 40}&&gc.inst.s.py[1]===${py0[1]}`), await s.ev(`gc.inst.s.py`));
await touch(q1, 'touchEnd', []);
await touch(q2, 'touchStart', [{ x: sb.x, y: sb.y - sb.h * 0.45, id: 1 }]);
await sleep(300); await adv(30);
check("pushing Bo's stick up moves his paddle up", await s.ev(`gc.inst.s.py[1]<${py0[1] - 40}`), await s.ev(`gc.inst.s.py`));
await touch(q2, 'touchEnd', []);
const ba = await center(q2, '.btn'), ba1 = await center(q1, '.btn');
await touch(q2, 'touchStart', [{ x: ba.x, y: ba.y, id: 2 }]); await touch(q2, 'touchEnd', []);
await sleep(300);
check("the other player's A does not serve", await s.ev(`gc.inst.s.phase==='serve'`), await s.ev(`gc.inst.s.phase`));
await touch(q1, 'touchStart', [{ x: ba1.x, y: ba1.y, id: 2 }]); await touch(q1, 'touchEnd', []);
check("the server's A launches the ball", await s.until(`gc.inst.s.phase==='play'&&Math.abs(gc.inst.s.ball.vx)>200`, 3000), await s.ev(`gc.inst.s`));
const bx = await s.ev(`gc.inst.s.ball.x`); await adv(10);
check('the ball moves on the screen', await s.ev(`gc.inst.s.ball.x`) !== bx, await s.ev(`gc.inst.s.ball`));
if (process.env.SHOTS) { await s.send('Page.bringToFront'); await s.shot('pong'); }
await q2.ev(`pad.leave();1`);
check('a player who leaves ends the game', await s.until(`gc.state==='lobby'`, 8000), await s.ev(`gc.state`));
await s.until(`gc.players.size===1`, 5000);

// Sumo Push with two real pages: the stick pushes only your own disc, A dashes
await s.ev(`gc.select('sumopush');1`);
const r2 = await padPage('Cy', code); await r2.ev(`document.querySelector('#go').click();1`);
check('two players enable Start for Sumo Push', await s.until(`gc.players.size===2&&gc.canStart()`, 8000), await s.ev(`[gc.players.size,gc.canStart()]`));
await s.ev(`gc.start()`);
check('the phones get a stick and one button', await p1.until(`!!document.querySelector('.stick')&&document.querySelectorAll('.btn').length===1`, 5000) && await r2.until(`!!document.querySelector('.stick')&&document.querySelectorAll('.btn').length===1`, 5000), await r2.ev(`document.body.innerText`));
await p1.until(`pad.room.peers.get(pad.screen)&&pad.room.peers.get(pad.screen).state==='direct'`, 10000); await r2.until(`pad.room.peers.get(pad.screen)&&pad.room.peers.get(pad.screen).state==='direct'`, 10000);
await adv(200);
check('it counts down and then plays', await s.ev(`gc.inst.s.phase==='play'&&gc.inst.s.bodies.length===2`), await s.ev(`gc.inst.s.phase`));
const sc = await center(p1, '.stick');
const bx0 = await s.ev(`gc.inst.s.bodies.map(b=>[b.x,b.y])`);
await touch(p1, 'touchStart', [{ x: sc.x + sc.w * 0.45, y: sc.y, id: 1 }]);
await sleep(300); await adv(20);
check("pushing Ann's stick right moves her disc right and not Cy's", await s.ev(`(b=>b[0].x>${bx0[0][0]}+5&&b[1].x===${bx0[1][0]}&&b[1].y===${bx0[1][1]})(gc.inst.s.bodies)`), await s.ev(`gc.inst.s.bodies.map(b=>[b.x,b.y])`));
await touch(p1, 'touchEnd', []);
const bd = await center(p1, '.btn');
await touch(p1, 'touchStart', [{ x: bd.x, y: bd.y, id: 2 }]); await touch(p1, 'touchEnd', []);
check('A dashes: a cooldown starts on her disc', await s.until(`gc.inst.s.bodies[0].cd>1`, 3000), await s.ev(`gc.inst.s.bodies[0]`));
if (process.env.SHOTS) { await s.ev(`gc.inst.s.bodies.forEach((b,i)=>{b.x=330+i*80;b.y=225});gc.inst.tick(0.01);1`); await s.send('Page.bringToFront'); await sleep(200); await s.shot('sumo'); }
await r2.ev(`pad.leave();1`);
check('a game with fewer than two players ends', await s.until(`gc.state==='lobby'`, 8000), await s.ev(`gc.state`));
await s.until(`gc.players.size===1`, 5000);

// Imposter with three real pages: secrets arrive as private panels, answers go back, a rebuilt or reloaded phone keeps its panel
await s.ev(`gc.select('imposter');1`);
const ia = await padPage('Bo', code), ib = await padPage('Cy', code);
await ia.ev(`document.querySelector('#go').click();1`); await ib.ev(`document.querySelector('#go').click();1`);
check('three players enable Start for Imposter', await s.until(`gc.players.size===3&&gc.canStart()`, 10000), await s.ev(`[gc.players.size,gc.canStart()]`));
await s.ev(`gc.start()`);
const trio = [p1, ia, ib];
const tapPick = async (c, n) => { const r = await c.ev(`(()=>{const b=document.querySelectorAll('.pick')[${n}].getBoundingClientRect();return {x:b.x+b.width/2,y:b.y+b.height/2}})()`); await touch(c, 'touchStart', [{ x: r.x, y: r.y, id: 1 }]); await touch(c, 'touchEnd', []); };
const secret = c => c.ev(`document.querySelector('.panel')&&!document.querySelector('.panel').hidden?document.querySelector('.panel').innerText:''`);
check('every phone gets its own secret in a private panel', (await Promise.all(trio.map(c => c.until(`!document.querySelector('.panel').hidden&&document.querySelectorAll('.pick').length===1`, 6000)))).every(Boolean), await Promise.all(trio.map(secret)));
if (process.env.SHOTS) { await p1.send('Page.bringToFront'); await p1.shot('pad-panel'); }
const texts = await Promise.all(trio.map(secret)), word = await s.ev(`gc.inst.s.word`), imp = await s.ev(`gc.inst.s.imposter`);
const ids3 = await s.ev(`JSON.stringify([...gc.players.keys()])`).then(JSON.parse);
const byId = Object.fromEntries(ids3.map((id, i) => [id, trio[i]]));
check('the crew see the word, the imposter does not', ids3.every((id, i) => id === imp ? !texts[i].includes(word) && /IMPOSTER/.test(texts[i]) : texts[i].includes(word)), texts);
check('and the shared screen shows no word', !(await s.ev(`document.body.innerText`)).includes(word), null);
await s.ev(`gc._state()`); await sleep(400); // a pause or resume rebuilds every phone's page
check('a phone that is rebuilt still shows its panel', (await Promise.all(trio.map(c => c.ev(`!document.querySelector('.panel').hidden&&document.querySelectorAll('.pick').length===1`)))).every(Boolean), null);
const rl = byId[ids3[1]]; await rl.goto(info.url + '/pad'); // a reload comes back to the same place, and the screen sends the panel again
check('a phone that reloads gets its panel back', await rl.until(`window.pad&&!document.querySelector('.panel').hidden`, 10000), await rl.ev(`document.body.innerText`));
for (const c of trio) await tapPick(c, 0);
check('everyone tapping Got it starts the clues', await s.until(`gc.inst.s.phase==='clues'`, 5000), await s.ev(`gc.inst.s.phase`));
const sp = await s.ev(`gc.inst.s.order[gc.inst.s.idx]`);
check('only the speaker has a Done button', await byId[sp].until(`!document.querySelector('.panel').hidden`, 4000) && (await Promise.all(ids3.filter(i => i !== sp).map(i => byId[i].ev(`document.querySelector('.panel').hidden`)))).every(Boolean), sp);
for (let i = 0; i < 3; i++) { const who = await s.ev(`gc.inst.s.order[gc.inst.s.idx]`); await byId[who].until(`!document.querySelector('.panel').hidden`, 4000); await tapPick(byId[who], 0); await sleep(250); }
if (process.env.SHOTS) { await s.send('Page.bringToFront'); await sleep(200); await s.ev(`gc.inst.tick(0.01);1`); await s.shot('imposter'); }
check('after the last clue everyone gets Ready to vote', await s.until(`gc.inst.s.phase==='discuss'`, 5000), await s.ev(`gc.inst.s.phase`));
for (const c of trio) { await c.until(`!document.querySelector('.panel').hidden`, 4000); await tapPick(c, 0); }
check('all ready starts the vote with the other two as choices', await s.until(`gc.inst.s.phase==='vote'`, 5000) && await p1.until(`document.querySelectorAll('.pick').length===2`, 4000), await s.ev(`gc.inst.s.phase`));
for (const c of trio) { await c.until(`document.querySelectorAll('.pick').length===2`, 4000); await tapPick(c, 0); await sleep(250); }
check('the votes come in and are shown', await s.until(`gc.inst.s.phase==='reveal'||gc.inst.s.phase==='guess'||gc.inst.s.phase==='result'`, 5000), await s.ev(`gc.inst.s.phase`));
await s.ev(`gc.inst.tick(5);gc.inst.tick(0.1);1`); // out of the reveal
await sleep(300);
const ph = await s.ev(`gc.inst.s.phase`);
if (ph === 'guess') { await byId[imp].until(`document.querySelectorAll('.pick').length===4`, 4000); await tapPick(byId[imp], 0); await sleep(300); }
check('the round ends with a result and the word on the screen', await s.until(`gc.inst.s.phase==='result'`, 5000) && (await s.ev(`document.body.innerText`)) !== undefined, await s.ev(`gc.inst.s.phase`));
await s.ev(`gc.inst.tick(0.01);1`);
const host = ids3[0]; await byId[host].until(`document.querySelectorAll('.pick').length===2`, 4000); await tapPick(byId[host], 1);
check('Stop on the first phone ends the game', await s.until(`gc.state==='lobby'`, 5000), await s.ev(`gc.state`));
await ia.ev(`pad.leave();1`); await ib.ev(`pad.leave();1`);
await s.until(`gc.players.size===1`, 8000);

// pause and the same place back
await s.ev(`gc.staleMs=1500;gc.stop();gc.select('padtest');gc.start()`); // the heartbeat rule, shortened: the grace period here is only 4 s
await p1.until(`!!document.querySelector('.btn')`, 5000);
const slot0 = (await pl(s)).slot, id0 = (await pl(s)).id;
await p1.goto('about:blank');
check('a controller that vanishes pauses the game', await s.until(`gc.state==='paused'&&!document.querySelector('#pause').hidden`, 8000), await s.ev(`gc.state`));
await p1.goto(info.url + '/pad'); // the tab remembers its place, so it comes back by itself
check('and when it returns the game resumes with the same player', await s.until(`gc.state==='play'`, 8000) && (await pl(s)).id === id0 && (await pl(s)).slot === slot0, [await s.ev(`gc.state`), await pl(s)]);
await p1.goto('about:blank');
await s.until(`gc.state==='paused'`, 8000);
check('"Continue without" drops the missing player and resumes', await s.ev(`document.querySelector('#skip').click();gc.state==='play'&&gc.players.size===0`), await s.ev(`[gc.state,gc.players.size]`));
await s.ev(`gc.stop();1`);
check('Menu / stop returns to the lobby', await s.until(`!document.querySelector('#lobby').hidden`, 3000), null);

await s.ev(`gc.closed='no such room';gc.onUpdate();1`);
check('a room the box forgot offers a new one', await s.ev(`!document.querySelector('#fresh').hidden`), null);

const errs = [s, ...pads].flatMap(x => x.logs).filter(l => !/favicon|Failed to load resource|AudioContext was not allowed|handshake: Unexpected response code: 503/.test(l)) // the test's clicks are not real taps, so the audio context may not start; a 503 is the room channel shedding load while this busy machine runs chromium, and the pages retry;
check('no script errors on any page', errs.length === 0, errs);
console.log(fails.length ? `\n${fails.length} FAILED` : '\nall ok');
done(fails.length ? 1 : 0);

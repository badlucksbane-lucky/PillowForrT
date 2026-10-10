// Drives the real browse.html in headless Chromium with every network source mocked (Cinemeta, AniList, Kitsu, YTS, EZTV, Torrentio, the box's Nyaa relay and /api/bt), and checks what the
// torrent lists show: both sources merged and deduped by infohash, the Torrentio text parsed, a failing source not hiding the other, the anime episode stepper, the Nyaa box being the only call to
// the box, and the second tap on a row with no seeds. Needs nothing from the box or the internet. Usage: node browse-test.mjs   (Node 22, chromium on the PATH or CHROMIUM=/path)
// CDP_PORT picks the debugging port (default 9333). Exit code 1 if anything fails.
import http from 'node:http';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { spawn } from 'node:child_process';
import { fileURLToPath } from 'node:url';
const here = path.dirname(fileURLToPath(import.meta.url));
process.env.CDP_PORT ||= '9333'; // cdp.mjs reads this when it is imported
const { connect } = await import('./cdp.mjs');
const page = fs.readFileSync(process.env.PAGE || path.join(here, '../../browse.html'), 'utf8'); // PAGE: another copy of the page, to try a broken one

// ---- made-up Torrentio streams in the real shape: title is "name\n[file\n]👤 seeds 💾 size ⚙️ indexer" ----
const hex = (a, i) => ({ M: 'a', S: 'b', A: 'c', Z: 'd' }[a] + i.toString(16)).padStart(40, '0'); // a valid 40-hex infohash per set and index
const stream = (a, i, o = {}) => ({
  name: 'Torrentio\n1080p',
  title: `${a} Release ${i} 1080p\n${o.noline ? '' : `\u{1F464} ${o.seeds ?? 100 - i} \u{1F4BE} ${o.size ?? '1.5 GB'} ⚙️ ${o.src ?? 'IndexerA'}`}`,
  infoHash: o.hash ?? hex(a, i), fileIdx: 0, behaviorHints: { filename: `${a}.${i}.mkv` },
});
const fixture = a => [
  ...Array.from({ length: 20 }, (_, i) => stream(a, i)),
  stream(a, 20, { noline: true }),                 // no seeds line: kept, shows 0 seeds
  stream(a, 21, { size: '2.0 TB', seeds: 7 }),     // a TB size
  stream(a, 3),                                    // same hash as release 3: deduped
  stream(a, 23, { hash: 'abc' }),                  // not a 40-hex hash: dropped
];
const validUnique = ss => new Set(ss.map(s => s.infoHash.toLowerCase()).filter(h => /^[0-9a-f]{40}$/.test(h))).size;
const MOV = { streams: fixture('M') }, SER = { streams: fixture('S') };
const ANI = { streams: [...fixture('A').slice(0, 8), { title: 'Zero Seed Pack\n\u{1F464} 0 \u{1F4BE} 1 GB ⚙️ IndexerB', infoHash: hex('Z', 1), behaviorHints: {} }] };
const ytsHash = MOV.streams[2].infoHash;   // YTS lists this one too: shown once
const ezHash = SER.streams[5].infoHash.toUpperCase(); // EZTV lists this one too, upper case: shown once

// ---- the page's network, replaced before its own scripts run ----
const mock = `<script>
const MOV=${JSON.stringify(MOV)},SER=${JSON.stringify(SER)},ANI=${JSON.stringify(ANI)},FAIL=new URLSearchParams(location.search).get('fail')||'';
const J=o=>new Response(JSON.stringify(o),{headers:{'content-type':'application/json'}});
window.__urls=[];
window.fetch=async(u)=>{u=String(u);window.__urls.push(u);
 if(u.includes('/meta/movie/'))return J({meta:{id:'tt1',imdb_id:'tt1',name:'Example Movie',releaseInfo:'2000',description:'d'}});
 if(u.includes('/meta/series/'))return J({meta:{id:'tt2',imdb_id:'tt2',name:'Example Show',releaseInfo:'2001',videos:[{season:1,episode:1,name:'Pilot',released:'2001-01-01'}]}});
 if(u.includes('graphql.anilist.co'))return J({data:{Media:{id:21,title:{romaji:'Example Anime',english:'Example Anime'},episodes:50,format:'TV',coverImage:{},genres:[],status:'RELEASING',description:''}}});
 if(u.includes('kitsu.io'))return J({data:[{relationships:{item:{data:{type:'anime',id:'12'}}}}]});
 if(u.includes('/api/search/nyaa'))return J({items:[{title:'Nyaa Item',hash:'a'.repeat(40),seeds:5,size:'1 GiB',url:''}]});
 if(u.includes('torrentio')){if(FAIL==='all'||(FAIL==='series'&&u.includes('/series/')))throw new Error('down');
  return J(u.includes('/movie/kitsu:')||u.includes('/series/kitsu:')?ANI:u.includes('/movie/')?MOV:SER)}
 if(u.includes('yts')||u.includes('accel'))return J({data:{movies:[{imdb_code:'tt1',torrents:[{quality:'2160p',type:'bluray',video_codec:'x265',hash:'${ytsHash}',size_bytes:7e9,seeds:163}]}]}});
 if(u.includes('eztv'))return J({torrents_count:2,torrents:[{season:1,episode:1,title:'EZ Release 1',hash:'${ezHash}',size_bytes:5e8,seeds:9},{season:1,episode:1,title:'EZ Only',hash:'${'e'.repeat(40)}',size_bytes:5e8,seeds:4}]});
 if(u.includes('/api/bt'))return J({available:true,enabled:true,ready:'',upload:'off'});
 return J({metas:[]})};
</script>`;
const srv = http.createServer((q, r) => {
  if (q.url.startsWith('/bt/') || q.url === '/sw.js') { r.writeHead(200, { 'content-type': 'text/javascript' }); return r.end(''); }
  if (!q.url.startsWith('/?') && q.url !== '/') { r.writeHead(404); return r.end(); }
  r.writeHead(200, { 'content-type': 'text/html' }); r.end(page.replace('<head>', '<head>' + mock));
});
await new Promise(r => srv.listen(0, r));
const base = `http://127.0.0.1:${srv.address().port}/`;

const fails = [];
const check = (name, ok, got) => { console.log((ok ? 'ok   ' : 'FAIL ') + name + (ok ? '' : '  got: ' + JSON.stringify(got))); if (!ok) fails.push(name); };

const prof = fs.mkdtempSync(path.join(os.tmpdir(), 'browse-test-'));
const cr = spawn(process.env.CHROMIUM || 'chromium', ['--headless=new', '--no-sandbox', '--disable-gpu', '--remote-debugging-port=' + process.env.CDP_PORT, '--user-data-dir=' + prof, '--disable-background-networking', 'about:blank'], { stdio: 'ignore', detached: true }); // its own process group, so the helper processes can be stopped with it
const exited = new Promise(r => cr.once('exit', r));
const done = async code => {
  try { process.kill(-cr.pid, 'SIGTERM'); } catch (e) { /* already gone */ }
  await Promise.race([exited, new Promise(r => setTimeout(r, 3000))]);
  await new Promise(r => setTimeout(r, 500)); // the helpers stop writing to the profile before it is removed
  try { process.kill(-cr.pid, 'SIGKILL'); } catch (e) { /* none left */ }
  srv.close();
  try { fs.rmSync(prof, { recursive: true, force: true, maxRetries: 5, retryDelay: 200 }); } catch (e) { /* a temp directory; the OS clears it */ }
  process.exit(code);
};
for (let i = 0; ; i++) { try { await fetch(`http://127.0.0.1:${process.env.CDP_PORT}/json/version`); break; } catch (e) { if (i > 50) { console.error('chromium did not start'); done(2); } await new Promise(r => setTimeout(r, 200)); } }
const c = await connect();

// a fresh load of one page; the page keeps results in memory and localStorage, so each scenario starts clean
async function open(hash, q = '', until = 'document.querySelector(".tor")') {
  await c.ev('try{localStorage.clear()}catch(e){}'); await c.goto('about:blank'); await c.wait(150);
  await c.goto(base + q + hash); return c.until(until, 12000);
}
const rows = () => c.ev('document.querySelectorAll(".tor").length');
const text = () => c.ev('(document.querySelector("#panel")||{}).textContent||""'); // the sheet only: the page's own script text also holds words like "null"
const urls = f => c.ev(`JSON.stringify(window.__urls.filter(u=>u.includes(${JSON.stringify(f)})))`).then(JSON.parse);
const rowText = s => c.ev(`([...document.querySelectorAll('.tor')].find(r=>r.textContent.includes(${JSON.stringify(s)}))||{}).textContent||''`);
const clickPlay = s => c.ev(`[...[...document.querySelectorAll('.tor')].find(r=>r.textContent.includes(${JSON.stringify(s)})).querySelectorAll('button')].find(b=>/^Play/.test(b.textContent)).click()`);
const playLabel = s => c.ev(`[...[...document.querySelectorAll('.tor')].find(r=>r.textContent.includes(${JSON.stringify(s)})).querySelectorAll('button')].map(b=>b.textContent).filter(t=>/^Play/.test(t))[0]`);
const playerOpen = () => c.ev('document.querySelector("#player").classList.contains("open")');
const wantMovie = validUnique(MOV.streams), wantSeries = validUnique(SER.streams) + 1, wantAnime = validUnique(ANI.streams); // series: + the EZTV-only release
if (wantMovie < 20 || wantAnime < 5) { console.error('bad fixtures'); done(2); }

// movie: YTS + Torrentio
await open('#/movies?id=tt1', '', 'document.querySelectorAll(".tor").length>=' + wantMovie);
check('movie: both sources merged, duplicates and bad hashes dropped', (await rows()) === wantMovie, await rows());
check('movie: a stream with no seeds line is kept with 0 seeds', /0 seeds/.test(await rowText('Release 20')), await rowText('Release 20'));
check('movie: a TB size is parsed', /TB/.test(await rowText('Release 21')), await rowText('Release 21'));
check('movie: no "null" text in the sheet', !/null/.test(await text()), (await text()).slice(0, 200));

// series: EZTV + Torrentio, fetched when the episode is opened
await open('#/series?id=tt2', '', 'document.querySelector(".eh")');
check('series: Torrentio is not asked until an episode is opened', (await urls('torrentio')).length === 0, await urls('torrentio'));
await c.ev('document.querySelector(".eh").click()');
await c.until('document.querySelectorAll(".ep.open .tor").length>=' + wantSeries, 12000);
check('series: EZTV and Torrentio merged and deduped (upper-case EZTV hash)', (await rows()) === wantSeries, await rows());
check('series: Torrentio asked for the opened episode', (await urls('torrentio'))[0].includes('/series/tt2:1:1.json'), await urls('torrentio'));

// anime: Kitsu then Torrentio per episode; the Nyaa relay only from its own box
await open('#/anime?id=21', '', 'document.querySelector("[aria-label=\\"Next episode\\"]")&&document.querySelectorAll(".tor").length>=' + wantAnime);
check('anime: rows from Torrentio', (await rows()) === wantAnime, await rows());
check('anime: asked for Kitsu episode 1', (await urls('torrentio')).some(u => u.includes('/series/kitsu:12:1.json')), await urls('torrentio'));
check('anime: the box was not asked for anything yet', (await urls('/api/search/nyaa')).length === 0);
await c.ev('document.querySelector("[aria-label=\\"Next episode\\"]").click()');
await c.until('window.__urls.some(u=>u.includes("kitsu:12:2"))', 8000);
check('anime: the stepper asks for episode 2', (await urls('torrentio')).some(u => u.includes('kitsu:12:2')));
await c.wait(500);
check('zero seeds: Play is labelled Play', (await playLabel('Zero Seed Pack')) === 'Play', await playLabel('Zero Seed Pack'));
await clickPlay('Zero Seed Pack'); await c.wait(300);
check('zero seeds: the first tap only arms the button', (await playLabel('Zero Seed Pack')) === 'Play anyway' && !(await playerOpen()), [await playLabel('Zero Seed Pack'), await playerOpen()]);
await clickPlay('Zero Seed Pack'); await c.wait(500);
check('zero seeds: the second tap starts the player', await playerOpen());
await c.ev('document.querySelector("#pclose").click()');
await c.ev('document.querySelector(".refine:last-of-type button[type=submit]").click()');
await c.until('[...document.querySelectorAll(".tor")].some(r=>r.textContent.includes("Nyaa Item"))', 8000);
check('anime: the Nyaa box asks the box and shows its result', (await urls('/api/search/nyaa')).length === 1 && /Nyaa Item/.test(await text()), await urls('/api/search/nyaa'));

// one source down: the other still shows, and a movie says which one
await open('#/movies?id=tt1', '?fail=all', 'document.querySelector(".tor")&&document.querySelector("#panel").textContent.includes("did not answer")');
check('movie, Torrentio down: YTS row stays, note names Torrentio', (await rows()) === 1 && /Torrentio did not answer/.test(await text()), [await rows(), (await text()).includes('did not answer')]);
await open('#/series?id=tt2', '?fail=series', 'document.querySelector(".eh")');
await c.ev('document.querySelector(".eh").click()'); await c.until('document.querySelectorAll(".ep.open .tor").length>=2', 12000);
check('series, Torrentio down: the EZTV rows stay', (await rows()) === 2, await rows());

const exc = c.logs.filter(l => l.startsWith('EXC'));
check('no uncaught page errors', exc.length === 0, exc);
console.log(fails.length ? `\n${fails.length} failed` : '\nall passed');
c.close(); await done(fails.length ? 1 : 0);

// Tests Kids mode in the Browse page (the <kids-browse> block in browse.html): the state it reads, the rating filter (batches, "still checking", fail closed), the list wrapper that refills a page and keeps its
// place, the gate on a detail sheet, the clearance before Play, the Web tab, and the wiring around them. A fake box stands in for /api/kids, /api/rating, /api/session and /api/kids/clear.
// Usage: node kidsbrowse-unit.mjs   Exit code 1 on failure.
import fs from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
const html = fs.readFileSync(path.join(path.dirname(fileURLToPath(import.meta.url)), '../../browse.html'), 'utf8');
const block = html.slice(html.indexOf('// <kids-browse>'), html.indexOf('// </kids-browse>'));
if (!block) { console.log('FAIL markers not found'); process.exit(1); }
const fails = [];
const check = (name, ok, got) => { console.log((ok ? 'ok   ' : 'FAIL ') + name + (ok ? '' : '  got: ' + JSON.stringify(got))); if (!ok) fails.push(name); };

// a fake box
const mkBox = () => {
  const b = { kids: { on: true, ratings_key: true }, ratings: {}, calls: [], pendingFor: new Map(), failRating: false, failKids: false, clear: { status: 200, body: {} }, clearCalls: [], csrfCalls: 0, now: 1e9 };
  b.jf = async (url) => {
    b.calls.push(url);
    if (url.startsWith('/api/kids')) { if (b.failKids) throw new Error('HTTP 500'); return { ...b.kids }; }
    if (url.startsWith('/api/session')) { b.csrfCalls++; return { csrf: 'TOKEN' }; }
    if (url.startsWith('/api/rating')) {
      if (b.failRating) throw new Error('HTTP 500');
      const u = new URL(url, 'http://x'); const ids = u.searchParams.get('ids').split(',').map(decodeURIComponent); const out = {};
      for (const id of ids) {
        if (b.omit && b.omit.has(id)) continue; // the box leaves this id out of its answer
        if (b.mangled && b.mangled[id]) { out[id] = b.mangled[id]; continue; } // a strange entry
        const left = b.pendingFor.get(id) || 0;
        if (left > 0) { b.pendingFor.set(id, left - 1); out[id] = { ok: false, why: 'checking', pending: true }; } else out[id] = b.ratings[id] || { ok: false, why: 'no rating' };
      }
      return { ratings: out, configured: true };
    }
    throw new Error('unexpected ' + url);
  };
  b.fetch = async (url, init) => { b.clearCalls.push([url, init]); return { ok: b.clear.status < 400, status: b.clear.status, json: async () => b.clear.body }; };
  return b;
};
const mkPage = (box, extra = {}) => {
  const els = { web: { hidden: false } }; const went = [];
  const env = {
    jf: box.jf, fetch: box.fetch, Date: { now: () => box.now }, setTimeout: (f) => { box.now += 1500; f(); },
    h: (tag, p, ...kids) => ({ tag, p, kids: kids.flat(2).filter(Boolean) }), $: (sel) => sel.includes('data-t="web"') ? els.web : null, S: { tab: 'movies' }, go: (o, r) => went.push([o, r]),
    rawList: extra.rawList || (async () => ({ items: [], more: false })), CUR_INIT: null, ...extra
  };
  const code = block + '\nreturn {kidsState, ratingsFor, kidsFilter, kidsAllows, list, kidsClear, kidsBanner, kidsTabs, setCUR: v => { CUR = v; }, getKIDS: () => KIDS, RMEMO, KCUR};';
  const api = new Function(...Object.keys(env), code)(...Object.values(env));
  return { api, els, went, env };
};
const ok = (cert) => ({ ok: true, cert, why: '' });
const no = (why) => ({ ok: false, cert: why, why });
const items = (ids) => ids.map(id => ({ id, name: 'T' + id }));

// ---- the state ----
{ const box = mkBox(); const p = mkPage(box);
  const k = await p.api.kidsState();
  check('it reads Kids mode and whether ratings are set up', k.on === true && k.key === true, k);
  const n = box.calls.length; await p.api.kidsState(); box.now += 14000; await p.api.kidsState();
  check('and keeps the answer for 15 seconds', box.calls.length === n, box.calls);
  box.now += 2000; box.kids = { on: false, ratings_key: true }; const k2 = await p.api.kidsState();
  check('then asks again and notices a change', box.calls.length === n + 1 && k2.on === false, k2);
  box.kids = { on: true, ratings_key: false }; const k3 = await p.api.kidsState(true);
  check('"force" asks at once, and a missing key shows as key:false', k3.on === true && k3.key === false, k3);
  box.failKids = true; const k4 = await p.api.kidsState(true);
  check('if the box does not answer, the last known state stands', k4.on === true && k4.key === false, k4);
  const c = box.calls.length; box.now += 3000; await p.api.kidsState(); const early = box.calls.length; box.now += 2500; await p.api.kidsState();
  check('and it is asked again after about 5 seconds, not 15 and not at once', early === c && box.calls.length === c + 1, [c, early, box.calls.length]); }

// ---- ratings and the filter ----
{ const box = mkBox(); box.ratings = { tt1: ok('PG'), tt2: no('R'), tt3: no('no rating'), tt4: ok('TV-14') }; const p = mkPage(box);
  const kept = await p.api.kidsFilter('movies', items(['tt1', 'tt2', 'tt3', 'tt4', 'tt9']));
  check('only titles whose rating was found and allowed stay (PG, TV-14); R, unrated and unknown go', kept.map(i => i.id).join() === 'tt1,tt4', kept);
  check('a tab with no ratings (the Web tab) and an empty list pass through untouched', (await p.api.kidsFilter('web', items(['x']))).length === 1 && (await p.api.kidsFilter('movies', [])).length === 0, null);
  const n = box.calls.length; await p.api.kidsFilter('movies', items(['tt1', 'tt2'])); check('answers are remembered: asking again costs nothing', box.calls.length === n, null);
  const ids = Array.from({ length: 130 }, (_, i) => 'tt' + (100 + i)); ids.forEach(id => { box.ratings[id] = ok('G'); });
  const before = box.calls.length; await p.api.kidsFilter('series', items([...ids, ...ids.slice(0, 10)]));
  const reqs = box.calls.slice(before).filter(u => u.startsWith('/api/rating'));
  check('130 titles go in batches of 60, duplicates counted once, and the kind is sent', reqs.length === 3 && reqs.every(u => u.includes('kind=series')) && reqs.map(u => new URL(u, 'http://x').searchParams.get('ids').split(',').length).join() === '60,60,10', reqs.map(u => u.length)); }
{ const box = mkBox(); box.ratings = { tt1: ok('PG') }; box.pendingFor.set('tt1', 2); const p = mkPage(box);
  const r = await p.api.ratingsFor('movie', ['tt1']);
  check('a title the box is still looking up is asked about again and then answered', r.tt1.ok === true, r); }
{ const box = mkBox(); box.ratings = { tt1: ok('PG') }; box.pendingFor.set('tt1', 99); const p = mkPage(box);
  const r = await p.api.ratingsFor('movie', ['tt1']); const kept = await p.api.kidsFilter('movies', items(['tt1']));
  check('one that never finishes is hidden, not shown ("checking")', r.tt1.ok === false && r.tt1.why === 'checking' && kept.length === 0, r); }
{ const box = mkBox(); const p = mkPage(box); box.failRating = true;
  let err = ''; try { await p.api.kidsFilter('movies', items(['tt1'])); } catch (e) { err = e.message; }
  check('if the box cannot be asked the list FAILS (and the page shows "could not load"), it never shows unfiltered', /HTTP 500/.test(err), err);
  box.failRating = false; box.ratings = { tt1: { ok: false, why: 'lookup failed' } }; await p.api.ratingsFor('movie', ['tt1']);
  check('a failed lookup is not remembered, so the next look asks again', !p.api.RMEMO.has('movie:tt1'), [...p.api.RMEMO.keys()]);
  box.ratings = { tt1: ok('PG') }; check('and then finds it', (await p.api.ratingsFor('movie', ['tt1'])).tt1.ok === true, null); }

// ---- strange answers never let a title through ----
{ const box = mkBox(); box.ratings = { tt1: ok('PG') }; box.omit = new Set(['tt2']); box.mangled = { tt3: { why: 'x' }, tt4: {}, tt5: { ok: 'yes' }, tt6: { ok: 1 }, tt7: { ok: null }, tt8: { pending: false } };
  const p = mkPage(box);
  const kept = await p.api.kidsFilter('movies', items(['tt1', 'tt2', 'tt3', 'tt4', 'tt5', 'tt6', 'tt7', 'tt8']));
  check('an id the box left out, or an entry that is not exactly ok:true (missing, "yes", 1, null), is hidden', kept.map(i => i.id).join() === 'tt1', kept.map(i => i.id));
  check('and a sheet for such a title does not open', (await p.api.kidsAllows('movie', 'tt2')) === false && (await p.api.kidsAllows('movie', 'tt5')) === false && (await p.api.kidsAllows('movie', 'tt4')) === false, null); }

// ---- the list wrapper ----
const pageOf = (n, ids) => ({ items: items(ids.slice(n * 3, n * 3 + 3)), more: (n + 1) * 3 < ids.length });
{ const box = mkBox(); const all = Array.from({ length: 9 }, (_, i) => 'tt' + (200 + i)); all.forEach((id, i) => { box.ratings[id] = i % 3 === 0 ? ok('PG') : no('R'); });
  const raw = []; const p = mkPage(box, { rawList: async (tab, cat, o) => { raw.push(o.page); return pageOf(o.page, all); } });
  box.kids.on = false; await p.api.kidsState(true);
  const r0 = await p.api.list('movies', 'top', { page: 0 });
  check('with Kids mode off the list is exactly what the source gave', r0.items.length === 3 && raw.join() === '0', raw);
  box.kids.on = true; box.now += 20000; await p.api.kidsState(true); raw.length = 0;
  const a = await p.api.list('movies', 'top', { page: 0 });
  check('with it on, a page that lost most titles reads on until it has enough or the source ends', raw.join() === '0,1,2' && a.items.map(i => i.id).join() === 'tt200,tt203,tt206' && a.more === false, [raw, a]);
  const filler = Array.from({ length: 40 }, (_, i) => 'tt' + (300 + i)); filler.forEach((id, i) => { box.ratings[id] = i % 2 ? no('R') : ok('G'); });
  raw.length = 0; const p2 = mkPage(box, { rawList: async (tab, cat, o) => { raw.push(o.page); return pageOf(o.page, filler); } }); await p2.api.kidsState(true);
  const b0 = await p2.api.list('series', 'top', { page: 0 }), b1 = await p2.api.list('series', 'top', { page: 1 }), b2 = await p2.api.list('series', 'top', { page: 2 });
  const seen = [...b0.items, ...b1.items, ...b2.items].map(i => i.id);
  check('successive calls carry on from where the last one stopped: no title twice, none skipped', new Set(seen).size === seen.length && seen.join() === filler.filter((x, i) => i % 2 === 0).slice(0, seen.length).join(), [seen, raw]);
  check('"more" is passed on while the source has more', b0.more === true, b0);
  const other = await p2.api.list('series', 'popular', { page: 0 });
  check('another list starts at its own beginning', other.items[0].id === 'tt300', other.items[0]);
  const stuck = Array.from({ length: 30 }, (_, i) => 'tt' + (500 + i)); stuck.forEach(id => { box.ratings[id] = no('R'); }); raw.length = 0;
  const p3 = mkPage(box, { rawList: async (tab, cat, o) => { raw.push(o.page); return pageOf(o.page, stuck); } }); await p3.api.kidsState(true);
  const s = await p3.api.list('movies', 'top', { page: 0 });
  check('when nothing passes it gives up after 4 source pages, so a page never takes forever', raw.length === 4 && s.items.length === 0 && s.more === true, [raw, s]); }

// ---- a detail sheet ----
{ const box = mkBox(); box.ratings = { tt1: ok('PG'), tt2: no('TV-MA') }; const p = mkPage(box);
  check('a PG title may open, a TV-MA one may not', (await p.api.kidsAllows('movie', 'tt1')) === true && (await p.api.kidsAllows('series', 'tt2')) === false, null);
  check('an unknown title may not', (await p.api.kidsAllows('movie', 'tt404')) === false, null);
  box.kids.on = false; await p.api.kidsState(true); const ratingCalls = () => box.calls.filter(u => u.startsWith('/api/rating')).length; const n = ratingCalls();
  check('with Kids mode off everything may, without asking for a rating', (await p.api.kidsAllows('movie', 'tt2')) === true && ratingCalls() === n, [n, ratingCalls()]);
  box.kids.on = true; box.now += 20000; await p.api.kidsState(true); box.failRating = true;
  let err = ''; try { await p.api.kidsAllows('movie', 'tt777'); } catch (e) { err = e.message; }
  check('if the rating cannot be fetched the sheet does not open (the error reaches the page\'s "could not load")', /HTTP 500/.test(err), err); }

// ---- Play ----
{ const box = mkBox(); const p = mkPage(box); const hash = 'a'.repeat(40);
  box.kids.on = false; await p.api.kidsState(true);
  check('with Kids mode off Play needs no clearance and asks nothing', (await p.api.kidsClear(hash)).ok === true && box.clearCalls.length === 0, null);
  box.kids.on = true; box.now += 20000; await p.api.kidsState(true);
  check('with it on and no title open, Play is refused', (await p.api.kidsClear(hash)).ok === false && box.clearCalls.length === 0, null);
  p.api.setCUR({ kind: 'movie', id: 'tt1' });
  const r = await p.api.kidsClear(hash); const [url, init] = box.clearCalls[0];
  check('it posts the kind, the title and the hash to the box, with the CSRF token', r.ok === true && url === '/api/kids/clear' && init.method === 'POST' && init.headers['X-CSRF-Token'] === 'TOKEN' && JSON.parse(init.body).kind === 'movie' && JSON.parse(init.body).id === 'tt1' && JSON.parse(init.body).hash === hash, init);
  await p.api.kidsClear(hash); check('the token is fetched once', box.csrfCalls === 1, box.csrfCalls);
  box.clear = { status: 403, body: { error: 'hidden by Kids mode', why: 'R' } };
  check('a refusal from the box stops Play with its words', await p.api.kidsClear(hash).then(x => x.ok === false && x.error === 'hidden by Kids mode'), null);
  const p2 = mkPage(Object.assign(mkBox(), { fetch: async () => { throw new Error('down'); } })); p2.api.setCUR({ kind: 'movie', id: 'tt1' });
  check('if the box cannot be reached, Play is refused ("could not check")', await p2.api.kidsClear(hash).then(x => x.ok === false && /Could not check/.test(x.error)), null); }

// ---- tabs and banner ----
{ const box = mkBox(); const p = mkPage(box); p.api.kidsTabs(); await new Promise(r => setImmediate(r));
  check('with Kids mode on the Web tab is hidden', p.els.web.hidden === true, p.els.web);
  p.env.S.tab = 'web'; box.kids.on = true; await p.api.kidsState(true); p.api.kidsTabs(); await new Promise(r => setImmediate(r));
  check('and someone on the Web tab is sent to Movies', p.went.some(([o]) => o.tab === 'movies'), p.went);
  const box2 = mkBox(); box2.kids.on = false; const p2 = mkPage(box2); p2.api.kidsTabs(); await new Promise(r => setImmediate(r));
  check('with it off the Web tab is there and nobody is moved', p2.els.web.hidden === false && p2.went.length === 0, null);
  const b = mkPage(mkBox(), {}); await b.api.kidsState(); const ban = b.api.kidsBanner();
  check('the banner says Kids mode, and when ratings are not set up says why a page is empty', ban.kids.length === 1, ban);
  const box3 = mkBox(); box3.kids.ratings_key = false; const c = mkPage(box3); await c.api.kidsState();
  check('(and with no key it adds the explanation)', c.api.kidsBanner().kids.length === 2, null); }

// ---- wiring ----
const outside = html.replace(block, '');
check('no list is read around the filter: rawList is only used inside the Kids block', (outside.match(/rawList\(/g) || []).length === 0 && /const rawList=\(tab,cat,o\)=>tab==='anime'\?alList\(cat,o\):cmList\(tab,cat,o\);/.test(html), null);
check('a detail sheet is gated before anything loads and remembers its title for Play', /CUR=null;const kind=KIND\[S\.tab\];\n try\{if\(kind&&!\(await kidsAllows\(kind,S\.id\)\)\)\{if\(rid===S\.sid\)panel\.replaceChildren\(grab\(\),h\('div',\{class:'body'\},h\('div',\{class:'msg',text:'Hidden by Kids mode'\}\)\)\);return\}\n  CUR=kind\?\{kind,id:S\.id\}:null;/.test(html), null);
check('Play asks the box to clear the torrent before the player starts', /say\('Starting…'\);\n const kc=await kidsClear\(hash\);if\(!kc\.ok\)\{say\(kc\.error\|\|'Hidden by Kids mode',true\);return\}/.test(html) && html.indexOf('const kc=await kidsClear(hash)') < html.indexOf('c=await engine()'), null);
check('the Nyaa search box is not built in Kids mode', /KIDS\.on\?null:h\('form',\{class:'refine',onsubmit:ev=>\{ev\.preventDefault\(\);loadNyaa\(\)\}/.test(html), null);
check('swiping cannot reach the Web tab, and every render re-checks the tab', /!\(TABS\[i\]==='web'&&KIDS\.on\)/.test(html) && /function render\(force\)\{kidsTabs\(\);/.test(html), null);
check('the browse panes get the banner', /function renderBrowse\(pane,rid\)\{\n kidsState\(\)\.then\(k=>\{if\(k\.on&&rid===S\.rid\)pane\.prepend\(kidsBanner\(\)\)\}\);/.test(html), null);
console.log(fails.length ? '\n' + fails.length + ' failed' : '\nall ok'); process.exit(fails.length ? 1 : 0);

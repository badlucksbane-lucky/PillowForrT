// Tests the episode result list in browse.html: the <result-sort> block (qualityScore, sortItems) and torSorted (every single episode listed, packs folded, sort bar, direction flip, remembered choice)
// on realistic release names with a tiny fake DOM. Usage: node resultsort-unit.mjs   Exit code 1 on failure.
import fs from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
const html = fs.readFileSync(path.join(path.dirname(fileURLToPath(import.meta.url)), '../../browse.html'), 'utf8');
const cut = (a, b) => html.slice(html.indexOf(a), html.indexOf(b) + b.length);
const tiers = cut('// <result-tiers>', '// </result-tiers>'), sorts = cut('// <result-sort>', '// </result-sort>'), packs = cut('// <season-packs>', '// </season-packs>');
const dom = html.slice(html.indexOf('// The episode list: sort bar'), html.indexOf(' return out}\n', html.indexOf('// The episode list: sort bar')) + ' return out}\n'.length);
const hSrc = html.match(/^function h\(tag,p,\.\.\.kids\)\{.*\}$/m)[0];
if (!tiers || !sorts || !dom || !hSrc) { console.log('FAIL markers not found'); process.exit(1); }
const fails = [];
const check = (name, ok, got) => { console.log((ok ? 'ok   ' : 'FAIL ') + name + (ok ? '' : '  got: ' + JSON.stringify(got))); if (!ok) fails.push(name); };

class El {
  constructor (tag) { this.tag = tag; this.children = []; this.attrs = {}; this.open = false; this._t = ''; this.className = ''; this.handlers = {}; }
  get nodeType () { return 1; }
  setAttribute (k, v) { this.attrs[k] = v; if (k === 'open') this.open = true; if (k === 'class') this.className = v; } append (...c) { this.children.push(...c); } prepend (...c) { this.children.unshift(...c); }
  replaceChildren (...c) { this.children = c; } addEventListener (e, f) { this.handlers[e] = f; }
  set textContent (t) { this._t = t; } get textContent () { return this._t; }
  all () { return this.children.flatMap(c => c instanceof El ? [c, ...c.all()] : []); }
  querySelector (sel) { const [t, cls, open] = /^([a-z]*)\.?([\w-]*)(\[open\])?$/.exec(sel).slice(1); return this.all().find(e => (!t || e.tag === t) && (!cls || e.className.split(' ').includes(cls)) && (!open || e.open)) || null; }
  click () { this.handlers.click && this.handlers.click(); }
}
const doc = { createElement: t => new El(t), createTextNode: s => ({ nodeType: 3, s }) };
const mkStore = (init) => { const m = new Map(init ? [['b:tsort', init]] : []); return { getItem: k => m.has(k) ? m.get(k) : null, setItem: (k, v) => m.set(k, v), m }; };
const load = (stored) => { const ls = mkStore(stored); const api = new Function('document', 'localStorage', hSrc + '\n' + tiers + '\n' + sorts + '\n' + packs + '\n' + dom + '\nreturn {qualityScore, sortItems, torSorted, TSORT, h}')(doc, ls); return { api, ls }; };
const { api } = load();

// ---- quality score and sorting ----
const Q = api.qualityScore;
check('resolution decides quality: 2160 > 1080 > 720 > 576 > 480 > no resolution', Q('S.2160p.WEB-DL') > Q('S.1080p.WEB-DL') && Q('S.1080p.WEB-DL') > Q('S.720p.WEB-DL') && Q('S.720p.WEB-DL') > Q('S.576p.WEB-DL') && Q('S.576p.WEB-DL') > Q('S.480p.WEB-DL') && Q('S.480p.WEB-DL') > Q('S.WEB-DL'), null);
check('at one resolution the source only breaks the tie: BluRay = WEB > HDTV > DVD > unlabeled', Q('S.1080p.BluRay') === Q('S.1080p.WEB-DL') && Q('S.1080p.WEB-DL') > Q('S.1080p.HDTV') && Q('S.1080p.HDTV') > Q('S.1080p.DVDRip') && Q('S.1080p.DVDRip') > Q('S.1080p'), [Q('S.1080p.WEB-DL'), Q('S.1080p.HDTV'), Q('S.1080p.DVDRip'), Q('S.1080p')]);
check('a lower resolution never beats a higher one on source alone', Q('S.720p.BluRay') < Q('S.1080p'), null);
const it = (t, n, z) => ({ t, n, z: Math.round(z * 1073741824) });
const list = [it('Show.S02E05.720p.HDTV.x264-A', 40, 0.9), it('Show.S02E05.1080p.WEB-DL.DDP5.1-B', 120, 3.1), it('Show.S02E05.2160p.WEB-DL-C', 15, 9.8), it('Show.S02E05.480p.WEBRip-D', 200, 0.3), it('Show.S02E05.1080p.WEB-DL-E', 90, 2.2), it('Show.S02E05.1080p.HDTV-F', 300, 2.9), it('Show.S02E05-G', 5, 0)];
const q1 = api.sortItems(list, 'q', -1).map(x => x.t);
check('quality order is exactly 2160p, 1080p WEB (120 over 90), 1080p HDTV, 720p, 480p, no resolution', q1[0].includes('2160p') && q1[1].includes('-B') && q1[2].includes('-E') && q1[3].includes('-F') && q1[4].includes('720p') && q1[5].includes('480p') && q1[6].endsWith('-G'), q1);
check('quality flipped is the exact reverse order', api.sortItems(list, 'q', 1).map(x => x.t).join() === api.sortItems(list, 'q', -1).map(x => x.t).reverse().join(), null);
const s1 = api.sortItems(list, 's', -1);
check('size, biggest first; an unknown size is last', s1.map(x => x.z > 0 ? 1 : 0).join('') === '1111110' && s1[0].t.includes('2160p') && s1[1].t.includes('-B') && s1.at(-1).t.endsWith('-G'), s1.map(x => x.t));
const s2 = api.sortItems(list, 's', 1);
check('size, smallest first; an unknown size is still last', s2[0].t.includes('480p') && s2.at(-1).t.endsWith('-G') && s2.slice(0, -1).every((x, i, a) => !i || a[i - 1].z <= x.z), s2.map(x => x.z));
check('seeds, most first, and the other way', api.sortItems(list, 'n', -1)[0].n === 300 && api.sortItems(list, 'n', -1).at(-1).n === 5 && api.sortItems(list, 'n', 1)[0].n === 5 && api.sortItems(list, 'n', 1).at(-1).n === 300, null);
check('seeds tie: the better quality first', api.sortItems([it('S.720p.WEB-DL', 50, 1), it('S.1080p.WEB-DL', 50, 2)], 'n', -1)[0].t.includes('1080p'), null);
check('sorting never mutates the list it was given, and an unknown key falls back to quality', (() => { const c = list.slice(); api.sortItems(list, 'n', -1); return c.every((x, i) => x === list[i]) && api.sortItems(list, 'zzz', -1)[0].t.includes('2160p'); })(), null);
check('equal items keep a stable, seed-led order', api.sortItems([it('S.1080p.WEB-DL.A', 10, 1), it('S.1080p.WEB-DL.B', 30, 1)], 'q', -1)[0].t.endsWith('B'), null);

// ---- the list ----
const make = () => api.h('div', { class: 'tor' }, api.h('div', { class: 's' }));
const mk = (t, n, z) => ({ t, n, z: Math.round(z * 1073741824), make });
const ep = [mk('Show.S02E05.1080p.WEB-DL-A', 120, 3.1), mk('Show.S02E05.720p.HDTV-B', 40, 0.9), mk('Show.S02E05.2160p.WEB-DL-C', 15, 9.8), mk('Show.S02E05.480p.WEBRip-D', 200, 0.3), mk('Show.S02E05.1080p.WEB-DL-E', 90, 2.2),
  mk('Show.S02.COMPLETE.1080p.WEB-DL-P1', 800, 48), mk('Show.Season.2.720p.WEB-DL-P2', 300, 22), mk('Show.S02.2160p.BluRay-P3', 60, 140)];
const host = doc.createElement('div'); let redraws = 0;
const draw = () => api.torSorted(ep, 'none', { host, redraw: () => { redraws++; host.replaceChildren(...draw()); } });
let out = draw(); host.replaceChildren(...out);
const rows = out.filter(x => x.className && x.className.split(' ').includes('tor'));
check('EVERY single-episode release is listed (5 of 5), none hidden', rows.length === 5, rows.length);
check('the packs are not in the main list but folded: "Season packs (3)", closed', out.at(-1).tag === 'details' && out.at(-1).children[0].textContent === 'Season packs (3)' && out.at(-1).open === false, out.map(x => x.tag + ':' + x.className));
check('a sort bar leads the list: Quality (active, ↓), Size, Seeds', out[0].className.includes('sortbar') && out[0].children.map(b => b.textContent).join('|') === 'Quality ↓|Size|Seeds', out[0].children.map(b => b.textContent));
const tierOf = r => { const t = r.querySelector('.tier'); return t ? t._t : null; };
check('each row is labelled with its tier and source, best quality first by default', rows.map(tierOf).join('|') === '2160p · WEB|1080p · WEB|1080p · WEB|720p · TV|SD · WEB', rows.map(tierOf));
out[0].children[1].click(); // Size
check('tapping Size sorts by size, biggest first, and asks the page to redraw', redraws === 1 && api.TSORT.k === 's' && api.TSORT.d === -1, [redraws, api.TSORT]);
out = host.children; const sizeBar = out[0];
check('the bar shows the active key and direction: "Size ↓"', sizeBar.children.map(b => b.textContent).join('|') === 'Quality|Size ↓|Seeds' && sizeBar.children[1].className === 'on', sizeBar.children.map(b => b.textContent));
sizeBar.children[1].click(); // flip
check('tapping the active key flips it: "Size ↑" smallest first', api.TSORT.d === 1 && host.children[0].children[1].textContent === 'Size ↑' && tierOf(host.children[1]).startsWith('SD'), [api.TSORT, host.children[0].children[1].textContent]);
const smallFirst = host.children.filter(x => x.className.includes('tor')).map(tierOf);
check('and the list really is smallest first (480p before 2160p)', smallFirst[0].startsWith('SD') && smallFirst.at(-1).startsWith('2160p'), smallFirst);
host.children[0].children[2].click(); // Seeds
const bySeeds = host.children.filter(x => x.className.includes('tor')).map(tierOf);
check('Seeds sorts by seeds, most first (the 200-seed 480p leads)', api.TSORT.k === 'n' && api.TSORT.d === -1 && bySeeds[0].startsWith('SD'), [api.TSORT, bySeeds]);
check('the packs stay folded and sorted the same way under any choice', host.children.at(-1).tag === 'details' && host.children.at(-1).children.length === 1 + 3, host.children.at(-1).children.length);

// ---- remembering the choice ----
const a2 = load(JSON.stringify({ k: 's', d: 1 })).api;
check('a saved choice is restored on the next page load', a2.TSORT.k === 's' && a2.TSORT.d === 1, a2.TSORT);
const a3 = load('not json').api, a4 = load(JSON.stringify({ k: 'bogus', d: 7 })).api;
check('junk in storage falls back to quality, best first', a3.TSORT.k === 'q' && a3.TSORT.d === -1 && a4.TSORT.k === 'q' && a4.TSORT.d === -1, [a3.TSORT, a4.TSORT]);
const l5 = load(); const h5 = doc.createElement('div'); const o5 = l5.api.torSorted(ep, 'x', { host: h5, redraw() {} }); o5[0].children[2].click();
check('a choice is written to storage (b:tsort)', JSON.parse(l5.ls.m.get('b:tsort')).k === 'n', [...l5.ls.m]);
check('storage that throws changes nothing but the memory', (() => { const broke = new Function('document', 'localStorage', hSrc + '\n' + tiers + '\n' + sorts + '\n' + packs + '\n' + dom + '\nreturn {TSORT, torSorted, h}')(doc, { getItem() { throw new Error('x'); }, setItem() { throw new Error('x'); } }); const o = broke.torSorted(ep, 'x', { redraw() {} }); o[0].children[1].click(); return broke.TSORT.k === 's'; })(), null);

// ---- edge cases ----
const only = api.torSorted([mk('Show.S02.COMPLETE.1080p-P1', 100, 40), mk('Show.Season.2.720p-P2', 50, 20)], 'none', {});
check('only packs found: no sort bar, the pack fold opens by itself', only.length === 1 && only[0].tag === 'details' && only[0].open === true && only[0].children[0].textContent === 'Season packs (2)', only.map(x => x.tag));
const one = api.torSorted([mk('Show.S02E05.1080p.WEB-DL', 50, 2)], 'none', {});
check('a single result needs no sort bar', one.length === 1 && one[0].className.includes('tor'), one.map(x => x.className));
check('nothing found shows the message', (r => r.length === 1 && r[0].textContent === 'No torrents found')(api.torSorted([], 'No torrents found', {})), null);
check('a result that cannot make a row is left out', api.torSorted([mk('Show.S02E05.1080p', 5, 1), { ...mk('Show.S02E06.1080p', 5, 1), make: () => null }], 'x', {}).filter(x => x.className.includes('tor')).length === 1, null);
const hostOpen = doc.createElement('div'); const first = api.torSorted(ep, 'x', { host: hostOpen }); hostOpen.replaceChildren(...first); first.at(-1).open = true;
check('a redraw keeps the pack fold open if it was open', api.torSorted(ep, 'x', { host: hostOpen }).at(-1).open === true, null);

// ---- wiring ----
check('the series episode list uses torSorted and redraws itself on a sort change; movies and anime keep the tiers', /tl\.replaceChildren\(\.\.\.torSorted\(t\.map\(x=>\(\{t:x\.t,n:x\.n,z:\+x\.z\|\|0,/.test(html) && /\{host:tl,redraw:fill\}/.test(html) && /torTiers\(\[\.\.\.ys\.map/.test(html) && /\{host:tl,episode:!movie\}/.test(html), null);
check('the sort bar is styled small', /\.sortbar button\{min-height:30px/.test(html), null);
console.log(fails.length ? '\n' + fails.length + ' failed' : '\nall ok'); process.exit(fails.length ? 1 : 0);

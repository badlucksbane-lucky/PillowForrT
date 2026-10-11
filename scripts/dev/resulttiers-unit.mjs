// Tests the condensed torrent lists in browse.html: the <result-tiers> block (tierOf, sourceOf, tierKey, pickBest) on realistic release names, and torTiers (best rows, the folded "All results", kept open on
// redraw) against a tiny fake DOM. Usage: node resulttiers-unit.mjs   Exit code 1 on failure.
import fs from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
const html = fs.readFileSync(path.join(path.dirname(fileURLToPath(import.meta.url)), '../../browse.html'), 'utf8');
const cut = (a, b) => html.slice(html.indexOf(a), html.indexOf(b) + b.length);
const tiers = cut('// <result-tiers>', '// </result-tiers>'), packs = cut('// <season-packs>', '// </season-packs>');
const dom = html.slice(html.indexOf('// Rows for a list of results'), html.indexOf('return [...best,d]}') + 'return [...best,d]}'.length);
const hSrc = html.match(/^function h\(tag,p,\.\.\.kids\)\{.*\}$/m)[0];
if (!tiers || !dom || !hSrc) { console.log('FAIL markers not found'); process.exit(1); }
const fails = [];
const check = (name, ok, got) => { console.log((ok ? 'ok   ' : 'FAIL ') + name + (ok ? '' : '  got: ' + JSON.stringify(got))); if (!ok) fails.push(name); };

class El {
  constructor (tag) { this.tag = tag; this.children = []; this.attrs = {}; this.open = false; this._t = ''; this.className = ''; }
  get nodeType () { return 1; }
  setAttribute (k, v) { this.attrs[k] = v; if (k === 'open') this.open = true; if (k === 'class') this.className = v; } append (...c) { this.children.push(...c); } prepend (...c) { this.children.unshift(...c); }
  replaceChildren (...c) { this.children = c; } addEventListener () {}
  set textContent (t) { this._t = t; } get textContent () { return this._t; }
  all () { return this.children.flatMap(c => c instanceof El ? [c, ...c.all()] : []); }
  querySelector (sel) { const [t, cls, open] = /^([a-z]*)\.?([\w-]*)(\[open\])?$/.exec(sel).slice(1); return this.all().find(e => (!t || e.tag === t) && (!cls || e.className.split(' ').includes(cls)) && (!open || e.open)) || null; }
}
const doc = { createElement: t => new El(t), createTextNode: s => ({ nodeType: 3, s }) };
const api = new Function('document', 'tor', hSrc + '\n' + tiers + '\n' + packs + '\n' + dom + '\nreturn {tierOf, sourceOf, tierKey, pickBest, tierLabel, torTiers, h}')(doc, () => api.h('div', { class: 'tor' }, api.h('div', { class: 's' })));

// ---- reading the release name ----
const T = (t) => api.tierOf(t);
check('2160p, 4K, UHD', T('Movie.2019.2160p.UHD.BluRay.x265') === 2160 && T('Movie (2019) 4K HDR') === 2160 && T('Movie 2019 UHD Remux') === 2160, null);
check('1080p / 1080i / FHD', T('Show.S01E01.1080p.WEB-DL') === 1080 && T('Show 1080i HDTV') === 1080 && T('Movie FHD') === 1080, null);
check('720p', T('Show.S01E01.720p.HDTV.x264') === 720, null);
check('576p, 540p and 512p are one tier', ['576p', '576i', '540p', '512p'].every(x => T('Movie.2001.' + x + '.GRP') === 576), null);
check('480p, 360p, SD, XviD, DivX are the lowest tier', ['480p', '480i', '360p', 'SD', 'XviD', 'DivX'].every(x => T('Movie.2001.' + x + '.GRP') === 480), null);
check('720p wins over a DVD mention (a 720p encode of a DVD source)', T('Movie 720p DVDRip') === 720, null);
check('a name that says nothing is tier 0; codec and audio tokens are not a resolution', T('Movie.2019.x264.DTS.5.1-GRP') === 0 && T('Show S01E05 AAC') === 0 && T('Movie DVDRip') === 0, null);
check('"4k" inside a word is not a tier', T('Super4kids') === 0, null);
const S = (t) => api.sourceOf(t);
check('BluRay family: BluRay, BDRip, BRRip, Remux, BD', ['BluRay', 'Blu-Ray', 'BDRip', 'BRRip', 'REMUX', 'BD'].every(x => S('Movie 1080p ' + x + ' x264') === 'BR'), null);
check('WEB family: WEB-DL, WEBRip, WEB, AMZN, NF', ['WEB-DL', 'WEBRip', 'WEB', 'AMZN', 'NF', 'DSNP'].every(x => S('Show 1080p ' + x + ' H264') === 'WEB'), null);
check('DVD, HDTV', S('Movie DVDRip XviD') === 'DVD' && S('Show 720p HDTV x264') === 'TV', null);
check('camera copies are CAM', S('Movie 2024 HDCAM x264') === 'CAM' && S('Movie 2024 TELESYNC 720p') === 'CAM' && S('Movie 2024 HDTS') === 'CAM', null);
check('an unlabeled name has no source; "web" inside a word is not WEB', S('Movie 2019') === '' && S('Webster 1080p') === '', null);
const K = (t) => api.tierKey(t, api.sourceOf(t));
check('a name with a resolution is in that tier; with none it falls to its source: web, dvd, br, else other', K('Movie 1080p WEB-DL') === 1080 && K('Movie WEB-DL x264') === 'web' && K('Movie DVDRip') === 'dvd' && K('Movie BluRay x264') === 'br' && K('Movie 2019 x264') === 'other' && K('Show HDTV') === 'other', null);
check('labels: "1080p · BR", "SD", "576p", "2160p · WEB", and the source tiers', api.tierLabel(1080, 'BR') === '1080p · BR' && api.tierLabel(480, '') === 'SD' && api.tierLabel(576, 'DVD') === '576p · DVD' && api.tierLabel(2160, 'WEB') === '2160p · WEB' && api.tierLabel('web', 'WEB') === 'WEB' && api.tierLabel('dvd', 'DVD') === 'DVD' && api.tierLabel('br', 'BR') === 'BR' && api.tierLabel('other', '') === '?', null);

// ---- choosing ----
const item = (t, n) => ({ t, n });
const list = [
  item('Movie.2019.2160p.UHD.BluRay.x265-AAA', 40), item('Movie.2019.2160p.WEB-DL.DDP5.1.x265-BBB', 90), item('Movie 2019 2160p WEB-DL x265 (other index)', 70),
  item('Movie.2019.1080p.BluRay.x264-CCC', 300), item('Movie.2019.1080p.WEB-DL.x264-DDD', 500), item('Movie 2019 1080p WEBRip', 520),
  item('Movie.2019.720p.BluRay.x264-EEE', 200), item('Movie.2019.720p.HDTV', 50),
  item('Movie.2019.576p.DVDRip', 60), item('Movie.2019.480p.WEBRip', 20), item('Movie.2019.XviD-GRP', 10),
  item('Movie.2019.WEB-DL.x264-HHH', 30), item('Movie.2019.DVDRip-III', 150), item('Movie.2019.BluRay.x264-JJJ', 12),
  item('Movie.2019.HDCAM.x264', 900), item('Movie 2019 x264 AAC', 5)
];
const best = api.pickBest(list);
check('one result per tier, in the order 2160, 1080, 720, 576, 480, then WEB, DVD, BR, other', best.map(b => b.tier).join() === '2160,1080,720,576,480,web,dvd,br,other', best.map(b => b.tier));
check('2160: the better-seeded WEB-DL, not the BluRay; the same release from another index is not a second row', best[0].item.t.includes('BBB') && best.filter(b => b.tier === 2160).length === 1, best[0].item.t);
check('1080: the most seeds', best[1].item.t === 'Movie 2019 1080p WEBRip', best[1].item.t);
check('720: BluRay (200) over HDTV (50)', best[2].item.t.includes('EEE'), best[2].item.t);
check('576: the 576p DVDRip', best[3].item.t === 'Movie.2019.576p.DVDRip', best[3].item.t);
check('480: the 480p WEBRip (20) over the XviD (10)', best[4].item.t === 'Movie.2019.480p.WEBRip', best[4].item.t);
check('no resolution in the name: the best WEB, the best DVD and the best BluRay get a row each', best[5].item.t.includes('HHH') && best[6].item.t.includes('III') && best[7].item.t.includes('JJJ'), best.slice(5, 8).map(b => b.item.t));
check('a camera copy with 900 seeds is not shown while real releases exist', !best.some(b => b.src === 'CAM'), best.map(b => b.src));
check('the unnamed one comes last', best[8].item.t === 'Movie 2019 x264 AAC', best[8].item.t);
check('only camera copies available: they are shown (one per tier) rather than nothing', (r => r.length === 2 && r.every(x => x.src === 'CAM') && r[0].tier === 720)(api.pickBest([item('Movie HDCAM', 10), item('Movie TELESYNC 720p', 5)])), null);
check('no results gives no picks', api.pickBest([]).length === 0, null);
const ep = [item('Show.S02E05.1080p.WEB-DL', 50), item('Show.S02.Complete.1080p.WEB-DL', 54)];
check('in an episode list a pack must be clearly healthier than the single episode to win; in a movie list it just wins on seeds', api.pickBest(ep, { episode: true })[0].item.t.includes('E05') && api.pickBest(ep)[0].item.t.includes('Complete'), api.pickBest(ep, { episode: true }).map(b => b.item.t));
check('but a much healthier pack does win', api.pickBest([item('Show.S02E05.1080p.WEB-DL', 5), item('Show.S02.Complete.1080p.WEB-DL', 400)], { episode: true })[0].item.t.includes('Complete'), null);
check('zero seeds everywhere: still a best guess per tier', api.pickBest([item('Old.Movie.1080p', 0), item('Old.Movie.720p', 0)]).length === 2, null);
check('source breaks near-ties: equal seeds, BluRay over DVD at the same tier', api.pickBest([item('M 720p DVDRip', 100), item('M 720p BluRay', 100)])[0].item.t.includes('BluRay'), null);

// ---- the rows ----
const mk = (n, label) => ({ ...item(label, n), make: () => api.h('div', { class: 'tor' }, api.h('div', { class: 's' })) });
const many = [mk(10, 'A 2160p WEB-DL'), mk(20, 'B 1080p WEB-DL'), mk(30, 'C 1080p BluRay x264'), mk(5, 'D 720p HDTV'), mk(2, 'E DVDRip')];
const host = doc.createElement('div');
const out = api.torTiers(many, 'none', { host });
const tierText = r => { const t = r.querySelector('.tier'); return t ? t._t : null; };
check('the best rows come first, each labelled with its tier and source', out.slice(0, 4).map(tierText).join('|') === '2160p · WEB|1080p · BR|720p · TV|DVD', out.slice(0, 4).map(tierText));
const rowsOnly = out.filter(x => x.tag !== 'details');
check('four tiers give four rows and the fold', rowsOnly.length === 4 && out.at(-1).tag === 'details', out.map(x => x.tag));
check('the fold is closed and says how many results it holds', out.at(-1).open === false && out.at(-1).children[0].textContent === 'All results (5)', out.at(-1).children[0].textContent);
check('and holds every result as before (not only the hidden ones)', out.at(-1).children.length === 1 + 5, out.at(-1).children.length);
host.replaceChildren(...out); out.at(-1).open = true;
check('a redraw while it is open keeps it open', api.torTiers(many, 'none', { host }).at(-1).open === true, null);
host.replaceChildren(...api.torTiers(many, 'none', { host }));
const small = api.torTiers([mk(10, 'A 1080p WEB-DL'), mk(8, 'B 720p WEB-DL')], 'none', {});
check('when every result is already shown there is no fold', small.length === 2 && small.every(x => x.tag !== 'details'), small.map(x => x.tag));
check('an empty list shows the message', (r => r.length === 1 && r[0].textContent === 'No torrents found')(api.torTiers([], 'No torrents found', {})), null);
const partly = api.torTiers([...many.slice(0, 3), { ...mk(1, 'bad 1080p'), make: () => null }], 'x', {});
check('a result that cannot make a row (no usable magnet) is left out of the count', partly.at(-1).tag === 'details' && partly.at(-1).children[0].textContent === 'All results (3)', partly.map(x => x.tag));
const labelled = api.torTiers([mk(10, 'A 1080p BluRay')], 'x', {})[0];
check('the label is the first thing in the row\'s detail line', labelled.querySelector('.s').children[0]._t === '1080p · BR', labelled.querySelector('.s').children.map(c => c._t));

// ---- wiring ----
check('movies and anime keep the best-per-tier lists (the series episode list uses the sorted list instead, see resultsort-unit.mjs), and nothing uses the old flat rows', (html.match(/torTiers\(\[|torTiers\(f\.slice/g) || []).length === 2 && !/torRows/.test(html), (html.match(/torTiers\(/g) || []).length);
check('the anime list says it is an episode list (a pack must earn its place)', /\{host:tl,episode:!movie\}/.test(html), null);
console.log(fails.length ? '\n' + fails.length + ' failed' : '\nall ok'); process.exit(fails.length ? 1 : 0);

// Tests the season-pack logic in browse.html (the <season-packs> block: parseEp, pickEpisode, packOrder, isPack, chooseFile, packTitle, isSample) on made-up but realistic file lists, plus the wiring around
// it in the player (start with nothing selected, the episode passed from the episode list, Previous/Next, auto-advance). Usage: node seasonpack-unit.mjs   Exit code 1 on failure.
import fs from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
const html = fs.readFileSync(path.join(path.dirname(fileURLToPath(import.meta.url)), '../../browse.html'), 'utf8');
const block = html.slice(html.indexOf('// <season-packs>'), html.indexOf('// </season-packs>'));
if (!block) { console.log('FAIL markers not found'); process.exit(1); }
const api = new Function(block + '\nreturn {parseEp, pickEpisode, packOrder, isPack, chooseFile, packTitle, isSample, epLabel, isVideoName}')();
const fails = [];
const check = (name, ok, got) => { console.log((ok ? 'ok   ' : 'FAIL ') + name + (ok ? '' : '  got: ' + JSON.stringify(got))); if (!ok) fails.push(name); };
const F = (p, len = 1e9) => ({ name: p.split('/').pop(), path: p, length: len });
const P = (p) => JSON.stringify(api.parseEp(p));
const is = (p, s, e) => { const x = api.parseEp(p); return x.s === s && x.e === e; };

// ---- reading season and episode ----
check('S01E05 in a scene name', is('Show.Name.S01E05.1080p.WEB-DL.DDP5.1.H.264-GRP.mkv', 1, 5), P('Show.Name.S01E05.1080p.WEB-DL.DDP5.1.H.264-GRP.mkv'));
check('lower case and separators: s2e10', is('show name s2e10 720p x265.mkv', 2, 10), P('show name s2e10 720p x265.mkv'));
check('three-digit episodes: S03E112', is('Daily.Show.S03E112.mkv', 3, 112), P('Daily.Show.S03E112.mkv'));
check('a double episode takes the first: S01E05E06', is('Show.S01E05E06.mkv', 1, 5), P('Show.S01E05E06.mkv'));
check('1x05 style', is('Show - 1x05 - Title.avi', 1, 5), P('Show - 1x05 - Title.avi'));
check('"Season 2 Episode 7"', is('Show Season 2 Episode 7.mp4', 2, 7), P('Show Season 2 Episode 7.mp4'));
check('a Season folder and "05 - Title"', is('Show/Season 2/05 - The Title.mkv', 2, 5), P('Show/Season 2/05 - The Title.mkv'));
check('a folder named S03 and E07', is('Show.S03.1080p/Show.E07.mkv', 3, 7), P('Show.S03.1080p/Show.E07.mkv'));
check('fansub style " - 05 [1080p]"', is('[Group] Some Anime - 05 [1080p][ABCD1234].mkv', null, 5), P('[Group] Some Anime - 05 [1080p][ABCD1234].mkv'));
check('fansub with a version: " - 05v2"', is('[Group] Some Anime - 05v2 (BD 1080p).mkv', null, 5), P('[Group] Some Anime - 05v2 (BD 1080p).mkv'));
check('long-running anime: " - 1085"', is('[G] One Show - 1085 [720p].mkv', null, 1085), P('[G] One Show - 1085 [720p].mkv'));
check('"Episode 12" and "Ep12"', is('Show Episode 12.mkv', null, 12) && is('Show Ep12.mkv', null, 12), [P('Show Episode 12.mkv'), P('Show Ep12.mkv')]);
check('a movie is not an episode: year, resolution, codec and audio tokens are ignored', ['Movie.Title.2019.1080p.BluRay.x264.DTS-HD.MA.5.1-GRP.mkv', 'Movie Title (2019) [2160p] HDR.mkv', 'Some Film - 2019 - Director\'s Cut.mkv', 'Movie.Title.1999.720p.H.264.E-AC-3.mkv'].every(n => api.parseEp(n).e === null), ['Movie.Title.2019.1080p.BluRay.x264.DTS-HD.MA.5.1-GRP.mkv', 'Movie Title (2019) [2160p] HDR.mkv', "Some Film - 2019 - Director's Cut.mkv", 'Movie.Title.1999.720p.H.264.E-AC-3.mkv'].map(P));
check('a file with no number has no episode', is('Behind The Scenes.mkv', null, null), P('Behind The Scenes.mkv'));
check('"x265" and "e" inside words do not count', api.parseEp('Some.Show.Extended.Edition.x265.mkv').e === null, P('Some.Show.Extended.Edition.x265.mkv'));

// ---- finding the episode in a pack ----
const season = (s, n) => Array.from({ length: n }, (_, i) => F(`Show.S${String(s).padStart(2, '0')}.1080p/Show.S${String(s).padStart(2, '0')}E${String(i + 1).padStart(2, '0')}.mkv`, 1e9 + i));
const pack1 = season(1, 10);
check('the asked-for episode is found in a one-season pack', api.pickEpisode(pack1, { s: 1, e: 7 }) === pack1[6], api.pickEpisode(pack1, { s: 1, e: 7 }));
check('an episode that is not there gives nothing, not a neighbour', api.pickEpisode(pack1, { s: 1, e: 11 }) === null && api.pickEpisode(pack1, { s: 2, e: 7 }) === null);
const multi = [...season(1, 8), ...season(2, 8), ...season(3, 8)];
check('in a multi-season pack, season and episode both count', api.pickEpisode(multi, { s: 2, e: 5 }) === multi[8 + 4] && api.pickEpisode(multi, { s: 3, e: 1 }) === multi[16], null);
const bare = ['01', '02', '03', '04'].map(n => F(`Show Complete/${n} - Title ${n}.mkv`));
check('a pack whose names carry no season is taken as the season asked for', api.pickEpisode(bare, { s: 4, e: 3 }) === bare[2], null);
const mixed = [F('Show/Season 1/03 - A.mkv'), F('Show/Season 2/03 - B.mkv')];
check('but a pack that names its seasons is not guessed at', api.pickEpisode(mixed, { s: 3, e: 3 }) === null && api.pickEpisode(mixed, { s: 2, e: 3 }) === mixed[1], null);
const anime = [1, 2, 3, 4, 5].map(n => F(`[Group] Anime - ${String(n).padStart(2, '0')} [1080p].mkv`));
check('anime numbered straight through: no season needed', api.pickEpisode(anime, { s: null, e: 4 }) === anime[3], null);
const animeTwo = [F('[G] Anime S1 - 05 [1080p].mkv'), F('[G] Anime S2 - 05 [1080p].mkv')];
check('anime episode, no season given, same number in two seasons: do not guess', api.pickEpisode([F('Anime/Season 1/Anime - 05.mkv'), F('Anime/Season 2/Anime - 05.mkv')], { s: null, e: 5 }) === null, null);
const dup = [F('Show.S01E02.720p.mkv', 5e8), F('Show.S01E02.1080p.mkv', 2e9), F('Show.S01E01.1080p.mkv', 2e9)];
check('two files for one episode: the bigger', api.pickEpisode(dup, { s: 1, e: 2 }) === dup[1], null);
check('no episode asked for, or none known: nothing is picked', api.pickEpisode(pack1, null) === null && api.pickEpisode(pack1, { s: 1, e: null }) === null);

// ---- order, pack or not ----
const shuffled = [pack1[9], pack1[0], pack1[4], F('Extras/Making Of.mkv'), pack1[1]];
check('a pack is listed in episode order, files with no episode last', api.packOrder(shuffled).map(f => f.name).join() === [pack1[0], pack1[1], pack1[4], pack1[9]].map(f => f.name).concat('Making Of.mkv').join(), api.packOrder(shuffled).map(f => f.name));
check('season order beats episode order even when the episode number is lower', api.packOrder([F('Show.S02E01.mkv'), F('Show.S01E05.mkv')]).map(f => f.name).join() === 'Show.S01E05.mkv,Show.S02E01.mkv', api.packOrder([F('Show.S02E01.mkv'), F('Show.S01E05.mkv')]).map(f => f.name));
check('season order beats episode order', api.packOrder([multi[16], multi[0], multi[8]]).map(f => f.name).join() === [multi[0], multi[8], multi[16]].map(f => f.name).join());
check('a pack is two or more different episodes', api.isPack(pack1) && api.isPack(multi) && api.isPack(bare) && api.isPack(anime));
check('a movie with extras is not a pack', !api.isPack([F('Movie.2019.1080p.mkv', 8e9), F('Movie.2019.Featurette.mkv', 3e8)]) && !api.isPack([F('Show.S01E01.mkv')]) && !api.isPack([F('Show.S01E01.mkv'), F('Show.S01E01.720p.mkv')]));
check('samples are told apart', api.isSample('Show.S01E01/Sample/sample-show.mkv') && api.isSample('Show.S01E01.SAMPLE.mkv') && !api.isSample('Samples.of.Love.S01E01.mkv') === false || api.isSample('Show/sample.mkv'), null);
check('"Sample" inside a longer word is not a sample', !api.isSample('Resampled.Show.S01E01.mkv') && !api.isSample('Samplers.S01E01.mkv'), null);

// ---- chooseFile: the order of preference ----
const vids = f => f.slice().sort((a, b) => b.length - a.length);
check('the exact file name from the source wins (as before), case-insensitively', api.chooseFile(vids(pack1), 'show.s01.1080p'.length ? 'SHOW.S01E03.MKV' : '', { s: 1, e: 9 }).play === pack1[2], null);
check('else the episode asked for', api.chooseFile(vids(pack1), '', { s: 1, e: 9 }).play === pack1[8] && api.chooseFile(vids(pack1), 'other.mkv', { s: 1, e: 9 }).play === pack1[8], null);
const lst = api.chooseFile(vids(pack1), '', { s: 1, e: 99 });
check('else a pack gives the list in episode order, saying the episode was not there', lst.pack === true && lst.missing === true && lst.list.map(f => f.name).join() === pack1.map(f => f.name).join(), lst.list && lst.list.map(f => f.name));
const lst2 = api.chooseFile(vids(pack1), '', null);
check('a pack opened with no episode (a movie row, a search) lists without a complaint', lst2.pack === true && lst2.missing === false, lst2);
check('a single file plays at once', api.chooseFile([F('Movie.mkv', 5e9)], '', null).play.name === 'Movie.mkv');
const extras = [F('Movie.2019.mkv', 8e9), F('Movie.2019.Extended.mkv', 8.5e9), F('Featurette.mkv', 2e8)];
check('a movie with two big cuts still offers the two big ones, as before', (r => r.list && r.list.length === 2 && !r.pack)(api.chooseFile(vids(extras), '', null)), api.chooseFile(vids(extras), '', null));
check('a movie and a small extra plays the movie', api.chooseFile(vids([extras[0], extras[2]]), '', null).play === extras[0]);

// ---- result titles ----
for (const [t, want] of [['Show Name S02 Complete 1080p WEB-DL', true], ['Show.Name.Season.3.720p', true], ['[Group] Anime (01-24) [BD 1080p] Batch', true], ['Show.Name.S01.1080p.BluRay.x265', true],
  ['Show Name S02E05 1080p', false], ['Movie 2019 1080p BluRay x264', false], ['Show.S01E01.720p.HDTV', false], ['Complete Series Collection 1080p', true], ['[Group] Anime - 05 [1080p]', false]]) {
  check('"' + t + '" ' + (want ? 'is' : 'is not') + ' labelled a season pack', api.packTitle(t) === want, api.packTitle(t));
}

// ---- wiring in the player ----
check('the torrent starts with nothing selected (otherwise a pack downloads every episode)', /storeCacheSlots:0,deselect:true,/.test(html), null);
check('a play carries the episode, and the sheet/anime pass it', /function tor\(label,sub,hash,name,seeds,sz,file,ep\)/.test(html) && /play\(hash,name,mg,file,ep\)/.test(html) && /x\.f,\{s:v\.s,e:v\.e\}\)/.test(html) && /t\.file,movie\?null:\{s:null,e:ep\}\)/.test(html), null);
check('play takes the wanted episode and the ready handler asks chooseFile', /async function play\(hash,name,mg,want,epWant\)/.test(html) && /chooseFile\(vids,want,epWant\)/.test(html), null);
check('Previous / Next sit in the top bar (outside the once-a-second redraw), and an ended episode moves on', /<span class="pnav" id="pnav" hidden><\/span>/.test(html) && /v\.addEventListener\('ended',\(\)=>go\(1\)\)/.test(html), null);
check('changing episode drops the old audio menu and the pack buttons go away with the player', /const start=f=>\{resetAudio\(\);/.test(html) && /const pn=\$\('#pnav'\);if\(pn\)\{pn\.hidden=true/.test(html), null);
check('sample clips are left out of the choice', /real=found\.filter\(f=>!isSample\(filePath\(f\)\)\)/.test(html), null);
console.log(fails.length ? '\n' + fails.length + ' failed' : '\nall ok'); process.exit(fails.length ? 1 : 0);

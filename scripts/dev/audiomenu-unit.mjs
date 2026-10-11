// Tests the player's audio-track menu and the removed Download entry in browse.html (the <audio-tracks> block: audioCount, trackLabel, audioPicker) with a fake PFAudio, <select> and <video>.
// Usage: node audiomenu-unit.mjs   Exit code 1 on failure.
import fs from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
const html = fs.readFileSync(path.join(path.dirname(fileURLToPath(import.meta.url)), '../../browse.html'), 'utf8');
const block = html.slice(html.indexOf('// <audio-tracks>'), html.indexOf('// </audio-tracks>'));
if (!block) { console.log('FAIL markers not found'); process.exit(1); }
const fails = [];
const check = (name, ok, got) => { console.log((ok ? 'ok   ' : 'FAIL ') + name + (ok ? '' : '  got: ' + JSON.stringify(got))); if (!ok) fails.push(name); };
const tick = () => new Promise(r => setTimeout(r, 0));

// ---- a tiny DOM: just what h() and the menu use ----
class El { constructor (tag) { this.tag = tag; this.children = []; this.attrs = {}; this.hidden = false; this.value = ''; this.onchange = null; }
  setAttribute (k, v) { this.attrs[k] = v; } append (...c) { this.children.push(...c); } replaceChildren (...c) { this.children = c; }
  set textContent (t) { this._t = t; } get textContent () { return this._t; } addEventListener () {} }
const documentFake = { createElement: t => new El(t), createTextNode: s => ({ nodeType: 3, s }) };
const hSrc = html.match(/^function h\(tag,p,\.\.\.kids\)\{.*\}$/m)[0];
const mk = (extra = {}) => {
  const env = { BT: { audio: null }, loadScript: async () => { env.loaded++; }, loaded: 0, document: documentFake, PFAudio: null, Intl, ...extra };
  const f = new Function(...Object.keys(env), hSrc + '\n' + block + '\nreturn {audioCount, trackLabel, audioPicker, langName}');
  return { env, api: f(...Object.values(env)) };
};
const bytes = s => Uint8Array.from(Buffer.from(s, 'latin1'));

// ---- counting tracks in the first 128 KB ----
{ const { api } = mk();
  check('an MKV with two audio tracks counts two', api.audioCount(bytes('\x1aE\xdf\xa3....V_VIDEO...V_MPEG4/ISO/AVC....A_EAC3....A_AAC....S_TEXT/UTF8')) === 2);
  check('an MKV with one counts one', api.audioCount(bytes('xxV_MPEG4/ISO/AVC..A_AAC..S_TEXT/ASS')) === 1);
  check('three tracks of the same codec count three', api.audioCount(bytes('A_AAC....A_AAC...A_AAC')) === 3);
  check('an MKV with no audio counts zero', api.audioCount(bytes('V_VP9 S_TEXT/UTF8')) === 0);
  const mp4 = n => '\x00\x00\x00\x18ftypisom....moov' + Array.from({ length: n }, () => '....hdlr\x00\x00\x00\x00\x00\x00\x00\x00soun....').join('');
  check('an MP4 with two sound handlers counts two', api.audioCount(bytes(mp4(2))) === 2);
  check('an MP4 with one counts one', api.audioCount(bytes(mp4(1))) === 1);
  check('an MP4 whose moov box is not up front counts zero (cannot tell)', api.audioCount(bytes('\x00\x00\x00\x18ftypisom....mdat....')) === 0);
  check('a big array does not overflow the string builder', api.audioCount(new Uint8Array(131072).fill(65)) === 0);
}
// ---- labels ----
{ const { api } = mk();
  const L = (o) => api.trackLabel({ index: 0, codec: 'aac', lang: '', name: '', channels: 2, ...o });
  check('a language code becomes the language name with codec and channels', L({ lang: 'jpn', codec: 'aac', channels: 2 }) === 'Japanese · AAC · stereo', L({ lang: 'jpn' }));
  check('5.1 E-AC-3 English', L({ lang: 'eng', codec: 'eac3', channels: 6 }) === 'English · E-AC-3 · 5.1', L({ lang: 'eng', codec: 'eac3', channels: 6 }));
  check('with no language the track\'s own name is used', L({ lang: 'und', name: 'Commentary' }) === 'Commentary · AAC · stereo', L({ lang: 'und', name: 'Commentary' }));
  check('with neither, it is "Track N"', L({ index: 1 }) === 'Track 2 · AAC · stereo', L({ index: 1 }));
  check('an unknown codec is shown upper case, odd channel counts as "n ch"', L({ lang: 'fra', codec: 'dts', channels: 3 }) === 'French · DTS · 3 ch', L({ lang: 'fra', codec: 'dts', channels: 3 }));
  check('a code Intl does not know falls back to the code itself', typeof api.langName('qqq') === 'string' && api.langName('qqq').length > 0 && api.langName('') === '', api.langName('qqq'));
}
// ---- the menu ----
const tracks = [{ index: 0, codec: 'eac3', lang: 'eng', name: '', channels: 6 }, { index: 1, codec: 'aac', lang: 'jpn', name: '', channels: 2 }, { index: 2, codec: 'dts', lang: 'fra', name: '', channels: 6 }];
const fakePF = (over = {}) => { const st = { selects: [], disposed: false, current: -1 };
  return { st, open: async () => ({ tracks, primaryIndex: 0, get current () { return st.current; }, select: async (i, o) => { st.selects.push([i, o]); if (over.refuse && over.refuse.includes(i)) throw new Error('cannot decode ' + tracks[i].codec); st.current = i; return i; }, dispose: () => { st.disposed = true; } }) }; };
const video = (o = {}) => ({ isConnected: true, ...o });
const aud = () => ({ textContent: '', hidden: true });
{ // Chrome-style: via Mediabunny
  const pf = fakePF({ refuse: [2] }); const { env, api } = mk({ PFAudio: pf }); const sel = new El('select'); sel.hidden = true; const a = aud();
  const ok = await api.audioPicker(video(), a, sel, {});
  check('with several tracks the menu appears, one option per track, the primary selected', ok === true && !sel.hidden && sel.children.length === 3 && sel.value === 0 && sel.children[1].textContent === 'Japanese · AAC · stereo', [ok, sel.hidden, sel.children.length, sel.value]);
  check('the audio helper was loaded once, and the controller is kept for cleanup', env.loaded === 1 && env.BT.audio !== null);
  check('and nothing is switched until you choose', pf.st.selects.length === 0, pf.st.selects);
  sel.value = 1; sel.onchange(); await tick();
  check('choosing a track plays it and silences the video\'s own sound', JSON.stringify(pf.st.selects) === '[[1,{"silenceVideo":true}]]', pf.st.selects);
  check('and the "switching" note goes away', a.hidden === true, a);
  sel.value = 2; sel.onchange(); await tick();
  check('a track the device cannot decode says so and puts the menu back on the playing track', /Cannot play that track here \(cannot decode dts\)/.test(a.textContent) && a.hidden === false && sel.value === 1, [a.textContent, sel.value]);
}
{ const pf = fakePF({ refuse: [2] }); const { api } = mk({ PFAudio: pf }); const sel = new El('select'); const a = aud();
  await api.audioPicker(video(), a, sel, {}); sel.value = 2; sel.onchange(); await tick();
  check('a refused first choice falls back to the primary track in the menu', sel.value === 0 && /cannot decode/.test(a.textContent), [sel.value, a.textContent]);
}
{ // fewer than two, closed, already taken
  const one = { open: async () => ({ tracks: [tracks[0]], primaryIndex: 0, current: -1, select: async () => 0, dispose () { one.disposed = true; } }) };
  const { api } = mk({ PFAudio: one }); const sel = new El('select'); sel.hidden = true;
  check('a file that turns out to have one track shows no menu and frees the controller', (await api.audioPicker(video(), aud(), sel, {})) === false && sel.hidden === true && one.disposed === true, sel.hidden);
  const pf = fakePF(); const m2 = mk({ PFAudio: pf }); const s2 = new El('select'); s2.hidden = true;
  check('a player closed while the tracks were being read shows nothing and frees the controller', (await m2.api.audioPicker(video({ isConnected: false }), aud(), s2, {})) === false && s2.hidden === true && pf.st.disposed, s2.hidden);
  const pf3 = fakePF(); const m3 = mk({ PFAudio: pf3 }); m3.env.BT.audio = { dispose () {} };
  check('if another audio path already owns the sound the menu stays out of it', (await m3.api.audioPicker(video(), aud(), new El('select'), {})) === false && pf3.st.disposed, null);
  const m4 = mk({ PFAudio: { open: async () => { throw new Error('unreadable'); } } }); let err = ''; try { await m4.api.audioPicker(video(), aud(), new El('select'), {}); } catch (e) { err = e.message; }
  check('unreadable tracks reject, so the caller can fall back to the old behaviour', err === 'unreadable', err);
}
{ // AC-3 first track: played in the page at once
  const pf = fakePF(); const { api } = mk({ PFAudio: pf }); let said = null;
  await api.audioPicker(video(), aud(), new El('select'), { soft: true, nosound: w => { said = w; } });
  check('when the first track is one only the page can decode, it is played straight away (no silencing needed)', JSON.stringify(pf.st.selects) === '[[0,null]]' || (pf.st.selects.length === 1 && pf.st.selects[0][0] === 0 && !pf.st.selects[0][1]), pf.st.selects);
  const pf2 = fakePF({ refuse: [0] }); const m = mk({ PFAudio: pf2 }); let said2 = null;
  await m.api.audioPicker(video(), aud(), new El('select'), { soft: true, nosound: w => { said2 = w; } });
  check('and if that fails, the "no sound" message is given with the reason', /cannot decode eac3/.test(said2), said2);
}
{ // Safari-style: the browser lists audioTracks itself
  const nat = [{ language: 'eng', label: 'English', enabled: true }, { language: 'jpn', label: 'Japanese', enabled: false }];
  const { env, api } = mk({ PFAudio: fakePF() }); const sel = new El('select'); const v = video({ audioTracks: nat });
  const ok = await api.audioPicker(v, aud(), sel, {});
  check('a browser with audioTracks gets a menu from them and loads nothing', ok === true && env.loaded === 0 && sel.children.length === 2 && sel.value === 0 && sel.children[1].textContent === 'Japanese', [ok, env.loaded, sel.children.length]);
  sel.value = 1; sel.onchange();
  check('choosing enables that track and disables the others', nat[0].enabled === false && nat[1].enabled === true, nat);
  const single = mk({ PFAudio: fakePF() }); const r = await single.api.audioPicker(video({ audioTracks: [nat[0]] }), aud(), new El('select'), {});
  check('a single native track does not count: the helper is used instead', single.env.loaded === 1, r);
}
{ // wiring in the page
  check('the video has no Download entry: controlsList nodownload', /h\('video',\{controls:true,controlsList:'nodownload'/.test(html), null);
  check('and no "Save video as" context menu', /oncontextmenu:e=>e\.preventDefault\(\)/.test(html), null);
  check('the top bar has an audio menu, hidden until there is something to choose', /<select id="paudio" aria-label="Audio track" hidden><\/select>/.test(html), null);
  check('stopping the player hides and empties the menu', /const pa=\$\('#paudio'\);if\(pa\)\{pa\.hidden=true;pa\.onchange=null;pa\.replaceChildren\(\)\}/.test(html), null);
  check('the menu is only offered for files with two or more audio tracks, and falls back to the old path if it fails', /if\(audioCount\(bytes\)>=2\)audioPicker\(v,aud,sel,\{soft,nosound\}\)\.then\(ok=>\{if\(!ok\)before\(\)/.test(html) && /,before\);else before\(\)/.test(html), null);
  check('the "no sound" text points at the menu when there is one', /Choose another audio track above\./.test(html), null);
}
console.log(fails.length ? '\n' + fails.length + ' failed' : '\nall ok'); process.exit(fails.length ? 1 : 0);

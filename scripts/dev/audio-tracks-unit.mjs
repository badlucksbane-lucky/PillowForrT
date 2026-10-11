// Tests btclient/audio-entry.js (the in-page audio: track list, track switching, silencing the video's own sound, the old attach) without a browser: the real file is bundled by esbuild against a fake
// Mediabunny and run with a fake Web Audio and a fake <video>. Usage: node audio-tracks-unit.mjs   Exit code 1 on failure.
import fs from 'node:fs';
import path from 'node:path';
import vm from 'node:vm';
import { fileURLToPath } from 'node:url';
const root = path.join(path.dirname(fileURLToPath(import.meta.url)), '../..');
const esbuild = await import(path.join(root, 'btclient/node_modules/esbuild/lib/main.js'));
const fake = `
export const ALL_FORMATS = {}
export class UrlSource { constructor (u) { this.url = u } }
export class Input {
  constructor (o) { this.url = o.source.url; globalThis.__inputs.push(this); this.disposed = false }
  async getAudioTracks () { if (globalThis.__fail) throw new Error('unreadable'); return globalThis.__tracks }
  async getPrimaryAudioTrack () { return globalThis.__tracks.find(t => t.primary) || globalThis.__tracks[0] || null }
  dispose () { this.disposed = true }
}
export class AudioBufferSink {
  constructor (track) { this.track = track; globalThis.__sinks.push(this) }
  async * buffers (from) { this.from = from; for (let i = 0; i < 3; i++) yield { buffer: { duration: 0.5, from: this.track.id, i }, timestamp: from + i * 0.5 } }
}`;
const built = await esbuild.build({
  entryPoints: [path.join(root, 'btclient/audio-entry.js')], bundle: true, write: false, format: 'iife', platform: 'browser', target: 'es2022', logLevel: 'silent',
  plugins: [{ name: 'fake', setup (b) {
    b.onResolve({ filter: /^mediabunny$/ }, () => ({ path: 'mediabunny', namespace: 'fake' }));
    b.onResolve({ filter: /^@mediabunny\/ac3$/ }, () => ({ path: 'ac3', namespace: 'fake' }));
    b.onLoad({ filter: /^mediabunny$/, namespace: 'fake' }, () => ({ contents: fake, loader: 'js' }));
    b.onLoad({ filter: /^ac3$/, namespace: 'fake' }, () => ({ contents: 'export const registerAc3Decoder = () => { globalThis.__ac3 = true }', loader: 'js' }));
  } }]
});
const bundle = built.outputFiles[0].text;
const fails = [];
const check = (name, ok, got) => { console.log((ok ? 'ok   ' : 'FAIL ') + name + (ok ? '' : '  got: ' + JSON.stringify(got))); if (!ok) fails.push(name); };
const tick = (n = 1) => new Promise(r => setTimeout(r, n));

function env (tracks, opts = {}) {
  const log = { ctxs: [], sources: [], buffers: [], stopped: 0, docListeners: new Map() };
  class Ctx {
    constructor () { this.currentTime = 0; this.state = 'running'; this.destination = { dest: true }; this.closed = false; log.ctxs.push(this) }
    createGain () { this.gainNode = { gain: { value: 1 }, connect: d => { this.gainTo = d } }; return this.gainNode }
    createBufferSource () { const n = { playbackRate: { value: 1 }, connect: g => { n.to = g }, start: () => { n.started = true; log.buffers.push(n) }, stop: () => { n.stopped = true; log.stopped++ } }; return n }
    createMediaElementSource (v) { if (v.__srcMade) throw new Error('InvalidStateError'); v.__srcMade = true; log.sources.push(v); return { connect () { throw new Error('must stay unconnected') } } }
    async resume () { this.state = 'running' }
    async close () { this.closed = true }
  }
  const listeners = new Map();
  const video = {
    currentSrc: 'blob:video', paused: false, seeking: false, ended: false, readyState: 4, playbackRate: 1, currentTime: 10, volume: 0.8, muted: false,
    addEventListener (e, f) { (listeners.get(e) || listeners.set(e, new Set()).get(e)).add(f) }, removeEventListener (e, f) { listeners.get(e)?.delete(f) },
    emit (e) { listeners.get(e)?.forEach(f => f()) }, count () { let n = 0; listeners.forEach(s => { n += s.size }); return n }
  };
  const sandbox = {
    __tracks: tracks, __sinks: [], __inputs: [], __fail: !!opts.fail, AudioContext: Ctx, setTimeout, clearTimeout, setInterval, clearInterval, console,
    document: { addEventListener (e, f) { log.docListeners.set(e, f) }, removeEventListener (e) { log.docListeners.delete(e) } }
  };
  sandbox.globalThis = sandbox;
  vm.runInNewContext(bundle, sandbox);
  return { P: sandbox.PFAudio, video, log, sandbox };
}
const T = (id, codec, o = {}) => ({ id, codec, languageCode: o.lang || 'und', name: o.name || null, numberOfChannels: o.ch || 2, primary: !!o.primary, canDecode: async () => o.can !== false });
const three = () => [T(1, 'ac3', { lang: 'eng', ch: 6, primary: true }), T(2, 'aac', { lang: 'jpn' }), T(3, 'dts', { lang: 'fra', can: false })];

{ // open lists the tracks and starts nothing
  const e = env(three()); const c = await e.P.open(e.video);
  check('open lists every audio track with codec, language, channels and the primary one', c.tracks.length === 3 && c.tracks[0].codec === 'ac3' && c.tracks[1].lang === 'jpn' && c.tracks[0].channels === 6 && c.primaryIndex === 0 && c.tracks[2].index === 2, c.tracks);
  check('and starts nothing: no audio context, no sink, no listeners on the video', e.log.ctxs.length === 0 && e.sandbox.__sinks.length === 0 && e.video.count() === 0, [e.log.ctxs.length, e.sandbox.__sinks.length, e.video.count()]);
  check('the AC-3 decoder was registered', e.sandbox.__ac3 === true);
  check('the file is read from the video\'s own source', e.sandbox.__inputs[0].url === 'blob:video');
  const second = env([T(7, 'aac'), T(8, 'aac', { primary: true })]); const c2 = await second.P.open(second.video);
  check('the primary index follows what the file marks as primary, not the first', c2.primaryIndex === 1, c2.primaryIndex);
  c.dispose(); check('dispose frees the input', e.sandbox.__inputs[0].disposed === true);
}
{ // switching tracks
  const e = env(three()); const c = await e.P.open(e.video);
  await c.select(1, { silenceVideo: true }); await tick(20);
  check('choosing a track makes one audio context, takes the video\'s sound once, and decodes that track', e.log.ctxs.length === 1 && e.log.sources.length === 1 && e.sandbox.__sinks.length === 1 && e.sandbox.__sinks[0].track.id === 2 && c.current === 1, [e.log.ctxs.length, e.log.sources.length, e.sandbox.__sinks.map(s => s.track.id)]);
  check('its sound is scheduled into the gain node, which feeds the speakers', e.log.buffers.length >= 1 && e.log.buffers[0].to === e.log.ctxs[0].gainNode && e.log.ctxs[0].gainTo === e.log.ctxs[0].destination, e.log.buffers.length);
  check('the gain follows the video\'s volume', e.log.ctxs[0].gainNode.gain.value === 0.8, e.log.ctxs[0].gainNode.gain.value);
  e.video.muted = true; e.video.emit('volumechange');
  check('and its mute', e.log.ctxs[0].gainNode.gain.value === 0, e.log.ctxs[0].gainNode.gain.value);
  e.video.muted = false; e.video.emit('volumechange');
  const stoppedBefore = e.log.stopped;
  await c.select(0, { silenceVideo: true }); await tick(20);
  check('switching again changes the sink, keeps the one context, and does not take the sound twice', e.log.ctxs.length === 1 && e.log.sources.length === 1 && e.sandbox.__sinks.length === 2 && e.sandbox.__sinks[1].track.id === 1 && c.current === 0, [e.log.ctxs.length, e.log.sources.length, e.sandbox.__sinks.length]);
  check('the old track\'s scheduled sound is stopped when the track changes', e.log.stopped > stoppedBefore, [stoppedBefore, e.log.stopped]);
  e.video.currentTime = 42; e.video.emit('seeked'); await tick(20);
  const lastFrom = e.sandbox.__sinks.map(s => s.from).filter(x => x !== undefined).at(-1);
  check('a seek restarts the current track from the new position (a little before it)', Math.abs(lastFrom - 41.95) < 1e-9, e.sandbox.__sinks.map(s => s.from));
  e.video.paused = true; e.video.emit('pause'); await tick(5);
  const n = e.log.buffers.length; e.video.emit('pause'); await tick(20);
  check('nothing is scheduled while the video is paused', e.log.buffers.length === n, [n, e.log.buffers.length]);
  c.dispose();
}
{ // an undecodable choice changes nothing
  const e = env(three()); const c = await e.P.open(e.video);
  let err = ''; try { await c.select(2, { silenceVideo: true }); } catch (x) { err = x.message; }
  check('a track that cannot be decoded is refused with the codec in the message', /cannot decode dts/.test(err), err);
  check('and nothing was touched: no context, the video\'s sound not taken, no sink', e.log.ctxs.length === 0 && e.log.sources.length === 0 && e.sandbox.__sinks.length === 0 && c.current === -1, [e.log.ctxs.length, e.log.sources.length]);
  let bad = ''; try { await c.select(9); } catch (x) { bad = x.message; }
  check('a track number that does not exist is refused', /no such/.test(bad), bad);
  await c.select(1, { silenceVideo: true });
  let again = ''; try { await c.select(2, { silenceVideo: true }); } catch (x) { again = x.message; }
  check('a refusal after a working choice keeps the working one', /cannot decode/.test(again) && c.current === 1 && e.sandbox.__sinks.length === 1, [again, c.current]);
  c.dispose();
}
{ // the sound of the video cannot be taken twice by one page
  const e = env(three()); const c = await e.P.open(e.video); e.video.__srcMade = true;
  let err = ''; try { await c.select(1, { silenceVideo: true }); } catch (x) { err = x.message; }
  check('if the video\'s sound is already taken the choice fails clearly, not silently', /cannot take over/.test(err) && e.sandbox.__sinks.length === 0, [err, e.sandbox.__sinks.length]);
  c.dispose();
}
{ // the old attach: primary track, video's own sound left alone
  const e = env(three()); const c = await e.P.attach(e.video); await tick(20);
  check('attach plays the primary track and does not touch the video\'s own sound', e.sandbox.__sinks.length === 1 && e.sandbox.__sinks[0].track.id === 1 && e.log.sources.length === 0 && c.current === 0, [e.sandbox.__sinks.length, e.log.sources.length]);
  const d = env([T(1, 'dts', { can: false, primary: true })]); let err = ''; try { await d.P.attach(d.video); } catch (x) { err = x.message; }
  check('attach on an undecodable primary throws and frees what it opened', /cannot decode/.test(err) && d.sandbox.__inputs[0].disposed === true, err);
  const z = env([]); let err2 = ''; try { await z.P.attach(z.video); } catch (x) { err2 = x.message; }
  check('a file with no audio throws "no audio track"', /no audio track/.test(err2) && z.sandbox.__inputs[0].disposed, err2);
  const f = env(three(), { fail: true }); let err3 = ''; try { await f.P.open(f.video); } catch (x) { err3 = x.message; }
  check('an unreadable file throws and frees the input', /unreadable/.test(err3) && f.sandbox.__inputs[0].disposed, err3);
  c.dispose();
}
{ // dispose
  const e = env(three()); const c = await e.P.open(e.video); await c.select(1, { silenceVideo: true }); await tick(20);
  check('while playing, the video has listeners and the page has a tap listener', e.video.count() > 0 && e.log.docListeners.has('pointerdown'), e.video.count());
  c.dispose();
  check('dispose closes the context, stops the sound, and removes every listener', e.log.ctxs[0].closed && e.video.count() === 0 && !e.log.docListeners.has('pointerdown') && e.log.buffers.every(b => b.stopped), [e.log.ctxs[0].closed, e.video.count()]);
  const sinks = e.sandbox.__sinks.length; e.video.emit('playing'); await tick(10);
  check('events after dispose start nothing', e.sandbox.__sinks.length === sinks);
  let err = ''; try { await c.select(0); } catch (x) { err = x.message; }
  check('and a choice after dispose is refused', /closed/.test(err), err);
}
console.log(fails.length ? '\n' + fails.length + ' failed' : '\nall ok'); process.exit(fails.length ? 1 : 0);

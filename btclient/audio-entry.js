// In-page audio for files whose sound the <video> cannot give us: a track the browser cannot decode (AC-3, E-AC-3: Chrome on Android has neither), or a track other than the one it plays (Chrome has no
// audio-track switching). The picture still plays in the <video>; this reads the same file again through the service worker, demuxes it with Mediabunny, decodes the chosen audio track (the FFmpeg
// AC-3/E-AC-3 decoder is WASM, in a worker) and plays it through Web Audio, clocked to the video element: restarted on play, seek and buffering, and whenever the two drift apart.
//
//   PFAudio.open(video, onstate)  -> {tracks, primaryIndex, current, select(index, {silenceVideo}), dispose()}   lists the file's audio tracks, starts nothing
//   PFAudio.attach(video, onstate) -> the same controller, already playing the primary track (the video has no sound of its own)
//   select(i, {silenceVideo: true}) plays track i and silences the video's own sound (it is routed into a Web Audio node nobody listens to); that cannot be undone for this element
import { Input, ALL_FORMATS, UrlSource, AudioBufferSink } from 'mediabunny'
import { registerAc3Decoder } from '@mediabunny/ac3'

registerAc3Decoder()

const AHEAD = 3 // seconds of audio scheduled in advance
const DRIFT = 0.25 // seconds of disagreement with the video before the audio restarts
const sleep = ms => new Promise(resolve => setTimeout(resolve, ms))

async function open (video, onstate = () => {}) {
  const input = new Input({ source: new UrlSource(video.currentSrc), formats: ALL_FORMATS })
  const drop = () => { try { input.dispose() } catch (e) {} }
  let all, primary
  try {
    all = await input.getAudioTracks()
    if (!all.length) throw new Error('no audio track')
    primary = await input.getPrimaryAudioTrack()
  } catch (e) { drop(); throw e }
  const primaryIndex = Math.max(0, all.findIndex(t => primary && t.id === primary.id))
  const tracks = all.map((t, index) => ({ index, id: t.id, codec: t.codec, lang: t.languageCode || '', name: t.name || '', channels: t.numberOfChannels }))

  let ctx = null // made on the first select, from a tap
  let gain = null
  let sink = null
  let current = -1
  let silenced = false
  let attached = false
  let poll = null
  let run = 0 // each start() owns one generation; bumping it stops the previous one
  let nodes = []
  let base = null // {t0, c0, rate}: video time t0 played when the audio clock read c0
  let dead = false

  const volume = () => { if (gain) gain.gain.value = video.muted ? 0 : video.volume }
  const silence = () => {
    run++
    base = null
    for (const n of nodes) { try { n.stop() } catch (e) {} }
    nodes = []
  }
  const wanted = () => !dead && !video.paused && !video.seeking && !video.ended && video.readyState >= 3

  async function start () {
    silence()
    if (!wanted() || !sink) return
    const mine = run
    const mySink = sink
    try { await ctx.resume() } catch (e) {}
    if (mine !== run) return
    const rate = video.playbackRate || 1
    const t0 = video.currentTime
    const c0 = ctx.currentTime + 0.05
    base = { t0, c0, rate }
    try {
      for await (const { buffer, timestamp } of mySink.buffers(Math.max(0, t0 - 0.05))) {
        if (mine !== run) return
        const when = c0 + (timestamp - t0) / rate
        while (mine === run && when - ctx.currentTime > AHEAD) await sleep(250)
        if (mine !== run) return
        const node = ctx.createBufferSource()
        node.buffer = buffer
        node.playbackRate.value = rate
        node.connect(gain)
        const late = ctx.currentTime - when
        if (late > 0) {
          if (late * rate >= buffer.duration) continue
          node.start(ctx.currentTime, late * rate)
        } else node.start(when)
        node.onended = () => { nodes = nodes.filter(x => x !== node) }
        nodes.push(node)
      }
    } catch (e) {
      if (mine === run) onstate('audio stopped: ' + (e.message || e))
    }
  }

  const events = ['playing', 'pause', 'waiting', 'seeking', 'seeked', 'ratechange', 'ended']
  const restart = () => { start() }
  const wake = () => { if (ctx && ctx.state === 'suspended') ctx.resume().catch(() => {}) }

  async function select (index, { silenceVideo = false } = {}) {
    if (dead) throw new Error('closed')
    const track = all[index]
    if (!track) throw new Error('no such audio track')
    if (!(await track.canDecode())) throw new Error('cannot decode ' + track.codec) // before anything is silenced: the old sound stays
    if (dead) throw new Error('closed')
    if (!ctx) {
      ctx = new AudioContext()
      gain = ctx.createGain()
      gain.connect(ctx.destination)
    }
    if (silenceVideo && !silenced) {
      try { ctx.createMediaElementSource(video) } catch (e) { throw new Error('cannot take over the sound of this video') }
      silenced = true
    }
    sink = new AudioBufferSink(track)
    current = index
    if (!attached) {
      attached = true
      events.forEach(e => video.addEventListener(e, restart))
      video.addEventListener('volumechange', volume)
      document.addEventListener('pointerdown', wake)
      poll = setInterval(() => {
        if (!base || !wanted()) return
        const at = base.t0 + (ctx.currentTime - base.c0) * base.rate
        if (Math.abs(at - video.currentTime) > DRIFT) start()
      }, 1000)
    }
    volume()
    start()
    return index
  }

  return {
    tracks,
    primaryIndex,
    get current () { return current },
    select,
    dispose () {
      dead = true
      silence()
      if (poll) clearInterval(poll)
      if (attached) {
        events.forEach(e => video.removeEventListener(e, restart))
        video.removeEventListener('volumechange', volume)
        document.removeEventListener('pointerdown', wake)
      }
      drop()
      if (ctx) ctx.close().catch(() => {})
    }
  }
}

async function attach (video, onstate = () => {}) {
  const c = await open(video, onstate)
  try { await c.select(c.primaryIndex) } catch (e) { c.dispose(); throw e }
  return c
}

globalThis.PFAudio = { open, attach, codec: async video => {
  const input = new Input({ source: new UrlSource(video.currentSrc), formats: ALL_FORMATS })
  try { const t = await input.getPrimaryAudioTrack(); return t ? t.codec : null } finally { try { input.dispose() } catch (e) {} }
} }

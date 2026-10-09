// In-page audio for files whose sound track the browser cannot decode (AC-3, E-AC-3: Chrome on Android has neither). The picture still plays in the <video>; this reads the same
// file again through the service worker, demuxes it with Mediabunny, decodes the audio with the FFmpeg AC-3/E-AC-3 decoder (WASM, in a worker) and plays it through Web Audio,
// clocked to the video element: restarted on play, seek and buffering, and whenever the two drift apart.
import { Input, ALL_FORMATS, UrlSource, AudioBufferSink } from 'mediabunny'
import { registerAc3Decoder } from '@mediabunny/ac3'

registerAc3Decoder()

const AHEAD = 3 // seconds of audio scheduled in advance
const DRIFT = 0.25 // seconds of disagreement with the video before the audio restarts
const sleep = ms => new Promise(resolve => setTimeout(resolve, ms))

async function attach (video, onstate = () => {}) {
  const input = new Input({ source: new UrlSource(video.currentSrc), formats: ALL_FORMATS })
  const track = await input.getPrimaryAudioTrack()
  if (!track) throw new Error('no audio track')
  if (!(await track.canDecode())) throw new Error('cannot decode ' + track.codec)
  const ctx = new AudioContext()
  const gain = ctx.createGain()
  gain.connect(ctx.destination)
  const sink = new AudioBufferSink(track)
  let run = 0 // each start() owns one generation; bumping it stops the previous one
  let nodes = []
  let base = null // {t0, c0, rate}: video time t0 played when the audio clock read c0
  let dead = false

  const volume = () => { gain.gain.value = video.muted ? 0 : video.volume }
  const silence = () => {
    run++
    base = null
    for (const n of nodes) { try { n.stop() } catch (e) {} }
    nodes = []
  }
  const wanted = () => !dead && !video.paused && !video.seeking && !video.ended && video.readyState >= 3

  async function start () {
    silence()
    if (!wanted()) return
    const mine = run
    try { await ctx.resume() } catch (e) {}
    if (mine !== run) return
    const rate = video.playbackRate || 1
    const t0 = video.currentTime
    const c0 = ctx.currentTime + 0.05
    base = { t0, c0, rate }
    try {
      for await (const { buffer, timestamp } of sink.buffers(Math.max(0, t0 - 0.05))) {
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
  events.forEach(e => video.addEventListener(e, restart))
  video.addEventListener('volumechange', volume)
  const poll = setInterval(() => {
    if (!base || !wanted()) return
    const at = base.t0 + (ctx.currentTime - base.c0) * base.rate
    if (Math.abs(at - video.currentTime) > DRIFT) start()
  }, 1000)
  const wake = () => { if (ctx.state === 'suspended') ctx.resume().catch(() => {}) }
  document.addEventListener('pointerdown', wake)
  volume()
  start()

  return {
    dispose () {
      dead = true
      silence()
      clearInterval(poll)
      events.forEach(e => video.removeEventListener(e, restart))
      video.removeEventListener('volumechange', volume)
      document.removeEventListener('pointerdown', wake)
      try { input.dispose() } catch (e) {}
      ctx.close().catch(() => {})
    }
  }
}

globalThis.PFAudio = { attach, codec: async video => {
  const input = new Input({ source: new UrlSource(video.currentSrc), formats: ALL_FORMATS })
  try { const t = await input.getPrimaryAudioTrack(); return t ? t.codec : null } finally { try { input.dispose() } catch (e) {} }
} }

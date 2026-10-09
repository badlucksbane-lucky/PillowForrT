// Plays a torrent in desktop Chromium through live-proxy.mjs and prints the peer count and playhead over time. Default: Sintel, a Blender open movie (legal to share).
//   node live-play.mjs [infohash] [name]      env: CDP_PORT (9222), SHOTS (screenshot folder), SECONDS (30)
// Start first: chromium --headless=new --no-sandbox --autoplay-policy=no-user-gesture-required --remote-debugging-port=9222 --user-data-dir=/tmp/pf-chrome about:blank &
//              node live-proxy.mjs &
// Careful: this loads the box (tracker and DHT lookups through Mullvad, dozens of bridged connections). See docs/HANDOFF.md before running it often.
import { connect } from './cdp.mjs'
const HASH = process.argv[2] || '08ada5a7a6183aae1e09d831df6748d566095a10'
const NAME = process.argv[3] || 'Sintel'
const SECONDS = +(process.env.SECONDS || 30)
const b = await connect()
await b.mobile()
await b.goto('http://127.0.0.1:' + (process.env.LOCAL_PORT || 18800) + '/browse')
await b.until("typeof window.__play==='function'", 15000)
await b.wait(1500)
await b.ev(`window.__play('${HASH}','${NAME}','magnet:?xt=urn:btih:${HASH}')`)
const t0 = Date.now()
let last = ''
for (let i = 0; i < SECONDS; i++) {
  await b.wait(1000)
  const s = JSON.parse(await b.ev(`(()=>{const v=document.querySelector('#pv video');const m=/(\\d+) peers?/.exec(document.querySelector('#pstat').innerText);return JSON.stringify({status:document.querySelector('#pstat').innerText.replace(/\\s+/g,' ').split(' Open magnet')[0],peers:m?+m[1]:0,t:v?+v.currentTime.toFixed(1):null,err:v&&v.error&&v.error.message})})()`))
  const line = `${String(Math.round((Date.now() - t0) / 1000)).padStart(3)}s  ${s.peers} peers  playhead ${s.t}  ${s.err || ''}  ${s.status}`
  if (line.slice(6) !== last) { console.log(line); last = line.slice(6) }
}
await b.shot('live-play')
console.log('page errors:', b.logs.filter(l => !/favicon|aria-hidden/.test(l)).slice(0, 5))
b.close()

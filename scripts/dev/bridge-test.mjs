// Dials peers through the box's bridge over TLS and sends a real BitTorrent handshake to each: shows how many connect and how many answer.
//   node bridge-test.mjs <peers.json> <infohash>      peers.json is a JSON array of "ip:port" from /api/bt/peers (see README.md)
//   env: PF_HOST (pillowforrt.lan)  PF_PORT (3129)  MAX (80 peers)
// Needs `npm ci` in btclient/ once (for the ws module). Uses ~/.pillowforrt/tls.pem and ui.token.
import fs from 'node:fs'
import { fileURLToPath } from 'node:url'
const { WebSocket } = await import(fileURLToPath(new URL('../../', import.meta.url)) + 'btclient/node_modules/ws/wrapper.mjs')
const HOST = process.env.PF_HOST || 'pillowforrt.lan', PORT = process.env.PF_PORT || 3129
const peers = JSON.parse(fs.readFileSync(process.argv[2])).slice(0, +(process.env.MAX || 80))
const hash = Buffer.from(process.argv[3], 'hex')
const ca = fs.readFileSync(process.env.HOME + '/.pillowforrt/tls.pem')
const token = fs.readFileSync(process.env.HOME + '/.pillowforrt/ui.token', 'utf8').trim()
const hs = Buffer.concat([Buffer.from([19]), Buffer.from('BitTorrent protocol'), Buffer.alloc(8), hash, Buffer.from('-HS0001-' + 'x'.repeat(12))])
const res = { opened: 0, refused: 0, handshakes: 0, other: 0, firstMs: null, bytes: 0 }
const t0 = Date.now()
await Promise.all(peers.map(p => new Promise(done => {
  const ws = new WebSocket(`wss://${HOST}:${PORT}/api/bt/conn?peer=${p}`, { ca, headers: { 'X-UI-Token': token } })
  const to = setTimeout(() => { ws.terminate(); done() }, 12000)
  ws.on('unexpected-response', (rq, rs) => { res.refused++; res.lastStatus = rs.statusCode; clearTimeout(to); done() })
  ws.on('error', () => { clearTimeout(to); done() })
  ws.on('open', () => { res.opened++; ws.send(hs) })
  ws.on('message', d => {
    res.bytes += d.length
    if (d.length >= 68 && d[0] === 19 && d.subarray(28, 48).equals(hash)) { res.handshakes++; if (res.firstMs === null) res.firstMs = Date.now() - t0 } else res.other++
    clearTimeout(to); ws.close(); done()
  })
  ws.on('close', () => { clearTimeout(to); done() })
})))
console.log(JSON.stringify({ tried: peers.length, ...res, totalMs: Date.now() - t0 }))
process.exit(0)

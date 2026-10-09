// Serves the real browse page on this machine and forwards /api/* and the torrent bridge WebSocket to the real box, adding the API token (a browser cannot add a header to a
// WebSocket). With it, desktop Chromium plays real swarms through the real box: run this, then `node live-play.mjs`. Needs `npm ci` in btclient/ once (for the ws module).
//   PF_HOST (default pillowforrt.lan)   PF_PORT (3129)   LOCAL_PORT (18800)
// Config comes from ~/.pillowforrt: tls.pem (the box's certificate, pinned) and ui.token.
import http from 'node:http'
import https from 'node:https'
import fs from 'node:fs'
import { fileURLToPath } from 'node:url'
const ROOT = fileURLToPath(new URL('../../', import.meta.url))
const { WebSocketServer, WebSocket } = await import(ROOT + 'btclient/node_modules/ws/wrapper.mjs')
const HOST = process.env.PF_HOST || 'pillowforrt.lan', PORT = +(process.env.PF_PORT || 3129), LOCAL = +(process.env.LOCAL_PORT || 18800)
const ca = fs.readFileSync(process.env.HOME + '/.pillowforrt/tls.pem')
const token = fs.readFileSync(process.env.HOME + '/.pillowforrt/ui.token', 'utf8').trim()
// the page's own security policy, read from the Go source so the test runs under the same rules
const goSrc = fs.readFileSync(ROOT + 'browse.go', 'utf8')
const csp = [...goSrc.slice(goSrc.indexOf('const browseCSP')).split('\n\n')[0].matchAll(/"((?:[^"\\]|\\.)*)"/g)].map(m => m[1]).join('')
// expose the player to the test script (the real page keeps it private)
const html = fs.readFileSync(ROOT + 'browse.html', 'utf8').replace('btStatus();render(true);', 'window.__play=play;btStatus();render(true);')
const UP = { host: HOST, port: PORT, ca, headers: { 'X-UI-Token': token } }
const files = { '/sw.js': ['btclient/sw.js', 'text/javascript'], '/bt/btclient.js': ['btclient/btclient.js', 'text/javascript'], '/favicon.svg': ['assets/mark.svg', 'image/svg+xml'] }
const srv = http.createServer((q, r) => {
  const u = q.url.split('?')[0]
  if (u === '/browse') { r.setHeader('content-security-policy', csp); r.setHeader('content-type', 'text/html; charset=utf-8'); r.end(html); return }
  if (files[u]) { r.setHeader('content-type', files[u][1]); r.setHeader('cache-control', 'no-cache'); r.end(fs.readFileSync(ROOT + files[u][0])); return }
  if (u.startsWith('/api/')) {
    const up = https.request({ ...UP, path: q.url, method: q.method, headers: { ...UP.headers, accept: q.headers.accept || '*/*', 'content-type': q.headers['content-type'] || '' } }, ur => { r.writeHead(ur.statusCode, ur.headers); ur.pipe(r) })
    up.on('error', e => { r.statusCode = 502; r.end(String(e)) })
    q.pipe(up)
    return
  }
  r.statusCode = 404
  r.end()
})
const wss = new WebSocketServer({ noServer: true })
srv.on('upgrade', (q, sock, head) => wss.handleUpgrade(q, sock, head, c => {
  const up = new WebSocket(`wss://${HOST}:${PORT}${q.url}`, { ca, headers: UP.headers })
  const pending = []
  up.on('open', () => pending.splice(0).forEach(m => up.send(m)))
  up.on('message', d => { if (c.readyState === 1) c.send(d) })
  up.on('close', () => c.close())
  up.on('error', () => c.close())
  c.on('message', d => { if (up.readyState === 1) up.send(d); else pending.push(d) })
  c.on('close', () => up.close())
  c.on('error', () => up.close())
}))
srv.listen(LOCAL, '127.0.0.1', () => console.log(`proxy on http://127.0.0.1:${LOCAL}/browse -> ${HOST}:${PORT}`))

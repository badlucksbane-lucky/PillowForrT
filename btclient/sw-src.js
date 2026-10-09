// Service worker that serves a torrent file to <video src="/webtorrent/<hash>/<file>">. It speaks the same message protocol as WebTorrent's own worker (dist/sw.min.js: the page
// answers each request on a MessageChannel and streams chunks back), with one change: the request goes to the page that made it (event.clientId) instead of to every open window,
// where the first answer won. With two browse tabs open, the other tab answered 404 for a torrent it did not have.
let cancelled = false

self.addEventListener('install', () => self.skipWaiting())
self.addEventListener('activate', e => e.waitUntil(self.clients.claim()))

self.addEventListener('fetch', ev => {
  const url = ev.request.url
  const scope = self.registration.scope
  if (!url.includes(scope + 'webtorrent/')) return
  if (url.includes(scope + 'webtorrent/keepalive/')) return ev.respondWith(new Response())
  if (url.includes(scope + 'webtorrent/cancel/')) return ev.respondWith(new Response(new ReadableStream({ cancel () { cancelled = true } })))
  ev.respondWith(serve(ev))
})

async function serve (ev) {
  const { url, method, headers, destination } = ev.request
  const own = ev.clientId ? await self.clients.get(ev.clientId) : null
  const list = own ? [own] : await self.clients.matchAll({ type: 'window', includeUncontrolled: true })
  const first = await new Promise(resolve => {
    setTimeout(() => resolve(null), 15000)
    for (const c of list) {
      const ch = new MessageChannel()
      ch.port1.onmessage = ({ data }) => resolve([data, ch.port1])
      c.postMessage({ url, method, headers: Object.fromEntries(headers.entries()), scope: self.registration.scope, destination, type: 'webtorrent' }, [ch.port2])
    }
  })
  if (!first) return new Response('no page answered', { status: 504 })
  const [res, port] = first
  let timer = null
  const done = () => { port.postMessage(false); clearTimeout(timer); port.onmessage = null }
  if (res.body !== 'STREAM') { done(); return new Response(res.body, res) }
  return new Response(new ReadableStream({
    pull: ctl => new Promise(resolve => {
      port.onmessage = ({ data }) => {
        if (data) ctl.enqueue(data)
        else { done(); ctl.close() }
        resolve()
      }
      if (!cancelled) {
        clearTimeout(timer)
        if (destination !== 'document') timer = setTimeout(() => { done(); resolve() }, 5000)
      }
      port.postMessage(true)
    }),
    cancel () { done() }
  }), res)
}

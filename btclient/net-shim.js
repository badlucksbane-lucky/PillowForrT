// A stand-in for Node's `net` module inside the browser bundle. WebTorrent opens outgoing TCP peers with net.connect({host, port}) and expects a duplex stream that emits
// 'connect', 'error' and 'close'. Here every such stream is carried over ONE WebSocket to the box (/api/bt/mux), which dials each peer over the Mullvad tunnel and copies bytes both
// ways. One socket means one TLS handshake, where one socket per peer meant up to 25 of them on a single slow core. The box only dials peers it handed out itself
// (/api/bt/peers), so this is not a general TCP proxy.
//
// Frames (one WebSocket message each; the box side is btmux.go): [type, id high, id low, ...payload]
//   1 OPEN  page to box: payload "ip:port"     2 DATA  both ways: bytes     3 CLOSE  page to box: nothing; box to page: one byte, 0 the peer ended, 1 it failed     4 PING  page to box
import { Duplex } from 'streamx'

const OPEN = 1
const DATA = 2
const CLOSE = 3
const PING = 4
const HIGH = 1 << 20 // stop writing while this much is queued in the socket
const CHUNK = 60000 // the box refuses messages over 128 KB
const IDLE_MS = 10000 // close the socket this long after the last peer is gone
const PING_MS = 60000 // the box ends a socket it has heard nothing from in 3 minutes
const RETRY_MS = 5000 // after the box refuses the socket (busy, tunnel down), fail new peers at once for this long instead of opening a socket and a TLS handshake for each

const frame = (type, id, payload) => {
  const f = new Uint8Array(3 + (payload ? payload.length : 0))
  f[0] = type
  f[1] = id >> 8
  f[2] = id & 255
  if (payload) f.set(payload, 3)
  return f
}

class Mux {
  constructor () {
    this.ws = null
    this.streams = new Map()
    this.next = 1
    this.queue = [] // frames written while the socket is still connecting, in order
    this.idle = null
    this.ping = null
    this.refusedAt = 0
  }

  get isOpen () { return !!this.ws && this.ws.readyState === 1 }

  get buffered () { return this.ws ? this.ws.bufferedAmount : 0 }

  _ensure () {
    if (this.ws) return
    const ws = this.ws = new WebSocket(globalThis.BT_BRIDGE || (location.origin.replace(/^http/, 'ws') + '/api/bt/mux'))
    ws.binaryType = 'arraybuffer'
    let opened = false
    ws.onopen = () => {
      if (this.ws !== ws) return
      opened = true
      for (const f of this.queue.splice(0)) ws.send(f)
      this.ping = setInterval(() => { if (ws.readyState === 1) ws.send(frame(PING, 0)) }, PING_MS)
      for (const s of [...this.streams.values()]) s._connected()
    }
    ws.onmessage = e => this._message(new Uint8Array(e.data))
    const down = () => { // the socket died: every peer on it failed
      if (this.ws !== ws) return
      if (!opened) this.refusedAt = Date.now()
      this._reset()
      const all = [...this.streams.values()]
      this.streams.clear()
      for (const s of all) s._lost()
    }
    ws.onclose = down
    ws.onerror = down
  }

  _reset () {
    clearInterval(this.ping)
    clearTimeout(this.idle)
    this.ping = this.idle = null
    this.queue = []
    this.ws = null
  }

  // gives a stream an id and asks the box to dial; false if all 65535 ids are in use
  add (sock, peer) {
    if (!this.ws && Date.now() - this.refusedAt < RETRY_MS) return false
    for (let i = 0; i < 65535; i++) {
      const id = this.next
      this.next = this.next % 65535 + 1
      if (this.streams.has(id)) continue
      this._ensure()
      clearTimeout(this.idle)
      this.idle = null
      sock.id = id
      this.streams.set(id, sock)
      this.send(frame(OPEN, id, new TextEncoder().encode(peer)))
      return true
    }
    return false
  }

  send (f) {
    if (!this.ws) return
    if (this.ws.readyState === 1) this.ws.send(f)
    else if (this.ws.readyState === 0) this.queue.push(f)
  }

  // the page is done with a stream (it ended it, or it was destroyed)
  release (sock) {
    if (this.streams.get(sock.id) !== sock) return
    this.streams.delete(sock.id)
    this.send(frame(CLOSE, sock.id))
    this._maybeIdle()
  }

  _maybeIdle () {
    if (this.streams.size || this.idle) return
    this.idle = setTimeout(() => {
      this.idle = null
      if (this.streams.size || !this.ws) return
      const ws = this.ws
      this._reset()
      try { ws.close() } catch (e) { /* already closed */ }
    }, IDLE_MS)
  }

  _message (b) {
    if (b.length < 3) return
    const id = (b[1] << 8) | b[2]
    const s = this.streams.get(id)
    if (!s) return
    if (b[0] === DATA) {
      s._data(b.subarray(3))
    } else if (b[0] === CLOSE) {
      this.streams.delete(id)
      s._closedByBox(b[3] === 1)
      this._maybeIdle()
    }
  }
}

const mux = new Mux()

class BridgeSocket extends Duplex {
  constructor (opts) {
    super()
    this.remoteAddress = opts.host
    this.remotePort = opts.port
    this.connecting = true
    this.id = 0
    this.done = false
    if (!mux.add(this, opts.host + ':' + opts.port)) {
      this.done = true
      queueMicrotask(() => this.destroy(new Error('bridge unavailable')))
    } else if (mux.isOpen) {
      queueMicrotask(() => this._connected())
    }
  }

  _connected () {
    if (this.done || !this.connecting) return
    this.connecting = false
    this.emit('connect')
  }

  _data (b) { if (!this.done) this.push(b) }

  _closedByBox (failed) {
    this.done = true
    if (failed) this.destroy(new Error('bridge connection failed'))
    else this.push(null)
  }

  _lost () {
    this.done = true
    this.destroy(new Error('bridge connection failed'))
  }

  _write (data, cb) {
    if (this.done) { cb(new Error('bridge closed')); return }
    for (let at = 0; at < data.length; at += CHUNK) mux.send(frame(DATA, this.id, data.subarray(at, at + CHUNK)))
    if (mux.buffered < HIGH) { cb(); return }
    const t = setInterval(() => {
      if (this.done || !mux.ws || mux.ws.readyState > 1) { clearInterval(t); cb(new Error('bridge closed')); return }
      if (mux.buffered < HIGH / 2) { clearInterval(t); cb() }
    }, 30)
  }

  _final (cb) { mux.release(this); cb() }
  _destroy (cb) { this.done = true; mux.release(this); cb() }

  setTimeout () { return this }
  setKeepAlive () { return this }
  setNoDelay () { return this }
  ref () { return this }
  unref () { return this }
}

export function connect (opts) { return new BridgeSocket(opts) }
export function isIPv4 (s) { return /^\d{1,3}(\.\d{1,3}){3}$/.test(s) }
export function isIP (s) { return isIPv4(s) ? 4 : 0 }
export default { connect, isIPv4, isIP }

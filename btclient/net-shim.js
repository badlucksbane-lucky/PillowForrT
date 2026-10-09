// A stand-in for Node's `net` module inside the browser bundle. WebTorrent opens outgoing TCP peers with net.connect({host, port}) and expects a duplex stream that emits
// 'connect', 'error' and 'close'. Here that stream is one WebSocket to the box (/api/bt/conn), which dials the peer over the Mullvad tunnel and copies bytes both ways.
// The box only dials peers it handed out itself (/api/bt/peers), so this is not a general TCP proxy.
import { Duplex } from 'streamx'

const HIGH = 1 << 20 // stop writing while this much is queued in the socket

class BridgeSocket extends Duplex {
  constructor (opts) {
    super()
    this.remoteAddress = opts.host
    this.remotePort = opts.port
    this.connecting = true
    this._queue = []
    const base = (globalThis.BT_BRIDGE || (location.origin.replace(/^http/, 'ws') + '/api/bt/conn'))
    this.ws = new WebSocket(base + '?peer=' + encodeURIComponent(opts.host + ':' + opts.port))
    this.ws.binaryType = 'arraybuffer'
    this.ws.onopen = () => {
      this.connecting = false
      this.emit('connect')
      for (const [d, cb] of this._queue.splice(0)) this._send(d, cb)
    }
    this.ws.onmessage = e => { this.push(new Uint8Array(e.data)) }
    this.ws.onerror = () => { this.destroy(new Error('bridge connection failed')) }
    this.ws.onclose = () => { if (!this.destroyed) this.push(null) }
  }

  _send (data, cb) {
    this.ws.send(data)
    if (this.ws.bufferedAmount < HIGH) return cb()
    const t = setInterval(() => {
      if (this.ws.readyState !== 1) { clearInterval(t); cb(new Error('bridge closed')); return }
      if (this.ws.bufferedAmount < HIGH / 2) { clearInterval(t); cb() }
    }, 30)
  }

  _write (data, cb) {
    if (this.ws.readyState === 0) { this._queue.push([data, cb]); return }
    if (this.ws.readyState !== 1) { cb(new Error('bridge closed')); return }
    this._send(data, cb)
  }

  _final (cb) { try { this.ws.close() } catch (e) {} cb() }
  _destroy (cb) { try { this.ws.close() } catch (e) {} cb() }

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

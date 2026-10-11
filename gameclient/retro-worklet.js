// Audio sink for the Retro game (gameclient/retro.js): the screen posts the core's interleaved 16-bit stereo samples, this plays them. Loaded with audioWorklet.addModule, served at /game/retro-worklet.js.
// The core's rate (32768 Hz for Game Boy, 48000 for NES) differs from the device's, so samples are resampled by linear interpolation, and the ratio is nudged a little by how full the buffer is,
// which keeps the sound from drifting away from the picture over a long game. An empty buffer plays silence.
class RetroSink extends AudioWorkletProcessor {
  constructor() {
    super();
    this.cap = 32768; this.buf = new Float32Array(this.cap * 2); // frames of left and right, a ring
    this.rd = 0; this.wr = 0; this.fill = 0; this.pos = 0; this.rate = 48000;
    this.port.onmessage = (e) => {
      const d = e.data;
      if (d instanceof ArrayBuffer) { const a = new Int16Array(d); for (let i = 0; i + 1 < a.length && this.fill < this.cap; i += 2) { this.buf[this.wr * 2] = a[i] / 32768; this.buf[this.wr * 2 + 1] = a[i + 1] / 32768; this.wr = (this.wr + 1) & (this.cap - 1); this.fill++; } }
      else if (d && d.rate) this.rate = d.rate;
    };
  }
  process(inputs, outputs) {
    const out = outputs[0], L = out[0], R = out[1] || out[0], target = this.rate * 0.06; // about four frames in hand
    const ratio = (this.rate / sampleRate) * (1 + Math.max(-1, Math.min(1, (this.fill - target) / target)) * 0.005);
    for (let i = 0; i < L.length; i++) {
      if (this.fill < 2) { L[i] = 0; R[i] = 0; continue; }
      const a = this.rd * 2, b = ((this.rd + 1) & (this.cap - 1)) * 2, f = this.pos;
      L[i] = this.buf[a] + (this.buf[b] - this.buf[a]) * f; R[i] = this.buf[a + 1] + (this.buf[b + 1] - this.buf[a + 1]) * f;
      this.pos += ratio;
      while (this.pos >= 1) { this.pos -= 1; this.rd = (this.rd + 1) & (this.cap - 1); this.fill--; }
    }
    return true;
  }
}
registerProcessor('retro-sink', RetroSink);

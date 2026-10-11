// Bluetooth/USB game controllers read through the browser's Gamepad API, wherever the browser runs: the screen (the box/laptop running /play, see console.js)
// or a phone (a controller paired to the phone itself, see pad.js) both poll one of these. The browser gives no per-button events, only a snapshot to read each
// tick, so this is pulled rather than pushed; the onButton callback below turns that snapshot into the press/release edges a game actually wants.
// Maps the W3C "standard" gamepad layout onto the same shape a phone widget produces (stick, btn, ptr, tilt), SNES-style: 0 A, 1 B, 2 X, 3 Y, 4 L, 5 R, 8 Select, 9 Start, 12-15 d-pad into the stick.
'use strict';
(function () {
  var DEAD = 0.2; // a worn or uncalibrated pad can rest well off true zero
  var BTN = ['A', 'B', 'X', 'Y', 'L', 'R', 'L2', 'R2', 'Select', 'Start']; // standard-mapping button indices 0..9

  function LocalPads() { this.list = new Map(); } // gamepad.index -> player-shaped record, same object reused every poll so edits are seen where the record is already held
  var P = LocalPads.prototype;
  P.poll = function (onAdd, onRemove, onButton) {
    var pads = navigator.getGamepads ? navigator.getGamepads() : [], seen = {}, self = this;
    for (var i = 0; i < pads.length; i++) {
      var gp = pads[i];
      if (!gp || !gp.connected || gp.mapping !== 'standard') continue; // a non-standard pad has no reliable button positions
      seen[gp.index] = 1;
      var p = this.list.get(gp.index);
      if (!p) {
        p = { id: 'gp:' + gp.index, local: true, name: (gp.id || 'Controller').slice(0, 24), away: false,
          stick: { x: 0, y: 0 }, ptr: { x: 0, y: 0, down: false }, tilt: { b: 0, g: 0 }, btn: {}, _prev: {} };
        this.list.set(gp.index, p);
        if (onAdd) onAdd(p);
      }
      var b = gp.buttons, x = gp.axes[0] || 0, y = gp.axes[1] || 0;
      if (Math.hypot(x, y) < DEAD) { x = 0; y = 0; }
      if (b[12] && b[12].pressed) y = -1; if (b[13] && b[13].pressed) y = 1; // d-pad overrides the stick when held
      if (b[14] && b[14].pressed) x = -1; if (b[15] && b[15].pressed) x = 1;
      p.stick.x = x; p.stick.y = y;
      for (var n = 0; n < BTN.length; n++) {
        var name = BTN[n], down = !!(b[n] && b[n].pressed);
        p.btn[name] = down;
        if (down !== !!p._prev[name]) { p._prev[name] = down; if (onButton) onButton(p, name, down); }
      }
    }
    this.list.forEach(function (p, idx) {
      if (seen[idx]) return;
      for (var name in p._prev) if (p._prev[name] && onButton) onButton(p, name, false); // release anything still held when the pad disconnects
      self.list.delete(idx);
      if (onRemove) onRemove(p);
    });
  };
  window.LocalPads = LocalPads;
})();

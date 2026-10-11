// Tests the Kids mode card on /ui (the <kids-card> block in ui.html): what it shows in each state, the PIN pad (digits, limits, keyboard), and every flow a person can start (switch on with no PIN, switch off,
// wrong and locked-out PINs, remove and add a kids' device, set and change the PIN, lock now, the countdown), against a fake page and a fake server that follows kids.go's contract.
// Usage: node kidscard-unit.mjs   Exit code 1 on failure.
import fs from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
const html = fs.readFileSync(path.join(path.dirname(fileURLToPath(import.meta.url)), '../../ui.html'), 'utf8');
const block = html.slice(html.indexOf('// <kids-card>'), html.indexOf('// </kids-card>'));
const grab = (re) => { const m = html.match(re); if (!m) { console.log('FAIL helper not found', re); process.exit(1); } return m[0]; };
const helpers = [grab(/^const esc=.*$/m), grab(/^const chip=\(t,cls,tip\)=>.*$/m), grab(/^const seg=\(label,opts,cur,fn,full\)=>.*$/m), grab(/^function guard\(el,force\)\{.*\}$/m)].join('\n');
if (!block) { console.log('FAIL markers not found'); process.exit(1); }
const fails = [];
const check = (name, ok, got) => { console.log((ok ? 'ok   ' : 'FAIL ') + name + (ok ? '' : '  got: ' + JSON.stringify(got))); if (!ok) fails.push(name); };

// ---- a fake server that follows kids.go ----
const mkServer = (init = {}) => {
  const s = { on: false, pin: null, unlockedUntil: 0, fails: 0, lockUntil: 0, devices: [], calls: [], now: 1_800_000_000_000, ...init };
  const view = () => ({ on: s.on, has_pin: !!s.pin, unlocked: s.unlockedUntil > s.now, unlock_left: Math.max(0, Math.round((s.unlockedUntil - s.now) / 1000)), locked_for: Math.max(0, Math.round((s.lockUntil - s.now) / 1000)), tries_left: 5 - s.fails, devices: s.devices.slice() });
  const unl = () => s.unlockedUntil > s.now;
  const tryPin = (pin) => { if (s.lockUntil > s.now) return [429, { error: 'locked', locked_for: Math.round((s.lockUntil - s.now) / 1000) }]; if (pin === s.pin) { s.fails = 0; return null; } s.fails++; if (s.fails >= 5) { s.fails = 0; s.lockUntil = s.now + 300000; return [429, { error: 'locked', locked_for: 300 }]; } return [403, { error: 'wrong PIN', tries_left: 5 - s.fails }]; };
  s.get = (url) => url === '/api/kids' ? view() : { devices: [{ mac: 'aa:bb:cc:dd:ee:01', label: "Maya's tablet" }, { mac: 'aa:bb:cc:dd:ee:02', name: 'Switch' }, { mac: 'aa:bb:cc:dd:ee:03', hostname: '<b>x</b>' }, { mac: 'aa:bb:cc:dd:ee:04', ip: '192.168.1.44' }] };
  s.post = (p, b) => {
    s.calls.push([p, JSON.parse(JSON.stringify(b))]);
    if (p === 'kids/unlock') { const bad = tryPin(b.pin); if (bad) return bad; s.unlockedUntil = s.now + 600000; return [200, { unlocked_for: 600, view: view() }]; }
    if (p === 'kids/lock') { s.unlockedUntil = 0; return [200, view()]; }
    if (p === 'kids/set') {
      if (b.devices) { const removing = s.devices.some(d => !b.devices.includes(d)); if (removing && s.pin && !unl()) return [403, { error: 'enter the parent PIN first', needs_pin: true }]; s.devices = b.devices; }
      if (b.on !== undefined) { if (!s.pin) return [409, { error: 'set a parent PIN first', needs_setup: true }]; if (!b.on && !unl()) return [403, { error: 'enter the parent PIN first', needs_pin: true }]; s.on = b.on; }
      return [200, view()];
    }
    if (p === 'kids/pin') { if (s.pin && !unl()) { if (!b.current) return [403, { error: 'enter the parent PIN first', needs_pin: true }]; const bad = tryPin(b.current); if (bad) return bad; } s.pin = b.pin; s.unlockedUntil = 0; s.fails = 0; return [200, view()]; }
    return [404, {}];
  };
  return s;
};
class El { constructor () { this.innerHTML = ''; this.textContent = ''; this.hidden = false; } contains () { return false; } }
const mkPage = (srv) => {
  const els = {}; const el = (id) => els[id] || (els[id] = new El());
  els.kmpad = new El(); els.kmpad.hidden = true;
  const doc = { listeners: {}, hidden: false, activeElement: null, addEventListener (e, f) { this.listeners[e] = f; } };
  let timer = null;
  const env = {
    $: el, document: doc, setInterval: (f) => { timer = f; return 1; },
    api: async (url) => ({ json: async () => srv.get(url) }),
    apost: async (p, b) => { const [code, j] = srv.post(p, b); return { ok: code < 400, j }; },
    Date: { now: () => srv.now }
  };
  const code = helpers + '\n' + block + '\nreturn {kmload, kmrender, kmswitch, kmdevadd, kmdevdel, kmlockNow, kmpin, kmkey, kmpadClose, kmunlock, kmLeft, kmLock, kmfmt, getKm: () => Km, getPad: () => KmPad};';
  const api = new Function(...Object.keys(env), code)(...Object.values(env));
  return { api, els, doc, tick: () => timer && timer() };
};
const type = async (api, digits) => { for (const d of digits) await api.kmkey(d); };
const enter = async (api, digits) => { await type(api, digits); await api.kmkey('Enter'); };
const padTitle = (p) => (p.els.kmpad.innerHTML.match(/<h3>([^<]*)<\/h3>/) || [])[1];
const padMsg = (p) => (p.els.kmpad.innerHTML.match(/class="pmsg"[^>]*>([^<]*)</) || [])[1];
const dots = (p) => [...p.els.kmpad.innerHTML.matchAll(/<i class="(f?)"><\/i>/g)].map(m => m[1]);
const kinds = (srv) => srv.calls.map(c => c[0] + (c[1].on !== undefined ? ':' + c[1].on : ''));

// ---- what the card shows ----
{ const srv = mkServer(); const p = mkPage(srv); await p.api.kmload(); const h = p.els.km.innerHTML;
  check('a fresh box: Off is selected, "No PIN yet", the button says Set PIN, no badge', /aria-checked="true" class="on"[^>]*>Off</.test(h) && h.includes('No PIN yet') && h.includes('>Set PIN<') && p.els.kmbadge.innerHTML === '', h);
  check('the add menu lists the devices by label, then name, then hostname (escaped), then address', h.includes('>Maya&#39;s tablet<') || h.includes("Maya's tablet"), h);
  check('a device name with markup is shown as text, never as markup', h.includes('&lt;b&gt;x&lt;/b&gt;') && !h.includes('<b>x</b>'), h);
  check('an address-only device is listed by its address', h.includes('>192.168.1.44<'), null); }
{ const srv = mkServer({ on: true, pin: '1234', devices: ['aa:bb:cc:dd:ee:01', 'aa:bb:cc:dd:ee:02'] }); const p = mkPage(srv); await p.api.kmload(); const h = p.els.km.innerHTML;
  check('on with a PIN: On is selected, a badge, "PIN locked", "Change PIN"', /aria-checked="true" class="on"[^>]*>On</.test(h) && p.els.kmbadge.innerHTML.includes('on') && h.includes('PIN locked') && h.includes('>Change PIN<') && !h.includes('Lock now'), h);
  check('kids\' devices are chips with a × to remove; the ones already chosen are not in the add menu', h.includes('Remove Switch from') && /onclick="kmdevdel\('aa:bb:cc:dd:ee:01'\)"/.test(h) && !/<option value="aa:bb:cc:dd:ee:01"/.test(h) && /<option value="aa:bb:cc:dd:ee:03"/.test(h), h);
  srv.unlockedUntil = srv.now + 570000; await p.api.kmload();
  check('unlocked: a countdown (9:30) and a Lock now button', p.els.km.innerHTML.includes('Unlocked <span id="kmleft">9:30</span>') && p.els.km.innerHTML.includes('Lock now'), p.els.km.innerHTML);
  srv.unlockedUntil = 0; srv.lockUntil = srv.now + 250000; await p.api.kmload();
  check('locked out: the chip is red and counts down (4:10)', p.els.km.innerHTML.includes('cnt bad') && p.els.km.innerHTML.includes('PIN locked <span id="kmlock">4:10</span>'), p.els.km.innerHTML);
  const all = mkServer({ on: false, pin: '1111', devices: ['aa:bb:cc:dd:ee:01', 'aa:bb:cc:dd:ee:02', 'aa:bb:cc:dd:ee:03', 'aa:bb:cc:dd:ee:04'] }); const p2 = mkPage(all); await p2.api.kmload();
  check('with every device chosen there is no empty add menu', !p2.els.km.innerHTML.includes('<select'), null); }

{ const srv = mkServer({ on: true, pin: '1234' }); const view = srv.get; srv.get = (u) => u === '/api/kids' ? { ...view(u), ratings_key: false } : view(u);
  const p = mkPage(srv); await p.api.kmload();
  check('Kids mode on with no ratings key says so (movies and series are all hidden until there is one)', p.els.km.innerHTML.includes('No ratings key') && p.els.km.innerHTML.includes('cnt bad'), p.els.km.innerHTML);
  srv.get = (u) => u === '/api/kids' ? { ...view(u), ratings_key: true } : view(u); await p.api.kmload();
  check('and says nothing once there is a key', !p.els.km.innerHTML.includes('No ratings key'), null);
  srv.get = (u) => u === '/api/kids' ? { ...view(u), on: false, ratings_key: false } : view(u); await p.api.kmload();
  check('or when Kids mode is off', !p.els.km.innerHTML.includes('No ratings key'), null); }

// ---- the pad ----
{ const srv = mkServer({ pin: '1234' }); const p = mkPage(srv); await p.api.kmload(); p.api.kmunlock(() => {});
  check('the pad opens as a dialog titled "Parent PIN" with four empty dots and OK disabled', !p.els.kmpad.hidden && padTitle(p) === 'Parent PIN' && dots(p).join() === ',,,' && /class="on pok"[^>]* disabled/.test(p.els.kmpad.innerHTML), p.els.kmpad.innerHTML.slice(0, 200));
  await type(p.api, '123');
  check('typing fills dots; OK stays disabled under 4 digits and Enter submits nothing', dots(p).join() === 'f,f,f,' && /pok"[^>]* disabled/.test(p.els.kmpad.innerHTML), dots(p));
  await p.api.kmkey('Enter'); check('(no request was made)', srv.calls.length === 0, srv.calls);
  await type(p.api, '4567890');
  check('at most 8 digits: the dots grow to 8 and a 9th digit is ignored', dots(p).length === 8 && dots(p).every(d => d === 'f') && p.api.getPad().pin === '12345678', p.api.getPad().pin);
  await p.api.kmkey('Backspace'); await p.api.kmkey('Backspace');
  check('Backspace removes the last digit', p.api.getPad().pin === '123456', p.api.getPad().pin);
  await p.api.kmkey('Escape'); check('Escape closes the pad without asking anything', p.els.kmpad.hidden && p.api.getPad() === null && srv.calls.length === 0, null);
  p.api.kmunlock(() => {}); p.doc.listeners.keydown({ key: '7', preventDefault () {} }); await Promise.resolve();
  check('the keyboard works while the pad is open', p.api.getPad().pin === '7', null);
  let stopped = false; p.doc.listeners.keydown({ key: '8', ctrlKey: true, preventDefault () { stopped = true; } });
  check('but a shortcut (Ctrl+8) is left alone', p.api.getPad().pin === '7' && !stopped, null);
  p.api.kmpadClose(); stopped = false; p.doc.listeners.keydown({ key: '5', preventDefault () { stopped = true; } });
  check('and with the pad closed the keys are not taken over', !stopped && p.api.getPad() === null, null); }

// ---- switching on ----
{ const srv = mkServer(); const p = mkPage(srv); await p.api.kmload(); await p.api.kmswitch(true);
  check('switching On with no PIN first asks you to choose one', padTitle(p) === 'Choose a PIN (4 to 8 digits)', padTitle(p));
  await enter(p.api, '2468');
  check('then to repeat it', padTitle(p) === 'Repeat the PIN', padTitle(p));
  await enter(p.api, '2469');
  check('a different second PIN goes back to the start with a message and sends nothing', padTitle(p) === 'Choose a PIN (4 to 8 digits)' && padMsg(p) === 'The PINs differ, try again' && srv.calls.length === 0, [padTitle(p), padMsg(p), srv.calls]);
  await enter(p.api, '2468'); await enter(p.api, '2468');
  check('matching PINs set it (sending the PIN, no current), close the pad, and then turn Kids mode on', p.els.kmpad.hidden && JSON.stringify(srv.calls[0]) === JSON.stringify(['kids/pin', { pin: '2468', current: '' }]) && kinds(srv).join() === 'kids/pin,kids/set:true' && srv.on === true, [srv.calls, srv.on]);
  check('the card now shows it on, and a PIN exists', p.api.getKm().on === true && p.api.getKm().has_pin === true, null); }

// ---- switching off ----
{ const srv = mkServer({ on: true, pin: '1234' }); const p = mkPage(srv); await p.api.kmload(); await p.api.kmswitch(false);
  check('switching Off while locked asks for the Parent PIN and sends nothing yet', padTitle(p) === 'Parent PIN' && srv.calls.length === 0, null);
  await enter(p.api, '9999');
  check('a wrong PIN stays on the pad, says how many tries are left, clears the dots, and shakes', padTitle(p) === 'Parent PIN' && padMsg(p) === 'Wrong PIN, 4 left' && dots(p).join() === ',,,' && p.els.kmpad.innerHTML.includes('pdots bad'), [padMsg(p), dots(p)]);
  await enter(p.api, '1234');
  check('the right PIN closes the pad, unlocks, and then turns Kids mode off', p.els.kmpad.hidden && kinds(srv).join() === 'kids/unlock,kids/unlock,kids/set:false' && srv.on === false, kinds(srv));
  srv.on = true; await p.api.kmload(); srv.calls.length = 0; await p.api.kmswitch(false);
  check('while unlocked, Off goes straight through with no pad', p.els.kmpad.hidden && kinds(srv).join() === 'kids/set:false', kinds(srv)); }
{ const srv = mkServer({ on: true, pin: '1234' }); const p = mkPage(srv); await p.api.kmload(); await p.api.kmswitch(false);
  for (let i = 0; i < 4; i++) await enter(p.api, '0000');
  await enter(p.api, '0000');
  check('the fifth wrong PIN says it is locked and for how long', padMsg(p) === 'Locked: try again in 5 min', padMsg(p));
  await enter(p.api, '1234');
  check('and then even the right PIN is refused while locked', padMsg(p).startsWith('Locked') && srv.on === true && p.api.getKm().locked_for > 0, padMsg(p)); }

// ---- the kids' devices ----
{ const srv = mkServer({ on: true, pin: '1234', devices: ['aa:bb:cc:dd:ee:01', 'aa:bb:cc:dd:ee:02'] }); const p = mkPage(srv); await p.api.kmload();
  await p.api.kmdevadd('aa:bb:cc:dd:ee:03');
  check('adding a device needs no PIN and sends the whole new list', JSON.stringify(srv.calls[0]) === JSON.stringify(['kids/set', { devices: ['aa:bb:cc:dd:ee:01', 'aa:bb:cc:dd:ee:02', 'aa:bb:cc:dd:ee:03'] }]) && srv.devices.length === 3, srv.calls);
  srv.calls.length = 0; await p.api.kmdevadd(''); check('choosing the "+ Add device" heading adds nothing', srv.calls.length === 0, srv.calls);
  await p.api.kmdevdel('aa:bb:cc:dd:ee:02');
  check('removing one while locked asks for the PIN first', padTitle(p) === 'Parent PIN' && srv.devices.length === 3, null);
  await enter(p.api, '1234');
  check('and after the PIN removes exactly that one', p.els.kmpad.hidden && srv.devices.join() === 'aa:bb:cc:dd:ee:01,aa:bb:cc:dd:ee:03', srv.devices);
  srv.calls.length = 0; await p.api.kmdevdel('aa:bb:cc:dd:ee:03');
  check('while unlocked removal goes straight through', kinds(srv).join() === 'kids/set' && srv.devices.join() === 'aa:bb:cc:dd:ee:01', kinds(srv)); }

// ---- changing the PIN ----
{ const srv = mkServer({ on: true, pin: '1111' }); const p = mkPage(srv); await p.api.kmload(); p.api.kmpin();
  check('with a PIN set and the card locked, the change starts with the current PIN', padTitle(p) === 'Current PIN', padTitle(p));
  await enter(p.api, '2222'); await enter(p.api, '3333'); await enter(p.api, '3333');
  check('a wrong current PIN is only found out at the end, then it asks for the current PIN again with the tries left', padTitle(p) === 'Current PIN' && padMsg(p) === 'Wrong PIN, 4 left' && srv.pin === '1111', [padTitle(p), padMsg(p), srv.pin]);
  await enter(p.api, '1111'); await enter(p.api, '3333'); await enter(p.api, '3333');
  check('the right current PIN then the new one twice changes it and sends both', srv.pin === '3333' && p.els.kmpad.hidden && JSON.stringify(srv.calls.at(-1)) === JSON.stringify(['kids/pin', { pin: '3333', current: '1111' }]), srv.calls.at(-1)); }
{ const srv = mkServer({ on: true, pin: '1111' }); const p = mkPage(srv); await p.api.kmload(); srv.unlockedUntil = srv.now + 300000; await p.api.kmload(); p.api.kmpin();
  check('when already unlocked the change skips the current PIN', padTitle(p) === 'Choose a PIN (4 to 8 digits)', padTitle(p));
  await enter(p.api, '5555'); await enter(p.api, '5555');
  check('and sends an empty current PIN', srv.pin === '5555' && srv.calls.at(-1)[1].current === '', srv.calls.at(-1)); }

// ---- lock now and the countdown ----
{ const srv = mkServer({ on: true, pin: '1234', unlockedUntil: 1_800_000_000_000 + 125000 }); const p = mkPage(srv); await p.api.kmload();
  check('the countdown reads 2:05', p.api.kmLeft() === 125 && p.api.kmfmt(125) === '2:05', p.api.kmLeft());
  srv.now += 61000; p.tick();
  check('a second later the shown time moves on (1:04), without redrawing the card', p.api.kmLeft() === 64 && p.els.km.innerHTML.includes('2:05'), p.api.kmLeft());
  const before = srv.calls.length; srv.now += 70000; srv.unlockedUntil = 0; p.tick(); await new Promise(r => setTimeout(r, 5));
  check('when it reaches zero the card reloads and shows the locked state', p.api.getKm().unlocked === false && p.els.km.innerHTML.includes('PIN locked') && !p.els.km.innerHTML.includes('Lock now'), p.els.km.innerHTML);
  srv.unlockedUntil = srv.now + 300000; await p.api.kmload(); await p.api.kmlockNow();
  check('Lock now asks the server to lock and the card shows locked', srv.calls.at(-1)[0] === 'kids/lock' && p.api.getKm().unlocked === false, srv.calls.at(-1)); }

// ---- wiring ----
check('the card sits in the Devices section and the page loads it with the other cards', /<div class="sec">Devices<\/div>\n<div class="card" id="c-kids">/.test(html) && /if\(tickN\+\+%3===0\)\{kmload\(\);/.test(html), null);
check('the pad is a modal dialog in the page, hidden until used', /<div id="kmpad" class="mod" hidden role="dialog" aria-modal="true" aria-label="Parent PIN"><\/div>/.test(html), null);
check('no name clashes with the existing kload()', (html.match(/\bfunction kload\b|\basync function kload\b/g) || []).length === 1 && !/function kmsg\b/.test(block), null);
console.log(fails.length ? '\n' + fails.length + ' failed' : '\nall ok'); process.exit(fails.length ? 1 : 0);

// Tests the downloaded-data housekeeping in browse.html (holdStore, releaseStore, sweepStore between the <store-sweep> markers) against a fake Web Locks and a fake private file system:
// what a live tab uses is kept, what nobody holds is deleted (folders and chunks/ entries, leftovers of any name), a stop before the lock is granted lets it go, and without Web Locks nothing is touched.
// Usage: node btstore-unit.mjs   Exit code 1 on failure.
import fs from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
const html = fs.readFileSync(path.join(path.dirname(fileURLToPath(import.meta.url)), '../../browse.html'), 'utf8');
const code = html.slice(html.indexOf('// <store-sweep>'), html.indexOf('// </store-sweep>'));
if (!code) { console.log('FAIL markers not found'); process.exit(1); }
const fails = [];
const check = (name, ok, got) => { console.log((ok ? 'ok   ' : 'FAIL ') + name + (ok ? '' : '  got: ' + JSON.stringify(got))); if (!ok) fails.push(name); };
const tick = () => new Promise(r => setTimeout(r, 0));

class Dir { // a directory in the fake file system
  constructor() { this.m = new Map(); this.failRemove = new Set(); }
  async getDirectoryHandle(n, o) { if (!this.m.has(n)) { if (o && o.create) this.m.set(n, new Dir()); else throw new Error('NotFound'); } return this.m.get(n); }
  async removeEntry(n, o) { if (this.failRemove.has(n)) throw new Error('busy'); if (!this.m.has(n)) throw new Error('NotFound'); this.m.delete(n); }
  async *entries() { for (const e of [...this.m]) yield e; }
  list() { return [...this.m.keys()].sort(); }
}
const mkEnv = (withLocks = true) => {
  const held = new Map(); // lock name -> count
  const nav = { storage: { root: new Dir(), getDirectory() { return Promise.resolve(this.root); } } };
  if (withLocks) nav.locks = {
    request(name, o, cb) { return new Promise(async (res, rej) => { await tick(); held.set(name, (held.get(name) || 0) + 1); try { res(await cb({ name })); } catch (e) { rej(e); } finally { held.set(name, held.get(name) - 1); if (!held.get(name)) held.delete(name); } }); },
    async query() { return { held: [...held.keys()].map(name => ({ name })) }; }
  };
  const BT = { want: new Set(), locks: new Map() };
  const api = new Function('navigator', 'BT', code + '; return {holdStore, releaseStore, sweepStore, STORE_LOCK}')(nav, BT);
  return { nav, BT, held, ...api };
};
const H1 = 'aaaaaaaa11112222333344445555666677778888', H2 = 'bbbbbbbb11112222333344445555666677778888';
const seed = async (e) => { // two torrents' folders and chunk folders, plus junk
  const r = e.nav.storage.root;
  for (const n of ['Movie One - aaaaaaaa', 'Movie Two - bbbbbbbb', 'Old Thing - cccccccc', 'junk', 'a - b']) await r.getDirectoryHandle(n, { create: true });
  const c = await r.getDirectoryHandle('chunks', { create: true });
  for (const n of ['Movie One - aaaaaaaa', 'Old Thing - cccccccc', 'stray']) await c.getDirectoryHandle(n, { create: true });
  return r;
};

{ // nothing held: everything goes, the chunks folder itself stays
  const e = mkEnv(); const r = await seed(e); await e.sweepStore();
  check('with no tab holding anything, every leftover folder is deleted', r.list().join() === 'chunks', r.list());
  check('and the chunks folder is emptied but kept', (await r.getDirectoryHandle('chunks')).list().length === 0, (await r.getDirectoryHandle('chunks')).list());
}
{ // one live torrent
  const e = mkEnv(); const r = await seed(e);
  e.holdStore(H1); await tick(); await tick();
  check('a held torrent shows up as a shared lock named for the first 8 of its hash', e.held.has(e.STORE_LOCK + 'aaaaaaaa') && e.STORE_LOCK === 'pf-bt:', [...e.held.keys()]);
  await e.sweepStore();
  check('the live torrent\'s folder and chunks are kept, all others deleted', r.list().join() === 'Movie One - aaaaaaaa,chunks' && (await r.getDirectoryHandle('chunks')).list().join() === 'Movie One - aaaaaaaa', [r.list(), (await r.getDirectoryHandle('chunks')).list()]);
  e.holdStore(H1); e.holdStore(H1.toUpperCase());
  await tick(); await tick();
  check('asking for the same lock again does not stack locks', e.held.get(e.STORE_LOCK + 'aaaaaaaa') === 1, [...e.held]);
  e.holdStore(H2); await tick(); await tick();
  check('two torrents hold two locks', e.held.size === 2, [...e.held.keys()]);
  e.releaseStore(); await tick(); await tick();
  check('releasing lets every lock go', e.held.size === 0, [...e.held.keys()]);
  await e.sweepStore();
  check('and then the sweep takes the rest', r.list().join() === 'chunks', r.list());
}
{ // a stop before the lock is granted
  const e = mkEnv(); e.holdStore(H1); e.releaseStore(); await tick(); await tick(); await tick();
  check('a stop before the lock was granted leaves no lock behind', e.held.size === 0 && e.BT.locks.size === 0 && e.BT.want.size === 0, [[...e.held], e.BT.locks.size]);
  e.holdStore(H2); await tick(); await tick();
  check('and a later torrent still gets its own lock', e.held.has(e.STORE_LOCK + 'bbbbbbbb'), [...e.held.keys()]);
}
{ // another tab's lock counts too (a shared lock held outside this BT)
  const e = mkEnv(); const r = await seed(e);
  e.held.set('pf-bt:bbbbbbbb', 1); e.held.set('something-else', 1);
  await e.sweepStore();
  check('a lock held by another tab protects that torrent\'s data; unrelated locks mean nothing', r.list().join() === 'Movie Two - bbbbbbbb,chunks', r.list());
}
{ // odd input and failures
  const e = mkEnv(); const r = await seed(e);
  e.holdStore(''); e.holdStore(undefined); e.holdStore('../../x'); e.holdStore('zzzzzzzz'); await tick(); await tick();
  check('a missing or bad info-hash takes no lock', e.held.size === 0 && e.BT.want.size === 0, [...e.held.keys()]);
  r.failRemove.add('Old Thing - cccccccc'); r.failRemove.add('junk');
  await e.sweepStore();
  check('a folder that cannot be deleted is skipped and the rest still go', r.list().join() === 'Old Thing - cccccccc,chunks,junk', r.list());
}
{ // no Web Locks: a live tab cannot be told from a dead one, so nothing is deleted
  const e = mkEnv(false); const r = await seed(e); e.holdStore(H1); await e.sweepStore();
  check('without Web Locks nothing is swept and nothing breaks', r.list().length === 6 && e.BT.want.size === 0, r.list());
  const e2 = mkEnv(); e2.nav.storage = {}; await e2.sweepStore(); // no OPFS either
  check('without a private file system the sweep does nothing', true);
}
{ // wiring in the page
  check('the player turns the piece cache off', /storeCacheSlots:0/.test(html), null);
  check('the page stops the player when it is left', /addEventListener\('pagehide',\(\)=>\{try\{stopPlayer\(\)\}/.test(html), null);
  check('every stop lets its locks go and sweeps', /releaseStore\(\);setTimeout\(sweepStore,2000\)/.test(html) && /\nsweepStore\(\);window\.addEventListener\('pagehide'/.test(html), null);
  check('a play takes its lock as soon as the hash is known', /holdStore\(t\.infoHash\);t\.on\('infoHash',\(\)=>holdStore\(t\.infoHash\)\)/.test(html), null);
}
console.log(fails.length ? '\n' + fails.length + ' failed' : '\nall ok'); process.exit(fails.length ? 1 : 0);

// Tests that sign-in brings a person back to the page they asked for, with the room code (#CODE) from a scanned QR still on it, in headless Chromium against the real web UI (login, the same-site
// bounce and the game pages, started from `go test` as TestLoginServeForJS; login ben / correct horse battery). The server never sees a #fragment, so this needs a real browser: it checks that
// the fragment survives the redirects, that a wrong password keeps both the target and the code, that a target that is not one of our pages is ignored, and that a signed-in visit is forwarded.
// Usage: node login-return-test.mjs   (Node 22, chromium on the PATH or CHROMIUM=/path)   Exit code 1 on failure.
import { spawn } from 'node:child_process';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
const here = path.dirname(fileURLToPath(import.meta.url));
const root = path.join(here, '../..');
process.env.CDP_PORT = process.env.CDP_PORT || String(9300 + Math.floor(Math.random() * 500));
const { connect } = await import(path.join(here, 'cdp.mjs'));

const go = spawn('go', ['test', '-count=1', '-run', 'TestLoginServeForJS', '-v', '.'], { cwd: root, env: { ...process.env, LOGIN_SERVE: '1' }, stdio: ['ignore', 'pipe', 'inherit'] });
const info = await new Promise((resolve, reject) => {
  let buf = '';
  go.stdout.on('data', d => { buf += d; const line = buf.split('\n').find(l => l.startsWith('{')); if (line) resolve(JSON.parse(line)); });
  go.on('exit', c => reject(new Error('go test ended early, code ' + c + '\n' + buf)));
});
const fails = [];
const check = (name, ok, got) => { console.log((ok ? 'ok   ' : 'FAIL ') + name + (ok ? '' : '  got: ' + JSON.stringify(got))); if (!ok) fails.push(name); };
const prof = fs.mkdtempSync(path.join(os.tmpdir(), 'login-test-'));
const cr = spawn(process.env.CHROMIUM || 'chromium', ['--headless=new', '--no-sandbox', '--disable-gpu', '--remote-debugging-port=' + process.env.CDP_PORT, '--user-data-dir=' + prof, '--disable-background-networking', 'about:blank'], { stdio: 'ignore', detached: true });
const exited = new Promise(r => cr.once('exit', r));
const done = async code => {
  try { await fetch(info.url + '/quit'); } catch (e) { /* already gone */ }
  try { process.kill(-cr.pid, 'SIGTERM'); } catch (e) { /* already gone */ }
  await Promise.race([exited, new Promise(r => setTimeout(r, 3000))]);
  try { process.kill(-cr.pid, 'SIGKILL'); } catch (e) { /* none left */ }
  try { fs.rmSync(prof, { recursive: true, force: true, maxRetries: 5, retryDelay: 200 }); } catch (e) { /* a temp directory */ }
  process.exit(code);
};
for (let i = 0; ; i++) { try { await fetch(`http://127.0.0.1:${process.env.CDP_PORT}/json/version`); break; } catch (e) { if (i > 50) { console.error('chromium did not start'); done(2); } await new Promise(r => setTimeout(r, 200)); } }

const J = JSON.stringify;
const loc = c => c.ev(`location.pathname+location.search+location.hash`);
const fill = (c, pw) => c.ev(`document.querySelector('#u').value='ben';document.querySelector('#p').value=${J(pw)};document.querySelector('form').requestSubmit();1`);

const c = await connect(); await c.desktop();
// a signed-out phone opens the link from a QR
await c.goto(info.url + '/pad#ABCD');
check('a signed-out link to /pad lands on the login page, told where to come back to, with the code still on it', await c.until(`location.pathname==='/login'`, 8000) && (await loc(c)) === '/login?next=%2Fpad#ABCD', await loc(c));
check('the form carries the target and the code', await c.ev(`document.querySelector('input[name=next]').value`) === '/pad' && (await c.ev(`document.querySelector('form').action`)).endsWith('/login#ABCD'), await c.ev(`document.querySelector('form').action`));
await fill(c, 'wrong password');
check('a wrong password keeps the target and the code', await c.until(`!!document.querySelector('.err')&&document.querySelector('.err').textContent.length>0`, 8000) && await c.ev(`document.querySelector('input[name=next]').value`) === '/pad' && (await c.ev(`document.querySelector('form').action`)).endsWith('/login#ABCD'), [await loc(c), await c.ev(`document.querySelector('form').action`)]);
await fill(c, 'correct horse battery');
check('signing in returns to /pad and the room code is filled in', await c.until(`location.pathname==='/pad'&&document.querySelector('#cd')&&document.querySelector('#cd').value==='ABCD'`, 8000), await loc(c));
check('and the code is dropped from the address as the pad page always does', await c.ev(`location.hash===''`), await loc(c));

// signed in: /login forwards by the same rule
await c.goto(info.url + '/login?next=%2Fplay');
check('a signed-in visit to /login?next=/play goes to /play', await c.until(`location.pathname==='/play'`, 8000), await loc(c));
await c.goto(info.url + '/login?next=%2F%2Fevil.example');
check('a next that is not ours goes to /ui', await c.until(`location.pathname==='/ui'`, 8000), await loc(c));
// sign out and try the other pages, and a bad target on the form
await c.ev(`fetch('/logout',{method:'POST'}).then(()=>1)`);
await c.goto(info.url + '/login?next=%2F%2Fevil.example');
check('the login page drops a bad next', await c.until(`!!document.querySelector('form')`, 5000) && await c.ev(`!document.querySelector('input[name=next]')`), await loc(c));
await c.goto(info.url + '/login?next=%2Fbrowse#WXYZ');
await c.until(`!!document.querySelector('form')`, 5000);
await fill(c, 'correct horse battery');
check('/browse works the same way (a code on it is harmless)', await c.until(`location.pathname==='/browse'`, 8000), await loc(c));
await c.ev(`fetch('/logout',{method:'POST'}).then(()=>1)`);
await c.goto(info.url + '/ui');
check('/ui without a login is still just /login', await c.until(`location.pathname==='/login'`, 5000) && (await loc(c)) === '/login', await loc(c));
await c.goto(info.url + '/login#ABCD');
await c.until(`!!document.querySelector('form')`, 5000);
check('with no target the form does not carry a code', (await c.ev(`document.querySelector('form').getAttribute('action')`)) === '/login' && (await c.ev(`document.querySelector('form').action`)).endsWith('/login'), await c.ev(`document.querySelector('form').action`));

console.log(fails.length ? `\n${fails.length} FAILED` : '\nall ok');
done(fails.length ? 1 : 0);

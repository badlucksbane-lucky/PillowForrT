# Installing Stone of Heimdall

**Where this stands.** Building it, updating a unit that already runs it, setting the login and
first sign-in are written down and match the scripts. **The very first install on a stock,
unrooted hotspot is not documented or supported yet**: see [First install](#first-install-not-yet-supported)
at the end for what it must leave on the device. If your unit does not already run this software,
you can read this guide but not finish it.

## Before you start
- An Orbic RC400L hotspot you are willing to risk. Rooting may void the warranty or breach the
  carrier's terms. Reading some flash partitions can freeze the unit until a power cycle:
  **never read `mtdblock1`.**
- A trusted computer on the hotspot's LAN with Go 1.24 or newer (see `go.mod`), `ssh` and
  `sha256sum`. Everything is vendored, so building needs no network.
- A written note of the unit's original settings (Wi-Fi name, LAN range, admin login) before you
  change anything.
- This is tested on one unit of one model on one carrier. Treat everything below as "worked there".

## 1. Build
```
./build.sh
```
Cross-builds `tinyfwd` for the hotspot (ARM, one core, roughly 77 MB of usable memory, so keep
extras modest) and prints its SHA-256. Keep that hash: the deploy script checks it on the unit.

## 2. Reach the unit over SSH
Every script below runs `ssh orbic`, key-only, as root, and never prompts (`BatchMode`). Put this
in `~/.ssh/config` on your computer:
```
Host orbic
    HostName 192.168.1.254
    User root
    IdentityFile ~/.ssh/<your key>
    IdentitiesOnly yes
```
Your public key must be in `/data/dropbear/ssh/authorized_keys` on the unit. Test it:
```
ssh orbic true && echo ok
```
The first connection asks you to accept the unit's host key. Do that only from the trusted LAN.

## 3. Deploy the program
```
scripts/deploy-tinyfwd.sh            # deploys ./tinyfwd
scripts/deploy-tinyfwd.sh <binary>   # or a binary you name
```
It copies the file, checks the hash on the unit, keeps the old binary as
`/data/proxy/tinyfwd.prev`, swaps, restarts the service and waits for `/status.json` to answer.
The swap runs detached on the unit, so a dropped SSH session cannot leave it half done.

- `DEPLOYED OK after Ns`: it is running.
- `NO ANSWER - ROLLING BACK` then `ROLLED BACK`: the new binary did not start, and the old one is
  back. Nothing is lost; read the log it prints.
- `HASH MISMATCH`: the copy was damaged. Run it again.

It usually finishes in under a minute.

## 4. Deploy the guard
```
scripts/guard-deploy.sh
```
The guard is a small script that runs every 60 seconds and keeps the router's own settings where
this project needs them: the DNS redirect, SSH, the IPv6 firewall and the suspension of the carrier's
update engines. This script keeps the previous copy as `wpad-guard.sh.prev`, runs one pass, restarts
the loop and prints the rules it manages.

**Know your way back in before you change the guard.** A bad guard rule can cut off SSH. The way back
is the modem's AT command channel over a USB cable, which this release does not document yet.

## 5. Set the web login
```
scripts/set-login.sh
```
You type the username (letters, digits, `.`, `_`, `-`) and a password of 10 or more characters. The
password travels over SSH on standard input and is stored on the unit only as a bcrypt hash. Setting
a login ends every open session.

Until you do this, **nobody can sign in**: a fresh install has no default password and no
sign-up page on the web (so nobody on the LAN can claim it first). The sign-in page says "No login
has been set up yet" and refuses every attempt. The script is the only way in, and it needs SSH.
To do it by hand on the unit: `/data/proxy/tinyfwd -set-login <username>`, with the password on
standard input.

## How sign-in works
- **One account.** A single username and password, stored on the unit only as a bcrypt hash in
  `/data/proxy/secure/auth.json` (mode 0600). The password must be 10 to 72 bytes long; bcrypt ignores
  anything past 72, so longer ones are refused rather than silently cut.
- **HTTPS only.** The page is served over TLS on port 3129 (plain-HTTP requests to the unit's name are
  redirected). The session cookie is marked `Secure`, and every change a signed-in browser makes also
  carries a per-session anti-forgery (CSRF) token.
- **Sessions last 12 hours,** at most 20 at once. Setting a new login, or signing out, ends them.
- **Guessing is throttled.** Five failed attempts from one address, or thirty from anywhere, in ten
  minutes locks sign-in for the rest of that window, and each wrong attempt is also delayed half a second.
  A locked window affects you as well as an attacker: if you mistype five times, wait ten minutes.
- **There is no "forgot password" page.** Recovery is running `scripts/set-login.sh` again over SSH.

## Scripts: the API token (optional, off by default)
Out of the box only the web login works. If you want scripts to call the API without a browser
session, turn on the **script token**:

1. Make a long random secret on your computer, for example `openssl rand -hex 32 > ui.token`.
2. Put it on the unit, readable by root only:
   `scripts/orbic-push.sh ui.token /data/proxy/ui.token 600`
3. Start `tinyfwd` with `-ui-token-file=/data/proxy/ui.token` (the init script that starts it must
   pass the flag), then restart it.
4. Keep a copy in `~/.heimdallstone/ui.token`. `scripts/orbic-api.sh GET /api/wifi` then calls the API
   over HTTPS with the header `X-UI-Token`, pinning the unit's certificate.

Things to know:
- **It is a master key.** The token does everything a signed-in session can, with no session and no
  anti-forgery check, and it also unlocks the per-device and browsing detail in `/status.json`. Guard
  it like the password, and send it **only over HTTPS** (port 3129).
- **No file, no token.** If the flag is not given, or the file is missing or empty, every
  `X-UI-Token` header is refused. (Before commit `c2421f4` it was the other way round: with no file,
  any header was accepted. If you built an earlier version, rebuild.)
- **A separate heartbeat token** (`-beat-token-file`) belongs to the optional heartbeat from a companion
  computer. It is off and hidden by default, and fails closed in the same way.

## 6. First sign-in
Open `https://orbic/` (plain HTTP requests are redirected there). The web page uses a **self-signed
certificate**, so your browser will warn. The sign-in page prints the certificate's SHA-256
fingerprint: compare it with the one your browser shows before you type the password.

Be clear about what that proves. It is trust on first use: it protects every visit after the first,
not the first one. Do the first visit from a device on the trusted LAN. The "Web page certificate" card on the
page lets you download the certificate to install as trusted on a device. A renewal gives a new
fingerprint, and browsers will warn again.

## 7. Start in watch-only mode
A fresh install **only reports** what your devices tried to reach. On the **System** card, leave the outbound services in **Watch only** mode. After a few days, read the "Would be refused" list on that
same card, tick the services your devices really need, and only then switch to enforcing. Turning on
enforcement first will break things you did not know you used.

## If something goes wrong
- The program does not answer: the deploy script already rolled back. To check by hand,
  `ssh orbic 'wget -q -O - http://127.0.0.1:3128/status.json'`.
- A bad update that did start: the old binary is `/data/proxy/tinyfwd.prev`, the old guard is
  `/data/proxy/wpad-guard.sh.prev`.
- The web login is lost: run `scripts/set-login.sh` again.
- SSH is cut off: only the USB AT channel is left (not documented yet). Until it is, change the guard
  only when you can reach the unit physically.

## Check it yourself
Do not take the README's word for it. From a device on the network, run a third-party DNS leak test
and a WebRTC/IPv6 leak test, with the unit's VPN or Tor exit on and off for that device, and see
whether what they report matches what the web page says it is doing.

## First install (not yet supported)
There is no supported way to go from a stock, unrooted unit to the state above. `fork/rootshell/` and
`fork/orbic-at/` are GPL-3.0 code from a third-party project, each file carrying its own license
header that names its source, with the license text alongside:

- `fork/rootshell/` is a small privileged-shell binary. Running on the unit, it gives a root shell
  with the Android network groups the proxy needs.
- `fork/orbic-at/orbic.rs` is the Orbic-specific code that talks to the device's `AT+SYSCMD`
  channel, including how a root shell is first obtained. **It is not wired up and does not compile as
  it stands**: the modules it imports were deliberately left out. It is here to read and to start from.

A finished first install has to leave this on the unit, because the scripts above assume it:
- a root shell with network privileges for the daemon;
- `/data/proxy/` holding the `tinyfwd` binary (mode 755) and `wpad-guard.sh`;
- an init script, `/etc/init.d/http_proxy`, that starts and stops `tinyfwd` and passes it the flags you want (`-ui-token-file`, `-beat-token-file`; see the script token above);
- dropbear, key-only on `192.168.1.254:22`, with its key directory at `/data/dropbear/ssh`;
- `wget` (BusyBox) for the deploy script's health check;
- the other programs the features use (dnsmasq, dropbear, and Tor if you want it), each fetched from
  its own source.

Writing and testing that path on a bare unit is the most useful contribution this project needs.

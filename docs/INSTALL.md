# Installing Stone of Heimdall

**Where this stands.** Building it, updating a unit that already runs it, setting the login and first sign-in are written down and match the scripts.
**The first install on a factory-fresh unit now has an installer, `install/stone-install`, and it is EXPERIMENTAL and UNTESTED from a factory-fresh unit**:
see [First install](#first-install-experimental-untested-on-a-factory-fresh-unit) at the end. Its pieces were tested separately (in a fake filesystem, on
a real unit's busybox, and read-only against a running unit), but the whole path has not yet been run from a stock unit. It can undo itself, but
treat it as a first draft on hardware you are willing to risk.

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

## First install (experimental, untested on a factory-fresh unit)
**Status: written and rehearsed in pieces, never yet run from a factory-fresh unit.** Read the risks below before you use it.

`install/stone-install` puts Stone of Heimdall on an Orbic RC400L over its **USB cable**, with questions you answer in the terminal. It needs:
- a Linux or macOS computer with `python3`, `adb`, and the system `libusb-1.0` (no pip packages), and the cable between it and the unit;
- the three programs for the unit, built for 32-bit ARM and statically linked, in one folder you give with `--payload`:
  `tinyfwd` (build it with `./build.sh`), `dnsmasq` (version 2.91 or newer: the stock one is 2.73) and `dropbearmulti` (the dropbear multi-call binary
  with the `dropbear` and `dropbearkey` applets). Build recipes for the last two are not published yet; use the upstream sources. The scripts the installer
  also needs (`wpad-guard.sh`, `dhcp-hook.sh`, `dnsmasq-swap.sh`, `wps-guard.sh`, `http_proxy.init`) come from this repository.

```
install/stone-install check   --payload DIR     # read-only: what the unit looks like; changes nothing
install/stone-install install --payload DIR     # asks for Wi-Fi name and password, web login, SSH key; shows a summary; you type "install"
install/stone-install rollback                  # undoes the last install from the journal on the unit (works with no network), then the unit reboots
```
`install --dry-run` shows the plan and the exact commands without touching the unit; `--answers FILE` takes the answers as JSON for unattended runs
(see `install/stone-install --help`).

**It installs only onto a unit you have just factory-reset.** Before anything else, `install` asks you to confirm this (interactively, or with
`"confirmed_factory_reset": true` in the answers file); refusing, or leaving it out of an unattended run, cancels before the device is touched.
Installing over a unit already running this, or carrying other changes, is not supported and risks damaging it.

**What it does.** Over USB, with adb, it stages the files into the unit's RAM disk (the only place adb may write), verifies their hashes there, and starts one
root script with a single short AT line. The script journals every change before it makes it, then: puts the programs in `/data/proxy`, makes the SSH host key
and installs your public key, sets the web login (the password arrives on standard input and is never in a command line or a log), sets the Wi-Fi name and password
through `tinyfwd -set-wifi` (the same backup, hostapd check and rollback as the web page), installs the init script and boot link, starts everything, and checks that
the program answers and SSH is listening. If any step fails it undoes everything it did. Passwords travel in files on the RAM disk that are wiped afterwards.

**What to know first**
- **Untested path:** the pieces were tested (a fake filesystem under two shells, the unit's own busybox in a scratch folder, read-only checks and a
  settings restore on a running unit), but not the real first install on a factory-fresh unit, nor the USB switch a fresh unit needs (it appears as `05c6:f626` and must
  be switched into command mode; `install/orbic-at.py mode-switch` does it from the documented request, untried).
- **Rooting:** the unit's AT channel runs commands as root. That is how the installer works and it needs physical access to your own unit. It may void the warranty or
  breach your carrier's terms. Never read the flash partition `mtdblock1`.
- **Hard limit on the AT channel:** lines must stay under 64 bytes and contain no `;` or `,`. A 96-byte line wedged the unit's AT port until a reboot. The installer
  enforces this; if you write your own commands, keep to it.
- **Space:** the root filesystem has only about 6 MB free and `/data` about 128 MB; the staged files take about 18 MB of RAM while they are on the unit.
- **A factory reset does not remove what the installer put on the root filesystem** (the init script and its boot link): a true stock state needs `rollback`.

`fork/` holds GPL-3.0 code from a third-party project, each file with its own license header; `stone-install` does not use it.

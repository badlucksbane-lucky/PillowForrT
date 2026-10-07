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

## 8. The detectors
Eleven passive detectors watch the LAN and raise events; the README's ["What it watches for"](../README.md#what-it-watches-for)
says what each one looks for. This section is about running them: checking they work, reading what
they say, quieting a known-good source, and turning one off. Nothing here is required: every detector
is on from the first start (except the Tor relay check, below) and needs no setup.

### Check they are capturing
Most detectors read the bridge through a raw packet socket, which needs the daemon's capabilities
from the init script. Each card (**ARP watch**, **Rogue DHCP**, **Canary**, **Bare-IP TLS**, **Certificate change**,
**DHCP fingerprint drift**) shows whether its capture is running; the **Canary** card also shows whether
the decoy address is on the bridge, and the **Rogue DHCP** card counts the honest replies it has seen
from the unit itself, so a zero there after a device has joined means it is not seeing the wire.
A card that says capture is off means the raw socket could not be opened; the init script
`/etc/init.d/http_proxy` starts the daemon with the capabilities that needs, so check the daemon was
started from there and read `/data/proxy/tinyfwd.log`.

Two cheap tests from a device on the LAN: `ping 192.168.1.253` should produce a **Canary** event
within seconds, and a shell loop that looks up 20 or more made-up names inside five minutes should
produce an **NXDOMAIN flood** event (a handful of typos never will; 20 distinct failing names from one
device is the threshold).

### Read them
Every finding is an event, on the **Events** card and on the detector's own card, at one of two
levels. **Alert** means something is impersonating or steering the network (`arp_gateway`,
`arp_conflict`, `dns_mitm_confirmed`, `rogue_dhcp`, `tls_ja3_match`). **To look at** means unusual, with a benign
explanation possible (everything else: `arp_flip`, `canary`, `canary_scan`, `tls_bare_ip`,
`dhcp_fingerprint_drift`, `dns_canary`, `dns_plain_fallback`, `dns_exfil`, `dns_nxdomain_flood`,
`dns_mitm_suspect`, `tor_bypass_exit`, `tor_bypass_onion`, `beacon_pattern`, and the MAC churn pair).
Each detector's source file opens with its false positives; the ones to expect on an ordinary LAN:
- `arp_flip` and MAC churn from phones that rejoin with a fresh random MAC;
- `dhcp_fingerprint_drift` after a device's OS update;
- `beacon_pattern` from mail clients, chat apps, smart-home devices and backup software, which all poll on
  a schedule. This is the noisiest detector by design and never rises above "to look at";
- `tls_bare_ip` from a few IoT devices that talk to a hard-coded address.

The text of an event never names a device or an address; the card does, to someone signed in. Events are
rate-limited per source (typically one per 10 minutes, one per MAC per day for fingerprint drift), so a
quiet card does not mean the thing stopped.

### Quiet a known-good source
Each card that has a benign case lets you mark it, from the page, without turning the detector off:
- **Canary**: ignore a MAC (a scanner you run yourself);
- **DNS canary**: ignore a MAC (a DNS research tool);
- **Beacon patterns**: mark a device-to-destination pair as expected;
- **Rogue DHCP**: allow a second server by its MAC (a router or lab DHCP server you run on purpose).
  It is matched by MAC, never by IP, so a forged gateway address is still caught.
Those marks are kept in the detector's own file under `/data/proxy/` and survive restarts. The other
detectors have no allow-list; their rate limits are the only quieting, and they are not meant to be
turned off per device.

### Push notifications
By default nothing leaves the unit. On the **Events** card, give an ntfy address
(`https://ntfy.sh/your-secret-topic`, or plain `http://` only to a server on the LAN) and pick the lowest
level to push; the default is "to look at" and above. What is sent is the generic sentence only, never
a name, MAC or address. Pushes are held to one per kind per 10 minutes and 20 an hour, so a flood on the
page is a few pushes on your phone.

### The JA3 fingerprint check
`tls_ja3_match` compares the JA3 fingerprint of every outbound ClientHello (the same one the Bare-IP TLS
card already parses) against a hash list, and needs no setup to run -- but like the Tor relay check, the
unit will not fetch that list on its own. It ships empty and so, until you populate it, this check never
fires. To turn it on, put one `<md5 hash>,<name>` pair per line in `/data/proxy/ja3-blocklist.txt` from a
threat-intel JA3 feed you trust (e.g. Abuse.ch's SSL Blacklist):
```
scripts/orbic-push.sh ja3-blocklist.txt /data/proxy/ja3-blocklist.txt 644
```
Keep it current yourself; a stale list means silence, not "nothing is wrong". A match is reported as
`tls_ja3_match`, at the **alert** level, since a fingerprint match is a stronger signal than the plain
bare-IP/no-SNI heuristic the same card also raises.

### The Tor relay check
`tor_bypass_exit` (a device running its own Tor client, outside the unit's Tor controls) needs a list of
relay addresses, and the unit will not fetch one on its own. It ships with the list empty and the
check off. To turn it on, put one IP or CIDR per line (`#` comments allowed) in
`/data/proxy/tor-exits.txt`:
```
scripts/orbic-push.sh tor-exits.txt /data/proxy/tor-exits.txt 644
```
Keep it current yourself; relays change by the hour, and a stale list means silence, not "nothing is
wrong". The `.onion` half of the same card (`tor_bypass_onion`) needs no list.

### Turn one off
**Canary** and **DNS canary** have a switch on their cards. The rest are on while the daemon runs, with
these exceptions set on the daemon's command line in `/etc/init.d/http_proxy` (the deploy script does
not touch that file; change it over ssh and restart the service):

| Flag | Default | Turns off |
|---|---|---|
| `-arp-watch=false` | on | ARP watch, and with it MAC churn and the ARP half of the ARP / DNS correlation |
| `-rogue-dhcp=false` | on | Rogue DHCP |
| `-tls-sni-watch=false` | on | Bare-IP TLS, and with it the JA3 fingerprint check |
| `-tls-cert-watch=false` | on | Certificate change (and `-tls-cert-file ""` keeps its per-name baseline in memory only instead of `/data/proxy/tlscert.json`) |
| `-dhcp-fp-watch=false` | on | DHCP fingerprint drift |
| `-canary ""` | `192.168.1.253` | The canary entirely, including the decoy address on the bridge |
| `-tor-exit-file ""` | `/data/proxy/tor-exits.txt` | The Tor relay check (an empty or missing file does the same) |

The detectors inside the DNS stub (DNS canary, NXDOMAIN flood, ARP / DNS correlation, the `.onion`
check) and the beacon detector ride the stub and the outbound sampler and have no flag of their own:
they stop when those do (`-dns-listen ""`, or the outbound services mode set to off).

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

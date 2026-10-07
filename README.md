<p align="center"><img src="assets/logo-parchment.svg" width="560" alt="Stone of Heimdall: a watchman for your hotspot"></p>

# Stone of Heimdall
### watchman for your hotspot

**A privacy and intrusion-watching firmware layer for the Orbic RC400L cellular hotspot.** One static Go binary (`tinyfwd`) replaces the stock admin page and takes over DNS, the firewall, Wi-Fi settings and the exits, then sits on the LAN bridge and watches the wire. It filters DNS and forces it to leave encrypted, sends chosen devices through a VPN or Tor, closes the IPv6 and WebRTC address leaks, blocks outbound services you have not approved, and raises an event when something on your network behaves like a scanner, a spoofer, a rogue router or malware phoning home.

**It watches before it guards.** A fresh install only reports what your devices tried to reach (the "would be refused" list), and you decide what to allow before anything is enforced. Every detector is passive: nothing is ever sent, nothing is decrypted, and the text of an event never names a device or an address.

"Orbic" is the trademark of its owner and appears here only to say which hardware this runs on. This project is not affiliated with or endorsed by Orbic or any carrier.

<p align="center"><img src="assets/screenshot-ui.jpg" width="420" alt="The Stone of Heimdall web UI: collapsible cards for the DNS filter, Tor, events, ARP watch, devices, Wi-Fi and more, with today's query, block and encryption counts at the top"></p>

## Contents
- [What it guards](#what-it-guards)
- [What it watches for](#what-it-watches-for)
- [The rest of the page](#the-rest-of-the-page)
- [How it is put together](#how-it-is-put-together)
- [Build and test](#build-and-test)
- [Repository map](#repository-map)
- [What it does not do](#what-it-does-not-do)
- [First install](#first-install)
- [How it was made](#how-it-was-made)
- [Status and license](#status-and-license)

## What it guards
Tested on one unit; see ["Check it yourself"](docs/INSTALL.md#check-it-yourself) in `docs/INSTALL.md` to verify each one on yours. The full list of claims, and where each one stops, is in [`docs/THREAT-MODEL.md`](docs/THREAT-MODEL.md).

- **Encrypted DNS, or nothing.** Every query goes `device -> dnsmasq -> filter stub -> DNS-over-HTTPS` (Quad9 and Cloudflare by default, dialled by IP so there is no bootstrap lookup). Plain DNS and DNS-over-TLS are refused out of the cellular side, so a device with its own resolver settings gets nowhere. If DoH stays down for 60 seconds the stub may fall back to the carrier's resolvers with a visible warning; you can turn that fallback off.
- **A DNS filter** with a catalog of published block lists, your own wildcard rules (`*.example.com`, `ads*.example.com`, `*track*`, per device, optionally for a limited time), an allow-list that always wins, per-device modes, and a "why was this blocked?" box that names the list or rule responsible. Lists live in memory as sorted 64-bit hashes, so switching one on or off is instant and 130k names cost about 1 MB.
- **Per-device exits:** direct, Mullvad (an in-process WireGuard tunnel with a kill switch, so a dead tunnel blocks instead of leaking), or Tor (forced in the kernel by MAC, fails closed). The whole house can default to the VPN, and PAC-proxy users ride it too.
- **No IPv6 leaks.** LAN IPv6 is off by default: the stock router-advertisement relay is muzzled, LAN IPv6 headed for the cellular side is refused, and a withdraw advertisement makes devices drop the address they already hold. Without this a device behind the IPv4-only tunnel still showed its real carrier IPv6 address through WebRTC.
- **Default-deny outbound.** Forwarded connections are matched against an allow-list of services, global or per device. A fresh install ticks web, QUIC, clock sync, ssh, email and push notifications; calls, consoles, VPN protocols, torrents, remote desktop, MQTT and IRC are off. A monitor mode samples the connection table every 10 seconds and tallies, per device, what *would* be refused, so you build the list from what the house really uses before you flip it to enforce.
- **Blocked devices that stay blocked.** The stock Wi-Fi deny list does not hold on this driver (a dropped device walked straight back in), so a blocked MAC is dropped in the firewall and deauthenticated whenever it reappears.
- **Blocked destinations** (IP or CIDR, for every device and for the router's own proxied traffic), and **internet schedules and pauses** per device that cut the internet but keep the LAN, DHCP and this page.
- **House-wide `.onion`.** A small client-only Tor runs on the box. Any device can open a v3 `.onion` name with no setup: the stub answers with an address from `198.18.0.0/16` and the firewall sends that TCP through a bridge into Tor's SOCKS port. A `.onion` name never reaches a public resolver.
- **The stock admin switched off** for the network (reversibly), the carrier's firmware-update and remote-management engines kept suspended, and WPS forced off every five minutes in case a reset turns it back on.
- **A web page over HTTPS** behind one bcrypt login with a session cookie and CSRF token; optional API-key token for scripts, off by default. Key-only SSH. No telemetry. Nothing leaves the house unless you configure it.

## What it watches for
Eleven detectors run on the box, most of them reading the LAN bridge through an `AF_PACKET` socket with a kernel filter that passes only the frames they need. Each finding becomes an event at one of two levels: **alert** (something is impersonating or steering the network) or **to look at** (unusual, with a benign explanation possible). Each detector's source file opens with its honest limits; the main one is shared: traffic the radio relays Wi-Fi-to-Wi-Fi never reaches the bridge, though broadcasts and anything aimed at the router do.

| Card | What it sees | Findings |
|---|---|---|
| **ARP watch** | Every ARP claim on the bridge | A foreign MAC claiming the router's address (alert); a MAC claiming an address reserved for another device (alert); an address changing owner within 10 minutes (to look at: poisoning looks like this, but so does a phone rejoining with a fresh random MAC) |
| **MAC churn** | The same ARP stream over a wider window | One IP claimed by three or more MACs, or one MAC claiming four or more IPs, within 10 minutes |
| **Rogue DHCP** | Every DHCP offer, ack and nak | A reply not from the router's own address *and* own MAC: a plugged-in router, a phone sharing its connection, a hostile device |
| **DHCP fingerprint drift** | Option 55 in each DHCP request, the same passive fingerprint Fingerbank and p0f use | A MAC whose fingerprint had settled now sends a different one: new firmware, or a different device answering for a trusted address. One event per MAC per day at most |
| **Canary** | A decoy address, `192.168.1.253`, that the router answers for and tarpits | Anything that pings it, ARPs for it or opens a port there is looking around; five or more ports from one source is a scan |
| **Bare-IP TLS** | The ClientHello of every outbound TLS connection, the one plaintext part of the handshake | A connection with no SNI, or with an IP address as the SNI: hand-rolled C2 clients, TLS probes and a few IoT devices do this; browsers do not |
| **DNS canary** | Every query, from inside the stub | A device asked for one of a few decoy names nobody configured; a query that left as plain port 53 while the stub was doing DoH (something routed around it); a run of long, high-entropy subdomains of one base name, the shape of DNS tunneling |
| **NXDOMAIN flood** | Every answer, from inside the stub | One client racking up NXDOMAIN answers for many *different* base names in a few minutes: the signature of a domain-generation algorithm, distinct from tunneling |
| **ARP / DNS correlation** | The two findings above, together | A public name answered with a LAN address is suspect on its own (nothing on this box ever does that); within a short window of an ARP impersonation it is a confirmed man-in-the-middle (alert) |
| **Tor / proxy bypass** | Outbound connections and `.onion` queries | A device not assigned to the house's Tor path reaching a known Tor relay (ships with the relay list empty and off until you populate it); a device asking for a `.onion` while house-wide `.onion` is off |
| **Beacon patterns** | New connections per (device, destination) pair over two hours, from the same sampler the allow-list uses | Connections spaced regularly, 30 seconds to an hour apart. Deliberately the noisiest detector: IMAP idle, chat heartbeats and smart-home polling look exactly like this, so it is never more than "to look at" |

Rate limits keep the page readable (typically one event per source per 10 minutes), the canary, DNS canary and beacon detectors let a device or destination be marked expected and a known second DHCP server can be allowed by MAC, and the firmware's own **events** detector adds the ordinary signals: a device never seen before, the uplink down and back, encrypted DNS failing, a service dying, the box running hot, bursts of failed ssh logins, a radio dropping out, the certificate renewed, the data plan crossing a threshold, restarts. Events can be pushed to an [ntfy](https://ntfy.sh) topic you choose; that is the one outward-facing feature, so it is off until you give a URL, and what is sent is a generic sentence only.

## The rest of the page
One single-page web UI with collapsible cards. Besides the filter, exits and detectors above:

- **Devices**: one row per device joining the radio (band, connected since), ARP and NDP addresses, reservations, leases, labels and notes you write, the block list, pauses and schedules, DNS activity and exit. **Presence** says who is here now and since when, who was last seen when, and what each device calls itself (host name and DHCP vendor class); devices you choose to watch raise an event when they arrive or leave. Wake-on-LAN.
- **Wi-Fi** settings for both bands, replacing the stock page: every change is backed up, verified against the regenerated hostapd config, and rolled back by itself on a mismatch. The password is write-only.
- **DHCP reservations and pool**, edited in the stock files so they survive a reboot; a reservation change releases the device's old lease so it actually moves.
- **Latency history**: weeks of uplink latency and loss on flash in hourly buckets, with an outage log and a "flaky" event when the link is lossy without being down. **Speed history**: a small download and upload every few hours, never while the house is using the link. **Live graphs** of rates, latency, queries, clients and temperature for the last hour and day, in RAM only.
- **Diagnostics**: one click runs every check and says in plain words what is fine, what deserves a look and what is broken. The report is written to share: no names, MACs, messages, keys or full IPv6 addresses.
- **Scheduled actions** from a fixed list (snapshot, update block lists, run diagnostics, reboot), never an arbitrary command; a reboot needs the word typed and is refused within 10 minutes of boot so a bad schedule cannot loop.
- **Backup**: settings snapshots kept on the box and downloadable, restorable per section, with a "before restore" snapshot taken first. Identity (VPN key, login, TLS key, tokens) is deliberately not in them.
- **Certificate**: the self-signed HTTPS certificate renews itself at 60 days left or on demand, without a restart, and can be downloaded to trust on a device.
- **SSH access**: dropbear's authorized keys (public keys only, ed25519, forwarding always off), the host fingerprint, and a login audit trail. The last key cannot be removed from the page.
- **Onion door**: a Tor onion service that reaches this page from anywhere with no open port, behind three locks (v3 client authorization, the login, read-only unless you turn remote write on). With no authorized client the service is not rendered at all.
- **System** and **cellular** pages read straight from `/proc`, `/sys` and the stock config files; a confirmed reboot; no IMEI, serials or factory reset on offer. A read-only **SMS inbox** from the stock SQLite file, queried from a RAM copy and never written.
- **Node**: `/status.json` reports what the box sees from the carrier's edge, a `/beat` heartbeat lets a companion computer be noticed when it goes silent, and `/metrics` serves aggregate-only numbers in the Prometheus text format, safe to scrape without a login.
- A built-in **PAC file and forward proxy** on `:3128` (the daemon's original job), LAN-only, with a destination guard so a client cannot use it to reach the hotspot's own loopback services.

## How it is put together
- **`tinyfwd`**, one static Go binary, cross-built for ARMv7 with everything vendored: the DNS stub (its own minimal wire parser, no DNS library), the HTTPS page, the proxy, the WireGuard tunnel (wireguard-go as a library, no kernel module), all the detectors, and the supervisors for dnsmasq and Tor. It runs on one Cortex-A7 core with about 77 MB of usable memory, which is why block lists are hash sets, graphs are rings, the stub caps in-flight queries at 64 and nothing keeps a query history on flash.
- **Kernel rules** are rendered into chains the project owns, all prefixed `HS_` (`HS_FW`, `HS_EXIT`, `HS_KILL`, `HS_TOR`, `HS_MACBLOCK`, `HS_LANV6_*` and so on), loaded atomically with `iptables-restore --noflush`, and re-asserted on a loop because the stock firmware rebuilds its own chains on some network events.
- **`wpad-guard.sh`** is the standing guard: a 60-second loop that keeps the services address `192.168.1.254` on the bridge, the DNS redirect, SSH, the IPv6 firewall and the firmware-update suspension in place.
- **Third-party programs** fetched from their own sources: a current static dnsmasq (2.91, swapped in over the stock 2.73 with automatic rollback), dropbear for key-only SSH, and a client-only Tor.
- **Stock files are edited, not replaced**, where a reboot must keep the result (Wi-Fi XML, DHCP pool XML, reservations), always backed up first; where the stock behaviour is simply wrong (the Wi-Fi deny list, the firewall pages) it is bypassed with the project's own rules.

## Build and test
```
./build.sh                       # cross-builds ./tinyfwd for the hotspot and prints its SHA-256
GOFLAGS=-mod=vendor go test ./...  # the unit tests, offline (252 of them at the time of writing)
```
Needs Go 1.24 or newer and nothing from the network. The deploy script checks the printed hash on the unit, and `-buildvcs=false` in `build.sh` is what keeps that hash reproducible. The rule evaluation, planners and thresholds are pure functions so the tests cover them without hardware; the installer has its own tests under `install/test/`.

## Repository map
| Path | What is there |
|---|---|
| `*.go` | The daemon, one file per feature, each opening with a comment that says what it does and where its claims stop. Start with `main.go`, then `dnsproxy.go`, `egress.go`, `events.go` |
| `ui.html`, `login.html` | The single-page UI and the sign-in page, embedded in the binary |
| `docs/` | [`INSTALL.md`](docs/INSTALL.md), [`THREAT-MODEL.md`](docs/THREAT-MODEL.md), [`SECURITY.md`](docs/SECURITY.md) |
| `scripts/` | Run from a trusted computer on the LAN over SSH: deploy the binary with rollback, push the guard, set the login, copy files, call the API. `wpad-guard.sh` and `dhcp-hook.sh` run on the unit |
| `install/` | `stone-install`, the experimental first-install tool over USB; `device/bootstrap.sh` runs on the unit and journals every change so it can roll back; `payload/` holds the init script and the dnsmasq and WPS guards |
| `fork/` | Two files from EFF's [rayhunter](https://github.com/EFForg/rayhunter) (GPL-3.0, unlike the rest): the root shell used by the installer, and its AT-channel installer kept for reading and as a starting point |
| `assets/`, `site/` | Logo and brand files ([`assets/README.md`](assets/README.md)); the GitHub Pages landing page |
| `vendor/` | Vendored Go dependencies, so the build is offline |

## What it does not do
- It is not anonymity. Your carrier still knows where your hotspot is and sees connection metadata. The VPN provider sees what the carrier otherwise would.
- It cannot see inside encrypted traffic and does not try to. The detectors read what is already in the clear (ARP, DHCP, the TLS ClientHello, DNS inside the stub, connection metadata) and nothing else.
- Detectors are signals, not proof. Each one states its false positives, and the noisier ones never rise above "to look at".
- It has been tested on **one unit** of one model on one carrier. Rooting the hotspot may void its warranty or breach the carrier's terms, and reading some flash partitions can freeze the device until a power cycle. You are responsible for your own hardware.

## First install
**Experimental and untested from a factory-fresh unit.** `install/stone-install` installs over the USB cable with questions in the terminal, journals every change and rolls back on failure. Its pieces were tested separately, but the whole path has not yet been run from a stock unit. Read ["First install"](docs/INSTALL.md#first-install-experimental-untested-on-a-factory-fresh-unit) in `docs/INSTALL.md` before you try it. Updating, signing in and configuring a unit that already runs it are documented there too.

## How it was made
Written by Claude, an AI model made by Anthropic, under the direction of the project's maintainer, who set the goals and decisions and tested it on their own hardware. The maintainer did not write or line-by-line audit the code. It has a large automated test suite and one real unit's worth of use. Read it before you trust it with anything that matters.

## Status and license
Early, and a **source release** for now: the install guide is in [`docs/`](docs/); the first-install tool is experimental and untested from a stock unit, so expect to read the code. Licensed under the [MIT license](LICENSE), except the two files in `fork/` (GPL-3.0, from rayhunter); third-party programs it installs (dnsmasq, dropbear, Tor) are fetched from their own sources and keep their own licenses.

- [`docs/SECURITY.md`](docs/SECURITY.md) — how to report a vulnerability
- [`docs/THREAT-MODEL.md`](docs/THREAT-MODEL.md) — what it defends against, and what it does not

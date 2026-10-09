# Handoff: PillowForrT, 2026-10-09

Written at the end of a long session. **Playback works. The box (an Orbic RC400L) freezes and drops connections at random, and has cold-rebooted. Tor has been switched off for every playback test.** The freeze is the open problem; everything else below is context for it.

## State

| | |
|---|---|
| Repo | `github.com/badlucksbane-lucky/PillowForrT` (`origin`, public, full history). The old repo is the `stone-of-heimdall` remote, untouched. |
| Head | `c35387f` (docs only). The binary on the box is the build of `8d9d761`, sha256 starting `96c6a98d01dde6db`. Everything is pushed. |
| Web page | `https://pillowforrt.lan/` (also `pillowforrt`). SSH alias `pillowforrt`. Local config in `~/.pillowforrt` (`tls.pem` pinned certificate, `ui.token`). |
| Certificate | Self-signed, marked as a CA limited by critical name constraints to this box's own names and two addresses (Android's installer only installs a CA). SHA-256 begins `4C:A4:AD:90`. Valid 800 days from 2026-10-09. |
| Deploy | `./build.sh` then `scripts/deploy-tinyfwd.sh` (rolls back by itself if the daemon doesn't answer). Always ask Ben before committing or deploying: he says "commit, build and deploy" each time. |

## What works (all verified on the real box)

- **Web search** (Wikipedia, DuckDuckGo, Wiby) with a selectable proxy and DNS path (Direct, Mullvad, Tor, Tor over Mullvad). Off by default.
- **Browse page** `/browse`: Movies and Series from Cinemeta, Anime from AniList, torrents from YTS, EZTV and a Nyaa relay (`/api/search/nyaa`), all drawn in the browser. Web search is its fourth tab.
- **Play**: WebTorrent in the page, one WebSocket per peer to the box (`/api/bt/conn`), which dials the peer through the Mullvad tunnel only. Peers come from `/api/bt/peers` (UDP and HTTP trackers plus a DHT lookup, all through Mullvad). A service worker (`btclient/sw-src.js`) serves the file to a plain `<video src>`. Upload is **off** by default (Search card: Off, 128 KB/s, 512 KB/s).
- **Measured**: a legal Sintel swarm played in about 20 s with 11 peers by 30 s; 80 of 80 bridge sockets opened and 19 returned real BitTorrent handshakes; the box released its bridge connections after the client left.
- **.onion** is SSH-only and off: no setting in the page or API; change it with `tinyfwd -onion ...` (docs/INSTALL.md).
- **Rebrand** done (see the memory note `project-pillowforrt-rebrand`).

## Open problem: the box freezes and drops connections

### Evidence (box clock, EDT, 2026-10-09)

1. **The log goes silent, then the daemon starts again.** The daemon started at 01:44, 02:02, 02:29, 02:56, 03:03, 03:26, 04:00, 04:19. Deploys explain some of these. At least **02:56, 03:03, 03:26 and 04:19** each directly follow a log silence of 3 to 9 minutes (03:17:58 to 03:26:40 was 8.7 min).
2. **04:19:42 was a cold boot, not a software restart.** Every volume (rootfs, usrfs, usrdata, modem, cachefs) logged "UBIFS recovery needed" and the PMIC reported a 'cold' power-on. I can't tell whether Ben power-cycled it after it froze or it reset itself.
3. **What came just before:** at 04:14 to 04:15 the Pixel opened a burst of TLS connections and the box logged about 50 `TLS handshake error ... write tcp ...: i/o timeout` in a minute (the busiest minute in the log). The last log line was 04:15:17, then nothing until the boot.
4. **Older bursts exist** (48/min on 10-07 22:15, 31/min on 10-06), so the box has been fragile under connection bursts before this session's code.
5. **It is busy at idle.** Five minutes after the reboot, with nobody playing: load average 1.8 to 2.0 on a single core; `tinyfwd` at about 35 to 50 % CPU (4.8 CPU-seconds in a 10-second sample); RSS 50 MB (peak 55 MB); Go heap 52 MB. `main.go:401` sets `debug.SetMemoryLimit(48 << 20)` and `SetGCPercent(40)`.
6. **RAM overall is fine**: `MemAvailable` about 56 to 60 MB, 163 MB total, no OOM lines in dmesg (dmesg only covers the current boot). Connection tracking 77 of 10048. No pstore or last_kmsg exists, so a crash leaves no trace.

### Hypotheses, most likely first

1. **The daemon is over its own memory limit, so the garbage collector runs flat out.** Go caps GC at about half the CPU once the heap exceeds `SetMemoryLimit`; a steady 40 to 50 % CPU at idle matches that. Any extra work (TLS handshakes, a DHT lookup, WireGuard encryption, bridge copying) then starves the rest of the box, including the vendor daemons and possibly the watchdog. *Not yet checked: what holds more than 48 MB of live heap, and whether this predates this session.*
2. **Handshake storm from the player.** One TLS handshake (pure-Go ECDSA P-256 on ARMv7) plus one WebSocket per peer, up to 60 from the page and 96 on the bridge, and a re-announce every 30 s while under 10 peers adds up to about 300 peers again. This is my last change (`8d9d761`), made after the first freezes, so it may have made things worse but did not start them.
3. **DHT and tracker lookups**: hundreds of UDP packets through the userspace WireGuard tunnel per lookup, repeated on each re-announce.
4. **Hardware**: the unit runs on its battery (about 3.7 V, 32 °C when sampled); brownout or thermal behaviour under sustained load hasn't been ruled out.

### Suggested next steps

1. **Measure idle CPU on an older build.** Deploy the binary from before this session (for example the build of `548c995`) right after a reboot, with Ben's approval, and compare `top` and `/metrics` (`pillowforrt_daemon_heap_bytes`). That separates "always like this" from "my additions".
2. **Make the daemon observable.** There is no profiling hook. Add a heap profile behind the token or on loopback, and a log line every 15 s with load, heap and goroutines, so the freeze onset is visible next time.
3. **Fix hypothesis 1 first if confirmed**: find the large allocation; raise the limit only if RAM allows (about 56 MB is free, shared with the vendor daemons).
4. **Reduce the player's load**: multiplex all peers over **one** WebSocket with a small framing protocol (removes the handshake storm), cap peers returned per lookup (about 60), re-announce no more often than every 90 s, lower the caps (page about 25, bridge about 32), and refuse new bridge connections when the load average is high (the own-traffic router already has a load check to copy: `stepUpLoadLimit` in `rungs.go`).
5. **Reproduce only with Ben present**: a freeze needs a power cycle.

## Tor

Tor has been **off** (`tor.json`: enabled false, installed true) for all playback tests. I don't know whether Tor running adds enough memory and CPU to make the freezes worse. The Tor, Tor over Mullvad, and Tor-routed search and Nyaa relay paths were **not exercised on the device this session**. The bridge is Mullvad-only regardless.

## Testing notes

- **Pixel 6a over wireless adb**: the port changes whenever wireless debugging restarts, so ask for the new `ip:port`. A second adb device (USB) is attached, so always use `adb -s`. Chrome's debug socket: `adb forward tcp:9333 localabstract:chrome_devtools_remote`; `/json/new` does not work there, attach to an existing tab. The phone's CA list still has a stale `Stone of Heimdall / orbic` entry (harmless). Android's installer cannot read `file://`, so install from Settings, Encryption & credentials, CA certificate, then the file in Downloads.
- **Real-swarm test without a phone**: serve `browse.html` locally, proxy `/api/*` and the bridge WebSocket to the box with the API token added, drive desktop Chromium over the DevTools protocol, and play a *legal* swarm (Sintel `08ada5a7a6183aae1e09d831df6748d566095a10`). The scripts (`cdp.mjs`, `proxy.mjs`, `play2.mjs`, `bridge-test.mjs`) lived in the session scratchpad and **will be lost**; they are short to rewrite. Offer to move them into `scripts/dev/`.
- **Never run BitTorrent from this Pi directly**: its traffic leaves over the carrier link.

## Left as is, on purpose or for later

- Kept names: "Orbic RC400L" for the hardware, `install/orbic-at.py` and `fork/`, the format tags `orbic-events-2` and `orbic-snapshot-1`, the EVE `stone` key and syslog `stone@0`, `STONE_*` variables, `install/stone-install`.
- The installer does not write the dnsmasq lines for `pillowforrt` and `pillowforrt.lan`; on this unit they were added by hand (backup `/data/dnsmasq.conf.pre-rename`).
- The device's copies of `wpad-guard.sh` and the init script still say `orbic` in comments.
- The house-wide `.onion` bridge still listens on `192.168.1.1:3130`; it does nothing unless a name is mapped.
- MQTT defaults changed (prefix `pillowforrt`, node `box`), so Home Assistant will rediscover.
- No issue tracker is set up in this repo (`bd` has no database here); these items live in this file.

## Pitfalls I hit

`pkill -f` can match and kill your own shell (use `pkill -x`); an unquoted `*` inside a curl option string expands to the files in the current directory; the box's busybox has no `ls --full-time`; the deploy script's rollback does not cover DNS or certificate changes.

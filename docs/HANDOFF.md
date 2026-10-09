# Handoff: PillowForrT, 2026-10-09 (updated after the performance audit)

**Playback works. The box (an Orbic RC400L) used to freeze, drop connections and cold-reboot at random, and Tor has been off for every playback test.** A performance and stability audit on 2026-10-09 found the idle load (the daemon at 40 to 50 % CPU, GC pinned against its memory limit) and fixed it, plus seven other choke points; see "Audit and fixes" below. **The freezes are not proven fixed**: the box also restarted six times in 16 minutes after the audit's second deploy (four confirmed as cold reboots by the watcher, a fifth by its uptime), with healthy vitals just before each death, and that is unexplained. See "The reboot cluster".

## Next session: start here

1. **Read "The reboot cluster" first**, then ask Ben what he was doing between 07:45 and 08:06 on the box's clock (EDT) on 2026-10-09: playing from the Pixel, moving the unit, unplugging or replugging power. Ask what powers the box (its battery or a charger) and what powers the Pi, since the Pi rebooted too.
2. Check the watcher (`pgrep -x watch.sh`; restart command under "Freeze investigation: progress") and read `~/freeze-watch/watch.log` for `up` dropping since 2026-10-09 06:58 (Pi clock).
3. Ask Ben to play a stream from the Pixel with you watching the vitals line (`ssh pillowforrt 'grep "vitals load" /data/proxy/tinyfwd.log | tail'`), to see CPU, heap and `gcs=` under real load now that the idle problem is fixed. Nobody has done that with the audit's fixes in place and the box staying up.
4. Open audit items are listed under "Still open from the audit". Ask before deploying anything; a freeze needs a power cycle.

## Audit and fixes (2026-10-09)

Ten code commits (`2b94e26` to `4aa829b`), all deployed to the box and pushed. The binary on the box is the build of `4aa829b`, sha256 `f640ea3182fa7cbd0f3acbe5637a65670938ec641c2fd13757860e74326e6d8c` (`./build.sh` prints it; the build is reproducible).

| Commit | What | Measured effect |
|---|---|---|
| `2b94e26` | wireguard-go packet buffers 64 KB to 1700 bytes (**local patch to the vendored library**, see below); `vitals.go` wired in: a `vitals` line every 15 s and `/api/debug/heap`, `/api/debug/goroutines` | idle tunnel 25.4 MB to 0.9 MB of heap; daemon idle CPU about 50 % to 5 to 8 %; heap 54 to 64 MB to 19 to 25 MB; `gcs=` 2 to 3 per 15 s |
| `5e7fd15` | bridge: WebSocket frame built in place (no per-chunk copy), page frames read into one reused buffer, message cap 512 to 128 KB | not measured under load |
| `af399a1` | bridge: 2.5 MB/s total cap, no new peer connection or lookup above load 4.0, two lookups at once, repeat lookups answered from a 90 s cache | not measured under load |
| `352dd2d` | DNS stub starts before the block lists are read (they load one by one in the background); hash sets built pre-sized and exact | on the A7 the lists take **9.1 to 9.4 s** to read (a DNS blackout on every restart before this); live list heap 16.0 to 13.7 MB, peak 47 to 34 MB (measured on a fast core) |
| `f273760` | proxy: at most 256 open connections (128 per device), 503 with `Retry-After` beyond; CONNECT keeps the answer flowing after the client half-closes; TCP keepalive on the client side | unit tests only |
| `92f4eb4` | DNS: next DoH resolver asked after 400 ms or at once on failure (hedged); identical in-flight lookups share one request; a failed lookup is remembered 5 s per route | unit tests only |
| `f7feed9` | firewall: rules loaded only when they changed or the hooks are gone (a read-only check every 15 s, full re-assert every 5 min) instead of replacing both tables every 15 s | pause on a fake MAC applied and expired correctly; a deleted hook came back within 10 s |
| `30dab50` | log: rotates at 512 KB (one `.1` copy), client aborts not logged, repeated proxy and TLS-handshake errors said once per 10 min or per minute with a count | old 3.8 MB log moved to `tinyfwd.log.1` (still world-writable, delete it when no longer needed) |
| `dc8dbb3` | `scanProcs` reads `stat` and `cmdline` with bare syscalls and skips kernel threads; the conntrack parser walks the text in place and its strings no longer pin the whole table (before, anything stored from a parsed flow kept the whole dump alive) | on the Pi: `scanProcs` 25.7 to 6.6 ms and 5,655 to 893 allocations (1.2 MB to 47 KB); conntrack, 3,000 lines, 27.6 to 13.9 ms and 14,724 to 2,729 allocations (3.7 to 1.5 MB). On the box: service table and egress view verified, no errors |
| `4aa829b` | the 14 block lists in one merged table (`listindex.go`): a name stored once with a mask of its lists, bucket-indexed on the hash's top bits; built in place at start-up; a list update shares the table's keys and copies only the masks (new names go to a small overlay) | lookup of an unlisted name 51.5 to 1.75 µs and 5 to 0 allocations (this Pi); **costs memory**: live filter heap 13.8 to 19.5 MB, load peak 19.7 to 22.8 MB, daily update +3 MB. On the box: lists read in 8.6 s, heap 25 to 32 MB (was 18 to 27), `sys` 43.6 MB (was 35 to 40), available memory 59 MB (was 62 to 66) |

### What the audit measured

- **The cause of the idle load:** the block lists hold 16 MB live (1.71M names, 8-byte hashes; all lists but nsfw are enabled), the idle WireGuard tunnel held 25.4 MB, base about 5 MB: about 46 MB before any client, against `debug.SetMemoryLimit(48<<20)` in `main.go`. The GC ran against its limit. The first guess in this file (30 MB of lists) was wrong: lists are 16 MB.
- **Shell-outs are not the load:** the daemon's reaped children cost 12 CPU ticks in 30 s (0.4 %).
- **ARMv7 crypto:** Go has no assembly for AES or ChaCha on 32-bit ARM. On a 32-bit ARM build on the Pi, ChaCha20-Poly1305 ran 2.7x faster than AES-GCM (48.6 against 18.2 MB/s), and Go already prefers ChaCha when the server has no AES hardware, so TLS is on the fast one. Every bridged byte is still sealed twice in pure Go (WireGuard, then TLS): my extrapolation to the A7 is about 3 to 4 MB/s of bridge throughput with nothing else running. **That is an estimate, never measured on the box.** It is why the bridge cap is 2.5 MB/s.
- **Load average is a poor health signal on this box:** `kworker/u2:1` sits in uninterruptible I/O wait permanently (+1.0 load), and other kernel workers and `spi1` block in bursts (load spikes of 8 to 14 with the daemon at 4 to 14 % CPU). Use the daemon's `cpu=`, `heap=` and `gcs=` in the vitals line instead. The cause of the I/O waits is unknown (the kernel has no per-process I/O accounting).
- **Process launches:** `/proc/stat` `processes` shows about 20 a second on the box, but it counts threads too and is dominated by vendor kernel `DIAG_*` threads respawning and the `wps-guard.sh` and `wpad-guard.sh` loops, not by the daemon.
- **Kernel 3.18, no BPF JIT:** the roughly ten AF_PACKET watchers run interpreted filters on every bridge packet. Small, not measured.

### Things to know

- **Vendor patch:** `vendor/golang.zx2c4.com/wireguard/device/queueconstants_default.go` has `MaxSegmentSize = 1700` (upstream `(1<<16)-1`). Safe while no UDP GRO is in play (kernel 3.18; GRO needs 5.0+). `go mod vendor` undoes it: reapply it and re-run the idle memory check.
- **Filter fails open while the lists load:** for the first 9 s after a restart (8.6 s measured), names on the block lists are not blocked (the allow-list and your own rules apply at once); all the lists then come into service together, not in groups. `Filter.LoadBase` and `LoadLists` in `filter.go`; the list updater waits for `LoadLists` before it checks for missing lists.
- **The merged filter table** (`listindex.go`, `filter.go`): keys are 64-bit name hashes with the low 4 bits cleared (60-bit keys, about 1 false match in 10^12 a probe), a 16-bit mask says which of the lists (bit = position in `defaultLists`, at most 16) has each name, and the blocking list named is the lowest set bit, as the old per-list search did. Start-up streams every list into one array tagged with the list number, sorts it and compacts it in place. `withList` (the daily update) shares the old table's keys and bucket table, copies the masks, and puts names the table lacks into an overlay, folded back in when it passes 1/`overlayDiv` of the table; a name that left a list stays in the table with an empty mask until the next fold or restart. **It trades memory for speed** (see the table): if the heap becomes a problem, this is the first thing to look at, and the old per-list design is in the history before `4aa829b`. `filterindex_test.go` checks it against the old algorithm on random lists (both overlay modes) and `filter_bench_test.go` benchmarks it on a copy of `/data/dnsfilter` (`FILTER_BENCH_DIR=... go test -run '^$' -bench FilterMatch .`); a one-off run on the box's real lists compared 2.5 million answers in every mode with no difference.
- **Tunables** (variables, easy to change): `btRate` 2.5e6, `btBurst`, `btLoadLimit` 4.0, `btLookups` capacity 2, `btCacheTTL` 90 s (`btbridge.go`); `proxyMaxConns` 256, `proxyMaxPerClient` 128 (`proxylimit.go`); `HedgeAfter` 400 ms, `dnsFailTTL` 5 s (`dnsproxy.go`); `fwReassertEvery` 5 min (`fwrules.go`); `logMax` 512 KB (`lograte.go`); `overlayDiv` 8 (`listindex.go`). If a stream stutters while the CPU has room, the bridge cap is the first suspect.
- **Failed lookups are remembered 5 s per route**, so a name that failed stays refused up to 5 s after the upstream recovers. The memory is keyed by route generation, so a route change (tunnel up, kill tier moved) clears its meaning.
- **Oracle tests and benchmarks:** `oracle_test.go` keeps the original `parseConntrack` and `scanProcs` and checks the fast versions against them (the scan on a snapshot of the real `/proc`, since the live one changes between two reads); `perf_bench_test.go` re-measures both (`go test -run '^$' -bench 'ParseConntrack3000|ScanProcsRealProc' .`). If either function changes again, keep the oracles passing.
- **A blocked name still makes some apps retry** through the proxy (the stub answers 0.0.0.0, the proxy refuses it); the log now says it once per 10 minutes.

### Still open from the audit

- Event store rewrites its whole file on every batch; `macfilter` runs a long shell pipeline every 20 s (read-mostly, but still about 8 launches).
- The race detector does not run on the Pi (its 39-bit address range is unsupported), so the concurrent code added this session (hedging, coalescing, the limiters) is tested but not race-checked.

## The reboot cluster (2026-10-09, unexplained)

All times below are the **box's clock (EDT)**; the Pi's clock (CDT, `~/freeze-watch/watch.log`) is one hour earlier.

- The daemon was deployed at **07:45:34** (commit `5e7fd15`, the bridge write path). Vitals were healthy until **07:49:38** (CPU 11 %, load 1.29, 61.7 MB available, 109 goroutines).
- Then the box restarted at **07:50:28, 07:51:26, 07:53:52, 07:58:00, 08:05:41 and 08:06:43**. Before each, the last vitals line was healthy (CPU 6 to 15 %, load 1.3 to 2.3, 62 to 70 MB free); nothing ramped. The watcher confirmed four of them as **cold reboots** (box uptime dropped from 6148 s to 44, then 40, 44, 38); the 08:05 start is a fifth by the box's current uptime (it booted at about 08:05:06); 08:06:43 is a daemon restart 62 s later. The daemon's vitals started up again about 55 s after each.
- The **Pi rebooted too** at 07:58:01 box time (06:58:01 Pi clock), and the watcher died with it. That is **within one second of the box daemon's fourth start (07:58:00)**: look for something on the box that power-cycles or reboots the Pi (USB port power, a script), or for both losing power together. The cause is unknown (no journal from the previous boot; throttled flags are clean now). The Pi's watcher was restarted at about 16:52 Pi clock and was logging again.
- Since the 08:05 boot the box has **not rebooted**: uptime was 39,391 s (10.9 h) at 19:03, through eight deploys (08:25, 16:40, 16:53, 17:11, 17:27, 17:46, 18:21, 18:56). Every later start in the log is a deploy, and the restarted watcher has seen no uptime drop. That is a quiet box, not a playback test: nobody has played from the Pixel since the cluster.
- No dmesg from before the 08:05 boot survives (no pstore), and the PMIC power-on reason was not read. The current-boot dmesg matched none of the power, reset, watchdog or battery patterns I grepped; `/sys/class/power_supply/usb` shows online with an odd `VOLTAGE_NOW=-19`.
- **I do not know what happened.** Healthy vitals just before a sudden death, a Pi reboot at the same time, and a stable stretch afterwards all fit a **power problem** (the box runs on its battery, about 3.7 V; an unplug, a loose cable, a battery cutting out) better than a software fault, but nothing proves it. It may also have been a playback test from the Pixel with the new bridge code: whether anyone was playing between 07:45 and 08:06 is not recorded. Ask Ben. If he was playing, the bridge write-path change (`5e7fd15`) is the one to suspect, and the unit tests do not cover real load.
- Cheap things that would help: read the PMIC reason right after a boot (`dmesg | grep -i pon`), record battery voltage and charger state in the watcher, and note on the watcher which USB or power source feeds the Pi.

## Original plan (2026-10-09 morning; steps 3 to 5 are done, see the audit)

**First task: find out why the box freezes.** Do this before any new feature. Ben decided on 2026-10-09 that this is the priority.

1. Ask Ben to be present and to say how he wants to recover a frozen box (a freeze needs a power cycle). Don't deploy anything without his say.
2. Read "Open problem" below, then check the box is up: `ssh pillowforrt uptime` and `cat /data/proxy/tinyfwd.log | tail`.
3. Take a baseline at idle: `top -b -n 1`, the daemon's CPU time over 10 s (`/proc/<pid>/stat` fields 14 and 15), `/metrics` heap and goroutines. The strongest lead is the daemon sitting at 40 to 50 % CPU with its heap over the 48 MB limit set in `main.go`.
4. Compare with an older build (deploy the binary from before the player work, then look at the same numbers right after a boot). That tells you whether the idle load predates this session.
5. Add the missing visibility (heap profile, a 15-second heartbeat line with load, heap and goroutines) so that the next freeze leaves evidence, then reproduce under a small player load while watching `top` over SSH.
6. Only then change behaviour (memory limit or leak, one multiplexed WebSocket for peers, lower caps, load shedding).

## State

| | |
|---|---|
| Repo | `github.com/badlucksbane-lucky/PillowForrT` (`origin`, public, full history). The old repo is the `stone-of-heimdall` remote, untouched. |
| Head | The last code commit is `4aa829b`; the docs commits after it only touch this file. The binary on the box is the build of `4aa829b`, sha256 starting `f640ea3182fa7cbd0f3`. Everything is pushed. |
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

## Freeze investigation: progress (later on 2026-10-09)

Deferred by Ben after the first step; **a watcher keeps logging meanwhile.**

- **Watcher:** `~/freeze-watch/watch.sh` runs detached on the Pi (start it again with `cd ~/freeze-watch && setsid nohup ./watch.sh >/dev/null 2>&1 </dev/null &` if `pgrep -x watch.sh` is empty). One line per 15 s in `~/freeze-watch/watch.log` (rotates at 5 MB to `.1`): box uptime, load, daemon CPU ticks, RSS, MemAvailable, handshake-error count, daemon pid, heap bytes, goroutines. **A freeze shows as a gap or `no answer`; a cold reboot as `up` dropping to a small number; a daemon restart as a new `pid`.** `session-1-playback.log` there is the 5 s log of the playback test.
- **Playback test (about 40 min, one Pixel, Sintel-free: a Star Trek episode):** no freeze. Load 2.5 to 3.4, daemon about 65 to 70 % CPU, MemAvailable 37 to 47 MB, heap 54 to 63 MB, goroutines 115 to 150, handshake errors nearly flat. One steady phone does not freeze it; the earlier freezes followed connection bursts.
- **Idle after a fresh restart (nobody playing):** about 35 % of the core (351 CPU ticks in 10 s), heap flat at 53 MB, over the 48 MB `SetMemoryLimit`. Load 1.6 to 2.0 at idle.
- **New lead, not yet checked:** `/data/dnsfilter` holds about 30 MB of blocklists (hagezi gambling 10 MB, tif 10 MB, pro 3.7 MB, phishing-army 2.9 MB, others) and `flt.Load()` keeps them in memory (main.go, right after the limit is set). The comment at main.go:401 says the live heap is small; with these lists it probably is not. If the live set is above 48 MB the GC runs at its CPU cap all the time. To check: how `Filter` stores the domains (map of strings vs a compact structure), then a heap profile; also try disabling the biggest lists to see idle CPU drop.
- **Deployed this session:** the audio-codec warning in `browse.html` (`df73a98`, not pushed). Daemon binary sha256 starts `d9a3b6ada1cfd5d9`. The Pixel's wireless-debugging port changes often.
- **Audio (built and deployed 2026-10-09, commit `8271713`, not yet tried on the Pixel):** AC-3 and E-AC-3 are decoded in the page (`btclient/audio-entry.js` -> `audio.js`: Mediabunny + the FFmpeg decoder as WASM in a blob worker, played through Web Audio and clocked to the `<video>`). `browse.html` `softAudio()` loads it only when the first audio track is AC-3/E-AC-3 and the browser cannot play it; DTS and TrueHD still get the warning. The page CSP gained `'wasm-unsafe-eval'` and `blob:` workers. Test: `scripts/dev/audio-test.mjs` (desktop Chromium, passes). Next: play the E-AC-3 Star Trek file on the Pixel and watch CPU and sync; the daemon binary hash starts `3087aef9031d41fe`.

# Dev tools for the browser player

Node scripts (Node 22, no extra packages except the `ws` module in `btclient/`: run `npm ci` there once). They test the real box and the real player.
Config comes from `~/.pillowforrt/`: `tls.pem` (the box's certificate, to pin) and `ui.token` (the API token).

| Script | What it does |
|---|---|
| `cdp.mjs` | Tiny Chrome DevTools Protocol driver the others import (also works against Chrome on Android over `adb forward`). |
| `live-proxy.mjs` | Serves the real browse page locally and forwards `/api/*` and the bridge WebSocket to the box with the token added. |
| `live-play.mjs` | Plays a torrent in desktop Chromium through the proxy and prints peers and playhead over time. Default: Sintel. |
| `audio-test.mjs` | Plays a local E-AC-3/AC-3 file through `btclient/audio.js` in desktop Chromium (same CSP as the page) and checks sound before and after a seek and silence on pause. |
| `browse-test.mjs` | Loads the real `browse.html` in headless Chromium with every source mocked (Cinemeta, AniList, Kitsu, YTS, EZTV, Torrentio, the Nyaa relay, `/api/bt`) and checks the torrent lists: sources merged and deduped, Torrentio text parsed, one source down, the anime episode stepper, the Nyaa box, the second tap on a row with no seeds. Needs neither the box nor the internet; exits 1 on any failure. `PAGE=other.html` tries a different copy. |
| `mux-test.mjs` | Drives the browser's net shim (`btclient/net-shim.js`) against the real multiplexed bridge (`btmux.go`, started from `go test`, with made-up peers on 127.0.0.1): many peers on one WebSocket, bytes stay with their stream, a peer ending or refused is reported, closing one leaves the rest, the socket closes when idle and reopens, and a refused socket is not retried for 5 s. No box or internet needed; about 25 s; exits 1 on failure. Needs `npm ci` in `btclient/`. |
| `room-test.mjs` | Tests the room client (`roomclient/room.js`) in headless Chromium against the real room channel (`room.go`, started from `go test` as `TestRoomServeForJS`, 4 s grace): create and join, a direct WebRTC link, string/object/unordered/binary messages, round trips, the box relay as the fallback (a page with WebRTC off) with binary and its size limit, a dropped socket resuming the same place with the direct link untouched, a place expiring and re-joining afresh, a reload returning to its place, leaving. With `JSQR_DIR` set (see qr-test.mjs) it also decodes the page's QR code from a screenshot and checks that a link with `#CODE` joins at once. About 40 s. Loopback only; says nothing about a phone on the Orbic's Wi-Fi. |
| `game-test.mjs` | Tests the game shell (`/play`, `/pad`, `gameclient/*.js`; see `docs/GAMES.md`) in headless Chromium against the real room channel (started from `go test`): a screen page and phone-sized pages join by code, the game starts, stick, buttons, pointer, tilt and a private panel arrive, two touches at once, stale and lost input, a full room, pause when a phone goes quiet and the same place back, "Continue without". `SHOTS=dir` keeps screenshots. About 15 s; exits 1 on failure. Loopback only. |
| `pong-unit.mjs` | Fort Pong's rules (`gameclient/fortpong.js`) in plain Node with made-up players and a fixed clock: serve, walls, paddle hits, speed cap, no tunnelling, scoring, serve order, winning, rematch, a player leaving. No browser. |
| `sumo-unit.mjs` | Sumo Push's rules (`gameclient/sumopush.js`) the same way: countdown, stick speed and drag, the shrinking arena, ring-outs, rounds and the match, collisions (momentum, overlap, tunnelling), the dash and its cooldown, a draw, leaving and arriving, seven discs on the start ring. No browser. |
| `imposter-unit.mjs` | Imposter's rules (`gameclient/imposter.js`) in plain Node, recording each phone's private panel: who is told what, turn order, timers, stale answers, the vote and its tie rule, the imposter's guess, scoring, rounds, leaving, a phone coming back, seven players. No browser. |
| `qr-test.mjs` | Decodes what `roomclient/qr.js` makes with an independent decoder (jsQR): every length and version 1 to 10 at levels L and M, join links, UTF-8, random strings, the SVG and the size limit. Needs jsQR (not a dependency): `npm install --ignore-scripts --prefix /tmp/qrcheck jsqr`, then `JSQR_DIR=/tmp/qrcheck node qr-test.mjs`. |
| `bridge-test.mjs` | Dials peers through the box's bridge over TLS and sends a real BitTorrent handshake to each. |

```sh
# peers for a torrent, as the page would get them (writes the first 80)
H=08ada5a7a6183aae1e09d831df6748d566095a10
curl -sN --cacert ~/.pillowforrt/tls.pem -H "X-UI-Token: $(cat ~/.pillowforrt/ui.token)" "https://pillowforrt.lan:3129/api/bt/peers?h=$H" \
  | python3 -c 'import sys,json;p=[];[p.extend(json.loads(l).get("peers",[])) for l in sys.stdin if l.strip().startswith("{")];print(json.dumps(p[:80]))' > /tmp/peers.json
node bridge-test.mjs /tmp/peers.json $H
```

Use **legal** swarms for tests (Sintel and Big Buck Bunny are open movies). Never run BitTorrent from the development machine itself: its traffic would leave over the carrier link, not Mullvad.
**Go easy on the box**: it has frozen under bursts of connections (see `docs/HANDOFF.md`). Run one test at a time, watch `top` over SSH, and have a way to power-cycle it.

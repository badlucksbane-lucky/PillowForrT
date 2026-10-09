# Dev tools for the browser player

Node scripts (Node 22, no extra packages except the `ws` module in `btclient/`: run `npm ci` there once). They test the real box and the real player.
Config comes from `~/.pillowforrt/`: `tls.pem` (the box's certificate, to pin) and `ui.token` (the API token).

| Script | What it does |
|---|---|
| `cdp.mjs` | Tiny Chrome DevTools Protocol driver the others import (also works against Chrome on Android over `adb forward`). |
| `live-proxy.mjs` | Serves the real browse page locally and forwards `/api/*` and the bridge WebSocket to the box with the token added. |
| `live-play.mjs` | Plays a torrent in desktop Chromium through the proxy and prints peers and playhead over time. Default: Sintel. |
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

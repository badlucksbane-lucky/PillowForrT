#!/bin/sh
# Builds btclient.js (WebTorrent for the browser, with the WebSocket `net` shim) and sw.js (WebTorrent's service worker, which serves a file to <video>). The outputs are committed and
# embedded in tinyfwd, so this only needs to run (with npm) when the pinned WebTorrent version or net-shim.js changes.
cd "$(dirname "$0")" || exit 1
npm ci --no-audit --no-fund --loglevel=error || exit 1
./node_modules/.bin/esbuild entry.js --bundle --minify --format=iife --platform=browser --target=es2022 \
  --alias:net=./net-shim.js --alias:path=path-browserify --inject:./process-shim.js --define:global=globalThis --legal-comments=none --outfile=btclient.js || exit 1
./node_modules/.bin/esbuild sw-src.js --minify --legal-comments=none --outfile=sw.js || exit 1
ls -l btclient.js sw.js

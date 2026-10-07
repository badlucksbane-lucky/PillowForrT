#!/bin/bash
# gps-feed.sh -- give the Orbic the location its tower telemetry needs (the hotspot has no GPS). Run on a companion computer on the LAN.
#   gps-feed.sh                 read gpsd on this machine (gpspipe -w) and post each fix with a 2D/3D lock, at most once every 10 s
#   gps-feed.sh 40.7128 -74.0060 [alt] [acc]   post one fixed position (a parked box), then exit
# Uses the same pinned certificate and API token as orbic-api.sh (~/.heimdallstone/). Needs gpspipe (gpsd-clients) and jq for the gpsd mode.
set -eu
CERT=~/.heimdallstone/orbic-tls.pem
[ -s "$CERT" ] || { ssh -o BatchMode=yes orbic 'cat /data/proxy/secure/tls/cert.pem' > "$CERT"; chmod 644 "$CERT"; }
T=$(cat ~/.heimdallstone/ui.token)
post() { curl -s --cacert "$CERT" -X POST -H "X-UI-Token: $T" -H 'Content-Type: application/json' -d "$1" "https://orbic:3129/api/towers/fix"; echo; }
if [ $# -ge 2 ]; then
  post "{\"lat\":$1,\"lon\":$2,\"alt\":${3:-0},\"acc\":${4:-0}}"
  exit
fi
command -v gpspipe >/dev/null || { echo "gpspipe not found: install gpsd-clients, or give a fixed position: $0 <lat> <lon>" >&2; exit 1; }
command -v jq >/dev/null || { echo "jq not found" >&2; exit 1; }
last=0
gpspipe -w | while read -r line; do
  [ "$(printf '%s' "$line" | jq -r '.class')" = TPV ] || continue
  mode=$(printf '%s' "$line" | jq -r '.mode // 0')
  [ "$mode" -ge 2 ] || continue
  now=$(date +%s); [ $((now - last)) -ge 10 ] || continue; last=$now
  body=$(printf '%s' "$line" | jq -c '{lat: .lat, lon: .lon, alt: (.altMSL // .alt // 0), acc: (.eph // 0)}')
  [ "$(printf '%s' "$body" | jq -r '.lat')" != null ] || continue
  post "$body"
done

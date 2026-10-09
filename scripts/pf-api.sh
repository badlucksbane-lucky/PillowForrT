#!/bin/bash
# pf-api.sh <GET|POST> <path> [json]  -- call any endpoint of the box's web API from a shell (HTTPS to :3129, certificate pinned from ~/.pillowforrt/tls.pem, API-key token from
# ~/.pillowforrt/ui.token, never printed). Example: pf-api.sh GET /api/wifi    pf-api.sh POST /api/dhcp/set '{"mac":"aa:bb:cc:dd:ee:ff","ip":"192.168.1.150","name":"test"}'
set -eu
CERT=~/.pillowforrt/tls.pem
[ -s "$CERT" ] || { ssh -o BatchMode=yes pillowforrt 'cat /data/proxy/secure/tls/cert.pem' > "$CERT"; chmod 644 "$CERT"; }
T=$(cat ~/.pillowforrt/ui.token)
if [ "$1" = POST ]; then curl -s --cacert "$CERT" -X POST -H "X-UI-Token: $T" -H 'Content-Type: application/json' -d "${3:-{\}}" "https://pillowforrt.lan:3129$2"
else curl -s --cacert "$CERT" -H "X-UI-Token: $T" "https://pillowforrt.lan:3129$2"; fi
echo

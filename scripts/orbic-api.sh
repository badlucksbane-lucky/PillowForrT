#!/bin/bash
# orbic-api.sh <GET|POST> <path> [json]  -- call any endpoint of the Orbic's web API from a shell (HTTPS to :3129, certificate pinned from ~/.heimdallstone/orbic-tls.pem, API-key token from
# ~/.heimdallstone/ui.token, never printed). Example: orbic-api.sh GET /api/wifi    orbic-api.sh POST /api/dhcp/set '{"mac":"aa:bb:cc:dd:ee:ff","ip":"192.168.1.150","name":"test"}'
set -eu
CERT=~/.heimdallstone/orbic-tls.pem
[ -s "$CERT" ] || { ssh -o BatchMode=yes orbic 'cat /data/proxy/secure/tls/cert.pem' > "$CERT"; chmod 644 "$CERT"; }
T=$(cat ~/.heimdallstone/ui.token)
if [ "$1" = POST ]; then curl -s --cacert "$CERT" -X POST -H "X-UI-Token: $T" -H 'Content-Type: application/json' -d "${3:-{\}}" "https://orbic:3129$2"
else curl -s --cacert "$CERT" -H "X-UI-Token: $T" "https://orbic:3129$2"; fi
echo

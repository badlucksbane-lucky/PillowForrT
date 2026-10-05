#!/bin/bash
# deploy-tinyfwd.sh [binary] -- deploy a built tinyfwd to the Orbic over SSH (no AT channel): push, hash-check, swap, wait for /status.json, and ROLL BACK by itself if it never answers.
# The swap runs detached on the device, so a dropped SSH session cannot leave it half-done. Default binary: ./tinyfwd (from build.sh).
set -eu
HERE="$(cd "$(dirname "$0")" && pwd)"
BIN="${1:-./tinyfwd}"
WANT="$(sha256sum "$BIN" | cut -d' ' -f1)"
"$HERE/orbic-push.sh" "$BIN" /data/proxy/tinyfwd.new 755 | tail -1
ssh -o BatchMode=yes orbic "cat > /tmp/deploy-tinyfwd.sh" <<REMOTE
exec > /tmp/deploy-tinyfwd.log 2>&1
P=/data/proxy
[ "\$(sha256sum \$P/tinyfwd.new | cut -d' ' -f1)" = "$WANT" ] || { echo HASH MISMATCH; exit 1; }
cp \$P/tinyfwd \$P/tinyfwd.prev
/etc/init.d/http_proxy stop; sleep 1
mv \$P/tinyfwd.new \$P/tinyfwd
/etc/init.d/http_proxy start
ok=0; i=0
while [ \$i -lt 25 ]; do sleep 1; i=\$((i+1)); wget -q -O - http://127.0.0.1:3128/status.json 2>/dev/null | grep -q '"class": "vantage"' && { ok=1; break; }; done
if [ \$ok = 1 ]; then echo "DEPLOYED OK after \${i}s"; else
  echo "NO ANSWER - ROLLING BACK"; /etc/init.d/http_proxy stop; sleep 1; cp \$P/tinyfwd.prev \$P/tinyfwd; /etc/init.d/http_proxy start; sleep 2; echo ROLLED BACK; fi
echo FINISHED
REMOTE
ssh -o BatchMode=yes orbic 'rm -f /tmp/deploy-tinyfwd.log; sh -c "nohup sh /tmp/deploy-tinyfwd.sh >/dev/null 2>&1 </dev/null &"'
for i in $(seq 1 40); do sleep 2; if ssh -o BatchMode=yes -o ConnectTimeout=5 orbic 'grep -q FINISHED /tmp/deploy-tinyfwd.log' 2>/dev/null; then break; fi; done
ssh -o BatchMode=yes orbic 'cat /tmp/deploy-tinyfwd.log'

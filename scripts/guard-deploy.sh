#!/bin/bash
# guard-deploy.sh -- push orbic-proxy/wpad-guard.sh to the Orbic over SSH and reload it (the guard keeps the services address, the DNS redirect, SSH, the IPv6 firewall and FOTA suspension in place).
# Keeps the previous copy as wpad-guard.sh.prev, runs one pass, restarts the 60-second loop, and prints the rules it manages. Rescue if SSH itself breaks: the AT+SYSCMD channel over USB (see docs/INSTALL.md).
set -eu
HERE="$(cd "$(dirname "$0")" && pwd)"
"$HERE/orbic-push.sh" "$HERE/wpad-guard.sh" /data/proxy/wpad-guard.sh.new 755 >/dev/null
ssh -o BatchMode=yes orbic 'cd /data/proxy && cp wpad-guard.sh wpad-guard.sh.prev && mv wpad-guard.sh.new wpad-guard.sh && kill $(cat /tmp/wpad-guard.pid) 2>/dev/null; ./wpad-guard.sh once; ( setsid ./wpad-guard.sh >/dev/null 2>&1 </dev/null & echo $! > /tmp/wpad-guard.pid ); sleep 1; echo "loop pid $(cat /tmp/wpad-guard.pid)"'

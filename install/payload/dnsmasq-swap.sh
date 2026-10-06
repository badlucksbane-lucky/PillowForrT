#!/bin/sh
# dnsmasq-swap.sh: make the running dnsmasq our current static build (/data/proxy/dnsmasq, 2.91) instead of the stock 2.73.
# Re-runs the running dnsmasq's own saved command line with the binary replaced, checks DNS and the DHCP process, and on any failure puts
# the stock command back. (2026-10-02) It used to give up for good after ONE failed check; but at boot the check can race tinyfwd's DNS stub (127.0.0.1:5354 came up 3 s
# after the check and the rollback stranded the house on the old 2.73 for hours). Now it waits up to ~70 s for DNS to answer, and a failure retries after 5 minutes, giving up
# (dnsmasq.bad) only after 3 failures in a row.
# `loop` mode (started by the init script at boot): every 60 s, swap if dnsmasq is running the stock one (qcmap may relaunch it).
NEW=/data/proxy/dnsmasq
HOOK=/data/proxy/dhcp-hook.sh
BAD=/data/proxy/dnsmasq.bad
RETRY=/data/proxy/dnsmasq.retry
FAILS=/data/proxy/dnsmasq.fails
LOG=/data/proxy/dnsmasq-swap.log
log() { echo "$(date '+%F %T') $*" >> $LOG; }
swap() {
  [ -x $NEW ] && [ ! -f $BAD ] || return 0
  [ -f $RETRY ] && [ $(( $(date +%s) - $(cat $RETRY) )) -lt 300 ] && return 0   # a failed attempt waits 5 minutes
  pid=$(cat /data/dnsmasq.pid 2>/dev/null); [ -n "$pid" ] && [ -d /proc/$pid ] || return 0
  old=$(tr '\0' ' ' < /proc/$pid/cmdline); [ -n "$old" ] || return 0
  # (2026-10-02) the DHCP hook: dnsmasq runs /data/proxy/dhcp-hook.sh (the stock script, then a note to tinyfwd) when that file is executable. Already our binary: only the hook may be missing.
  hook=0; [ -x $HOOK ] && hook=1
  if [ "$(readlink /proc/$pid/exe)" = "$NEW" ]; then
    [ $hook = 1 ] && echo "$old" | grep -q -- "--dhcp-script=/bin/dnsmasq_script.sh" || return 0
  fi
  new=$(echo "$old" | sed "s#^[^ ]*dnsmasq #$NEW #")
  [ $hook = 1 ] && new=$(echo "$new" | sed "s#--dhcp-script=/bin/dnsmasq_script.sh#--dhcp-script=$HOOK#")
  log "swapping: $old"
  grep -q '^rebind-localhost-ok' /data/dnsmasq.conf || { [ -f /data/dnsmasq.conf.pre-swap ] || cp /data/dnsmasq.conf /data/dnsmasq.conf.pre-swap; echo 'rebind-localhost-ok' >> /data/dnsmasq.conf; log 'added rebind-localhost-ok (2.91 drops 0.0.0.0 answers otherwise)'; }
  $NEW --test --conf-file=/data/dnsmasq.conf >/dev/null 2>&1 || { log "config test failed under new binary"; touch $BAD; return 1; }
  kill $(pidof dnsmasq) 2>/dev/null; sleep 2
  pidof dnsmasq >/dev/null && kill -9 $(pidof dnsmasq) 2>/dev/null; sleep 1
  sh -c "$new"
  ok=0; i=0
  while [ $i -lt 14 ]; do   # up to ~70 s: at boot the daemon's DNS stub can come up after dnsmasq does
    sleep 5; i=$((i+1))
    pidof dnsmasq >/dev/null || break
    if nslookup example.com 127.0.0.1 2>/dev/null | grep -q 'Address.*[0-9]' && nslookup doubleclick.net 127.0.0.1 2>/dev/null | grep -q '0\.0\.0\.0\|::'; then ok=1; break; fi
  done
  if [ $ok = 1 ]; then rm -f $RETRY $FAILS; log "swapped OK after $((i*5))s: $($NEW --version | head -1)"; return 0; fi
  log "CHECK FAILED, restoring the stock dnsmasq"
  kill $(pidof dnsmasq) 2>/dev/null; sleep 2; kill -9 $(pidof dnsmasq) 2>/dev/null
  sh -c "$old"; sleep 2
  date +%s > $RETRY; n=$(cat $FAILS 2>/dev/null || echo 0); n=$((n+1)); echo $n > $FAILS
  if [ $n -ge 3 ]; then touch $BAD; log "3 failures in a row: giving up (delete $BAD to try again)"; else log "will retry in 5 minutes (failure $n of 3)"; fi
  return 1
}
if [ "$1" = loop ]; then
  while :; do swap; sleep 60; done
else
  swap
fi

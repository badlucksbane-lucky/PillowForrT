#!/bin/sh
# wps-guard.sh -- WPS must stay OFF on the Orbic's Wi-Fi (WPS is a known weak spot; a factory reset or the stock settings can turn it back on).
# Runs as root from /etc/init.d/http_proxy at boot and then every 5 minutes. hostapd treats a config with no wps_state as "WPS off"; if a generated
# /tmp/hostapd_wlan*.conf ever has wps_state=1 or 2 (the web settings, a factory reset), set it to 0 and send hostapd a SIGHUP so it reloads. Logs to
# /data/proxy/wps-guard.log: one line per check. Test knobs (env): CONF_GLOB, LOG, ONCE=1 (single pass), NOHUP=1 (do not signal hostapd), WAIT (seconds to wait for the conf).
CONF_GLOB="${CONF_GLOB:-/tmp/hostapd_wlan*.conf}"; LOG="${LOG:-/data/proxy/wps-guard.log}"; WAIT="${WAIT:-120}"
i=0; while [ "$i" -lt "$WAIT" ]; do ls $CONF_GLOB >/dev/null 2>&1 && break; sleep 2; i=$((i + 2)); done
while :; do
  for f in $CONF_GLOB; do
    [ -f "$f" ] || continue
    if grep -q -E '^wps_state=[12]' "$f"; then
      mode=$(stat -c %a "$f" 2>/dev/null); sed -i -E 's/^wps_state=.*/wps_state=0/' "$f"; [ -n "$mode" ] && chmod "$mode" "$f"
      pidf="${f%.conf}.pid"
      [ "${NOHUP:-0}" = 1 ] || { [ -f "$pidf" ] && kill -HUP "$(cat "$pidf")" 2>/dev/null; }
      echo "$(date) $f: WPS WAS ON, switched off and hostapd reloaded" >>"$LOG"
    else
      echo "$(date) $f: WPS off (no wps_state in the config)" >>"$LOG"
    fi
  done
  [ "${ONCE:-0}" = 1 ] && exit 0
  sleep 300
done

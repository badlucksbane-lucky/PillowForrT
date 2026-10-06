#!/bin/sh
# bootstrap.sh -- runs ON the Orbic, as root (started by the host installer with a short AT+SYSCMD line: `sh /tmp/stone/boot.sh install`).
#   install     put the staged files in place, journal every change, start the services, verify; on any failure roll everything back
#   check       read-only report (nothing is changed)
#   rollback    undo the last install from its journal (works with no network: the host runs it over USB), then reboot
#   uninstall   same as rollback
# Staged by the host in $STONE_STAGE (default /tmp/stone, a RAM disk): payload/ + MANIFEST.sha256, env, secrets/*, authorized_keys, identity.tar, state/*.tar.
# Test hooks: STONE_ROOT=<dir> prefixes every device path (device-only steps are skipped); STONE_NO_REBOOT=1; STONE_NO_AUTOROLLBACK=1.
# Never log a value from secrets/ or env: only names. Plain POSIX sh (busybox ash), no bashisms.

[ -z "$STONE_ROOT" ] && PATH="/sbin:/bin:/usr/sbin:/usr/bin:$PATH"; export PATH     # started from the AT daemon, whose environment may be bare
S="${STONE_STAGE:-/tmp/stone}"; R="${STONE_ROOT:-}"
D="$R/data/stone"; J="$D/journal"; BK="$D/backup"; LOG="${STONE_LOG:-$S/log}"
STEP="start"
real() { [ -z "$R" ]; }
log() { mkdir -p "$(dirname "$LOG")" 2>/dev/null; echo "$(date +%H:%M:%S) $*" >> "$LOG"; echo "$*"; }
jadd() { echo "$*" >> "$J"; }
sha() { sha256sum < "$1" 2>/dev/null | cut -d' ' -f1; }

fail() {
  log "STONE-FAILED $STEP"
  if [ -z "$STONE_NO_AUTOROLLBACK" ] && [ -s "$J" ]; then log "rolling back"; do_rollback; fi
  rm -rf "$S/secrets" "$S/identity.tar" 2>/dev/null
  log "STONE-DONE"; exit 1
}
try() { "$@" || fail; }

# ---------------------------------------------------------------- journaled file operations
next_backup() { n=$(cat "$D/backup.n" 2>/dev/null || echo 0); n=$((n+1)); echo $n > "$D/backup.n"; echo $n; }
# mkd <path>: create a directory (and note it) unless it exists
mkd() {
  [ -d "$R$1" ] && return 0
  jadd "CREATED $1"; mkdir -p "$R$1" || return 1
  [ -n "$2" ] && chmod "$2" "$R$1"; return 0
}
# keep_old <path>: before replacing a file, save the old one and journal it (or journal that it is new)
keep_old() {
  if [ -e "$R$1" ] || [ -L "$R$1" ]; then n=$(next_backup); cp -dp "$R$1" "$BK/$n" || return 1; jadd "REPLACED $1 $n"; else jadd "CREATED $1"; fi
}
# put <src> <dest> <mode>: install a file atomically; identical content is left alone
put() {
  src="$1"; dest="$2"; mode="$3"
  if [ -f "$R$dest" ] && [ "$(sha "$src")" = "$(sha "$R$dest")" ]; then chmod "$mode" "$R$dest"; return 0; fi
  mkd "$(dirname "$dest")" || return 1
  keep_old "$dest" || return 1
  cp "$src" "$R$dest.stone-new" && chmod "$mode" "$R$dest.stone-new" && mv "$R$dest.stone-new" "$R$dest"
}
# link <target> <linkpath>
link() {
  [ "$(readlink "$R$2" 2>/dev/null)" = "$1" ] && return 0
  mkd "$(dirname "$2")" || return 1
  keep_old "$2" || return 1
  rm -f "$R$2"; ln -s "$1" "$R$2"
}
# untar <tarfile> <basedir>: extract with every file journaled first
untar() {
  tar -tf "$1" 2>/dev/null | while read -r f; do
    case "$f" in */) continue ;; esac
    keep_old "$(echo "$2/$f" | sed 's#//*#/#g')" || exit 1
  done || return 1
  mkdir -p "$R$2" && tar -xf "$1" -C "$R$2"
}

# ---------------------------------------------------------------- env (parsed, never sourced)
WIFI_SSID=""; WIFI_SSID5=""; LOGIN_USER=""; WANT_TOKEN="no"
read_env() {
  [ -f "$S/env" ] || return 0
  while IFS='=' read -r k v; do
    case "$k" in WIFI_SSID) WIFI_SSID="$v" ;; WIFI_SSID5) WIFI_SSID5="$v" ;; LOGIN_USER) LOGIN_USER="$v" ;; TOKEN) WANT_TOKEN="$v" ;; esac
  done < "$S/env"
}

# ---------------------------------------------------------------- rollback
stop_services() {
  real || return 0
  [ -x /etc/init.d/http_proxy ] && /etc/init.d/http_proxy stop >/dev/null 2>&1
  for p in /tmp/wpad-guard.pid /tmp/dnsmasq-swap.pid /tmp/wps-guard.pid /tmp/dropbear.pid; do
    [ -f "$p" ] && kill "$(cat "$p")" 2>/dev/null; rm -f "$p"
  done
  for b in tinyfwd; do pidof "$b" >/dev/null 2>&1 && kill $(pidof "$b") 2>/dev/null; done
  # our dnsmasq / dropbear (running from /data/proxy) go too; the stock dnsmasq is relaunched by the firmware on boot
  for pid in $(pidof dnsmasq dropbear 2>/dev/null); do
    case "$(readlink /proc/$pid/exe 2>/dev/null)" in /data/proxy/*) kill "$pid" 2>/dev/null ;; esac
  done
  return 0
}
do_rollback() {
  [ -s "$J" ] || { log "no journal: nothing to roll back"; return 1; }
  stop_services
  wifi=0
  awk '{a[NR]=$0} END{for(i=NR;i>0;i--)print a[i]}' "$J" | while IFS= read -r line; do
    set -- $line
    # a journal line is only ever acted on inside the three trees the installer writes to: a damaged line must never reach anywhere else
    case "$2" in /data/stone|/data/stone/*) continue ;; esac     # the journal and the backups live here: never touched until the very end
    case "$2" in /data/?*|/etc/?*|/usrdata/?*) ;; *) log "refusing a journal path outside /data, /etc and /usrdata"; continue ;; esac
    case "$1" in
      CREATED)  rm -rf "$R$2" ;;
      REPLACED) { [ -e "$BK/$3" ] || [ -L "$BK/$3" ]; } && { rm -rf "$R$2"; cp -dp "$BK/$3" "$R$2"; } ;;
    esac
  done
  grep -q '^REPLACED /usrdata/data/usr/wlan/wlan_conf_6174.xml' "$J" && wifi=1
  if [ $wifi = 1 ] && real; then kill $(pidof wland) 2>/dev/null; fi
  cp "$LOG" "$R/data/stone-last.log" 2>/dev/null
  rm -rf "$D"
  log "rolled back"
  return 0
}

# ---------------------------------------------------------------- check (read-only)
do_check() {
  log "CHECK id: $(id 2>/dev/null | cut -d' ' -f1)"
  log "CHECK kernel: $(uname -sr 2>/dev/null)"
  log "CHECK /data free KB: $(df -k "$R/data" 2>/dev/null | tail -1 | awk '{print $4}')   / free KB: $(df -k "${R:-/}" 2>/dev/null | tail -1 | awk '{print $4}')"
  log "CHECK memory: free+buffers+cache KB: $(awk '/^(MemFree|Buffers|Cached):/{s+=$2} END{print s}' /proc/meminfo 2>/dev/null)   (the staged files live in RAM: about 18 MB)"
  for t in sha256sum wget tar awk sed cp mv ln chmod mkdir readlink start-stop-daemon; do command -v $t >/dev/null 2>&1 && log "CHECK tool ok: $t" || log "CHECK tool MISSING: $t"; done
  [ -f "$D/INSTALLED" ] && log "CHECK installed marker: $(cat "$D/INSTALLED")" || log "CHECK no installer marker"
  for f in /data/proxy/tinyfwd /data/proxy/dnsmasq /data/proxy/dropbearmulti /etc/init.d/http_proxy /data/dropbear/ssh/authorized_keys /data/proxy/secure/auth.json; do
    [ -e "$R$f" ] && log "CHECK exists (would be kept or replaced): $f" || log "CHECK absent: $f"
  done
  if [ -f "$S/MANIFEST.sha256" ]; then
    if (cd "$S/payload" && sha256sum -c "$S/MANIFEST.sha256" >/dev/null 2>&1); then log "CHECK staged payload hashes verify"; else log "CHECK staged payload hashes DO NOT verify"; fi
  else log "CHECK nothing staged yet"; fi
  log "STONE-DONE"
}

# ---------------------------------------------------------------- install
wait_status() { i=0; while [ $i -lt 30 ]; do wget -q -O - http://127.0.0.1:3128/status.json 2>/dev/null | grep -q '"class"' && return 0; sleep 2; i=$((i+1)); done; return 1; }
wait_ssh() { i=0; while [ $i -lt 30 ]; do netstat -ltn 2>/dev/null | grep -q ':22 ' && return 0; sleep 2; i=$((i+1)); done; return 1; }

do_install() {
  rm -f "$LOG"; read_env
  STEP="preflight"
  if real && [ "$(id -u)" != 0 ]; then log "must run as root"; fail; fi
  [ -d "$S/payload" ] || { log "nothing staged in $S"; fail; }
  (cd "$S/payload" && sha256sum -c "$S/MANIFEST.sha256" >/dev/null 2>&1) || { log "staged payload hashes do not verify"; fail; }
  free=$(df -k "$R/data" 2>/dev/null | tail -1 | awk '{print $4}'); [ "${free:-0}" -ge 40000 ] || { log "not enough space on /data (${free:-?} KB free, need 40000)"; fail; }
  for t in tar awk sha256sum; do command -v $t >/dev/null 2>&1 || { log "missing tool: $t"; fail; }; done
  [ -f "$J" ] && log "an earlier install left a journal: continuing on top of it"

  STEP="journal"; mkdir -p "$BK" || fail; chmod 700 "$D"; touch "$J"   # $D itself is not journaled: rollback removes it explicitly, after everything else
  cp "$S/boot.sh" "$D/boot.sh" 2>/dev/null || cp "$0" "$D/boot.sh"; chmod 700 "$D/boot.sh"

  STEP="directories"
  try mkd /data/proxy; try mkd /data/proxy/secure 700; try mkd /data/dropbear; try mkd /data/dropbear/ssh 700

  STEP="program files"
  for f in tinyfwd dnsmasq dropbearmulti; do try put "$S/payload/$f" /data/proxy/$f 755; done
  [ -f "$S/payload/tor" ] && try put "$S/payload/tor" /data/proxy/tor 755
  for f in wpad-guard.sh dhcp-hook.sh dnsmasq-swap.sh wps-guard.sh; do [ -f "$S/payload/$f" ] && try put "$S/payload/$f" /data/proxy/$f 755; done
  for l in dropbear dbclient dropbearkey scp; do try link dropbearmulti /data/proxy/$l; done

  STEP="identity"
  if [ -f "$S/identity.tar" ]; then try untar "$S/identity.tar" /; chmod 700 "$R/data/proxy/secure" "$R/data/dropbear/ssh" 2>/dev/null; chmod 700 "$R/data/proxy/secure/tls" "$R/data/proxy/vpn" 2>/dev/null; log "identity restored (login, certificate, tokens, VPN registration, SSH host key)"; fi

  STEP="ssh keys"
  if [ -f "$S/authorized_keys" ]; then
    ak="$R/data/dropbear/ssh/authorized_keys"
    if [ ! -f "$ak" ]; then keep_old /data/dropbear/ssh/authorized_keys || fail; cp "$S/authorized_keys" "$ak"
    else
      keep_old_done=0
      while IFS= read -r line; do [ -n "$line" ] || continue
        grep -qxF "$line" "$ak" || { [ $keep_old_done = 0 ] && { keep_old /data/dropbear/ssh/authorized_keys || fail; keep_old_done=1; }; echo "$line" >> "$ak"; }
      done < "$S/authorized_keys"
    fi
    chmod 600 "$ak"; log "ssh authorized key(s) in place"
  fi
  if [ ! -f "$R/data/dropbear/ssh/host_ed25519" ]; then
    keep_old /data/dropbear/ssh/host_ed25519 || fail
    "$R/data/proxy/dropbearmulti" dropbearkey -t ed25519 -f "$R/data/dropbear/ssh/host_ed25519" >/dev/null 2>&1 || { log "could not make the SSH host key"; fail; }
    chmod 600 "$R/data/dropbear/ssh/host_ed25519"; log "SSH host key made"
  fi

  STEP="web login"
  if [ -n "$LOGIN_USER" ] && [ -f "$S/secrets/login.pw" ]; then
    keep_old /data/proxy/secure/auth.json || fail
    "$R/data/proxy/tinyfwd" -secure-dir "$R/data/proxy/secure" -set-login "$LOGIN_USER" < "$S/secrets/login.pw" >/dev/null 2>&1 || { log "could not set the web login"; fail; }
    log "web login set for the chosen user"
  elif [ -f "$R/data/proxy/secure/auth.json" ]; then log "web login: kept (restored identity)"; else log "web login: NOT SET (run scripts/set-login.sh)"; fi

  STEP="script token"
  if [ "$WANT_TOKEN" = yes ] && [ -f "$S/secrets/ui.token" ]; then try put "$S/secrets/ui.token" /data/proxy/ui.token 600; log "script token installed"; fi

  STEP="saved state"
  for t in "$S"/state/proxy-state.tar; do [ -f "$t" ] && try untar "$t" /data/proxy; done
  [ -f "$S/state/dnsfilter-user.tar" ] && try untar "$S/state/dnsfilter-user.tar" /data
  [ -f "$S/state/extra.tar" ] && { STEP="extra files"; try untar "$S/state/extra.tar" /; log "extra files restored"; }   # paths from /, for anything else to be restored

  STEP="wifi"
  if [ -n "$WIFI_SSID" ] && [ -f "$S/secrets/wifi.pw" ]; then
    "$R/data/proxy/tinyfwd" -h 2>&1 | grep -q 'set-wifi' || { log "the staged tinyfwd is too old: it has no -set-wifi command (build a current one)"; fail; }
    x=/usrdata/data/usr/wlan/wlan_conf_6174.xml
    if [ -f "$R$x" ]; then
      keep_old "$x" || fail
      if [ -n "$WIFI_SSID5" ]; then
        "$R/data/proxy/tinyfwd" -secure-dir "$R/data/proxy/secure" -wlan-xml "$R$x" -set-wifi "$WIFI_SSID" -set-wifi-5ghz-name "$WIFI_SSID5" < "$S/secrets/wifi.pw" >/dev/null 2>&1 || { log "could not set the Wi-Fi"; fail; }
      else
        "$R/data/proxy/tinyfwd" -secure-dir "$R/data/proxy/secure" -wlan-xml "$R$x" -set-wifi "$WIFI_SSID" < "$S/secrets/wifi.pw" >/dev/null 2>&1 || { log "could not set the Wi-Fi"; fail; }
      fi
      log "Wi-Fi name and password set"
    else log "the stock Wi-Fi settings file is missing ($x): refusing to continue without a way to set the Wi-Fi"; fail; fi
  fi

  STEP="init script"
  try put "$S/payload/http_proxy.init" /data/proxy/http_proxy.init 755
  try put "$S/payload/http_proxy.init" /etc/init.d/http_proxy 755
  for rc in rc5.d; do try link ../init.d/http_proxy /etc/$rc/S99http_proxy; done

  if real; then
    STEP="start"; /etc/init.d/http_proxy start >/dev/null 2>&1; wait_status || { log "the program did not answer on :3128 within 60 s"; fail; }
    log "the program is up"
    STEP="guard"; /data/proxy/wpad-guard.sh once >/dev/null 2>&1; wait_ssh || { log "SSH did not come up within 60 s"; fail; }
    log "SSH is listening"
  else log "(fake root: services not started)"; fi

  STEP="finish"
  { echo "installed $(date '+%F %T') tinyfwd $(sha "$R/data/proxy/tinyfwd" | cut -c1-12)"; } > "$D/INSTALLED"
  rm -rf "$S/secrets" "$S/identity.tar" 2>/dev/null
  log "STONE-OK"; log "STONE-DONE"; exit 0
}

case "$1" in
  install)  do_install ;;
  check)    rm -f "$LOG"; do_check ;;
  rollback|uninstall)
    rm -f "$LOG"
    do_rollback; rc=$?; rm -rf "$S/secrets" "$S/identity.tar" 2>/dev/null
    if [ $rc = 0 ] && real && [ -z "$STONE_NO_REBOOT" ]; then log "rebooting in 5 s"; log "STONE-DONE"; ( sleep 5; sync; reboot ) >/dev/null 2>&1 & else log "STONE-DONE"; fi
    exit $rc ;;
  *) echo "usage: sh bootstrap.sh install|check|rollback|uninstall"; exit 2 ;;
esac

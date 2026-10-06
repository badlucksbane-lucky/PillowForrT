#!/bin/sh
# device_smoke.sh -- runs install/device/bootstrap.sh in a FAKE root under /tmp on the real unit (its busybox, its kernel). Touches only /tmp/smoke.
# Push both files and run it as the ordinary adb user (no AT, no root needed):
#   adb -d push install/device/bootstrap.sh /tmp/smoke-in/boot.sh; adb -d push install/test/device_smoke.sh /tmp/smoke-in/smoke.sh; adb -d shell sh /tmp/smoke-in/smoke.sh
B=/tmp/smoke; IN=/tmp/smoke-in; BOOT="$IN/boot.sh"
fails=0; ok() { echo "  ok    $1"; }; bad() { echo "  FAIL  $1"; fails=$((fails+1)); }
chk() { if eval "$2"; then ok "$1"; else bad "$1"; fi; }
tree() { ( cd "$B/root" && find . | sort | while read -r p; do
    if [ -L "$p" ]; then echo "L $p $(readlink "$p")"; elif [ -f "$p" ]; then echo "F $p $(ls -ld "$p" | cut -c1-10) $(sha256sum < "$p")"; else echo "D $p $(ls -ld "$p" | cut -c1-10)"; fi; done | grep -v "stone-last.log" ); }
SL="smoke-login-pw-123"; SW="smoke-wifi-pw-456"
fresh() {
  rm -rf "$B"; mkdir -p "$B/root/data" "$B/root/etc/init.d" "$B/root/etc/rc5.d" "$B/root/usrdata/data/usr/wlan" "$B/stage/payload" "$B/stage/secrets" "$B/stage/state"
  echo "old leftover init" > "$B/root/etc/init.d/http_proxy"; chmod 755 "$B/root/etc/init.d/http_proxy"; ln -s ../init.d/other "$B/root/etc/rc5.d/S99http_proxy"
  echo '<wlan><Basic_0><ssid>StockNet</ssid><psk>stockpass</psk></Basic_0></wlan>' > "$B/root/usrdata/data/usr/wlan/wlan_conf_6174.xml"
  cat > "$B/stage/payload/tinyfwd" <<'STUB'
#!/bin/sh
[ "$1" = -h ] && { echo "  -set-wifi string"; exit 2; }
echo "tinyfwd $*" >> "$STUB_LOG"; secdir=""; xml=""; login=""; wifi=""
while [ $# -gt 0 ]; do case "$1" in -secure-dir) secdir=$2; shift;; -wlan-xml) xml=$2; shift;; -set-login) login=$2; shift;; -set-wifi) wifi=$2; shift;; -set-wifi-5ghz-name) shift;; esac; shift; done
pw=$(head -n1); [ -n "$login" ] && { [ "$STUB_FAIL" = login ] && exit 1; echo "{\"user\":\"$login\"}" > "$secdir/auth.json"; exit 0; }
[ -n "$wifi" ] && { [ "$STUB_FAIL" = wifi ] && exit 1; sed -i "s#<ssid>[^<]*</ssid>#<ssid>$wifi</ssid>#" "$xml"; exit 0; }
exit 0
STUB
  printf '#!/bin/sh\n[ "$1" = dropbearkey ] && { echo fake > "$5"; exit 0; }\nexit 0\n' > "$B/stage/payload/dropbearmulti"
  for f in dnsmasq tor; do echo "binary $f" > "$B/stage/payload/$f"; done
  for f in wpad-guard.sh dhcp-hook.sh dnsmasq-swap.sh wps-guard.sh http_proxy.init; do echo "# $f" > "$B/stage/payload/$f"; done
  chmod 755 "$B/stage/payload/"*; ( cd "$B/stage/payload" && sha256sum * > ../MANIFEST.sha256 )
  printf 'WIFI_SSID=Hearth Home\nWIFI_SSID5=Hearth Home 5G\nLOGIN_USER=alice\nTOKEN=no\n' > "$B/stage/env"
  echo "$SL" > "$B/stage/secrets/login.pw"; echo "$SW" > "$B/stage/secrets/wifi.pw"; echo "ssh-ed25519 AAAAFAKE user@host" > "$B/stage/authorized_keys"
  cp "$BOOT" "$B/stage/boot.sh"
  mkdir -p "$B/idsrc/data/proxy/secure/tls" "$B/idsrc/data/dropbear/ssh"; echo CERT > "$B/idsrc/data/proxy/secure/tls/cert.pem"; echo HK > "$B/idsrc/data/dropbear/ssh/host_ed25519"
  ( cd "$B/idsrc" && tar -cf "$B/stage/identity.tar" data ); mkdir -p "$B/st"; echo '{"n":1}' > "$B/st/state.json"; ( cd "$B/st" && tar -cf "$B/stage/state/proxy-state.tar" state.json )
  export STUB_LOG="$B/calls.log" STONE_ROOT="$B/root" STONE_STAGE="$B/stage" STONE_NO_REBOOT=1; unset STUB_FAIL STONE_NO_AUTOROLLBACK; : > "$STUB_LOG"
}
run() { sh "$BOOT" "$@" > "$B/out.txt" 2>&1; echo $?; }
echo "busybox: $(busybox 2>&1 | head -1)"; echo "kernel: $(uname -sr)   shell: $0   user: $(id -un)"

echo "== check"
fresh; before=$(tree); rc=$(run check)
chk "check exits 0, reports, changes nothing"  '[ "$rc" = 0 ] && grep -q "CHECK staged payload hashes verify" "$B/stage/log" && [ "$(tree)" = "$before" ]'

echo "== install with identity and state"
fresh; before=$(tree); rc=$(run install)
[ "$rc" = 0 ] || sed 's/^/    | /' "$B/stage/log"
chk "install exits 0 with STONE-OK"            '[ "$rc" = 0 ] && grep -q "STONE-OK" "$B/stage/log"'
chk "programs, links, keys, login in place"    '[ -x "$B/root/data/proxy/tinyfwd" ] && [ "$(readlink "$B/root/data/proxy/dropbear")" = dropbearmulti ] && [ -f "$B/root/data/dropbear/ssh/host_ed25519" ] && grep -q AAAAFAKE "$B/root/data/dropbear/ssh/authorized_keys" && [ -f "$B/root/data/proxy/secure/tls/cert.pem" ] && [ -f "$B/root/data/proxy/state.json" ]'
chk "wifi name changed in the stock file"      'grep -q "<ssid>Hearth Home</ssid>" "$B/root/usrdata/data/usr/wlan/wlan_conf_6174.xml"'
chk "init script and rc link replaced leftovers" '[ "$(cat "$B/root/etc/init.d/http_proxy")" = "# http_proxy.init" ] && [ "$(readlink "$B/root/etc/rc5.d/S99http_proxy")" = ../init.d/http_proxy ]'
chk "no secret in the log or journal"          '! grep -rq "$SL\|$SW" "$B/stage/log" "$B/out.txt" "$B/root/data/stone" 2>/dev/null'
echo "== idempotent second install, then rollback"
mkdir -p "$B/stage/secrets"; echo "$SL" > "$B/stage/secrets/login.pw"; echo "$SW" > "$B/stage/secrets/wifi.pw"
rc=$(run install); chk "second install exits 0" '[ "$rc" = 0 ]'
rc=$(run rollback); chk "rollback exits 0" '[ "$rc" = 0 ]'
chk "tree byte-identical to before the install" '[ "$(tree)" = "$before" ]'
echo "== failure mid-install rolls back by itself"
fresh; before=$(tree); export STUB_FAIL=wifi; rc=$(run install)
chk "failed install exits 1, unit identical to before" '[ "$rc" = 1 ] && grep -q STONE-FAILED "$B/stage/log" && [ "$(tree)" = "$before" ]'
unset STUB_FAIL
echo "== tampered payload"
fresh; before=$(tree); echo x >> "$B/stage/payload/dnsmasq"; rc=$(run install)
chk "refused with nothing changed" '[ "$rc" = 1 ] && [ "$(tree)" = "$before" ]'

rm -rf "$B"; echo; echo "SMOKE-DONE failures=$fails"; [ $fails = 0 ]

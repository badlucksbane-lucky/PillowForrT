#!/bin/bash
# bootstrap_test.sh -- runs install/device/bootstrap.sh against a fake root with stub binaries. No device needed.
cd "$(dirname "$0")/.." || exit 1
BOOT="$PWD/device/bootstrap.sh"; T=$(mktemp -d); trap 'rm -rf "${T:?}"' EXIT
pass=0; failn=0
ok()   { pass=$((pass+1)); printf '  ok    %s\n' "$1"; }
bad()  { failn=$((failn+1)); printf '  FAIL  %s\n' "$1"; }
chk()  { if eval "$2"; then ok "$1"; else bad "$1"; fi; }
tree() { (cd "$T/root" && find . -not -path './data/stone-last.log' | sort | while read -r p; do
           if [ -L "$p" ]; then echo "L $p $(readlink "$p")"; elif [ -f "$p" ]; then echo "F $p $(stat -c %a "$p") $(sha256sum < "$p")"; else echo "D $p $(stat -c %a "$p")"; fi; done); }

SECRET_LOGIN="login-secret-9f3"; SECRET_WIFI="wifi-secret-77a"; SECRET_TOKEN="token-secret-c21"
WLAN='<?xml version="1.0"?><wlan><Basic_0><ssid>StockNet</ssid><psk>stockpass</psk></Basic_0><Basic_1><ssid>StockNet5</ssid><psk>stockpass</psk></Basic_1></wlan>'

secrets() { mkdir -p "$T/stage/secrets"; printf '%s\n' "$SECRET_LOGIN" > "$T/stage/secrets/login.pw"; printf '%s\n' "$SECRET_WIFI" > "$T/stage/secrets/wifi.pw"; printf '%s\n' "$SECRET_TOKEN" > "$T/stage/secrets/ui.token"; }

fresh() {   # a stock-like fake unit that already has one leftover init script, and a full stage
  rm -rf "${T:?}"/*
  mkdir -p "$T/root/data" "$T/root/etc/init.d" "$T/root/etc/rc5.d" "$T/root/usrdata/data/usr/wlan" "$T/stage/payload" "$T/stage/state"
  echo "old leftover init" > "$T/root/etc/init.d/http_proxy"; chmod 755 "$T/root/etc/init.d/http_proxy"
  ln -s ../init.d/other "$T/root/etc/rc5.d/S99http_proxy"
  printf '%s' "$WLAN" > "$T/root/usrdata/data/usr/wlan/wlan_conf_6174.xml"; chmod 755 "$T/root/usrdata/data/usr/wlan/wlan_conf_6174.xml"
  cat > "$T/stage/payload/tinyfwd" <<'STUB'
#!/bin/sh
[ "$1" = -h ] && { [ "$STUB_OLD" = 1 ] && echo "  -listen string" || echo "  -set-wifi string"; exit 2; }
echo "tinyfwd $*" >> "$STUB_LOG"
secdir=""; xml=""; login=""; wifi=""
while [ $# -gt 0 ]; do case "$1" in -secure-dir) secdir=$2; shift;; -wlan-xml) xml=$2; shift;; -set-login) login=$2; shift;; -set-wifi) wifi=$2; shift;; -set-wifi-5ghz-name) shift;; esac; shift; done
pw=$(head -n1); printf '%s' "$pw" | sha256sum | cut -c1-16 >> "$STUB_LOG.pwhash"
[ -n "$login" ] && { [ "$STUB_FAIL" = login ] && exit 1; echo "{\"user\":\"$login\"}" > "$secdir/auth.json"; exit 0; }
[ -n "$wifi" ] && { [ "$STUB_FAIL" = wifi ] && exit 1; sed -i "s#<ssid>[^<]*</ssid>#<ssid>$wifi</ssid>#" "$xml"; exit 0; }
exit 0
STUB
  cat > "$T/stage/payload/dropbearmulti" <<'STUB'
#!/bin/sh
[ "$1" = dropbearkey ] && { [ "$2" = -t ] && [ "$4" = -f ] && echo "fake host key" > "$5"; exit 0; }
exit 0
STUB
  for f in dnsmasq tor; do echo "binary $f" > "$T/stage/payload/$f"; done
  for f in wpad-guard.sh dhcp-hook.sh dnsmasq-swap.sh wps-guard.sh http_proxy.init; do echo "# $f" > "$T/stage/payload/$f"; done
  chmod 755 "$T/stage/payload/"*
  (cd "$T/stage/payload" && sha256sum * > ../MANIFEST.sha256)
  printf 'WIFI_SSID=Hearth Home\nWIFI_SSID5=Hearth Home 5G\nLOGIN_USER=alice\nTOKEN=yes\n' > "$T/stage/env"
  secrets
  echo "ssh-ed25519 AAAAFAKEKEY user@host" > "$T/stage/authorized_keys"
  cp "$BOOT" "$T/stage/boot.sh"
  export STUB_LOG="$T/calls.log" STONE_ROOT="$T/root" STONE_STAGE="$T/stage" STONE_NO_REBOOT=1; unset STUB_FAIL STONE_NO_AUTOROLLBACK
  : > "$STUB_LOG"
}
run() { sh "$BOOT" "$@" >"$T/out.txt" 2>&1; echo $?; }

echo "== check changes nothing"
fresh; before=$(tree); rc=$(run check)
chk "check exits 0 and reports"            '[ "$rc" = 0 ] && grep -q "STONE-DONE" "$T/stage/log" && grep -q "CHECK staged payload hashes verify" "$T/stage/log"'
chk "check left the unit byte-identical"   '[ "$(tree)" = "$before" ]'

echo "== install"
fresh; before=$(tree); rc=$(run install)
[ "$rc" = 0 ] || { echo "  (install log:)"; sed 's/^/    | /' "$T/stage/log"; }
chk "install exits 0 with STONE-OK"        '[ "$rc" = 0 ] && grep -q "STONE-OK" "$T/stage/log"'
chk "programs installed mode 755"          '[ "$(stat -c %a "$T/root/data/proxy/tinyfwd")" = 755 ] && [ -f "$T/root/data/proxy/dnsmasq" ] && [ -f "$T/root/data/proxy/wpad-guard.sh" ]'
chk "dropbear applet links"                '[ "$(readlink "$T/root/data/proxy/dropbear")" = dropbearmulti ] && [ -L "$T/root/data/proxy/scp" ]'
chk "SSH host key made, 600, dir 700"      '[ "$(stat -c %a "$T/root/data/dropbear/ssh/host_ed25519")" = 600 ] && [ "$(stat -c %a "$T/root/data/dropbear/ssh")" = 700 ]'
chk "authorized key in place, 600"         'grep -q AAAAFAKEKEY "$T/root/data/dropbear/ssh/authorized_keys" && [ "$(stat -c %a "$T/root/data/dropbear/ssh/authorized_keys")" = 600 ]'
chk "web login set through stdin"          'grep -q "\"user\":\"alice\"" "$T/root/data/proxy/secure/auth.json" && grep -q "^tinyfwd .*-set-login alice$" "$T/calls.log"'
chk "password reached stdin, not argv"     '[ "$(printf %s "$SECRET_LOGIN" | sha256sum | cut -c1-16)" = "$(head -1 "$T/calls.log.pwhash")" ] && ! grep -q "$SECRET_LOGIN\|$SECRET_WIFI" "$T/calls.log"'
chk "wifi set on both radios (names)"      'grep -q -- "-set-wifi Hearth Home -set-wifi-5ghz-name Hearth Home 5G" "$T/calls.log" && grep -q "<ssid>Hearth Home</ssid>" "$T/root/usrdata/data/usr/wlan/wlan_conf_6174.xml"'
chk "script token installed, 600"          '[ "$(stat -c %a "$T/root/data/proxy/ui.token")" = 600 ]'
chk "init script replaced the leftover"    '[ "$(cat "$T/root/etc/init.d/http_proxy")" = "# http_proxy.init" ] && [ "$(readlink "$T/root/etc/rc5.d/S99http_proxy")" = ../init.d/http_proxy ]'
chk "journal, marker and rollback copy"    '[ -s "$T/root/data/stone/journal" ] && [ -f "$T/root/data/stone/INSTALLED" ] && [ -x "$T/root/data/stone/boot.sh" ]'
chk "secrets wiped from the stage"         '[ ! -e "$T/stage/secrets" ]'
chk "no secret in any log or journal"      '! grep -rq "$SECRET_LOGIN\|$SECRET_WIFI\|$SECRET_TOKEN" "$T/stage/log" "$T/out.txt" "$T/root/data/stone" 2>/dev/null'

echo "== install again is idempotent"
secrets; rc=$(run install)
chk "second install exits 0"               '[ "$rc" = 0 ]'
chk "programs unchanged by the second run" '[ "$(sha256sum < "$T/root/data/proxy/tinyfwd")" = "$(sha256sum < "$T/stage/payload/tinyfwd")" ]'

echo "== rollback is byte-identical to before the install"
rc=$(run rollback)
chk "rollback exits 0"                     '[ "$rc" = 0 ]'
chk "tree identical to the pre-install tree" '[ "$(tree)" = "$before" ] || { diff <(echo "$before") <(tree) | head -8; false; }'
chk "leftover init script is back"         '[ "$(cat "$T/root/etc/init.d/http_proxy")" = "old leftover init" ] && [ "$(readlink "$T/root/etc/rc5.d/S99http_proxy")" = ../init.d/other ]'
chk "stock Wi-Fi file is back"             '[ "$(cat "$T/root/usrdata/data/usr/wlan/wlan_conf_6174.xml")" = "$WLAN" ]'

echo "== a failure mid-install rolls back by itself"
for where in wifi login; do
  fresh; before=$(tree); export STUB_FAIL=$where; rc=$(run install)
  chk "failing $where: exit 1, STONE-FAILED logged" '[ "$rc" = 1 ] && grep -q "STONE-FAILED" "$T/stage/log"'
  chk "failing $where: unit identical to before"    '[ "$(tree)" = "$before" ] || { diff <(echo "$before") <(tree) | head -6; false; }'
  chk "failing $where: secrets wiped"               '[ ! -e "$T/stage/secrets" ]'
done
fresh; export STUB_FAIL=wifi STONE_NO_AUTOROLLBACK=1; rc=$(run install)
chk "STONE_NO_AUTOROLLBACK keeps the partial install" '[ "$rc" = 1 ] && [ -s "$T/root/data/stone/journal" ] && [ -f "$T/root/data/proxy/tinyfwd" ]'
unset STUB_FAIL STONE_NO_AUTOROLLBACK; rc=$(run rollback); chk "and it can still be rolled back by hand" '[ "$rc" = 0 ] && [ ! -e "$T/root/data/proxy" ]'

echo "== an outdated tinyfwd (no -set-wifi) is refused with a clear message and rolled back"
fresh; before=$(tree); export STUB_OLD=1; rc=$(run install); unset STUB_OLD
chk "old tinyfwd: install fails clearly, unit unchanged" '[ "$rc" = 1 ] && grep -q "too old: it has no -set-wifi" "$T/stage/log" && [ "$(tree)" = "$before" ]'

echo "== bad payloads and low space change nothing"
fresh; before=$(tree); echo tampered >> "$T/stage/payload/dnsmasq"; rc=$(run install)
chk "tampered payload refused, nothing changed" '[ "$rc" = 1 ] && [ "$(tree)" = "$before" ] && grep -q "hashes do not verify" "$T/stage/log"'
fresh; before=$(tree); mkdir -p "$T/fakebin"; printf '#!/bin/sh\necho "Filesystem 1K-blocks Used Available Use%% Mounted"\necho "ubi 100 99 1 99%% /data"\n' > "$T/fakebin/df"; chmod +x "$T/fakebin/df"
rc=$(PATH="$T/fakebin:$PATH" run install)
chk "low space refused, nothing changed"        '[ "$rc" = 1 ] && [ "$(tree)" = "$before" ] && grep -q "not enough space" "$T/stage/log"'

echo "== a unit without the stock Wi-Fi file refuses and rolls back"
fresh; rm -f "$T/root/usrdata/data/usr/wlan/wlan_conf_6174.xml"; before=$(tree); rc=$(run install)
chk "missing Wi-Fi file: install fails and the unit is unchanged" '[ "$rc" = 1 ] && grep -q "refusing to continue without a way to set the Wi-Fi" "$T/stage/log" && [ "$(tree)" = "$before" ]'

echo "== a damaged journal cannot reach outside the three trees"
fresh; run install >/dev/null; echo "CREATED /home/never" >> "$T/root/data/stone/journal"; echo "CREATED /" >> "$T/root/data/stone/journal"; mkdir -p "$T/root/home/never"
rc=$(run rollback)
chk "rollback ran and refused the bad lines"    '[ "$rc" = 0 ] && grep -q "refusing a journal path" "$T/stage/log" && [ -d "$T/root/home/never" ] && [ -d "$T/root/data" ]'

echo "== identity, saved state and unattended restore"
fresh; mkdir -p "$T/idsrc/data/proxy/secure/tls" "$T/idsrc/data/proxy/vpn" "$T/idsrc/data/dropbear/ssh"
echo '{"user":"restored"}' > "$T/idsrc/data/proxy/secure/auth.json"; echo CERT > "$T/idsrc/data/proxy/secure/tls/cert.pem"; echo WG > "$T/idsrc/data/proxy/vpn/state.json"; echo T1 > "$T/idsrc/data/proxy/ui.token"; echo HK > "$T/idsrc/data/dropbear/ssh/host_ed25519"; echo "ssh-ed25519 AAAAOLD old@box" > "$T/idsrc/data/dropbear/ssh/authorized_keys"
(cd "$T/idsrc" && tar -cf "$T/stage/identity.tar" data); mkdir -p "$T/st"; echo '{"n":1}' > "$T/st/state.json"; (cd "$T/st" && tar -cf "$T/stage/state/proxy-state.tar" state.json)
mkdir -p "$T/ex/data/proxy/extra"; echo DAEMON > "$T/ex/data/proxy/extra/daemon"; chmod 755 "$T/ex/data/proxy/extra/daemon"; echo '#!/bin/sh' > "$T/ex/data/proxy/extra.sh"; chmod 755 "$T/ex/data/proxy/extra.sh"
(cd "$T/ex" && tar -cf "$T/stage/state/extra.tar" data)
printf 'WIFI_SSID=Hearth\nTOKEN=no\n' > "$T/stage/env"; rm -f "$T/stage/secrets/login.pw" "$T/stage/secrets/ui.token"
before=$(tree); rc=$(run install)
chk "restore install exits 0"              '[ "$rc" = 0 ]'
chk "login hash, certificate, VPN, token, host key restored" 'grep -q restored "$T/root/data/proxy/secure/auth.json" && [ -f "$T/root/data/proxy/secure/tls/cert.pem" ] && [ -f "$T/root/data/proxy/vpn/state.json" ] && [ "$(cat "$T/root/data/proxy/ui.token")" = T1 ] && [ "$(cat "$T/root/data/dropbear/ssh/host_ed25519")" = HK ]'
chk "chosen key added next to the restored one" 'grep -q AAAAOLD "$T/root/data/dropbear/ssh/authorized_keys" && grep -q AAAAFAKEKEY "$T/root/data/dropbear/ssh/authorized_keys"'
chk "restored identity dirs are 700"       '[ "$(stat -c %a "$T/root/data/proxy/vpn")" = 700 ] && [ "$(stat -c %a "$T/root/data/proxy/secure/tls")" = 700 ]'
chk "saved state restored"                 '[ "$(cat "$T/root/data/proxy/state.json")" = "{\"n\":1}" ]'
chk "extra files restored with their modes" '[ "$(stat -c %a "$T/root/data/proxy/extra/daemon")" = 755 ] && [ -x "$T/root/data/proxy/extra.sh" ]'
chk "no login step ran (identity kept it)" '! grep -q -- "-set-login" "$T/calls.log"'
rc=$(run rollback); chk "rollback of a restore install is byte-identical" '[ "$rc" = 0 ] && [ "$(tree)" = "$before" ]'

echo; echo "$pass passed, $failn failed"; [ $failn = 0 ]

#!/bin/sh
# dhcp-hook.sh: dnsmasq's --dhcp-script (arguments: add|old|del MAC IP [hostname]; the environment carries DNSMASQ_VENDOR_CLASS and friends). It runs the STOCK script first,
# because the stock admin and qcmap read the /tmp/dnsmasq_host.txt it keeps, and then tells tinyfwd (best effort, in the background, never blocking dnsmasq) so it can learn
# the device's host name and DHCP vendor class and notice arrivals at once. tinyfwd accepts it only from loopback with the beat token. dnsmasq-swap.sh points dnsmasq here
# when this file is executable, and back to the stock script if it is not. (DNSMASQ_STOCK_SCRIPT overrides the stock path, for testing only.)
${DNSMASQ_STOCK_SCRIPT:-/bin/dnsmasq_script.sh} "$@"
T=$(cat /data/proxy/beat.token 2>/dev/null) || exit 0
[ -n "$T" ] || exit 0
V=$(printf %s "$DNSMASQ_VENDOR_CLASS" | tr -cd 'A-Za-z0-9 ._:/()-' | cut -c1-60 | sed 's/ /%20/g')
H=$(printf %s "$4" | tr -cd 'A-Za-z0-9._-' | cut -c1-63)
( wget -q -T 2 -O /dev/null --header "X-Beat-Token: $T" --post-data "op=$1&mac=$2&ip=$3&host=$H&vendor=$V" http://127.0.0.1:3128/dhcp-hook >/dev/null 2>&1 & )
exit 0

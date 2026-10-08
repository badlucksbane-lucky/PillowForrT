#!/bin/sh
# wpad-guard.sh (also the DNS redirect, SSH and FOTA lines below): the name `wpad` (and `orbic`) lives at its own address, 192.168.1.254, so the stock web admin that owns port 80 on 192.168.1.1 is never what
# a client reaches. This keeps (a) the address on the bridge and (b) a DNAT that sends port 80 on that address to the proxy daemon's own PAC/UI server (:3128).
# qcmap rebuilds the NAT chains on some network events, so it re-checks every 60 s (one copy; started by the init script; `once` runs a single pass).
A=192.168.1.254
# IPv6: the kernel has no ip6 nat table, so IPv6 DNS cannot be redirected; it is refused in FORWARD instead (below).
# add a rule once: add_rule <iptables-cmd> <table> <chain> <rule...>  (checks with -C first; the table flag is only for nat)
add_rule() {
  cmd=$1; tbl=$2; chain=$3; shift 3
  $cmd -t $tbl -C $chain "$@" 2>/dev/null || $cmd -t $tbl -I $chain 1 "$@"
}
# The DNS rules. tinyfwd owns them (dnsguard.go: one chain per table, applied atomically, checked by hash) and says so by writing /var/volatile/dnsguard.on once they are in; until then (after a boot,
# or with tinyfwd started with -dns-guard=false) this function installs the same protection the old way, and tinyfwd deletes these loose rules when it takes over.
legacy_dns() {
  # every DNS query a device sends to anyone else (8.8.8.8, a router's own resolver...) comes to the Orbic instead, so the filter cannot be bypassed;
  # the client address is untouched, so the per-device view still works. Encrypted DNS (DoT, port 853) is refused so devices fall back to plain DNS.
  # (iptables 1.4 takes one -d per rule: the Orbic's own addresses are exempted first with RETURN rules, which end up above the REDIRECT)
  for p in udp tcp; do
    add_rule iptables nat PREROUTING -i bridge0 -p $p --dport 53 -j REDIRECT --to-ports 53
    add_rule iptables nat PREROUTING -i bridge0 -p $p --dport 53 -d $A -j RETURN
    add_rule iptables nat PREROUTING -i bridge0 -p $p --dport 53 -d 192.168.1.1 -j RETURN
  done
  add_rule iptables filter FORWARD -i bridge0 -p tcp --dport 853 -j REJECT --reject-with tcp-reset
  # IPv6 does reach the uplink (devices hold global IPv6 addresses) and there is no ip6 nat table to redirect with, so DNS and DoT to any outside IPv6
  # resolver is refused instead; clients then fall back to the Orbic (which they are also told about over IPv6 and IPv4)
  add_rule ip6tables filter FORWARD -i bridge0 -p udp --dport 53 -j REJECT --reject-with icmp6-port-unreachable
  add_rule ip6tables filter FORWARD -i bridge0 -p tcp --dport 53 -j REJECT --reject-with tcp-reset
  add_rule ip6tables filter FORWARD -i bridge0 -p tcp --dport 853 -j REJECT --reject-with tcp-reset
  # No plain DNS leaves over the cellular side, from the Orbic itself or from anyone behind it (): DNS is encrypted (DoH from tinyfwd), carried by the Mullvad tunnel
  # (10.64.0.1 inside it, so never on rmnet) or by Tor. tinyfwd runs with -dns-plain-after -1, so nothing needs the old plain fallback; measured 0 packets before this was added.
  # The redirect above still sends devices' DNS to the Orbic; these rules are the net under it (REJECT, so a stray resolver fails fast instead of hanging).
  for t in iptables ip6tables; do
    for p in udp tcp; do
      for d in 53 853; do
        add_rule $t filter OUTPUT -o rmnet_data+ -p $p --dport $d -j REJECT
        add_rule $t filter FORWARD -i bridge0 -o rmnet_data+ -p $p --dport $d -j REJECT
      done
    done
  done
}
pass() {
  [ -e /var/volatile/dnsguard.on ] || legacy_dns
  # IPv6 firewall on the cellular side. The stock firmware leaves ip6tables INPUT and FORWARD at ACCEPT with no rules, while devices hold global IPv6 addresses (the companion computer
  # listens on SMB, NFS, rpcbind and ssh over IPv6), so nothing but the carrier stood between them and the internet. Now: unsolicited NEW connections arriving from the cellular
  # interfaces are DROPPED silently (stealth: no reset, no ICMP) both to the Orbic itself and to the LAN; replies to our own traffic and related ICMP errors pass, and the
  # ICMPv6 types IPv6 cannot work without (errors 1-4, neighbour/router discovery 133-137) are allowed. Echo requests from outside get no answer.
  add_rule ip6tables filter INPUT -i rmnet_data+ -m state --state NEW -j DROP
  for t in 1 2 3 4 133 134 135 136 137; do add_rule ip6tables filter INPUT -i rmnet_data+ -p icmpv6 --icmpv6-type $t -j ACCEPT; done
  add_rule ip6tables filter FORWARD -i rmnet_data+ -o bridge0 -m state --state NEW -j DROP
  # FOTA (the carrier's firmware-over-the-air engine, `upgrade`): its config already has autocheck/autodown/autoinstall = 0 and no server, and this keeps the
  # process itself suspended so it can never fetch or install anything (suspended, not killed: cpe_daemon would respawn a dead one). Undo: kill -CONT $(pidof upgrade).
  for p in $(pidof upgrade); do grep -q '^State:.*stopped' /proc/$p/status || kill -STOP $p; done
  # dmclient (the carrier's OMA-DM device-management client; it can trigger an update through `upgrade` and holds a credentials file, never print dmacc-current.txt): suspended the same way (). Undo: kill -CONT $(pidof dmclient) and remove this line.
  for p in $(pidof dmclient); do grep -q '^State:.*stopped' /proc/$p/status || kill -STOP $p; done
  ip addr show dev bridge0 | grep -q "inet $A/" || ip addr add $A/32 dev bridge0
  # SSH (dropbear 2026.94, key-only root, ed25519 + chacha20-poly1305 only, no forwarding), on the services address, open to the whole LAN (192.168.1.0/24, 
  # no per-device exceptions and no rate limit, the key is the lock) and to nothing outside it. The accept goes in first, the retired per-source rules come out after it.
  add_rule iptables filter INPUT -p tcp --dport 22 -d $A -j DROP
  add_rule iptables filter INPUT -p tcp --dport 22 -d $A -s 192.168.1.0/24 -j ACCEPT
  # the listener is tracked by its pid file (an open session also shows up in pidof); the audit log is on tmpfs and kept small
  if ! { [ -f /tmp/dropbear.pid ] && kill -0 "$(cat /tmp/dropbear.pid)" 2>/dev/null; }; then
    ( /data/proxy/dropbear -F -s -j -k -T 3 -I 900 -K 30 -p $A:22 -r /data/dropbear/ssh/host_ed25519 -D /data/dropbear/ssh -P /tmp/dropbear.pid >>/var/volatile/dropbear.log 2>&1 </dev/null & )
  fi
  if [ -f /var/volatile/dropbear.log ] && [ "$(wc -c < /var/volatile/dropbear.log)" -gt 262144 ]; then
    tail -c 65536 /var/volatile/dropbear.log > /var/volatile/dropbear.log.new; cat /var/volatile/dropbear.log.new > /var/volatile/dropbear.log; rm -f /var/volatile/dropbear.log.new
  fi
  # FOTA (the carrier's firmware-over-the-air engine, `upgrade`): its config already has autocheck/autodown/autoinstall = 0 and no server, and this keeps the
  # process itself suspended so it can never fetch or install anything (suspended, not killed: cpe_daemon would respawn a dead one). Undo: kill -CONT $(pidof upgrade).
  for p in $(pidof upgrade); do grep -q '^State:.*stopped' /proc/$p/status || kill -STOP $p; done
  ip addr show dev bridge0 | grep -q "inet $A/" || ip addr add $A/32 dev bridge0
  pidof dropbear >/dev/null || /data/proxy/dropbear -s -k -p $A:22 -r /data/dropbear/ssh/host_ed25519 -D /data/dropbear/ssh -P /tmp/dropbear.pid -K 30
  iptables -t nat -C PREROUTING -d $A -p tcp --dport 80 -j DNAT --to-destination 192.168.1.1:3128 2>/dev/null ||
    iptables -t nat -I PREROUTING 1 -d $A -p tcp --dport 80 -j DNAT --to-destination 192.168.1.1:3128
  # https://orbic/ : port 443 on the services address goes to tinyfwd's HTTPS web page (login required); the stock admin keeps 192.168.1.1:443
  iptables -t nat -C PREROUTING -d $A -p tcp --dport 443 -j DNAT --to-destination 192.168.1.1:3129 2>/dev/null ||
    iptables -t nat -I PREROUTING 1 -d $A -p tcp --dport 443 -j DNAT --to-destination 192.168.1.1:3129
  # DHCP reservations survive a reboot: the stock firmware empties /data/dhcp_hosts at every boot (found 2026-10-02, the first reboot since we added reservations; the companion computer came
  # back as .198 and lost SSH). The guard keeps a copy while the file has entries and puts it back, with a dnsmasq SIGHUP, when the file has none.
  if grep -qE '^[0-9a-fA-F:]{17},' /data/dhcp_hosts 2>/dev/null; then
    cmp -s /data/dhcp_hosts /data/proxy/dhcp_hosts.keep 2>/dev/null || cp /data/dhcp_hosts /data/proxy/dhcp_hosts.keep
  elif [ -s /data/proxy/dhcp_hosts.keep ]; then
    cp /data/proxy/dhcp_hosts.keep /data/dhcp_hosts && chmod 644 /data/dhcp_hosts && kill -HUP $(cat /data/dnsmasq.pid 2>/dev/null) 2>/dev/null
  fi
}
if [ "$1" = once ]; then pass; else while :; do pass; sleep 60; done; fi

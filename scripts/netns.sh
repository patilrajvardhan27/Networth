#!/usr/bin/env bash
# Built or tore down the four-namespace test network: client, two translators and a server.
set -euo pipefail
. "$(dirname "$0")/lib.sh"

# Joined two namespaces with a veth pair and a /30 on each end.
link() { # ns1 if1 ip1 ns2 if2 ip2
  ip link add "$2" netns "$1" type veth peer name "$5" netns "$4"
  ns "$1" ip addr add "$3/30" dev "$2"; ns "$4" ip addr add "$6/30" dev "$5"
  ns "$1" ip link set "$2" up; ns "$4" ip link set "$5" up
  ns "$1" ethtool -K "$2" tx off rx off >/dev/null 2>&1 || true
  ns "$4" ethtool -K "$5" tx off rx off >/dev/null 2>&1 || true
}

# Removed every namespace this script knows about.
down() { for n in client nat nat2 server; do ip netns del "ns-$n" 2>/dev/null || true; done; }

# Created the namespaces, links, addresses and the sysctls the translators need.
up() {
  down
  for n in client nat nat2 server; do ip netns add "ns-$n"; ns "ns-$n" ip link set lo up; done
  link ns-client ca "$CA_CLIENT" ns-nat na-c "$CA_NAT"
  link ns-client cb "$CB_CLIENT" ns-nat2 nb-c "$CB_NAT"
  link ns-nat na-s "$SA_NAT" ns-server sa "$SA_SERVER"
  link ns-nat2 nb-s "$SB_NAT" ns-server sb "$SB_SERVER"
  link ns-nat sync-a "$SYNC_A" ns-nat2 sync-b "$SYNC_B"
  ns ns-client ip addr add "$CLIENT_IP/32" dev lo
  ns ns-client ip route add default via "$CA_NAT" dev ca src "$CLIENT_IP"
  ns ns-server ip addr add "$SERVER_IP/32" dev lo
  ns ns-server ip route add "$POOL" via "$SA_NAT" dev sa
  for n in client nat nat2 server; do
    ns "ns-$n" sysctl -qw net.ipv4.conf.all.rp_filter=0 net.ipv4.conf.default.rp_filter=0
  done
  for n in nat nat2; do ns "ns-$n" sysctl -qw net.ipv4.ip_forward=1; done
  log "network up"
}

case "${1:-}" in
  up) up ;;
  down) down ;;
  *) echo "usage: $0 up|down" >&2; exit 2 ;;
esac

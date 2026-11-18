#!/usr/bin/env bash
# Ran the end-to-end suite: TCP, UDP, ICMP, TLS and DNS through the NAT, then a mid-transfer failover.
set -uo pipefail
. "$(dirname "$0")/lib.sh"
PROBE=$ROOT/scripts/probe.py
FAILED=0
WORK=$(mktemp -d)

# Cleaned up processes and namespaces on the way out.
cleanup() { reap; "$ROOT/scripts/netns.sh" down; rm -rf "$WORK"; }
trap cleanup EXIT

# Reported a pass or fail for one named check.
check() { # name command...
  local name=$1; shift
  if "$@"; then log "PASS $name"; else log "FAIL $name"; FAILED=1; fi
}

# Asked the client for a page and expected the server to see a pool address.
tcp_through_nat() { ns ns-client curl -fsS --max-time 5 "http://$SERVER_IP:$HTTP_PORT/" | grep -Eq "peer=198\.51\.100\.([1-9]|[12][0-9]|30):"; }

# Sent a datagram and expected the echo to name a pool address as the sender.
udp_through_nat() { ns ns-client python3 "$PROBE" udp-client "$SERVER_IP" "$UDP_PORT" | grep -Eq "^198\.51\.100\."; }

# Read the MSS the server negotiated and expected it to sit at or under the clamp.
mss_is_clamped() {
  local mss
  mss=$(ns ns-client curl -fsS --max-time 5 "http://$SERVER_IP:$HTTP_PORT/" | sed -n 's/.*mss=//p')
  [ -n "$mss" ] && [ "$mss" -le 1400 ]
}

# Sent to an inside prefix the ACL exempts and expected the server to see the untranslated source.
acl_bypass_skips_translation() { ns ns-client python3 "$PROBE" udp-client "$EXEMPT_IP" "$UDP_PORT" | grep -Eq "^172\.16\.10\.2:"; }

# Fetched a page from an IPv6-only client through the NAT64 prefix and expected a pool address at the server.
nat64_tcp() { ns ns-client curl -g -6 -fsS --max-time 5 "http://[$SERVER_IP6]:$HTTP_PORT/" | grep -Eq "peer=198\.51\.100\.[0-9]+:"; }

# Sent a datagram from the IPv6 client and expected the server to see a pool address.
nat64_udp() { ns ns-client python3 "$PROBE" udp-client "$SERVER_IP6" "$UDP_PORT" | grep -Eq "^198\.51\.100\."; }

# Pinged the IPv4 server from the IPv6 client and expected two replies.
nat64_icmp() { ns ns-client ping -6 -c 2 -W 2 "$SERVER_IP6" >/dev/null; }

# Pinged the server and expected two replies.
icmp_through_nat() { ns ns-client ping -c 2 -W 2 "$SERVER_IP" >/dev/null; }

# Handshook with rustls against openssl and expected a TLS 1.3 session.
tls_through_nat() { ns ns-client "$BIN/tlsprobe" "$SERVER_IP:$TLS_PORT" --server-name nat.test --ca "$WORK/cert.pem" | grep -q "tls ok"; }

# Asked DNS twice and expected the forwarder to answer the second from its cache.
dns_through_nat() {
  for _ in 1 2; do ns ns-client python3 "$PROBE" dns-client "$SERVER_IP" 53 | grep -q "192.0.2.53" || return 1; done
  grep -q "cache hit" "$WORK/dnsfwd.log"
}

# Showed the table through the CLI and expected the pool to appear in it.
show_lists_pool() { ns ns-nat "$BIN/natctl" show | grep -Eq "198\.51\.100\.[0-9]+:[0-9]+ +172\.16\.10\.2:"; }

# Killed the active translator mid-download and expected the standby to finish the stream.
failover_keeps_stream() {
  ns ns-client python3 "$PROBE" stream-client "$SERVER_IP" "$STREAM_PORT" >"$WORK/stream.out" 2>&1 &
  local client=$!
  sleep 2
  kill "${PIDS[0]}"
  ns ns-client ip route replace default via "$CB_NAT" dev cb src "$CLIENT_IP"
  ns ns-server ip route replace "$POOL" via "$SB_NAT" dev sb
  wait "$client" && grep -q "received=60000" "$WORK/stream.out"
}

"$ROOT/scripts/netns.sh" up
make_cert "$WORK"
start_pair || exit 1
start_servers "$WORK"

check "tcp through nat" tcp_through_nat
check "udp through nat" udp_through_nat
check "icmp through nat" icmp_through_nat
check "mss is clamped on the handshake" mss_is_clamped
check "acl exemption skips translation" acl_bypass_skips_translation
if [ "$IPV6" = 1 ]; then
  check "nat64 tcp from an ipv6 only client" nat64_tcp
  check "nat64 udp from an ipv6 only client" nat64_udp
  check "nat64 icmp from an ipv6 only client" nat64_icmp
else
  log "SKIP nat64 checks, this kernel has ipv6 disabled"
fi
check "tls through nat" tls_through_nat
check "dns through nat" dns_through_nat
check "natctl show lists the flows" show_lists_pool
check "failover keeps the tcp stream" failover_keeps_stream
pkill -f "dnsfwd --listen" 2>/dev/null
exit $FAILED

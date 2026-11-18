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

# Started one translator, optionally as the active or the standby side of a sync pair.
start_nat() { # ns sync-flag...
  local n=$1; shift
  bg "$n" "$BIN/natctl" run --pool "$POOL" --mss 1400 \
    --acl "deny $INSIDE_ALL $INSIDE_ALL" --acl "permit $INSIDE any" "$@"
}

# Asked the client for a page and expected the server to see a pool address.
tcp_through_nat() { ns ns-client curl -fsS --max-time 5 "http://$SERVER_IP:$HTTP_PORT/" | grep -Eq "peer=198\.51\.100\.([1-9]|[12][0-9]|30):"; }

# Sent a datagram and expected the echo to name a pool address as the sender.
udp_through_nat() { ns ns-client python3 "$PROBE" udp-client "$SERVER_IP" "$UDP_PORT" | grep -Eq "^198\.51\.100\."; }

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
openssl req -x509 -newkey rsa:2048 -nodes -keyout "$WORK/key.pem" -out "$WORK/cert.pem" -days 2 \
  -subj "/CN=nat.test" -addext "subjectAltName=DNS:nat.test" -addext "basicConstraints=CA:FALSE" 2>/dev/null

start_nat ns-nat --sync-peer "$SYNC_B:$SYNC_PORT"
start_nat ns-nat2 --sync-listen "$SYNC_B:$SYNC_PORT"
nat_routes ns-nat "$CA_CLIENT" "$SA_SERVER" && nat_routes ns-nat2 "$CB_CLIENT" "$SB_SERVER" || exit 1

bg ns-server python3 "$PROBE" tcp-whoami "$SERVER_IP" "$HTTP_PORT"
bg ns-server python3 "$PROBE" udp-echo "$SERVER_IP" "$UDP_PORT"
bg ns-server python3 "$PROBE" stream-server "$SERVER_IP" "$STREAM_PORT"
bg ns-server python3 "$PROBE" dns-stub 127.0.0.1 5353
bg ns-server openssl s_server -quiet -www -accept "$SERVER_IP:$TLS_PORT" -cert "$WORK/cert.pem" -key "$WORK/key.pem"
(ns ns-server env RUST_LOG=dnsfwd=info "$BIN/dnsfwd" --listen "$SERVER_IP:53" --upstream 127.0.0.1:5353 >"$WORK/dnsfwd.log" 2>&1 &)
sleep 1

check "tcp through nat" tcp_through_nat
check "udp through nat" udp_through_nat
check "icmp through nat" icmp_through_nat
check "tls through nat" tls_through_nat
check "dns through nat" dns_through_nat
check "natctl show lists the flows" show_lists_pool
check "failover keeps the tcp stream" failover_keeps_stream
pkill -f "dnsfwd --listen" 2>/dev/null
exit $FAILED

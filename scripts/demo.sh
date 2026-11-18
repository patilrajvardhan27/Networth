#!/usr/bin/env bash
# Stood the whole network up, pushed varied traffic through it and kept the console reachable at http://192.0.2.22:8080.
set -uo pipefail
. "$(dirname "$0")/lib.sh"
WORK=$(mktemp -d)

# Cleaned up processes, namespaces and the host link on the way out.
cleanup() { reap; ip link del demo0 2>/dev/null; "$ROOT/scripts/netns.sh" down; rm -rf "$WORK"; }
trap cleanup EXIT

# Fired a mix of flows from several inside hosts so the table had something to show.
traffic() {
  for host in 172.16.10.2 172.16.10.3 172.16.10.4 172.16.10.5; do
    ns ns-client curl -s --interface "$host" --max-time 5 "http://$SERVER_IP:$HTTP_PORT/" >/dev/null
    ns ns-client python3 "$ROOT/scripts/probe.py" udp-client "$SERVER_IP" "$UDP_PORT" >/dev/null
  done
  ns ns-client python3 "$ROOT/scripts/probe.py" dns-client "$SERVER_IP" 53 >/dev/null
  ns ns-client "$BIN/tlsprobe" "$SERVER_IP:$TLS_PORT" --server-name nat.test --ca "$WORK/cert.pem" >/dev/null
  ns ns-client ping -c 1 -W 1 "$SERVER_IP" >/dev/null
  (ns ns-client python3 "$ROOT/scripts/probe.py" stream-client "$SERVER_IP" "$STREAM_PORT" >/dev/null 2>&1 &)
}

"$ROOT/scripts/netns.sh" up
for i in 3 4 5; do ns ns-client ip addr add "172.16.10.$i/32" dev lo; done
ip link add demo0 type veth peer name demo1 netns ns-nat
ip addr add 192.0.2.21/30 dev demo0 && ip link set demo0 up
ns ns-nat ip addr add 192.0.2.22/30 dev demo1 && ns ns-nat ip link set demo1 up
make_cert "$WORK"
start_pair --admin 192.0.2.22:8080 || exit 1
start_servers "$WORK"
traffic
log "console ready at http://192.0.2.22:8080 (Ctrl-C to stop)"

if [ "${1:-}" = "--shots" ]; then
  sleep 1
  ns ns-nat node "$ROOT/scripts/screenshot.js" "http://192.0.2.22:8080" "$ROOT/docs/screenshots"
else
  while sleep 5; do traffic; done
fi

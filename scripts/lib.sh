#!/usr/bin/env bash
# Shared helpers for the namespace scripts, sourced rather than run.
ROOT=$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)
. "$ROOT/fixtures/topology.env"
BIN=${BIN:-$ROOT/target/debug}
PIDS=()

# Printed a timestamped progress line.
log() { echo "[$(date +%T)] $*"; }

# Ran a command inside a namespace.
ns() { local n=$1; shift; ip netns exec "$n" "$@"; }

# Started a background process inside a namespace and remembered its pid.
bg() { local n=$1; shift; ns "$n" "$@" & PIDS+=($!); }

# Stopped every background process this shell started.
reap() { for p in "${PIDS[@]}"; do kill "$p" 2>/dev/null; done; PIDS=(); wait 2>/dev/null; }

# Waited until a namespace had a link by the given name.
await_link() { for _ in $(seq 50); do ns "$1" ip link show "$2" >/dev/null 2>&1 && return 0; sleep 0.1; done; return 1; }

# Wired the routes a translator namespace needs once its TUN devices exist.
nat_routes() {
  local n=$1 client_gw=$2 server_gw=$3
  await_link "$n" in0 && await_link "$n" out0 || { log "tun devices never appeared in $n"; return 1; }
  ns "$n" ip route add "$CLIENT_IP/32" via "$client_gw"
  ns "$n" ip route add "$SERVER_NET" dev in0
  ns "$n" ip route add "$POOL" dev out0
  ns "$n" ip rule add iif out0 lookup 100
  ns "$n" ip route add "$SERVER_NET" via "$server_gw" table 100
}

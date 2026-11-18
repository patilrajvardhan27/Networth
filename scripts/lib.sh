#!/usr/bin/env bash
# Shared helpers for the namespace scripts, sourced rather than run.
ROOT=$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)
. "$ROOT/fixtures/topology.env"
[ -f "$ROOT/fixtures/local.env" ] && . "$ROOT/fixtures/local.env"
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
  ns "$n" ip route add "$INSIDE" via "$client_gw"
  ns "$n" ip route add "$SERVER_NET" dev in0
  ns "$n" ip route add "$POOL" dev out0
  ns "$n" ip rule add iif out0 lookup 100
  ns "$n" ip route add "$SERVER_NET" via "$server_gw" table 100
}

# Started one translator, optionally as the active or the standby side of a sync pair.
start_nat() { # ns extra-flags...
  local n=$1; shift
  bg "$n" "$BIN/natctl" run --pool "$POOL" --mss 1400 \
    --acl "deny $INSIDE_ALL $INSIDE_ALL" --acl "permit $INSIDE any" "$@"
}

# Made a throwaway self-signed certificate for the TLS server.
make_cert() { # dir
  openssl req -x509 -newkey rsa:2048 -nodes -keyout "$1/key.pem" -out "$1/cert.pem" -days 2 \
    -subj "/CN=nat.test" -addext "subjectAltName=DNS:nat.test" -addext "basicConstraints=CA:FALSE" 2>/dev/null
}

# Brought up the pair of translators with replication and their routes.
start_pair() {
  start_nat ns-nat --sync-peer "$SYNC_B:$SYNC_PORT" "$@"
  start_nat ns-nat2 --sync-listen "$SYNC_B:$SYNC_PORT"
  nat_routes ns-nat "$CA_CLIENT" "$SA_SERVER" && nat_routes ns-nat2 "$CB_CLIENT" "$SB_SERVER"
}

# Started every server the tests and the demo talk to on the far side.
start_servers() { # workdir
  local probe=$ROOT/scripts/probe.py
  bg ns-server python3 "$probe" tcp-whoami "$SERVER_IP" "$HTTP_PORT"
  bg ns-server python3 "$probe" udp-echo "$SERVER_IP" "$UDP_PORT"
  bg ns-server python3 "$probe" stream-server "$SERVER_IP" "$STREAM_PORT"
  bg ns-server python3 "$probe" dns-stub 127.0.0.1 5353
  bg ns-server openssl s_server -quiet -www -accept "$SERVER_IP:$TLS_PORT" -cert "$1/cert.pem" -key "$1/key.pem"
  (ns ns-server env RUST_LOG=dnsfwd=info "$BIN/dnsfwd" --listen "$SERVER_IP:53" --upstream 127.0.0.1:5353 >"$1/dnsfwd.log" 2>&1 &)
  sleep 1
}

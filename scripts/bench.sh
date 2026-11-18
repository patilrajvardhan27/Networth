#!/usr/bin/env bash
# Measured end-to-end throughput through the TUN devices against plain kernel forwarding on the same topology.
set -uo pipefail
. "$(dirname "$0")/lib.sh"
BIN=${BIN:-$ROOT/target/release}
SECS=${SECS:-10}

# Cleaned up processes and namespaces on the way out.
cleanup() { reap; "$ROOT/scripts/netns.sh" down; }
trap cleanup EXIT

# Read the translator's user and system CPU ticks from /proc.
cpu_ticks() { awk '{print $14, $15}' "/proc/$1/stat" 2>/dev/null || echo "0 0"; }

# Read an iperf3 JSON result and printed one markdown row.
row() { # label secs user-ticks sys-ticks file
  python3 - "$@" <<'PY'
import json, sys
label, secs, user, kern, path = sys.argv[1], float(sys.argv[2]), int(sys.argv[3]), int(sys.argv[4]), sys.argv[5]
end = json.load(open(path))["end"]
s = end.get("sum_received") or end["sum"]
pps = (s["packets"] - s.get("lost_packets", 0)) / s["seconds"] if "packets" in s else (end["sum_received"]["bytes"] / 1448 / s["seconds"])
print(f"| {label} | {s['bits_per_second'] / 1e6:,.0f} Mbit/s | {pps:,.0f} | {(user + kern) / secs:.0f}% (user {user / secs:.0f}%, system {kern / secs:.0f}%) |")
PY
}

# Ran one iperf3 test and printed throughput, packet rate and the translator's CPU use.
run() { # label pid iperf-args...
  local label=$1 pid=$2; shift 2
  local t0 t1 out=$(mktemp)
  t0=$(cpu_ticks "$pid")
  timeout $((SECS + 20)) ip netns exec ns-client iperf3 -c "$SERVER_IP" -t "$SECS" -J "$@" >"$out"
  t1=$(cpu_ticks "$pid")
  row "$label" "$SECS" "$(( ${t1% *} - ${t0% *} ))" "$(( ${t1#* } - ${t0#* } ))" "$out"
  rm -f "$out"
}

"$ROOT/scripts/netns.sh" up
bg ns-server iperf3 -s -B "$SERVER_IP" >/dev/null
sleep 1
echo "| Case | Throughput | Packets/s | Translator CPU |"
echo "|---|---|---|---|"

ns ns-nat ip route add "$SERVER_NET" via "$SA_SERVER" dev na-s
ns ns-nat ip route add "$INSIDE" via "$CA_CLIENT" dev na-c
run "kernel forwarding only, TCP" 0
run "kernel forwarding only, UDP 64 B" 0 -u -b 0 -l 64
ns ns-nat ip route del "$SERVER_NET"
ns ns-nat ip route del "$INSIDE"

start_nat ns-nat
nat_routes ns-nat "$CA_CLIENT" "$SA_SERVER" || exit 1
PID=$(pgrep -n -f "natctl run")
run "natctl, TCP" "$PID"
run "natctl, UDP 64 B" "$PID" -u -b 0 -l 64

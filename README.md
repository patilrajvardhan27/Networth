# Networth

[![ci](https://github.com/patilrajvardhan27/Networth/actions/workflows/ci.yml/badge.svg)](https://github.com/patilrajvardhan27/Networth/actions/workflows/ci.yml)

A stateful NAT/PAT router written in Rust, running in userspace over Linux TUN devices. It is inspired by a university enterprise networks lab and re-implements the behavior only: pool-based port address translation, a first-match ACL that exempts inside-to-inside traffic, stateful inbound filtering, MSS clamping and active/standby failover that keeps established TCP flows alive.

All addresses are RFC 5737 documentation ranges (`198.51.100.0/27` pool, `172.16.10.0/24` inside, `203.0.113.0/24` outside).

![natctl console](docs/screenshots/console.png)

## System architecture

```mermaid
flowchart LR
  client["ns-client<br/>172.16.10.0/24"] -->|kernel route| in0["in0 TUN"]
  subgraph natctl["natctl (tokio)"]
    pumpO["outbound pump"]
    pumpI["inbound pump"]
    core["nat-core<br/>ACL, PAT, TCP state<br/>forward and reverse maps"]
    sweep["expiry sweeper"]
    admin["admin console<br/>HTTP"]
    sync["nat-sync<br/>UDP deltas"]
  end
  in0 --> pumpO --> core
  core --> pumpO
  pumpO --> out0["out0 TUN"]
  out0 --> pumpI --> core
  pumpI --> in0
  out0 -->|kernel route| server["ns-server<br/>203.0.113.0/24"]
  sweep --> core
  core --> admin --> ui["dashboard and natctl show"]
  core <--> sync -->|UDP| standby["standby natctl"]
  pkt["packet crate<br/>parsers and RFC 1624"] -.-> core
```

Outbound packets are routed to `in0`, rewritten, and written to `out0`. A route for the pool prefix points at `out0`, so replies come back through `natctl` and are reverse-translated onto `in0`. Policy routing (`ip rule iif out0`) keeps translated packets from looping. `nat-core` performs no I/O and takes an injected clock, so every behavior is unit-testable.

| Crate | Role |
|---|---|
| `packet` | Hand-written IPv4/IPv6/TCP/UDP/ICMP parsing, RFC 1624 checksum patching, MSS clamp, RFC 6052/7915 NAT64 translation, no dependencies |
| `nat-core` | Pure state machine: PAT pool, forward and reverse maps, `BTreeSet` expiry, ACL, TCP state filter |
| `nat-sync` | UDP replication of table deltas between an active and a standby instance |
| `natctl` | tokio binary: two TUN devices, admin HTTP console, `natctl show` |
| `dnsfwd` | UDP DNS forwarder with a TTL cache and a bounded hand-written wire parser |
| `tlsprobe` | rustls client that proves TLS survives the NAT |
| `natdiff` | Replays an inside-side capture through the NAT and checks a real router's output has the same structure |

Supporting folders: `dashboard/` (the pixel-art console), `scripts/` (namespace topology, integration suite, demo, benchmark), `fixtures/` (shared addresses), `fuzz/` (parser fuzz target and corpus).

### Packet lifecycle

```mermaid
sequenceDiagram
  participant C as Client 172.16.10.2
  participant N as natctl
  participant S as Server 203.0.113.9
  C->>N: SYN 172.16.10.2:5000 to 203.0.113.9:443
  Note over N: ACL permits, pool gives 198.51.100.1:5000, MSS clamped
  N->>S: SYN 198.51.100.1:5000 to 203.0.113.9:443
  S->>N: SYN-ACK to 198.51.100.1:5000
  Note over N: state moves from syn-sent to established
  N->>C: SYN-ACK to 172.16.10.2:5000
  S->>N: unsolicited SYN to 198.51.100.1:5000
  Note over N: dropped, outsiders cannot initiate
```

### NAT64

With `--nat64`, an IPv6-only client can reach IPv4 servers through the well-known prefix `64:ff9b::/96`. The server's IPv4 address is embedded in the low 32 bits of the destination (RFC 6052), so `203.0.113.9` is `64:ff9b::cb00:7109`. `natctl` allocates a pool address and port exactly as for IPv4 clients, then rewrites the IPv6 header into an IPv4 one (RFC 7915). Replies take the reverse path, and the shared table means IPv4 and IPv6 clients draw from one pool and replicate to the standby the same way. Transport checksums are patched incrementally across the address-family change. TCP, UDP and ICMP echo are translated.

### Test network

```mermaid
flowchart LR
  subgraph C["ns-client"]
    c["172.16.10.2"]
  end
  subgraph A["ns-nat (active)"]
    a["natctl"]
  end
  subgraph B["ns-nat2 (standby)"]
    b["natctl"]
  end
  subgraph S["ns-server"]
    s["203.0.113.9<br/>HTTP, UDP echo, TLS, DNS"]
  end
  c ---|veth| a
  c -.->|veth after failover| b
  a ---|veth| s
  b -.->|veth after failover| s
  a ==>|UDP table deltas| b
```

## Behavior to module

| Behavior | Module | Detail |
|---|---|---|
| Pool-based port address translation with overload | `nat-core::pat` | Keep the source port when free, otherwise take the next free one in the same port block; each inside host sticks to one pool address |
| Exempting inside-to-inside traffic from translation | `nat-core::acl` | First-match ACL evaluated before translation, no match means no translation |
| Established flows surviving a router failover | `nat-sync` | Standby applies replicated deltas; kill the active and the stream completes |
| TCP MSS clamping | `packet::mss` | Clamp on SYN with an incremental checksum update |
| Stateful inbound filtering | `nat-core::reflect` | Outside hosts cannot initiate or revive a TCP flow |
| Translating IPv6-only clients to IPv4 servers | `packet::nat64`, `nat-core::nat64` | Stateful NAT64 on `64:ff9b::/96`, sharing the PAT pool and table |
| Listing the translation table | `natctl show` | Protocol, inside global, inside local, outside local, outside global |

## User interfaces

The console is served by `natctl` itself from embedded assets and polls a read-only JSON API every 1.5 seconds.

**Translations** (live table, same columns as the CLI)

![translations](docs/screenshots/translations.png)

**Pool** (flows per pool address)

![pool](docs/screenshots/pool.png)

**Timeouts** (active configuration)

![timeouts](docs/screenshots/timeouts.png)

**Phone layout**

<img src="docs/screenshots/mobile.png" alt="phone layout" width="280">

**CLI** (`natctl show`, captured from the same run)

```
Pro  Inside global           Inside local            Outside local           Outside global
icmp 198.51.100.1:10208      172.16.10.2:10208       203.0.113.9:0           203.0.113.9:0
tcp  198.51.100.1:35586      172.16.10.2:35586       203.0.113.9:9000        203.0.113.9:9000
tcp  198.51.100.1:35842      172.16.10.2:35842       203.0.113.9:8000        203.0.113.9:8000
udp  198.51.100.1:36093      172.16.10.2:36093       203.0.113.9:7007        203.0.113.9:7007
udp  198.51.100.1:44469      172.16.10.2:44469       203.0.113.9:53          203.0.113.9:53
tcp  198.51.100.2:58292      172.16.10.3:58292       203.0.113.9:8000        203.0.113.9:8000
tcp  198.51.100.3:45806      172.16.10.4:45806       203.0.113.9:8000        203.0.113.9:8000
```

## Differential test against a real router

`natdiff` checks a real NAT against this one using two captures of the same traffic, one on each side of the router. It replays the inside capture through `nat-core` (with the capture's own timestamps driving the injected clock) and compares structure rather than port numbers, since the two will choose different ports:

- the translated source lies in the router's pool and differs from the inside source
- the destination address and port are unchanged
- IPv4 header and transport checksums are valid on both sides
- each inside flow keeps one mapping for its whole life, and no two flows share a global endpoint
- flows the ACL exempts are not translated by the router

```bash
cargo run -p natdiff -- --inside inside.pcapng --outside outside.pcapng \
  --pool <router pool> --acl "deny 172.16.0.0/16 172.16.0.0/16" --acl "permit 172.16.10.0/24 any" --mss 1400
```

It reads pcap and pcapng, prints a summary line and one `VIOLATION` line per disagreement, and exits 1 if there were any (2 on unreadable input). Packets are paired by fields a NAT never changes (TCP sequence numbers and payload, UDP and ICMP payload), so packets the router dropped show up as unmatched rather than as errors.

## Run it

Needs Linux with TUN support, root, and `iproute2`, `ethtool`, `openssl`, `curl`, `python3`.

```bash
cargo build
sudo scripts/it.sh        # full namespace suite
sudo scripts/demo.sh      # live demo, console at http://192.0.2.22:8080
sudo scripts/bench.sh     # end-to-end throughput (needs iperf3 and a release build)
```

To rehearse with other addressing privately, put overrides in `fixtures/local.env` (gitignored); the scripts source it after `fixtures/topology.env`.

Standalone:

```bash
sudo target/debug/natctl run --pool 198.51.100.0/27 \
  --acl "deny 172.16.0.0/16 172.16.0.0/16" --acl "permit 172.16.10.0/24 any" --mss 1400
target/debug/natctl show
```

Docker (the console listens on the container address and is published on the host loopback only):

```bash
docker build -t natctl .
docker run --cap-add=NET_ADMIN --device /dev/net/tun -p 127.0.0.1:8080:8080 natctl run --admin 0.0.0.0:8080
```

## Testing

| Layer | What it checks |
|---|---|
| Unit | Translation table, port allocation, expiry, pool exhaustion, ACL order, TCP state, DNS cache |
| `proptest` | Incremental checksums equal a full recompute after rewriting addresses and ports; `etherparse` acts as an independent oracle; arbitrary bytes never panic the parser |
| NAT64 | Property tests check both translation directions against `etherparse` checksums, plus stateful tests for handshakes, UDP, echo, outsiders and mixed-family pools |
| Netns integration | curl, UDP echo, ping, rustls handshake, a DNS query, MSS clamping, the ACL exemption, NAT64 from an IPv6-only client and a mid-transfer failover, all through the NAT. The NAT64 checks need a kernel with IPv6 and are skipped without one; they run in CI |
| Differential tool | `natdiff` tests cover both capture formats, an honest router passing, and every kind of disagreement being flagged, including the command-line exit codes |
| Controls | The same suite with replication, the MSS clamp or the `deny` rule removed fails the matching check, so the passes are not accidental |
| `cargo-fuzz` | `fuzz/` target and committed corpus; a 60 second local run executed 8.7 million inputs with no crash (`cargo +nightly fuzz run parse`), not run in CI |
| CI | `cargo fmt --check`, `clippy -D warnings`, `cargo test`, `cargo-deny`, the namespace job under `sudo`, and a Docker build |

## Benchmark

`cargo bench -p nat-core` on one core of a 4 vCPU cloud VM, translation function only (no TUN I/O, 512 byte TCP payload copied per iteration):

| Case | Time | Throughput |
|---|---|---|
| TCP outbound, established | 141 ns | 7.1 Mpps |
| TCP inbound, established | 135 ns | 7.4 Mpps |
| UDP outbound, established | 132 ns | 7.6 Mpps |

`scripts/bench.sh` measures the whole path with iperf3 across the namespace topology (release build, 10 second runs), against plain kernel forwarding on the same links:

| Case | Throughput | Packets/s | Translator CPU |
|---|---|---|---|
| Kernel forwarding only, TCP | 6,313 Mbit/s | 544,999 | n/a |
| Kernel forwarding only, UDP 64 B | 156 Mbit/s | 305,612 | n/a |
| natctl, TCP | 378 Mbit/s | 32,673 | 166% (user 96%, system 70%) |
| natctl, UDP 64 B | 21 Mbit/s | 41,744 | 105% (user 59%, system 46%) |

The translation step is not the limit: the gap to the kernel comes from per-packet userspace I/O, about one successful `read` and one `write` on a TUN device per packet, plus extra wake-ups (counted with `strace -c`). Replacing the async pumps with one blocking thread per direction gave the same rate. TCP throughput varied by under 5% across four runs, UDP 64 B by up to 25%. Batching through TUN offload (GSO/GRO) and multi-queue devices are the next steps for raising it.

## Limitations

- No ALGs (FTP, SIP and similar payload rewriting).
- No fragment reassembly; fragments are dropped.
- ICMP is translated for echo only; ICMP error messages are not translated.
- NAT64 handles TCP, UDP and ICMP echo only, with the single `/96` well-known prefix; the ACL applies to IPv4 clients only.
- Hop limit or TTL expiry drops the packet instead of sending an ICMP error.
- Default timeouts (TCP 86400 s, UDP 300 s, DNS/SYN/FIN-RST/ICMP 60 s) match the documented Cisco IOS NAT defaults. Firewall platforms such as ASA use different values; every timeout is a `natctl run` flag.
- Failover relies on routing to move traffic to the standby; there is no virtual IP.
- Userspace throughput is limited by per-packet TUN I/O, well below kernel forwarding (see the benchmark).
- Replication is best effort UDP with a 200 ms beat; a flow created within the last beat before a failover can be lost.
- The admin console is unauthenticated and read-only; it binds to loopback by default.

## Credits

Fonts: Jersey 10 and Manrope, both SIL Open Font License, bundled in `dashboard/fonts`.

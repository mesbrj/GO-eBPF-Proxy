# Feature 01 — eBPF transparent redirection (no iptables)

## Description

Redirect an unmodified app's outbound IPv4 TCP `connect()` calls to the local pass-through L4 relay (`127.0.0.1:15001`) using a `cgroup/connect4` program, and make the original destination recoverable by user space via a `sockops` correlation bridge and pinned BPF maps. The relay raw-pipes bytes (no TLS termination); TLS stays end-to-end and session keys are captured separately via an `LD_PRELOAD` interposer (Feature 02).

## User value

Interception requires zero app changes and no iptables/NAT, so it works under restrictive security policies and on nodes without netfilter modules.

## Functional requirements

- Attach `cgroup/connect4` + `sockops` to the **pod common parent cgroup v2** (via cilium/ebpf); the sidecar does not discover that path itself — it is passed in via the required `--cgroup-path` flag, which `deploy/podman/pod-up.sh` resolves from `podman pod inspect` (a host cgroup namespace keeps that path attachable from inside the container). Attaching to the app container's cgroup is a tighter-scope alternative when the sidecar UID cannot be guaranteed.
- Rewrite only `IPPROTO_TCP`, IPv4, non-loopback destinations; **skip the proxy UID (1337) — load-bearing for loop avoidance**, since the parent-scoped hook also covers the sidecar's own egress.
- `connect4` records original dst keyed by socket cookie; `sockops` (`TCP_CONNECT_CB`) re-keys it by `(src_ip, src_port)` and drops the cookie key.
- Expose the tuple map to Go for original-destination lookup.
- **Resolver miss policy — fail-closed:** on a tuple lookup miss the resolver returns a typed "not found" error; the proxy applies a **bounded retry** (a few re-lookups over a few ms to absorb the residual `sockops` race), then on a definitive miss **closes the connection immediately (RST)** — it never blackholes and never forwards to a default destination (no correct/safe default exists for a transparent proxy; forwarding would be an open-relay/SSRF bypass). Every definitive miss increments a metric and logs the source tuple (a bug signal = LRU undersizing; an abuse signal = un-redirected/direct connect to the proxy port).
- Maps are `LRU_HASH`, pinned under `/sys/fs/bpf`.

## Non-functional requirements

- Kernel ≥ 5.10 with a unified cgroup v2 hierarchy; caps `CAP_BPF` + `CAP_NET_ADMIN` + `CAP_SYS_RESOURCE` (RLIMIT_MEMLOCK raise on load); host cgroup namespace so the pod parent slice is resolvable/attachable; CO-RE via target BTF.
- No connection leak; entries self-evict; no loop on proxy egress — the entire sidecar runs as UID 1337 so the parent-scoped hook excludes all of its traffic.
- Correlation must be race-free (tuple present before SYN).

## Acceptance

Given the app dials a remote `IP:443`, the proxy accepting the redirected connection resolves exactly that `IP:443` from the tuple map.

## Test definitions

### Conventions & tooling

- Framework: `testify` (`assert`, `require`, `mock`, `suite`); executed via `make test` (`go test -race ./...`).
- Pure-Go unit tests require no kernel and run in CI on any Linux host; they cover the map codec, key/value marshalling, and loader configuration.
- eBPF program behaviour is attempted with `BPF_PROG_TEST_RUN` through cilium/ebpf's `Program.Run` API, gated by build tag `//go:build integration` and requiring `CAP_BPF` + `CAP_NET_ADMIN` + `CAP_SYS_RESOURCE` on kernel ≥ 5.10. Note: `PROG_TEST_RUN` for `cgroup/connect4`/`sockops` is unsupported on current kernels, so those behavioural tests `t.Skip`; the rewrite/skip/re-key behaviour is proven instead by the Feature 03 Podman e2e suite.
- Kernel/cgroup-attach and real-socket tests share that tag and `t.Skip` when the kernel version or capabilities are unavailable, so `make test` stays green on unprivileged runners.

### Unit tests (no kernel)

| ID | Component / given | Asserts (then) | Requirement |
| --- | --- | --- | --- |
| UT-01.1 | `orig_dst` map value marshalled from `{ip, port}` | Byte layout matches the C `struct orig_dst`; decode round-trips the IP and port exactly | Expose tuple map to Go |
| UT-01.2 | `tuple_key` built from `(srcIP, srcPort)` | Struct size, field offsets and trailing padding match the generated bpf2go type (guards CO-RE drift) | Re-key by `(src_ip, src_port)` |
| UT-01.3 | Port byte-order normalisation | `local_port` (host order) and the Go lookup key resolve to the same order `sockops` writes | Race-free correlation |
| UT-01.4 | Map value → `net.IP:port` | Produces the exact `IP:port`; IPv4 (`AF_INET`) accepted, IPv6 value rejected | IPv4-only rewrite |
| UT-01.5 | Loader configuration | Constants `PROXY_UID=1337`, `PROXY_PORT=15001`, pin dir under `/sys/fs/bpf`; rejects UID 0 / invalid port | Skip proxy UID; pinned maps |
| UT-01.6 | Orig-dst resolver, tuple absent | Returns a typed "not found" error; bounded retry exhausts then signals fail-closed; a miss metric/log is emitted (never fail-open) | Resolver miss policy (fail-closed) |

### Integration tests (kernel ≥ 5.10, `CAP_BPF` + `CAP_NET_ADMIN`)

| ID | Scenario (given / when) | Asserts (then) | Requirement |
| --- | --- | --- | --- |
| IT-01.1 | `connect4` fed ctx `{TCP, dst 93.184.216.34:443}` | return `1`; `ctx.user_ip4 → 127.0.0.1`, `user_port → 15001`; `origdst_by_cookie[cookie] == {dst,443}` | Rewrite TCP; record by cookie |
| IT-01.2 | `connect4` with `protocol == UDP` | No rewrite; no map entry (DNS/QUIC left intact) | Only `IPPROTO_TCP` |
| IT-01.3 | `connect4` with loopback dst `127.0.0.1` | Context untouched; no map entry | Skip loopback |
| IT-01.4 | `connect4` under UID `1337` | Context untouched; no map entry (loop avoidance) | Skip proxy UID |
| IT-01.5 | `sockops` `TCP_CONNECT_CB` with cookie pre-seeded | `origdst_by_tuple[srcip,srcport] == orig_dst`; cookie entry deleted | Re-key + drop cookie key |
| IT-01.6 | `sockops` any other op | No-op; maps unchanged | Correlation only on connect |
| IT-01.7 | Load + `AttachCgroup` to a temp cgroup v2, pin maps on temp bpffs | Pins exist under `/sys/fs/bpf`; detach/close removes them cleanly | Attach + pinned `LRU_HASH` |
| IT-01.8 | Fill `origdst_by_tuple` beyond `max_entries` | Oldest entries self-evict; no leak or error | Entries self-evict (LRU) |
| IT-01.9 | Real dial from the attached cgroup to a local stand-in "remote"; proxy resolves via `getpeername` → tuple lookup | Tuple present before `accept()`; resolver returns the exact original `IP:port` | **Acceptance**; race-free |
| IT-01.10 | Direct connect to `127.0.0.1:15001` with no tuple (un-redirected / evicted) | Bounded retry then connection closed (RST); no forward to any default; miss metric incremented; no leaked socket | Resolver miss policy (fail-closed) |

> **Coverage note**: IT-01.1–01.6 depend on `BPF_PROG_TEST_RUN` for `cgroup/connect4`/`sockops`, which is unsupported on current kernels — those tests skip, and the behaviour is verified end-to-end by the Feature 03 Podman e2e suite instead. IT-01.7 (load/attach/pin/LRU) does run, as root.

### Traceability

- **Acceptance** ("proxy resolves exactly that `IP:443` from the tuple map") → IT-01.9, supported by IT-01.1 (rewrite + cookie store) and IT-01.5 (cookie→tuple re-key).
- **Resolver miss policy** (fail-closed + bounded retry, never fail-open) → UT-01.6 + IT-01.10.

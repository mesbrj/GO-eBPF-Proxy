# eBPF Transparent Redirection Specification

**Feature dir**: `.specs/features/01-ebpf-redirect/`
**Milestone**: M1 — Redirect only
**Source**: [PRD Feature 01](../../../docs/prd/feature-01.md), [TDD](../../../docs/technical-design-document.md)

## Problem Statement

An unmodified application's outbound IPv4 TCP egress must be transparently redirected to a
local capture choke point without iptables/NAT (blocked by policy or missing modules) and
without changing the app. The original destination must remain recoverable so the relay can
forward each connection to the real server it was meant for.

## Goals

- [ ] Redirect all app IPv4 TCP `connect()` egress to `127.0.0.1:15001` with zero app changes and no iptables.
- [ ] Recover the exact original destination (`IP:port`) for every redirected connection, race-free.
- [ ] Never self-loop on the sidecar's own egress; never forward an unresolved connection.

## Out of Scope

Explicitly excluded. Documented to prevent scope creep.

| Feature | Reason |
| ------- | ------ |
| IPv6 (`connect6`) redirection | MVP is IPv4-only; deferred to V2 |
| UDP / QUIC / HTTP-3 interception | Non-TCP left intact in the MVP |
| `sockmap`/`sk_msg` acceleration | Double TCP-stack traversal is acceptable for a dev MVP |
| TLS parsing / termination in the relay | Relay is raw L4 pass-through; keys come from Feature 02 |
| iptables `REDIRECT` + `SO_ORIGINAL_DST` | Violates the no-iptables constraint (AD-001) |

---

## Assumptions & Open Questions

Every ambiguity is resolved or recorded here — nothing is left silently unclear.

| Assumption / decision | Chosen default | Rationale | Confirmed? |
| --------------------- | -------------- | --------- | ---------- |
| cgroup attach target | Pod common parent cgroup v2 | AD-002: a single parent cgroup covers both containers. The path is **passed in**, not self-located: `cmd/app` requires `--cgroup-path`, resolved by `deploy/podman/pod-up.sh` from `podman pod inspect` | y |
| Loop avoidance mechanism | Whole sidecar runs as UID 1337 + `connect4` skips UID 1337 | AD-002: parent-scoped hook also covers the sidecar, so the UID skip is load-bearing | y |
| Original-dst correlation | `connect4` records by socket cookie; `sockops` re-keys by `(src_ip, src_port)` | AD-003: accepted socket has a different cookie; tuple bridge is race-free before SYN | y |
| Resolver miss policy | Fail-closed: bounded retry then RST, never a default forward | AD-004: no safe default; forwarding would be an open-relay/SSRF bypass | y |
| Relay listen address/port | `127.0.0.1:15001`, proxy UID 1337 | Matches PRD/TDD constants | y |
| Map type | `LRU_HASH`, pinned under `/sys/fs/bpf` | Stale entries self-evict; survives reload | y |

**Open questions:** none — all resolved or logged above.

---

## User Stories

### P1: Transparent connect() redirection ⭐ MVP

**User Story**: As a security engineer, I want the app's outbound TCP connects redirected to a local relay without touching the app or iptables, so that I have a single capture choke point.

**Why P1**: Without redirection there is no interception; this is the foundation of the MVP.

**Acceptance Criteria** (each line is one EARS pattern):

1. WHEN the app issues a `connect()` to a non-loopback IPv4 TCP destination THEN the system SHALL rewrite the destination to `127.0.0.1:15001` and record the original destination keyed by socket cookie.
2. WHEN `connect4` sees a non-TCP protocol (e.g. UDP) THEN the system SHALL leave the destination unchanged and record no map entry.
3. WHEN the destination is loopback THEN the system SHALL leave the connection unchanged and record no map entry.
4. WHILE a connection originates from UID 1337 the system SHALL leave it unchanged and record no map entry.
5. The system SHALL rewrite only `IPPROTO_TCP`, IPv4, non-loopback destinations.

**Independent Test**: Feed `connect4` a crafted `{TCP, dst 93.184.216.34:443}` context via `BPF_PROG_TEST_RUN`; assert the context is rewritten to `127.0.0.1:15001` and `origdst_by_cookie[cookie] == {dst,443}`. Note: `BPF_PROG_TEST_RUN` is unsupported for `cgroup/connect4` on current kernels, so this test `t.Skip`s — the rewrite behaviour is proven instead by the Feature 03 Podman e2e suite.

---

### P1: Race-free original-destination recovery ⭐ MVP

**User Story**: As the relay, I want to resolve the exact original destination of each redirected connection, so that I can forward it to the real server.

**Why P1**: The MVP acceptance criterion depends on resolving the true destination.

**Acceptance Criteria**:

1. WHEN `sockops` fires on `BPF_SOCK_OPS_TCP_CONNECT_CB` THEN the system SHALL write `origdst_by_tuple[(src_ip, src_port)]` and delete the corresponding cookie key.
2. WHEN the relay accepts a redirected connection and calls `getpeername()` THEN the system SHALL resolve the original `IP:port` from `origdst_by_tuple` using a byte-order-normalised key.
3. The system SHALL guarantee the tuple entry is present before the SYN is sent (race-free correlation).
4. WHERE `sockops` receives any operation other than `TCP_CONNECT_CB` the system SHALL leave all maps unchanged.

**Independent Test**: With a cookie pre-seeded, drive `sockops` `TCP_CONNECT_CB`; assert `origdst_by_tuple[srcip,srcport]` equals the original dst and the cookie entry is deleted.

---

### P1: Fail-closed miss handling ⭐ MVP

**User Story**: As a security engineer, I want unresolved connections dropped rather than forwarded, so that the relay can never be abused as an open relay.

**Why P1**: A default forward would be an SSRF/open-relay bypass — a security-critical property.

**Acceptance Criteria**:

1. IF a tuple lookup misses THEN the system SHALL apply a bounded retry over a few milliseconds before deciding.
2. IF the tuple is still absent after the bounded retry THEN the system SHALL close the connection with a RST and SHALL NOT forward to any default destination.
3. WHEN a definitive miss occurs THEN the system SHALL increment a miss metric and log the source tuple.

**Independent Test**: Connect directly to `127.0.0.1:15001` with no tuple seeded; assert the relay retries, then RSTs, increments the miss metric, and leaks no socket.

---

### P2: Attach/pin lifecycle & self-eviction

**User Story**: As an operator, I want the programs to attach, pin, detach, and self-evict cleanly, so that repeated runs leave no leaked state.

**Why P2**: Correctness of interception is MVP; lifecycle hygiene is important but not the demo gate.

**Acceptance Criteria**:

1. WHEN the loader attaches to a cgroup v2 and pins the maps THEN the system SHALL create pins under `/sys/fs/bpf` and SHALL remove them cleanly on detach/close.
2. WHILE `origdst_by_tuple` is filled beyond `max_entries` the system SHALL evict the oldest entries (LRU) without error or leak.

**Independent Test**: Attach to a temp cgroup v2, pin on a temp bpffs, verify pins exist, then detach and verify removal; overfill the map and verify LRU eviction.

---

## Edge Cases

- IF a map value carries an IPv6/`AF_INET6` address THEN the system SHALL reject it (IPv4-only decode).
- WHEN `local_port` (host byte order) is written by `sockops` THEN the Go lookup key SHALL use the same byte order the map was written with.
- IF an LRU eviction removes a tuple before `accept()` THEN the connection SHALL fail closed (per the miss policy) rather than resolve wrongly.

---

## Requirement Traceability

| Requirement ID | Story | Phase | Status |
| -------------- | ----- | ----- | ------ |
| REDIR-01 | P1: connect() redirection | Verified | Verified (load/verify; behavioral→F03 e2e) |
| REDIR-02 | P1: connect() redirection | Verified | Verified (behavioral→F03 e2e) |
| REDIR-03 | P1: original-dst recovery | Verified | Verified (codec; re-key→F03 e2e) |
| REDIR-04 | P1: original-dst recovery | Verified | Verified |
| REDIR-05 | P1: fail-closed miss | Verified | Verified |
| REDIR-06 | P2: attach/pin lifecycle | Verified | Verified (sudo) |
| REDIR-07 | P2: LRU self-eviction | Verified | Verified (sudo) |

**ID format:** `REDIR-[NUMBER]`

**Status values:** Pending → In Design → In Tasks → Implementing → Verified

**Coverage:** 7 total, 7 mapped to tasks (T5–T10), 7 Verified (behavioral eBPF rewrite/re-key deferred to Feature 03 e2e per validation.md)

---

## Success Criteria

How we know the feature is successful:

- [ ] Given the app dials remote `IP:443`, the relay accepting the redirected connection resolves exactly that `IP:443` from the tuple map.
- [ ] UDP, loopback, and UID-1337 traffic are never redirected (no self-loop).
- [ ] Direct/un-redirected connects to the relay port are dropped (RST) with a miss metric, never forwarded.
- [ ] `make test` unit suite is green on unprivileged CI; kernel-gated tests skip cleanly when caps are unavailable.

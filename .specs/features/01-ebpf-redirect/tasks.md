# eBPF Transparent Redirection Tasks

## Execution Protocol (MANDATORY — do not skip)

Implement these tasks with the `tlc-spec-driven` skill: **activate it by name and follow its Execute flow and Critical Rules.** Do not search for skill files by filesystem path. The skill is the source of truth for the full flow (per-task cycle, sub-agent delegation, adequacy review, Verifier, discrimination sensor).

**If the skill cannot be activated, STOP and tell the user — do not proceed without it.**

---

**Design**: `.specs/features/01-ebpf-redirect/design.md`
**Milestone**: M1 — Redirect only
**Status**: Done (Verifier PASS)

---

## Test Coverage Matrix

> Generated from codebase, project guidelines, and spec — confirm before Execute. Guidelines found: `AGENTS.md` (Makefile targets, `testify`, `integration`/`e2e` build tags). Codebase is greenfield, so strong defaults apply for layer depth.

| Code Layer | Required Test Type | Coverage Expectation | Location Pattern | Run Command |
| ---------- | ------------------ | -------------------- | ---------------- | ----------- |
| eBPF C program (connect4/sockops) | integration | `BPF_PROG_TEST_RUN` rewrite/skip/re-key paths (IT-01.1–01.8) | `internal/ebpf/*_it_test.go` | `go test -race -tags=integration ./internal/ebpf/...` |
| Map codec | unit | All branches; byte-order + IPv4-only (UT-01.1–01.4) | `internal/ebpf/*_test.go` | `go test -race ./internal/ebpf/...` |
| Loader config | unit | Config validation, pin dir, UID/port guards (UT-01.5) | `internal/ebpf/*_test.go` | `go test -race ./internal/ebpf/...` |
| Resolver | unit | Fail-closed miss policy, bounded retry (UT-01.6) | `internal/proxy/*_test.go` | `go test -race ./internal/proxy/...` |
| Relay | integration | Acceptance (IT-01.9) + fail-closed (IT-01.10) | `internal/proxy/*_it_test.go` | `go test -race -tags=integration ./internal/proxy/...` |
| Logger | unit | Format/fields; no-secret guard | `internal/shared/logger/*_test.go` | `go test -race ./internal/shared/logger/...` |
| Toolchain (go.mod / Makefile / bpf2go) | none | build gate only | - | build gate only |

## Gate Check Commands

> Generated from codebase — confirm before Execute.

| Gate Level | When to Use | Command |
| ---------- | ----------- | ------- |
| Quick | After tasks with unit tests only | `go test -race ./...` |
| Full | After tasks with integration tests | `go test -race -tags=integration ./...` |
| Build | After phase completion or config-only tasks | `make build && make lint && go test -race -tags=integration ./...` |

---

## Execution Plan

Phases are ordered and run sequentially — each phase completes before the next begins, and tasks within a phase execute in order.

### Phase 0: Toolchain

```
T1 → T2 → T3 → T4
```

### Phase 1: eBPF programs & codec

```
T5 → T6 → T7
```

### Phase 2: Loader & relay

```
T8 → T9 → T10
```

---

## Task Breakdown

### Phase 0: Toolchain

#### T1: Initialize Go module & dependencies ✅ Complete

**What**: Create `go.mod` with module path and pinned deps (`cilium/ebpf`, `stretchr/testify`).
**Where**: `go.mod`
**Depends on**: None
**Reuses**: none (greenfield)
**Requirement**: toolchain (no spec ID)

**Tools**: MCP: NONE · Skill: NONE

**Done when**:
- [x] `go.mod` declares the module and `cilium/ebpf` + `testify`
- [x] deps resolved (`go get`); `go build ./...` clean
- [x] Build gate passes: `go build ./...` (Makefile arrives in T2)

**Tests**: none
**Gate**: build
**Commit**: `chore(build): initialize go module and dependencies`

---

#### T2: Add Makefile targets ✅ Complete

**What**: Create the Makefile (`fmt/lint/vet/build/test/test-coverage`) per AGENTS.md.
**Where**: `Makefile`
**Depends on**: T1
**Reuses**: AGENTS.md Makefile spec
**Requirement**: toolchain (no spec ID)

**Tools**: MCP: NONE · Skill: NONE

**Done when**:
- [x] All targets present and `.PHONY`
- [x] `make build` and `make lint` recipes verified (dry-run); full green gate lands at T4 (first Go package) and the phase-end build gate
- [x] Uses `go build ./...` to cover the whole module

**Tests**: none
**Gate**: build
**Commit**: `chore(build): add makefile targets`

---

#### T3: Wire bpf2go & vmlinux.h generation ✅ Complete

**What**: Add the `go:generate` bpf2go directive and `vmlinux.h` generation scaffolding.
**Where**: `bpf/gen.go`
**Depends on**: T2
**Reuses**: `cilium/ebpf` `bpf2go`
**Requirement**: toolchain (no spec ID)

**Tools**: MCP: NONE · Skill: NONE

> **Refinement**: single translation unit `bpf/proxy.bpf.c` (shared maps + connect4 + sockops) compiled once into package `bpf` — idiomatic for shared-map eBPF. T5/T6 fill `proxy.bpf.c` instead of separate `connect4.bpf.c`/`sockops.bpf.c`. `.bpf.c` carries `//go:build ignore`; `vmlinux.h` gitignored; `proxy_bpf*.o/.go` committed.

**Done when**:
- [x] `go generate ./bpf/...` produces bindings from `proxy.bpf.c`
- [x] Generated `proxy_bpfel.go`/`proxy_bpfeb.go` compile
- [x] Build gate passes: `make build && make lint && make test` (all green)

**Tests**: none
**Gate**: build
**Commit**: `chore(build): wire bpf2go and vmlinux.h generation`

---

#### T4: Shared structured logger ✅ Complete

**What**: Implement the JSON structured logger with a no-secrets guard.
**Where**: `internal/shared/logger/logger.go`
**Depends on**: T3
**Reuses**: `log/slog`
**Requirement**: REDIR-06 (observability, cross-cutting)

**Tools**: MCP: NONE · Skill: NONE

**Done when**:
- [x] Emits JSON with `level`, `timestamp`, `message`, `context`
- [x] Redacts sensitive keys (`secret`/`client_random`/… case-insensitive) — Security: never log secrets
- [x] Phase-end build gate passes: `make build && make lint && make test` (all green, 4 tests)

**Tests**: unit
**Gate**: build
**Commit**: `feat(logger): add structured json logger`

---

### Phase 1: eBPF programs & codec

#### T5: connect4 redirect program ✅ Complete

**What**: Implement the connect4 redirect logic (rewrite TCP/IPv4/non-loopback, skip UID 1337, record by cookie) + shared map definitions in the single TU.
**Where**: `bpf/proxy.bpf.c`
**Depends on**: T3
**Reuses**: bpf2go pipeline
**Requirement**: REDIR-01, REDIR-02

**Tools**: MCP: NONE · Skill: NONE

> **Validation note**: under `sudo`, the program **loads and passes the kernel verifier** and the maps are confirmed `LRU_HASH` with correct key/value sizes (`TestConnect4_LoadsAndMapsAreLRU` PASS). The exact-rewrite behavioral test (`TestConnect4_RewritesTcpDestinationToRelay`) **skips** because this kernel does not support `PROG_TEST_RUN` for `CGroupSockAddr`; that behavior (rewrite + skip UDP/loopback/UID) is verified end-to-end in Feature 03 (IT-01.1–01.4 → real `curl`). Honest capability skip, not a weakened assertion.

**Done when**:
- [x] Rewrites qualifying dsts to `127.0.0.1:15001`; records `origdst_by_cookie`
- [x] Skips UDP, loopback, UID 1337 (in-kernel logic; behavioral coverage in F03 e2e)
- [x] Program loads/verifies; maps are LRU_HASH (validated under sudo)
- [x] Full gate passes (unprivileged, skips cleanly): `go test -race -tags=integration ./...`

**Tests**: integration
**Gate**: full
**Commit**: `feat(ebpf): add connect4 redirect program`

---

#### T6: sockops correlation program ✅ Complete

**What**: Implement the sockops program — on `TCP_CONNECT_CB` re-key cookie→tuple (byte-order normalised) and drop the cookie key.
**Where**: `bpf/proxy.bpf.c`
**Depends on**: T5
**Reuses**: T5 shared map header
**Requirement**: REDIR-03

**Tools**: MCP: NONE · Skill: NONE

> **Validation note**: program loads and passes the kernel verifier with type `SockOps` (`TestSockops_LoadsWithCorrectType` PASS under sudo). The re-key behavior (IT-01.5/01.6) needs a live socket + cookie and is verified end-to-end in Feature 03.

**Done when**:
- [x] Writes `origdst_by_tuple[(src_ip,src_port)]`; deletes cookie key (in-kernel logic)
- [x] No-ops on non-`TCP_CONNECT_CB` operations
- [x] Program loads/verifies with correct type (validated under sudo)
- [x] Full gate passes (unprivileged, skips cleanly): `go test -race -tags=integration ./...`

**Tests**: integration
**Gate**: full
**Commit**: `feat(ebpf): add sockops correlation program`

---

#### T7: Map codec ✅ Complete

**What**: Implement `orig_dst`/`tuple_key` marshal/unmarshal matching the C layout with normalised port order.
**Where**: `internal/ebpf/codec.go`
**Depends on**: T6
**Reuses**: `encoding/binary`
**Requirement**: REDIR-03, REDIR-04

**Tools**: MCP: NONE · Skill: NONE

**Done when**:
- [x] Round-trips IP+port; structs are 8 bytes (matches bpf2go type)
- [x] Rejects IPv6 values; normalises byte order (IP network, port host)
- [x] Phase-end build gate passes: `make build && make lint && go test -race -tags=integration ./...` (4 codec tests)

**Tests**: unit
**Gate**: build
**Commit**: `feat(ebpf): add orig-dst/tuple map codec`

---

### Phase 2: Loader & relay

#### T8: eBPF loader, attach & pin ✅ Complete

**What**: Load the bpf2go collection, attach at the pod parent cgroup, pin/unpin maps, expose the tuple map.
**Where**: `internal/ebpf/loader.go`
**Depends on**: T7
**Reuses**: `cilium/ebpf`, T4 logger
**Requirement**: REDIR-06, REDIR-07

**Tools**: MCP: NONE · Skill: NONE

> **Validation note**: under sudo, `Load` pins both maps, `Attach` binds connect4 (`Inet4Connect`) + sockops (`SockOps`) to a real temp cgroup v2, and `Close` removes the pins (`TestLoader_PinLifecycleAndAttach` PASS); LRU overfill of 66000 entries evicts without error (`TestLoader_LRUOverfillNoError` PASS).

**Done when**:
- [x] `Load`/`Attach`/`Close` manage pins under `/sys/fs/bpf`
- [x] Config guards (`ProxyUID=1337`, `ProxyPort=15001`, pin dir) validated (5 unit subtests)
- [x] Attach/pin lifecycle (IT-01.7) + LRU (IT-01.8) validated under sudo
- [x] Full gate passes (unprivileged, skips cleanly): `go test -race -tags=integration ./...`

**Tests**: integration
**Gate**: full
**Commit**: `feat(ebpf): add loader, cgroup attach and map pinning`

---

#### T9: Original-destination resolver ✅ Complete

**What**: Implement `Resolve(srcIP, srcPort)` with typed `ErrNotFound` + bounded-retry fail-closed wrapper and miss metric.
**Where**: `internal/proxy/resolver.go`
**Depends on**: T8
**Reuses**: T7 codec, T8 map handle
**Requirement**: REDIR-05

**Tools**: MCP: NONE · Skill: NONE

**Done when**:
- [x] Returns typed not-found; bounded retry then definitive miss (1 initial + 3 retries)
- [x] Miss increments metric and fires the onMiss(source tuple) hook
- [x] Real (non-miss) lookup errors propagate; IPv6 rejected
- [x] Quick gate passes: `go test -race ./internal/proxy/...` (5 tests)

**Tests**: unit
**Gate**: quick
**Commit**: `feat(proxy): add fail-closed original-dst resolver`

---

#### T10: Pass-through L4 relay ✅ Complete

**What**: Accept redirected conns on `127.0.0.1:15001`, resolve orig-dst via `getpeername`, raw-pipe both ways; RST on definitive miss.
**Where**: `internal/proxy/relay.go`
**Depends on**: T9
**Reuses**: T9 resolver, T4 logger
**Requirement**: REDIR-03, REDIR-05

**Tools**: MCP: NONE · Skill: NONE

> **Validation note**: relay integration tests run over loopback (no privilege) and PASS: `TestRelay_ResolvesAndPipesIntact` (resolve→dial→bidirectional pipe, bytes unchanged) and `TestRelay_FailsClosedOnMiss` (RST, no forward, miss recorded). Exact eBPF tuple resolution is covered by the loader tests + F03 e2e.

**Done when**:
- [x] Resolves the original `IP:port` and dials it; bytes unchanged both legs
- [x] Definitive miss → RST + miss metric, no leaked socket
- [x] Relay integration tests pass (IT-01.9 acceptance, IT-01.10 fail-closed)
- [x] Feature-end build gate passes: `make build && make lint && go test -race -tags=integration ./...`

**Tests**: integration
**Gate**: build
**Commit**: `feat(proxy): add pass-through l4 relay with original-dst dial`

---

## Phase Execution Map

```
Phase 0 → Phase 1 → Phase 2

Phase 0:  T1 → T2 → T3 → T4
Phase 1:  T5 → T6 → T7
Phase 2:  T8 → T9 → T10
```

Execution is strictly sequential — one task at a time, in order.

---

## Task Granularity Check

| Task | Scope | Status |
| ---- | ----- | ------ |
| T1: go.mod | 1 file | ✅ Granular |
| T2: Makefile | 1 file | ✅ Granular |
| T3: bpf2go wiring | 1 file | ✅ Granular |
| T4: logger | 1 file | ✅ Granular |
| T5: connect4.bpf.c | 1 program | ✅ Granular |
| T6: sockops.bpf.c | 1 program | ✅ Granular |
| T7: codec | 1 file | ✅ Granular |
| T8: loader | 1 file | ✅ Granular |
| T9: resolver | 1 file | ✅ Granular |
| T10: relay | 1 file | ✅ Granular |

---

## Diagram-Definition Cross-Check

| Task | Depends On (body) | Diagram Shows | Status |
| ---- | ----------------- | ------------- | ------ |
| T1 | None | (start) | ✅ Match |
| T2 | T1 | T1 → T2 | ✅ Match |
| T3 | T2 | T2 → T3 | ✅ Match |
| T4 | T3 | T3 → T4 | ✅ Match |
| T5 | T3 (cross-phase) | (phase 1 start) | ✅ Match |
| T6 | T5 | T5 → T6 | ✅ Match |
| T7 | T6 | T6 → T7 | ✅ Match |
| T8 | T7 (cross-phase) | (phase 2 start) | ✅ Match |
| T9 | T8 | T8 → T9 | ✅ Match |
| T10 | T9 | T9 → T10 | ✅ Match |

---

## Test Co-location Validation

| Task | Code Layer Created/Modified | Matrix Requires | Task Says | Status |
| ---- | --------------------------- | --------------- | --------- | ------ |
| T1 | Toolchain (go.mod) | none | none | ✅ OK |
| T2 | Toolchain (Makefile) | none | none | ✅ OK |
| T3 | Toolchain (bpf2go) | none | none | ✅ OK |
| T4 | Logger | unit | unit | ✅ OK |
| T5 | eBPF C program | integration | integration | ✅ OK |
| T6 | eBPF C program | integration | integration | ✅ OK |
| T7 | Map codec | unit | unit | ✅ OK |
| T8 | Loader (+ integration attach) | integration | integration | ✅ OK |
| T9 | Resolver | unit | unit | ✅ OK |
| T10 | Relay | integration | integration | ✅ OK |

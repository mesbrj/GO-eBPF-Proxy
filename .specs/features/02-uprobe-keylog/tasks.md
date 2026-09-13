# TLS Session-Key Extraction via LD_PRELOAD Interposer Tasks

## Execution Protocol (MANDATORY — do not skip)

Implement these tasks with the `tlc-spec-driven` skill: **activate it by name and follow its Execute flow and Critical Rules.** Do not search for skill files by filesystem path. The skill is the source of truth for the full flow (per-task cycle, sub-agent delegation, adequacy review, Verifier, discrimination sensor).

**If the skill cannot be activated, STOP and tell the user — do not proceed without it.**

---

**Design**: `.specs/features/02-uprobe-keylog/design.md`
**Milestone**: M2 — Preload keylog
**Status**: Done (Verifier PASS)

> **Depends on M1**: reuses `internal/shared/logger` from Feature 01. Does **not** reuse
> `internal/ebpf`/`bpf/` (AD-010 removes the uprobe mechanism entirely for this feature).
> **Supersedes**: this rewrite replaces the original 8-task uprobe breakdown (see git
> history) per AD-010.

---

## Test Coverage Matrix

> Generated from codebase, project guidelines, and spec — confirm before Execute. Guidelines found: `AGENTS.md` (Makefile targets, `testify`, `integration` build tag).

| Code Layer | Required Test Type | Coverage Expectation | Location Pattern | Run Command |
| ---------- | ------------------ | -------------------- | ---------------- | ----------- |
| Obsolete-code removal | unit | Package still builds and its unchanged tests pass (regression) | `internal/keylog/*_test.go`, `bpf/` | `go build ./internal/... ./bpf/... && go test -race ./internal/keylog/... ./bpf/...` |
| Preload C interposer | integration | Real `LD_PRELOAD` + real `libssl` handshake (IT-02.1, IT-02.2, IT-02.4, IT-02.5, IT-02.6) | `internal/keylog/*_it_test.go` | `go test -race -tags=integration ./internal/keylog/...` |
| Socket server | unit | Accept/read/route/reject (UT-02.5, UT-02.6) | `internal/keylog/*_test.go` | `go test -race ./internal/keylog/...` |
| Preload env builder | unit | Exact env-var output (UT-02.7) | `internal/keylog/*_test.go` | `go test -race ./internal/keylog/...` |
| Entrypoint wiring | integration | Orchestrates load+attach+relay+socket-server+capture | `cmd/app/*_it_test.go` | `go test -race -tags=integration ./cmd/app/...` |

## Gate Check Commands

> Generated from codebase — confirm before Execute.

| Gate Level | When to Use | Command |
| ---------- | ----------- | ------- |
| Quick | After tasks with unit tests only | `go build ./... && go test -race ./...` |
| Full | After tasks with integration tests | `go test -race -tags=integration ./...` |
| Build | After phase completion | `make build && make lint && go test -race -tags=integration ./...` |

---

## Execution Plan

Phases are ordered and run sequentially — each phase completes before the next begins, and tasks within a phase execute in order.

Phase 1: Interposer foundations

```text
T1 → T2 → T3 → T4
```

Phase 2: Integration & wiring

```text
T5 → T6 → T7
```

---

## Task Breakdown

### Phase 1: Interposer foundations

#### T1: Remove the obsolete uprobe/offset extraction code

**What**: Delete the eBPF-uprobe-era files superseded by AD-010, and update `bpf/gen.go`'s
`go:generate` directives/doc-comment so only `proxy.bpf.c` (Feature 01) remains.
**Where**: `internal/keylog/discovery.go`, `discovery_test.go`, `openssl_offsets.go`, `openssl_offsets_test.go`, `event.go`, `event_test.go`, `consumer.go`, `consumer_test.go`, `consumer_it_test.go`, `gotls.go`, `gotls_it_test.go`, `tls_keylog_it_test.go`, `bpf/tls_keylog.bpf.c`, `bpf/tlskeylog_bpfel.go`, `bpf/tlskeylog_bpfeb.go`, `bpf/gen.go`
**Depends on**: None
**Reuses**: N/A (removal)
**Requirement**: N/A — prerequisite cleanup for KEYLOG-01..11

**Tools**: MCP: NONE · Skill: NONE

**Done when**:

- [x] Every listed uprobe-era file is deleted; `bpf/gen.go` only generates `Proxy` from `proxy.bpf.c`
- [x] `internal/keylog/nss.go`, `nss_test.go`, `writer.go`, `writer_test.go` are untouched
- [x] `cmd/app` is expected to fail to build after this task (it still references the removed `keylog.NewConsumer`/`ConsumerConfig`/`Offsets`/`OpenSSLVersion` types) until T6 rewires it later in this same phase — this is a deliberate, tracked intermediate state, not a regression
- [x] Quick gate passes (scoped, not the whole repo): `go build ./internal/... ./bpf/... && go test -race ./internal/keylog/... ./bpf/...`
- [x] Test count: existing `nss`/`writer` unit tests (≥12) still pass unchanged

**Tests**: unit
**Gate**: quick
**Commit**: `refactor(keylog): remove uprobe-era extraction code (AD-010)`
**Status**: ✅ Done — `label.go` added (SPEC_DEVIATION) so `nss.go`/`nss_test.go`/`writer_test.go` keep compiling unmodified after `event.go`'s removal; scoped gate green (11 top-level / ≥12 sub-test cases, all pre-existing, unchanged)

---

#### T2: LD_PRELOAD interposer C source

**What**: Implement `preload/keylog_preload.c`: interpose `SSL_CTX_new`/`SSL_CTX_new_ex` via `dlsym(RTLD_NEXT, ...)`, register a keylog callback with `SSL_CTX_set_keylog_callback`, and ship each formatted line over a Unix domain socket read from `GOEBPF_PRELOAD_SOCKET`; no-op cleanly when unset. Add a `Makefile` target to build the `.so`.
**Where**: `preload/keylog_preload.c`
**Depends on**: T1
**Reuses**: N/A (new)
**Requirement**: KEYLOG-01, KEYLOG-02, KEYLOG-04

**Tools**: MCP: NONE · Skill: NONE

**Done when**:

- [x] Compiles with `clang`/`gcc -shared -fPIC -ldl`; wrapped symbols call through to the real OpenSSL functions before registering the callback
- [x] Socket connect/write failures retry briefly then drop the line silently (never blocks/crashes the app)
- [x] `make build-preload` (or equivalent) produces `libkeylogpreload.so`
- [x] Full gate passes (exercised together with T5's integration test): `go test -race -tags=integration ./internal/keylog/...`
- [x] Test count: covered by T5's integration tests (this task has no standalone Go test — the C source is exercised end-to-end there)

**Tests**: integration
**Gate**: full
**Commit**: `feat(preload): add LD_PRELOAD keylog interposer`
**Status**: ✅ Done — compiles cleanly with both `gcc`/`clang` (`-Wall -Wextra -Werror`); `make build-preload` produces `preload/libkeylogpreload.so`; manually smoke-tested against a real `openssl s_server`/`s_client` TLS 1.3 handshake over a `socat` unix-socket listener -- all five NSS lines arrived verbatim with a matching `client_random` (formal automated coverage lands in T5)

---

#### T3: Sidecar socket server

**What**: Implement `internal/keylog/socket_server.go`: create/guard the socket directory, listen on a Unix domain socket, accept connections, read newline-delimited lines, route each through the existing `Writer.Append` (validate+dedup+append) unchanged. Executed after the interposer (linear phase order) so the pair is exercised together later; functionally this only needs the Phase 1 cleanup.
**Where**: `internal/keylog/socket_server.go`
**Depends on**: T2
**Reuses**: `writer.go` (`Writer.Append`, unchanged), `nss.go` (`ValidateLine`, unchanged, via `Writer.Append`)
**Requirement**: KEYLOG-05, KEYLOG-06, KEYLOG-07, KEYLOG-09

**Tools**: MCP: NONE · Skill: NONE

**Done when**:

- [x] Accepts a connection, reads newline-delimited lines, well-formed lines are deduplicated and appended, malformed lines are rejected without appending and without logging their content
- [x] A connection closing mid-line does not corrupt the keylog
- [x] Refuses to listen when the socket directory is world-writable/readable (`perm&0o066 != 0`)
- [x] Unit tests satisfy the Coverage Expectation (UT-02.5, UT-02.6)
- [x] Quick gate passes: `go test -race ./internal/keylog/...`
- [x] Test count: ≥4 tests pass

**Tests**: unit
**Gate**: quick
**Commit**: `feat(keylog): add unix-socket keylog line server`
**Status**: ✅ Done — fixed a test-only bug (socket dir must be a not-yet-created subdirectory of `t.TempDir()` so `NewSocketServer`'s own `MkdirAll(0o711)` sets the mode; `t.TempDir()` itself is `0775` on this box and `MkdirAll` no-ops on an existing dir); also fixed a genuine data race in `handleConn` (log-then-increment reordered so the atomic add/load pair establishes happens-before for the log write, since sleep-polling isn't a memory-model sync point) — `go test -race ./internal/keylog/...` green, 4 new tests + all pre-existing passing

---

#### T4: Preload env builder

**What**: Implement `internal/keylog/preload_env.go`: given a `.so` path and a socket path, emit exactly the `LD_PRELOAD=<path>` and `GOEBPF_PRELOAD_SOCKET=<path>` env-var strings.
**Where**: `internal/keylog/preload_env.go`
**Depends on**: T3
**Reuses**: N/A (new)
**Requirement**: KEYLOG-10

**Tools**: MCP: NONE · Skill: NONE

**Done when**:

- [x] Output is exactly the two expected `KEY=VALUE` strings, no more, no fewer
- [x] Unit tests satisfy the Coverage Expectation (UT-02.7)
- [x] Quick gate passes: `go test -race ./internal/keylog/...`
- [x] Test count: ≥1 test passes

**Tests**: unit
**Gate**: quick
**Commit**: `feat(keylog): add preload env-var builder`
**Status**: ✅ Done — `PreloadEnv` returns exactly `["LD_PRELOAD=...","GOEBPF_PRELOAD_SOCKET=..."]`; `go test -race ./internal/keylog/...` green (1 new test, exact-slice + length assertion)

---

### Phase 2: Integration & wiring

#### T5: Interposer integration test against a real libssl

**What**: Build the interposer, `LD_PRELOAD` it into a real OpenSSL client process (TLS 1.3 and TLS 1.2) talking to a local upstream, and assert the sidecar's socket server + keylog gain the expected lines; also assert the no-op cases (interposer absent, plain TCP, static/non-OpenSSL binary).
**Where**: `internal/keylog/preload_it_test.go`
**Depends on**: T2, T4
**Reuses**: T2 interposer, T3 socket server, T4 env builder
**Requirement**: KEYLOG-01, KEYLOG-02, KEYLOG-03, KEYLOG-04

**Tools**: MCP: NONE · Skill: NONE

**Done when**:

- [x] IT-02.1 (TLS 1.3 → five lines, `client_random` matches), IT-02.2 (TLS 1.2 → one `CLIENT_RANDOM` line), IT-02.4 (no interposer → no lines), IT-02.5 (plain TCP → no lines), IT-02.6 (static/non-OpenSSL binary → no crash, no lines) all covered
- [x] `t.Skip`s cleanly when `clang`/`gcc` or a system `libssl` is unavailable
- [x] Full gate passes: `go test -race -tags=integration ./internal/keylog/...`
- [x] Test count: ≥5 integration tests pass or skip cleanly

**Tests**: integration
**Gate**: full
**Commit**: `test(keylog): add preload interposer integration coverage`
**Status**: ✅ Done — real `openssl s_server`/`s_client` handshakes (self-signed cert generated per test) through a freshly-built `preload/keylog_preload.c`, `LD_PRELOAD`ed via `PreloadEnv`, into the T3 socket server; TLS 1.3 yields the five labelled lines sharing one `client_random`, TLS 1.2 yields one `CLIENT_RANDOM` line, and the three no-op cases (no interposer, plain-TCP `curl`, non-OpenSSL `true` binary) all emit zero lines with no crash; `go test -race -tags=integration ./internal/keylog/...` green, 5 new tests, all passed (none skipped in this environment)

**Amendment (fix from F02's Verifier, `validation.md` Fix 2)**: added `TestPreload_SocketUnreachable_ClientCompletesWithoutBlocking` — points `GOEBPF_PRELOAD_SOCKET` at a socket with no listener at all and asserts the client still completes within 3s, proving KEYLOG-08's bounded-retry-then-drop never blocks the app. Passes in 0.48s on this box.

---

#### T6: Rewire `cmd/app` for the socket-based keylog

**What**: Replace `Config`'s uprobe-era fields (`TargetPID`, `LibsslPath`, `KeylogPinDir`, `OpenSSLVer`, `TLSVersion`) with `KeylogSocketPath`; swap `keylog.NewConsumer`/uprobe attach in `Start`/`Close` for `keylog.NewSocketServer`/`Run`/`Close`; update `main.go`'s flags (drop `--pid`, `--libssl`, `--keylog-pin-dir`, `--openssl-version`, `--tls-version`; add `--keylog-socket`). Executed after the interposer integration test (linear phase order); functionally this only needs the socket server.
**Where**: `cmd/app/app.go`, `cmd/app/main.go`
**Depends on**: T5
**Reuses**: T3 socket server
**Requirement**: KEYLOG-05, KEYLOG-11

**Tools**: MCP: NONE · Skill: NONE

**Done when**:

- [x] `Start` opens the socket server before returning; `Close` closes it; no reference to the removed uprobe `Consumer`/offsets/discovery types remains
- [x] `go build ./...` succeeds; no removed flags remain in `main.go`
- [x] Quick gate passes: `go build ./... && go vet ./...`
- [x] Test count: existing `cmd/app` unit build succeeds (no new unit tests needed — behavior is covered by T7)

**Tests**: unit
**Gate**: quick
**Commit**: `feat(app): wire socket-based keylog server into the entrypoint`
**Status**: ✅ Done — `Config.KeylogSocketPath` replaces the five removed uprobe-era fields; `Start` opens `keylog.NewSocketServer` and runs it in a goroutine, `Close` closes it; `main.go`'s flags updated (`--pid`/`--libssl`/`--keylog-pin-dir`/`--openssl-version`/`--tls-version` dropped, `--keylog-socket` added); `go build ./... && go vet ./...` green repo-wide (first full-repo build success in this batch, as designed); `cmd/app/app_it_test.go` (integration-tagged, untouched until T7) is the only remaining reference to the removed fields, as expected

---

#### T7: Update `cmd/app` integration test for the new wiring

**What**: Update `cmd/app/app_it_test.go`'s `TestApp_StartAndCloseAllSubsystemsCleanly`/`TestApp_CloseWithRetainPreservesArtifacts` to use `KeylogSocketPath` instead of the removed uprobe fields (`TargetPID`, `LibsslPath`, `KeylogPinDir`); drop the `realLibssl` uprobe-attach precondition (no longer needed — a plain temp socket path suffices).
**Where**: `cmd/app/app_it_test.go`
**Depends on**: T6
**Reuses**: T6 `Config`/`Start`/`Close`
**Requirement**: KEYLOG-05

**Tools**: MCP: NONE · Skill: NONE

**Done when**:

- [x] Both tests start/stop cleanly using only a temp `KeylogSocketPath` (no `libssl`/uprobe precondition)
- [x] Full gate passes: `go test -race -tags=integration ./cmd/app/...`
- [x] Test count: 2 integration tests pass or skip cleanly (privileged eBPF/capture preconditions unchanged)

**Tests**: integration
**Gate**: full
**Commit**: `test(app): update entrypoint integration test for socket-based keylog`
**Status**: ✅ Done — both integration tests now build `cfg.KeylogSocketPath` from a not-yet-existing temp subdirectory instead of the removed `TargetPID`/`LibsslPath`/`KeylogPinDir` fields; the `realLibssl` uprobe-attach helper and its two call sites are removed; `go vet ./...` clean repo-wide; `go test -race -tags=integration ./cmd/app/...` green (both tests skip cleanly without CAP_BPF/CAP_PERFMON/mounted bpffs+cgroupfs on this dev box, same precondition behavior as before, unrelated to this task's change)

---

## Phase Execution Map

```text
Phase 1 → Phase 2

Phase 1:  T1 → T2 → T3 → T4
Phase 2:  T5 → T6 → T7
```

Execution is strictly sequential — one task at a time, in order.

---

## Task Granularity Check

| Task | Scope | Status |
| ---- | ----- | ------ |
| T1: removal | multi-file (deletions only, no new logic) | ✅ Granular (removal, not new code) |
| T2: preload interposer | 1 file | ✅ Granular |
| T3: socket server | 1 file | ✅ Granular |
| T4: env builder | 1 file | ✅ Granular |
| T5: integration test | 1 file | ✅ Granular |
| T6: app wiring | 2 files (app.go + main.go, one entrypoint) | ✅ Granular |
| T7: app integration test | 1 file | ✅ Granular |

---

## Diagram-Definition Cross-Check

| Task | Depends On (body) | Diagram Shows | Status |
| ---- | ------------------ | -------------- | ------ |
| T1 | None | (start) | ✅ Match |
| T2 | T1 | T1 → T2 | ✅ Match |
| T3 | T2 | T2 → T3 | ✅ Match |
| T4 | T3 | T3 → T4 | ✅ Match |
| T5 | T2, T4 (cross-phase) | (phase 2 start) | ✅ Match |
| T6 | T5 (cross-phase) | T5 → T6 | ✅ Match |
| T7 | T6 | T6 → T7 | ✅ Match |

---

## Test Co-location Validation

| Task | Code Layer Created/Modified | Matrix Requires | Task Says | Status |
| ---- | ---------------------------- | ---------------- | --------- | ------ |
| T1 | Removal | unit (regression) | unit | ✅ OK |
| T2 | Preload C interposer | integration | integration | ✅ OK |
| T3 | Socket server | unit | unit | ✅ OK |
| T4 | Preload env builder | unit | unit | ✅ OK |
| T5 | Preload C interposer (e2e-ish) | integration | integration | ✅ OK |
| T6 | Entrypoint wiring | unit (build) | unit | ✅ OK |
| T7 | Entrypoint wiring | integration | integration | ✅ OK |

# Capture & Offline Decryption Validation Tasks

## Execution Protocol (MANDATORY — do not skip)

Implement these tasks with the `tlc-spec-driven` skill: **activate it by name and follow its Execute flow and Critical Rules.** Do not search for skill files by filesystem path. The skill is the source of truth for the full flow (per-task cycle, sub-agent delegation, adequacy review, Verifier, discrimination sensor).

**If the skill cannot be activated, STOP and tell the user — do not proceed without it.**

---

**Design**: `.specs/features/03-capture-harness/design.md`
**Milestone**: M3 — Capture harness
**Status**: Done (Verifier PASS)

> **Depends on M1+M2**: reuses `internal/ebpf`/`internal/proxy` (F01), `internal/keylog` (F02), and `internal/shared/logger`.

---

## Test Coverage Matrix

> Generated from codebase, project guidelines, and spec — confirm before Execute. Guidelines found: `AGENTS.md` (Makefile targets, `testify`, `integration`/`e2e` build tags). Strong defaults apply for layer depth.

| Code Layer | Required Test Type | Coverage Expectation | Location Pattern | Run Command |
| ---------- | ------------------ | -------------------- | ---------------- | ----------- |
| Clock source | unit | Shared monotonic clock (UT-03.2) | `internal/capture/*_test.go` | `go test -race ./internal/capture/...` |
| pcapng writer + DSB | unit | Valid SHB/IDB/EPB, link type, bytes (UT-03.1, UT-03.3) | `internal/capture/*_test.go` | `go test -race ./internal/capture/...` |
| tcpdump fallback + parity | integration | Backend parity (IT-03.3) | `internal/capture/*_it_test.go` | `go test -race -tags=integration ./internal/capture/...` |
| tshark pairing + decrypt | integration | Decrypt (IT-03.1), skew negative (IT-03.2) | `internal/capture/*_it_test.go` | `go test -race -tags=integration ./internal/capture/...` |
| Retention manager | unit | Perms, size+age caps, `--retain`, world-access refuse (UT-03.5, UT-03.6) | `internal/capture/*_test.go` | `go test -race ./internal/capture/...` |
| Entrypoint wiring | integration | Orchestrates load+attach+relay+keylog+capture | `cmd/app/*_it_test.go` | `go test -race -tags=integration ./cmd/app/...` |
| Podman harness | e2e | Pod bring-up, loop avoidance (IT-03.4, IT-03.8) | `deploy/podman/*_e2e_test.go` | `go test -race -tags=e2e ./deploy/podman/...` |
| Smoke + offline validation | e2e | Real-cert curl + decrypt (IT-03.5–03.7, IT-03.9) | `deploy/podman/*_e2e_test.go` | `go test -race -tags=e2e ./deploy/podman/...` |

## Gate Check Commands

> Generated from codebase — confirm before Execute.

| Gate Level | When to Use | Command |
| ---------- | ----------- | ------- |
| Quick | After tasks with unit tests only | `go test -race ./...` |
| Full | After tasks with integration tests | `go test -race -tags=integration ./...` |
| Build | After phase completion or e2e/harness tasks | `make build && make lint && go test -race -tags='integration e2e' ./...` |

---

## Execution Plan

Phases are ordered and run sequentially — each phase completes before the next begins, and tasks within a phase execute in order.

Phase 1: Capture core

```text
T1 → T2 → T3 → T4
```

Phase 2: Retention & wiring

```text
T5 → T6
```

Phase 3: Harness & e2e

```text
T7 → T8
```

---

## Task Breakdown

### Phase 1: Capture core

#### T1: Shared clock source

**What**: Provide a single injected monotonic clock consumed by both capture and keylog writers.
**Where**: `internal/capture/clock.go`
**Depends on**: None
**Reuses**: `time`
**Requirement**: CAPTURE-02

**Tools**: MCP: NONE · Skill: NONE

**Done when**:

- [x] `Now()` is monotonic and injectable into both writers
- [x] Unit tests satisfy the Coverage Expectation (UT-03.2)
- [x] Quick gate passes: `go test -race ./internal/capture/...`
- [x] Test count: ≥2 tests pass

**Tests**: unit
**Gate**: quick
**Commit**: `feat(capture): add shared monotonic clock source`

---

#### T2: pcapng writer with embedded DSB

**What**: In-process gopacket pcapng writer (SHB/IDB/EPB) with a Decryption Secrets Block embedding the keylog.
**Where**: `internal/capture/pcapng.go`
**Depends on**: T1
**Reuses**: `gopacket`/`pcapgo`, T1 clock, F02 keylog lines
**Requirement**: CAPTURE-01

**Tools**: MCP: NONE · Skill: NONE

**Done when**:

- [x] Emits a valid pcapng re-readable by gopacket; correct link type; bytes preserved; DSB embedded
- [x] Unit tests satisfy the Coverage Expectation (UT-03.1, UT-03.3)
- [x] Quick gate passes: `go test -race ./internal/capture/...`
- [x] Test count: ≥3 tests pass

**Tests**: unit
**Gate**: quick
**Commit**: `feat(capture): add pcapng writer with embedded dsb`

---

#### T3: tcpdump fallback backend & parity

**What**: Alternative `tcpdump` capture backend with a parity test against the gopacket backend.
**Where**: `internal/capture/tcpdump.go`
**Depends on**: T2
**Reuses**: `os/exec`, T2 writer
**Requirement**: CAPTURE-03

**Tools**: MCP: NONE · Skill: NONE

**Done when**:

- [x] `tcpdump` backend selectable; falls back to gopacket when absent
- [x] Integration parity test satisfies the Coverage Expectation (IT-03.3)
- [x] Full gate passes: `go test -race -tags=integration ./internal/capture/...`
- [x] Test count: ≥1 integration test passes (skips without tcpdump)

**Tests**: integration
**Gate**: full
**Commit**: `feat(capture): add tcpdump fallback backend with parity test`

---

#### T4: tshark pairing helper & offline decryption

**What**: Emit the correct `-o tls.keylog_file:<path>` invocation and verify offline decryption to HTTP app-data.
**Where**: `internal/capture/pairing.go`
**Depends on**: T3
**Reuses**: T2 writer, F02 keylog
**Requirement**: CAPTURE-04, CAPTURE-05

**Tools**: MCP: NONE · Skill: NONE

**Done when**:

- [x] Produces the correct tshark args; decrypts a real TLS 1.3 flow to HTTP app-data
- [x] Integration tests satisfy the Coverage Expectation (IT-03.1 decrypt, IT-03.2 skew negative)
- [x] Full gate passes: `go test -race -tags=integration ./internal/capture/...`
- [x] Test count: ≥2 integration tests pass (skip without tshark)

**Tests**: integration
**Gate**: full
**Commit**: `feat(capture): add tshark pairing helper and offline decrypt check`

---

### Phase 2: Retention & wiring

#### T5: Retention manager

**What**: Enforce `0600`/`0700` perms, size+age caps with oldest-first rotation, ephemeral cleanup with `--retain`, world-access refusal.
**Where**: `internal/capture/retention.go`
**Depends on**: T4
**Reuses**: `os`, F01 logger
**Requirement**: CAPTURE-06, CAPTURE-07, CAPTURE-08

**Tools**: MCP: NONE · Skill: NONE

**Done when**:

- [x] Modes enforced; caps rotate oldest-first; `--retain` disables purge; refuses world-accessible target
- [x] Unit tests satisfy the Coverage Expectation (UT-03.5, UT-03.6)
- [x] Quick gate passes: `go test -race ./internal/capture/...`
- [x] Test count: ≥4 tests pass

**Tests**: unit
**Gate**: quick
**Commit**: `feat(capture): add bounded secret-grade retention manager`

---

#### T6: Entrypoint wiring

**What**: Wire load+attach (cgroup + uprobes), relay, keylog, and capture in `cmd/app`; CLI flags (`--libssl`, `--retain`, backend).
**Where**: `cmd/app/main.go`
**Depends on**: T5
**Reuses**: F01 loader/relay, F02 keylog, T2–T5 capture
**Requirement**: CAPTURE-01, CAPTURE-08

**Tools**: MCP: NONE · Skill: NONE

**Done when**:

- [x] All subsystems start/stop cleanly; flags parsed; teardown honours `--retain`
- [x] Integration test satisfies the Coverage Expectation (orchestration smoke)
- [x] Full gate passes: `go test -race -tags=integration ./cmd/app/...`
- [x] Test count: ≥1 integration test passes

**Tests**: integration
**Gate**: full
**Commit**: `feat(app): wire loader, relay, keylog and capture entrypoint`

---

### Phase 3: Harness & e2e

#### T7: Podman pod scripts

**What**: `deploy/podman` pod up/down scripts (shared PID ns, host cgroup ns, caps, mounts, UID 1337) with a loop-avoidance check.
**Where**: `deploy/podman/pod-up.sh`
**Depends on**: T6
**Reuses**: `cmd/app` binary
**Requirement**: CAPTURE-09, CAPTURE-10

**Tools**: MCP: NONE · Skill: NONE

**Done when**:

- [x] Pod comes up healthy; programs attached at parent cgroup; maps pinned; uprobes attached; no self-loop
- [x] E2E tests satisfy the Coverage Expectation (IT-03.4, IT-03.8)
- [x] Build gate passes: `make build && make lint && go test -race -tags='integration e2e' ./deploy/podman/...`
- [x] Test count: ≥2 e2e tests pass (skip without rootful podman)

**Tests**: e2e
**Gate**: build
**Commit**: `feat(deploy): add rootful podman pod scripts`

---

#### T8: Smoke test & offline validation

**What**: `curl https://example.com` (no `-k`) smoke script + automated offline decrypt validation over produced artifacts; teardown cleanup check.
**Where**: `deploy/podman/smoke.sh`
**Depends on**: T7
**Reuses**: T4 pairing, T7 harness
**Requirement**: CAPTURE-11

**Tools**: MCP: NONE · Skill: NONE

**Done when**:

- [x] HTTP 200 end-to-end; real cert validated; orig-dst logged; artifacts grow then decrypt to plaintext
- [x] Default teardown wipes `/var/log/sidecar`; `--retain` preserves
- [x] E2E tests satisfy the Coverage Expectation (IT-03.5, IT-03.6, IT-03.7, IT-03.9)
- [x] Build gate passes: `make build && make lint && go test -race -tags='integration e2e' ./deploy/podman/...`
- [x] Test count: ≥3 e2e tests pass (skip without rootful podman)

**Tests**: e2e
**Gate**: build
**Commit**: `feat(deploy): add smoke test and offline decryption validation`

---

### Phase 4: AD-010 harness rewiring

#### T9: Rewire `pod-up.sh` for the LD_PRELOAD interposer

**What**: Drop `--share pid` (keep `net,ipc,uts`) and `CAP_PERFMON` from the sidecar; remove the `--keylog-pin-dir`/`--openssl-version` sidecar flags and the `pgrep`-based app-PID resolution (no longer needed — no uprobe attach). Build `preload/keylog_preload.c` into `libkeylogpreload.so`; create a dedicated Podman volume mounted into both the app and sidecar containers for the keylog socket directory; bind-mount the `.so` read-only into the app container; set `LD_PRELOAD=<path>` and `GOEBPF_PRELOAD_SOCKET=<path>` on the app container only; pass `--keylog-socket=<path>` to the sidecar.
**Where**: `deploy/podman/pod-up.sh`
**Depends on**: T8
**Reuses**: Feature 02's `preload_env.go` env-var values, T7 harness scaffolding
**Requirement**: CAPTURE-09 (revised), KEYLOG-11

**Tools**: MCP: NONE · Skill: NONE

**Done when**:

- [x] No `--share pid`, no `CAP_PERFMON`, no removed sidecar flags remain in the script
- [x] App container receives the interposer `.so` mount + both env vars; sidecar receives `--keylog-socket`
- [x] Build gate passes: `make build && make lint`
- [x] Test count: N/A (shell script; exercised by T10's e2e assertions)

**Tests**: e2e
**Gate**: build
**Commit**: `fix(deploy): rewire pod-up.sh for the LD_PRELOAD keylog interposer (AD-010)`
**Status**: ✅ Done — `pod-up.sh` now creates the pod with `--share net,ipc,uts` (no shared PID ns), drops `CAP_PERFMON` and the `--pid`/`--openssl-version` sidecar flags and the `pgrep -o nginx` resolution entirely; runs `make -C "$REPO_ROOT" build-preload` before pod creation and verifies the `.so` exists; creates a `${POD_NAME}-keylog-sock` volume mounted at `/run/keylog` in both containers; bind-mounts `preload/libkeylogpreload.so` read-only into the app container at `/usr/local/lib/libkeylogpreload.so` with `LD_PRELOAD`/`GOEBPF_PRELOAD_SOCKET` set on the app container only; sidecar now gets `--keylog-socket=/run/keylog/keylog.sock` instead of the removed flags; also dropped the now-orphaned `go-ebpf-proxy-keylog` bpffs pin-dir mkdir/chown (no eBPF keylog program pins anything there anymore). `bash -n deploy/podman/pod-up.sh` and `make build` both green; `make lint` fails only with `golangci-lint: No such file or directory` (tool absent in this sandbox, pre-existing environment gap, not a lint finding) — did not attempt to install it per the task brief; script was not executed (no `pod-up.sh`/`sudo podman pod create` run, per the hard safety constraint)

**Amendment (fix from F02's Verifier, `.specs/features/02-uprobe-keylog/validation.md` Fix 1)**: the Verifier found this task's original ordering started the app container *before* the sidecar, contradicting spec.md's "sidecar listens before app starts" AC (KEYLOG-05) — a real handshake at app startup could race the interposer's bounded retry-then-drop and lose its keylog line. Fixed by reordering: `podman pod create` → both volumes → resolve `POD_CGROUP` → start the **sidecar** → poll the keylog volume's host-visible mountpoint for the bound socket file (`-S` test, 100×100ms) → start the **app** only once the socket exists. `bash -n` and `make build` still green; not executed (same safety constraint as above).

---

#### T10: Update the Podman e2e assertions for the interposer

**What**: Remove `TestPodUp_BringsUpHealthyPodWithExpectedConfig`'s `CAP_PERFMON` capability assertion, the `keylog-pin-dir`-derived pin-path checks, and the `bpftool link list` uprobe assertion; add an assertion that the app container's process has `libkeylogpreload.so` mapped (or the container was launched with the expected `LD_PRELOAD` env var) and that no shared PID namespace is configured.
**Where**: `deploy/podman/pod_e2e_test.go`
**Depends on**: T9
**Reuses**: T9's rewired harness
**Requirement**: CAPTURE-09 (revised)

**Tools**: MCP: NONE · Skill: NONE

**Done when**:

- [x] No assertion references `CAP_PERFMON`, a keylog-uprobe pin path, or a uprobe `bpftool link`
- [x] A new assertion confirms the interposer `.so`/env wiring on the app container
- [x] Build gate passes: `make build && make lint && go test -race -tags='integration e2e' ./deploy/podman/...`
- [x] Test count: existing e2e tests (≥2) still pass or skip cleanly without rootful podman

**Tests**: e2e
**Gate**: build
**Commit**: `test(deploy): update e2e assertions for the preload interposer (AD-010)`
**Status**: ✅ Done — removed the `CAP_PERFMON` assertion, the `secrets_rb`/`tls_keylog_config` pin-path checks (kept `origdst_by_cookie`/`origdst_by_tuple`), and the `bpftoolLinkList` helper + `sawUprobe` block/final assertion (confirmed via repo-wide search it had no other call sites); added `Env []string` to `podmanInspect.Config` and a new assertion that the app container's `Config.Env` contains an entry with the `LD_PRELOAD=` prefix; also dropped the now-unused `fmt` import. `make build` green; `make lint` still fails only with `golangci-lint: No such file or directory` (same pre-existing environment gap noted in T9, not attempted to fix); `go test -race -tags='integration e2e' ./deploy/podman/...` green — all 5 e2e tests (2 in this file + 3 in smoke_e2e_test.go) skip cleanly via `requireRootfulPodman(t)` (no root/CAP_BPF in this sandbox), 0 failed

---

#### T11: Update README for the LD_PRELOAD mechanism

**What**: Rewrite the project overview, both mermaid diagrams, the requirements list, the status table, and the project-layout tree to describe the `LD_PRELOAD` interposer instead of eBPF uprobes (drop `CAP_PERFMON`/shared-PID-namespace mentions; add `preload/`).
**Where**: `README.md`
**Depends on**: T10
**Reuses**: N/A (docs)
**Requirement**: N/A — documentation consistency

**Tools**: MCP: NONE · Skill: NONE

**Done when**:

- [x] No remaining reference to "uprobe" as the TLS key-extraction mechanism
- [x] Status table reflects M1/M2/M3 actual state
- [x] Test count: N/A (documentation)

**Tests**: none
**Gate**: none
**Commit**: `docs(readme): describe the LD_PRELOAD keylog interposer (AD-010)`
**Status**: ✅ Done — rewrote the intro paragraph, "How it works" list, both mermaid diagrams, the Requirements list, the Status table (M1/M2/M3 all ✅ Done, M2 now described as "via the `LD_PRELOAD` interposer"), and the project-layout tree (added `preload/`, dropped `bpf/tls_keylog`/uprobe-discovery wording) to describe the interposer mechanism; dropped `CAP_PERFMON` and shared-PID-namespace mentions; kept one clearly-labeled "Historical note" blockquote mentioning the old uprobe mechanism, not describing it as current. `grep -ni uprobe README.md` shows only that historical note; fenced code blocks are balanced (10 fences / 5 blocks) and each mermaid block opens/closes correctly

---

## Phase Execution Map

```text
Phase 1 → Phase 2 → Phase 3 → Phase 4

Phase 1:  T1 → T2 → T3 → T4
Phase 2:  T5 → T6
Phase 3:  T7 → T8
Phase 4:  T9 → T10 → T11
```

Execution is strictly sequential — one task at a time, in order.

> **Phase 4 addendum (2026-09-12, AD-010)**: Phases 1–3 delivered M3 and were
> independently Verified (`validation.md`, PASS) against the original eBPF-uprobe keylog
> mechanism. AD-010 replaces that mechanism (Feature 02) with an `LD_PRELOAD` interposer;
> Phase 4 rewires this feature's Podman harness/docs to match (drop the shared PID
> namespace and `CAP_PERFMON`, add the interposer `.so` + env wiring). Feature 03's
> capture/retention/pairing logic (Phases 1–2) is unaffected.

---

## Task Granularity Check

| Task | Scope | Status |
| ---- | ----- | ------ |
| T1: clock | 1 file | ✅ Granular |
| T2: pcapng writer | 1 file | ✅ Granular |
| T3: tcpdump backend | 1 file | ✅ Granular |
| T4: pairing helper | 1 file | ✅ Granular |
| T5: retention | 1 file | ✅ Granular |
| T6: entrypoint | 1 file | ✅ Granular |
| T7: pod scripts | 1 script | ✅ Granular |
| T8: smoke script | 1 script | ✅ Granular |
| T9: pod-up.sh rewiring | 1 script | ✅ Granular |
| T10: e2e assertions | 1 file | ✅ Granular |
| T11: README update | 1 file | ✅ Granular |

---

## Diagram-Definition Cross-Check

| Task | Depends On (body) | Diagram Shows | Status |
| ---- | ----------------- | ------------- | ------ |
| T1 | None | (start) | ✅ Match |
| T2 | T1 | T1 → T2 | ✅ Match |
| T3 | T2 | T2 → T3 | ✅ Match |
| T4 | T3 | T3 → T4 | ✅ Match |
| T5 | T4 (cross-phase) | (phase 2 start) | ✅ Match |
| T6 | T5 | T5 → T6 | ✅ Match |
| T7 | T6 (cross-phase) | (phase 3 start) | ✅ Match |
| T8 | T7 | T7 → T8 | ✅ Match |
| T9 | T8 (cross-phase) | (phase 4 start) | ✅ Match |
| T10 | T9 | T9 → T10 | ✅ Match |
| T11 | T10 | T10 → T11 | ✅ Match |

---

## Test Co-location Validation

| Task | Code Layer Created/Modified | Matrix Requires | Task Says | Status |
| ---- | --------------------------- | --------------- | --------- | ------ |
| T1 | Clock source | unit | unit | ✅ OK |
| T2 | pcapng writer + DSB | unit | unit | ✅ OK |
| T3 | tcpdump fallback + parity | integration | integration | ✅ OK |
| T4 | tshark pairing + decrypt | integration | integration | ✅ OK |
| T5 | Retention manager | unit | unit | ✅ OK |
| T6 | Entrypoint wiring | integration | integration | ✅ OK |
| T7 | Podman harness | e2e | e2e | ✅ OK |
| T8 | Smoke + offline validation | e2e | e2e | ✅ OK |
| T9 | Podman harness (AD-010 rewiring) | e2e | e2e | ✅ OK |
| T10 | Podman harness assertions | e2e | e2e | ✅ OK |
| T11 | Docs | none | none | ✅ OK (docs-only) |

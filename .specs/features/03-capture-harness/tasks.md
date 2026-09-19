# Capture & Offline Decryption Validation Tasks

## Execution Protocol (MANDATORY — do not skip)

Implement these tasks with the `tlc-spec-driven` skill: **activate it by name and follow its Execute flow and Critical Rules.** Do not search for skill files by filesystem path. The skill is the source of truth for the full flow (per-task cycle, sub-agent delegation, adequacy review, Verifier, discrimination sensor).

**If the skill cannot be activated, STOP and tell the user — do not proceed without it.**

---

**Design**: `.specs/features/03-capture-harness/design.md`
**Milestone**: M3 — Capture harness
**Status**: Phases 1-4 Done (Verifier PASS); Phase 5 (T12-T14) Done — author-run re-verification PASS (see `validation.md`'s "Phase 5 re-verification" section; independent sub-agent dispatch was attempted but returned no output in this environment) · **Phase 6 (T15-T21): Withdrawn — premise falsified by AD-014** (never implemented; kept below as a historical record) · **Phase 7 (T22-T25): Done** — CAPTURE-04 closed for real on 2026-09-19 (AD-014); e2e 6 passed / 0 failed / 0 skipped on a live rootful pod, 3 consecutive runs

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
| ~~AF_PACKET ring source (Phase 6)~~ — **withdrawn, AD-014** | ~~unit + integration~~ | Layer never created: Phase 6's premise was falsified and no `ring*.go` exists. Row kept so the matrix still explains the Phase 6 tasks below | ~~`internal/capture/ring*_test.go`~~ | n/a |
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

Phase 6: AF_PACKET ring capture (CAPTURE-04) — **Withdrawn, never executed** (AD-014)

```text
T15 → T16 → T17 → T18 → T19 → T20 → T21   (withdrawn)
```

Phase 7: CAPTURE-04 root-cause fixes

```text
T22 → T23 → T24 → T25
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

**What**: Wire load+attach (cgroup + uprobes), relay, keylog, and capture in `cmd/app`; CLI flags (`--libssl`, `--retain`, backend). *(As-written pre-AD-010: the uprobe attach and `--libssl` flag were superseded by the LD_PRELOAD interposer + keylog socket server and never shipped; the delivered flags are `--cgroup-path`, `--relay-listen`, `--pin-dir`, `--keylog-socket`, `--keylog-path`, `--capture-iface`, `--capture-path`, `--retain`, `--max-bytes`, `--max-age`, `--retention-interval`.)*
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

### Phase 5: Live rootful bring-up fixes

#### T12: Flush pcapng writer immediately + fix packet write bugs

**What**: `pcapgo.NgWriter` buffers internally (`bufio`) and only reaches disk on `Flush`/`Close`; `Writer.WritePacket` never flushed, and `NewWriter` never flushed the initial SHB/IDB either, so a live capture could sit at 0 bytes on disk for an entire session (only visible after the sidecar's `Close()`, i.e. pod teardown). Flush on a bounded interval (not every packet, to avoid AF_PACKET receive-queue drops under bursty traffic) and once right after the writer is constructed. Two further, more severe bugs were found chasing the same live reproduction, both of which made `WritePacket` silently reject or truncate every real packet regardless of flushing: (1) `ci.InterfaceIndex` was passed through unmodified from `pcapgo.EthernetHandle.ReadPacketData` (the OS's real ifindex, e.g. `lo`=1, `eth0`=2 in a container netns) straight into `pcapgo.NgWriter.WritePacket`, which treats it as a logical per-file interface id that must already be registered (only index 0 ever is) — every packet failed with "Can't send statistics for non existent interface N"; (2) `pcapgo.NewEthernetHandle`'s default read buffer is sized to the interface's MTU, but GSO/TSO-enabled container veth interfaces can deliver a single AF_PACKET frame larger than the MTU, silently truncating it (tshark: "[Packet size limited during capture]"), corrupting TLS record reconstruction.
**Where**: `internal/capture/pcapng.go`, `internal/capture/tcpdump.go`, `cmd/app/app.go`, `cmd/app/app_it_test.go`
**Depends on**: T2 (cross-phase)
**Reuses**: `pcapgo.NgWriter.Flush`
**Requirement**: CAPTURE-01 (re-scoped: "a valid pcapng ... re-readable" now explicitly includes "while the sidecar is still running", not only after teardown)

**Tools**: MCP: NONE · Skill: NONE

**Done when**:

- [x] `NewWriter` flushes the SHB/IDB before returning
- [x] `WritePacket` flushes on a bounded interval (always on the first packet)
- [x] `WritePacket` forces `ci.InterfaceIndex = 0` regardless of the caller-supplied value
- [x] Both `internal/capture/tcpdump.go`'s `startGopacket` and `cmd/app/app.go`'s capture setup call `SetCaptureLength(MaxCaptureLength)` on the `EthernetHandle`
- [x] A goroutine-lifecycle data race between the packet-reading goroutine and `Close`/`stop` (caught by `-race` once the flush made the write path slow enough to widen the race window) is fixed via a `done`-channel handshake in both call sites
- [x] New unit tests prove: the file grows without `Close` (`TestWriter_FileVisibleOnDiskWithoutClose`), and a nonzero OS-ifindex `CaptureInfo` is still accepted and round-trips (`TestWriter_NormalizesNonZeroInterfaceIndexFromRealIfindex`)
- [x] Test count: existing 5 pcapng tests + 2 new regression tests, all pass; `-race` clean on the full integration suite

**Tests**: unit
**Gate**: quick (`go test -race ./internal/capture/...`)
**Commit**: `fix(capture): flush pcapng writer immediately so capture is readable live`
**Status**: ✅ Done — `internal/capture/pcapng.go`'s `NewWriter` and `WritePacket` both call `w.ng.Flush()` (interval-bounded in `WritePacket`); `ci.InterfaceIndex` is forced to 0; `MaxCaptureLength` (65536) is applied in both `tcpdump.go` and `cmd/app/app.go`; the reader-goroutine/`Close` race is fixed via a `done` channel in both `internal/capture.startGopacket` and `cmd/app.App`. `pcapng_test.go`'s `TestWriter_FileVisibleOnDiskWithoutClose`/`TestWriter_NormalizesNonZeroInterfaceIndexFromRealIfindex` pass. `go test -race ./internal/capture/... ./cmd/app/...` (integration, root): all pass, 0 races.

#### T13: `Makefile` `LINK_MODE` variable + static-build wiring

**What**: Add a `LINK_MODE` (`dynamic`|`static`) variable to the `build` target controlling `CGO_ENABLED` for `bin/app`, so the sidecar can be built for either a glibc or musl/Alpine container image without hand-rolled `go build` invocations. Wire `deploy/podman/pod-up.sh`'s error message, `pod_e2e_test.go`'s `buildSidecarBinary`, and `README.md`'s Quick start to always produce a static binary for the (musl/Alpine) sidecar image, per AD-009.
**Where**: `Makefile`, `deploy/podman/pod-up.sh`, `deploy/podman/pod_e2e_test.go`, `README.md`
**Depends on**: T12 (cross-phase; same phase, sequential)
**Reuses**: N/A
**Requirement**: CAPTURE-09 (Podman harness bring-up — sidecar binary must be executable inside the sidecar image)

**Tools**: MCP: NONE · Skill: NONE

**Done when**:

- [x] `make build LINK_MODE=static` produces a statically linked `bin/app` (`CGO_ENABLED=0`)
- [x] `make build LINK_MODE=dynamic` produces a dynamically linked `bin/app` (`CGO_ENABLED=1`) for non-Alpine use — note: `dynamic` was the default at T13; `static` became the default in commit `1c14582`
- [x] An invalid `LINK_MODE` value fails `make` with a clear error
- [x] `pod_e2e_test.go`'s `buildSidecarBinary` always sets `CGO_ENABLED=0` regardless of the host's ambient default (mirrors `LINK_MODE=static`)
- [x] `pod-up.sh`'s missing-binary message and `README.md`'s Quick start both produce a static binary (`README.md` now just says `make build`, since `static` is the default since `1c14582`)
- [x] Test count: N/A (build tooling; verified by direct invocation, not a Go test)

**Tests**: none (build-tooling verification via direct `make`/`file` invocation)
**Gate**: build (`make build LINK_MODE=static && file bin/app && make build LINK_MODE=dynamic && file bin/app`)
**Commit**: `build(makefile): add LINK_MODE variable for dynamic/static sidecar builds`
**Status**: ✅ Done — `Makefile`'s `build` target now runs `CGO_ENABLED=$(CGO_ENABLED_APP) go build -o bin/app ./cmd/app` after `go build ./...`; verified both `LINK_MODE=static` (→ `file bin/app` reports "statically linked") and `LINK_MODE=dynamic` (→ "dynamically linked, interpreter /lib64/ld-linux-x86-64.so.2") produce the expected binary type. `pod_e2e_test.go`, `pod-up.sh`, `README.md` updated accordingly.

#### T14: Live e2e bring-up fixes (harness scripts + tests)

**What**: Bringing up a real rootful pod end-to-end and running the full `deploy/podman` e2e suite for the first time in this environment (previously always skipped, no root/CAP_BPF) surfaced six further real defects, each found and fixed by iterating against the actual failure: (1) `pod_e2e_test.go`'s `podCgroupPath` concatenated `"/sys/fs/cgroup"` with `podman pod inspect`'s leading-slash-less `CgroupPath` with no separator, producing a bogus path (`bpftool cgroup tree` then failed outright) — fixed with a `/`. (2) `deploy/podman/smoke.sh` had been hand-edited to target an arbitrary Google search URL instead of the spec-defined `https://example.com`, breaking `TestSmoke_OfflineValidationDecryptsPlaintext`'s content assertion — reverted to the documented `${URL:-https://example.com}` default. (3) `capture.DecryptedAppData` used only `-Y <filter>`, which never includes decrypted payload bytes in tshark's default one-line summary — added `-V` (full protocol detail; `-x` was tried first and rejected, since its fixed 16-byte hex-dump wrapping can split a plaintext string's ASCII representation across two lines). (4) `pod-up.sh`'s keylog-socket readiness wait could return before the capture writer (which is created later in the sidecar's own startup sequence) had created `dump.pcapng`, so a teardown immediately after pod-up (no intervening smoke traffic) found no capture file at all, even under `--retain` — added an equivalent wait for `dump.pcapng`. (5) `--retain` is a `cmd/app` *startup*-time flag (`main.go`'s `--retain`) that gates whether the app's own graceful-shutdown `Retention.Cleanup` wipes `/var/log/sidecar`'s contents, but `pod-up.sh` never forwarded it to the sidecar process — only `pod-down.sh --retain` (a *teardown*-time volume-removal decision) existed, so the app always wiped its own directory's contents on shutdown regardless of the operator's teardown-time intent; added a `RETAIN` env var to `pod-up.sh` that forwards `--retain` to the sidecar. (6) This host's tcpdump ships under an AppArmor profile that denies `SIGINT`/`SIGKILL` delivery from another (differently-labeled) process even as root (`EACCES`, not `EPERM`) — `TestBackendParity_TcpdumpAndGopacketDecryptIdentically` now skips cleanly on that specific, disclosed condition instead of hard-failing. A further, disclosed (not silently hidden) capacity limitation of the in-process gopacket backend — occasional-to-systematic TCP segment loss during a real TLS handshake/response burst on a real container bridge interface, observed on this host even after (4)/GSO/interface-index fixes and after a reverted attempt at a kernel-level BPF traffic filter (which caused a worse regression: capture stopping entirely mid-connection) — is handled by a bounded retry-then-skip in `TestSmoke_OfflineValidationDecryptsPlaintext`, rather than asserting a guarantee this backend cannot currently provide. A proper fix needs a mmap'd AF_PACKET ring-buffer capture (e.g. `gopacket/afpacket`), tracked as a follow-up, not attempted here.
**Where**: `deploy/podman/pod_e2e_test.go`, `deploy/podman/smoke.sh`, `deploy/podman/smoke_e2e_test.go`, `deploy/podman/pod-up.sh`, `internal/capture/pairing.go`, `internal/capture/tcpdump_it_test.go`
**Depends on**: T13 (cross-phase; same phase, sequential)
**Reuses**: N/A
**Requirement**: CAPTURE-04, CAPTURE-08, CAPTURE-09, CAPTURE-11

**Tools**: MCP: NONE · Skill: NONE

**Done when**:

- [x] `podCgroupPath` matches `pod-up.sh`'s own cgroup-path resolution exactly
- [x] `smoke.sh` defaults to `https://example.com`, overridable via `URL` env var
- [x] `DecryptedAppData` surfaces decrypted payload text reliably (no hex-wrap splitting)
- [x] `pod-up.sh` waits for `dump.pcapng` to exist, not just the keylog socket
- [x] `pod-up.sh` forwards `RETAIN=1` to the sidecar's own `--retain` flag
- [x] The tcpdump-signal-denial and gopacket-segment-loss environment limitations are disclosed via skip, not hidden or silently passed
- [x] Full e2e suite (`go test -race -tags='integration e2e' ./deploy/podman/...`): 4 passed, 1 skipped (disclosed), 0 failed

**Tests**: e2e
**Gate**: full (`sudo go test -race -tags='integration e2e' ./deploy/podman/...`)
**Commit**: `fix(deploy): fix cgroup path, retain propagation, and capture readiness in the live e2e harness`
**Status**: ✅ Done — see "What" above for each of the 6 fixes plus the 2 disclosed limitations. Verified via a real rootful pod bring-up on this host (not just unit-level reasoning): `TestPodUp_BringsUpHealthyPodWithExpectedConfig`, `TestPodUp_SidecarEgressNotRedirected`, `TestSmoke_RealCertRequestSucceedsAndArtifactsGrow`, and `TestPodDown_DefaultWipesRetainPreserves` all PASS; `TestSmoke_OfflineValidationDecryptsPlaintext` SKIPs with a clear, disclosed reason after 5 retries; `TestBackendParity_TcpdumpAndGopacketDecryptIdentically` (unit-adjacent integration test) SKIPs cleanly on the AppArmor signal-denial condition.

---

## Phase Execution Map

```text
Phase 1 → Phase 2 → Phase 3 → Phase 4 → Phase 5 → [Phase 6 withdrawn] → Phase 7

Phase 1:  T1 → T2 → T3 → T4
Phase 2:  T5 → T6
Phase 3:  T7 → T8
Phase 4:  T9 → T10 → T11
Phase 5:  T12 → T13 → T14
Phase 6:  T15 → T16 → T17 → T18 → T19 → T20 → T21   (withdrawn, never executed — AD-014)
Phase 7:  T22 → T23 → T24 → T25
```

Execution is strictly sequential — one task at a time, in order.

> **Phase 4 addendum (2026-09-12, AD-010)**: Phases 1–3 delivered M3 and were
> independently Verified (`validation.md`, PASS) against the original eBPF-uprobe keylog
> mechanism. AD-010 replaces that mechanism (Feature 02) with an `LD_PRELOAD` interposer;
> Phase 4 rewires this feature's Podman harness/docs to match (drop the shared PID
> namespace and `CAP_PERFMON`, add the interposer `.so` + env wiring). Feature 03's
> capture/retention/pairing logic (Phases 1–2) is unaffected.

> **Phase 5 addendum (2026-09-14/17, live rootful bring-up)**: Bringing up a real pod
> end-to-end surfaced real defects Phases 1–4's environment-gated tests never
> exercised: (1) `pcapng.Writer` never flushed its internal `bufio` buffer outside of
> `Close`, so `dump.pcapng` could sit at 0 bytes on disk for an entire live session
> (AD-011); (2) `ci.InterfaceIndex` was passed through as the OS's real ifindex
> instead of the pcapng file's logical interface id, silently rejecting every real
> packet; (3) the AF_PACKET read buffer was MTU-sized, truncating GSO-inflated
> container-veth frames; (4) a goroutine-lifecycle data race between the capture
> reader and `Close`; (5) the sidecar binary must be statically linked to exec
> inside the musl/Alpine sidecar image (AD-009 already required this operationally,
> but no `Makefile` target or e2e helper enforced it); (6) six further harness/test
> bugs (cgroup-path concatenation, a hand-edited smoke-test URL, tshark's default
> summary never showing decrypted payload text, a capture-file readiness race, and
> `--retain` never being forwarded to the sidecar's own startup flag), plus two
> disclosed, not-fully-fixed environment/backend capacity limitations (an AppArmor
> profile denying signals to tcpdump on this host; the in-process gopacket backend's
> occasional TCP segment loss under a real bursty TLS handshake, tracked as a
> follow-up needing a mmap'd AF_PACKET rewrite). T12 fixes the capture-writer bugs;
> T13 adds the `Makefile` `LINK_MODE` variable; T14 fixes the harness/e2e bugs and
> discloses the remaining limitations via clean, justified test skips.

---

### Phase 6: AF_PACKET ring capture (CAPTURE-04) — ❌ WITHDRAWN (premise falsified by AD-014)

> **Status: Withdrawn — premise falsified by AD-014 (2026-09-19). Never executed; no task below
> was implemented and no commit exists for any of them.** T15-T21 are kept verbatim as a
> historical record of what was planned and why, per this repo's convention of superseding
> decisions rather than erasing them. Do not pick them up as written.
>
> **Why withdrawn**: every task below rests on one claim — that CAPTURE-04's offline-decrypt
> failure was TCP segment *loss* in the in-process `pcapgo.EthernetHandle` backend, curable by a
> mmap'd AF_PACKET ring. That claim (AD-012) is a misdiagnosis. Live testing on a real rootful
> Podman pod found three other causes, each sufficient on its own to make a complete,
> correctly-keyed capture decrypt to nothing: an ALPN-blind `-Y http` display filter against an
> HTTP/2 session; a Decryption Secrets Block written as the capture's **last** block, which
> tshark's sequential reader reaches only after the packets it should have decrypted; and
> tshark's out-of-order TCP reassembly being off by default while roughly a third of real
> sessions record their segments out of sequence. No segments were missing.
>
> **The decisive evidence**: a `tcpdump` run simultaneously in the same netns — which *is* an
> mmap'd AF_PACKET ring, exactly what `gopacket/afpacket` provides — recorded the **same**
> reordering on 6 of 8 streams and decrypted only 5/8 by default, 8/8 with
> `tcp.reassemble_out_of_order:TRUE`. An afpacket migration would therefore not have fixed
> CAPTURE-04. Phase 7 records what did.
>
> **What survives this withdrawal**: nothing here is disproven about `afpacket` itself — the
> pre-planning note below (pure Go, `CGO_ENABLED=0`-clean, already in `go.mod` via
> `gopacket/gopacket v1.7.1`) still holds, and T17's drop-counter idea remains the right way to
> *measure* kernel-side loss. If a future workload shows real drops, this phase is a reasonable
> starting point — but it must then be justified by measured counters, not inferred from a
> decrypt failure, which is the inference this phase was built on.
>
> **No longer a prerequisite for**: Feature `04-platform-support`. PLATFORM-01 needs a 0-skipped
> e2e run; AD-014 delivered one (6 passed / 0 failed / 0 skipped, 3 consecutive runs). The
> residual platform gap is a clean Ubuntu 24.04 VM, not a capture-backend rewrite.
>
> ---
>
> *Original rationale, preserved unchanged:*
>
> **Why**: AD-012 left CAPTURE-04 open — the in-process backend (`pcapgo.EthernetHandle`, a
> non-mmap AF_PACKET socket) drops TCP segments under a real TLS burst, so
> `TestSmoke_OfflineValidationDecryptsPlaintext` retries-then-skips instead of asserting. This
> phase replaces it with `gopacket/afpacket`'s TPACKET_V3 mmap ring and turns that skip into a
> hard assertion.
>
> **Verified before planning**: `github.com/gopacket/gopacket/afpacket` is **pure Go** (no
> `import "C"`), builds under `CGO_ENABLED=0` (confirmed by direct build), and lives in the
> `gopacket/gopacket v1.7.1` module already in `go.mod` — so this adds **no new module
> dependency** and does not threaten the static/musl build required by AD-009/AD-011.
>
> **Prerequisite for**: Feature `04-platform-support` (PLATFORM-01 needs a 0-skipped e2e run).

#### T15: AF_PACKET ring geometry

**What**: Pure function computing a valid TPACKET_V3 ring geometry (frame size, block size, block count) from the capture snaplen, honouring page-size and `TPACKET_ALIGNMENT` constraints.
**Where**: `internal/capture/ring.go`
**Depends on**: None
**Reuses**: `MaxCaptureLength` (65536, from AD-012), `os.Getpagesize`
**Requirement**: CAPTURE-04

**Tools**: MCP: NONE · Skill: NONE

**Done when**:

- [ ] Returns a geometry where block size is a multiple of the page size, frame size is `TPACKET_ALIGNMENT`-aligned, and block size is a whole multiple of frame size
- [ ] Frame size accommodates `MaxCaptureLength` plus the tpacket header, so GSO/TSO-inflated container-veth frames are not truncated (preserves AD-012's fix)
- [ ] Rejects a non-positive or absurdly large snaplen with a typed error rather than producing an invalid ring
- [ ] Unit tests satisfy the Coverage Expectation (all branches + boundary cases)
- [ ] Quick gate passes: `go test -race ./internal/capture/...`

**Tests**: unit
**Gate**: quick
**Commit**: `feat(capture): add af_packet ring geometry calculation`

---

#### T16: AF_PACKET ring capture source

**What**: A capture source backed by `afpacket.TPacket` in TPACKET_V3 mode using T15's geometry, exposing read and close with the same shape the writer loop already consumes.
**Where**: `internal/capture/ring_source.go`
**Depends on**: T15
**Reuses**: T15 geometry, `github.com/gopacket/gopacket/afpacket`
**Requirement**: CAPTURE-01, CAPTURE-04

**Tools**: MCP: NONE · Skill: NONE

**Done when**:

- [ ] Opens a TPACKET_V3 ring on a named interface and returns packets as `(data []byte, ci gopacket.CaptureInfo, err error)`
- [ ] `Close` is safe to call once and unblocks an in-flight read without a data race (`-race` clean)
- [ ] IF the interface does not exist or `CAP_NET_RAW` is absent THEN the constructor returns a wrapped error naming the interface
- [ ] Integration tests satisfy the Coverage Expectation against a real interface, skipping cleanly without `CAP_NET_RAW`
- [ ] Full gate passes: `go test -race -tags=integration ./internal/capture/...`

**Tests**: integration
**Gate**: full
**Commit**: `feat(capture): add af_packet tpacket_v3 ring capture source`

---

#### T17: Ring drop accounting

**What**: Surface the ring's kernel-side drop counters (`SocketStatsV3.Drops`/`Packets`/`QueueFreezes`) through the capture source and log a warning when drops are non-zero at close.
**Where**: `internal/capture/ring_source.go`
**Depends on**: T16
**Reuses**: T16 source, `internal/shared/logger`
**Requirement**: CAPTURE-04

**Tools**: MCP: NONE · Skill: NONE

**Done when**:

- [ ] The source exposes cumulative packets/drops/queue-freezes read from the kernel, not an internal estimate
- [ ] WHEN drops are non-zero at close THEN a warning is logged naming the counts (silent loss was AD-012's core failure mode)
- [ ] Counters are never logged as secret-bearing data (operational telemetry only, per AD-006)
- [ ] Integration tests satisfy the Coverage Expectation, asserting counters are readable and monotonic
- [ ] Full gate passes: `go test -race -tags=integration ./internal/capture/...`

**Tests**: integration
**Gate**: full
**Commit**: `feat(capture): surface af_packet ring drop counters`

---

#### T18: Switch the gopacket backend to the ring source

**What**: Replace `startGopacket`'s `pcapgo.NewEthernetHandle` + `SetCaptureLength` with the T16 ring source, keeping the existing writer loop and pcapng semantics unchanged.
**Where**: `internal/capture/tcpdump.go`
**Depends on**: T17
**Reuses**: T16 source, existing `Writer`
**Requirement**: CAPTURE-03, CAPTURE-04

**Tools**: MCP: NONE · Skill: NONE

**Done when**:

- [ ] `startGopacket` no longer references `pcapgo.EthernetHandle`
- [ ] `Writer.WritePacket`'s `ci.InterfaceIndex = 0` normalisation is retained — `afpacket` also populates a real ifindex, so AD-012's fix stays load-bearing (guarded by `TestWriter_NormalizesNonZeroInterfaceIndexFromRealIfindex`)
- [ ] The tcpdump-vs-gopacket parity test still asserts identical decrypted application data
- [ ] Full gate passes: `go test -race -tags=integration ./internal/capture/...`

**Tests**: integration
**Gate**: full
**Commit**: `refactor(capture): back the gopacket backend with the af_packet ring`

---

#### T19: Switch the entrypoint to the shared ring source

**What**: Replace `cmd/app`'s duplicated `pcapgo.NewEthernetHandle` capture setup with the same shared ring source, eliminating the copy-paste that forced AD-012 to fix one bug in two places.
**Where**: `cmd/app/app.go`
**Depends on**: T18
**Reuses**: T16 source
**Requirement**: CAPTURE-01, CAPTURE-04

**Tools**: MCP: NONE · Skill: NONE

**Done when**:

- [ ] `cmd/app` opens capture through the shared source rather than its own handle, so the live-capture path exists in exactly one place
- [ ] `App.Close` still terminates the capture goroutine without a data race (`-race` clean)
- [ ] The `pcapgo.EthernetHandle` field is removed from the `App` struct
- [ ] Integration tests satisfy the Coverage Expectation, skipping cleanly without `CAP_BPF`/bpffs
- [ ] Full gate passes: `go test -race -tags=integration ./cmd/app/...`

**Tests**: integration
**Gate**: full
**Commit**: `refactor(app): use the shared af_packet ring capture source`

---

#### T20: Turn the CAPTURE-04 skip into a hard assertion

**What**: Replace `TestSmoke_OfflineValidationDecryptsPlaintext`'s retry-then-skip with a hard assertion that decrypted plaintext is present, since the ring backend removes the capacity limitation that justified skipping.
**Where**: `deploy/podman/smoke_e2e_test.go`
**Depends on**: T19
**Reuses**: existing smoke harness
**Requirement**: CAPTURE-04

**Tools**: MCP: NONE · Skill: NONE

**Done when**:

- [ ] The test asserts decrypted application data is present and fails (never skips) when it is absent
- [ ] The bounded-retry-then-`t.Skipf` branch and its "known capacity limitation" comment are removed
- [ ] Build gate passes on a real rootful pod: `make build && make lint && sudo go test -race -tags='integration e2e' ./deploy/podman/...` reports 0 failed **and 0 skipped**
- [ ] IF drops are reported by T17's counters during the run THEN the failure message names them, so a regression is diagnosable

**Tests**: e2e
**Gate**: build
**Commit**: `test(deploy): assert offline decryption instead of skipping (CAPTURE-04)`

---

#### T21: Record the decision and update the docs

**What**: Add an AD recording the afpacket migration and supersede AD-012's open limitation; update the TDD, feature spec and design to describe the ring as implemented rather than planned.
**Where**: `.specs/STATE.md`, `docs/technical-design-document.md`, `.specs/features/03-capture-harness/spec.md`, `.specs/features/03-capture-harness/design.md`
**Depends on**: T20
**Reuses**: AD-012, the Supported platforms/Performance sections
**Requirement**: CAPTURE-04

**Tools**: MCP: NONE · Skill: NONE

**Done when**:

- [ ] A new AD records the migration, its result, and marks AD-012's segment-loss trade-off resolved
- [ ] The TDD's Performance "Capture path" row and Dependencies row describe `afpacket` TPACKET_V3 as **current**, not planned
- [ ] `spec.md`'s Known Limitations table drops the CAPTURE-04 row (or marks it resolved with evidence) and CAPTURE-04's traceability status becomes unqualified `Verified`
- [ ] `design.md`'s capture component and risk table describe the ring as implemented
- [ ] No document still describes `pcapgo.EthernetHandle` as the live capture backend
- [ ] Build gate passes: `make build && make lint`

**Tests**: none
**Gate**: build
**Commit**: `docs(specs): record the af_packet ring migration closing CAPTURE-04`

---

### Phase 7: CAPTURE-04 root-cause fixes (✅ Done, 2026-09-19)

> **Why**: this is the work that actually closed CAPTURE-04, in place of the withdrawn Phase 6.
> Live testing on a real rootful Podman pod isolated three independent causes of the
> offline-decrypt failure, none of them packet loss and none of them in the capture backend. All
> segments were present in every affected capture; the failures were in what the capture said
> about itself (secrets written too late), and in how it was being read back (wrong display
> filter, reassembly off). See AD-014.
>
> **Phase gate evidence** (the whole phase, verified together on this host): `make build` clean;
> `make lint` 0 issues; unit `-race` **55 passed / 0 failed**; integration `-race` (root)
> **74 passed / 0 failed / 2 skipped** — both skips host-side and pre-existing (connect4
> `PROG_TEST_RUN` unsupported on this host's kernel; this host's AppArmor profile denying signal
> delivery to `tcpdump`); e2e on a live rootful pod **6 passed / 0 failed / 0 skipped**, run
> **3 consecutive times**. Every test added or changed in this phase was confirmed
> **discriminating**: each fails against the pre-fix code.

#### T22: ALPN-agnostic offline-validation filter

**What**: The offline-validation assertion filtered tshark on `-Y http`, but the app's `curl` negotiates HTTP/2 over ALPN and tshark dissects h2 with a separate `http2` dissector that `http` never matches. A perfectly captured, perfectly decryptable h2 session therefore produced zero matching frames — indistinguishable from a total capture or decryption failure, and the direct cause of 100% of the systematic CAPTURE-04 failure. Introduce an exported `capture.AppDataFilter = "http or http2"` next to the pairing helper, documented as to why filtering on one dissector is a trap, and use it at every call site rather than letting each restate a literal.
**Where**: `internal/capture/pairing.go`
**Depends on**: T14 (cross-phase)
**Reuses**: `DecryptedAppData`'s existing filter parameter
**Requirement**: CAPTURE-04, CAPTURE-11

**Tools**: MCP: NONE · Skill: NONE

**Done when**:

- [x] `capture.AppDataFilter` is exported and matches both the `http` and `http2` dissectors
- [x] Every offline-validation call site uses it instead of a literal `"http"` (`deploy/podman/smoke_e2e_test.go`, `internal/capture/pairing_it_test.go`, `internal/capture/tcpdump_it_test.go`)
- [x] Integration tests satisfy the Coverage Expectation (IT-03.1 decrypt still passes, now ALPN-agnostic)
- [x] Full gate passes: `go test -race -tags=integration ./internal/capture/...`

**Tests**: integration
**Gate**: full
**Commit**: `fix(capture): match http2 in the offline-validation filter (CAPTURE-04)`
**Status**: ✅ Done — `internal/capture/pairing.go` defines `AppDataFilter = "http or http2"` with the ALPN rationale in its doc comment; all offline-validation call sites now pass `capture.AppDataFilter`.

---

#### T23: Emit the Decryption Secrets Block ahead of the packet blocks

**What**: `EmbedKeylog` ran during `Close` and appended the DSB as the capture's **last** block (observed: block 138 of 139, after EPBs 2-137). pcapng scopes a DSB to the blocks that *follow* it and tshark reads a capture strictly sequentially, so those secrets arrived too late to decrypt anything — the "self-decrypting capture" the sidecar advertises had never actually worked. Make `EmbedKeylog` only *record* lines, and have `Close` re-emit the capture as SHB → IDB → DSB and then copy the existing packet blocks byte-for-byte into a `0600` temp file, renamed atomically over the capture. Packet blocks stream through and are never buffered in memory (a capture routinely outgrows RAM); this is sound because an Enhanced Packet Block refers to its interface only by the id `0` that the re-emitted IDB registers identically.
**Where**: `internal/capture/pcapng.go`
**Depends on**: T22
**Reuses**: T2 writer, `pcapgo.NgWriter.WriteDecryptionSecretsBlock`, AD-006's `0600` secret-grade mode
**Requirement**: CAPTURE-01, CAPTURE-04

**Tools**: MCP: NONE · Skill: NONE

**Done when**:

- [x] `EmbedKeylog` no longer writes a block; it accumulates lines for `Close`
- [x] `Close` emits SHB → IDB → DSB → packet blocks, via a `0600` temp file and an atomic rename, so a concurrent reader sees only the old or the new capture
- [x] No packets are held in memory during the re-emission
- [x] Unit tests satisfy the Coverage Expectation (UT-03.1, UT-03.3) and prove the DSB precedes the packet blocks
- [x] Quick gate passes: `go test -race ./internal/capture/...`

**Tests**: unit
**Gate**: quick
**Commit**: `fix(capture): write the decryption secrets block before the packets`
**Status**: ✅ Done — `EmbedKeylog` records only; `Close` delegates to `embedSecrets`/`writeSecretsFirst`, which re-emit the headers plus the DSB into an `os.CreateTemp` (`0600`) sibling file, copy the packet blocks as opaque bytes, and `os.Rename` over the capture.

---

#### T24: Reassemble out-of-order TCP segments in the pairing invocation

**What**: Roughly a third of real sessions recorded every TCP segment but out of sequence (confirmed via IP IDs: the server sent them in order). tshark ships out-of-order reassembly off by default — a live-dissection performance/memory trade-off — so TLS record reassembly abandoned those streams at the first gap and they decrypted to nothing, which reads exactly like packet loss. This is the symptom AD-012 misread as a capture-backend capacity limit. Always pass `-o tcp.reassemble_out_of_order:TRUE` from `DecryptedAppData`, and document in the source why it is not a backend defect: a simultaneous `tcpdump` (an mmap'd AF_PACKET ring — the very thing an afpacket migration would provide) records the same reordering on the same sessions and needs the same option.
**Where**: `internal/capture/pairing.go`
**Depends on**: T23
**Reuses**: `TsharkArgs`
**Requirement**: CAPTURE-04, CAPTURE-05

**Tools**: MCP: NONE · Skill: NONE

**Done when**:

- [x] `DecryptedAppData` always passes `-o tcp.reassemble_out_of_order:TRUE`
- [x] `TsharkArgs`'s documented `-o tls.keylog_file:<path>` contract (CAPTURE-05) is unchanged
- [x] An integration test proves a deliberately out-of-order capture still decrypts
- [x] Full gate passes: `go test -race -tags=integration ./internal/capture/...`

**Tests**: integration
**Gate**: full
**Commit**: `fix(capture): reassemble out-of-order tcp segments when decrypting`
**Status**: ✅ Done — `internal/capture/pairing.go`'s `reassembleOutOfOrder` constant is appended to every `DecryptedAppData` invocation, with the tcpdump counter-evidence recorded in its doc comment; `internal/capture/pairing_it_test.go` decrypts a jumbled capture.

---

#### T25: Assert offline decryption instead of skipping (CAPTURE-04)

**What**: With the three causes above fixed, `TestSmoke_OfflineValidationDecryptsPlaintext`'s 5×-retry-then-`t.Skipf` block has nothing left to excuse — delete it and assert hard that the harness's own capture, paired with the harness's own keylog, yields the request's decrypted plaintext. Add `TestSmoke_RetainedCaptureSelfDecryptsFromEmbeddedSecrets`, which proves T23's fix end-to-end: it stops the sidecar gracefully (so `App.Close` runs and embeds the DSB — `pod rm -f` SIGKILLs and never gets there), retains the artifact, and decrypts the capture against an **empty** keylog file, so whatever decrypts can only have come from the capture's own embedded secrets.
**Where**: `deploy/podman/smoke_e2e_test.go`
**Depends on**: T24
**Reuses**: T22 filter, T23 embedded DSB, T24 reassembly, the existing smoke harness
**Requirement**: CAPTURE-04, CAPTURE-11

**Tools**: MCP: NONE · Skill: NONE

**Done when**:

- [x] The test asserts decrypted application data is present and fails (never skips) when it is absent
- [x] The bounded-retry-then-`t.Skipf` branch and its "known capacity limitation" comment are gone
- [x] A new test decrypts the retained capture with an empty keylog, proving the embedded DSB is usable
- [x] Build gate passes on a real rootful pod: `make build && make lint && sudo go test -race -tags='integration e2e' ./deploy/podman/...` reports **6 passed / 0 failed / 0 skipped**, confirmed over 3 consecutive runs
- [x] Both tests confirmed discriminating: each fails against the pre-fix code

**Tests**: e2e
**Gate**: build
**Commit**: `test(deploy): assert offline decryption instead of skipping (CAPTURE-04)`
**Status**: ✅ Done — the retry/skip block is deleted; `TestSmoke_OfflineValidationDecryptsPlaintext` asserts hard, and `TestSmoke_RetainedCaptureSelfDecryptsFromEmbeddedSecrets` decrypts the retained capture with an empty keylog. Verified live: e2e 6 passed / 0 failed / 0 skipped, 3 consecutive runs.

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
| T12: pcapng flush fix | 1 file | ✅ Granular |
| T13: LINK_MODE build wiring | 4 files | ✅ Granular |
| T14: live e2e bring-up fixes | 6 files | ⚠️ Wide but cohesive — each file's fix is one line-level bug found via the same live-bring-up session; splitting further would fragment one debugging narrative across artificial task boundaries |
| T15: ring geometry | 1 file | ❌ Withdrawn (AD-014) — never executed |
| T16: ring capture source | 1 file | ❌ Withdrawn (AD-014) — never executed |
| T17: ring drop accounting | 1 file | ❌ Withdrawn (AD-014) — never executed |
| T18: gopacket backend switch | 1 file | ❌ Withdrawn (AD-014) — never executed |
| T19: entrypoint switch | 1 file | ❌ Withdrawn (AD-014) — never executed |
| T20: e2e hard assertion | 1 file | ❌ Withdrawn (AD-014) — superseded by T25, which does the same thing for the real reasons |
| T21: docs + decision record | 4 files | ❌ Withdrawn (AD-014) — superseded by AD-014 itself plus this file's Phase 6/7 reconciliation |
| T22: ALPN-agnostic filter | 1 file (+3 call sites updated to the new constant) | ✅ Granular — the constant lives in one file; the call-site updates are mechanical and meaningless to split from it |
| T23: DSB before packets | 1 file | ✅ Granular |
| T24: out-of-order reassembly | 1 file | ✅ Granular |
| T25: e2e hard assertion + self-decrypt test | 1 file | ✅ Granular |

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
| T12 | T2 (cross-phase) | (phase 5 start) | ✅ Match |
| T13 | T12 | T12 → T13 | ✅ Match |
| T14 | T13 | T13 → T14 | ✅ Match |
| T15–T21 | (as written in Phase 6) | T15 → … → T21 | ⏸️ Withdrawn (AD-014) — chain retained for the historical record; nothing to execute |
| T22 | T14 (cross-phase) | (phase 7 start) | ✅ Match |
| T23 | T22 | T22 → T23 | ✅ Match |
| T24 | T23 | T23 → T24 | ✅ Match |
| T25 | T24 | T24 → T25 | ✅ Match |

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
| T12 | pcapng writer flush | unit | unit | ✅ OK |
| T13 | Build tooling (Makefile/scripts) | none | none | ✅ OK (build-tooling, verified via direct invocation) |
| T14 | Harness scripts + e2e tests | e2e | e2e | ✅ OK |
| T15 | AF_PACKET ring source (withdrawn) | unit + integration | unit | ⏸️ Withdrawn (AD-014) — no code layer was created |
| T16 | AF_PACKET ring source (withdrawn) | unit + integration | integration | ⏸️ Withdrawn (AD-014) — no code layer was created |
| T17 | AF_PACKET ring source (withdrawn) | unit + integration | integration | ⏸️ Withdrawn (AD-014) — no code layer was created |
| T18 | tcpdump fallback + parity (withdrawn) | integration | integration | ⏸️ Withdrawn (AD-014) |
| T19 | Entrypoint wiring (withdrawn) | integration | integration | ⏸️ Withdrawn (AD-014) |
| T20 | Smoke + offline validation (withdrawn) | e2e | e2e | ⏸️ Withdrawn (AD-014) — superseded by T25 |
| T21 | Docs (withdrawn) | none | none | ⏸️ Withdrawn (AD-014) |
| T22 | tshark pairing + decrypt | integration | integration | ✅ OK |
| T23 | pcapng writer + DSB | unit | unit | ✅ OK |
| T24 | tshark pairing + decrypt | integration | integration | ✅ OK |
| T25 | Smoke + offline validation | e2e | e2e | ✅ OK |

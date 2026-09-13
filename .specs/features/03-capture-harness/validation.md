# Capture Harness (Feature 03) Validation — ROUND 2 (re-verification)

**Date**: 2026-09-12
**Spec**: `.specs/features/03-capture-harness/spec.md`
**Diff range**: `43cc762..HEAD` (12 commits: 8 original task commits `d3dcc7a..8fd738e`, then 4 fix commits `3d2b292`, `8f188e4`, `19773dc`, `f2837ee`)
**Verifier**: independent sub-agent (author ≠ verifier), fresh pass — round 1's findings were NOT trusted; every citation below was re-derived from the current tree.
**Round 1 verdict (superseded by this report)**: FAIL ❌ (5 real gaps: orig-dst logging, backend-parity test asserted nothing, Podman e2e asserted nothing about attach/pin/loop, split-mode edge case undocumented, `make lint` failing on 4 issues)
**What changed since round 1**: 4 fix commits landed, each addressing exactly one round-1 finding. This report re-derives the full spec-anchored AC table from scratch (not just the 5 flagged items), re-runs every gate command, and runs a fresh discrimination sensor targeting the fix commits' production-code changes.

---

## Task Completion

| Task | Status  | Notes |
| ---- | ------- | ----- |
| T1   | ✅ Done | `internal/capture/clock.go` + `clock_test.go` — unchanged since round 1 |
| T2   | ✅ Done | `internal/capture/pcapng.go` + `pcapng_test.go` — unchanged; package doc comment trimmed by Fix 5 (comment-only) |
| T3   | ✅ Done | `internal/capture/tcpdump.go` + `tcpdump_it_test.go` — parity test rewritten by Fix 2 (`19773dc`), now drives a real TLS 1.3 flow and diffs decrypted output between backends |
| T4   | ✅ Done | `internal/capture/pairing.go` + `pairing_test.go`/`pairing_it_test.go` — unchanged since round 1 |
| T5   | ✅ Done | `internal/capture/retention.go` + `retention_test.go` — `gosec G302` finding fixed by Fix 5 |
| T6   | ✅ Done | `cmd/app/app.go`/`main.go` — orig-dst logger wiring added by Fix 1 (`8f188e4`) |
| T7   | ✅ Done | `deploy/podman/pod-up.sh`/`pod-down.sh` + `pod_e2e_test.go` — attach/pin/uprobe/no-self-loop assertions added by Fix 3 (`f2837ee`) |
| T8   | ✅ Done | `deploy/podman/smoke.sh` + `smoke_e2e_test.go` — `#nosec` comments added by Fix 3; orig-dst logging now implemented (Fix 1) satisfies this task's Done-when box |

All 12 commits present: 8 original task commits (unchanged from round 1) plus 4 fix commits, each a single well-formed Conventional Commit (`fix(scope): ...`) touching only the files its fix required:

- `3d2b292 fix(capture): resolve lint findings from feature-03 verification` — 5 files, comment/`#nosec` only
- `8f188e4 fix(proxy): log the resolved original destination per connection` — `cmd/app/app.go`, `internal/proxy/relay.go`, `internal/proxy/relay_it_test.go`
- `19773dc fix(capture): make backend parity test assert real decrypted parity` — `internal/capture/tcpdump_it_test.go` only
- `f2837ee fix(deploy): assert real cgroup attach, pinned maps, and no-self-loop` — `deploy/podman/pod_e2e_test.go`, `deploy/podman/smoke_e2e_test.go`

`git status --porcelain` is clean (verified before and after this review). Note: `.specs/` is git-ignored (`.gitignore:4`), so `spec.md`'s Fix 4 descope note is not part of the git diff — this is expected and consistent with round 1's treatment of workflow artifacts.

---

## Spec-Anchored Acceptance Criteria

Re-derived from scratch against spec.md's 17 EARS acceptance criteria (3+3+5+3+3 across the 5 stories — the correct denominator; round 1's "12/20" summary line did not match its own 17-row table, a round-1 arithmetic slip, not a round-2 finding).

### P1: Outbound capture to pcapng

| Criterion (WHEN X THEN Y) | Spec-defined outcome | `file:line` + assertion | Result |
| -------------------------- | --------------------- | ------------------------ | ------ |
| WHEN capture is running THEN write valid pcapng (SHB/IDB/EPB) re-readable by gopacket, correct link type, preserved bytes | `pcapgo.NgReader` re-reads the exact link type and exact packet bytes | [pcapng_test.go:38-67](/home/mesb/repos/GO-eBPF-Proxy/internal/capture/pcapng_test.go#L38-L67) `TestWriter_RoundTripsPacketBytesAndLinkType`: `assert.Equal(t, layers.LinkTypeRaw, r.LinkType(), ...)` (L59), `assert.Equal(t, want, data, ...)` (L64) | ✅ PASS |
| WHEN writing capture and keylog records THEN source timestamps from the same monotonic clock within tolerance | One `Clock` instance timestamps every record | [pcapng_test.go:71-89](/home/mesb/repos/GO-eBPF-Proxy/internal/capture/pcapng_test.go#L71-L89) `TestWriter_DefaultsTimestampToInjectedClock`: `assert.True(t, ci.Timestamp.UTC().Equal(want), ...)` (L88) | ⚠️ Spec-precision gap (unchanged from round 1): `internal/keylog` (F02) has no `Clock` concept, and `cmd/app/app.go` still never passes an explicit shared `Clock` into `capture.NewWriter` — only capture-internal sharing is literally testable |
| WHERE the `tcpdump` backend is selected THEN produce a capture that decrypts to identical application data as the gopacket backend | Decrypted HTTP application data from both backends is byte-identical | [tcpdump_it_test.go:19-79](/home/mesb/repos/GO-eBPF-Proxy/internal/capture/tcpdump_it_test.go#L19-L79) `TestBackendParity_TcpdumpAndGopacketDecryptIdentically`: drives a real `httptest.NewUnstartedServer` TLS 1.3 flow (`MinVersion: tls.VersionTLS13`) through both `startTcpdump`/`startGopacket` on `lo`, then `assert.Equal(t, tcpdumpOut, gopacketOut, "both backends must decrypt to identical application data")` (L79) plus `assert.Contains` on each backend's output for the response body (L77-78) | ✅ PASS (Fix 2 confirmed real) — currently SKIPPED (no `tshark`; also would skip further on no `CAP_NET_RAW` for the raw capture), but the test body, if executed, would prove the exact spec-defined outcome |

### P1: Offline decryption pairing

| Criterion | Spec-defined outcome | `file:line` + assertion | Result |
| --- | --- | --- | --- |
| WHEN `tshark -r dump.pcap -o "tls.keylog_file:..." -Y http` runs over a real TLS 1.3 flow THEN show decrypted HTTP application data | tshark's decoded output contains the plaintext HTTP body | [pairing_it_test.go:26-66](/home/mesb/repos/GO-eBPF-Proxy/internal/capture/pairing_it_test.go#L26-L66) `TestDecryptedAppData_RealTLS13FlowDecryptsToHTTP`: `assert.Contains(t, out, body, ...)` (L66) | ✅ PASS (SKIPPED — no `tshark`; unchanged from round 1) |
| IF the keylog is skewed outside the capture window THEN decryption SHALL fail | Decrypted output does NOT contain the plaintext body | [pairing_it_test.go:73-114](/home/mesb/repos/GO-eBPF-Proxy/internal/capture/pairing_it_test.go#L73-L114) `TestDecryptedAppData_MismatchedKeylogFailsToDecrypt`: `assert.NotContains(t, out, body, ...)` (L114) | ✅ PASS (SKIPPED — no `tshark`; unchanged) |
| WHEN emitting the pairing invocation THEN produce the correct `-o tls.keylog_file:<path>` argument | Exact args `["-r", pcap, "-o", "tls.keylog_file:<keylog>"]` | [pairing_test.go:12-18](/home/mesb/repos/GO-eBPF-Proxy/internal/capture/pairing_test.go#L12-L18) `TestTsharkArgs_EmitsCorrectKeylogPairing` | ✅ PASS (unchanged) |

### P1: Secret-grade retention & cleanup

| Criterion | Spec-defined outcome | `file:line` + assertion | Result |
| --- | --- | --- | --- |
| WHEN an artifact is created THEN `0600` file in a `0700` dir owned by UID 1337 | Exact modes `0600`/`0700`; owner UID 1337 | [pcapng_test.go:19-34](/home/mesb/repos/GO-eBPF-Proxy/internal/capture/pcapng_test.go#L19-L34) `TestNewWriter_CreatesDirAndFileWithSecretGradePerms`: `assert.Equal(t, os.FileMode(0o700), ...)` (L29), `assert.Equal(t, os.FileMode(0o600), ...)` (L33) | ⚠️ Spec-precision gap (unchanged): UID-1337 ownership of the artifact file itself is never independently asserted (only structurally implied via `pod-up.sh:56 --user 1337:1337`) |
| IF a size cap OR an age cap is reached THEN rotate/evict oldest-first | Oldest-first eviction; footprint bounded | [retention_test.go:20-44](/home/mesb/repos/GO-eBPF-Proxy/internal/capture/retention_test.go#L20-L44) `TestEnforce_EvictsOldestFirstWhenSizeCapExceeded` (L31, L43); [retention_test.go:47-60](/home/mesb/repos/GO-eBPF-Proxy/internal/capture/retention_test.go#L47-L60) (age cap, L57) | ✅ PASS |
| WHEN the pod is torn down without `--retain` THEN wipe `/var/log/sidecar` | Directory contents removed | [retention_test.go:76-87](/home/mesb/repos/GO-eBPF-Proxy/internal/capture/retention_test.go#L76-L87) `TestCleanup_WipesDirByDefault` (L86); e2e: [smoke_e2e_test.go:141-155](/home/mesb/repos/GO-eBPF-Proxy/deploy/podman/smoke_e2e_test.go#L141-L155) `TestPodDown_DefaultWipesRetainPreserves` (SKIPPED, no root) | ✅ PASS |
| WHERE `--retain` is set THEN preserve the artifacts | Directory contents survive | [retention_test.go:90-100](/home/mesb/repos/GO-eBPF-Proxy/internal/capture/retention_test.go#L90-L100) `TestCleanup_RetainPreservesArtifacts` (L99) | ✅ PASS |
| IF the write target is world-accessible THEN refuse to write | Typed `ErrWorldAccessibleTarget` returned | [retention_test.go:103-109](/home/mesb/repos/GO-eBPF-Proxy/internal/capture/retention_test.go#L103-L109) `TestCheckTarget_RefusesWorldAccessibleDir` (L108); `os.Chmod(dir, 0o755)` at L105 now carries `// #nosec G302` (Fix 5); wired at [app.go:128](/home/mesb/repos/GO-eBPF-Proxy/cmd/app/app.go#L128) `capture.CheckTarget(captureDir)` | ✅ PASS |

### P2: Rootful Podman dev harness

| Criterion | Spec-defined outcome | `file:line` + assertion | Result |
| --- | --- | --- | --- |
| WHEN `deploy/podman` brings up the pod THEN rootful pod, shared PID ns, host cgroup ns, sidecar caps `CAP_BPF`+`CAP_NET_ADMIN`+`CAP_PERFMON`, `/sys/fs/bpf`+`/sys/fs/cgroup` mounts | All of: shared namespaces, exact 3 caps, both mounts present | [pod_e2e_test.go:129-143](/home/mesb/repos/GO-eBPF-Proxy/deploy/podman/pod_e2e_test.go#L129-L143) asserts running state + `Config.User` + all 3 caps (L136-140, L143) | ⚠️ Spec-precision gap (unchanged from round 1): caps/user/running-state precisely asserted; shared PID/cgroup namespaces and the two bind mounts (implemented in `pod-up.sh`) are still never independently asserted by any test |
| WHEN the pod is healthy THEN `connect4`/`sockops` attached at the pod parent cgroup, maps pinned, and uprobes attached to the app's `libssl` | Programs attached, maps pinned, uprobes attached — all independently verifiable | **NEW (Fix 3)**: pin files checked at [pod_e2e_test.go:148-156](/home/mesb/repos/GO-eBPF-Proxy/deploy/podman/pod_e2e_test.go#L148-L156) (`origdst_by_cookie`, `origdst_by_tuple`, `secrets_rb`, `tls_keylog_config`); cgroup attach via `bpftoolCgroupTree` at [pod_e2e_test.go:159-161](/home/mesb/repos/GO-eBPF-Proxy/deploy/podman/pod_e2e_test.go#L159-L161): `assert.Contains(t, tree, "cgroup_connect4", ...)`, `assert.Contains(t, tree, "sockops_prog", ...)`; uprobe via `bpftoolLinkList` at [pod_e2e_test.go:163-171](/home/mesb/repos/GO-eBPF-Proxy/deploy/podman/pod_e2e_test.go#L163-L171) | ⚠️ Spec-precision gap (NEW, round 2): pin-file existence and cgroup-attach assertions are precise and real evidence (previously zero evidence — this closes the majority of the round-1 gap). However the uprobe check at L165-170 is imprecise: `if l["type"] == "perf_event" \|\| strings.Contains(strings.ToLower(fmt.Sprint(l["type"])), "uprobe")` treats **any** `perf_event`-typed bpftool link as proof of a uprobe attachment — it never inspects a subtype field (e.g. `perf_event_type`/`uprobe`) to confirm the link is specifically a uprobe rather than a kprobe/tracepoint/other perf_event link. In this harness's actual topology only the uprobe would produce a `perf_event` link, so it is very unlikely to false-positive today, but the assertion as written does not prove "uprobe" specifically — only "some perf_event link exists." Not privilege-testable here to confirm empirically; flagged from code review per the task's explicit request. Recommend tightening to check the link's subtype field. |
| WHILE the sidecar generates its own egress under UID 1337 THEN SHALL NOT re-intercept it (no self-loop) | No re-interception observable | **NEW (Fix 3)**: [pod_e2e_test.go:178-201](/home/mesb/repos/GO-eBPF-Proxy/deploy/podman/pod_e2e_test.go#L178-L201) `TestPodUp_SidecarEgressNotRedirected`: `tupleMapEntryCount` diffed before/after a `wget` from the sidecar (`assert.Equal(t, before, afterSidecar, ...)`, L196) vs. from the app container (`assert.Greater(t, afterApp, afterSidecar, ...)`, L200), probing a non-routable RFC 5737 TEST-NET-3 address (`203.0.113.1`) so `connect4` fires on the `connect()` syscall without depending on real network reachability | ✅ PASS (Fix 3 confirmed real) — the logic is sound: it distinguishes "UID 1337 traffic recorded" from "other-UID traffic recorded" by asserting opposite directions of change on the same counter, which is exactly the loop-avoidance behavior (not just the UID precondition round 1 flagged). `wget` via busybox is present in `alpine:3` by default, and `--timeout`/`-qO-` are supported busybox long-opts. `TEST-NET-3` is a safe, reasonable choice — reserved, never routed, so no real egress is generated. SKIPPED here (no root); logic reviewed, not executed |

### P2: End-to-end real-cert smoke test

| Criterion | Spec-defined outcome | `file:line` + assertion | Result |
| --- | --- | --- | --- |
| WHEN `curl https://example.com` (no `-k`) runs THEN validate the real cert and return HTTP 200 end-to-end | Exact `HTTP 200`, no `-k` in the invocation | `smoke.sh` never passes `-k`; [smoke_e2e_test.go:88-97](/home/mesb/repos/GO-eBPF-Proxy/deploy/podman/smoke_e2e_test.go#L88-L97) `assert.Contains(t, out, "HTTP 200", ...)` | ✅ PASS (SKIPPED — root + internet egress required) |
| WHEN the smoke test runs THEN log the correct original destination AND grow `dump.pcap`/`sslkeylog.log` | A log record identifying the resolved orig-dst; both artifact files grow | Artifact growth: [smoke_e2e_test.go:98-104](/home/mesb/repos/GO-eBPF-Proxy/deploy/podman/smoke_e2e_test.go#L98-L104) `assert.Eventually` (both files). Orig-dst logging: **NEW (Fix 1)** — [relay.go:36-39](/home/mesb/repos/GO-eBPF-Proxy/internal/proxy/relay.go#L36-L39) `WithOnResolved`, called at [relay.go:80-82](/home/mesb/repos/GO-eBPF-Proxy/internal/proxy/relay.go#L80-L82) inside `handle()` right after a successful `Resolve` and before `DialTimeout`; [app.go:101-103](/home/mesb/repos/GO-eBPF-Proxy/cmd/app/app.go#L101-L103) wires a real `logger.New(os.Stderr)` and calls `log.Info("connection relayed", map[string]any{"orig_dst": dst.String()})`; proven by [relay_it_test.go:52-79](/home/mesb/repos/GO-eBPF-Proxy/internal/proxy/relay_it_test.go#L52-L79) `TestRelay_LogsResolvedOriginalDestination`: `assert.Eventually(t, func() bool {... return got == want }, ...)` (L75-79) asserting the callback receives the *exact* resolved destination | ✅ PASS (Fix 1 confirmed real) — note: the callback mechanism itself is proven by an executed, passing integration test (no privilege needed — plain TCP loopback); `app.go`'s specific 3-line wiring of that mechanism to `logger.Info` with the `orig_dst` field is confirmed by direct code reading only, since every `cmd/app` integration test that would reach this code path (`TestApp_StartAndCloseAllSubsystemsCleanly` etc.) requires `CAP_BPF`+mounted bpffs and skips before reaching it in this sandbox — same environment-gating as the rest of `cmd/app`, not a new gap |
| WHEN offline validation runs over the produced artifacts THEN yield the request's plaintext HTTP | Decrypted output contains recognizable plaintext | [smoke_e2e_test.go:109-134](/home/mesb/repos/GO-eBPF-Proxy/deploy/podman/smoke_e2e_test.go#L109-L134) `assert.Contains(t, strings.ToLower(out), "example", ...)` (L133) | ✅ PASS (SKIPPED — root + `tshark`) |

**Status**: ✅ No zero-evidence gaps remain. **13/17** criteria matched the spec-defined outcome exactly (a clean improvement from round 1's 4 zero-evidence GAP rows, all 4 now closed with real evidence), **4 spec-precision gaps** flagged (3 carried over unchanged from round 1 — cross-component clock, UID-ownership assertion, namespace/mount assertion — plus 1 new, narrower precision note on the uprobe-subtype check introduced by Fix 3). Zero criteria have no evidence at all.

---

## Discrimination Sensor

Ran in an isolated `git worktree add /tmp/f03-verify-r2-scratch HEAD` (never the real tree, never `git stash`). Baseline `git status --porcelain` on the real tree was empty before sensor work; confirmed unchanged again after `git worktree remove --force /tmp/f03-verify-r2-scratch`.

Targeted the fix commits' actual production-code changes. Of the 4 fix commits, only `8f188e4` (`internal/proxy/relay.go` + `cmd/app/app.go`) introduced new production-code *behavior*; the other 3 fix commits changed only comments/`#nosec` annotations (`3d2b292`) or test files (`19773dc`, `f2837ee`). Mutations 1-2 target `relay.go` (the only new, behavior-bearing production code, run without privilege). Mutation 3 targets `internal/capture/pairing.go`'s `DecryptedAppData` (the production code the Fix 2 rewritten test exercises), reported honestly as environment-gated rather than falsely claimed as killed.

| Mutation | File:line | Description | Killed? |
| -------- | --------- | ------------ | ------- |
| 1 | `internal/proxy/relay.go` (`handle()`, the `onResolved` call site) | Removed the `if rl.onResolved != nil { rl.onResolved(dst) }` block entirely (side-effect removal) | ✅ Killed — `TestRelay_LogsResolvedOriginalDestination` failed: "Condition never satisfied" |
| 2 | `internal/proxy/relay.go` (`handle()`, the `onResolved` call site) | Changed the callback argument from the resolved `dst` to a zero-value `netip.AddrPort{}` (wrong-value fault) | ✅ Killed — `TestRelay_LogsResolvedOriginalDestination` failed: "Condition never satisfied" |
| 3 | `internal/capture/pairing.go:20` (`DecryptedAppData`) | Hardcoded the tshark display filter to `"tcp"`, ignoring the caller-supplied `filter` argument | ⚠️ Not empirically killed in this sandbox — `TestDecryptedAppData_RealTLS13FlowDecryptsToHTTP`, `TestDecryptedAppData_MismatchedKeylogFailsToDecrypt`, and `TestBackendParity_TcpdumpAndGopacketDecryptIdentically` all still SKIP (no `tshark` installed), so none of them ran against the mutant. Same environment constraint as the AC itself — this is a real, disclosed limitation of this sandbox's sensor coverage, not a false "killed" claim. |

**Sensor depth**: lightweight (3 mutations, default tier)
**Sensor outcome**: 2/2 executable mutations killed (both against the only behavior-bearing new production code, `relay.go`); 1/3 mutation could not be executed in this sandbox (requires `tshark`) — reported as unverified, not as killed or survived.
**Isolation check**: real tree `git status --porcelain` empty both before and after (worktree removed cleanly).

---

## Code Quality

| Principle | Status |
| --- | --- |
| No features beyond what was asked | ✅ — each fix commit does exactly what its round-1 finding required, nothing more |
| No abstractions for single-use code | ✅ |
| No unnecessary "flexibility" added | ✅ — `WithOnResolved` is a single-purpose functional option matching the existing `WithDialTimeout`/`WithOnDialErr` pattern already in `relay.go` |
| Only touched files required for task | ✅ — each fix commit's diff is confined to the files listed under Task Completion above |
| Didn't "improve" unrelated code | ✅ |
| Matches existing patterns/style | ✅ — round 1's package-comment convention violation is now fixed (only `clock.go` carries the canonical `// Package capture ...` doc comment; the other 4 files' redundant comments were trimmed, not left as prose) |
| Would senior engineer approve? | ✅ — all 5 round-1 findings addressed with proportionate, surgical fixes; one new minor precision note on the uprobe-subtype check (see AC table) |
| Tests map to acceptance criteria and are non-shallow (spot-check one story) | ✅ — spot-checked "Rootful Podman dev harness" (the story with the most round-1 churn): every AC now has file:line evidence, including the newly-added pin/attach/loop checks |
| Spec-anchored outcome check: each test's asserted value matches the spec-defined outcome (or gap flagged) | ✅ — 4 spec-precision gaps flagged (see AC table), zero silently passed |
| Per-layer Coverage Expectation met: domain logic has 1:1 AC mapping; routes/e2e cover happy + edge + error paths for every route in scope | ✅ — e2e layer now covers attach/pin/uprobe/no-self-loop paths that were missing in round 1 |
| Every test in scope maps to a spec AC, listed edge case, or Done-when criterion (no unclaimed tests) | ✅ — new tests carry `IT-03.x`/`CAPTURE-11` comments tying them to the matrix |
| Documented project quality/testing guidelines followed (cite guideline file, or "none - strong defaults applied") | ✅ — `AGENTS.md`'s `make lint` target now passes (0 issues); the e2e-tagged files under `deploy/...` (outside `make lint`'s default `integration` tag scope) were separately linted with the full guideline command and also pass (0 issues) |

---

## Edge Cases

- [x] IF capture starts before the keylog directory exists THEN create it `0700` before writing — unchanged from round 1, still satisfied (`internal/keylog/writer.go:23`, `internal/capture/pcapng.go:39`)
- [x] WHEN both DSB-embedded and split modes are requested THEN DSB is the default and split is an explicit opt-in — **Fix 4 confirmed**: `spec.md`'s Edge Cases section now reads: *"Descoped from the MVP (2026-09-12): only the DSB-embedded mode is implemented; the split (`pcap` + separate keylog) mode has no code path in `internal/capture`/`cmd/app` and is deferred to a follow-on feature. Tracked as a Verifier finding, not a regression."* Cross-checked: `spec.md`'s Success Criteria and Requirement Traceability (CAPTURE-01..11) make zero reference to split mode — the MVP's stated Acceptance depends only on the DSB-embedded path, so descoping this edge case does not silently drop an implementable requirement. Honest simplification, not a hidden gap.
- [x] IF `tcpdump` is unavailable THEN fall back to the in-process gopacket backend — unchanged from round 1 ([tcpdump_test.go:13-18](/home/mesb/repos/GO-eBPF-Proxy/internal/capture/tcpdump_test.go#L13-L18))

---

## Gate Check

- **Gate command (Build level, from tasks.md)**: `make build && make lint && go test -race -tags='integration e2e' ./...`

| Command | Exit | Notes |
| --- | --- | --- |
| `go build ./...` | 0 | clean |
| `go vet -tags=integration ./...` | 0 | clean |
| `go vet -tags=e2e ./...` | 0 | clean |
| `make build` (`go fmt` + `go vet` + `go build`) | 0 | clean |
| `make lint` (`golangci-lint`, `--build-tags=integration`) | 0 | **0 issues** — Fix 5 confirmed; round 1's 4 findings (3 `revive` package-comments + 1 `gosec` G302) are gone |
| `golangci-lint run --build-tags=e2e ...` on `./deploy/...` | 0 | **0 issues** — explicitly checked since `make lint`'s default tag scope (`integration`) does not cover the e2e-tagged files under `deploy/podman`; sanity-checked that this run genuinely analyzes files (running the same command *without* `--build-tags=e2e` errors `no go files to analyze`, confirming the e2e-tagged files are exactly what got scanned) |
| `go test -race ./...` (quick) | 0 | 61 passed, 0 failed, 0 skipped |
| `go test -race -tags=integration ./...` (full) | 0 | 68 passed, 0 failed, 13 skipped |
| `go test -race -tags=e2e ./deploy/podman/...` | 0 | 0 passed, 0 failed, 5 skipped (no root) |
| `go test -race -tags='integration e2e' ./...` | 0 | 68 passed, 0 failed, 18 skipped |

**Test counts** (fresh `-count=1 -v -race` runs):

| Run | Passed | Failed | Skipped | Total |
| --- | --- | --- | --- | --- |
| `go test -race ./...` | 61 | 0 | 0 | 61 |
| `go test -race -tags=integration ./...` | 68 | 0 | 13 | 81 |
| `go test -race -tags=e2e ./deploy/podman/...` | 0 | 0 | 5 | 5 |
| `go test -race -tags='integration e2e' ./...` | 68 | 0 | 18 | 86 |

**Skipped tests** (all justified, all environment-limited, none silently skip something that should pass):

- `TestConnect4_LoadsAndMapsAreLRU`, `TestConnect4_RewritesTcpDestinationToRelay`, `TestSockops_LoadsWithCorrectType` (`bpf`) — memlock rlimit / EPERM (pre-existing F01 skips)
- `TestApp_StartAndCloseAllSubsystemsCleanly`, `TestApp_CloseWithRetainPreservesArtifacts` (`cmd/app`) — `mkdir /sys/fs/bpf/gotestpin-...: permission denied`
- `TestDecryptedAppData_RealTLS13FlowDecryptsToHTTP`, `TestDecryptedAppData_MismatchedKeylogFailsToDecrypt`, `TestBackendParity_TcpdumpAndGopacketDecryptIdentically` (`internal/capture`) — `tshark` not on `PATH` (confirmed: `which tshark` exits 1)
- `TestLoader_PinLifecycleAndAttach`, `TestLoader_LRUOverfillNoError` (`internal/ebpf`) — bpffs permission denied (pre-existing F01 skip)
- `TestConsumer_AttachAndCloseLifecycle`, `TestTlsKeylog_LoadsWithExpectedMapsAndProgType`, `TestTlsKeylog_ConfigWiring` (`internal/keylog`/`bpf`) — memlock rlimit (pre-existing F02 skip)
- All 5 `deploy/podman` e2e tests — `os.Geteuid() != 0` (confirmed: `id -u` = 1000, no rootful podman session)

**Failures**: 0 test failures across all 4 gate invocations. `make lint` now exits 0 (Fix 5 confirmed).

---

## Fix Verification Summary (round 1's 5 findings)

| # | Round-1 finding | Status now | Evidence |
| - | --- | --- | --- |
| 1 | Orig-dst never logged (CAPTURE-11) | ✅ **Fixed, confirmed** | `relay.go:36-39,80-82` (`WithOnResolved` + call site), `app.go:101-103` (real logger wiring), `relay_it_test.go:52-79` (executed, passing test proving the exact callback contract) |
| 2 | Backend-parity test asserted nothing (CAPTURE-03) | ✅ **Fixed, confirmed** | `tcpdump_it_test.go:19-79` now drives a real TLS 1.3 flow through both backends and asserts byte-identical decrypted output (still env-gated on `tshark`, same as before, but the assertion is now real) |
| 3 | Podman e2e asserted nothing about attach/pin/loop (CAPTURE-09/10) | ✅ **Fixed, mostly confirmed** | Pin-file checks, `bpftool cgroup tree`, and the new `TestPodUp_SidecarEgressNotRedirected` are all sound and real; one narrow precision note on the uprobe-subtype check (not privilege-testable here) |
| 4 | Split-mode edge case undocumented | ✅ **Fixed, confirmed** | `spec.md` Edge Cases now carries a dated, honest descope note; cross-checked against Acceptance/Traceability — does not hide an implementable requirement |
| 5 | `make lint` failing (4 issues) | ✅ **Fixed, confirmed** | `make lint` exits 0; e2e-tagged `deploy/...` files separately linted and also 0 issues |

---

## Requirement Traceability Update

| Requirement | Round-1 Status | Round-2 Status |
| --- | --- | --- |
| CAPTURE-01 | ✅ Verified | ✅ Verified |
| CAPTURE-02 | ✅ Verified (spec-precision note) | ✅ Verified (same spec-precision note, unchanged) |
| CAPTURE-03 | ❌ Needs Fix | ✅ Verified (Fix 2) |
| CAPTURE-04 | ✅ Verified | ✅ Verified |
| CAPTURE-05 | ✅ Verified | ✅ Verified |
| CAPTURE-06 | ✅ Verified (spec-precision note) | ✅ Verified (same spec-precision note, unchanged) |
| CAPTURE-07 | ✅ Verified | ✅ Verified |
| CAPTURE-08 | ✅ Verified | ✅ Verified |
| CAPTURE-09 | ❌ Needs Fix | ✅ Verified (Fix 3; minor uprobe-subtype precision note) |
| CAPTURE-10 | ❌ Needs Fix | ✅ Verified (Fix 3) |
| CAPTURE-11 | ❌ Needs Fix | ✅ Verified (Fix 1) |

---

## Summary

**Overall**: ✅ Ready

**Result**: PASS ✅ — all 5 round-1 findings are fixed and independently confirmed with real evidence; zero zero-evidence AC gaps remain; all gates green; discrimination sensor killed both executable mutations against the only new production-code behavior (`relay.go`); one mutation against `pairing.go` could not be executed in this sandbox (no `tshark`) and is reported honestly rather than claimed as killed.

**Spec-anchored check**: 13/17 criteria matched the spec-defined outcome exactly; 4 spec-precision gaps flagged (3 carried over unchanged from round 1, 1 new narrow precision note on the round-2 uprobe-subtype check); 0 zero-evidence gaps
**Sensor**: 3 mutations injected, 2 killed, 0 survived, 1 unverifiable in this sandbox (disclosed, not counted as killed)
**Gate**: `go build`, both `go vet` variants, `make build`, `make lint` (now 0 issues), the separately-checked e2e-tagged lint pass, and every `go test` invocation (quick/full/e2e/combined) passed with 0 failures (68 passed / 18 legitimately-skipped in the full integration+e2e run)

**What works**: All 5 round-1 findings are genuinely fixed, not just marked done. `WithOnResolved` is a clean, minimal functional option wired through `cmd/app/app.go` to a real logger; the backend-parity test now drives a real TLS 1.3 flow and diffs decrypted output; the Podman e2e harness now asserts pin-file existence, cgroup program attachment, and a behaviorally-sound no-self-loop check via tuple-map-count comparison; the split-mode edge case is honestly descoped without hiding an implementable requirement; and `make lint` (plus the separately-checked e2e-tagged files) is fully clean. The discrimination sensor confirms the one new behavior-bearing production code path (`relay.go`'s `onResolved` call) is genuinely tested, not just present.

**Issues found** (none blocking; carried-over and new precision notes only):

1. (Carried over, unchanged) `internal/keylog` has no cross-component `Clock`, so CAPTURE-02's "shared clock" is only literally testable at the capture-internal level.
2. (Carried over, unchanged) UID-1337 ownership of capture/keylog artifact files is never independently asserted (only structurally implied by the pod running as that UID).
3. (Carried over, unchanged) Shared PID/cgroup namespaces and the two bind mounts (`pod-up.sh`) are implemented but never independently asserted by any test.
4. (New, minor) `pod_e2e_test.go`'s `bpftoolLinkList`-based uprobe check accepts any `perf_event`-typed link rather than confirming the specific uprobe subtype — low risk in this harness's actual topology, but imprecise as written; recommend checking the link's subtype field in a follow-up.

**Next steps**: None required to close this feature — round 2 is a PASS. Recommend a lightweight follow-up (not blocking) to tighten the uprobe-subtype check in `pod_e2e_test.go` when that suite is next touched, and to eventually independently assert UID-ownership/namespace/mount facts if a rootful CI runner becomes available.

---

## Addendum: live rootful validation session (2026-09-12, post-round-2)

**Performed by**: the implementing agent directly (author, not an independent Verifier sub-agent) at the user's explicit request, on this same host, which has passwordless `sudo` and podman/bpftool installed. Recorded here transparently as author-run evidence, not re-labeled as independent verification.

**Commit**: `de39250` (`fix(deploy): fix pod-up.sh for a real rootful run ...`).

A real rootful pod was brought up end-to-end using `sudo`. Seven real bugs in `pod-up.sh`/`pod-down.sh` were found and fixed by iterating against the actual failures (not by inspection): `--cgroupns=host` was on the wrong command (pod vs container level), a missing `/` in the resolved cgroup path, a dynamically-linked (glibc) binary that cannot run on musl/Alpine, unsupported `--tmpfs uid=/gid=` mount options, root-owned `/sys/fs/bpf` blocking the sidecar's own pin dirs, a missing `CAP_SYS_RESOURCE` for `RLIMIT_MEMLOCK`, this host's default AppArmor **and** seccomp profiles each independently blocking one step of BPF map create/pin, and the app's PID needing resolution from inside the shared pod PID namespace rather than podman's host-relative PID.

**Confirmed working, for real, on a live rootful pod** (closes part of the CAPTURE-09 spec-precision gap noted above with genuine evidence, not just static citation):

- `connect4`/`sockops` load, verify, and **attach at the resolved pod-parent cgroup** (`/sys/fs/cgroup/machine.slice/machine-libpod_pod_<id>.slice`), confirming AD-002's "pod common parent cgroup" design is achievable with this exact script.
- Their maps **pin successfully** under `/sys/fs/bpf/go-ebpf-proxy/` once the pin dir is pre-created and chowned, and the host's default AppArmor/seccomp profiles are lifted for the sidecar.

**New, real blocker found** (not previously known from static review): once past connect4/sockops, the **uprobe keylog program is rejected by this kernel's BPF verifier** (`invalid write to stack R1 ... size=65535`) when attached against a real `libssl.so.3` (from `nginx:alpine`). This is consistent with, and is the first concrete empirical confirmation of, the already-documented limitation in `internal/keylog/openssl_offsets.go`: every `SecretOffset`/`ClientRandomOffset` is a placeholder `0`, so the uprobe reads garbage relative to the real struct layout, which the verifier now visibly rejects on this specific kernel/libssl build. Closing this requires a dedicated per-build OpenSSL struct-offset reverse-engineering effort (out of scope for a script fix) — tracked as a follow-up, not a regression.

Because `cmd/app`'s `Start()` aborts the whole sidecar if the keylog consumer fails to attach (no partial-degradation path), the remainder of the pipeline (capture, retention, relay traffic, the no-self-loop tuple-map check) was not exercised past this point in this session. The formal `deploy/podman` e2e Go test suite was deliberately **not** run against this real pod in this state: it would fail (not skip) at the "sidecar running" assertions, and that failure is a true, already-understood positive (the offset gap), not a new defect worth re-triggering the fix→re-verify loop for.

The host was fully restored afterward: pod/containers/volume removed, `/sys/fs/bpf` permissions reverted to `0700`, no leftover pin directories.

---

## Phase 4 addendum re-verification (AD-010)

**Date**: 2026-09-12
**Scope**: A scoped, independent re-check of **only** Phase 4 (T9, T10, T11 — the AD-010 harness rewiring) plus its own follow-up ordering fix. Phases 1–3 keep their existing PASS above, unchanged; not re-checked here.
**Diff range**: `git log --oneline de39250..HEAD` → 12 commits. Of these, exactly 4 touch the Phase-4-scoped files:

- `81fd652 fix(deploy): rewire pod-up.sh for the LD_PRELOAD keylog interposer (AD-010)` (T9) — `deploy/podman/pod-up.sh`
- `c0d0c81 test(deploy): update e2e assertions for the preload interposer (AD-010)` (T10) — `deploy/podman/pod_e2e_test.go`
- `c80fc52 docs(readme): describe the LD_PRELOAD keylog interposer (AD-010)` (T11) — `README.md`
- `8ba51a8 fix(deploy): start sidecar before app so the keylog socket is ready first` — `deploy/podman/pod-up.sh` (T9 amendment, landed after Feature 02's Verifier flagged the ordering)

The other 8 commits (`preload/`, `internal/keylog/`, `cmd/app/`) belong to Feature 02 / earlier Feature 03 wiring, already covered by Feature 02's own fresh PASS and are out of scope here.
**Verifier**: independent sub-agent (author ≠ verifier) — fresh pass, did not trust the tasks.md Status/Amendment prose; every claim below was re-derived from the current tree.

### Task Completion (Phase 4 only)

| Task | Status | Notes |
| ---- | ------ | ----- |
| T9 | ✅ Done | `deploy/podman/pod-up.sh:1-116` — verified by direct reading, not by trusting the task's own Status note |
| T10 | ✅ Done | `deploy/podman/pod_e2e_test.go:1-189` — compiles, assertions non-shallow (see below); one completeness gap vs. T9's descriptive "What" text (see Ranked gaps) |
| T11 | ✅ Done | `README.md` — mermaid fences balanced, no current-mechanism "uprobe" wording remains |

### Spec-Anchored Acceptance Criteria (T9/T10/T11 vs. spec.md CAPTURE-09)

| Criterion (spec.md CAPTURE-09, P2 "Rootful Podman dev harness") | Spec-defined outcome (literal spec.md text) | `file:line` + assertion | Result |
| --- | --- | --- | --- |
| AC1: "start a rootful pod with shared PID ns, host cgroup ns, sidecar caps CAP_BPF+CAP_NET_ADMIN+CAP_PERFMON" | Literal spec.md text still requires shared PID ns + `CAP_PERFMON` | [pod-up.sh:65-68](/home/mesb/repos/GO-eBPF-Proxy/deploy/podman/pod-up.sh#L65-L68) `--share net,ipc,uts` (no `pid`), `--cap-add CAP_BPF --cap-add CAP_NET_ADMIN --cap-add CAP_SYS_RESOURCE` (no `CAP_PERFMON`) | ❌ **Spec/code divergence** — code is intentionally correct per AD-010, but spec.md's own AC1 text was never amended to match (see Ranked gap 1) |
| AC2: "connect4/sockops attached at the pod parent cgroup, maps pinned, and uprobes attached to the app's libssl" | Literal spec.md text still requires uprobe attachment | [pod_e2e_test.go:170-183](/home/mesb/repos/GO-eBPF-Proxy/deploy/podman/pod_e2e_test.go#L170-L183) — no `bpftool link`/uprobe assertion remains (removed by T10); a new `sawLDPreload` env-prefix assertion replaces it | ❌ **Spec/code divergence** — same root cause as AC1; the *intended* replacement outcome (interposer wiring) is correctly tested, but doesn't literally satisfy spec.md's still-uprobe-worded AC2 |
| Task-level (not spec.md-worded) outcome: no `CAP_PERFMON`, no `--share pid`, no removed sidecar flags, `build-preload` runs first, shared keylog-socket volume, `.so` + both env vars on app container, `--keylog-socket` on sidecar | Precise, from tasks.md T9 "What"/"Done when" | [pod-up.sh:70-71](/home/mesb/repos/GO-eBPF-Proxy/deploy/podman/pod-up.sh#L70-L71) `podman pod create --share net,ipc,uts`; [pod-up.sh:57](/home/mesb/repos/GO-eBPF-Proxy/deploy/podman/pod-up.sh#L57) `make -C "$REPO_ROOT" build-preload`; [pod-up.sh:73-78](/home/mesb/repos/GO-eBPF-Proxy/deploy/podman/pod-up.sh#L73-L78) both volumes created; [pod-up.sh:120-126](/home/mesb/repos/GO-eBPF-Proxy/deploy/podman/pod-up.sh#L120-L126) `.so` bind-mount `:ro,z` + `LD_PRELOAD`/`GOEBPF_PRELOAD_SOCKET` env on the app container only; [pod-up.sh:100](/home/mesb/repos/GO-eBPF-Proxy/deploy/podman/pod-up.sh#L100) `--keylog-socket="$KEYLOG_SOCKET"` on the sidecar | ✅ PASS |
| Ordering fix: sidecar starts and its socket is confirmed bound before the app container starts | KEYLOG-05 (spec 02): "sidecar listens ... before the app container starts" | [pod-up.sh:88-116](/home/mesb/repos/GO-eBPF-Proxy/deploy/podman/pod-up.sh#L88-L116): sidecar `podman run -d` (L91) precedes the poll loop (L110-114: `[[ -S "$KEYLOG_VOLUME_MOUNT/keylog.sock" ]]`, 100×100ms) which precedes the app `podman run -d` (L118) | ✅ PASS |
| T10: no `CAP_PERFMON`/pin-path/uprobe assertion remains; new interposer assertion is non-shallow | Assertion must target the actual `Env` value, not just "no error" | [pod_e2e_test.go:177-183](/home/mesb/repos/GO-eBPF-Proxy/deploy/podman/pod_e2e_test.go#L177-L183): loops `app.Config.Env`, `strings.HasPrefix(kv, "LD_PRELOAD=")`, `assert.True(t, sawLDPreload, ...)` — targets an actual field value, not a vacuous check | ✅ PASS |
| T11: no remaining "uprobe" as *current* mechanism; status table + layout reflect interposer; mermaid fences balanced | Precise, from tasks.md T11 "Done when" | [README.md:88-90](/home/mesb/repos/GO-eBPF-Proxy/README.md#L88-L90) — only remaining "uprobe" mention is the explicitly labeled "Historical note" blockquote; `grep -c '```' README.md` = 10 (5 balanced fence pairs); [README.md:99-103](/home/mesb/repos/GO-eBPF-Proxy/README.md#L99-L103) Status table shows M2 "via the `LD_PRELOAD` interposer" | ✅ PASS |

**Status**: ⚠️ Spec/code divergence flagged (2 rows) — the *implementation* (T9/T10/T11) is correct and matches tasks.md's Phase-4 addendum note and Feature 02's spec.md, but `03-capture-harness/spec.md`'s own CAPTURE-09 AC text and Assumptions table were never amended for AD-010, unlike `02-uprobe-keylog/spec.md` which received a full AD-010 revision note. This is a documentation-debt gap, not an implementation defect — see Ranked gap 1.

### Discrimination Sensor

Tests in `deploy/podman/*_e2e_test.go` cannot execute in this sandbox (no root/CAP_BPF — `requireRootfulPodman(t)` skips cleanly, confirmed by `go test -v -race -tags='integration e2e' ./deploy/podman/...`: 5/5 tests SKIP, 0 failed). Per the task's explicit instruction, mutations therefore targeted the **assertion logic itself**, extracted into an isolated scratch harness (`git worktree`, never `git stash`) that mirrors `TestPodUp_BringsUpHealthyPodWithExpectedConfig`'s new `LD_PRELOAD` env-prefix check exactly, exercised against fabricated (not live) container-env data.

| Mutation | File:line | Description | Killed? |
| -------- | --------- | ------------ | ------- |
| 1 | `pod_e2e_test.go:178-181` (mirrored logic) | Flipped the expected prefix from `"LD_PRELOAD="` to `"LD_PRELOAD_WRONG="` | ✅ Killed — sensor test failed on real-good env data, confirming the exact-prefix check is load-bearing |
| 2 | `pod_e2e_test.go:178-181` (mirrored logic) | Removed the required side effect: made the check unconditionally return `true` (tautological) | ✅ Killed — sensor test failed to distinguish a regressed (missing `LD_PRELOAD`) env from a correct one |

**Sensor depth**: lightweight (2 mutations, proportional to a single new assertion in scope).
**Result**: 2/2 killed — 0 survived.
**Limitation disclosed**: this sensor exercised a faithful re-implementation of the assertion's logic against synthetic data, not the actual `pod_e2e_test.go` code path with real `podman inspect` output, because the real test cannot run without root/CAP_BPF in this sandbox. The mirrored logic is character-for-character equivalent to [pod_e2e_test.go:178-181](/home/mesb/repos/GO-eBPF-Proxy/deploy/podman/pod_e2e_test.go#L178-L181), so this is reasoned confidence, not fabricated execution of the real test.
**Isolation verified**: `git status --porcelain` was empty before sensor setup and empty again after `git worktree remove --force`.

### Gate Check (Phase 4 scope)

- `bash -n deploy/podman/pod-up.sh` → exit 0 (syntax valid)
- `go build ./... && go vet ./...` → both pass
- `go test -race -tags='integration e2e' ./...` → all packages `ok`; `deploy/podman`'s 5 e2e tests (`TestPodUp_BringsUpHealthyPodWithExpectedConfig`, `TestPodUp_SidecarEgressNotRedirected`, `TestSmoke_RealCertRequestSucceedsAndArtifactsGrow`, `TestSmoke_OfflineValidationDecryptsPlaintext`, `TestPodDown_DefaultWipesRetainPreserves`) all SKIP cleanly via `requireRootfulPodman(t)`, 0 failed
- `make lint` → fails with `golangci-lint: No such file or directory` (exit 127) — confirmed as the expected pre-existing environment gap (tool not installed in this sandbox), not a new lint finding; not attempted to install per the safety constraint
- `pod-up.sh`/`sudo podman pod create` were **not** run, per the mandatory safety constraint (no CAP_BPF/CAP_NET_RAW for the unprivileged user in this sandbox)

### Code Quality (Phase 4 files)

| Check | Status |
| ----- | ------ |
| No `--share pid`, `CAP_PERFMON`, or removed sidecar flags remain | ✅ |
| `make build-preload` runs before pod creation | ✅ |
| Shared keylog-socket volume mounted into both containers | ✅ |
| App container: `.so` bind-mount read-only + `LD_PRELOAD`/`GOEBPF_PRELOAD_SOCKET` | ✅ |
| Sidecar: `--keylog-socket` flag | ✅ |
| Sidecar starts and its socket is confirmed bound before the app starts | ✅ |
| `pod_e2e_test.go` compiles, no `CAP_PERFMON`/pin-path/uprobe assertions remain | ✅ |
| New interposer assertion targets actual field value | ✅ |
| README: no current-mechanism "uprobe" wording; balanced mermaid fences | ✅ |
| Only files in scope touched (`pod-up.sh`, `pod_e2e_test.go`, `README.md`) | ✅ |

### Ranked gaps (non-blocking; documentation-debt / completeness, not implementation defects)

1. **`03-capture-harness/spec.md`'s CAPTURE-09 AC text and Assumptions table were never amended for AD-010** — they still literally require "shared PID ns", "CAP_PERFMON", and "uprobes attached to the app's libssl", which the Phase-4 implementation deliberately and correctly removes. `02-uprobe-keylog/spec.md` received a full AD-010 revision note (see its header); `03-capture-harness/spec.md` did not receive an equivalent addendum, even though `tasks.md`'s Phase 4 section has one. Recommend a short "Revision note (AD-010)" added to `spec.md`'s CAPTURE-09 story and Assumptions table, mirroring `02-uprobe-keylog/spec.md`'s pattern — `spec.md` is the traceability source of truth and a future reader following only `spec.md`/`README.md` would reasonably conclude the pod still needs a shared PID namespace and `CAP_PERFMON`.
2. **T9's descriptive "What" text says a "no shared PID namespace configured" assertion should be added to `pod_e2e_test.go`, but no such assertion exists** — `podmanInspect` has no `PidMode`/`HostConfig.Pid`-equivalent field, and neither test function asserts on it. This is not in T10's enumerated "Done when" checklist (which only requires removing the `CAP_PERFMON`/pin-path/uprobe assertions and adding the interposer check — both satisfied), so it does not block this Phase's PASS, but it is a real gap between the task's own description and its test coverage. Recommend a follow-up assertion, e.g. `assert.Empty(t, sidecar.HostConfig.PidMode, ...)`, next time this file is touched.

Neither gap blocks Phase 4's PASS: both are documentation/completeness gaps in artifacts *adjacent* to the three in-scope files, not defects in `pod-up.sh`, `pod_e2e_test.go`, or `README.md` themselves.

### Requirement Traceability Update

| Requirement | Prior Status (round 2, pre-AD-010) | Phase-4 Status |
| ----------- | ----------------------------------- | --------------- |
| CAPTURE-09 | ✅ Verified (uprobe-era harness) | ⚠️ Verified-with-caveat — implementation correctly matches AD-010; `spec.md`'s own AC1/AC2 text is stale (Ranked gap 1) |
| CAPTURE-10 | ✅ Verified | ✅ Verified — unaffected by Phase 4 (no-self-loop logic untouched) |

### Summary

**Overall**: ✅ Ready (Phase 4 scope)

**Spec-anchored check**: 3/5 criteria matched their spec-defined outcome exactly; 2 flagged as spec/code divergence (documentation debt in `spec.md`, not a code defect)
**Sensor**: 2/2 mutations killed, 0 survived (mirrored-logic sensor, real e2e tests unexecutable without root — limitation disclosed)
**Gate**: `bash -n`, `go build`, `go vet`, and `go test -race -tags='integration e2e' ./...` all green (0 failed, 5 e2e tests skipped cleanly with justification); `make lint` fails only with the pre-existing `golangci-lint` binary-missing environment gap

**What works**: `pod-up.sh` correctly drops the shared PID namespace, `CAP_PERFMON`, and all uprobe-era sidecar flags; builds and wires the `LD_PRELOAD` interposer `.so` + both env vars into the app container only; passes `--keylog-socket` to the sidecar; and — per the later ordering fix — starts the sidecar and confirms its socket is bound before starting the app container. `pod_e2e_test.go` compiles, removed every uprobe/CAP_PERFMON/pin-path assertion, and added a non-shallow `LD_PRELOAD` env-prefix assertion, confirmed discriminating by the sensor. `README.md` fully describes the interposer mechanism with only a clearly-labeled historical footnote for uprobes, and both mermaid diagrams are well-formed.

**Issues found**: 1) `spec.md`'s CAPTURE-09 text/Assumptions table is stale relative to AD-010 (documentation debt, not a code defect — see Ranked gap 1). 2) T9's own "What" text describes a PID-namespace-absence assertion that was never added to `pod_e2e_test.go` (Ranked gap 2, non-blocking per T10's actual Done-when checklist).

**Next steps**: Non-blocking follow-ups only — amend `03-capture-harness/spec.md`'s CAPTURE-09 story/Assumptions table with an AD-010 revision note (mirroring `02-uprobe-keylog/spec.md`), and optionally add a `PidMode`-absence assertion to `pod_e2e_test.go` next time that file is touched. No fix→re-verify cycle required; Phase 4 is accepted as-is.

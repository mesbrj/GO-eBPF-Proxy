# 02-uprobe-keylog Validation

> **Revision note (2026-09-12, re-verification 2)**: this report supersedes the prior
> validation pass (diff `de39250..2bc20ed`) entirely. That pass found 1 hard GAP
> (KEYLOG-05: `pod-up.sh` started the app container before the sidecar) and 1
> spec-precision gap flagged as a fix candidate (KEYLOG-08: no test for the
> interposer's unreachable-socket retry-then-drop path). Both have since been
> addressed by two follow-up commits. This is a from-scratch re-derivation, not a
> check of the two fixes in isolation — every AC, the gate, and the sensor were
> re-run independently.

**Date**: 2026-09-12
**Spec**: `.specs/features/02-uprobe-keylog/spec.md`
**Diff range**: `de39250..2bc20ed` (the original T1-T7 batch) **plus** `42ac87e`
(`test(keylog): cover the unreachable-socket retry-then-drop path (KEYLOG-08)`, this
feature's own fix commit). The pod-up.sh ordering fix (`8ba51a8`,
`fix(deploy): start sidecar before app so the keylog socket is ready first`) lives in
Feature 03's file scope (`deploy/podman/pod-up.sh`, owned by F03's T9) but directly
resolves this feature's KEYLOG-05 gap — read and confirmed sound below, not re-verified
as this feature's own task.
**Commit count note**: `git log --oneline de39250..HEAD` shows **12** commits (7
T1-T7 + 3 Feature-03-Phase-4 commits `81fd652`/`c0d0c81`/`c80fc52` + this feature's 2 fix
commits `8ba51a8`/`42ac87e`), not the 11 stated in the re-verification brief
(7+3+2=12 is arithmetically consistent with 12, not 11) — a harmless counting slip in
the brief, not a defect; noted for the record, not scored against the feature.
**Verifier**: independent sub-agent (author ≠ verifier), re-verification iteration 2/3

---

## Task Completion

| Task | Status  | Notes |
| ---- | ------- | ----- |
| T1   | ✅ Done | All 12 listed uprobe-era files remain deleted; `bpf/gen.go` generates only `Proxy` from `proxy.bpf.c` (unchanged since the prior pass). |
| T2   | ✅ Done | [preload/keylog_preload.c](../../../preload/keylog_preload.c) compiles via `make build-preload`; wraps both `SSL_CTX_new`/`SSL_CTX_new_ex`. |
| T3   | ✅ Done | [internal/keylog/socket_server.go](../../../internal/keylog/socket_server.go) implements guard/listen/accept/route/reject; unit-tested. |
| T4   | ✅ Done | [internal/keylog/preload_env.go](../../../internal/keylog/preload_env.go) — 1 unit test, exact-slice assertion. |
| T5   | ✅ Done | [internal/keylog/preload_it_test.go](../../../internal/keylog/preload_it_test.go) — now **6** integration tests (5 original + the new KEYLOG-08 test from `42ac87e`); all 6 confirmed **PASS** (none skipped) on this box. |
| T6   | ✅ Done | `Config.KeylogSocketPath` replaces the 5 removed uprobe fields in [cmd/app/app.go](../../../cmd/app/app.go); `go build ./... && go vet ./...` green repo-wide. |
| T7   | ✅ Done | [cmd/app/app_it_test.go](../../../cmd/app/app_it_test.go) uses `KeylogSocketPath`; both tests **skip** on this dev box (no `CAP_BPF`/mounted `bpffs`) — pre-existing precondition, unrelated to this feature. |
| Fix 1 (KEYLOG-05, out-of-range file) | ✅ Done | `deploy/podman/pod-up.sh` (commit `8ba51a8`) reordered to start the sidecar, poll the shared keylog volume for the bound socket file (`-S`, 100×0.1s), then start the app — read and confirmed sound below. |
| Fix 2 (KEYLOG-08) | ✅ Done | `internal/keylog/preload_it_test.go`'s new `TestPreload_SocketUnreachable_ClientCompletesWithoutBlocking` (commit `42ac87e`) — confirmed passing and, via the discrimination sensor below, confirmed to actually discriminate a real block. |

---

## Spec-Anchored Acceptance Criteria

### P1: Interposer captures OpenSSL's own keylog lines

| Criterion (WHEN X THEN Y) | Spec-defined outcome | `file:line` + assertion | Result |
| -------------------------- | --------------------- | ------------------------ | ------ |
| WHEN app calls `SSL_CTX_new`/`_ex` THEN call through to real fn, THEN register `SSL_CTX_set_keylog_callback` before returning ctx | Real ctx returned, callback registered on it, in that order | [preload/keylog_preload.c:122-132](../../../preload/keylog_preload.c) (`SSL_CTX_new`: `real_fn(method)` → `SSL_CTX_set_keylog_callback(ctx, keylog_cb)` → `return ctx`); [preload/keylog_preload.c:134-143](../../../preload/keylog_preload.c) (`SSL_CTX_new_ex`, same shape); proven end-to-end by [preload_it_test.go:167](../../../internal/keylog/preload_it_test.go) — a real TLS 1.3 handshake completes and all 5 lines arrive | ✅ PASS |
| WHEN OpenSSL invokes the callback THEN forward the already-NSS-formatted line verbatim, no reformatting | Byte-identical NSS grammar, no transformation | [preload/keylog_preload.c:100-119](../../../preload/keylog_preload.c) (`keylog_cb`: `memcpy(buf, line, linelen)`, appends only `\n`); [preload_it_test.go:193-201](../../../internal/keylog/preload_it_test.go) asserts each line splits into exactly `{label, client_random, secret}` matching the 5-label set with one shared `client_random` | ✅ PASS |
| App's handshake/cert validation left unmodified — interposer never touches handshake data | No spec-defined observable runtime value (code-shape invariant) | Code inspection: [preload/keylog_preload.c](../../../preload/keylog_preload.c) contains no calls to any `SSL_CTX_set_verify*`/`SSL_get_verify_result`/certificate API — only `SSL_CTX_new`, `SSL_CTX_new_ex`, `SSL_CTX_set_keylog_callback`. No test explicitly forces a cert-validation failure to prove the path is untouched (unchanged since the prior pass; already tracked as lesson `L-005`) | ⚠️ Spec-precision gap (code-shape evidenced, not runtime-tested — unchanged, not a regression) |
| IF app never links OpenSSL dynamically (static/non-OpenSSL) THEN symbols never called — no crash, no lines | Zero lines, `exec.Command.Run()` returns no error | [preload_it_test.go:281-301](../../../internal/keylog/preload_it_test.go) `TestPreload_NonOpenSSLBinary_NoCrashNoLines`: `assert.NoError(t, err, ...)` + `assert.Empty(t, string(data), ...)` against the `true` binary | ✅ PASS |

### P1: Reliable line transport to the sidecar

| Criterion (WHEN X THEN Y) | Spec-defined outcome | `file:line` + assertion | Result |
| -------------------------- | --------------------- | ------------------------ | ------ |
| WHEN sidecar starts THEN listen before app container starts | App's first handshake never races sidecar readiness | [deploy/podman/pod-up.sh:76-124](../../../deploy/podman/pod-up.sh) (commit `8ba51a8`, out-of-range file, re-derived independently): `podman run ... "${POD_NAME}-sidecar"` runs first, then a poll loop (`for _ in $(seq 1 100); do [[ -S "$KEYLOG_VOLUME_MOUNT/keylog.sock" ]] && break; sleep 0.1; done`) blocks until the bound socket file exists (or fails loudly after 10s), and only then is `"${POD_NAME}-app"` started. `bash -n deploy/podman/pod-up.sh` syntax-checks clean. Not executed end-to-end here (rootful podman pod creation is out of this review's safety scope — matches this repo's own convention of not autonomously running rootful podman) | ✅ PASS (independently re-derived from the fix, not merely trusted from the prior report) |
| WHEN interposer has a line THEN write it newline-terminated to its cached socket connection | `<line>\n` written to the cached fd | [preload/keylog_preload.c:104-108](../../../preload/keylog_preload.c) (`buf[linelen]='\n'`) + [preload/keylog_preload.c:116](../../../preload/keylog_preload.c) (`send_line_locked(buf, linelen+1)`); proven end-to-end via T5's tests | ✅ PASS |
| WHEN socket server receives a line THEN route through existing validate/dedup/append unchanged | Well-formed line appended exactly once even if sent twice | [internal/keylog/socket_server_test.go:73-86](../../../internal/keylog/socket_server_test.go) `TestSocketServer_WellFormedLines_DedupedAndAppended`: sends the same line twice, `assert.Equal(t, line+"\n", got, ...)` | ✅ PASS |
| IF a line is malformed THEN reject (no append) and never log its content | Keylog file stays empty; log buffer never contains the sentinel payload | [internal/keylog/socket_server_test.go:90-114](../../../internal/keylog/socket_server_test.go) `TestSocketServer_MalformedLine_RejectedWithoutAppendOrContentLog`: `assert.Empty(t, string(data), ...)` + `assert.NotContains(t, logBuf.String(), sentinel, ...)` | ✅ PASS |
| IF interposer can't connect/write fails THEN retry briefly then silently drop, never block the app | Bounded retry count/backoff, app never blocks; client process still completes | [preload/keylog_preload.c:31,77-96](../../../preload/keylog_preload.c) (`KEYLOG_MAX_SEND_ATTEMPTS=3`, 20ms backoff); **now runtime-tested** by [internal/keylog/preload_it_test.go:308-330](../../../internal/keylog/preload_it_test.go) `TestPreload_SocketUnreachable_ClientCompletesWithoutBlocking`: points `GOEBPF_PRELOAD_SOCKET` at a socket path with no listener at all, asserts the client completes within 3s (`t.Fatal` otherwise); confirmed **passing** (0.48s) and confirmed **discriminating** by the sensor below (inflating the attempt bound to a value that would genuinely block past 3s kills this exact test) | ✅ PASS (closes the prior spec-precision gap) |
| WHILE socket dir is world-writable/readable THEN refuse to listen | `NewSocketServer` returns `ErrWorldAccessibleSocketDir` | [internal/keylog/socket_server.go:88-105](../../../internal/keylog/socket_server.go) `checkSocketDir` (`perm&0o066 != 0`); [internal/keylog/socket_server_test.go:140-150](../../../internal/keylog/socket_server_test.go) `TestSocketServer_RefusesWorldWritableSocketDir`: `chmod 0777` then `assert.True(t, errors.Is(err, ErrWorldAccessibleSocketDir), ...)` | ✅ PASS |

### P2: Preload environment wiring on the app container

| Criterion (WHEN X THEN Y) | Spec-defined outcome | `file:line` + assertion | Result |
| -------------------------- | --------------------- | ------------------------ | ------ |
| WHEN building preload env THEN emit exactly `LD_PRELOAD=<path>` and the socket-path env var, no others | Exactly `["LD_PRELOAD=<so>", "GOEBPF_PRELOAD_SOCKET=<sock>"]`, length 2 | [internal/keylog/preload_env.go:5-8](../../../internal/keylog/preload_env.go); [internal/keylog/preload_env_test.go:10-16](../../../internal/keylog/preload_env_test.go): `assert.Equal(t, []string{...}, got)` + `assert.Len(t, got, 2, ...)` | ✅ PASS |
| WHERE app container launched by `pod-up.sh` THEN receive the `.so` bind-mounted read-only + both env vars | App container env contains `LD_PRELOAD=` and `GOEBPF_PRELOAD_SOCKET=`, volume mounted `:ro` | [deploy/podman/pod-up.sh:118-124](../../../deploy/podman/pod-up.sh) (F03's T9, commit `81fd652`, independently re-read): `--volume "$PRELOAD_SO:/usr/local/lib/libkeylogpreload.so:ro,z"`, `--env "LD_PRELOAD=..."`, `--env "GOEBPF_PRELOAD_SOCKET=..."` all present on the app container's `podman run` | ✅ PASS (evidence at HEAD, implemented in F03's task list as spec.md's own traceability table already notes) |

**Status**: ✅ 11/12 AC rows matched the spec-defined outcome exactly; 1 pre-existing spec-precision gap flagged (KEYLOG-03, unchanged since the prior pass, not a regression). **No hard (evidence-or-zero) GAPs remain.**

---

## Discrimination Sensor

Isolated scratch: `git worktree add /tmp/scratch-verify-keylog2 HEAD` (never `git stash`).
Baseline `git status --porcelain` on the real tree was empty before and after (confirmed via a
direct check immediately before starting, and again after worktree removal).

Both mutations target the two just-fixed commits' own subject matter (the KEYLOG-08 retry
mechanism), deliberately different lines/behaviors than the prior report's 3 mutations
(`checkSocketDir` permission bypass, `preload_env.go` wrong variable, `keylog_cb` early
`return`).

| Mutation | File:line | Description | Killed? |
| -------- | --------- | ------------ | ------- |
| 1 | `preload/keylog_preload.c:31` | `KEYLOG_MAX_SEND_ATTEMPTS` `3` → `200` (200×20ms ≈ 4s per secret — a real block that should exceed the new test's 3s bound) | ✅ Killed — `TestPreload_SocketUnreachable_ClientCompletesWithoutBlocking` failed: `client did not complete within 3s; an unreachable keylog socket must never block the app` (3.13s) |
| 2 | `preload/keylog_preload.c:31` | `KEYLOG_MAX_SEND_ATTEMPTS` `3` → `0` (retry loop never executes; every line silently dropped even with a live listener) | ✅ Killed — `TestPreload_TLS13Handshake_EmitsFiveLinesWithMatchingClientRandom` and `TestPreload_TLS12Handshake_EmitsOneClientRandomLine` both failed: `timed out waiting for N line(s) ...; last content: ""` |

**Deliberately not sensor-executed**: mutating `pod-up.sh`'s socket-wait `-S` test (suggested as
a third candidate) would require actually running `podman pod create`/`podman run` as root to
observe a real kill, which this repo's own recorded convention says not to do autonomously
(rootful pod creation touches shared host cgroups/network namespaces). That fix was instead
verified by direct code re-reading (see the AC table above: sidecar-then-poll-then-app is
present, `bash -n` syntax-clean) rather than by an executed mutation. Documented here for
transparency rather than silently counted as a 3rd killed mutation.

**Sensor depth**: lightweight (2 targeted mutations, standard-tier feature; both against the
newly-fixed KEYLOG-08 code path, not a re-run of the prior report's 3)
**Result**: 2/2 killed — ✅ PASS

Cleanup: `git worktree remove --force /tmp/scratch-verify-keylog2` + `rm -rf`; orphaned
`openssl s_client` processes spawned by the mutated (blocking) interposer were confirmed to
self-terminate within their own bounded retry window (no manual kill needed); `git status
--porcelain` on the real tree confirmed identical (empty) to the pre-sensor baseline.

---

## Code Quality

| Principle        | Status |
| ---------------- | ------ |
| No features beyond what was asked | ✅ — both fix commits are exactly what the prior validation.md's Fix 1/Fix 2 asked for, nothing more |
| No abstractions for single-use code | ✅ |
| No unnecessary "flexibility" added | ✅ |
| Only touched files required for task | ✅ — `8ba51a8` touches only `deploy/podman/pod-up.sh`; `42ac87e` touches only `internal/keylog/preload_it_test.go` |
| Didn't "improve" unrelated code | ✅ |
| Matches existing patterns/style | ✅ — the new test follows the same `requirePreloadSO`/`generateSelfSignedCert`/`startOpenSSLServer` helpers as the other 5 T5 tests |
| Would senior engineer approve? | ✅ |
| Tests map to acceptance criteria and are non-shallow (spot-check one story) | ✅ — spot-checked the new KEYLOG-08 test: it doesn't just assert "no error", it races a 3s timeout against a real blocked handshake path, which the sensor confirmed actually discriminates |
| Spec-anchored outcome check (asserted values match spec) | ✅ — 11/12 rows exact-match; 1 pre-existing, unchanged spec-precision gap (KEYLOG-03) |
| Per-layer Coverage Expectation met (domain 1:1 ACs; routes happy+edge+error) | ✅ — the transport story now has happy (well-formed), error (malformed), and edge (unreachable-socket, mid-line-close, world-writable-dir) coverage |
| Every test maps to a spec requirement — no unclaimed tests | ✅ |
| Documented project quality/testing guidelines followed | ✅ — `AGENTS.md` (Makefile targets, `testify`, `integration` build tag); new test uses `require`/`assert`/`t.TempDir()` per convention |

---

## Edge Cases

- [x] Plain-TCP (non-TLS) traffic emits no keylog lines — `TestPreload_PlainTCPTraffic_EmitsNoLines`
- [x] Static/non-OpenSSL binary — no crash, no lines — `TestPreload_NonOpenSSLBinary_NoCrashNoLines`
- [x] Connection closes mid-line does not corrupt the keylog — `TestSocketServer_ConnectionClosesMidLine_NoCorruption`
- [x] **Unreachable socket at the app's first handshake never blocks the app** — `TestPreload_SocketUnreachable_ClientCompletesWithoutBlocking` (new; closes the prior gap) — sensor-confirmed discriminating
- [x] **Sidecar-before-app startup ordering** — `deploy/podman/pod-up.sh`'s reordering + socket-file poll (re-derived independently above; closes the prior gap)
- [ ] Concurrent lines from multiple connections/secrets serialised via the reused `Writer` — no *new* test in this diff exercises concurrency through the socket server specifically (unchanged thin spot from the prior pass; the reused `Writer`'s own concurrency test covers the writer layer, not the socket-server→writer path under concurrent connections) — acceptable, mechanism unchanged, not a new gap

---

## Gate Check

- **Gate command**: `make build && go test -race -tags=integration ./...`
- **Result**: `make build` (fmt+vet+build) green, exit 0. Full suite: all 7 packages `ok`, 0 failed. `internal/keylog`: all 6 integration tests **PASS** (none skipped), confirmed via `-v` (including the new `TestPreload_SocketUnreachable_ClientCompletesWithoutBlocking`, 0.48s). `cmd/app`'s 2 integration tests **skip** (pre-existing `CAP_BPF`/`bpffs` precondition, unrelated to this feature — same as the prior pass).
- **Test count before feature** (`de39250`): 86
- **Test count at end of the original T1-T7 batch** (`2bc20ed`): 72 (established by the prior validation pass, independently re-confirmed here by the same arithmetic: −24 deleted uprobe-era tests + 10 new)
- **Test count at this re-verification's endpoint** (`42ac87e` / current HEAD): 73 top-level `func Test` across the repo (confirmed via `grep -rn '^func Test'`)
- **Delta from `2bc20ed` to `42ac87e`**: +1 (`TestPreload_SocketUnreachable_ClientCompletesWithoutBlocking`); the 3 intervening Feature-03-Phase-4 commits (`81fd652`/`c0d0c81`/`c80fc52`) touch `deploy/podman/pod-up.sh`, `deploy/podman/pod_e2e_test.go` (assertion updates within the existing test, no new/removed top-level test funcs), and `README.md` respectively — net zero additional test-count change from that out-of-scope batch, confirmed by the arithmetic reconciling cleanly (72 + 1 = 73)
- **Skipped tests**: `cmd/app/app_it_test.go`'s 2 tests (need `CAP_BPF`/mounted `bpffs`+`cgroupfs`) — pre-existing precondition, justified, unchanged from the prior pass
- **Failures**: none
- **golangci-lint**: not installed in this sandbox (pre-existing environment gap per the task brief, not scored against this feature)

---

## Fix Plans (if issues found)

None required. Both fix items from the prior validation pass are resolved and independently
re-confirmed:

- **Prior Fix 1 (KEYLOG-05 ordering)**: resolved by `8ba51a8`. Independently re-derived above
  from the actual `pod-up.sh` diff (not merely trusted from the commit message) — sidecar starts
  first, the script polls the shared volume's host-visible mountpoint for the bound socket file,
  and only then starts the app container.
- **Prior Fix 2 (KEYLOG-08 test coverage)**: resolved by `42ac87e`. Independently re-run (passes
  in 0.48s) and independently sensor-tested (a mutation that would cause a real 4s-per-secret
  block is killed by this exact test within its 3s bound).

---

## Requirement Traceability Update

| Requirement | Previous Status (spec.md, pre-re-verification) | Verifier's independent status |
| ----------- | ------------------------------------------------ | ------------------------------ |
| KEYLOG-01 | Verified | ✅ Confirmed |
| KEYLOG-02 | Verified | ✅ Confirmed |
| KEYLOG-03 | Verified | ⚠️ Spec-precision gap (code-shape evidenced only; unchanged from the prior pass — spec.md's "Verified" here is optimistic but not newly wrong) |
| KEYLOG-04 | Verified | ✅ Confirmed |
| KEYLOG-05 | Verified | ✅ Confirmed — independently re-derived from `pod-up.sh`'s actual diff (`8ba51a8`), not just trusted from the traceability table |
| KEYLOG-06 | Verified | ✅ Confirmed |
| KEYLOG-07 | Verified | ✅ Confirmed |
| KEYLOG-08 | Verified | ✅ Confirmed — the traceability table's "Verified" claim IS now justified: a real integration test exists, passes, and was shown by the sensor to actually discriminate a genuine block, not just exist |
| KEYLOG-09 | Verified | ✅ Confirmed |
| KEYLOG-10 | Verified | ✅ Confirmed |
| KEYLOG-11 | Verified | ✅ Confirmed — independently re-read `pod-up.sh` at HEAD (F03's T9, commit `81fd652`): both env vars and the `:ro` mount are present on the app container |

---

## Summary

**Overall**: ✅ Ready

**Spec-anchored check**: 11/12 AC rows matched the spec-defined outcome exactly; 1
pre-existing, unchanged spec-precision gap (KEYLOG-03 — code-shape only, no runtime test that
would fail if handshake/cert-validation behavior were touched)
**Sensor**: 2/2 mutations killed (both targeting the newly-fixed KEYLOG-08 retry mechanism; a
3rd candidate mutation on `pod-up.sh` was deliberately not executed for host-safety reasons and
was instead confirmed by direct code re-reading)
**Gate**: all 7 packages passed, 0 failed, 2 skipped (justified, pre-existing, unrelated to this
feature)

**What works**: Both gaps from the prior verification pass are genuinely closed, not just
paperwork-closed. KEYLOG-05's ordering fix was re-derived directly from `pod-up.sh`'s diff
(sidecar starts, polls for the bound socket file, then starts the app) rather than trusted from
the commit message or spec.md's table. KEYLOG-08's new test was re-run (passes, 0.48s) and,
critically, was verified by the discrimination sensor to actually catch a real block — a
mutation that would make the interposer block for ~20s (200 retries × 20ms) fails the test
within its 3s bound, proving the test doesn't just exist but discriminates. The rest of the
feature (interposer↔socket↔writer pipeline, dedup/reject/permission-guard behavior) is
unchanged and remains solid, matching the prior pass's findings.

**Issues found**: None blocking. One pre-existing spec-precision gap remains (KEYLOG-03 — "leaves
handshake/cert-validation unmodified" has no runtime test that would fail if that invariant were
broken, only a code-inspection citation). This is unchanged since the prior pass, already
tracked as lesson `L-005`, and does not block a PASS verdict per validate.md's rules
(spec-precision gaps are flagged, not scored as failures).

**Next steps**: None required to close this feature. KEYLOG-03's spec-precision gap remains a
candidate for a future task (e.g. an integration test that intentionally breaks cert validation
and asserts the interposer didn't cause it) but is not a blocking gap for this feature's
completion.

---

## 2026-09-18 — Independent revalidation (fresh Verifier, author ≠ verifier)

- **Verdict: PASS.** Coverage re-derived independently (evidence-or-zero).
- **Spec drift check**: none — `spec.md` accurately reflects the AD-010 LD_PRELOAD interposer + Unix-socket mechanism (carries the explicit AD-010 revision note; dir name `02-uprobe-keylog` deliberately kept). Verified all AD-010 removals: `discovery.go`/`event.go`/`consumer.go`/`openssl_offsets.go`/`gotls.go`/`bpf/tls_keylog.bpf.c` gone; zero uprobe/`bpf_probe_read`/ringbuf/offset residue in non-test `internal/keylog`.
- **Deterministic gates**: 0 errors. `make lint` 0 issues. Unit suite green; C-interposer integration layer (KEYLOG-01/02/03/04/08) skips without clang/libssl — inherent to an `LD_PRELOAD` library, disclosed, tests exist and are well-formed.
- **Discrimination sensor** (unit layers, restored from scratch — no `git stash`): 3/3 killed — NSS client_random length check removed (killed by `TestValidateLine_RejectsMalformed`), writer mode `0600→0644` (killed by `TestWriter_ModesAndAppend`), preload env var name change (killed by `TestPreloadEnv_ExactlyTwoExpectedVars`).
- **Confirmed residual (unchanged, non-blocking)**: KEYLOG-03 (handshake/cert untouched) is code-shape evidenced only, not runtime-tested (tracked as lesson `L-005`); dir-guard negative test covers only `0o777`, not a read-only-bit permutation (logic is correct).
- Real tree returned to baseline (` M .gitignore` only).

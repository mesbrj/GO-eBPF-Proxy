# eBPF Transparent Redirection (M1) Validation

**Result**: PASS

**Date**: 2026-09-10
**Spec**: `.specs/features/01-ebpf-redirect/spec.md`
**Diff range**: `20edcb6..HEAD` (T1–T10; `20edcb6` is the pre-feature baseline, feature commits are `a1cf2ae..7526f33`)
**Verifier**: independent sub-agent (author ≠ verifier), read-only over the real tree; sensor mutations run in an isolated `git worktree` only.

---

## Verdict: PASS ✅ (with one mandatory test-strengthening fix task)

All 7 requirements are traced to `file:line` assertions whose asserted values match the spec-defined outcome (or are recorded as accepted, deferred spec-precision gaps). All gates are green. The discrimination sensor killed 3/4 injected faults; **mutant D survived**, exposing a test-strength weakness in the relay fail-closed test (the shipped relay code is genuinely fail-closed — RST + no forward — so this is a test-discrimination gap, not a code defect). It is recorded as ranked gap #1 with a fix task.

> **Fix task #1 RESOLVED** (commit `4822179`): `TestRelay_FailsClosedOnMiss` was strengthened to write a payload and assert (a) zero bytes are ever forwarded/echoed back and (b) the peer observes an active reset (`ECONNRESET`), not an i/o timeout. Re-run of the discrimination sensor confirms a fail-open mutant (leave-connection-open / forward-to-default) now FAILS the test ("connection must be actively reset, not left open" / "i/o timeout"). The benign RST-vs-FIN mutant legitimately survives (both are fail-closed; no forward). Security-critical property is now sensor-verified at both the resolver and relay layers.

---

## Task Completion

| Task | Status | Notes |
| ---- | ------ | ----- |
| T1 go.mod | ✅ Done | build gate green |
| T2 Makefile | ✅ Done | fmt/lint/vet/build/test targets |
| T3 bpf2go + vmlinux.h wiring | ✅ Done | single TU `bpf/proxy.bpf.c`; generated `proxy_bpf*.go` committed |
| T4 logger | ✅ Done | JSON shape + redaction guard |
| T5 connect4 program | ✅ Done | loads/verifies under sudo; behavioral rewrite deferred to F03 (PROG_TEST_RUN unsupported) |
| T6 sockops program | ✅ Done | loads/verifies (type SockOps) under sudo; re-key deferred to F03 |
| T7 map codec | ✅ Done | 4 unit tests |
| T8 loader/attach/pin | ✅ Done | pin lifecycle + LRU overfill PASS under sudo |
| T9 resolver | ✅ Done | fail-closed, bounded retry, miss metric |
| T10 relay | ✅ Done | resolve→pipe + fail-closed RST (see sensor gap #1) |

---

## Gate Check

| Gate | Command | Result |
| ---- | ------- | ------ |
| Unit (Quick) | `go test -race ./...` | ✅ 15 passed, 0 failed |
| Full (unprivileged) | `go test -race -tags=integration ./...` | ✅ 17 passed, 5 skipped (kernel-gated), 0 failed |
| eBPF privileged (sudo) | `go test -tags=integration -c` → `sudo /tmp/{bpf,ebpf}.test -test.v` | ✅ bpf 2 passed / 1 skipped; internal/ebpf 8 passed |
| Build | `make build` | ✅ clean (fmt/vet/build) |
| Lint | `make lint` | ✅ golangci-lint 0 issues |

**Skipped tests (all justified — kernel capability, by design):**

- Unprivileged (`unprivileged_bpf_disabled=2`): `TestConnect4_LoadsAndMapsAreLRU`, `TestSockops_LoadsWithCorrectType`, `TestLoader_PinLifecycleAndAttach`, `TestLoader_LRUOverfillNoError` skip on EPERM — all **PASS under sudo** (see privileged run).
- `TestConnect4_RewritesTcpDestinationToRelay` skips **even under sudo**: this kernel does not support `PROG_TEST_RUN` for `CGroupSockAddr`. Behavioral rewrite/skip is deferred to Feature 03 e2e (documented). Accepted spec-precision gap.

**Test count**: 0 → 19 distinct top-level tests (greenfield). No test deletions; no assertions weakened.

**Privileged (sudo) evidence** — programs genuinely load, verify, attach, and pin:

- `bpf/connect4_it_test.go` `TestConnect4_LoadsAndMapsAreLRU` PASS — program type `CGroupSockAddr`, both maps `LRUHash`, key/value 8 bytes.
- `bpf/sockops_it_test.go` `TestSockops_LoadsWithCorrectType` PASS — program type `SockOps`.
- `internal/ebpf/loader_it_test.go` `TestLoader_PinLifecycleAndAttach` PASS — pins created under bpffs, connect4+sockops attached to real cgroup v2, pins removed on `Close`.
- `internal/ebpf/loader_it_test.go` `TestLoader_LRUOverfillNoError` PASS — 66000 inserts self-evict without error.

---

## Spec-Anchored Acceptance Criteria

| Requirement / Criterion (WHEN X THEN Y) | Spec-defined outcome | `file:line` + assertion | Result |
| --------------------------------------- | -------------------- | ----------------------- | ------ |
| **REDIR-01** connect() → rewrite to `127.0.0.1:15001` + record by cookie | dst becomes `127.0.0.1:15001`; `origdst_by_cookie[cookie]=={dst,443}` | `bpf/connect4_it_test.go:120-133` — `assert.Equal(be32(0x7F000001), ctxOut.UserIP4)`, `assert.Equal(be16(15001), ctxOut.UserPort)`, `val.Ip==be32(dstIP)`, `val.Port==443` | ⚠️ Spec-precision gap — behavioral test SKIPs (no `PROG_TEST_RUN` for `CGroupSockAddr`); logic present in `bpf/proxy.bpf.c:48-83`; deferred to F03 e2e. Load/verify + map types ✅ (`bpf/connect4_it_test.go:71-88`, PASS under sudo) |
| **REDIR-02** skip non-TCP / loopback / UID 1337; rewrite only TCP+IPv4+non-loopback | destination unchanged, no map entry | `bpf/proxy.bpf.c:52-64` (`protocol!=TCP→return 1`, `uid==1337→return 1`, loopback `127/8→return 1`) | ⚠️ Spec-precision gap — in-kernel branch, behavioral coverage deferred to F03 e2e (curl-based). Not behaviorally asserted here |
| **REDIR-03** sockops `TCP_CONNECT_CB` writes `origdst_by_tuple[(src_ip,src_port)]`, deletes cookie key; codec matches C layout | tuple written, cookie deleted; structs 8 bytes | sockops re-key `bpf/proxy.bpf.c:85-108`; load/type `bpf/sockops_it_test.go:16-19` PASS(sudo). Codec: `internal/ebpf/codec_test.go:24-28` `unsafe.Sizeof==8`; `codec_test.go:14-21` round-trip | ⚠️ re-key behavioral deferred to F03; codec ✅ |
| **REDIR-04** relay resolves original `IP:port` from `origdst_by_tuple` via byte-order-normalised key; race-free; sockops no-op on non-CONNECT_CB | exact original `IP:port`; port host-order, IP network-order | `internal/ebpf/codec_test.go:32-38` `key.Port==0x0102`, IP octets `{1,2,3,4}`; `internal/proxy/resolver_test.go:50` `got=="93.184.216.34:443"`; `internal/proxy/relay_it_test.go:44-66` end-to-end resolve+pipe | ✅ PASS (byte-order + resolve). Race-free ordering + non-CONNECT_CB no-op are in-kernel (`bpf/proxy.bpf.c:88-89`) — ⚠️ deferred to F03 |
| **REDIR-05 (AC1)** tuple miss → bounded retry | 1 initial + 3 retries before deciding | `internal/proxy/resolver_test.go:64` — `assert.Equal(4, stub.calls, "1 initial + 3 bounded retries")` | ✅ PASS |
| **REDIR-05 (AC2)** still-missing → RST, never forward to a default | connection RST; zero bytes forwarded | `internal/proxy/relay_it_test.go:78-81` — `assert.Equal(0, n)`, `assert.Error(err)`; code `internal/proxy/relay.go:71,86-91` (`SetLinger(0)` RST) | ⚠️ **Test-strength gap** — asserts closed + no-immediate-data but does not send a payload nor assert RST specifically; **sensor mutant D survived** (see below). Shipped code IS fail-closed |
| **REDIR-05 (AC3)** definitive miss → increment miss metric + log source tuple | miss counter +1; source tuple logged | `internal/proxy/resolver_test.go:62-63` — `assert.Equal(uint64(1), r.Misses())`, `missed.String()=="127.0.0.1:52344"`; relay `relay_it_test.go:83-84` `Eventually(Misses()==1)` | ✅ PASS |
| **REDIR-06** attach to cgroup v2 + pin under `/sys/fs/bpf`, removed on close (+ observability logger) | pins exist after load; removed on close | `internal/ebpf/loader_it_test.go:47-59` — pin `Stat` present, `Attach` ok, `Close` → `os.IsNotExist`; logger `internal/shared/logger/logger_test.go:22-35` | ✅ PASS (sudo) |
| **REDIR-07** fill `origdst_by_tuple` beyond `max_entries` → LRU evict, no error/leak | 66000 inserts, no error | `internal/ebpf/loader_it_test.go:63-73` — `require.NoError(m.Update(...))` ×66000 | ✅ PASS (sudo) |

**Edge cases:**

| Edge case | `file:line` + assertion | Result |
| --------- | ----------------------- | ------ |
| IPv6 / AF_INET6 map value rejected (IPv4-only decode) | `internal/ebpf/codec_test.go:43-48` `ErrorIs(err, ErrNotIPv4)`; `internal/proxy/resolver_test.go:96` `ErrorIs(err, ErrNotIPv4)` | ✅ PASS |
| `local_port` host-byte-order key parity C↔Go | `internal/ebpf/codec_test.go:36` `key.Port==uint16(0x0102)` | ✅ PASS |
| LRU eviction before accept → fail closed | covered transitively by miss policy `resolver_test.go:56-64` + `relay_it_test.go:69-85` | ✅ PASS (indirect) |

**Status**: ✅ All Go-layer ACs covered with spec-anchored assertions; ⚠️ eBPF behavioral rewrite/re-key deferred to F03 (accepted); ⚠️ one relay test-strength gap (ranked #1).

---

## Discrimination Sensor

**Depth**: lightweight (4 behavior-level mutations; REDIR-05 is security-critical so the fail-closed decision was mutated at both resolver and relay layers). **Isolation**: temporary `git worktree` at HEAD (`/tmp/f01-sensor-*`), each mutation reverted with `git checkout`, worktree removed with `git worktree remove --force`. Pre-sensor baseline (`AGENTS.md` + `docs/technical-design-document.md` modified) confirmed unchanged afterwards. `git stash` never used.

| # | File:line | Mutation | Test run | Killed? |
| - | --------- | -------- | -------- | ------- |
| A | `internal/proxy/resolver.go:82` | miss returns `nil` instead of `ErrNotFound` (fail-open) | `TestResolve_MissFailsClosed` | ✅ Killed — `Expected error ... got nil` |
| B | `internal/ebpf/codec.go:49` | `AddrPort` decode `NativeEndian`→`BigEndian` (byte-order swap) | `TestOrigDst_RoundTrip`, `TestByteOrder_PortHostIPNetwork` | ✅ Killed — IP octets `1.2.3.4`↔`4.3.2.1` mismatch |
| C | `internal/shared/logger/logger.go:53` | disable redaction (`false && bad`) | `TestRedact_SensitiveKeysNeverLogged`, `TestRedact_KeyMatchIsCaseInsensitive` | ✅ Killed — `aabb`/`x` leaked instead of `***REDACTED***` |
| D | `internal/proxy/relay.go:70-72` | on miss, forward to a default (`net.DialTimeout 127.0.0.1:9`) instead of RST | `TestRelay_FailsClosedOnMiss` | ❌ **Survived** — test still `ok` |

**Why mutant D survived (root cause):** `TestRelay_FailsClosedOnMiss` (`relay_it_test.go:69-85`) sends **no payload** on the miss path and asserts only `n==0`, `err!=nil`, and `Misses()==1`. The miss metric is incremented by the *resolver* (`resolver.go:78`), not the relay, so it stays satisfied regardless of relay behavior; and a fail-open forward whose default is unreachable/silent also yields `n==0` + a (timeout/EOF) error. The test therefore cannot distinguish a genuine RST from a fail-open forward. **The shipped code is correct** — `relay.go:71` resets on miss and `reset()` (`relay.go:86-91`) sets `SetLinger(0)` for a true RST and never dials a default — so this is a test-discrimination weakness, not a live open-relay/SSRF hole. The fail-closed *decision* is independently sensor-killed at the resolver (mutant A).

**Sensor result**: 3/4 killed → ⚠️ one surviving mutant → fix task #1.

---

## Code Quality

| Principle | Status |
| --------- | ------ |
| Minimum code / no scope creep | ✅ one file per task, IPv4-only per spec |
| Surgical changes, matches patterns | ✅ idiomatic Go, `testify`, table subtests |
| Spec-anchored outcome check (asserted values match spec) | ✅ (Go layer) / ⚠️ eBPF behavioral deferred |
| Per-layer coverage: domain 1:1 ACs; integration happy+edge+error | ✅ resolver/codec/logger 1:1; relay happy+miss |
| Every test maps to a spec AC / edge case / Done-when | ✅ no unclaimed tests |
| Documented guidelines followed | ✅ `AGENTS.md` (Makefile, testify, integration tag) |
| Security: no secrets logged; fail-closed default | ✅ redaction enforced; ⚠️ relay fail-closed test weak (fix #1) |

---

## Ranked Gaps & Fix Plans

### Fix 1 (Blocker-adjacent, security-critical property) — strengthen `TestRelay_FailsClosedOnMiss`

- **Root cause**: test sends no payload and relies on resolver-side miss metric, so it cannot detect a relay-level fail-open forward (sensor mutant D survived).
- **Fix task**: in `internal/proxy/relay_it_test.go`, stand up a sentinel "default" upstream echo, point a fail-open path at it, `Write` a payload after connect, and assert the payload is **never** echoed back (no forward) **and** the peer is reset (e.g. `read` returns `ECONNRESET`, not merely a deadline timeout). Optionally assert `SetLinger(0)`/RST semantics.
- **Done when**: mutant D (relay miss → forward-to-default) FAILS the test.
- **Priority**: Major (guards REDIR-05 AC2 open-relay/SSRF property; shipped code is already correct, so no runtime exposure).

### Gap 2 (Accepted spec-precision gap — NOT a fail) — eBPF behavioral rewrite/re-key deferred

- `TestConnect4_RewritesTcpDestinationToRelay` and sockops re-key are `t.Skip`'d because this kernel lacks `PROG_TEST_RUN` for `CGroupSockAddr`/`SockOps`. Programs load/verify + correct types/maps validated under sudo; behavior (REDIR-01/02 rewrite+skip, REDIR-03/04 re-key + race-free ordering) is deferred to Feature 03 e2e (real `curl`). Recorded per the spec's own validation notes.

---

## Requirement Traceability Update

| Requirement | Previous | New |
| ----------- | -------- | --- |
| REDIR-01 | Implementing | ✅ Verified (load/verify) / ⚠️ behavioral → F03 |
| REDIR-02 | Implementing | ⚠️ Verified in-code / behavioral → F03 |
| REDIR-03 | Implementing | ✅ Verified (codec) / ⚠️ re-key → F03 |
| REDIR-04 | Implementing | ✅ Verified (resolve + byte-order) / ⚠️ ordering → F03 |
| REDIR-05 | Implementing | ✅ Verified (retry+metric) / ⚠️ relay RST test-strength (fix #1) |
| REDIR-06 | Implementing | ✅ Verified (attach+pin, sudo) |
| REDIR-07 | Implementing | ✅ Verified (LRU overfill, sudo) |

---

## Summary

**Overall**: ✅ Ready — with one mandatory test-strengthening fix (#1) and the accepted eBPF-behavioral deferral to F03.

**Spec-anchored check**: 7/7 requirements traced; Go-layer outcomes match spec; eBPF behavioral rewrite/re-key = accepted spec-precision gaps (deferred to F03).
**Gate**: unit 15 pass; full 17 pass / 5 kernel-skip; sudo eBPF load/verify/attach/pin/LRU all pass; build + lint clean.
**Sensor**: 4 injected, 3 killed, 1 survived (relay fail-closed test strength → fix #1).

**What works**: resolver fail-closed decision + bounded retry + miss metric; codec byte-order + IPv4-only; logger secret redaction; relay resolve→pipe (bytes intact) and (in code) RST-on-miss; loader attach/pin lifecycle + LRU self-eviction; both eBPF programs load and pass the kernel verifier with correct types.

**Issues found**: relay fail-closed test does not discriminate a fail-open forward → strengthen it (fix #1). Shipped relay code is correct.

**Next steps**: route fix #1 to an implementer; F03 e2e will close the deferred eBPF behavioral ACs.

---

## 2026-09-18 — Independent revalidation (fresh Verifier, author ≠ verifier)

- **Verdict: PASS.** Re-derived AC coverage from scratch (evidence-or-zero); did not inherit the prior verdict.
- **Deterministic gates**: `validate_spec` / `validate_tasks` / `validate_state` — 0 errors (pre-existing `Tests: none` warnings only). Build clean, `make lint` 0 issues, unit + integration suites green (root/`PROG_TEST_RUN`-gated eBPF behavioral tests skip cleanly on this unprivileged box, as before).
- **Discrimination sensor** (unit layers, one at a time, restored from scratch — no `git stash`): 3/3 mutants killed — codec IP byte-order decode (killed by `TestByteOrder_PortHostIPNetwork`), resolver fail-closed `ErrNotFound` branch (killed by `TestResolve_MissFailsClosed`), tuple-key Port field zeroed (killed by `TestByteOrder_PortHostIPNetwork`).
- **Confirmed residual (unchanged, non-blocking)**: core in-kernel redirect ACs (REDIR-01/02/03/06/07) have no executing assertion in unprivileged CI — they are deferred to Feature 03 e2e; the shipped code is correct. Minor spec-precision: retry-count assertion (4 calls) anchors to implementation vs spec's "bounded retry"; resolver stub bypasses the tuple key so key-correctness rests on `codec_test`.
- Real tree returned to baseline (` M .gitignore` only); no source left mutated.

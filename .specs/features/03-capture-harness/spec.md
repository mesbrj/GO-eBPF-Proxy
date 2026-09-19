# Capture & Offline Decryption Validation Specification

**Feature dir**: `.specs/features/03-capture-harness/`
**Milestone**: M3 — Capture harness
**Source**: [PRD Feature 03](../../../docs/prd/feature-03.md), [TDD](../../../docs/technical-design-document.md)

## Problem Statement

> **Revision note (2026-09-12, AD-010)**: the Podman harness (P2 stories below) originally
> assumed Feature 02's uprobe mechanism (shared PID namespace, `CAP_PERFMON`, uprobe attach to
> the app's `libssl`). AD-010 replaced that with an `LD_PRELOAD` interposer; this feature's
> Phase 4 addendum (`tasks.md`) rewired `deploy/podman/pod-up.sh`/`pod_e2e_test.go` accordingly
> and `validation.md`'s Phase 4 re-verification confirms it. The AC text and Assumptions table
> below are updated to match; Phases 1-2 (capture/retention/pairing) are entirely unaffected.

The intercepted TLS egress and the interposer-extracted keys must be turned into a repeatable
"capture → decrypt → inspect" workflow, and the whole system must come up with one command on a
single host. Capture artifacts are plaintext-equivalent secrets, so they must be handled and
retained safely, and the pod must bring up the eBPF redirect programs, the LD_PRELOAD keylog
interposer, and the relay reproducibly.

## Goals

- [x] Capture the outbound leg to pcapng and pair it with the NSS keylog so tshark decrypts it offline.
- [x] Handle keylog and capture as plaintext-equivalent secrets with bounded, ephemeral-by-default retention.
- [x] Bring the whole sidecar+app pod up with one command and prove it end-to-end with a real-cert `curl`.

## Out of Scope

Explicitly excluded. Documented to prevent scope creep.

| Feature | Reason |
| ------- | ------ |
| Production Kubernetes manifests / multi-host | MVP is a single-host rootful Podman dev harness |
| Shipping secret artifacts to APM/observability | AD-006: only operational telemetry leaves the host |
| pcapng → IPFIX/flow conversion & DPI | Post-MVP (`internal/convert`, `internal/analisys`) |
| Governed encrypted artifact store / RBAC | Post-MVP; MVP uses a local host-mapped path |

---

## Assumptions & Open Questions

Every ambiguity is resolved or recorded here — nothing is left silently unclear.

| Assumption / decision | Chosen default | Rationale | Confirmed? |
| --------------------- | -------------- | --------- | ---------- |
| Capture backend | In-process gopacket pcapng + embedded DSB (default); `tcpdump` fallback/parity | AD-005: DSB self-decrypts; pure-Go avoids external dep | y |
| Capture/keylog modes | DSB-embedded single file, plus a `pcap + separate keylog` split mode | AD-005: split keeps ciphertext and secrets separable | y |
| Artifact permissions | `0600` files, `0700` dir, owner UID 1337; keylog on tmpfs | AD-006: plaintext-equivalent secrets | y |
| Retention | Bounded size cap AND age cap with rotation; ephemeral by default; `--retain` to keep | AD-006: avoids standing liability / disk exhaustion | y |
| Timestamp source | Single clock shared by capture and keylog writers | Misaligned timestamps break tshark decryption | y |
| Pod namespaces | Rootful pod: shared netns + host cgroup ns (`--cgroupns=host`); no shared PID ns | AD-010: the LD_PRELOAD interposer needs no PID resolution (uprobe-attach-only requirement, dropped); cgroup attach still needs host cgroup ns | y |
| Smoke test | `curl https://example.com` from the app container, no `-k` | Validates the real server cert end-to-end (no MITM) | y |

**Open questions:** none — all resolved or logged above.

---

## User Stories

### P1: Outbound capture to pcapng ⭐ MVP

**User Story**: As a security engineer, I want the relay's outbound leg captured to a valid pcapng, so that I have the ciphertext to decrypt.

**Why P1**: Without a valid capture there is nothing to decrypt.

**Acceptance Criteria** (each line is one EARS pattern):

1. WHEN capture is running THEN the system SHALL write a valid pcapng (SHB/IDB/EPB stream) re-readable by gopacket with the correct link type and preserved packet bytes, **and the file SHALL be readable on disk while the sidecar is still running, not only after teardown** (Revision note, 2026-09-17: a live rootful run surfaced that the writer's internal buffering left `dump.pcapng` at 0 bytes for an entire session; fixed by flushing after every packet and after the initial header — see AD-011).
2. WHEN writing capture and keylog records THEN the system SHALL source timestamps from the same monotonic clock within tolerance.
3. WHERE the `tcpdump` backend is selected the system SHALL produce a capture that decrypts to identical application data as the gopacket backend.

**Independent Test**: Run the pcapng writer over a known packet stream; assert gopacket re-reads it with correct link type and bytes; assert capture/keylog timestamps share one clock.

---

### P1: Offline decryption pairing ⭐ MVP

**User Story**: As a security engineer, I want the capture paired with the keylog so tshark shows plaintext, so that I can inspect the app's encrypted egress.

**Why P1**: This is the feature's headline acceptance criterion.

**Acceptance Criteria**:

1. WHEN `tshark -r dump.pcapng -o "tls.keylog_file:sslkeylog.log" -o tcp.reassemble_out_of_order:TRUE -Y 'http or http2' -V` is run over a real TLS 1.3 flow THEN the system SHALL show decrypted HTTP application data (Revision note, 2026-09-19: this criterion was written as `-Y http`, which never matches the HTTP/2 the app's `curl` negotiates over ALPN, and without out-of-order TCP reassembly, which real container-egress captures need — see AD-014).
2. IF the keylog clock is skewed outside the capture window THEN decryption SHALL fail (guarding the timestamp-alignment invariant).
3. WHEN emitting the pairing invocation THEN the system SHALL produce the correct `-o tls.keylog_file:<path>` argument.

**Independent Test**: Capture a real TLS 1.3 flow via the relay, emit the keylog, run the tshark pairing; assert decrypted HTTP application data is present; assert a skewed keylog fails to decrypt.

---

### P1: Secret-grade retention & cleanup ⭐ MVP

**User Story**: As a security engineer, I want capture/keylog artifacts treated as secrets and bounded, so that plaintext-equivalent material does not leak or grow unbounded.

**Why P1**: The artifacts decrypt all captured TLS; unsafe handling is a security failure.

**Acceptance Criteria**:

1. WHEN an artifact is created THEN the system SHALL create it `0600` in a `0700` directory owned by UID 1337.
2. IF a size cap OR an age cap is reached THEN the system SHALL rotate/evict oldest-first so the footprint stays bounded.
3. WHEN the pod is torn down without `--retain` THEN the system SHALL wipe `/var/log/sidecar`.
4. WHERE `--retain` is set the system SHALL preserve the artifacts.
5. IF the write target is world-accessible THEN the system SHALL refuse to write.

**Independent Test**: Exercise the writer/retention logic; assert modes are `0600`/`0700`, size+age caps rotate oldest-first, `--retain` disables purge, and a world-accessible target is refused.

---

### P2: Rootful Podman dev harness

**User Story**: As a developer, I want one command to bring up the app+sidecar pod correctly, so that the environment is reproducible.

**Why P2**: Essential for real e2e, but the capture/decrypt units are provable without the full pod.

**Acceptance Criteria**:

1. WHEN `deploy/podman` brings up the pod THEN the system SHALL start a rootful pod with host cgroup ns, sidecar caps `CAP_BPF`+`CAP_NET_ADMIN`+`CAP_SYS_RESOURCE`+`CAP_NET_RAW` (after `--cap-drop ALL`), and `/sys/fs/bpf`+`/sys/fs/cgroup` mounts (no shared PID ns — AD-010 dropped the uprobe-attach-only requirement).
2. WHEN the pod is healthy THEN the system SHALL have `connect4`/`sockops` attached at the pod parent cgroup, maps pinned, and the app container launched with the `LD_PRELOAD` keylog interposer wired (`.so` mounted, `LD_PRELOAD`/`GOEBPF_PRELOAD_SOCKET` env vars set).
3. WHILE the sidecar generates its own egress under UID 1337 the system SHALL NOT re-intercept it (no self-loop).

**Independent Test**: Bring up the pod via the scripts; assert containers healthy, programs attached at the parent cgroup, maps pinned, the app container's `LD_PRELOAD` env wiring present, and no self-loop in logs.

---

### P2: End-to-end real-cert smoke test

**User Story**: As a developer, I want a `curl https://example.com` smoke test through the relay, so that I can prove the whole pipeline in one shot.

**Why P2**: The definitive end-to-end proof, gated behind the harness (P2).

**Acceptance Criteria**:

1. WHEN `curl https://example.com` runs in the app container without `-k` THEN the system SHALL validate the real server certificate and return HTTP 200 end-to-end.
2. WHEN the smoke test runs THEN the system SHALL log the correct original destination and SHALL grow `dump.pcapng` and `sslkeylog.log`.
3. WHEN offline validation runs over the produced artifacts THEN the system SHALL yield the request's plaintext HTTP.

**Independent Test**: `podman exec app curl https://example.com`; assert 200, correct orig-dst logged, artifacts grow, and the offline tshark decode yields the plaintext request.

---

## Edge Cases

- IF capture starts before the keylog directory exists THEN the system SHALL create the directory with `0700` before writing.
- WHEN both DSB-embedded and split modes are requested THEN the system SHALL treat DSB as the default and split as an explicit opt-in. **Descoped from the MVP** (2026-09-12): only the DSB-embedded mode is implemented; the split (`pcap` + separate keylog) mode has no code path in `internal/capture`/`cmd/app` and is deferred to a follow-on feature. Tracked as a Verifier finding, not a regression.
- IF `tcpdump` is unavailable THEN the system SHALL fall back to the in-process gopacket backend.

---

## Known Limitations

Both remaining limitations are **host-side**: neither is a defect in this codebase, and neither
can be fixed from within it. No code-side limitation is currently open.

| # | Limitation | Nature | Handling |
| - | ---------- | ------ | -------- |
| REDIR-01/02 (F01) | `BPF_PROG_TEST_RUN` for `cgroup/connect4` is unsupported on **this host's** kernel (`7.0.0-31-generic`). The claim is scoped to the one host it was observed on — it has not been surveyed across kernel versions, and the test itself says only "unsupported here" (`bpf/connect4_it_test.go:109`) | **Host-side** (kernel feature gap) | Behavioural test skips; the rewrite is proven by the Podman e2e suite instead |
| CAPTURE-03 | This host's `tcpdump` runs under an AppArmor profile that denies signal delivery from another process, even as root | **Host-side** (security policy) | Parity test skips cleanly on that specific condition (AD-012) |

**Resolved — CAPTURE-04 (2026-09-19, AD-014).** This table previously carried a code-side
CAPTURE-04 row: "the in-process gopacket backend can lose TCP segments during a real TLS
handshake/response burst", handled by a 5×-retry-then-`t.Skip` and said to need a mmap'd
AF_PACKET ring (AD-012). That diagnosis was wrong — no segments were being lost. Three real
causes were found and fixed: an ALPN-blind `-Y http` display filter against an HTTP/2 session; a
Decryption Secrets Block emitted as the capture's **last** block, which tshark's sequential
reader reaches only after the packets it should decrypt; and tshark's out-of-order TCP
reassembly being off by default while roughly a third of real sessions record their segments out
of sequence. A simultaneous `tcpdump` — an mmap'd AF_PACKET ring, exactly what
`gopacket/afpacket` provides — reproduced the same reordering on 6 of 8 streams, so the proposed
migration would not have fixed this. The retry-then-skip is deleted and the assertion is now
hard. Evidence: e2e on a live rootful pod, **6 passed / 0 failed / 0 skipped**, 3 consecutive
runs; `TestSmoke_RetainedCaptureSelfDecryptsFromEmbeddedSecrets` decrypts the retained capture
with an **empty** keylog file.

---

## Requirement Traceability

| Requirement ID | Story | Phase | Status |
| -------------- | ----- | ----- | ------ |
| CAPTURE-01 | P1: pcapng capture | Design | Verified |
| CAPTURE-02 | P1: timestamp alignment | Design | Verified (spec-precision note: cross-component clock) |
| CAPTURE-03 | P1: backend parity | Design | Verified (assertion implemented and discriminating; it skips on **this host**, whose AppArmor profile denies signal delivery to `tcpdump` — see Known Limitations, AD-012. Parity has therefore not been executed end-to-end here) |
| CAPTURE-04 | P1: offline decryption pairing | Design | Verified (unit, integration **and** e2e — the e2e content assertion is hard, no longer a skip; AD-014) |
| CAPTURE-05 | P1: pairing invocation helper | Design | Verified |
| CAPTURE-06 | P1: artifact permissions | Design | Verified (spec-precision note: UID ownership implied, not independently asserted) |
| CAPTURE-07 | P1: bounded retention | Design | Verified |
| CAPTURE-08 | P1: ephemeral cleanup / --retain | Design | Verified |
| CAPTURE-09 | P2: Podman harness | Tasks | Verified — Phase 4 (T9) rewired for AD-010; see `validation.md`'s Phase 4 addendum re-verification |
| CAPTURE-10 | P2: loop avoidance (e2e) | Design | Verified |
| CAPTURE-11 | P2: real-cert smoke test | Design | Verified |

**ID format:** `CAPTURE-[NUMBER]`

**Status values:** Pending → In Design → In Tasks → Implementing → Verified

**Coverage:** 11 total, 11 mapped to tasks, 11 verified (see `validation.md` — latest: 2026-09-19 CAPTURE-04 root-cause fix pass, AD-014; e2e 6 passed / 0 failed / 0 skipped, 3 consecutive runs)

---

## Success Criteria

How we know the feature is successful:

- [x] `tshark -r dump.pcapng -o "tls.keylog_file:sslkeylog.log" -o tcp.reassemble_out_of_order:TRUE -Y 'http or http2' -V` shows decrypted HTTP application data for the app's TLS 1.3 request (proven by `TestDecryptedAppData_RealTLS13FlowDecryptsToHTTP` and, end-to-end on a live pod, by `TestSmoke_OfflineValidationDecryptsPlaintext` — which now asserts rather than skips, AD-014). The filter must match `http2`: the app's `curl` negotiates h2 over ALPN, which tshark's `http` dissector never matches.
- [x] The retained capture decrypts **unaided**, from its own embedded Decryption Secrets Block, with no keylog paired (proven by `TestSmoke_RetainedCaptureSelfDecryptsFromEmbeddedSecrets` against an empty keylog file; AD-014 moved the DSB ahead of the packet blocks, without which this never worked).
- [x] `curl https://example.com` (no `-k`) succeeds end-to-end through the relay, validating the real cert.
- [x] Artifacts are `0600`/`0700` under UID 1337, keylog on tmpfs, retention bounded, wiped on teardown unless `--retain`.
- [x] gopacket and tcpdump backends decrypt to identical application data (assertion implemented; skips where host AppArmor denies signal delivery to `tcpdump` — AD-012).
- [x] `dump.pcapng` grows on disk in real time (no explicit flush needed by an operator; the writer flushes itself) rather than only becoming readable after pod teardown (AD-011).
- [x] `make build LINK_MODE=static|dynamic` produces a sidecar binary linked correctly for the target container image's libc (musl/Alpine vs. glibc).

# TLS Session-Key Extraction via LD_PRELOAD Interposer Specification

**Feature dir**: `.specs/features/02-uprobe-keylog/`
**Milestone**: M2 — Preload keylog
**Source**: [PRD Feature 02](../../../docs/prd/feature-02.md), [TDD](../../../docs/technical-design-document.md), AD-010 (`.specs/STATE.md`)

> **Revision note (2026-09-12, AD-010)**: this spec replaces the original eBPF-uprobe +
> per-version-struct-offset design (see git history / `validation.md` for that prior,
> superseded implementation). A live rootful validation run proved the uprobe path
> unworkable: the internal keylog routine's symbol is stripped from production
> `libssl.so.3` builds, and the (necessarily placeholder) offset table was rejected
> outright by the kernel's BPF verifier. Feature 01's eBPF redirect is unaffected — only
> this feature's extraction mechanism changes. The feature directory name
> (`02-uprobe-keylog`) is kept as-is to avoid breaking cross-references from `STATE.md`
> and the PRD; it now covers the interposer mechanism.

## Problem Statement

Captured TLS 1.2/1.3 egress is end-to-end encrypted and, under TLS 1.3 forward secrecy,
cannot be decrypted with any static key. The app's per-session secrets must be extracted
passively from its own TLS library — without terminating TLS, without a MITM CA, and
without weakening the app's certificate validation — and written as an NSS keylog so the
captured flow can be decrypted offline. The extraction mechanism itself must not depend on
kernel struct-offset knowledge that drifts across OpenSSL builds/versions.

## Goals

- [ ] Passively extract TLS 1.2 master secret and the five TLS 1.3 secrets from the app's
      `libssl`, using OpenSSL's own `SSL_CTX_set_keylog_callback` — never reading raw
      process memory or kernel-side struct offsets.
- [ ] Emit valid, deduplicated NSS keylog lines whose `client_random` pairs to the
      captured flow, reusing the existing (unchanged) NSS validator/writer pipeline.
- [ ] Leave the app's end-to-end handshake and real-certificate validation completely
      untouched; the app is never modified, relinked, or restarted differently than
      normal beyond one extra `LD_PRELOAD` env var.

## Out of Scope

Explicitly excluded. Documented to prevent scope creep.

| Feature | Reason |
| ------- | ------ |
| MITM TLS termination / forging CA | AD-001: passive extraction only, no CA |
| In-band decryption / DPI | MVP writes keys only; decryption is offline (Feature 03) |
| eBPF uprobes / kernel struct-offset reads for key extraction | AD-010: proved unworkable against a real target; fully replaced by the interposer |
| TLS libraries beyond OpenSSL | AD-008 (unaffected by AD-010): BoringSSL/GnuTLS/NSS are follow-on interposer variants |
| GoTLS (Go `crypto/tls`) extraction | Statically linked — cannot be `LD_PRELOAD`-interposed; was uprobe-only (`internal/keylog/gotls.go`) and is removed with the rest of the uprobe mechanism. Remains an interface-only follow-on, now with no code in this feature (a future Go-specific mechanism would need its own design) |
| Decrypting non-TLS or QUIC traffic | Out of the MVP protocol scope |

---

## Assumptions & Open Questions

Every ambiguity is resolved or recorded here — nothing is left silently unclear.

| Assumption / decision | Chosen default | Rationale | Confirmed? |
| --------------------- | -------------- | --------- | ---------- |
| Extraction mechanism | `LD_PRELOAD` shared-library interposer wrapping `SSL_CTX_new`/`SSL_CTX_new_ex`, registering `SSL_CTX_set_keylog_callback` | AD-010: versioned public OpenSSL ABI, immune to symbol stripping and struct-offset drift | y |
| TLS library module (MVP) | OpenSSL `libssl`/`libcrypto` only | AD-008 (unaffected): one well-understood module proves the model | y |
| Transport from interposer to sidecar | Newline-delimited NSS lines over a Unix domain socket, interposer as client, sidecar as server | Simple, no kernel dependency, reuses the existing NSS grammar unchanged | y |
| Socket location | Filesystem path in a dedicated directory shared (via a Podman volume) between the app and sidecar containers, not network-reachable | Matches AD-006's "reuse `capture.CheckTarget`-style guard" intent for at-rest/transport secrecy while allowing the app's (non-1337) UID to `connect()` | y |
| Socket directory permission model | Directory `0711` (owner rwx, group/other search-only — no read/write); the bound socket file is `chmod 0666` after `Listen` so a different UID can `connect()` | A strict `0700` (like `capture.CheckTarget`'s at-rest file guard) would block the app's UID from traversing to the socket at all; the guard here instead rejects world/group **write** or **read** bits on the directory (`perm&0o066 != 0`), keeping search-only crossing as the one deliberate exception, justified by the exclusive (pod-only) volume mount being the real trust boundary | y |
| Keylog storage | `/var/log/sidecar/sslkeylog.log`-equivalent path, `0600` in `0700` dir on tmpfs, deduped by `(label, client_random, secret)` | AD-006: secrets are plaintext-equivalent (unchanged) | y |
| Preload wiring | `deploy/podman/pod-up.sh` builds `preload/keylog_preload.c`, bind-mounts the `.so` read-only into the app container, sets `LD_PRELOAD=<path>` and `GOEBPF_PRELOAD_SOCKET=<path>` on the app container only | The app container's own launch env is fully controlled by the pod harness | y |
| Reachability when the interposer can't connect yet | Bounded retry (a few attempts, short backoff) then drop the line silently — never block the app | TDD risk table: "sidecar not yet listening"; app must never stall on a diagnostic side-channel | y |
| Process/library scoping | None needed (no PID/cgroup filter) — the interposer only fires inside the process that dlopen'd/linked it | Fundamentally different from the uprobe model: there is no shared-inode cross-process leakage risk in the first place | y |

**Open questions:** none — all resolved or logged above.

---

## User Stories

### P1: Interposer captures OpenSSL's own keylog lines ⭐ MVP

**User Story**: As a security engineer, I want the app's TLS session secrets captured
directly from OpenSSL's own keylog callback, so that forward-secret TLS 1.3 flows (and
TLS 1.2) are decryptable offline without any struct-offset or symbol-stripping risk.

**Why P1**: This is the entire extraction mechanism; without it nothing is captured.

**Acceptance Criteria** (each line is one EARS pattern):

1. WHEN the app calls `SSL_CTX_new` or `SSL_CTX_new_ex` THEN the interposer SHALL call
   through to the real OpenSSL function and THEN register its own callback via
   `SSL_CTX_set_keylog_callback` on the returned context before returning it to the app.
2. WHEN OpenSSL invokes the registered callback for a derived secret THEN the interposer
   SHALL forward the already NSS-formatted line, verbatim, to the sidecar — no
   reformatting, no struct reads.
3. The system SHALL leave the app's end-to-end handshake and real-certificate validation
   unmodified — the interposer never touches handshake data, only observes formatted
   output.
4. IF the app never links OpenSSL dynamically (static libssl, or a non-OpenSSL stack)
   THEN the interposer's wrapped symbols SHALL simply never be called — no crash, no
   error surfaced to the app, no keylog lines.

**Independent Test**: `LD_PRELOAD` the built interposer into a real OpenSSL client
process completing a TLS 1.3 handshake to a local upstream; assert the sidecar's keylog
gains the five TLS 1.3 lines whose `client_random` matches the handshake (IT-02.1); a
process without the interposer produces nothing (IT-02.4).

---

### P1: Reliable line transport to the sidecar ⭐ MVP

**User Story**: As a security engineer, I want every captured line delivered to the
sidecar over a private channel, so that the existing validate/dedup/write pipeline
appends it to the NSS keylog exactly once.

**Why P1**: The interposer's captured lines are useless without a working transport into
the already-tested `internal/keylog` writer.

**Acceptance Criteria**:

1. WHEN the sidecar starts THEN it SHALL listen on a Unix domain socket before the app
   container starts, so the app's first handshake is never racing the sidecar's readiness.
2. WHEN the interposer has a line to send THEN it SHALL write it, newline-terminated, to
   its (lazily opened, cached) socket connection.
3. WHEN the sidecar's socket server receives a line THEN it SHALL route it through the
   existing NSS validator, dedup, and secure append writer unchanged.
4. IF a received line is malformed THEN the sidecar SHALL reject it (no append) and SHALL
   NOT log its content (only a rejection counter/event).
5. IF the interposer cannot connect (or a write fails) THEN it SHALL retry briefly and
   then silently drop the line rather than blocking the app.
6. WHILE the socket directory is not the exclusive, correctly permissioned trust boundary
   (world-writable or world-readable) THEN the sidecar SHALL refuse to listen.

**Independent Test**: Feed well-formed and malformed lines to the socket server over a
real Unix socket connection; assert well-formed lines are deduplicated and appended,
malformed lines are rejected without appending, and a connection closing mid-line does not
corrupt the keylog (UT-02.5); assert the server refuses a world-writable socket directory
(UT-02.6).

---

### P2: Preload environment wiring on the app container

**User Story**: As an operator, I want the pod harness to wire `LD_PRELOAD` and the
socket path onto the app container automatically, so that no manual app-image change is
ever required.

**Why P2**: Needed for the real Podman harness, but the core interposer↔socket path is
provable in isolation first.

**Acceptance Criteria**:

1. WHEN building the preload env for a given `.so` path and socket path THEN the system
   SHALL emit exactly `LD_PRELOAD=<path>` and the socket-path env var, and no others.
2. WHERE the app container is launched by `deploy/podman/pod-up.sh` THEN it SHALL receive
   the interposer `.so` bind-mounted read-only and both env vars set.

**Independent Test**: Given a `.so` path and a socket path, assert the env-var builder's
output is exactly the two expected `KEY=VALUE` strings (UT-02.7).

---

## Edge Cases

- WHEN the app sends plain-TCP (non-TLS) traffic THEN the system SHALL emit no keylog
  lines (there is no TLS handshake to trigger the callback).
- IF a statically linked or non-OpenSSL binary is `LD_PRELOAD`ed THEN the interposer's
  symbols SHALL never be called — no crash, no lines.
- IF the interposer's socket write fails mid-line (partial write) THEN it SHALL treat the
  connection as broken, close it, and reconnect on the next line rather than corrupting
  the stream.
- WHILE multiple lines arrive concurrently (e.g. TLS 1.3's five secrets, or multiple
  connections in the same process) THE sidecar SHALL serialise writes to the keylog
  (already guaranteed by the reused `Writer`).

---

## Requirement Traceability

| Requirement ID | Story | Phase | Status |
| -------------- | ----- | ----- | ------ |
| KEYLOG-01 | P1: interposer wraps `SSL_CTX_new`/`_ex`, registers callback | Tasks | Verified |
| KEYLOG-02 | P1: callback forwards the verbatim NSS line | Tasks | Verified |
| KEYLOG-03 | P1: app handshake/cert validation left unmodified | Tasks | Verified |
| KEYLOG-04 | P1: zero footprint when absent / non-OpenSSL / static | Tasks | Verified |
| KEYLOG-05 | P1: sidecar listens before app starts | Tasks | Verified |
| KEYLOG-06 | P1: socket server routes through existing validate/dedup/write | Tasks | Verified |
| KEYLOG-07 | P1: malformed line rejected, never logged | Tasks | Verified |
| KEYLOG-08 | P1: bounded retry then silent drop | Tasks | Verified |
| KEYLOG-09 | P1: socket directory permission guard | Tasks | Verified |
| KEYLOG-10 | P2: preload env builder | Tasks | Verified |
| KEYLOG-11 | P2: pod-up.sh wiring (app container env + mount) | Tasks | Verified — implemented in `.specs/features/03-capture-harness/tasks.md`'s Phase 4 (T9), which owns `deploy/podman/pod-up.sh` |

**ID format:** `KEYLOG-[NUMBER]`

**Status values:** Pending → In Design → In Tasks → Implementing → Verified

**Coverage:** 11 total, 11 mapped to tasks, 0 unmapped

---

## Success Criteria

How we know the feature is successful:

- [ ] For a TLS 1.3 handshake through OpenSSL with the interposer preloaded, the emitted
      NSS lines' `client_random` matches the captured ClientHello and decrypts the flow
      in Wireshark.
- [ ] TLS 1.2 emits one `CLIENT_RANDOM` line; TLS 1.3 emits the five labelled lines —
      identical grammar to the prior mechanism (the writer/validator are unchanged).
- [ ] A process without the interposer, or a statically linked/non-OpenSSL target,
      produces no keylog lines and no crash.
- [ ] The keylog is `0600` on tmpfs, deduplicated, and never logged to stdout; the
      transport socket lives only in a pod-exclusive, non-world-accessible directory.
- [ ] No eBPF uprobe, ring buffer, or OpenSSL struct-offset code remains in the tree for
      this feature.

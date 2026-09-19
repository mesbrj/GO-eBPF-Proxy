# Feature 02 — TLS session-key extraction via an `LD_PRELOAD` interposer (NSS keylog)

## Description

Passively extract each connection's TLS session secrets (TLS 1.2 master secret; TLS 1.3 handshake/traffic/exporter secrets) from the unmodified app's OpenSSL library using a small `LD_PRELOAD` shared-library interposer that registers OpenSSL's own built-in keylog callback (`SSL_CTX_set_keylog_callback`), and write them to an NSS-format `SSLKEYLOGFILE`. There is **no TLS termination, no MITM, and no CA**: the app's TLS handshake stays end-to-end with the real server, and the sidecar only reads the ephemeral keys OpenSSL already derives and formats.

> **Revision note (2026-09-12, AD-010)**: this supersedes the original eBPF-uprobe + per-version-struct-offset design. A live rootful validation run proved the uprobe path unworkable against a real target: the internal keylog routine's symbol is stripped from production `libssl.so.3` builds, and reading `SSL_st`/`SSL_SESSION` via the (necessarily placeholder, per-build) offset table was rejected outright by the kernel's BPF verifier. See "Alternatives Considered" in the TDD for the full comparison. Feature 01's eBPF redirect is unaffected — only this feature's extraction mechanism changes.

## User value

Yields decryptable TLS 1.2/1.3 traffic (including forward-secret flows) for offline inspection **without a MITM certificate authority**, without weakening the app's certificate validation, and transparently to **certificate-pinned** applications — the keys are read from the app's own TLS library via the same mechanism the library itself uses for `SSLKEYLOGFILE`, never negotiated or reconstructed by a proxy.

## Functional requirements

- Ship a small `LD_PRELOAD` shared library (`libkeylogpreload.so`) that interposes `SSL_CTX_new`/`SSL_CTX_new_ex`: call through to the real OpenSSL function, then call `SSL_CTX_set_keylog_callback()` on the returned context with our own callback, before returning it to the app.
- The callback receives the `SSL *` and the **already NSS-formatted line** (`LABEL client_random secret`) directly from OpenSSL — no struct offsets, no per-version table, no in-kernel memory reads.
- Ship each captured line to the sidecar over a Unix domain socket (the interposer is the client; the sidecar's Go process is the server, listening before the app's first handshake). The interposer never writes the keylog file itself and never opens or creates the socket path if it doesn't already exist — no privilege beyond `connect()`.
- The Go sidecar reads newline-delimited lines from the socket and runs each one through the **existing, unchanged** NSS line validator, dedup, and secure append writer (`internal/keylog/nss.go`, `writer.go`) — appending to the configured keylog path (`/var/log/sidecar/sslkeylog.log` by default; `/var/log/sidecar-keylog-tmpfs/keylog/sslkeylog.log` on the tmpfs mount in the Podman harness), deduplicated by `(label, client_random, secret)`.
- The app container is launched with `LD_PRELOAD=/path/to/libkeylogpreload.so` and the Unix-socket path via an env var (both set by `deploy/podman/pod-up.sh`); the app's own binary, arguments, and code are never modified.
- If the app never links OpenSSL dynamically (statically linked libssl, or a non-OpenSSL TLS stack), the interposer's symbols are simply never called — no lines are emitted, no crash, no error surfaced to the app.
- Module-based, extensible design unchanged from the prior decision: OpenSSL is the MVP module; BoringSSL/GnuTLS/NSS all expose an equivalent keylog-callback registration API and are follow-on modules using the same interposer pattern. Go `crypto/tls` (GoTLS) cannot be `LD_PRELOAD`-interposed (statically linked) and remains an interface-only follow-on (unchanged from the prior decision).
- No CA, no cert minting, no TLS termination; the sidecar never decrypts in-band.

## Non-functional requirements

- The interposer is a small C shared library with no third-party dependencies beyond OpenSSL's own headers (`-ldl -lssl -lcrypto`), built with `clang`/`gcc` via `make build-preload` (the project's existing C toolchain, already used for the eBPF programs) — not linked into or built as part of the Go binary; the main sidecar binary remains CGO-free (`LINK_MODE=static`).
- The Go sidecar's socket server and NSS line-processing pipeline are pure Go, reusing the already-tested `internal/keylog/nss.go` (validate/format/classify) and `writer.go` (secure append + dedup) unchanged.
- No `--libssl` discovery, no OpenSSL version detection, no per-version offset table, no ring buffer, no uprobe attach: all removed. The sidecar no longer needs to resolve the app's library path, its own PID relative to the app, or its OpenSSL version at all.
- **Reduced privilege footprint**: the sidecar no longer needs `CAP_PERFMON` (uprobe-attach-only) or a shared PID namespace with the app (uprobe-attach-only); both drop from the runtime requirements. `CAP_BPF`/`CAP_NET_ADMIN` (Feature 01's redirect) are unaffected.
- Kernel version is no longer a factor for key extraction (no uprobes, no ring buffer, no BTF/CO-RE dependency for this feature); Feature 01's `connect4`/`sockops` kernel floor (≥ 5.10 recommended) is unchanged.
- TLS 1.3 removes RSA key exchange and enforces forward secrecy — decryption depends on the ephemeral per-session secrets captured here, not on any static server key. This is unaffected by the mechanism change: OpenSSL derives and hands us the same secrets either way.
- Keys are sensitive: the keylog is written `0600` in a `0700` directory; concurrent writes serialised; lines deduplicated — unchanged from the prior decision.
- The Unix domain socket itself carries the same secret-grade material as the keylog file in transit: it must live in a directory only the sidecar and app (same pod, same UID trust boundary) can reach, and must never be network-reachable.

## Acceptance

Given the app performs a TLS 1.3 handshake through its OpenSSL library (launched with the interposer preloaded), the sidecar emits NSS keylog lines whose `client_random` matches the captured ClientHello, and those lines decrypt the captured flow to plaintext in Wireshark — with the app's validation of the real server certificate left intact (no MITM).

## Test definitions

### Conventions & tooling

- Framework: `testify` (`assert`, `require`, `mock`, `suite`); executed via `make test` (`go test -race ./...`).
- Unit tests cover `internal/keylog` (NSS line validation/formatting, dedup, secure append — unchanged) and the new Unix-socket line-ingestion server — all in-process, no kernel, no privilege.
- The interposer's C build and its real dynamic-linker behaviour (does it actually get preloaded and does OpenSSL actually call it) are verified against a real `libssl` process, gated by build tag `//go:build integration`; `t.Skip` when a compiler/OpenSSL/socket precondition is unavailable so `make test` stays green on unprivileged runners.
- Offline decryption of the captured flow using the emitted keylog is exercised end-to-end in Feature 03.

### Unit tests (in-process, no privilege)

| ID | Component / given | Asserts (then) | Requirement |
| --- | --- | --- | --- |
| UT-02.1 | NSS line validator, TLS 1.2 event | `CLIENT_RANDOM <cr> <ms>` accepted; 64-hex client_random, 96-hex master secret; malformed line rejected | NSS keylog (TLS 1.2) — unchanged |
| UT-02.2 | NSS line validator, TLS 1.3 events | The five labels (`CLIENT_HANDSHAKE_TRAFFIC_SECRET`, `SERVER_HANDSHAKE_TRAFFIC_SECRET`, `CLIENT_TRAFFIC_SECRET_0`, `SERVER_TRAFFIC_SECRET_0`, `EXPORTER_SECRET`) each validate; secret hex length tracks the cipher hash | NSS keylog (TLS 1.3) — unchanged |
| UT-02.3 | Secure append writer | `O_APPEND`, file `0600`, dir created `0700`, newline-terminated; concurrent writes serialised | Secure append keylog — unchanged |
| UT-02.4 | Dedup | Same `(label, client_random, secret)` written once; distinct handshakes each appended | Dedup lines — unchanged |
| UT-02.5 | Unix-socket line server | Accepts a connection, reads newline-delimited lines, routes each through validate→dedup→append; a malformed line is rejected without appending; the connection closing mid-line does not corrupt the keylog | Preload transport |
| UT-02.6 | Socket path / permissions | Socket file created in a `0700` directory; refuses to listen on a world-accessible path (reuses `capture.CheckTarget`-style guard) | Secret-grade transport at rest |
| UT-02.7 | Preload env builder | Given a `.so` path and socket path, emits the exact `LD_PRELOAD=<path>` and socket-path env vars to set on the app container | Preload wiring |

### Integration tests (real `libssl` + compiler; build tag `integration`)

| ID | Scenario (given / when) | Asserts (then) | Requirement |
| --- | --- | --- | --- |
| IT-02.1 | Interposer built and `LD_PRELOAD`ed into a real OpenSSL client process completing a TLS 1.3 handshake to a local upstream | The sidecar's keylog gains the five TLS 1.3 lines; `client_random` matches the handshake | Extract TLS 1.3 keys |
| IT-02.2 | Same, forcing a TLS 1.2 handshake | One `CLIENT_RANDOM` line; 48-byte master secret | Extract TLS 1.2 keys |
| IT-02.3 | Capture the TLS flow to pcap + the emitted keylog → decode with a keylog-aware decoder | Recovered plaintext matches the sent payload | Decryptable via preload keys |
| IT-02.4 | A process **not** `LD_PRELOAD`ed (interposer absent) completes a TLS handshake | No keylog lines emitted; no error, no crash | Zero footprint when absent |
| IT-02.5 | Plain-TCP (non-TLS) traffic from an `LD_PRELOAD`ed process | No keylog lines emitted (no spurious secrets) | No false output |
| IT-02.6 | A statically linked / non-OpenSSL binary is `LD_PRELOAD`ed | Interposer symbols are never called; no crash, no lines | Graceful no-op on unsupported target |

### Traceability

- **Acceptance** (TLS 1.3 handshake → NSS keylog whose `client_random` matches the capture and decrypts it in Wireshark) → IT-02.1 + IT-02.3, with the keylog grammar guaranteed by UT-02.1 + UT-02.2 (unchanged) and the app's certificate validation left intact (no MITM, no code change to the app).

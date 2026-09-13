# STATE

## Decisions

### AD-001

- **Decision**: Intercept egress with an eBPF `cgroup/connect4` transparent redirect to a pass-through L4 relay, and extract TLS keys passively via eBPF uprobes on the app's TLS library — no iptables, no TLS termination, no MITM CA.
- **Reason**: Works where iptables is forbidden; requires zero app changes; is cert-pinning-proof and never weakens the app's trust store; decrypts forward-secret TLS 1.3 via the app's own ephemeral secrets.
- **Trade-off**: Requires kernel ≥ 5.8 caps and per-`libssl` symbol/offset knowledge; reads app process memory; accepts a double TCP-stack traversal (no sockmap in MVP).
- **Scope**: Whole project (all features).
- **Date**: 2026-09-09
- **Status**: superseded by AD-010 (the redirect half stays eBPF; key extraction moves to an `LD_PRELOAD` interposer)

### AD-002

- **Decision**: Attach `connect4`/`sockops` at the **pod common parent cgroup v2**; achieve loop avoidance by running the entire sidecar as UID 1337 and skipping UID 1337 in `connect4`.
- **Reason**: A single parent cgroup covers both containers in the pod; the UID-1337 skip keeps the sidecar's own egress from being re-redirected.
- **Trade-off**: Requires a host cgroup namespace (`--cgroupns=host`) and a strict whole-sidecar UID discipline.
- **Scope**: Features 01 (redirect) and 03 (harness).
- **Date**: 2026-09-09
- **Status**: active

### AD-003

- **Decision**: Recover the original destination via `connect4` recording by socket cookie, then a `sockops` (`TCP_CONNECT_CB`) re-key to `(src_ip, src_port)`; the Go relay resolves via `getpeername()` + tuple-map lookup. Never use `SO_COOKIE`/`SO_ORIGINAL_DST` on the accepted socket.
- **Reason**: The accepted socket is a different `struct sock` (different cookie); the tuple bridge is the only race-free correlation before SYN.
- **Trade-off**: Needs a byte-order-normalised tuple codec and a `sockops` program in addition to `connect4`.
- **Scope**: Feature 01.
- **Date**: 2026-09-09
- **Status**: active

### AD-004

- **Decision**: Original-destination resolver is **fail-closed**: on a tuple miss, apply a bounded retry, then RST — never forward to a default. Every definitive miss increments a metric and logs the source tuple.
- **Reason**: No safe default exists for a transparent proxy; forwarding to a default would be an open-relay/SSRF bypass.
- **Trade-off**: A genuinely un-redirected connection to the relay port is dropped rather than served.
- **Scope**: Feature 01.
- **Date**: 2026-09-09
- **Status**: active

### AD-005

- **Decision**: Capture with in-process gopacket **pcapng + embedded DSB** as the default; keep `tcpdump` as an optional fallback/parity backend. Offer a `pcap + separate keylog` split mode.
- **Reason**: DSB makes the capture self-decrypting; pure-Go avoids an external dependency; split mode allows independent retention of ciphertext and secrets.
- **Trade-off**: Two capture backends to keep at parity.
- **Scope**: Feature 03.
- **Date**: 2026-09-09
- **Status**: active

### AD-006

- **Decision**: Treat keylog and capture as plaintext-equivalent secrets — `0600` files in a `0700` dir under UID 1337, keylog on **tmpfs**, retention **bounded** (size + age caps with rotation) and **ephemeral by default** (teardown wipes `/var/log/sidecar`; `--retain` opts in). Never ship secret artifacts to APM.
- **Reason**: The keylog decrypts all captured TLS; unbounded retention is standing liability and disk-exhaustion risk.
- **Trade-off**: Artifacts vanish on teardown unless `--retain` is set.
- **Scope**: Features 02 and 03.
- **Date**: 2026-09-09
- **Status**: active

### AD-007

- **Decision**: Load/attach eBPF in pure Go via `cilium/ebpf` + `bpf2go` (no CGO); target kernel ≥ 5.10 (BTF/CO-RE); sidecar caps `CAP_BPF` + `CAP_NET_ADMIN` + `CAP_PERFMON`.
- **Reason**: Pure-Go loader keeps the build CGO-free; CO-RE lets one object run across kernels; those caps are the least-privilege set for cgroup + uprobe attach on ≥ 5.8.
- **Trade-off**: Excludes kernels < 5.10 and rootless Podman (these program types need rootful).
- **Scope**: Whole project.
- **Date**: 2026-09-09
- **Status**: active

### AD-008

- **Decision**: OpenSSL `libssl` is the only TLS-library uprobe module in the MVP; BoringSSL/GnuTLS/NSS/GoTLS are interface-only follow-ons. Primary hook is the pre-formatted keylog routine; fallback reads `SSL_st`/`SSL_SESSION` via BTF/CO-RE or a per-version offset table.
- **Reason**: One well-understood module proves the model; the keylog-line hook avoids struct-offset fragility where available.
- **Trade-off**: Statically linked/stripped non-OpenSSL builds are unsupported in the MVP.
- **Scope**: Feature 02.
- **Date**: 2026-09-09
- **Status**: superseded by AD-010 — a live rootful run (AD-009) proved the fallback offset table is rejected outright by the kernel verifier against a real, unverified-offset `libssl.so.3`; the primary keylog-routine hook was also unreachable (symbol stripped). Both paths in this decision failed in practice.

### AD-010

- **Decision**: Replace eBPF-uprobe-based TLS key extraction with an `LD_PRELOAD` shared-library interposer that wraps `SSL_CTX_new`/`SSL_CTX_new_ex` and registers OpenSSL's own `SSL_CTX_set_keylog_callback`. OpenSSL formats and hands us the exact NSS line; the callback ships it to the sidecar over a Unix domain socket, where the existing `internal/keylog` NSS validator/dedup/secure-writer pipeline (unchanged) appends it to the tmpfs keylog. eBPF stays exactly as-is for Feature 01's `connect4`/`sockops` transparent redirect; only the TLS key extraction mechanism changes.
- **Reason**: `SSL_CTX_set_keylog_callback` is versioned public OpenSSL API (`@@OPENSSL_3.0.0`) that cannot be stripped without breaking the library's own ABI contract — confirmed present in `.dynsym` on this project's target Ubuntu `libssl.so.3` even though `.symtab`/debug symbols and the internal keylog routine are gone. It sidesteps struct-offset/verifier fragility entirely: no `bpf_probe_read_user`, no per-version offset table, no BTF/CO-RE dependency, and OpenSSL formats the NSS line itself instead of the sidecar reconstructing it from raw memory.
- **Trade-off**: No longer "pure eBPF" for this half of the system — it is classic dynamic-linker interposition (the same technique curl/Firefox use for `SSLKEYLOGFILE`), requiring the sidecar to control the app container's launch environment (`LD_PRELOAD=` env var + a bind-mounted `.so`) rather than attaching from outside after the fact. GoTLS (statically linked, no dynamic OpenSSL to interpose) remains an interface-only follow-on, unchanged from AD-008.
- **Side effects (positive)**: drops the sidecar's need for `CAP_PERFMON` (uprobe-only) and the pod's shared PID namespace (was uprobe-attach-only) entirely — both were load-bearing only for the mechanism this replaces. `internal/keylog/discovery.go`, `openssl_offsets.go`, `event.go`, `consumer.go`, and `bpf/tls_keylog.bpf.c` are removed; `internal/keylog/nss.go` and `writer.go` are reused unchanged.
- **Scope**: Feature 02 (mechanism); Feature 03's Podman harness (drops `--share pid`, `CAP_PERFMON`; adds the interposer `.so` + `LD_PRELOAD` wiring on the **app** container).
- **Date**: 2026-09-12
- **Status**: active

### AD-009

- **Decision**: The sidecar binary must be built `CGO_ENABLED=0` (static); the sidecar container needs `CAP_SYS_RESOURCE` in addition to `CAP_BPF`+`CAP_NET_ADMIN`+`CAP_PERFMON`, plus `--security-opt apparmor=unconfined` and `--security-opt seccomp=unconfined` on this host's podman; `/sys/fs/bpf`'s pin dirs must be pre-created and chowned to UID 1337 by `pod-up.sh` before the sidecar starts; the app's PID must be resolved from inside the shared pod PID namespace (`podman exec ... pgrep`), not via `podman inspect`'s host-relative PID.
- **Reason**: Confirmed empirically by bringing up a real rootful pod: each item is a hard failure otherwise (dynamic linking fails to exec on musl/Alpine; `RLIMIT_MEMLOCK` raise needs `CAP_SYS_RESOURCE`; this host's default AppArmor and seccomp profiles each independently block one step of BPF map create/pin; bpffs's root is `0700` root-owned; the pod's shared PID namespace renumbers PIDs vs the host).
- **Trade-off**: Disabling AppArmor/seccomp confinement on the sidecar widens its effective attack surface beyond the spec's stated cap list; scoped to only the sidecar container, never the app container.
- **Scope**: Feature 03 (`deploy/podman/pod-up.sh`).
- **Date**: 2026-09-12
- **Status**: active

## Handoff

- **Feature**: AD-010 rollout (Feature 02's `LD_PRELOAD` interposer replacing eBPF uprobes) — COMPLETE.
- **Phase / Task**: All done. Docs (PRD, TDD, README) updated. `.specs/features/02-uprobe-keylog/{spec,design,tasks}.md` rewritten and fully implemented (T1-T7, 7 commits) plus 2 Verifier-driven fix commits (pod-up.sh start ordering; KEYLOG-08 retry-then-drop test). `.specs/features/03-capture-harness/tasks.md`'s Phase 4 addendum (T9-T11, 3 commits) rewired the Podman harness for the interposer. Both features have a fresh, independent Verifier PASS (`02-uprobe-keylog/validation.md` full re-verification PASS; `03-capture-harness/validation.md` gained a "Phase 4 addendum re-verification" section, PASS). `validate_state.py` accepts both.
- **Completed**: F01 (M1), F02 (M2, now the LD_PRELOAD interposer — Verified PASS), F03 (M3, Phases 1-3 Verified PASS as before + Phase 4 addendum Verified PASS) — all three features fully done under AD-010.
- **In-progress**: none.
- **Next step**: none required. Optional future follow-ons (not blocking): a GoTLS extraction module was removed with the uprobe code and remains undesigned (Feature 02 spec's Out-of-Scope table); a BoringSSL/GnuTLS/NSS interposer variant remains a follow-on (AD-008, unaffected).
- **Blockers**: none
- **Uncommitted files**: none (working tree clean; only `.specs`/`docs` planning-artifact edits remain, which are gitignored by convention)
- **Branch**: main (local only; no push without go-ahead — 12 new local commits since `de39250`, none pushed)

### 2026-09-13 — Final check (all three features)

- Re-ran all deterministic gates repo-wide: `validate_spec.py`/`validate_tasks.py`/`validate_state.py` for all three features — 0 errors each (only pre-existing, documented granularity/none-tests warnings). All `- [ ]` checkboxes across `.specs/features/**` were already `[x]` (none unmarked).
- `make lint` now passes with 0 issues (golangci-lint v2 was installed on this box after the last Verifier pass, which had reported the binary missing) — no lint findings this time.
- `make build`, `go test -race ./...` (49 passed), and `go test -race -tags=integration ./...` (58 passed / 10 skipped, all environment-gated: no CAP_BPF/root/tshark) all green.
- Fixed stale metadata that no longer matched the Verifier-confirmed PASS state: `docs/technical-design-document.md`'s Roadmap table (all milestones were still `⏳ Pending`, now `✅ Done`/`✅ Done (Verifier PASS)`); `02-uprobe-keylog/tasks.md` and `03-capture-harness/tasks.md` headers (`Status: Draft` → `Status: Done (Verifier PASS)`); all three `design.md` headers (`Status: Draft` → `Status: Verified (Verifier PASS)`). No spec/design/task content changed — cosmetic status-field sync only.

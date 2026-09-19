# Feature 03 — Capture & offline decryption validation

## Description

Capture the proxy relay's outbound traffic to pcap/pcapng and pair it with the `LD_PRELOAD` interposer-emitted NSS keylog so the (end-to-end encrypted) TLS 1.2/1.3 egress can be decrypted and validated offline; provide the Podman dev harness (pod, smoke test).

## User value

Turns intercepted keys into a repeatable "capture → decrypt → inspect" workflow and a one-command local environment.

## Functional requirements

- Capture the outbound leg (`eth0`) into `/var/log/sidecar/dump.pcapng` with the in-process gopacket (pcapng) writer — the MVP sidecar always uses it; `tcpdump` exists only as a parity/fallback backend (exercised by tests), not a runtime-selectable option.
- Document/automate Wireshark/tshark pairing (TLS keylog filename) to decrypt.
- Treat all capture artifacts (keylog and pcap/pcapng) as **plaintext-equivalent secrets**: files `0600`, directory `0700` owned by the sidecar UID (1337), and the host bind-mount target `0700`; write the keylog to a **tmpfs** mount so secrets never persist to disk (in the Podman harness: `/var/log/sidecar-keylog-tmpfs/keylog/sslkeylog.log`).
- DSB-embedded pcapng is self-contained and is the MVP's **only** capture mode; the `pcap + separate keylog` mode that would keep ciphertext and secrets separable for independent retention is **descoped** (AD-005 — no code path) and deferred to a follow-on.
- **Bounded retention:** enforce a size cap **and** an age cap (whichever first) with rotation; never unbounded (avoids standing liability and disk-exhaustion).
- **Ephemeral by default:** pod teardown wipes `/var/log/sidecar`; the sidecar's own `--retain` startup flag (forwarded by `RETAIN=1` from `pod-up.sh`) and `deploy/podman/pod-down.sh --retain` govern keep/export. Secret artifacts are never shipped to APM — operational telemetry only.
- Podman: rootful pod, host cgroup namespace (`--cgroupns=host`) so the eBPF programs attach at the pod common parent cgroup, sidecar caps (`--cap-drop ALL` then `CAP_BPF` + `CAP_NET_ADMIN` (cgroup attach) + `CAP_SYS_RESOURCE` (RLIMIT_MEMLOCK raise on BPF load) + `CAP_NET_RAW` (AF_PACKET capture socket)) + `/sys/fs/bpf` + `/sys/fs/cgroup` mounts; the sidecar container runs entirely as UID 1337 (loop exclusion); the app container is launched with `LD_PRELOAD=<keylog interposer.so>` (AD-010) — no shared PID namespace, no `CAP_PERFMON` (both were uprobe-attach-only). No CA injection — the app validates the real server certificate end-to-end.
- Smoke test: `curl https://example.com` from the app container end-to-end.

## Non-functional requirements

- Single Linux host/VM; reproducible via `deploy/podman` scripts.
- Capture and keylog timestamps must align for reliable decryption.
- Artifacts are plaintext-equivalent secret material: retention is **bounded** (size + age caps) and **ephemeral by default**; at-rest perms `0600`/`0700` under the sidecar UID; keylog on tmpfs; no secret artifacts to APM.

## Acceptance

`tshark -r dump.pcapng -o "tls.keylog_file:sslkeylog.log"` shows decrypted HTTP application data for the app's TLS 1.3 request.

## Test definitions

### Conventions & tooling

- Framework: `testify` (`assert`, `require`, `mock`, `suite`); executed via `make test` (`go test -race ./...`).
- Unit tests cover the `internal/capture` pcapng writer, timestamp sourcing, path/config handling, and retention/rotation + artifact-permission enforcement — no external tools.
- Offline-decryption integration tests require `tshark`; gated by build tag `//go:build integration`.
- The one-command environment is exercised by a Podman harness (`deploy/podman`), gated by build tag `//go:build e2e`; it is rootful and needs `podman` + kernel ≥ 5.10.

### Unit tests (no external tools)

| ID | Component / given | Asserts | Requirement |
| --- | --- | --- | --- |
| UT-03.1 | pcapng writer | Emits a valid SHB/IDB/EPB stream re-readable by gopacket; correct `LinkType`; packet bytes preserved | In-process gopacket pcapng |
| UT-03.2 | Capture timestamp source | Uses the same clock as the keylog writer; monotonic; within tolerance | Timestamps must align |
| UT-03.3 | Output paths / config | `/var/log/sidecar/dump.pcapng` and `sslkeylog.log` resolved; directory created; append/rotation policy honoured | Capture to file |
| UT-03.4 | tshark pairing helper | Emits the correct `-o tls.keylog_file:<path>` invocation | Automate keylog pairing |
| UT-03.5 | Retention enforcement | Size cap **and** age cap trigger rotation/eviction (oldest first); footprint stays within bounds; `--retain` disables purge | Bounded retention |
| UT-03.6 | Artifact permissions | Keylog/pcap(ng) created `0600`, dir `0700`, owner UID 1337; refuses to write under a world-accessible target | Secret-grade at rest |

### Integration tests — offline decryption (needs `tshark`; build tag `integration`)

| ID | Scenario | Asserts | Requirement |
| --- | --- | --- | --- |
| IT-03.1 | Real TLS 1.3 flow via the proxy → capture `dump.pcapng` + emit `sslkeylog.log`; run `tshark -r dump.pcapng -o tls.keylog_file:sslkeylog.log -Y http` | Decrypted HTTP application-data is present | **Acceptance** |
| IT-03.2 | Keylog clock skewed outside the capture window | Decryption fails — guards the timestamp-alignment invariant against regression | Timestamps must align |
| IT-03.3 | `tcpdump` vs in-process gopacket backends | Both pcaps decrypt to identical application-data | Capture parity |

### Integration tests — Podman harness (rootful; needs `podman` + kernel ≥ 5.10; build tag `e2e`)

| ID | Scenario | Asserts | Requirement |
| --- | --- | --- | --- |
| IT-03.4 | `deploy/podman` brings up the rootful pod: host cgroup ns (`--cgroupns=host`), sidecar caps after `--cap-drop ALL` (`CAP_BPF`, `CAP_NET_ADMIN`, `CAP_SYS_RESOURCE`, `CAP_NET_RAW`), mounts `/sys/fs/bpf` + `/sys/fs/cgroup`, log volume, app container launched with the keylog interposer preloaded | Containers healthy; `connect4`/`sockops` attached at the pod parent cgroup; maps pinned; the app's process has the interposer `.so` mapped | Podman dev harness |
| IT-03.5 | App makes a real end-to-end TLS 1.3 request (no MITM) | `curl https://example.com` (no `-k`) validates the real server cert and succeeds; the preload-interposer keylog gains the session's lines | Real-cert egress + preload keylog |
| IT-03.6 | `podman exec app curl https://example.com` | HTTP 200 end-to-end; sidecar logs the correct original dst; `dump.pcapng` and `sslkeylog.log` grow | Smoke test |
| IT-03.7 | Offline validation over the produced artifacts | IT-03.1 decode yields the app request's plaintext | Capture → decrypt workflow |
| IT-03.8 | Sidecar egress runs as UID 1337 under the pod-parent-scoped hook | Not re-intercepted; no proxy self-loop in logs | Loop avoidance |
| IT-03.9 | Pod teardown (default vs `--retain`) | Default wipes `/var/log/sidecar` (keylog tmpfs gone on stop); `--retain` preserves artifacts | Ephemeral-by-default cleanup |

### Traceability

- **Acceptance** (`tshark` shows decrypted HTTP application data) → IT-03.1, exercised end-to-end by IT-03.6 + IT-03.7.

# Capture & Offline Decryption Validation Design

**Spec**: `.specs/features/03-capture-harness/spec.md`
**Milestone**: M3 — Capture harness
**Status**: Verified (Verifier PASS)

---

## Architecture Overview

An in-process gopacket writer captures the outbound leg to pcapng and embeds the uprobe-emitted
keylog as a Decryption Secrets Block (DSB) so the file self-decrypts. A retention manager keeps
artifacts secret-grade and bounded. A rootful Podman harness brings up the app+sidecar pod and a
smoke test proves the pipeline end-to-end; offline `tshark` validates decryption.

```mermaid
graph TD
    ETH["eth0 outbound leg"] --> CAP["internal/capture<br/>gopacket pcapng writer"]
    KL["sslkeylog.log (F02)"] -->|embed DSB| CAP
    CAP --> PCAP[("/var/log/sidecar/dump.pcapng<br/>0600, DSB-embedded")]
    CAP -.->|split mode| PCAP2[("dump.pcap + separate keylog")]
    RET["retention manager<br/>size+age caps, --retain"] -.-> PCAP & KL
    subgraph harness["deploy/podman (rootful)"]
        POD["pod: shared netns+PID ns+host cgroup ns"]
        SMOKE["curl https://example.com (no -k)"]
    end
    POD --> CAP
    SMOKE -->|HTTP 200| TSHARK["tshark -o tls.keylog_file → plaintext HTTP"]
    PCAP --> TSHARK
```

---

## Code Reuse Analysis

### Existing Components to Leverage

| Component | Location | How to Use |
| --------- | -------- | ---------- |
| Keylog writer | `internal/keylog/` (from F02) | Source of the NSS lines embedded as a DSB |
| eBPF loader + relay | `internal/ebpf/`, `internal/proxy/` (from F01) | The harness attaches these; capture wraps the same run |
| Logger | `internal/shared/logger/` (from F01) | Operational telemetry (bytes, rotation) — never secrets |

### Integration Points

| System | Integration Method |
| ------ | ------------------ |
| `eth0` | gopacket `afpacket` (TPACKET_V3 mmap ring) with in-kernel BPF filter; `tcpdump` fallback |
| pcapng DSB | `pcapgo` NgWriter with a Decryption Secrets Block from the keylog |
| Podman | `deploy/podman` create/run scripts (caps, mounts, namespaces) |
| tshark | `-o tls.keylog_file:<path>` pairing invocation |

---

## Components

### pcapng capture writer

- **Purpose**: Write the outbound leg to a valid pcapng with an embedded DSB.
- **Location**: `internal/capture/pcapng.go`
- **Interfaces**:
  - `NewWriter(path string, opts Options) (*Writer, error)` — SHB/IDB, correct `LinkType`
  - `WritePacket(ci gopacket.CaptureInfo, data []byte) error`
  - `EmbedKeylog(lines []string) error` — DSB block
- **Dependencies**: `gopacket`, `pcapgo`, `afpacket`
- **Reuses**: keylog lines from `internal/keylog`

### tcpdump fallback backend

- **Purpose**: Alternative capture backend for parity.
- **Location**: `internal/capture/tcpdump.go`
- **Interfaces**: `Start(iface, path string) (stop func(), error)`
- **Reuses**: `os/exec`

### Clock source

- **Purpose**: Single monotonic clock shared by capture + keylog for aligned timestamps.
- **Location**: `internal/capture/clock.go`
- **Interfaces**: `Now() time.Time` injected into both writers
- **Reuses**: `time`

### Retention manager

- **Purpose**: Enforce size + age caps, rotation, and ephemeral-by-default cleanup.
- **Location**: `internal/capture/retention.go`
- **Interfaces**:
  - `Enforce() error` — evict oldest-first when either cap is hit
  - `Cleanup(retain bool) error` — wipe `/var/log/sidecar` unless `--retain`
  - permission guard: refuse to write under a world-accessible target
- **Reuses**: `os`, logger

### tshark pairing helper

- **Purpose**: Emit the correct offline-decryption invocation.
- **Location**: `internal/capture/pairing.go`
- **Interfaces**: `TsharkArgs(pcap, keylog string) []string` → `-o tls.keylog_file:<path>`
- **Reuses**: N/A

### Podman harness

- **Purpose**: Bring up the pod with correct namespaces, caps, and mounts; smoke test.
- **Location**: `deploy/podman/` (`pod-up.sh`, `pod-down.sh`, `smoke.sh`)
- **Interfaces**: shell scripts — pod create/run, `curl` smoke, teardown (default wipe / `--retain`)
- **Reuses**: F01/F02 sidecar binary from `cmd/app`

### Entrypoint wiring

- **Purpose**: Wire load+attach (cgroup + uprobes), relay, keylog, and capture together.
- **Location**: `cmd/app/main.go`
- **Interfaces**: CLI flags (`--libssl`, `--retain`, backend select); orchestrates all packages
- **Reuses**: everything above

---

## Data Models

### Capture artifacts (on disk)

```text
/var/log/sidecar/
  dump.pcapng      # default: pcapng + embedded DSB (self-decrypting), 0600
  dump.pcap        # split mode: ciphertext only
  sslkeylog.log    # split mode: separate keylog (tmpfs), 0600
  (dir mode 0700, owner UID 1337)
```

### Retention config

```go
type Retention struct {
    MaxBytes int64         // size cap
    MaxAge   time.Duration // age cap
    Retain   bool          // --retain disables purge
}
```

---

## Error Handling Strategy

| Error Scenario | Handling | User Impact |
| -------------- | -------- | ----------- |
| Timestamp skew capture vs keylog | Single injected clock; IT-03.2 negative test | Reliable decryption |
| `tcpdump` unavailable | Fall back to in-process gopacket | Capture still works |
| Keylog dir missing | Create `0700` before writing | No world-readable secrets |
| World-accessible write target | Refuse to write | Prevents secret exposure |
| Size/age cap reached | Rotate/evict oldest-first | Bounded footprint |
| Pod missing PID/cgroup ns | Harness fails fast with precondition error | Clear operator fix |

---

## Risks & Concerns

| Concern | Location (file:line) | Impact | Mitigation |
| ------- | -------------------- | ------ | ---------- |
| Capture/keylog timestamp skew | `internal/capture/clock.go` (new) | Decryption fails | Single clock source; DSB embeds keylog; IT-03.2 |
| Plaintext-equivalent secrets on disk | `internal/capture/retention.go` (new) | High | tmpfs keylog, `0600`/`0700`, bounded + ephemeral; AD-006 |
| Rootful privileges / broad caps | `deploy/podman/` (new) | Medium | Scope to `CAP_BPF`+`CAP_NET_ADMIN`+`CAP_PERFMON`; avoid `SYS_ADMIN` |
| Backend divergence (tcpdump vs gopacket) | `internal/capture/` (new) | Medium | Parity test IT-03.3 asserts identical decrypted app-data |
| Capture loss under load | `internal/capture/pcapng.go` (new) | Medium | TPACKET_V3 mmap ring + in-kernel BPF filter |

> None hidden — all flagged with mitigations above.

---

## Tech Decisions (feature-local)

| Decision | Choice | Rationale |
| -------- | ------ | --------- |
| Default artifact | DSB-embedded single pcapng | Self-decrypting; simplest to hand off |
| Split mode | Opt-in `pcap + separate keylog` | Independent retention of ciphertext vs secrets |
| Harness form | Shell scripts under `deploy/podman` | Matches TDD; `podman generate kube` is post-MVP |

> Project-level decisions already recorded: AD-005, AD-006, AD-007 in `.specs/STATE.md`.

# GO-eBPF-Proxy

A sidecar that transparently redirects an unmodified application's outbound IPv4 TCP
egress to a local pass-through relay using eBPF (`cgroup/connect4`, no `iptables`/NAT),
and **passively extracts the app's TLS session keys via eBPF uprobes** on its TLS
library — emitting an NSS-format keylog so the captured (still end-to-end encrypted)
TLS 1.2/1.3 traffic can be decrypted and inspected offline.

**No TLS termination. No MITM. No CA.** The app's handshake stays end-to-end with the
real server; its certificate validation is never weakened, so certificate pinning is a
non-issue — the sidecar only reads the ephemeral keys the app's own TLS library already
derives.

## Why

Inspecting an app's encrypted egress usually means one of three intrusive options:
instrumenting the app, relying on `iptables`/NAT (often blocked by policy), or a MITM CA
(defeated by certificate pinning, and TLS 1.3 forward secrecy makes static-key decryption
impossible anyway). `go-ebpf-proxy` avoids all three: transparent redirection at the
socket layer, and TLS keys read passively from the process that already holds them.

## How it works

1. An eBPF `cgroup/connect4` program intercepts `connect()`, records the original
   destination, and rewrites it to a local relay (`127.0.0.1:15001`).
2. A `sockops` program re-keys that record by source tuple so the relay can recover it
   race-free after `accept()`.
3. The Go relay resolves the original destination and raw-pipes bytes both directions —
   it never parses or terminates TLS.
4. An eBPF uprobe on the app's TLS library (`libssl`) reads `client_random` and the TLS
   1.2/1.3 session secrets as the library derives them, and streams them to user space
   over a ring buffer.
5. The secrets are validated, deduplicated, and written as an NSS keylog
   (`/var/log/sidecar/sslkeylog.log`), which Wireshark/tshark can pair with a capture of
   the same egress to show decrypted traffic.

```mermaid
flowchart LR
    app["app process<br/>(unmodified)"] -- "connect()" --> kern["connect4 + sockops<br/>(eBPF)"]
    kern -- "redirect" --> relay["pass-through relay<br/>127.0.0.1:15001"]
    relay -- "raw pipe (end-to-end TLS)" --> upstream["Upstream server"]
    app -. "libssl handshake" .-> uprobe["uprobe on libssl<br/>(eBPF)"]
    uprobe -- "secret events" --> keylog["keylog consumer<br/>-> NSS keylog"]
```

## Pod view

`go-ebpf-proxy` runs as a second container in the same pod as the target app, sharing its
network, PID, and (host) cgroup namespaces. **Any app container that links OpenSSL's
`libssl` gets transparent redirection and TLS key extraction with zero changes** — no
code change, no rebuild, no env var, no trust-store edit. The app container doesn't even
need to know the sidecar exists.

```mermaid
flowchart TB
    subgraph pod["Pod (shared netns + PID ns + host cgroup ns)"]
        subgraph appc["app container — unmodified, any OpenSSL-linked binary"]
            app["app process<br/>connect(dst:443)"]
            libssl["libssl (TLS 1.2/1.3)"]
        end
        subgraph sidecar["go-ebpf-proxy container (UID 1337)"]
            loader["eBPF loader"]
            relay["pass-through relay<br/>127.0.0.1:15001"]
            keylog["keylog consumer"]
        end
    end
    kernel["Kernel: connect4 + sockops + uprobe<br/>(attached at the pod's common parent cgroup)"]

    app -- "connect() intercepted" --> kernel
    kernel -- "redirect to relay" --> relay
    libssl -. "handshake secrets read via uprobe" .-> kernel
    kernel -- "secret events" --> keylog
    loader -. "attach cgroup programs + uprobe(libssl)" .-> kernel
    relay == "raw pipe (real cert validated by the app)" ==> upstream["Upstream server"]
    keylog -. "NSS keylog (tmpfs)" .-> disk[("/var/log/sidecar")]
```

Swap in a different app container image — same or different language, any process that
links `libssl` — and the sidecar keeps working unchanged: the `connect4`/`sockops`
programs redirect at the socket layer regardless of what wrote the syscall, and the
uprobe attaches to the *library*, not to any particular app binary.

## Status

MVP delivered in three vertical slices:

| Milestone | Scope | Status |
| --- | --- | --- |
| M1 | eBPF transparent redirect (`connect4` + `sockops` + pass-through relay) | ✅ Done |
| M2 | Uprobe TLS keylog extraction (OpenSSL) | ✅ Done |
| M3 | Capture (pcapng + Podman dev environment + decrypt validation) | ⏳ Planned |

## Requirements

- Linux kernel ≥ 5.10 (BTF/CO-RE, uprobes, BPF ring buffer)
- `CAP_BPF` + `CAP_NET_ADMIN` + `CAP_PERFMON`
- Go ≥ 1.25, `clang`/`llvm` ≥ 14 and `bpftool` (for building the eBPF programs)
- Rootful Podman (local dev setup); a shared PID namespace is required so the sidecar
  can resolve and attach uprobes to the app's TLS library

## Build & test

```bash
make build             # fmt -> vet -> build
make test               # unit tests (go test -race ./...)
make test-integration   # kernel/eBPF-backed tests (build tag `integration`; skip cleanly
                        # without the required capabilities)
make lint               # golangci-lint, covers unit and integration-tagged files
make check              # lint + build + test + test-integration
```

eBPF objects are pre-generated and committed (`bpf/*_bpfel.go`, `*_bpfeb.go`). To
regenerate them after editing a `.bpf.c` file:

```bash
make generate
```

## Project layout

```
bpf/             eBPF C programs (connect4, sockops, tls_keylog) + generated bindings
internal/ebpf/   loader: load/attach/pin the eBPF programs, map codec
internal/proxy/  original-dst resolver (fail-closed) + pass-through L4 relay
internal/keylog/ TLS library discovery, uprobe attach, NSS keylog extraction/writer
internal/shared/ structured logging, shared infra
cmd/app/         sidecar entrypoint (wires loader, relay, keylog)
deploy/podman/   rootful Podman dev environment (pod scripts)
```

## Out of scope (MVP)

`sockmap`/`sk_msg` acceleration; IPv6 (`connect6`); UDP/QUIC/HTTP-3; production Kubernetes; live in-band DPI; the TUI; TLS-library modules beyond OpenSSL (BoringSSL/GnuTLS/NSS/GoTLS are interface-only).

## Skills reference

- [tlc-spec-driven](https://agent-skills.techleads.club/skills/tlc-spec-driven/): Plan and implement the features.
- [technical-design-doc-creator](https://agent-skills.techleads.club/skills/technical-design-doc-creator/): Create (and maintain) the technical design document based on previous researches, decisions and plans.
- [skill-taskwarrior](https://github.com/mesbrj/skills#skill-taskwarrior): Manage and track the human tasks/activities.

## License

GPL-3.0 — see [LICENSE](LICENSE).

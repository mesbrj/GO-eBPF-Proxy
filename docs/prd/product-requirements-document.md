# Product Requirements Document (PRD)

## Description

go-ebpf-proxy is a sidecar that transparently redirects an unmodified application's outbound IPv4 TCP egress using eBPF (`cgroup/connect4`, no iptables) to a pass-through L4 relay, and **passively extracts the app's TLS session keys via an `LD_PRELOAD` interposer** that registers OpenSSL's own keylog callback — producing NSS-format keylogs so the captured (still end-to-end encrypted) TLS 1.2/1.3 traffic can be decrypted and inspected offline. **No TLS termination, no MITM CA.**

## Problem to solve

Developers and security engineers need to inspect the plaintext of an application's encrypted egress **without modifying the application**, **without iptables** (blocked by policy/missing modules), and **without a MITM CA** (defeated by certificate pinning and weakening the app's trust), including TLS 1.3 flows that forward secrecy makes impossible to decrypt with static keys.

## Goals

- Transparent, code-free interception of an unmodified app's IPv4 TCP egress.
- Correct recovery of the original destination for each connection.
- Decryptable capture: pcap + paired NSS keylog that Wireshark/tshark can open.
- Reproducible local dev via a rootful Podman pod on a single Linux host/VM.

## Success criteria

`curl https://example.com` in the app container succeeds end-to-end through the relay (validating the **real** server certificate, no `-k`); the resolved original destination matches; and the captured pcap decrypts to plaintext HTTP using the preload-interposer-emitted NSS keylog.

## MVP Scope & Constraints

- Interception model: **eBPF `cgroup/connect4` transparent redirection (no iptables)** to a **pass-through L4 relay** (raw byte pipe, used as a single capture choke point) + **passive TLS key extraction via an `LD_PRELOAD` interposer** on the app's TLS library, emitting an NSS keylog. The `connect4`/`sockops` programs attach at the **pod common parent cgroup**; loop avoidance comes from the sidecar's UID-1337 exclusion. No TLS termination, no MITM CA, no sockmap in the MVP.

- Correlation: `connect4` stores original dst by socket cookie; a `sockops` (`TCP_CONNECT_CB`) program re-keys it by source tuple; the Go proxy resolves the original destination via `getpeername()` + map lookup. Never rely on `SO_COOKIE`/`SO_ORIGINAL_DST` on the accepted socket.

- Only rewrite `IPPROTO_TCP`, IPv4, non-loopback destinations; skip the proxy's own UID (1337) to avoid loops — load-bearing, since the pod-parent attach also scopes the sidecar, whose container therefore runs entirely as UID 1337.

- Runtime: rootful Podman pod, shared netns and **host cgroup namespace (`--cgroupns=host`)** so the programs can attach at the pod common parent cgroup; the sidecar container runs entirely as UID 1337 (loop exclusion); sidecar caps `CAP_BPF` + `CAP_NET_ADMIN` (redirect); the app container is launched with `LD_PRELOAD=<interposer.so>` for TLS key extraction (no shared PID namespace, no `CAP_PERFMON` — both were uprobe-attach-only and are no longer needed); kernel ≥ 5.10; mounts `/sys/fs/bpf`, `/sys/fs/cgroup`.

- Non-goals (MVP): MITM TLS termination and a self-hosted CA; sockmap acceleration; IPv6 (`connect6`); UDP/QUIC/HTTP-3; production Kubernetes; live in-band DPI; TUI. (Certificate pinning is a non-issue: passive key extraction reads the app's own keys and never presents a forged certificate.)

### Delivery milestones (vertical slices)

1. **M1 — Redirect only:** `connect4`+`sockops`+maps; a dumb TCP proxy that
   logs the resolved original dst and raw-pipes. Proves interception end-to-end.
2. **M2 — Preload interposer keylog:** `LD_PRELOAD` an interposer into the app's TLS
   library process (OpenSSL MVP) that registers OpenSSL's own keylog callback, and
   emit an NSS keylog. Proves decryption via Wireshark — no CA, no TLS termination,
   no in-kernel memory reads.
3. **M3 — Capture harness:** pcap capture + automated pcap+keylog pairing check;
   Podman scripts; smoke test with `curl https://…` (validates the real server
   certificate end-to-end).

### Explicitly out of scope for the MVP

MITM TLS termination and a self-hosted CA; sockmap/`sk_msg` acceleration; IPv6
(`connect6`); UDP/QUIC/HTTP-3; multi-host / production K8s manifests; the TUI;
live in-band decryption/DPI. (Passive key extraction is unaffected by certificate
pinning, so no pinning bypass is required.)

## Features

- Feature 01: [eBPF transparent redirection](feature-01.md)
- Feature 02: [TLS session-key extraction via an `LD_PRELOAD` interposer (NSS keylog)](feature-02.md)
- Feature 03: [Capture & offline decryption validation](feature-03.md)

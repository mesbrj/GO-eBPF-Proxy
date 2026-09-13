// Package bpf embeds the compiled eBPF objects for the transparent-redirect
// sidecar. proxy.bpf.c holds the connect4/sockops redirect programs; bpf2go
// compiles it into its generated Go bindings.
//
// AD-010: the TLS session-key extraction uprobe (tls_keylog.bpf.c) is removed
// -- extraction is now an LD_PRELOAD interposer (see preload/keylog_preload.c),
// not an eBPF uprobe.
package bpf

// vmlinux.h is generated from the running kernel's BTF (CO-RE); it is gitignored
// and regenerated on demand. The compiled objects (proxy_bpf*.o/.go) are committed.
//go:generate sh -c "bpftool btf dump file /sys/kernel/btf/vmlinux format c > vmlinux.h"
//go:generate go run github.com/cilium/ebpf/cmd/bpf2go -cc clang -target bpfel,bpfeb -type orig_dst -type tuple_key Proxy proxy.bpf.c

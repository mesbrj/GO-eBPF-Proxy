// Package bpf embeds the compiled eBPF objects for the transparent-redirect
// sidecar and the TLS session-key extraction uprobe. proxy.bpf.c holds the
// connect4/sockops redirect programs; tls_keylog.bpf.c holds the uprobe.
// bpf2go compiles each into its own generated Go bindings.
package bpf

// vmlinux.h is generated from the running kernel's BTF (CO-RE); it is gitignored
// and regenerated on demand. The compiled objects (proxy_bpf*.o/.go) are committed.
//go:generate sh -c "bpftool btf dump file /sys/kernel/btf/vmlinux format c > vmlinux.h"
//go:generate go run github.com/cilium/ebpf/cmd/bpf2go -cc clang -target bpfel,bpfeb -type orig_dst -type tuple_key Proxy proxy.bpf.c
//go:generate go run github.com/cilium/ebpf/cmd/bpf2go -cc clang -cflags "-D__TARGET_ARCH_x86" -target bpfel,bpfeb -type secret_event -type tls_config TlsKeylog tls_keylog.bpf.c

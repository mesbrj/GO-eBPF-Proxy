// Package bpf embeds the compiled eBPF objects for the transparent-redirect
// sidecar. The eBPF C lives in proxy.bpf.c (shared maps + connect4 + sockops);
// bpf2go compiles it and generates the proxy_bpf*.go bindings.
package bpf

// vmlinux.h is generated from the running kernel's BTF (CO-RE); it is gitignored
// and regenerated on demand. The compiled objects (proxy_bpf*.o/.go) are committed.
//go:generate sh -c "bpftool btf dump file /sys/kernel/btf/vmlinux format c > vmlinux.h"
//go:generate go run github.com/cilium/ebpf/cmd/bpf2go -cc clang -target bpfel,bpfeb -type orig_dst -type tuple_key Proxy proxy.bpf.c

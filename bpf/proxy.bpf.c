//go:build ignore

#include "vmlinux.h"
#include <bpf/bpf_helpers.h>

char __license[] SEC("license") = "Dual MIT/GPL";

/*
 * Placeholder program wired in T3 to prove the bpf2go toolchain. The real
 * transparent-redirect logic (shared maps + record-by-cookie + rewrite) is
 * filled in by T5 (connect4) and T6 (sockops).
 */
SEC("cgroup/connect4")
int cgroup_connect4(struct bpf_sock_addr *ctx)
{
	return 1; /* allow, unmodified */
}

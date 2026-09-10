//go:build ignore

#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_endian.h>

/*
 * go-ebpf-proxy transparent redirect (single translation unit).
 *
 * Byte-order contract (shared with the Go codec):
 *   - IP fields are stored in NETWORK byte order.
 *   - port fields are stored in HOST byte order.
 */

#define PROXY_UID 1337
#define PROXY_PORT 15001
#define PROXY_TCP 6 /* IPPROTO_TCP */

char __license[] SEC("license") = "Dual MIT/GPL";

struct orig_dst {
	__u32 ip;   /* network byte order */
	__u16 port; /* host byte order */
};

struct tuple_key {
	__u32 ip;   /* network byte order (source ip) */
	__u16 port; /* host byte order (source port)  */
};

/* Set by connect4 (join key = socket cookie), consumed+dropped by sockops. */
struct {
	__uint(type, BPF_MAP_TYPE_LRU_HASH);
	__uint(max_entries, 65536);
	__type(key, __u64);
	__type(value, struct orig_dst);
	__uint(pinning, LIBBPF_PIN_BY_NAME);
} origdst_by_cookie SEC(".maps");

/* Re-keyed by sockops; read by the Go relay for original-dst lookup. */
struct {
	__uint(type, BPF_MAP_TYPE_LRU_HASH);
	__uint(max_entries, 65536);
	__type(key, struct tuple_key);
	__type(value, struct orig_dst);
	__uint(pinning, LIBBPF_PIN_BY_NAME);
} origdst_by_tuple SEC(".maps");

SEC("cgroup/connect4")
int cgroup_connect4(struct bpf_sock_addr *ctx)
{
	/* Only rewrite IPv4 TCP. */
	if (ctx->protocol != PROXY_TCP)
		return 1;

	/* Skip the sidecar's own egress (loop avoidance). */
	__u32 uid = bpf_get_current_uid_gid() & 0xffffffff;
	if (uid == PROXY_UID)
		return 1;

	/* Skip loopback destinations (127.0.0.0/8). */
	__u32 dip_host = bpf_ntohl(ctx->user_ip4);
	if ((dip_host >> 24) == 127)
		return 1;

	/* Record the original destination keyed by socket cookie. */
	struct orig_dst od = {};
	od.ip = ctx->user_ip4;                      /* network order */
	od.port = bpf_ntohs((__u16)ctx->user_port); /* host order */

	__u64 cookie = bpf_get_socket_cookie(ctx);
	bpf_map_update_elem(&origdst_by_cookie, &cookie, &od, BPF_ANY);

	/* Redirect to the local relay. */
	ctx->user_ip4 = bpf_htonl(0x7F000001); /* 127.0.0.1 */
	ctx->user_port = bpf_htons(PROXY_PORT);

	return 1;
}

SEC("sockops")
int sockops_prog(struct bpf_sock_ops *ctx)
{
	/* Only act once the source port is assigned, before SYN. */
	if (ctx->op != BPF_SOCK_OPS_TCP_CONNECT_CB)
		return 0;

	/* Join on the socket cookie set by connect4. */
	__u64 cookie = bpf_get_socket_cookie(ctx);
	struct orig_dst *od = bpf_map_lookup_elem(&origdst_by_cookie, &cookie);
	if (!od)
		return 0;

	/* Re-key by (src_ip, src_port). local_ip4 is network order; local_port
	 * is host order (kernel convention) — matching the byte-order contract. */
	struct tuple_key key = {};
	key.ip = ctx->local_ip4;
	key.port = (__u16)ctx->local_port;

	bpf_map_update_elem(&origdst_by_tuple, &key, od, BPF_ANY);
	bpf_map_delete_elem(&origdst_by_cookie, &cookie);

	return 0;
}

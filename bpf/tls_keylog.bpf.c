//go:build ignore

#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>

/*
 * go-ebpf-proxy TLS session-key extraction uprobe (Feature 02).
 *
 * Passive extraction only: no TLS termination, no MITM, no CA. The app's
 * end-to-end handshake and certificate validation are never touched.
 *
 * Hook choice: the exported SSL_write is the attach point (uprobe target
 * resolved by internal/keylog/discovery.go). Production libssl builds (verified
 * on this repo's dev image, Ubuntu's libssl.so.3) ship fully stripped, so the
 * pre-formatted internal keylog-emitter (e.g. ssl_log_secret) has no symbol to
 * attach to outside debug/BTF builds; the offset-based fallback described in
 * design.md is therefore the generally applicable path, not merely a fallback
 * of last resort. Offsets come from internal/keylog/openssl_offsets.go via the
 * config map below, populated once by the Go loader after version detection.
 */

char __license[] SEC("license") = "Dual MIT/GPL";

#define MAX_SECRET_LEN 64
#define MAX_SECRETS 8

/* Mirrors internal/keylog/event.go's wire layout exactly (guards CO-RE drift). */
struct secret_event {
	__u16 version;      /* TLS version selector */
	__u16 label;        /* enum -> NSS label, see event.go */
	__u8 client_random[32];
	__u8 secret[MAX_SECRET_LEN];
	__u16 secret_len;
};

/* Populated once by the Go loader from the resolved OpenSSL offset table. */
struct tls_config {
	__u32 target_pid;
	__u32 client_random_off;
	__u32 secret_count;
	__u32 secret_off[MAX_SECRETS];
	__u32 secret_len[MAX_SECRETS];
	__u16 secret_label[MAX_SECRETS];
	__u16 tls_version;
};

struct {
	__uint(type, BPF_MAP_TYPE_ARRAY);
	__uint(max_entries, 1);
	__type(key, __u32);
	__type(value, struct tls_config);
	__uint(pinning, LIBBPF_PIN_BY_NAME);
} tls_keylog_config SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_RINGBUF);
	__uint(max_entries, 1 << 16);
} secrets_rb SEC(".maps");

/* secret_event is never stored in a typed map, so nothing forces the compiler
 * to emit its BTF; this dummy instance does, so bpf2go can generate the
 * matching Go type. */
const struct secret_event *unused_secret_event __attribute__((unused));

SEC("uprobe/tls_keylog")
int uprobe_tls_keylog(struct pt_regs *ctx)
{
	__u32 zero = 0;
	struct tls_config *cfg = bpf_map_lookup_elem(&tls_keylog_config, &zero);
	if (!cfg)
		return 0;

	/* Filter by the redirected workload's PID so a shared libssl inode
	 * never leaks another co-located process's secrets. */
	__u32 pid = bpf_get_current_pid_tgid() >> 32;
	if (cfg->target_pid != 0 && pid != cfg->target_pid)
		return 0;

	void *ssl = (void *)PT_REGS_PARM1(ctx);
	if (!ssl)
		return 0;

	__u32 count = cfg->secret_count;
	if (count > MAX_SECRETS)
		count = MAX_SECRETS;

#pragma unroll
	for (int i = 0; i < MAX_SECRETS; i++) {
		if (i >= count)
			break;

		struct secret_event ev = {};
		ev.version = cfg->tls_version;
		ev.label = cfg->secret_label[i];
		ev.secret_len = cfg->secret_len[i];
		if (ev.secret_len == 0 || ev.secret_len > MAX_SECRET_LEN)
			continue;

		if (bpf_probe_read_user(&ev.client_random, sizeof(ev.client_random),
					 (void *)((char *)ssl + cfg->client_random_off)))
			continue;
		if (bpf_probe_read_user(&ev.secret, ev.secret_len,
					 (void *)((char *)ssl + cfg->secret_off[i])))
			continue;

		struct secret_event *out = bpf_ringbuf_reserve(&secrets_rb, sizeof(*out), 0);
		if (!out)
			continue;
		*out = ev;
		bpf_ringbuf_submit(out, 0);
	}
	return 0;
}

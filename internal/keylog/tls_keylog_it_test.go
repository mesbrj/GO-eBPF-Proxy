//go:build integration

package keylog

import (
	"errors"
	"os"
	"testing"

	ciliumebpf "github.com/cilium/ebpf"
	"github.com/cilium/ebpf/rlimit"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"golang.org/x/sys/unix"

	bpf "github.com/mesbrj/GO-eBPF-Proxy/bpf"
)

// loadTlsKeylogOrSkip loads the uprobe program's objects with a temp bpffs pin
// dir, skipping (not failing) when the environment is unprivileged.
func loadTlsKeylogOrSkip(t *testing.T) *bpf.TlsKeylogObjects {
	t.Helper()
	if err := rlimit.RemoveMemlock(); err != nil {
		t.Skipf("cannot remove memlock (needs privilege): %v", err)
	}
	pinDir, err := os.MkdirTemp("/sys/fs/bpf", "keylogtest-")
	if err != nil {
		t.Skipf("cannot create bpffs pin dir (needs privilege + mounted bpffs): %v", err)
	}
	t.Cleanup(func() { _ = os.RemoveAll(pinDir) })

	var objs bpf.TlsKeylogObjects
	err = bpf.LoadTlsKeylogObjects(&objs, &ciliumebpf.CollectionOptions{
		Maps: ciliumebpf.MapOptions{PinPath: pinDir},
	})
	if errors.Is(err, unix.EPERM) || errors.Is(err, unix.EACCES) {
		t.Skipf("eBPF load not permitted (unprivileged): %v", err)
	}
	require.NoError(t, err, "program failed to load/verify")
	t.Cleanup(func() { _ = objs.Close() })
	return &objs
}

// IT-02.1/IT-02.2 (load/verify precondition): the uprobe program loads, passes
// the kernel verifier, and its maps have the expected types/sizes.
func TestTlsKeylog_LoadsWithExpectedMapsAndProgType(t *testing.T) {
	objs := loadTlsKeylogOrSkip(t)

	require.NotNil(t, objs.UprobeTlsKeylog)
	assert.Equal(t, ciliumebpf.Kprobe, objs.UprobeTlsKeylog.Type())

	require.NotNil(t, objs.TlsKeylogConfig)
	assert.Equal(t, ciliumebpf.Array, objs.TlsKeylogConfig.Type())

	require.NotNil(t, objs.SecretsRb)
	assert.Equal(t, ciliumebpf.RingBuf, objs.SecretsRb.Type())
}

// Driving a real OpenSSL handshake through an attached uprobe (IT-02.1, IT-02.2,
// IT-02.6) requires a verified per-build offset table (internal/keylog/openssl_offsets.go
// documents this as a known limitation: OpenSSL's SSL_st/SSL_SESSION layout is
// not stable ABI) plus CAP_BPF/CAP_PERFMON. That end-to-end path is exercised
// in the Feature 03 harness where the target build's offsets are supplied.
func TestTlsKeylog_ConfigWiring(t *testing.T) {
	objs := loadTlsKeylogOrSkip(t)

	cfg := bpf.TlsKeylogTlsConfig{
		TargetPid:       uint32(os.Getpid()),
		ClientRandomOff: 0,
		SecretCount:     1,
		TlsVersion:      0x0304,
	}
	cfg.SecretOff[0] = 0
	cfg.SecretLen[0] = 48
	cfg.SecretLabel[0] = 0

	var zero uint32
	require.NoError(t, objs.TlsKeylogConfig.Update(&zero, &cfg, ciliumebpf.UpdateAny))

	var got bpf.TlsKeylogTlsConfig
	require.NoError(t, objs.TlsKeylogConfig.Lookup(&zero, &got))
	assert.Equal(t, cfg.TargetPid, got.TargetPid)
	assert.Equal(t, cfg.SecretCount, got.SecretCount)
}

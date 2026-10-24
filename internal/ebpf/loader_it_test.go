//go:build integration

package ebpf

import (
	"errors"
	"os"
	"path/filepath"
	"testing"

	ciliumebpf "github.com/cilium/ebpf"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"golang.org/x/sys/unix"

	bpf "github.com/mesbrj/GO-eBPF-Proxy/bpf"
)

// loadLoaderOrSkip loads with a temp bpffs pin dir and temp cgroup v2, skipping
// when the environment is unprivileged. Returns the loader, pin dir, cgroup path.
func loadLoaderOrSkip(t *testing.T) (*Loader, string, string) {
	t.Helper()
	pinDir, err := os.MkdirTemp("/sys/fs/bpf", "gotestpin-")
	if err != nil {
		t.Skipf("need privilege + mounted bpffs: %v", err)
	}
	t.Cleanup(func() { _ = os.RemoveAll(pinDir) })

	cg, err := os.MkdirTemp("/sys/fs/cgroup", "gotestcg-")
	if err != nil {
		t.Skipf("need privilege + cgroup v2: %v", err)
	}
	t.Cleanup(func() { _ = os.Remove(cg) })

	cfg := DefaultConfig()
	cfg.PinDir = pinDir
	cfg.CgroupPath = cg

	l, err := Load(cfg)
	if errors.Is(err, unix.EPERM) || errors.Is(err, unix.EACCES) {
		t.Skipf("eBPF load not permitted (unprivileged): %v", err)
	}
	require.NoError(t, err)
	return l, pinDir, cg
}

// pinnedMaps are the maps proxy.bpf.c pins by name under the pin dir.
var pinnedMaps = []string{"origdst_by_cookie", "origdst_by_tuple"}

// IT-01.7: attach + pinned maps; detach/close removes the pins cleanly. The
// pin dir here pre-exists Load (as pod-up.sh pre-creates it, root-owned
// parent and all), so Close must leave the directory itself in place -- it
// removes only what Load created -- and still report success.
func TestLoader_PinLifecycleAndAttach(t *testing.T) {
	l, pinDir, cg := loadLoaderOrSkip(t)

	for _, name := range pinnedMaps {
		_, err := os.Stat(filepath.Join(pinDir, name))
		assert.NoErrorf(t, err, "pin %s must exist after load", name)
	}

	require.NoError(t, l.Attach(cg), "attach to cgroup must succeed")

	require.NoError(t, l.Close(), "close must succeed without removing a pin dir it did not create")
	for _, name := range pinnedMaps {
		_, err := os.Stat(filepath.Join(pinDir, name))
		assert.Truef(t, os.IsNotExist(err), "pin %s must be removed on close", name)
	}
	info, err := os.Stat(pinDir)
	require.NoError(t, err, "a pin dir that existed before Load must survive Close")
	assert.True(t, info.IsDir())
}

// A pin dir Load had to create is Load's own, so Close removes it again.
func TestLoader_CloseRemovesPinDirItCreated(t *testing.T) {
	parent, err := os.MkdirTemp("/sys/fs/bpf", "gotestpin-")
	if err != nil {
		t.Skipf("need privilege + mounted bpffs: %v", err)
	}
	t.Cleanup(func() { _ = os.RemoveAll(parent) })

	cg, err := os.MkdirTemp("/sys/fs/cgroup", "gotestcg-")
	if err != nil {
		t.Skipf("need privilege + cgroup v2: %v", err)
	}
	t.Cleanup(func() { _ = os.Remove(cg) })

	cfg := DefaultConfig()
	cfg.PinDir = filepath.Join(parent, "owned")
	cfg.CgroupPath = cg

	l, err := Load(cfg)
	if errors.Is(err, unix.EPERM) || errors.Is(err, unix.EACCES) {
		t.Skipf("eBPF load not permitted (unprivileged): %v", err)
	}
	require.NoError(t, err)
	_, err = os.Stat(cfg.PinDir)
	require.NoError(t, err, "Load must create the missing pin dir")

	require.NoError(t, l.Close())
	_, err = os.Stat(cfg.PinDir)
	assert.True(t, os.IsNotExist(err), "Close must remove the pin dir Load created")
}

// IT-01.8: filling the tuple map beyond max_entries self-evicts (LRU) without error.
func TestLoader_LRUOverfillNoError(t *testing.T) {
	l, _, _ := loadLoaderOrSkip(t)
	defer func() { _ = l.Close() }()

	m := l.OrigDstByTuple()
	val := bpf.ProxyOrigDst{}
	// max_entries is 65536; insert past it to force eviction.
	for i := 0; i < 66000; i++ {
		key := bpf.ProxyTupleKey{Ip: uint32(i), Port: uint16(i)}
		require.NoError(t, m.Update(&key, &val, ciliumebpf.UpdateAny))
	}
}

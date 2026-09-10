//go:build integration

package bpf

import (
	"encoding/binary"
	"errors"
	"os"
	"testing"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/rlimit"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"golang.org/x/sys/unix"
)

// bpfSockAddr mirrors the kernel struct bpf_sock_addr for PROG_TEST_RUN ctx.
type bpfSockAddr struct {
	UserFamily uint32
	UserIP4    uint32
	UserIP6    [4]uint32
	UserPort   uint32
	Family     uint32
	Type       uint32
	Protocol   uint32
	MsgSrcIP4  uint32
	MsgSrcIP6  [4]uint32
	_          uint32 // pad to align the trailing sk pointer
	Sk         uint64
}

// be32 / be16 return the native-endian representation of a network-order value,
// which is how __be fields sit in memory when read as integers.
func be32(x uint32) uint32 {
	var b [4]byte
	binary.BigEndian.PutUint32(b[:], x)
	return binary.NativeEndian.Uint32(b[:])
}

func be16(x uint16) uint16 {
	var b [2]byte
	binary.BigEndian.PutUint16(b[:], x)
	return binary.NativeEndian.Uint16(b[:])
}

// loadOrSkip loads the objects; it skips (not fails) when BPF is not permitted
// (unprivileged_bpf_disabled), and fails on genuine verifier/load errors.
func loadOrSkip(t *testing.T) *ProxyObjects {
	t.Helper()
	if err := rlimit.RemoveMemlock(); err != nil {
		t.Skipf("cannot remove memlock (needs privilege): %v", err)
	}
	// The maps pin by name, so a bpffs pin dir is required to load them.
	pinDir, err := os.MkdirTemp("/sys/fs/bpf", "proxytest-")
	if err != nil {
		t.Skipf("cannot create bpffs pin dir (needs privilege + mounted bpffs): %v", err)
	}
	t.Cleanup(func() { _ = os.RemoveAll(pinDir) })

	var objs ProxyObjects
	err = LoadProxyObjects(&objs, &ebpf.CollectionOptions{
		Maps: ebpf.MapOptions{PinPath: pinDir},
	})
	if errors.Is(err, unix.EPERM) || errors.Is(err, unix.EACCES) {
		t.Skipf("eBPF load not permitted (unprivileged): %v", err)
	}
	require.NoError(t, err, "program failed to load/verify")
	t.Cleanup(func() { _ = objs.Close() })
	return &objs
}

func TestConnect4_LoadsAndMapsAreLRU(t *testing.T) {
	objs := loadOrSkip(t)

	require.NotNil(t, objs.CgroupConnect4)
	assert.Equal(t, ebpf.CGroupSockAddr, objs.CgroupConnect4.Type())

	for name, m := range map[string]*ebpf.Map{
		"origdst_by_cookie": objs.OrigdstByCookie,
		"origdst_by_tuple":  objs.OrigdstByTuple,
	} {
		assert.Equalf(t, ebpf.LRUHash, m.Type(), "%s must be LRU_HASH", name)
		assert.Equalf(t, uint32(8), m.ValueSize(), "%s value = orig_dst (8 bytes)", name)
	}
	assert.Equal(t, uint32(8), objs.OrigdstByCookie.KeySize(), "cookie key = u64")
	assert.Equal(t, uint32(8), objs.OrigdstByTuple.KeySize(), "tuple_key = 8 bytes")
}

func TestConnect4_RewritesTcpDestinationToRelay(t *testing.T) {
	objs := loadOrSkip(t)

	const dstIP = 0x5DB8D822 // 93.184.216.34
	ctxIn := bpfSockAddr{
		UserFamily: unix.AF_INET,
		UserIP4:    be32(dstIP),
		UserPort:   uint32(be16(443)),
		Family:     unix.AF_INET,
		Type:       unix.SOCK_STREAM,
		Protocol:   unix.IPPROTO_TCP,
	}
	ctxOut := bpfSockAddr{}

	ret, err := objs.CgroupConnect4.Run(&ebpf.RunOptions{
		Context:    &ctxIn,
		ContextOut: &ctxOut,
	})
	if errors.Is(err, ebpf.ErrNotSupported) || errors.Is(err, unix.EINVAL) {
		t.Skipf("PROG_TEST_RUN for cgroup/connect4 unsupported here: %v", err)
	}
	require.NoError(t, err)

	// Verdict: allow; destination rewritten to 127.0.0.1:15001.
	assert.Equal(t, uint32(1), ret, "connect4 must return 1 (allow)")
	assert.Equal(t, be32(0x7F000001), ctxOut.UserIP4, "dst ip rewritten to 127.0.0.1")
	assert.Equal(t, uint32(be16(15001)), ctxOut.UserPort, "dst port rewritten to 15001")

	// The original destination is recorded (keyed by some cookie).
	var key uint64
	var val ProxyOrigDst
	it := objs.OrigdstByCookie.Iterate()
	require.True(t, it.Next(&key, &val), "an original-dst entry must be recorded")
	assert.Equal(t, be32(dstIP), val.Ip, "recorded ip = original dst (network order)")
	assert.Equal(t, uint16(443), val.Port, "recorded port = original dst (host order)")
}

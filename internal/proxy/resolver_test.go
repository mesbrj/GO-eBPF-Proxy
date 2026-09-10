package proxy

import (
	"net/netip"
	"testing"

	ciliumebpf "github.com/cilium/ebpf"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	bpf "github.com/mesbrj/GO-eBPF-Proxy/bpf"
	ebpfpkg "github.com/mesbrj/GO-eBPF-Proxy/internal/ebpf"
)

// stubLookuper returns a scripted sequence of errors; nil means "found" and
// yields val. Calls past the script return ErrKeyNotFound.
type stubLookuper struct {
	script []error
	val    bpf.ProxyOrigDst
	calls  int
}

func (s *stubLookuper) Lookup(_, valueOut any) error {
	i := s.calls
	s.calls++
	var err error
	if i < len(s.script) {
		err = s.script[i]
	} else {
		err = ciliumebpf.ErrKeyNotExist
	}
	if err == nil {
		*(valueOut.(*bpf.ProxyOrigDst)) = s.val
	}
	return err
}

func origDst(t *testing.T, ip string, port uint16) bpf.ProxyOrigDst {
	t.Helper()
	od, err := ebpfpkg.OrigDst(netip.MustParseAddr(ip), port)
	require.NoError(t, err)
	return od
}

// UT-01.6: present tuple resolves to the exact original dst.
func TestResolve_Hit(t *testing.T) {
	stub := &stubLookuper{script: []error{nil}, val: origDst(t, "93.184.216.34", 443)}
	r := NewResolver(stub, WithRetry(3, 0))

	got, err := r.Resolve(netip.MustParseAddr("127.0.0.1"), 52344)
	require.NoError(t, err)
	assert.Equal(t, "93.184.216.34:443", got.String())
	assert.Equal(t, uint64(0), r.Misses())
}

// UT-01.6: absent tuple -> typed ErrNotFound after bounded retry + miss metric/log.
func TestResolve_MissFailsClosed(t *testing.T) {
	stub := &stubLookuper{} // always ErrKeyNotFound
	var missed netip.AddrPort
	r := NewResolver(stub, WithRetry(3, 0), WithOnMiss(func(s netip.AddrPort) { missed = s }))

	_, err := r.Resolve(netip.MustParseAddr("127.0.0.1"), 52344)
	assert.ErrorIs(t, err, ErrNotFound)
	assert.Equal(t, uint64(1), r.Misses(), "miss metric incremented")
	assert.Equal(t, "127.0.0.1:52344", missed.String(), "source tuple logged")
	assert.Equal(t, 4, stub.calls, "1 initial + 3 bounded retries")
}

// UT-01.6: bounded retry absorbs a transient miss then resolves.
func TestResolve_RetryThenHit(t *testing.T) {
	stub := &stubLookuper{
		script: []error{ciliumebpf.ErrKeyNotExist, ciliumebpf.ErrKeyNotExist, nil},
		val:    origDst(t, "10.0.0.5", 8443),
	}
	r := NewResolver(stub, WithRetry(3, 0))

	got, err := r.Resolve(netip.MustParseAddr("127.0.0.1"), 40000)
	require.NoError(t, err)
	assert.Equal(t, "10.0.0.5:8443", got.String())
	assert.Equal(t, uint64(0), r.Misses())
}

// A non-miss lookup error is propagated (not treated as fail-closed miss).
func TestResolve_RealErrorPropagates(t *testing.T) {
	boom := assert.AnError
	stub := &stubLookuper{script: []error{boom}}
	r := NewResolver(stub, WithRetry(3, 0))

	_, err := r.Resolve(netip.MustParseAddr("127.0.0.1"), 1)
	assert.ErrorIs(t, err, boom)
	assert.Equal(t, uint64(0), r.Misses())
}

// IPv6 source is rejected by the codec.
func TestResolve_IPv6Rejected(t *testing.T) {
	r := NewResolver(&stubLookuper{}, WithRetry(0, 0))
	_, err := r.Resolve(netip.MustParseAddr("::1"), 443)
	assert.ErrorIs(t, err, ebpfpkg.ErrNotIPv4)
}

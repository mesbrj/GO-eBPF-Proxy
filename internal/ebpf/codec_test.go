package ebpf

import (
	"net/netip"
	"testing"
	"unsafe"

	bpf "github.com/mesbrj/GO-eBPF-Proxy/bpf"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// UT-01.1 / UT-01.4: orig_dst round-trips the IP and port exactly.
func TestOrigDst_RoundTrip(t *testing.T) {
	dst := netip.MustParseAddr("93.184.216.34")
	od, err := OrigDst(dst, 443)
	require.NoError(t, err)

	got := AddrPort(od)
	assert.Equal(t, dst, got.Addr())
	assert.Equal(t, uint16(443), got.Port())
}

// UT-01.2: generated key/value structs are exactly 8 bytes (layout guard vs CO-RE drift).
func TestStructLayout_Is8Bytes(t *testing.T) {
	assert.Equal(t, uintptr(8), unsafe.Sizeof(bpf.ProxyOrigDst{}), "orig_dst must be 8 bytes")
	assert.Equal(t, uintptr(8), unsafe.Sizeof(bpf.ProxyTupleKey{}), "tuple_key must be 8 bytes")
}

// UT-01.3: port is stored in host byte order; IP bytes are network order.
func TestByteOrder_PortHostIPNetwork(t *testing.T) {
	key, err := TupleKey(netip.MustParseAddr("1.2.3.4"), 0x0102)
	require.NoError(t, err)

	// Port kept in host order verbatim.
	assert.Equal(t, uint16(0x0102), key.Port)

	// IP integer round-trips to the same octets (network order preserved).
	assert.Equal(t, netip.AddrFrom4([4]byte{1, 2, 3, 4}), AddrPort(bpf.ProxyOrigDst{Ip: key.Ip}).Addr())
}

// UT-01.4: IPv6 is rejected.
func TestIPv6_Rejected(t *testing.T) {
	_, err := TupleKey(netip.MustParseAddr("::1"), 443)
	assert.ErrorIs(t, err, ErrNotIPv4)

	_, err = OrigDst(netip.MustParseAddr("2001:db8::1"), 443)
	assert.ErrorIs(t, err, ErrNotIPv4)
}

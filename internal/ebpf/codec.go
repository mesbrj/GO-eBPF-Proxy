// Package ebpf provides the user-space loader, map codec, and attach lifecycle
// for the transparent-redirect eBPF programs.
package ebpf

import (
	"encoding/binary"
	"errors"
	"net/netip"

	bpf "github.com/mesbrj/GO-eBPF-Proxy/bpf"
)

// ErrNotIPv4 is returned when a non-IPv4 address is passed to the codec.
// The MVP intercepts IPv4 only.
var ErrNotIPv4 = errors.New("ebpf: address is not IPv4")

// Byte-order contract (shared with bpf/proxy.bpf.c):
//   - Ip fields hold the IPv4 address in network byte order (as an integer
//     whose native memory bytes equal the network-order octets).
//   - Port fields hold the port in host byte order.

// TupleKey builds the origdst_by_tuple lookup key from a source address/port.
func TupleKey(srcIP netip.Addr, srcPort uint16) (bpf.ProxyTupleKey, error) {
	if !srcIP.Is4() {
		return bpf.ProxyTupleKey{}, ErrNotIPv4
	}
	b := srcIP.As4()
	return bpf.ProxyTupleKey{
		Ip:   binary.NativeEndian.Uint32(b[:]),
		Port: srcPort,
	}, nil
}

// OrigDst builds an orig_dst value from a destination address/port.
func OrigDst(dstIP netip.Addr, dstPort uint16) (bpf.ProxyOrigDst, error) {
	if !dstIP.Is4() {
		return bpf.ProxyOrigDst{}, ErrNotIPv4
	}
	b := dstIP.As4()
	return bpf.ProxyOrigDst{
		Ip:   binary.NativeEndian.Uint32(b[:]),
		Port: dstPort,
	}, nil
}

// AddrPort decodes an orig_dst value into a netip.AddrPort.
func AddrPort(od bpf.ProxyOrigDst) netip.AddrPort {
	var b [4]byte
	binary.NativeEndian.PutUint32(b[:], od.Ip)
	return netip.AddrPortFrom(netip.AddrFrom4(b), od.Port)
}

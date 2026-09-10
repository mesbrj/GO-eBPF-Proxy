// Package proxy implements the pass-through L4 relay and the fail-closed
// original-destination resolver backed by the eBPF tuple map.
package proxy

import (
	"errors"
	"net/netip"
	"sync/atomic"
	"time"

	ciliumebpf "github.com/cilium/ebpf"

	bpf "github.com/mesbrj/GO-eBPF-Proxy/bpf"
	ebpfpkg "github.com/mesbrj/GO-eBPF-Proxy/internal/ebpf"
)

// ErrNotFound is returned when the original destination cannot be resolved for
// a source tuple after the bounded retry. The relay treats this as fail-closed.
var ErrNotFound = errors.New("proxy: original destination not found")

// Lookuper reads a value for a key; satisfied by *ciliumebpf.Map and test stubs.
type Lookuper interface {
	Lookup(key, valueOut any) error
}

// Resolver maps a source (ip, port) to its original destination via the tuple map.
type Resolver struct {
	m       Lookuper
	retries int
	backoff time.Duration
	misses  atomic.Uint64
	onMiss  func(src netip.AddrPort)
}

// Option configures a Resolver.
type Option func(*Resolver)

// WithRetry sets the bounded retry count and per-attempt backoff.
func WithRetry(retries int, backoff time.Duration) Option {
	return func(r *Resolver) { r.retries, r.backoff = retries, backoff }
}

// WithOnMiss registers a callback invoked on each definitive miss (metric/log).
func WithOnMiss(fn func(src netip.AddrPort)) Option {
	return func(r *Resolver) { r.onMiss = fn }
}

// NewResolver builds a Resolver with sane defaults (3 retries, 1ms backoff).
func NewResolver(m Lookuper, opts ...Option) *Resolver {
	r := &Resolver{m: m, retries: 3, backoff: time.Millisecond}
	for _, o := range opts {
		o(r)
	}
	return r
}

// Resolve returns the original destination for a source tuple, or ErrNotFound
// after a bounded retry (fail-closed). Non-miss lookup errors are propagated.
func (r *Resolver) Resolve(srcIP netip.Addr, srcPort uint16) (netip.AddrPort, error) {
	key, err := ebpfpkg.TupleKey(srcIP, srcPort)
	if err != nil {
		return netip.AddrPort{}, err
	}
	var val bpf.ProxyOrigDst
	for attempt := 0; ; attempt++ {
		err := r.m.Lookup(&key, &val)
		if err == nil {
			return ebpfpkg.AddrPort(val), nil
		}
		if !errors.Is(err, ciliumebpf.ErrKeyNotExist) {
			return netip.AddrPort{}, err
		}
		if attempt >= r.retries {
			break
		}
		time.Sleep(r.backoff)
	}
	r.misses.Add(1)
	if r.onMiss != nil {
		r.onMiss(netip.AddrPortFrom(srcIP, srcPort))
	}
	return netip.AddrPort{}, ErrNotFound
}

// Misses returns the count of definitive fail-closed misses.
func (r *Resolver) Misses() uint64 { return r.misses.Load() }

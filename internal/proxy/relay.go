package proxy

import (
	"io"
	"net"
	"net/netip"
	"sync"
	"time"
)

// Relay is the pass-through L4 relay: it resolves each accepted connection's
// original destination and raw-pipes bytes both ways. It never parses or
// terminates TLS. An unresolved connection is closed with a RST (fail-closed).
type Relay struct {
	resolver    *Resolver
	dialTimeout time.Duration
	onDialErr   func(dst netip.AddrPort, err error)
	onRelayed   func(dst netip.AddrPort)
}

// RelayOption configures a Relay.
type RelayOption func(*Relay)

// WithDialTimeout sets the upstream dial timeout.
func WithDialTimeout(d time.Duration) RelayOption {
	return func(r *Relay) { r.dialTimeout = d }
}

// WithOnDialErr registers a callback for upstream dial failures, invoked
// with the resolved original destination the relay could not reach.
func WithOnDialErr(fn func(dst netip.AddrPort, err error)) RelayOption {
	return func(r *Relay) { r.onDialErr = fn }
}

// WithOnRelayed registers a callback invoked with the original destination
// once the upstream dial succeeds, as the relay starts piping -- the hook
// operators use to log the correct original destination per connection. A
// resolved connection triggers exactly one of onRelayed and onDialErr.
func WithOnRelayed(fn func(dst netip.AddrPort)) RelayOption {
	return func(r *Relay) { r.onRelayed = fn }
}

// NewRelay builds a Relay backed by the given resolver.
func NewRelay(r *Resolver, opts ...RelayOption) *Relay {
	rl := &Relay{resolver: r, dialTimeout: 5 * time.Second}
	for _, o := range opts {
		o(rl)
	}
	return rl
}

// Serve accepts connections until the listener is closed.
func (rl *Relay) Serve(ln net.Listener) error {
	for {
		c, err := ln.Accept()
		if err != nil {
			return err
		}
		go rl.handle(c)
	}
}

func (rl *Relay) handle(client net.Conn) {
	ra, ok := client.RemoteAddr().(*net.TCPAddr)
	if !ok {
		_ = client.Close()
		return
	}
	srcIP, ok := netip.AddrFromSlice(ra.IP)
	if !ok {
		_ = client.Close()
		return
	}
	if ra.Port < 0 || ra.Port > 0xFFFF {
		_ = client.Close()
		return
	}

	dst, err := rl.resolver.Resolve(srcIP.Unmap(), uint16(ra.Port))
	if err != nil {
		rl.reset(client) // fail-closed: never forward to a default
		return
	}
	upstream, err := net.DialTimeout("tcp", dst.String(), rl.dialTimeout)
	if err != nil {
		if rl.onDialErr != nil {
			rl.onDialErr(dst, err)
		}
		_ = client.Close()
		return
	}
	if rl.onRelayed != nil {
		rl.onRelayed(dst)
	}
	splice(client, upstream)
}

// reset closes the connection with a RST rather than a graceful FIN.
func (rl *Relay) reset(client net.Conn) {
	if tcp, ok := client.(*net.TCPConn); ok {
		_ = tcp.SetLinger(0)
	}
	_ = client.Close()
}

// splice copies bytes in both directions until either side closes.
func splice(a, b net.Conn) {
	defer func() { _ = a.Close() }()
	defer func() { _ = b.Close() }()
	var wg sync.WaitGroup
	wg.Add(2)
	cp := func(dst, src net.Conn) {
		defer wg.Done()
		_, _ = io.Copy(dst, src)
		if c, ok := dst.(*net.TCPConn); ok {
			_ = c.CloseWrite()
		}
	}
	go cp(a, b)
	go cp(b, a)
	wg.Wait()
}

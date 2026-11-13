package proxy

import (
	"io"
	"net"
	"net/netip"
	"sync"
	"time"

	"go.opentelemetry.io/otel/metric"
)

// Relay is the pass-through L4 relay: it resolves each accepted connection's
// original destination and raw-pipes bytes both ways. It never parses or
// terminates TLS. An unresolved connection is closed with a RST (fail-closed).
type Relay struct {
	resolver    *Resolver
	dialTimeout time.Duration
	onDialErr   func(dst netip.AddrPort, err error)
	onRelayed   func(dst netip.AddrPort)
	mp          metric.MeterProvider
	metrics     *relayMetrics
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

// WithMeterProvider makes the relay record its metrics (see metrics.go) into
// mp. Without it, or with a nil mp, the relay records nothing and copies
// between the two TCP connections directly.
func WithMeterProvider(mp metric.MeterProvider) RelayOption {
	return func(r *Relay) { r.mp = mp }
}

// NewRelay builds a Relay backed by the given resolver.
func NewRelay(r *Resolver, opts ...RelayOption) *Relay {
	rl := &Relay{resolver: r, dialTimeout: 5 * time.Second}
	for _, o := range opts {
		o(rl)
	}
	if rl.mp != nil {
		rl.metrics = newRelayMetrics(rl.mp, r)
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
	accepted := time.Now()
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
	dialStart := time.Now()
	upstream, err := net.DialTimeout("tcp", dst.String(), rl.dialTimeout)
	if err != nil {
		rl.metrics.dialFailed(dst, err)
		if rl.onDialErr != nil {
			rl.onDialErr(dst, err)
		}
		_ = client.Close()
		return
	}
	if rl.onRelayed != nil {
		rl.onRelayed(dst)
	}
	conn := rl.metrics.connOpened(dst, time.Since(dialStart))
	splice(client, conn.count(upstream))
	conn.closed(time.Since(accepted))
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
		if c, ok := dst.(interface{ CloseWrite() error }); ok {
			_ = c.CloseWrite()
		}
	}
	go cp(a, b)
	go cp(b, a)
	wg.Wait()
}

package proxy

import (
	"context"
	"errors"
	"net"
	"net/netip"
	"syscall"
	"time"

	"go.opentelemetry.io/otel"
	"go.opentelemetry.io/otel/attribute"
	"go.opentelemetry.io/otel/metric"
)

// meterName is the instrumentation scope of the relay's metrics.
const meterName = "github.com/mesbrj/netloupe-tap/internal/proxy"

// The relay's metric names (AD-033). Each carries the original destination as
// server.address and server.port, except connection.count and resolve.misses,
// which carry no attributes.
const (
	metricIO           = "netloupe.tap.relay.io"
	metricConnDuration = "netloupe.tap.relay.connection.duration"
	metricConnCount    = "netloupe.tap.relay.connection.count"
	metricDialDuration = "netloupe.tap.relay.dial.duration"
	metricDialErrors   = "netloupe.tap.relay.dial.errors"
	metricMisses       = "netloupe.tap.relay.resolve.misses"
)

// Histogram bucket bounds, in seconds. The SDK's defaults are scaled for
// milliseconds, so every sample would land in the first bucket.
var (
	dialDurationBounds = []float64{0.001, 0.0025, 0.005, 0.01, 0.025, 0.05, 0.1, 0.25, 0.5, 1, 2.5, 5}
	connDurationBounds = []float64{0.01, 0.05, 0.1, 0.5, 1, 5, 10, 30, 60, 300, 900, 3600, 14400, 86400}
)

// relayMetrics holds the relay's instruments. A nil *relayMetrics records
// nothing, so the relay calls it unconditionally.
type relayMetrics struct {
	io           metric.Int64Counter
	connDuration metric.Float64Histogram
	connCount    metric.Int64UpDownCounter
	dialDuration metric.Float64Histogram
	dialErrors   metric.Int64Counter
}

// newRelayMetrics creates the relay's instruments on mp, and an observable
// counter that reports r's fail-closed misses at each collection. An
// instrument the provider refuses is reported to the OpenTelemetry error
// handler and left as the no-op the API returns.
func newRelayMetrics(mp metric.MeterProvider, r *Resolver) *relayMetrics {
	meter := mp.Meter(meterName)
	var m relayMetrics
	var errs [6]error
	m.io, errs[0] = meter.Int64Counter(metricIO,
		metric.WithUnit("By"),
		metric.WithDescription("Bytes the relay exchanged with the original destination."))
	m.connDuration, errs[1] = meter.Float64Histogram(metricConnDuration,
		metric.WithUnit("s"),
		metric.WithDescription("Duration of a relayed connection, from accept to close."),
		metric.WithExplicitBucketBoundaries(connDurationBounds...))
	m.connCount, errs[2] = meter.Int64UpDownCounter(metricConnCount,
		metric.WithUnit("{connection}"),
		metric.WithDescription("Connections the relay is piping."))
	m.dialDuration, errs[3] = meter.Float64Histogram(metricDialDuration,
		metric.WithUnit("s"),
		metric.WithDescription("Duration of a successful dial to the original destination."),
		metric.WithExplicitBucketBoundaries(dialDurationBounds...))
	m.dialErrors, errs[4] = meter.Int64Counter(metricDialErrors,
		metric.WithUnit("{error}"),
		metric.WithDescription("Failed dials to the original destination."))
	_, errs[5] = meter.Int64ObservableCounter(metricMisses,
		metric.WithUnit("{miss}"),
		metric.WithDescription("Connections reset because their original destination was not found."),
		metric.WithInt64Callback(func(_ context.Context, o metric.Int64Observer) error {
			o.Observe(int64(r.Misses())) // #nosec G115 -- a count of connections, far below MaxInt64
			return nil
		}))
	if err := errors.Join(errs[:]...); err != nil {
		otel.Handle(err)
	}
	return &m
}

// dstAttrs returns the original destination as semantic-convention attributes.
func dstAttrs(dst netip.AddrPort) []attribute.KeyValue {
	return []attribute.KeyValue{
		attribute.String("server.address", dst.Addr().String()),
		attribute.Int("server.port", int(dst.Port())),
	}
}

// dialFailed counts a failed upstream dial under its error type.
func (m *relayMetrics) dialFailed(dst netip.AddrPort, err error) {
	if m == nil {
		return
	}
	attrs := append(dstAttrs(dst), attribute.String("error.type", dialErrorType(err)))
	m.dialErrors.Add(context.Background(), 1, metric.WithAttributes(attrs...))
}

// dialErrorType classifies a dial error as one of four fixed values, so the
// attribute never carries the error's own text.
func dialErrorType(err error) string {
	var ne net.Error
	switch {
	case errors.As(err, &ne) && ne.Timeout():
		return "timeout"
	case errors.Is(err, syscall.ECONNREFUSED):
		return "refused"
	case errors.Is(err, syscall.ENETUNREACH), errors.Is(err, syscall.EHOSTUNREACH):
		return "unreachable"
	default:
		return "_OTHER"
	}
}

// connMetrics records one relayed connection. A nil *connMetrics records
// nothing.
type connMetrics struct {
	m      *relayMetrics
	dst    metric.MeasurementOption
	tx, rx metric.MeasurementOption
}

// connOpened records a successful dial that took dialTook and counts the
// connection as open until closed is called.
func (m *relayMetrics) connOpened(dst netip.AddrPort, dialTook time.Duration) *connMetrics {
	if m == nil {
		return nil
	}
	attrs := dstAttrs(dst)
	direction := func(d string) metric.MeasurementOption {
		return metric.WithAttributeSet(attribute.NewSet(append(attrs[:len(attrs):len(attrs)], attribute.String("network.io.direction", d))...))
	}
	c := &connMetrics{
		m:   m,
		dst: metric.WithAttributeSet(attribute.NewSet(attrs...)),
		tx:  direction("transmit"),
		rx:  direction("receive"),
	}
	ctx := context.Background()
	m.dialDuration.Record(ctx, dialTook.Seconds(), c.dst)
	m.connCount.Add(ctx, 1)
	return c
}

// closed records the connection's duration and stops counting it as open.
func (c *connMetrics) closed(took time.Duration) {
	if c == nil {
		return
	}
	ctx := context.Background()
	c.m.connCount.Add(ctx, -1)
	c.m.connDuration.Record(ctx, took.Seconds(), c.dst)
}

// count returns upstream wrapped so that every byte read from it or written
// to it is counted as it passes. With no metrics it returns upstream itself,
// so io.Copy keeps its *net.TCPConn fast path.
func (c *connMetrics) count(upstream net.Conn) net.Conn {
	if c == nil {
		return upstream
	}
	return &countingConn{Conn: upstream, c: c}
}

// countingConn counts the bytes of an upstream connection. It embeds the
// net.Conn interface, not *net.TCPConn, on purpose: the concrete type's
// ReadFrom and WriteTo would move bytes in the kernel, past Read and Write.
type countingConn struct {
	net.Conn
	c *connMetrics
}

func (cc *countingConn) Read(p []byte) (int, error) {
	n, err := cc.Conn.Read(p)
	if n > 0 {
		cc.c.m.io.Add(context.Background(), int64(n), cc.c.rx)
	}
	return n, err
}

func (cc *countingConn) Write(p []byte) (int, error) {
	n, err := cc.Conn.Write(p)
	if n > 0 {
		cc.c.m.io.Add(context.Background(), int64(n), cc.c.tx)
	}
	return n, err
}

// CloseWrite half-closes the upstream connection, as splice needs.
func (cc *countingConn) CloseWrite() error {
	if hc, ok := cc.Conn.(interface{ CloseWrite() error }); ok {
		return hc.CloseWrite()
	}
	return nil
}

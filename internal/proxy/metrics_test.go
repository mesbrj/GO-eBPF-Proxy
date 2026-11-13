package proxy

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"net/netip"
	"os"
	"sync"
	"syscall"
	"testing"
	"time"

	ciliumebpf "github.com/cilium/ebpf"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.opentelemetry.io/otel/attribute"
	sdkmetric "go.opentelemetry.io/otel/sdk/metric"
	"go.opentelemetry.io/otel/sdk/metric/metricdata"

	bpf "github.com/mesbrj/netloupe-tap/bpf"
)

// foundLookuper resolves every source tuple to val; unlike stubLookuper it is
// safe for concurrent connections.
type foundLookuper struct{ val bpf.ProxyOrigDst }

func (f foundLookuper) Lookup(_, valueOut any) error {
	*(valueOut.(*bpf.ProxyOrigDst)) = f.val
	return nil
}

// missLookuper holds no tuple, so every lookup is a definitive miss.
type missLookuper struct{}

func (missLookuper) Lookup(_, _ any) error { return ciliumebpf.ErrKeyNotExist }

// deltaExceptUpDown is the temporality the sidecar exports with (door 3).
func deltaExceptUpDown(k sdkmetric.InstrumentKind) metricdata.Temporality {
	if k == sdkmetric.InstrumentKindUpDownCounter {
		return metricdata.CumulativeTemporality
	}
	return metricdata.DeltaTemporality
}

// meteredRelay serves a relay over m that records into a manual reader, and
// returns the relay's address and a function that takes one collection, keyed
// by metric name.
func meteredRelay(t *testing.T, m Lookuper) (string, func() map[string]metricdata.Metrics) {
	t.Helper()
	reader := sdkmetric.NewManualReader(sdkmetric.WithTemporalitySelector(deltaExceptUpDown))
	mp := sdkmetric.NewMeterProvider(sdkmetric.WithReader(reader))
	t.Cleanup(func() { _ = mp.Shutdown(context.Background()) })

	ln, err := net.Listen("tcp", "127.0.0.1:0")
	require.NoError(t, err)
	t.Cleanup(func() { _ = ln.Close() })
	relay := NewRelay(NewResolver(m, WithRetry(0, 0)), WithDialTimeout(2*time.Second), WithMeterProvider(mp))
	go func() { _ = relay.Serve(ln) }()

	collect := func() map[string]metricdata.Metrics {
		t.Helper()
		var rm metricdata.ResourceMetrics
		require.NoError(t, reader.Collect(context.Background(), &rm))
		got := map[string]metricdata.Metrics{}
		for _, sm := range rm.ScopeMetrics {
			for _, m := range sm.Metrics {
				got[m.Name] = m
			}
		}
		return got
	}
	return ln.Addr().String(), collect
}

// echoUpstream starts a loopback echo server and returns its port and the
// lookuper that resolves every connection to it.
func echoUpstream(t *testing.T) (int, Lookuper) {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	require.NoError(t, err)
	t.Cleanup(func() { _ = ln.Close() })
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			go func(c net.Conn) { _, _ = io.Copy(c, c); _ = c.Close() }(c)
		}
	}()
	port := ln.Addr().(*net.TCPAddr).Port
	return port, foundLookuper{val: origDst(t, "127.0.0.1", uint16(port))} // #nosec G115 -- TCPAddr.Port is always 0-65535
}

// closedPort returns a loopback port nothing listens on, and the lookuper that
// resolves every connection to it.
func closedPort(t *testing.T) (int, Lookuper) {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	require.NoError(t, err)
	port := ln.Addr().(*net.TCPAddr).Port
	require.NoError(t, ln.Close())
	return port, foundLookuper{val: origDst(t, "127.0.0.1", uint16(port))} // #nosec G115 -- TCPAddr.Port is always 0-65535
}

// roundTrip sends n bytes on c and reads them back.
func roundTrip(t *testing.T, c net.Conn, n int) {
	t.Helper()
	require.NoError(t, c.SetDeadline(time.Now().Add(5*time.Second)))
	_, err := c.Write(make([]byte, n))
	require.NoError(t, err)
	_, err = io.ReadFull(c, make([]byte, n))
	require.NoError(t, err)
}

// untilEOF reads c until the relay closes it.
func untilEOF(t *testing.T, c net.Conn) {
	t.Helper()
	require.NoError(t, c.SetDeadline(time.Now().Add(5*time.Second)))
	_, err := io.Copy(io.Discard, c)
	require.NoError(t, err)
}

func dial(t *testing.T, addr string) net.Conn {
	t.Helper()
	c, err := net.Dial("tcp", addr)
	require.NoError(t, err)
	t.Cleanup(func() { _ = c.Close() })
	return c
}

// dstSet is the destination attribute pair D for a loopback port, plus extra.
func dstSet(port int, extra ...attribute.KeyValue) attribute.Set {
	return attribute.NewSet(append([]attribute.KeyValue{
		attribute.String("server.address", "127.0.0.1"),
		attribute.Int("server.port", port),
	}, extra...)...)
}

// sumPoints returns a sum metric's value per attribute set; an absent metric
// has none.
func sumPoints(t *testing.T, m metricdata.Metrics) map[attribute.Distinct]int64 {
	t.Helper()
	got := map[attribute.Distinct]int64{}
	if m.Data == nil {
		return got
	}
	sum, ok := m.Data.(metricdata.Sum[int64])
	require.True(t, ok, "%s is %T, want an int64 sum", m.Name, m.Data)
	for _, dp := range sum.DataPoints {
		got[dp.Attributes.Equivalent()] = dp.Value
	}
	return got
}

// histPoints returns a histogram metric's data points; an absent metric has
// none.
func histPoints(t *testing.T, m metricdata.Metrics) []metricdata.HistogramDataPoint[float64] {
	t.Helper()
	if m.Data == nil {
		return nil
	}
	h, ok := m.Data.(metricdata.Histogram[float64])
	require.True(t, ok, "%s is %T, want a float64 histogram", m.Name, m.Data)
	return h.DataPoints
}

// dstKey is dstSet as the key sumPoints indexes by.
func dstKey(port int, extra ...attribute.KeyValue) attribute.Distinct {
	set := dstSet(port, extra...)
	return set.Equivalent()
}

// noAttrs is the key of a data point with no attributes.
func noAttrs() attribute.Distinct {
	set := attribute.NewSet()
	return set.Equivalent()
}

// ioBytes takes collections until the io deltas for port add up to wantTx
// transmitted and wantRx received bytes. The relay counts a write just after
// it returns, so the peer's answer can reach the client first: the two
// directions may arrive in different collections.
func ioBytes(t *testing.T, collect func() map[string]metricdata.Metrics, port int, wantTx, wantRx int64) {
	t.Helper()
	var tx, rx int64
	assert.Eventually(t, func() bool {
		io := sumPoints(t, collect()[metricIO])
		tx += io[dstKey(port, direction("transmit"))]
		rx += io[dstKey(port, direction("receive"))]
		return tx == wantTx && rx == wantRx
	}, 5*time.Second, 10*time.Millisecond)
	assert.Equal(t, wantTx, tx, "bytes written to the upstream")
	assert.Equal(t, wantRx, rx, "bytes read from the upstream")
}

func direction(d string) attribute.KeyValue { return attribute.String("network.io.direction", d) }

// openConnections reads connection.count, which is 0 when it has no point.
func openConnections(t *testing.T, got map[string]metricdata.Metrics) (int64, []metricdata.DataPoint[int64]) {
	t.Helper()
	m := got[metricConnCount]
	if m.Data == nil {
		return 0, nil
	}
	sum := m.Data.(metricdata.Sum[int64])
	var total int64
	for _, dp := range sum.DataPoints {
		total += dp.Value
	}
	return total, sum.DataPoints
}

// C6 (AC 5, door 4): without a provider the upstream connection reaches the
// copy as the *net.TCPConn that was dialled, so the kernel fast path stays;
// with one it is wrapped.
func TestRelay_WithoutMeterProviderKeepsTheTCPConn(t *testing.T) {
	port, m := echoUpstream(t)
	dst := netip.MustParseAddrPort(fmt.Sprintf("127.0.0.1:%d", port))
	upstream := dial(t, dst.String())
	require.IsType(t, &net.TCPConn{}, upstream)

	for name, opts := range map[string][]RelayOption{
		"no option":    nil,
		"nil provider": {WithMeterProvider(nil)},
	} {
		t.Run(name, func(t *testing.T) {
			rl := NewRelay(NewResolver(m), opts...)
			assert.Same(t, upstream, rl.metrics.connOpened(dst, 0).count(upstream))
		})
	}

	t.Run("with a provider", func(t *testing.T) {
		mp := sdkmetric.NewMeterProvider()
		t.Cleanup(func() { _ = mp.Shutdown(context.Background()) })
		rl := NewRelay(NewResolver(m), WithMeterProvider(mp))
		_, isTCP := rl.metrics.connOpened(dst, 0).count(upstream).(*net.TCPConn)
		assert.False(t, isTCP, "a metered relay must count through its own wrapper")
	})
}

// C15 (AC 11, AC 12): bytes written to and read from the upstream are counted
// per direction under the original destination.
func TestRelay_CountsBytesPerDirection(t *testing.T) {
	port, m := echoUpstream(t)
	addr, collect := meteredRelay(t, m)

	c := dial(t, addr)
	roundTrip(t, c, 1000)
	require.NoError(t, c.Close())

	ioBytes(t, collect, port, 1000, 1000)
}

// C16 (AC 13): the bytes are counted as they pass, not when the connection
// closes.
func TestRelay_BytesAreCountedWhileTheConnectionIsOpen(t *testing.T) {
	port, m := echoUpstream(t)
	addr, collect := meteredRelay(t, m)

	c := dial(t, addr)
	roundTrip(t, c, 1000) // the echo came back, so both directions have passed the relay

	ioBytes(t, collect, port, 1000, 1000)
	open, _ := openConnections(t, collect())
	assert.Equal(t, int64(1), open, "precondition: the connection is still open")
}

// C17 (AC 14): the wrapper must not swallow the half-close, or an upstream
// that answers only after EOF never answers.
func TestRelay_HalfCloseSurvivesMetrics(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	require.NoError(t, err)
	t.Cleanup(func() { _ = ln.Close() })
	go func() {
		c, err := ln.Accept()
		if err != nil {
			return
		}
		defer func() { _ = c.Close() }()
		req, _ := io.ReadAll(c) // returns only once the relay half-closes
		_, _ = fmt.Fprintf(c, "got %d bytes", len(req))
	}()
	port := ln.Addr().(*net.TCPAddr).Port
	addr, _ := meteredRelay(t, foundLookuper{val: origDst(t, "127.0.0.1", uint16(port))}) // #nosec G115 -- TCPAddr.Port is always 0-65535

	c := dial(t, addr)
	require.NoError(t, c.SetDeadline(time.Now().Add(5*time.Second)))
	_, err = c.Write([]byte("request"))
	require.NoError(t, err)
	require.NoError(t, c.(*net.TCPConn).CloseWrite())

	reply, err := io.ReadAll(c)
	require.NoError(t, err)
	assert.Equal(t, "got 7 bytes", string(reply))
}

// C18 (AC 15, AC 17): connection.count is the number of connections being
// piped, as one series with no attributes.
func TestRelay_ConnectionCountFollowsOpenConnections(t *testing.T) {
	_, m := echoUpstream(t)
	addr, collect := meteredRelay(t, m)

	c := dial(t, addr)
	roundTrip(t, c, 1)
	open, points := openConnections(t, collect())
	assert.Equal(t, int64(1), open)
	require.Len(t, points, 1)
	assert.Zero(t, points[0].Attributes.Len(), "connection.count carries no attributes")

	require.NoError(t, c.Close())
	require.Eventually(t, func() bool {
		open, _ := openConnections(t, collect())
		return open == 0
	}, 5*time.Second, 10*time.Millisecond)
	_, points = openConnections(t, collect())
	require.Len(t, points, 1)
	assert.Zero(t, points[0].Attributes.Len())
}

// C19 (AC 16): one duration per relayed connection, covering the time it was
// held open.
func TestRelay_RecordsConnectionDurationOnClose(t *testing.T) {
	port, m := echoUpstream(t)
	addr, collect := meteredRelay(t, m)

	c := dial(t, addr)
	roundTrip(t, c, 1)
	assert.Empty(t, histPoints(t, collect()[metricConnDuration]), "nothing is recorded while the connection is open")
	time.Sleep(200 * time.Millisecond)
	require.NoError(t, c.Close())

	var points []metricdata.HistogramDataPoint[float64]
	require.Eventually(t, func() bool {
		points = histPoints(t, collect()[metricConnDuration])
		return len(points) > 0
	}, 5*time.Second, 10*time.Millisecond)
	require.Len(t, points, 1)
	assert.Equal(t, uint64(1), points[0].Count)
	assert.GreaterOrEqual(t, points[0].Sum, 0.2)
	assert.Less(t, points[0].Sum, 5.0)
	assert.True(t, points[0].Attributes.Equals(ptr(dstSet(port))), "attributes: %v", points[0].Attributes)
}

func ptr[T any](v T) *T { return &v }

// C20 (AC 11, AC 12, AC 15, AC 16): concurrent connections lose no count.
func TestRelay_ConcurrentConnectionsAreCountedExactly(t *testing.T) {
	port, m := echoUpstream(t)
	addr, collect := meteredRelay(t, m)

	const conns, size = 50, 1000
	var wg sync.WaitGroup
	for range conns {
		wg.Go(func() {
			c, err := net.Dial("tcp", addr)
			if !assert.NoError(t, err) {
				return
			}
			defer func() { _ = c.Close() }()
			_ = c.SetDeadline(time.Now().Add(10 * time.Second))
			if _, err := c.Write(make([]byte, size)); !assert.NoError(t, err) {
				return
			}
			_, err = io.ReadFull(c, make([]byte, size))
			assert.NoError(t, err)
		})
	}
	wg.Wait()

	// Deltas arrive over several collections while the relay finishes closing.
	var tx, rx int64
	var durations uint64
	require.Eventually(t, func() bool {
		got := collect()
		io := sumPoints(t, got[metricIO])
		tx += io[dstKey(port, direction("transmit"))]
		rx += io[dstKey(port, direction("receive"))]
		for _, p := range histPoints(t, got[metricConnDuration]) {
			durations += p.Count
		}
		open, _ := openConnections(t, got)
		return durations == conns && open == 0
	}, 10*time.Second, 10*time.Millisecond)
	assert.Equal(t, int64(conns*size), tx)
	assert.Equal(t, int64(conns*size), rx)
	assert.Equal(t, uint64(conns), durations)
}

// C21 (AC 18): one dial duration per successful dial.
func TestRelay_RecordsDialDurationOnSuccess(t *testing.T) {
	port, m := echoUpstream(t)
	addr, collect := meteredRelay(t, m)

	c := dial(t, addr)
	roundTrip(t, c, 1)

	points := histPoints(t, collect()[metricDialDuration])
	require.Len(t, points, 1)
	assert.Equal(t, uint64(1), points[0].Count)
	assert.GreaterOrEqual(t, points[0].Sum, 0.0)
	assert.Less(t, points[0].Sum, 2.0)
	assert.True(t, points[0].Attributes.Equals(ptr(dstSet(port))), "attributes: %v", points[0].Attributes)
}

// C22 (AC 19): a refused dial is counted under its destination and type.
func TestRelay_CountsDialErrorByType(t *testing.T) {
	port, m := closedPort(t)
	addr, collect := meteredRelay(t, m)

	untilEOF(t, dial(t, addr))

	errs := sumPoints(t, collect()[metricDialErrors])
	require.Len(t, errs, 1)
	assert.Equal(t, int64(1), errs[dstKey(port, attribute.String("error.type", "refused"))])
}

// timeoutError is a net.Error that reports a timeout, as a dial past its
// deadline does.
type timeoutError struct{}

func (timeoutError) Error() string   { return "i/o timeout" }
func (timeoutError) Timeout() bool   { return true }
func (timeoutError) Temporary() bool { return true }

// C23 (AC 20): the four error types, one case per row and per errno.
func TestDialErrorType(t *testing.T) {
	dialErr := func(err error) error {
		return &net.OpError{Op: "dial", Net: "tcp", Err: os.NewSyscallError("connect", err)}
	}
	for _, tc := range []struct {
		name string
		err  error
		want string
	}{
		{"net.Error timeout", &net.OpError{Op: "dial", Net: "tcp", Err: timeoutError{}}, "timeout"},
		{"ETIMEDOUT", dialErr(syscall.ETIMEDOUT), "timeout"},
		{"ECONNREFUSED", dialErr(syscall.ECONNREFUSED), "refused"},
		{"ENETUNREACH", dialErr(syscall.ENETUNREACH), "unreachable"},
		{"EHOSTUNREACH", dialErr(syscall.EHOSTUNREACH), "unreachable"},
		{"ECONNRESET", dialErr(syscall.ECONNRESET), "_OTHER"},
		{"unrelated error", errors.New("no route for this test"), "_OTHER"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			assert.Equal(t, tc.want, dialErrorType(tc.err))
		})
	}
}

// C24 (AC 21): a failed dial moves only dial.errors.
func TestRelay_FailedDialRecordsNothingElse(t *testing.T) {
	_, m := closedPort(t)
	addr, collect := meteredRelay(t, m)

	untilEOF(t, dial(t, addr))

	got := collect()
	require.Len(t, sumPoints(t, got[metricDialErrors]), 1, "precondition: the dial failed")
	assert.Empty(t, histPoints(t, got[metricDialDuration]))
	assert.Empty(t, histPoints(t, got[metricConnDuration]))
	open, _ := openConnections(t, got)
	assert.Zero(t, open)
}

// miss connects to the relay and waits for its fail-closed reset.
func miss(t *testing.T, addr string) {
	t.Helper()
	c, err := net.Dial("tcp", addr)
	if err != nil {
		// The relay resets a miss at once; on a fast loopback the RST can land
		// before connect returns. The miss was counted before the reset.
		require.ErrorIs(t, err, syscall.ECONNRESET)
		return
	}
	defer func() { _ = c.Close() }()
	require.NoError(t, c.SetDeadline(time.Now().Add(5*time.Second)))
	_, _ = io.Copy(io.Discard, c) // a RST or EOF: either way the relay is done with it
}

// C25 (AC 22): resolve.misses reports the resolver's own count, as a delta,
// with no attributes.
func TestRelay_ResolveMissesReportsTheResolverCount(t *testing.T) {
	addr, collect := meteredRelay(t, missLookuper{})

	miss(t, addr)
	miss(t, addr)
	m := collect()[metricMisses]
	sum, ok := m.Data.(metricdata.Sum[int64])
	require.True(t, ok, "resolve.misses is %T", m.Data)
	require.Len(t, sum.DataPoints, 1)
	assert.Equal(t, int64(2), sum.DataPoints[0].Value)
	assert.Zero(t, sum.DataPoints[0].Attributes.Len(), "resolve.misses carries no attributes")

	miss(t, addr)
	next := sumPoints(t, collect()[metricMisses])
	assert.Equal(t, int64(1), next[noAttrs()], "the next collection reports only the new miss")
}

// C26 (AC 23): a miss moves only resolve.misses.
func TestRelay_MissRecordsNothingElse(t *testing.T) {
	addr, collect := meteredRelay(t, missLookuper{})

	miss(t, addr)

	got := collect()
	require.Equal(t, int64(1), sumPoints(t, got[metricMisses])[noAttrs()], "precondition: the miss was counted")
	assert.Empty(t, sumPoints(t, got[metricIO]))
	assert.Empty(t, sumPoints(t, got[metricDialErrors]))
	assert.Empty(t, histPoints(t, got[metricDialDuration]))
	assert.Empty(t, histPoints(t, got[metricConnDuration]))
	open, _ := openConnections(t, got)
	assert.Zero(t, open)
}

// C27 (AC 24, door 3): the bucket bounds are in seconds and fixed.
func TestRelay_HistogramBounds(t *testing.T) {
	_, m := echoUpstream(t)
	addr, collect := meteredRelay(t, m)

	c := dial(t, addr)
	roundTrip(t, c, 1)
	require.NoError(t, c.Close())

	// The two histograms are deltas recorded at different moments (dial, then
	// close), so they may arrive in different collections.
	bounds := map[string][]float64{}
	require.Eventually(t, func() bool {
		got := collect()
		for _, name := range []string{metricDialDuration, metricConnDuration} {
			if points := histPoints(t, got[name]); len(points) == 1 {
				bounds[name] = points[0].Bounds
			}
		}
		return len(bounds) == 2
	}, 5*time.Second, 10*time.Millisecond)
	assert.Equal(t,
		[]float64{0.001, 0.0025, 0.005, 0.01, 0.025, 0.05, 0.1, 0.25, 0.5, 1, 2.5, 5},
		bounds[metricDialDuration])
	assert.Equal(t,
		[]float64{0.01, 0.05, 0.1, 0.5, 1, 5, 10, 30, 60, 300, 900, 3600, 14400, 86400},
		bounds[metricConnDuration])
}

// C33 (AC 30): the dial.errors point carries the destination and one of four
// fixed types, never the error's own text.
func TestRelay_DialErrorAttributesCarryNoErrorText(t *testing.T) {
	_, m := closedPort(t)
	addr, collect := meteredRelay(t, m)

	untilEOF(t, dial(t, addr))

	sum, ok := collect()[metricDialErrors].Data.(metricdata.Sum[int64])
	require.True(t, ok)
	require.Len(t, sum.DataPoints, 1)
	for _, kv := range sum.DataPoints[0].Attributes.ToSlice() {
		value := kv.Value.String()
		if kv.Key == "error.type" {
			assert.Contains(t, []string{"timeout", "refused", "unreachable", "_OTHER"}, value)
			continue
		}
		assert.NotContains(t, value, "refused", "%s", kv.Key)
		assert.NotContains(t, value, "dial tcp", "%s", kv.Key)
		assert.NotContains(t, value, "connect:", "%s", kv.Key)
	}
}

// C49 (AC 11, AC 12): the two directions are told apart. The upstream answers
// a 1,000-byte request with 300 bytes, so swapped labels cannot pass.
func TestRelay_DirectionsAreNotInterchangeable(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	require.NoError(t, err)
	t.Cleanup(func() { _ = ln.Close() })
	go func() {
		c, err := ln.Accept()
		if err != nil {
			return
		}
		defer func() { _ = c.Close() }()
		if _, err := io.ReadFull(c, make([]byte, 1000)); err != nil {
			return
		}
		_, _ = c.Write(make([]byte, 300))
	}()
	port := ln.Addr().(*net.TCPAddr).Port
	addr, collect := meteredRelay(t, foundLookuper{val: origDst(t, "127.0.0.1", uint16(port))}) // #nosec G115 -- TCPAddr.Port is always 0-65535

	c := dial(t, addr)
	require.NoError(t, c.SetDeadline(time.Now().Add(5*time.Second)))
	_, err = c.Write(make([]byte, 1000))
	require.NoError(t, err)
	_, err = io.ReadFull(c, make([]byte, 300))
	require.NoError(t, err)

	ioBytes(t, collect, port, 1000, 300)
}

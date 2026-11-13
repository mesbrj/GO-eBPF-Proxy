package main

import (
	"compress/gzip"
	"context"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.opentelemetry.io/otel/attribute"
	"go.opentelemetry.io/otel/metric"
	sdkmetric "go.opentelemetry.io/otel/sdk/metric"
	colmetricpb "go.opentelemetry.io/proto/otlp/collector/metrics/v1"
	commonpb "go.opentelemetry.io/proto/otlp/common/v1"
	metricpb "go.opentelemetry.io/proto/otlp/metrics/v1"
	"google.golang.org/protobuf/proto"

	bpf "github.com/mesbrj/netloupe-tap/bpf"
	"github.com/mesbrj/netloupe-tap/internal/ebpf"
	"github.com/mesbrj/netloupe-tap/internal/shared/logger"
)

// exportRequest is one request a collector received.
type exportRequest struct {
	at              time.Time
	method, path    string
	contentType     string
	contentEncoding string
	header          http.Header
	body            *colmetricpb.ExportMetricsServiceRequest
	decodeErr       error
}

// collector is a local OTLP/HTTP metrics collector: it records each request,
// decodes its body, and answers with status (200 unless set). With hang set
// it never answers until the test ends.
type collector struct {
	url    string
	status int
	hang   chan struct{}

	mu   sync.Mutex
	reqs []exportRequest
}

func newCollector(t *testing.T, status int, hang bool) *collector {
	t.Helper()
	c := &collector{status: status}
	if hang {
		c.hang = make(chan struct{})
	}
	srv := httptest.NewServer(http.HandlerFunc(c.serve))
	t.Cleanup(func() {
		if c.hang != nil {
			close(c.hang)
		}
		srv.Close()
	})
	c.url = srv.URL
	return c
}

func (c *collector) serve(w http.ResponseWriter, r *http.Request) {
	req := exportRequest{
		at:              time.Now(),
		method:          r.Method,
		path:            r.URL.Path,
		contentType:     r.Header.Get("Content-Type"),
		contentEncoding: r.Header.Get("Content-Encoding"),
		header:          r.Header.Clone(),
	}
	var body io.Reader = r.Body
	if req.contentEncoding == "gzip" {
		zr, err := gzip.NewReader(r.Body)
		if err != nil {
			req.decodeErr = err
		} else {
			body = zr
		}
	}
	if req.decodeErr == nil {
		raw, err := io.ReadAll(body)
		req.decodeErr = err
		if err == nil {
			req.body = &colmetricpb.ExportMetricsServiceRequest{}
			req.decodeErr = proto.Unmarshal(raw, req.body)
		}
	}
	c.mu.Lock()
	c.reqs = append(c.reqs, req)
	c.mu.Unlock()

	if c.hang != nil {
		select {
		case <-c.hang:
		case <-r.Context().Done():
		}
		return
	}
	if c.status != 0 {
		w.WriteHeader(c.status)
	}
}

func (c *collector) requests() []exportRequest {
	c.mu.Lock()
	defer c.mu.Unlock()
	return append([]exportRequest(nil), c.reqs...)
}

// metrics returns every metric the collector received, grouped by name, in
// arrival order.
func (c *collector) metrics() map[string][]*metricpb.Metric {
	got := map[string][]*metricpb.Metric{}
	for _, req := range c.requests() {
		for _, rm := range req.body.GetResourceMetrics() {
			for _, sm := range rm.GetScopeMetrics() {
				for _, m := range sm.GetMetrics() {
					got[m.GetName()] = append(got[m.GetName()], m)
				}
			}
		}
	}
	return got
}

// metricsOn starts the sidecar's metrics against endpoint and returns the
// provider and the log. The provider is shut down when the test ends, unless
// the test already did.
func metricsOn(t *testing.T, endpoint string, interval time.Duration, limit int64) (*sdkmetric.MeterProvider, *syncBuffer) {
	t.Helper()
	logs := &syncBuffer{}
	cfg := DefaultConfig()
	cfg.MetricsEndpoint = endpoint
	cfg.MetricsInterval = interval
	cfg.MetricsCardinalityLimit = limit
	mp, err := startMetrics(cfg, logger.New(logs))
	require.NoError(t, err)
	require.NotNil(t, mp)
	t.Cleanup(func() {
		ctx, cancel := context.WithTimeout(context.Background(), time.Second)
		defer cancel()
		_ = mp.Shutdown(ctx)
	})
	return mp, logs
}

// closedAddr returns a loopback address nothing listens on.
func closedAddr(t *testing.T) netip.AddrPort {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	require.NoError(t, err)
	addr := ln.Addr().(*net.TCPAddr).AddrPort()
	require.NoError(t, ln.Close())
	return addr
}

// echoAddr starts a loopback echo server and returns its address.
func echoAddr(t *testing.T) netip.AddrPort {
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
	return ln.Addr().(*net.TCPAddr).AddrPort()
}

// resolveInTurn is an origdst_by_tuple stand-in that resolves the first
// connection to dsts[0], the next to dsts[1] and so on, and misses every
// lookup after the last.
func resolveInTurn(t *testing.T, dsts ...netip.AddrPort) lookupFunc {
	t.Helper()
	ods := make([]bpf.ProxyOrigDst, len(dsts))
	for i, dst := range dsts {
		od, err := ebpf.OrigDst(dst.Addr(), dst.Port())
		require.NoError(t, err)
		ods[i] = od
	}
	var calls atomic.Int64
	return func(_, valueOut any) error {
		i := int(calls.Add(1)) - 1
		if i >= len(ods) {
			return missEverything(nil, nil)
		}
		*(valueOut.(*bpf.ProxyOrigDst)) = ods[i]
		return nil
	}
}

// meteredRelay serves cmd/app's own relay over m, recording into mp and
// logging into the returned buffer, and returns its address.
func meteredRelay(t *testing.T, m lookupFunc, mp *sdkmetric.MeterProvider) (string, *syncBuffer) {
	t.Helper()
	logs := &syncBuffer{}
	log := logger.New(logs)
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	require.NoError(t, err)
	t.Cleanup(func() { _ = ln.Close() })
	go func() { _ = newRelay(newResolver(m, log), log, mp).Serve(ln) }()
	return ln.Addr().String(), logs
}

// echoRoundTrip sends n bytes through the relay at addr and reads them back,
// leaving the connection open; the returned func closes it.
func echoRoundTrip(t *testing.T, addr string, n int) func() {
	t.Helper()
	c, err := net.Dial("tcp", addr)
	require.NoError(t, err)
	t.Cleanup(func() { _ = c.Close() })
	require.NoError(t, c.SetDeadline(time.Now().Add(5*time.Second)))
	_, err = c.Write(make([]byte, n))
	require.NoError(t, err)
	_, err = io.ReadFull(c, make([]byte, n))
	require.NoError(t, err, "the relay must carry the echo back")
	return func() { _ = c.Close() }
}

// connectUntilClosed connects to the relay at addr and waits until the relay
// is done with the connection: a failed dial or a fail-closed miss.
func connectUntilClosed(t *testing.T, addr string) {
	t.Helper()
	c, err := net.Dial("tcp", addr)
	require.NoError(t, err)
	defer func() { _ = c.Close() }()
	require.NoError(t, c.SetDeadline(time.Now().Add(5*time.Second)))
	_, _ = io.Copy(io.Discard, c)
}

// mixedTraffic drives one relayed connection, one failed dial and one
// resolver miss through a relay recording into mp, and returns once all three
// are over.
func mixedTraffic(t *testing.T, mp *sdkmetric.MeterProvider) {
	t.Helper()
	addr, _ := meteredRelay(t, resolveInTurn(t, echoAddr(t), closedAddr(t)), mp)
	echoRoundTrip(t, addr, 1000)()
	connectUntilClosed(t, addr)
	connectUntilClosed(t, addr)
}

// The six metric names of door 3.
var relayMetricNames = []string{
	"netloupe.tap.relay.io",
	"netloupe.tap.relay.connection.duration",
	"netloupe.tap.relay.connection.count",
	"netloupe.tap.relay.dial.duration",
	"netloupe.tap.relay.dial.errors",
	"netloupe.tap.relay.resolve.misses",
}

// allSixExported waits until the collector has received each of the six
// metrics at least once, and returns the first of each.
func allSixExported(t *testing.T, c *collector) map[string]*metricpb.Metric {
	t.Helper()
	first := map[string]*metricpb.Metric{}
	require.Eventually(t, func() bool {
		got := c.metrics()
		for _, name := range relayMetricNames {
			if len(got[name]) == 0 {
				return false
			}
			first[name] = got[name][0]
		}
		return true
	}, 5*time.Second, 10*time.Millisecond, "the collector must receive all six metrics")
	return first
}

// dataPointAttrs returns the attributes of each data point of m.
func dataPointAttrs(m *metricpb.Metric) [][]*commonpb.KeyValue {
	var attrs [][]*commonpb.KeyValue
	for _, dp := range m.GetSum().GetDataPoints() {
		attrs = append(attrs, dp.GetAttributes())
	}
	for _, dp := range m.GetHistogram().GetDataPoints() {
		attrs = append(attrs, dp.GetAttributes())
	}
	return attrs
}

// C1 (AC 1): pushes start within one interval and repeat every interval,
// traffic or not.
func TestMetrics_ExportsEveryIntervalFromStartup(t *testing.T) {
	c := newCollector(t, 0, false)
	start := time.Now()
	mp, _ := metricsOn(t, c.url, 100*time.Millisecond, 2000)
	meteredRelay(t, missEverything, mp)

	require.Eventually(t, func() bool { return len(c.requests()) >= 3 }, 2*time.Second, 10*time.Millisecond)
	assert.Less(t, c.requests()[0].at.Sub(start), time.Second, "the first push comes within a second of startup")
}

// C2 (AC 2): the wire is gzip protobuf over an HTTP POST.
func TestMetrics_RequestIsGzipProtobufPost(t *testing.T) {
	c := newCollector(t, 0, false)
	mp, _ := metricsOn(t, c.url, 50*time.Millisecond, 2000)
	meteredRelay(t, missEverything, mp)

	require.Eventually(t, func() bool { return len(c.requests()) >= 1 }, 2*time.Second, 10*time.Millisecond)
	req := c.requests()[0]
	assert.Equal(t, http.MethodPost, req.method)
	assert.Equal(t, "application/x-protobuf", req.contentType)
	assert.Equal(t, "gzip", req.contentEncoding)
	require.NoError(t, req.decodeErr, "the body must gunzip and unmarshal as an ExportMetricsServiceRequest")
	assert.NotEmpty(t, req.body.GetResourceMetrics())
}

// C3 (AC 3): every push names the sidecar.
func TestMetrics_ResourceNamesTheService(t *testing.T) {
	c := newCollector(t, 0, false)
	mp, _ := metricsOn(t, c.url, 50*time.Millisecond, 2000)
	meteredRelay(t, missEverything, mp)

	require.Eventually(t, func() bool { return len(c.requests()) >= 2 }, 2*time.Second, 10*time.Millisecond)
	for _, req := range c.requests() {
		require.NotEmpty(t, req.body.GetResourceMetrics())
		for _, rm := range req.body.GetResourceMetrics() {
			var names []string
			for _, kv := range rm.GetResource().GetAttributes() {
				if kv.GetKey() == "service.name" {
					names = append(names, kv.GetValue().GetStringValue())
				}
			}
			assert.Equal(t, []string{"netloupe-tap"}, names)
		}
	}
}

// C4 (AC 4): an endpoint with no path gets the OTLP default; any other path
// is used as given.
func TestMetrics_EndpointPath(t *testing.T) {
	for suffix, want := range map[string]string{
		"":                 "/v1/metrics",
		"/":                "/",
		"/otlp/v1/metrics": "/otlp/v1/metrics",
	} {
		t.Run("endpoint path "+suffix, func(t *testing.T) {
			c := newCollector(t, 0, false)
			mp, _ := metricsOn(t, c.url+suffix, 50*time.Millisecond, 2000)
			meteredRelay(t, missEverything, mp)

			require.Eventually(t, func() bool { return len(c.requests()) >= 1 }, 2*time.Second, 10*time.Millisecond)
			assert.Equal(t, want, c.requests()[0].path)
		})
	}
}

// C5 (AC 5): with no endpoint there is nothing to start.
func TestStartMetrics_EmptyEndpointBuildsNothing(t *testing.T) {
	logs := &syncBuffer{}

	mp, err := startMetrics(DefaultConfig(), logger.New(logs))

	require.NoError(t, err)
	assert.Nil(t, mp)
	assert.Empty(t, logs.String())
}

// C12 (AC 10, as amended): the start line carries the endpoint the sidecar
// pushes to, and the interval.
func TestStartMetrics_LogsStartWithEndpointAndInterval(t *testing.T) {
	c := newCollector(t, 0, false)

	_, logs := metricsOn(t, c.url, 5*time.Second, 2000)

	records := logRecords(t, logs, "metrics export started")
	require.Len(t, records, 1)
	assert.Equal(t, "INFO", records[0].Level)
	assert.Equal(t, c.url+"/v1/metrics", records[0].Context["endpoint"])
	assert.Equal(t, "5s", records[0].Context["interval"])
}

// C55 (AC 43): OTEL_EXPORTER_OTLP_HEADERS is how a credential reaches the
// collector, in the percent-encoded form the README gives, and it reaches
// nothing else: not the log.
func TestMetrics_HeadersVariableReachesTheCollectorNotTheLog(t *testing.T) {
	t.Setenv("OTEL_EXPORTER_OTLP_HEADERS", "Authorization=Bearer%20s3cr3t-token,X-Scope=tap")
	c := newCollector(t, 0, false)
	mp, logs := metricsOn(t, c.url, 50*time.Millisecond, 2000)
	meteredRelay(t, missEverything, mp)

	require.Eventually(t, func() bool { return len(c.requests()) >= 1 }, 2*time.Second, 10*time.Millisecond)
	req := c.requests()[0]
	assert.Equal(t, "Bearer s3cr3t-token", req.header.Get("Authorization"))
	assert.Equal(t, "tap", req.header.Get("X-Scope"))
	assert.NotContains(t, logs.String(), "s3cr3t-token")
}

// C54 (AC 10, as amended): the start refuses an endpoint with credentials on
// its own too, not only through loadConfig.
func TestStartMetrics_RefusesEndpointWithCredentials(t *testing.T) {
	logs := &syncBuffer{}
	cfg := DefaultConfig()
	cfg.MetricsEndpoint = "http://user:hunter2@collector:4318"

	mp, err := startMetrics(cfg, logger.New(logs))

	require.Error(t, err)
	assert.Nil(t, mp)
	assert.Contains(t, err.Error(), "OTEL_EXPORTER_OTLP_HEADERS")
	assert.NotContains(t, err.Error(), "hunter2")
	assert.Empty(t, logs.String())
}

// C28 (AC 25): past the limit, attribute sets fold into one overflow series
// and no count is lost.
func TestMetrics_CardinalityLimitFoldsIntoOverflow(t *testing.T) {
	c := newCollector(t, 0, false)
	mp, logs := metricsOn(t, c.url, time.Hour, 3)
	addr, _ := meteredRelay(t, resolveInTurn(t,
		closedAddr(t), closedAddr(t), closedAddr(t), closedAddr(t), closedAddr(t)), mp)
	for range 5 {
		connectUntilClosed(t, addr)
	}

	stopMetrics(mp, logger.New(logs)) // the one export

	errs := c.metrics()["netloupe.tap.relay.dial.errors"]
	require.Len(t, errs, 1)
	points := errs[0].GetSum().GetDataPoints()
	require.Len(t, points, 3)
	var total int64
	var overflow int
	for _, dp := range points {
		total += dp.GetAsInt()
		if attrs := dp.GetAttributes(); len(attrs) == 1 && attrs[0].GetKey() == "otel.metric.overflow" && attrs[0].GetValue().GetBoolValue() {
			overflow++
		}
	}
	assert.Equal(t, 1, overflow, "exactly one series holds only otel.metric.overflow=true")
	assert.Equal(t, int64(5), total)
}

// C29 (AC 26): 0 lifts the limit, past the SDK's own default of 2000.
func TestMetrics_ZeroCardinalityLimitMeansNoLimit(t *testing.T) {
	c := newCollector(t, 0, false)
	mp, logs := metricsOn(t, c.url, time.Hour, 0)
	probe, err := mp.Meter("test").Int64Counter("probe")
	require.NoError(t, err)
	for i := range 2100 {
		probe.Add(context.Background(), 1, metric.WithAttributes(attribute.Int("n", i)))
	}

	stopMetrics(mp, logger.New(logs))

	got := c.metrics()["probe"]
	require.Len(t, got, 1)
	points := got[0].GetSum().GetDataPoints()
	assert.Len(t, points, 2100)
	for _, dp := range points {
		for _, kv := range dp.GetAttributes() {
			require.NotEqual(t, "otel.metric.overflow", kv.GetKey())
		}
	}
}

// C30 (AC 27, door 3): what only grows is exported as deltas, the open
// connection count as a running total.
func TestMetrics_Temporality(t *testing.T) {
	c := newCollector(t, 0, false)
	mp, _ := metricsOn(t, c.url, 50*time.Millisecond, 2000)
	mixedTraffic(t, mp)
	got := allSixExported(t, c)

	const (
		delta      = metricpb.AggregationTemporality_AGGREGATION_TEMPORALITY_DELTA
		cumulative = metricpb.AggregationTemporality_AGGREGATION_TEMPORALITY_CUMULATIVE
	)
	for _, name := range []string{"netloupe.tap.relay.io", "netloupe.tap.relay.dial.errors", "netloupe.tap.relay.resolve.misses"} {
		sum := got[name].GetSum()
		require.NotNil(t, sum, "%s must be a sum", name)
		assert.Equal(t, delta, sum.GetAggregationTemporality(), name)
		assert.True(t, sum.GetIsMonotonic(), name)
	}
	for _, name := range []string{"netloupe.tap.relay.connection.duration", "netloupe.tap.relay.dial.duration"} {
		hist := got[name].GetHistogram()
		require.NotNil(t, hist, "%s must be a histogram", name)
		assert.Equal(t, delta, hist.GetAggregationTemporality(), name)
	}
	count := got["netloupe.tap.relay.connection.count"].GetSum()
	require.NotNil(t, count, "connection.count must be a sum")
	assert.Equal(t, cumulative, count.GetAggregationTemporality())
	assert.False(t, count.GetIsMonotonic())
}

// C31 (AC 28, door 3): the names, scope, units and instrument types are the
// contract dashboards bind to.
func TestMetrics_ExportsExactlyTheSixMetrics(t *testing.T) {
	c := newCollector(t, 0, false)
	mp, _ := metricsOn(t, c.url, 50*time.Millisecond, 2000)
	mixedTraffic(t, mp)
	got := allSixExported(t, c)

	var names []string
	for name := range c.metrics() {
		names = append(names, name)
	}
	assert.ElementsMatch(t, relayMetricNames, names)
	for _, req := range c.requests() {
		for _, rm := range req.body.GetResourceMetrics() {
			for _, sm := range rm.GetScopeMetrics() {
				assert.Equal(t, "github.com/mesbrj/netloupe-tap/internal/proxy", sm.GetScope().GetName())
			}
		}
	}

	for name, unit := range map[string]string{
		"netloupe.tap.relay.io":                  "By",
		"netloupe.tap.relay.connection.duration": "s",
		"netloupe.tap.relay.connection.count":    "{connection}",
		"netloupe.tap.relay.dial.duration":       "s",
		"netloupe.tap.relay.dial.errors":         "{error}",
		"netloupe.tap.relay.resolve.misses":      "{miss}",
	} {
		assert.Equal(t, unit, got[name].GetUnit(), name)
	}
	for _, counter := range []string{"netloupe.tap.relay.io", "netloupe.tap.relay.dial.errors", "netloupe.tap.relay.resolve.misses"} {
		require.NotNil(t, got[counter].GetSum(), "%s must be a counter", counter)
		assert.True(t, got[counter].GetSum().GetIsMonotonic(), counter)
	}
	for _, hist := range []string{"netloupe.tap.relay.connection.duration", "netloupe.tap.relay.dial.duration"} {
		assert.NotNil(t, got[hist].GetHistogram(), "%s must be a histogram", hist)
	}
	upDown := got["netloupe.tap.relay.connection.count"].GetSum()
	require.NotNil(t, upDown, "connection.count must be an up-down counter")
	assert.False(t, upDown.GetIsMonotonic())
}

// C32 (AC 29): no data point carries an attribute outside the closed set,
// with or without the overflow series.
func TestMetrics_AttributeKeysAreTheClosedSet(t *testing.T) {
	allowed := []string{"server.address", "server.port", "network.io.direction", "error.type", "otel.metric.overflow"}
	seen := map[string]bool{}
	for _, limit := range []int64{2000, 2} {
		c := newCollector(t, 0, false)
		mp, _ := metricsOn(t, c.url, 50*time.Millisecond, limit)
		mixedTraffic(t, mp)
		allSixExported(t, c)

		for name, metrics := range c.metrics() {
			for _, m := range metrics {
				for _, attrs := range dataPointAttrs(m) {
					for _, kv := range attrs {
						assert.Contains(t, allowed, kv.GetKey(), "%s, limit %d", name, limit)
						seen[kv.GetKey()] = true
					}
				}
			}
		}
	}
	for _, key := range allowed {
		assert.True(t, seen[key], "precondition: the traffic must exercise %s", key)
	}
}

// C34 (AC 31): a collector that is down fails neither the start nor the relay.
func TestMetrics_UnreachableCollectorStillRelays(t *testing.T) {
	mp, _ := metricsOn(t, "http://"+closedAddr(t).String(), 50*time.Millisecond, 2000)
	addr, _ := meteredRelay(t, resolveInTurn(t, echoAddr(t)), mp)

	echoRoundTrip(t, addr, 1000)()
}

// C36 (AC 32): each way a push can fail is a WARN, and the relay goes on.
func TestMetrics_ExportFailureLogsWarnAndKeepsRelaying(t *testing.T) {
	for name, endpoint := range map[string]func(t *testing.T) string{
		"503":         func(t *testing.T) string { return newCollector(t, http.StatusServiceUnavailable, false).url },
		"400":         func(t *testing.T) string { return newCollector(t, http.StatusBadRequest, false).url },
		"no response": func(t *testing.T) string { return "http://" + closedAddr(t).String() },
	} {
		t.Run(name, func(t *testing.T) {
			mp, logs := metricsOn(t, endpoint(t), 50*time.Millisecond, 2000)
			addr, _ := meteredRelay(t, resolveInTurn(t, echoAddr(t)), mp)

			var failures []logRecord
			require.Eventually(t, func() bool {
				failures = logRecords(t, logs, "metrics export failed")
				return len(failures) > 0
			}, 5*time.Second, 10*time.Millisecond)
			assert.Equal(t, "WARN", failures[0].Level)
			assert.NotEmpty(t, failures[0].Context["error"])

			echoRoundTrip(t, addr, 1000)()
		})
	}
}

// C37 (AC 33): a collector that stays down does not flood the log.
func TestMetrics_ExportFailureWarnIsRateLimited(t *testing.T) {
	mp, logs := metricsOn(t, "http://"+closedAddr(t).String(), 20*time.Millisecond, 2000)
	meteredRelay(t, missEverything, mp)

	time.Sleep(time.Second)

	failures := len(logRecords(t, logs, "metrics export failed"))
	assert.GreaterOrEqual(t, failures, 1)
	assert.LessOrEqual(t, failures, 10)
}

// ioBytes sums the io data points of every request for one direction.
func ioBytes(c *collector, direction string) int64 {
	var total int64
	for _, m := range c.metrics()["netloupe.tap.relay.io"] {
		for _, dp := range m.GetSum().GetDataPoints() {
			for _, kv := range dp.GetAttributes() {
				if kv.GetKey() == "network.io.direction" && kv.GetValue().GetStringValue() == direction {
					total += dp.GetAsInt()
				}
			}
		}
	}
	return total
}

// C38 (AC 34): what was recorded since the last push leaves in one final
// push during Close.
func TestApp_CloseSendsOneFinalExport(t *testing.T) {
	c := newCollector(t, 0, false)
	mp, logs := metricsOn(t, c.url, time.Hour, 2000)
	addr, _ := meteredRelay(t, resolveInTurn(t, echoAddr(t)), mp)
	// Half-close and read to EOF: the relay ends each direction only after it
	// has counted every byte of it, so the counts are final before Close.
	conn, err := net.Dial("tcp", addr)
	require.NoError(t, err)
	defer func() { _ = conn.Close() }()
	require.NoError(t, conn.SetDeadline(time.Now().Add(5*time.Second)))
	_, err = conn.Write(make([]byte, 1000))
	require.NoError(t, err)
	require.NoError(t, conn.(*net.TCPConn).CloseWrite())
	echoed, err := io.ReadAll(conn)
	require.NoError(t, err)
	require.Len(t, echoed, 1000)
	require.Empty(t, c.requests(), "precondition: nothing is pushed before Close")

	a := &App{log: logger.New(logs), metrics: mp}
	require.NoError(t, a.Close())

	assert.Len(t, c.requests(), 1)
	assert.Equal(t, int64(1000), ioBytes(c, "transmit"))
	assert.Equal(t, int64(1000), ioBytes(c, "receive"))
	assert.Empty(t, logRecords(t, logs, "metrics shutdown failed"))
}

// C39, C40 (AC 35, AC 36): a collector that never answers holds Close for
// five seconds, no longer, and does not fail it.
func TestApp_CloseAbandonsAHungFinalExportAfterFiveSeconds(t *testing.T) {
	c := newCollector(t, 0, true)
	mp, logs := metricsOn(t, c.url, time.Hour, 2000)
	meteredRelay(t, missEverything, mp)

	a := &App{log: logger.New(logs), metrics: mp}
	start := time.Now()
	err := a.Close()
	took := time.Since(start)

	require.NoError(t, err)
	assert.GreaterOrEqual(t, took, 4900*time.Millisecond)
	assert.Less(t, took, 5900*time.Millisecond, "C53: the bound is 5 s, not 6")
	failed := logRecords(t, logs, "metrics shutdown failed")
	require.Len(t, failed, 1)
	assert.Equal(t, "WARN", failed[0].Level)
}

// C40 (AC 36): a final push that fails is a WARN, not a failed shutdown.
func TestApp_CloseWithFailedFinalExportReturnsNil(t *testing.T) {
	mp, logs := metricsOn(t, "http://"+closedAddr(t).String(), time.Hour, 2000)
	meteredRelay(t, missEverything, mp)

	a := &App{log: logger.New(logs), metrics: mp}
	require.NoError(t, a.Close())

	failed := logRecords(t, logs, "metrics shutdown failed")
	require.Len(t, failed, 1)
	assert.Equal(t, "WARN", failed[0].Level)
}

// C41 (Impact): recording metrics changes none of the relay's log lines, nor
// the stats line's miss counter.
func TestNewRelay_LogsAreUnchangedWithMetrics(t *testing.T) {
	c := newCollector(t, 0, false)
	mp, _ := metricsOn(t, c.url, time.Hour, 2000)
	echo, closed := echoAddr(t), closedAddr(t)
	a, logs, _ := statsApp(t, resolveInTurn(t, echo, closed), 0)
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	require.NoError(t, err)
	t.Cleanup(func() { _ = ln.Close() })
	go func() { _ = newRelay(a.resolver, a.log, mp).Serve(ln) }()
	addr := ln.Addr().String()

	echoRoundTrip(t, addr, 1000)()
	connectUntilClosed(t, addr)
	connectUntilClosed(t, addr)
	a.logStats()

	relayed := logRecords(t, logs, "connection relayed")
	require.Len(t, relayed, 1)
	assert.Equal(t, "INFO", relayed[0].Level)
	assert.Equal(t, echo.String(), relayed[0].Context["orig_dst"])
	failed := logRecords(t, logs, "upstream dial failed")
	require.Len(t, failed, 1)
	assert.Equal(t, "WARN", failed[0].Level)
	assert.Equal(t, closed.String(), failed[0].Context["orig_dst"])
	stats := logRecords(t, logs, "stats")
	require.Len(t, stats, 1)
	assert.InDelta(t, 1, stats[0].Context["origdst_lookup_miss"], 0)
}

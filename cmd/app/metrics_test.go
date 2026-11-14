package main

import (
	"bufio"
	"compress/gzip"
	"context"
	"errors"
	"io"
	stdlog "log"
	"log/slog"
	"net"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"net/url"
	"os"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/go-logr/logr"
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
// decodes its body, and answers with status (200 unless set), or as answer
// says when it is set. With hang set it never answers until the test ends.
type collector struct {
	url    string
	status int
	hang   chan struct{}
	answer http.HandlerFunc

	mu   sync.Mutex
	reqs []exportRequest
}

func newCollector(t *testing.T, status int, hang bool) *collector {
	t.Helper()
	c := &collector{status: status}
	if hang {
		c.hang = make(chan struct{})
	}
	return c.start(t)
}

// newAnsweringCollector is a collector that records each request and then
// lets answer write the response.
func newAnsweringCollector(t *testing.T, answer http.HandlerFunc) *collector {
	t.Helper()
	return (&collector{answer: answer}).start(t)
}

// start serves c on a loopback port until the test ends.
func (c *collector) start(t *testing.T) *collector {
	t.Helper()
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
	if c.answer != nil {
		c.answer(w, r)
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
	mp, err := startMetrics(cfg, sidecarLogger(logs))
	require.NoError(t, err)
	require.NotNil(t, mp)
	t.Cleanup(func() {
		ctx, cancel := context.WithTimeout(context.Background(), time.Second)
		defer cancel()
		_ = mp.Shutdown(ctx)
	})
	return mp, logs
}

// sidecarLogger returns a logger writing into logs, built as main builds the
// sidecar's from the process environment, header masking included.
func sidecarLogger(logs *syncBuffer) *logger.Logger {
	return newLogger(logs, slog.LevelInfo, os.Environ())
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
	assert.Contains(t, err.Error(), "metrics-endpoint")
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

// C60 (AC 43): the SDK's own diagnostics go through the sidecar's log without
// the values the SDK attaches, so a header it could not parse is reported
// and never printed. startMetrics is called directly: loadConfig would have
// refused this variable first (C59).
func TestStartMetrics_SDKDiagnosticsNeverCarryTheirInput(t *testing.T) {
	t.Setenv("OTEL_EXPORTER_OTLP_HEADERS", "Authorization: Bearer HSECRET")
	c := newCollector(t, 0, false)

	_, logs := metricsOn(t, c.url, time.Hour, 2000)

	diagnostics := logRecords(t, logs, "metrics sdk error")
	require.NotEmpty(t, diagnostics, "the SDK's parse error must arrive in the sidecar's log")
	assert.Equal(t, "WARN", diagnostics[0].Level)
	assert.Equal(t, "parse headers", diagnostics[0].Context["sdk_message"])
	assert.NotContains(t, logs.String(), "HSECRET")
	assert.NotContains(t, logs.String(), "Bearer")
}

// C63 (AC 47): the SDK's diagnostics reach the log as the SDK's message
// alone. An endpoint variable that does not parse is quoted whole in the
// SDK's error, password included, so the error text must not be logged
// either. The flag's endpoint still wins: the push goes to the collector.
func TestStartMetrics_SDKDiagnosticsNeverCarryTheirErrorText(t *testing.T) {
	for _, name := range []string{"OTEL_EXPORTER_OTLP_ENDPOINT", "OTEL_EXPORTER_OTLP_METRICS_ENDPOINT"} {
		t.Run(name, func(t *testing.T) {
			t.Setenv(name, "http://user:ESECRET@[::1")
			c := newCollector(t, 0, false)

			mp, logs := metricsOn(t, c.url, 50*time.Millisecond, 2000)
			meteredRelay(t, missEverything, mp)

			diagnostics := logRecords(t, logs, "metrics sdk error")
			require.NotEmpty(t, diagnostics, "the SDK's parse error must arrive in the sidecar's log")
			assert.Equal(t, map[string]any{"sdk_message": "parse url"}, diagnostics[0].Context)
			require.Eventually(t, func() bool { return len(c.requests()) >= 1 }, 2*time.Second, 10*time.Millisecond)
			assert.NotContains(t, logs.String(), "ESECRET")
			assert.NotContains(t, logs.String(), "[::1")
		})
	}
}

// C63 (AC 47), at the sink itself: whatever the SDK hands over, only its
// message is logged; informational messages are not logged at all.
func TestSDKLogSink_LogsTheMessageAlone(t *testing.T) {
	logs := &syncBuffer{}
	sink := sdkLogSink{log: logger.New(logs)}
	sdk := logr.New(sink)

	sdk.Error(errors.New("parse \"http://user:ESECRET@host\": bad"), "parse url", "input", "http://user:KSECRET@host")
	sdk.WithValues("token", "VSECRET").WithName("NSECRET").Error(nil, "second")
	sdk.Info("an informational ISECRET")
	sdk.V(8).Info("a debug ISECRET")
	sink.Info(0, "handed straight to the sink ISECRET", "token", "VSECRET") // past logr's own level gate

	records := logRecords(t, logs, "metrics sdk error")
	require.Len(t, records, 2)
	assert.Equal(t, map[string]any{"sdk_message": "parse url"}, records[0].Context)
	assert.Equal(t, map[string]any{"sdk_message": "second"}, records[1].Context)
	assert.NotContains(t, logs.String(), "SECRET")
}

// C65 (AC 48): a resource variable that does not parse fails the start
// without repeating the entry.
func TestStartMetrics_MalformedResourceAttributesAreNotEchoed(t *testing.T) {
	t.Setenv("OTEL_RESOURCE_ATTRIBUTES", "RSECRET-with-no-equals")
	logs := &syncBuffer{}
	cfg := DefaultConfig()
	cfg.MetricsEndpoint = "http://collector:4318"

	mp, err := startMetrics(cfg, logger.New(logs))

	require.Error(t, err)
	assert.Nil(t, mp)
	assert.Contains(t, err.Error(), "OTEL_RESOURCE_ATTRIBUTES")
	assert.NotContains(t, err.Error(), "RSECRET")
	assert.NotContains(t, logs.String(), "RSECRET")
}

// The collector credential the masking tests configure: an Authorization
// header and a vendor key header, as OTEL_EXPORTER_OTLP_HEADERS spells them.
const (
	echoBearer    = "Bearer tok-0123456789abcdef"
	echoToken     = "tok-0123456789abcdef"
	echoAPIKey    = "key-fedcba9876543210"
	echoHeaderVar = "Authorization=Bearer%20tok-0123456789abcdef,X-Api-Key=key-fedcba9876543210"
)

// requireNoHeaderValue fails when text holds a configured header value in
// any of the forms it can come back in.
func requireNoHeaderValue(t *testing.T, text string) {
	t.Helper()
	for _, form := range []string{
		echoBearer, echoToken, echoAPIKey,
		url.QueryEscape(echoBearer), url.PathEscape(echoBearer),
	} {
		require.NotContains(t, text, form)
	}
}

// C69 (AC 43): a collector that sends the header value back, in the body of
// its answer or in the URL of a redirect, has it logged with the failed push.
// Both failure lines carry the answer with the value masked, however it is
// spelled, and nothing else in the log holds it.
func TestMetrics_HeaderSentBackByTheCollectorIsMasked(t *testing.T) {
	moved := "http://" + closedAddr(t).String() + "/moved"
	for name, answer := range map[string]http.HandlerFunc{
		"the header in a 401 body": func(w http.ResponseWriter, r *http.Request) {
			http.Error(w, "invalid credentials: "+r.Header.Get("Authorization")+" / "+r.Header.Get("X-Api-Key"), http.StatusUnauthorized)
		},
		"the token alone in a 403 body": func(w http.ResponseWriter, r *http.Request) {
			http.Error(w, "token "+strings.TrimPrefix(r.Header.Get("Authorization"), "Bearer ")+" is not allowed here", http.StatusForbidden)
		},
		"the header percent-encoded in a 400 body": func(w http.ResponseWriter, r *http.Request) {
			http.Error(w, "bad header "+url.PathEscape(r.Header.Get("Authorization")), http.StatusBadRequest)
		},
		"the header percent-encoded in a redirect": func(w http.ResponseWriter, r *http.Request) {
			target := moved + "?auth=" + url.QueryEscape(r.Header.Get("Authorization")) + "&key=" + r.Header.Get("X-Api-Key")
			http.Redirect(w, r, target, http.StatusTemporaryRedirect) // #nosec G710 -- a test collector that redirects with the header on purpose
		},
		"the header as written in a redirect": func(w http.ResponseWriter, r *http.Request) {
			w.Header().Set("Location", moved+"?auth="+r.Header.Get("Authorization"))
			w.WriteHeader(http.StatusTemporaryRedirect)
		},
	} {
		t.Run(name, func(t *testing.T) {
			t.Setenv("OTEL_EXPORTER_OTLP_HEADERS", echoHeaderVar)
			c := newAnsweringCollector(t, answer)
			mp, logs := metricsOn(t, c.url, 50*time.Millisecond, 2000)
			meteredRelay(t, missEverything, mp)

			var failed []logRecord
			require.Eventually(t, func() bool {
				failed = logRecords(t, logs, "metrics export failed")
				return len(failed) > 0
			}, 5*time.Second, 10*time.Millisecond)
			require.NotEmpty(t, c.requests())
			require.Equal(t, echoBearer, c.requests()[0].header.Get("Authorization"), "precondition: the collector was sent the header")
			stopMetrics(mp, sidecarLogger(logs))
			stopped := logRecords(t, logs, "metrics shutdown failed")
			require.Len(t, stopped, 1)

			for _, rec := range append(logRecords(t, logs, "metrics export failed"), stopped...) {
				assert.Contains(t, rec.Context["error"], "***REDACTED***", "the line shows where the collector's answer held the value")
			}
			requireNoHeaderValue(t, logs.String())
		})
	}
}

// C70 (AC 50): the collector does not size the log line. Whatever it answers,
// the error text of the failed push is cut to 1,024 bytes, followed by the
// number of bytes left out.
func TestMetrics_FailedPushErrorTextIsCut(t *testing.T) {
	c := newAnsweringCollector(t, func(w http.ResponseWriter, _ *http.Request) {
		http.Error(w, strings.Repeat("x", 100_000), http.StatusBadRequest)
	})
	mp, logs := metricsOn(t, c.url, 50*time.Millisecond, 2000)
	meteredRelay(t, missEverything, mp)

	var failed []logRecord
	require.Eventually(t, func() bool {
		failed = logRecords(t, logs, "metrics export failed")
		return len(failed) > 0
	}, 5*time.Second, 10*time.Millisecond)
	stopMetrics(mp, sidecarLogger(logs))
	stopped := logRecords(t, logs, "metrics shutdown failed")
	require.Len(t, stopped, 1)

	for _, rec := range append(failed[:1], stopped...) {
		text, ok := rec.Context["error"].(string)
		require.True(t, ok)
		kept, left, found := strings.Cut(text, "… (")
		require.True(t, found, "the text must say it was cut: %q", text[len(text)-40:])
		assert.Len(t, kept, 1024)
		assert.Regexp(t, `^\d+ more bytes\)$`, left)
		assert.Contains(t, kept, "400 Bad Request", "the start of the error survives the cut")
	}
}

// C70 (AC 50), through a real failed push: a collector's answer that puts the
// header value across byte 1,024 of the error text leaves no head of it in
// the line. The line is written by the rate-limited logger, which must mask
// before the cut like the logger it derives from.
func TestMetrics_HeaderAcrossTheCutLeavesNoHead(t *testing.T) {
	t.Setenv("OTEL_EXPORTER_OTLP_HEADERS", echoHeaderVar)
	// The error text opens with about 110 bytes before the body (the two
	// prefixes, the URL and the status), so 901 bytes of padding start the
	// 27-byte header value some 13 bytes before the cut.
	c := newAnsweringCollector(t, func(w http.ResponseWriter, r *http.Request) {
		http.Error(w, strings.Repeat("x", 901)+r.Header.Get("Authorization")+strings.Repeat("y", 200), http.StatusBadRequest)
	})
	mp, logs := metricsOn(t, c.url, 50*time.Millisecond, 2000)
	meteredRelay(t, missEverything, mp)

	var failed []logRecord
	require.Eventually(t, func() bool {
		failed = logRecords(t, logs, "metrics export failed")
		return len(failed) > 0
	}, 5*time.Second, 10*time.Millisecond)

	text, ok := failed[0].Context["error"].(string)
	require.True(t, ok)
	kept, _, found := strings.Cut(text, "… (")
	require.True(t, found, "precondition: the text was cut")
	body := strings.Index(kept, strings.Repeat("x", 901))
	require.Positive(t, body, "precondition: the padding is in the kept text")
	require.Greater(t, body+901, 1024-len(echoBearer), "precondition: the value starts close enough to the cut to cross it")
	require.Less(t, body+901, 1024, "precondition: the value starts before the cut")
	masked := kept[:body+901] + "***REDACTED***" + strings.Repeat("y", 200)
	assert.Equal(t, masked[:1024], kept, "the padding, then the mask in place of the value, cut at 1,024 bytes")
	assert.NotContains(t, logs.String(), "Bearer t", "no head of the value")
	assert.NotContains(t, logs.String(), "tok-0", "no head of the token")
}

// C70 (AC 50): the text is masked before it is cut, so a masked value that
// straddles the cut leaves no head behind, and the cut never splits a
// character.
func TestPeerText_MasksThenCutsAtACharacterBoundary(t *testing.T) {
	secret := strings.Repeat("S3cr3t!", 10)
	log := logger.New(io.Discard, logger.WithMasked(secret))

	t.Run("short text is logged whole", func(t *testing.T) {
		assert.Equal(t, "refused", peerText(log, "refused"))
		assert.Equal(t, strings.Repeat("x", 1024), peerText(log, strings.Repeat("x", 1024)))
	})
	t.Run("a masked value across the cut", func(t *testing.T) {
		// The value starts 24 bytes before the cut and ends 46 bytes after it.
		text := peerText(log, strings.Repeat("x", 1000)+secret+strings.Repeat("y", 100))

		kept, left, found := strings.Cut(text, "… (")
		require.True(t, found)
		assert.Equal(t, strings.Repeat("x", 1000)+"***REDACTED***"+strings.Repeat("y", 10), kept)
		assert.Equal(t, "90 more bytes)", left)
		assert.NotContains(t, text, "S3cr3t")
	})
	t.Run("a character across the cut", func(t *testing.T) {
		// "a" then two-byte characters: byte 1024 is the second half of one.
		text := peerText(log, "a"+strings.Repeat("é", 600))

		kept, left, found := strings.Cut(text, "… (")
		require.True(t, found)
		assert.Equal(t, "a"+strings.Repeat("é", 511), kept)
		assert.Equal(t, "178 more bytes)", left)
	})
}

// unsolicitedCollector is a collector that answers a push with a complete
// 200 and then, on the same connection, with a second answer nobody asked
// for that repeats the Authorization header. Go's HTTP client reports such
// bytes through the standard logger, quoting them. It returns its URL.
func unsolicitedCollector(t *testing.T) string {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	require.NoError(t, err)
	t.Cleanup(func() { _ = ln.Close() })
	go func() {
		for {
			conn, err := ln.Accept()
			if err != nil {
				return
			}
			go func(conn net.Conn) {
				defer func() { _ = conn.Close() }()
				req, err := http.ReadRequest(bufio.NewReader(conn))
				if err != nil {
					return
				}
				_, _ = io.Copy(io.Discard, req.Body)
				_, _ = io.WriteString(conn, "HTTP/1.1 200 OK\r\nContent-Length: 0\r\n\r\n"+
					"HTTP/1.1 400 Bad Request\r\nX-Echo: "+req.Header.Get("Authorization")+"\r\n\r\n")
			}(conn)
		}
	}()
	return "http://" + ln.Addr().String()
}

// restoreStdLog puts Go's standard logger back as it was when the test ends.
func restoreStdLog(t *testing.T) {
	t.Helper()
	out, flags := stdlog.Writer(), stdlog.Flags()
	t.Cleanup(func() {
		stdlog.SetOutput(out)
		stdlog.SetFlags(flags)
	})
}

// C75 (AC 52): what Go's standard logger is given comes out as a WARN record
// of the sidecar's log, masked and cut like the error of a failed push.
func TestCaptureStdLog_WritesThroughTheSidecarLogger(t *testing.T) {
	t.Setenv("OTEL_EXPORTER_OTLP_HEADERS", echoHeaderVar)
	restoreStdLog(t)
	logs := &syncBuffer{}
	captureStdLog(sidecarLogger(logs))

	stdlog.Printf("Unsolicited response received on idle HTTP channel starting with %q; err=%v", "X-Echo: "+echoBearer, nil)
	stdlog.Print(strings.Repeat("x", 5000))

	records := logRecords(t, logs, "go library log")
	require.Len(t, records, 2)
	assert.Equal(t, "WARN", records[0].Level)
	assert.Equal(t, `Unsolicited response received on idle HTTP channel starting with "X-Echo: ***REDACTED***"; err=<nil>`, records[0].Context["text"])
	kept, left, found := strings.Cut(records[1].Context["text"].(string), "… (")
	require.True(t, found, "a long message must say it was cut")
	assert.Equal(t, strings.Repeat("x", 1024), kept)
	assert.Equal(t, "3976 more bytes)", left)
	requireNoHeaderValue(t, logs.String())
}

// C75 (AC 52): a collector that sends the header back in bytes nobody asked
// for has them reported by Go's HTTP client. With the standard logger
// captured, the report is a record of the sidecar's log with the header
// masked.
func TestMetrics_UnsolicitedAnswerWithTheHeaderIsMasked(t *testing.T) {
	t.Setenv("OTEL_EXPORTER_OTLP_HEADERS", echoHeaderVar)
	restoreStdLog(t)
	stdLogs := &syncBuffer{}
	captureStdLog(sidecarLogger(stdLogs))
	mp, logs := metricsOn(t, unsolicitedCollector(t), 50*time.Millisecond, 2000)
	meteredRelay(t, missEverything, mp)

	require.Eventually(t, func() bool { return strings.Contains(stdLogs.String(), "go library log") },
		5*time.Second, 10*time.Millisecond, "Go's HTTP client must report the unsolicited bytes")
	report := logRecords(t, stdLogs, "go library log")[0]
	assert.Contains(t, report.Context["text"], "Unsolicited response received")
	assert.Contains(t, report.Context["text"], "X-Echo: ***REDACTED***")
	requireNoHeaderValue(t, stdLogs.String())
	requireNoHeaderValue(t, logs.String())
}

// A collector credential whose values hold characters Go escapes when it
// quotes a text with %q, a double quote and a backslash, and one it does not
// escape, a printable letter outside ASCII.
const (
	quotedHeaderVar = `Authorization=Token token="tok-0123456789abcdef",X-Api-Key=dom\svc-0123456789abcdef,X-Pass=p%C3%A4"ss-0123456789abcdef`
	quotedToken     = "tok-0123456789abcdef"
	quotedAPIKey    = "svc-0123456789abcdef"
	quotedPass      = "ss-0123456789abcdef"
)

// C69 (AC 43): Go quotes a redirect's URL with %q in the error of the failed
// push, so a header value with a double quote or a backslash reaches the log
// escaped. It is masked in that spelling too, as it is when the collector
// sends it back as it was sent.
func TestMetrics_QuotedHeaderSentBackIsMasked(t *testing.T) {
	moved := "http://" + closedAddr(t).String() + "/moved"
	for name, answer := range map[string]http.HandlerFunc{
		"as sent, in a 401 body": func(w http.ResponseWriter, r *http.Request) {
			http.Error(w, "invalid credentials: "+r.Header.Get("Authorization")+" / "+r.Header.Get("X-Api-Key")+" / "+r.Header.Get("X-Pass"), http.StatusUnauthorized)
		},
		"as sent, in the URL of a redirect, which Go quotes": func(w http.ResponseWriter, r *http.Request) {
			w.Header().Set("Location", moved+"?auth="+r.Header.Get("Authorization")+"&key="+r.Header.Get("X-Api-Key")+"&pass="+r.Header.Get("X-Pass"))
			w.WriteHeader(http.StatusTemporaryRedirect)
		},
	} {
		t.Run(name, func(t *testing.T) {
			t.Setenv("OTEL_EXPORTER_OTLP_HEADERS", quotedHeaderVar)
			c := newAnsweringCollector(t, answer)
			mp, logs := metricsOn(t, c.url, 50*time.Millisecond, 2000)
			meteredRelay(t, missEverything, mp)

			require.Eventually(t, func() bool { return len(logRecords(t, logs, "metrics export failed")) > 0 },
				5*time.Second, 10*time.Millisecond)
			require.NotEmpty(t, c.requests())
			require.Equal(t, `Token token="`+quotedToken+`"`, c.requests()[0].header.Get("Authorization"), "precondition: the collector was sent the header")
			require.Equal(t, `dom\`+quotedAPIKey, c.requests()[0].header.Get("X-Api-Key"))
			require.Equal(t, `pä"`+quotedPass, c.requests()[0].header.Get("X-Pass"))
			stopMetrics(mp, sidecarLogger(logs))
			stopped := logRecords(t, logs, "metrics shutdown failed")
			require.Len(t, stopped, 1)

			for _, rec := range append(logRecords(t, logs, "metrics export failed"), stopped...) {
				assert.Contains(t, rec.Context["error"], "***REDACTED***")
			}
			assert.NotContains(t, logs.String(), quotedToken)
			assert.NotContains(t, logs.String(), quotedAPIKey)
			assert.NotContains(t, logs.String(), quotedPass)
		})
	}
}

// C75 (AC 52): Go's HTTP client quotes a server's unsolicited bytes with %q,
// so a header value with a double quote or a backslash arrives escaped. It is
// masked in that spelling.
func TestCaptureStdLog_MasksAValueGoQuoted(t *testing.T) {
	t.Setenv("OTEL_EXPORTER_OTLP_HEADERS", quotedHeaderVar)
	restoreStdLog(t)
	logs := &syncBuffer{}
	captureStdLog(sidecarLogger(logs))

	echoed := []byte("HTTP/1.1 400 Bad Request\r\nX-Echo: Token token=\"" + quotedToken + "\"\r\nX-Key: dom\\" + quotedAPIKey + "\r\nX-Pass: pä\"" + quotedPass + "\r\n\r\n")
	stdlog.Printf("Unsolicited response received on idle HTTP channel starting with %q; err=%v", echoed, nil)

	records := logRecords(t, logs, "go library log")
	require.Len(t, records, 1)
	assert.Equal(t, `Unsolicited response received on idle HTTP channel starting with "HTTP/1.1 400 Bad Request\r\nX-Echo: ***REDACTED***\r\nX-Key: ***REDACTED***\r\nX-Pass: ***REDACTED***\r\n\r\n"; err=<nil>`, records[0].Context["text"])
	assert.NotContains(t, logs.String(), quotedToken)
	assert.NotContains(t, logs.String(), quotedAPIKey)
	assert.NotContains(t, logs.String(), quotedPass)
}

// C75 (AC 52): a peer can make Go's libraries log at will, so at most 10 of
// their messages a minute become records; the rest are dropped.
func TestCaptureStdLog_KeepsTenMessagesAMinute(t *testing.T) {
	restoreStdLog(t)
	logs := &syncBuffer{}
	captureStdLog(sidecarLogger(logs))

	for i := range 25 {
		stdlog.Printf("message %d", i)
	}

	records := logRecords(t, logs, "go library log")
	require.Len(t, records, 10)
	assert.Equal(t, "message 0", records[0].Context["text"])
	assert.Equal(t, "message 9", records[9].Context["text"])
}

// C69 (AC 43): a header value is masked in every spelling it can come back
// in, each proven on a failed push. A collector that redirects with a header
// as it received it, in any one part of the URL: Go writes the URL out again
// for the error and escapes the path, the fragment and the userinfo each in
// its own way; the query it keeps as received and then quotes. And a
// collector that percent-encodes the header itself, as a query or as a path
// segment. Each value is one that only its own case spells the way the log
// shows it, so every spelling is needed.
func TestMetrics_HeaderInEachSpellingIsMasked(t *testing.T) {
	const headers = `X-Path=p/a!t"h-0123456789abcdef,X-Frag=f!r"ag-0123456789abcdef,X-User=us@e%2Cr-0123456789abcdef,` +
		`X-Query=q"ry-0123456789abcdef,X-B64=abc+def/0123456789abcdef==,X-Seg=a%2Cb+c-0123456789abcdef`
	closed := closedAddr(t).String()
	redirect := func(location func(r *http.Request) string) http.HandlerFunc {
		return func(w http.ResponseWriter, r *http.Request) {
			w.Header().Set("Location", location(r))
			w.WriteHeader(http.StatusTemporaryRedirect)
		}
	}
	for name, answer := range map[string]http.HandlerFunc{
		"as received, in a redirect's path": redirect(func(r *http.Request) string {
			return "http://" + closed + "/moved/" + r.Header.Get("X-Path")
		}),
		"as received, in a redirect's fragment": redirect(func(r *http.Request) string {
			return "http://" + closed + "/moved#" + r.Header.Get("X-Frag")
		}),
		"as received, in a redirect's userinfo": redirect(func(r *http.Request) string {
			return "http://" + r.Header.Get("X-User") + "@" + closed + "/moved"
		}),
		"as received, in a redirect's query": redirect(func(r *http.Request) string {
			return "http://" + closed + "/moved?auth=" + r.Header.Get("X-Query")
		}),
		"query-escaped by the collector, in a redirect's query": redirect(func(r *http.Request) string {
			return "http://" + closed + "/moved?auth=" + url.QueryEscape(r.Header.Get("X-B64"))
		}),
		"path-escaped by the collector, in a 400 body": func(w http.ResponseWriter, r *http.Request) {
			http.Error(w, "bad header "+url.PathEscape(r.Header.Get("X-Seg")), http.StatusBadRequest)
		},
	} {
		t.Run(name, func(t *testing.T) {
			t.Setenv("OTEL_EXPORTER_OTLP_HEADERS", headers)
			c := newAnsweringCollector(t, answer)
			mp, logs := metricsOn(t, c.url, 50*time.Millisecond, 2000)
			meteredRelay(t, missEverything, mp)

			var failed []logRecord
			require.Eventually(t, func() bool {
				failed = logRecords(t, logs, "metrics export failed")
				return len(failed) > 0
			}, 5*time.Second, 10*time.Millisecond)
			require.NotEmpty(t, c.requests())
			sent := c.requests()[0].header
			require.Equal(t, `p/a!t"h-0123456789abcdef`, sent.Get("X-Path"), "precondition: the collector was sent the headers")
			require.Equal(t, `f!r"ag-0123456789abcdef`, sent.Get("X-Frag"))
			require.Equal(t, "us@e,r-0123456789abcdef", sent.Get("X-User"))
			require.Equal(t, `q"ry-0123456789abcdef`, sent.Get("X-Query"))
			require.Equal(t, "abc+def/0123456789abcdef==", sent.Get("X-B64"))
			require.Equal(t, "a,b+c-0123456789abcdef", sent.Get("X-Seg"))

			text, ok := failed[0].Context["error"].(string)
			require.True(t, ok)
			assert.Contains(t, text, "***REDACTED***")
			assert.NotContains(t, logs.String(), "0123456789abcdef", "the tail all six values share")
		})
	}
}

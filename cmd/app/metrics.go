package main

import (
	"context"
	"fmt"
	"log/slog"
	"time"

	"github.com/go-logr/logr"
	"go.opentelemetry.io/otel"
	"go.opentelemetry.io/otel/attribute"
	"go.opentelemetry.io/otel/exporters/otlp/otlpmetric/otlpmetrichttp"
	sdkmetric "go.opentelemetry.io/otel/sdk/metric"
	"go.opentelemetry.io/otel/sdk/metric/metricdata"
	"go.opentelemetry.io/otel/sdk/resource"

	"github.com/mesbrj/netloupe-tap/internal/shared/logger"
)

// serviceName identifies the sidecar in every metrics push (AD-033).
const serviceName = "netloupe-tap"

// metricsShutdownTimeout bounds the final push at shutdown: a collector that
// does not answer must not hold the sidecar's teardown.
const metricsShutdownTimeout = 5 * time.Second

// At most exportLogBurst export failures are logged per exportLogInterval: an
// unreachable collector fails every push, one per --metrics-interval.
const (
	exportLogBurst    = 10
	exportLogInterval = time.Minute
)

// startMetrics builds the provider the sidecar's metrics are recorded into
// and pushed from: every cfg.MetricsInterval, as gzip OTLP/HTTP protobuf, to
// cfg.MetricsEndpoint. An empty endpoint means metrics are off: it returns a
// nil provider. It opens no connection, so a collector that is down is not an
// error here; each failed push is logged at WARN instead, rate-limited.
func startMetrics(cfg Config, log *logger.Logger) (*sdkmetric.MeterProvider, error) {
	if cfg.MetricsEndpoint == "" {
		return nil, nil
	}
	u, err := metricsURL(cfg.MetricsEndpoint)
	if err != nil {
		return nil, err
	}
	// The SDK reports a failed push to one process-wide handler, and its own
	// diagnostics to one process-wide logger, which by default prints to
	// stderr with every value it was given, a header it could not parse
	// included. Both go in before the exporter is built: it parses the header
	// variables as it is constructed.
	exportLog := log.Limited(exportLogInterval, exportLogBurst)
	otel.SetLogger(logr.New(sdkLogSink{log: exportLog}))
	otel.SetErrorHandler(otel.ErrorHandlerFunc(func(err error) {
		exportLog.Warn("metrics export failed", slog.String("error", err.Error()))
	}))

	ctx := context.Background()
	exporter, err := otlpmetrichttp.New(ctx,
		otlpmetrichttp.WithEndpointURL(u.String()),
		otlpmetrichttp.WithCompression(otlpmetrichttp.GzipCompression),
		otlpmetrichttp.WithTemporalitySelector(metricsTemporality),
	)
	if err != nil {
		return nil, fmt.Errorf("metrics exporter: %w", err)
	}
	// service.name comes last so OTEL_RESOURCE_ATTRIBUTES can add attributes
	// but never rename the sidecar.
	res, err := resource.New(ctx,
		resource.WithFromEnv(),
		resource.WithAttributes(attribute.String("service.name", serviceName)),
	)
	if err != nil {
		return nil, fmt.Errorf("metrics resource: %w", err)
	}

	mp := sdkmetric.NewMeterProvider(
		sdkmetric.WithResource(res),
		// The export timeout is the interval: the SDK default of 30 s would
		// let pushes queue behind a collector that hangs.
		sdkmetric.WithReader(sdkmetric.NewPeriodicReader(exporter,
			sdkmetric.WithInterval(cfg.MetricsInterval),
			sdkmetric.WithTimeout(cfg.MetricsInterval),
		)),
		sdkmetric.WithCardinalityLimit(int(cfg.MetricsCardinalityLimit)),
	)
	log.Info("metrics export started",
		slog.String("endpoint", u.String()), // scheme, host and path: metricsURL refused the rest
		slog.String("interval", cfg.MetricsInterval.String()),
	)
	return mp, nil
}

// sdkLogSink carries the OpenTelemetry SDK's own error diagnostics into the
// sidecar's log as WARN lines, with the SDK's message and error only. It
// drops the key/value pairs, where the SDK puts the input it was handling,
// and every informational message.
type sdkLogSink struct{ log *logger.Logger }

func (sdkLogSink) Init(logr.RuntimeInfo)            {}
func (sdkLogSink) Enabled(int) bool                 { return false }
func (sdkLogSink) Info(int, string, ...any)         {}
func (s sdkLogSink) WithValues(...any) logr.LogSink { return s }
func (s sdkLogSink) WithName(string) logr.LogSink   { return s }
func (s sdkLogSink) Error(err error, msg string, _ ...any) {
	attrs := []slog.Attr{slog.String("sdk_message", msg)}
	if err != nil {
		attrs = append(attrs, slog.String("error", err.Error()))
	}
	s.log.Warn("metrics sdk error", attrs...)
}

// metricsTemporality exports what only grows as deltas, so each push carries
// one interval and the cardinality limit applies per push, and what goes up
// and down as running totals (AD-033).
func metricsTemporality(kind sdkmetric.InstrumentKind) metricdata.Temporality {
	switch kind {
	case sdkmetric.InstrumentKindUpDownCounter, sdkmetric.InstrumentKindObservableUpDownCounter:
		return metricdata.CumulativeTemporality
	default:
		return metricdata.DeltaTemporality
	}
}

// stopMetrics pushes what was recorded since the last push and shuts mp down,
// giving up after metricsShutdownTimeout. Metrics are best effort: a final
// push that fails or is abandoned is logged at WARN and is not an error of
// the sidecar's shutdown. A nil mp is a no-op.
func stopMetrics(mp *sdkmetric.MeterProvider, log *logger.Logger) {
	if mp == nil {
		return
	}
	ctx, cancel := context.WithTimeout(context.Background(), metricsShutdownTimeout)
	defer cancel()
	if err := mp.Shutdown(ctx); err != nil {
		log.Warn("metrics shutdown failed", slog.String("error", err.Error()))
	}
}

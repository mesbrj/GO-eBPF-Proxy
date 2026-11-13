package main

import (
	"context"
	"fmt"
	"log/slog"
	"time"

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

	// The SDK reports a failed push to one process-wide handler.
	exportLog := log.Limited(exportLogInterval, exportLogBurst)
	otel.SetErrorHandler(otel.ErrorHandlerFunc(func(err error) {
		exportLog.Warn("metrics export failed", slog.String("error", err.Error()))
	}))

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
		slog.String("endpoint", u.Redacted()),
		slog.String("interval", cfg.MetricsInterval.String()),
	)
	return mp, nil
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

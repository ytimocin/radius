// ------------------------------------------------------------
// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.
// ------------------------------------------------------------

package metricsprovider

import (
	"go.opentelemetry.io/otel/exporters/metric/prometheus"
	export "go.opentelemetry.io/otel/sdk/export/metric"
	"go.opentelemetry.io/otel/sdk/metric/aggregator/histogram"
	controller "go.opentelemetry.io/otel/sdk/metric/controller/basic"
	processor "go.opentelemetry.io/otel/sdk/metric/processor/basic"
	selector "go.opentelemetry.io/otel/sdk/metric/selector/simple"
	"go.opentelemetry.io/otel/metric/global"
)

func RegisterPrometheusMetrics() (*prometheus.Exporter, error) {
	promConfig := prometheus.Config{}
	c := controller.New(
		processor.New(
			selector.NewWithHistogramDistribution(
				histogram.WithExplicitBoundaries(promConfig.DefaultHistogramBoundaries),
			),
			export.CumulativeExportKindSelector(),
		),
	)
	exporter, err := prometheus.NewExporter(promConfig, c)
	if err != nil {
		return nil, err
	}

	global.SetMeterProvider(exporter.MeterProvider())
	return exporter, nil
}
// Usage:
// To record latency
// 	metric.Must(global.GetMeterProvider().Meter("radius-rp")).NewInt64ValueRecorder(requestMetricName, metric.WithUnit(unit.Dimensionless)).Record(r.Context(), int64(1))

// For number of requests
// 	metric.Must(global.GetMeterProvider().Meter("radius-rp")).NewInt64Counter(metricName, metric.WithUnit(unit.Dimensionless)).Add(ctx, int64(val), labels...)

// To use a guage, define a call back function
// 	callback := func(v int) metric.Int64ObserverFunc {
// 		return metric.Int64ObserverFunc(func(_ context.Context, result metric.Int64ObserverResult) { result.Observe(int64(v), labels...) })
// 	}(val)
// 	getMeterMust().NewInt64ValueObserver(metricName, callback, metric.WithUnit(unit.Dimensionless)).Observation(int64(val))
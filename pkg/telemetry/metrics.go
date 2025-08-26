package telemetry

import (
	"context"
	"fmt"
	"runtime"
	"sync"
	"time"

	"github.com/f2u0a0d3/GoRecon/pkg/config"
	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promauto"
	"github.com/rs/zerolog/log"
	"go.opentelemetry.io/otel"
	"go.opentelemetry.io/otel/attribute"
	"go.opentelemetry.io/otel/exporters/prometheus"
	"go.opentelemetry.io/otel/exporters/jaeger"
	"go.opentelemetry.io/otel/metric"
	"go.opentelemetry.io/otel/sdk/metric"
	"go.opentelemetry.io/otel/trace"
)

type MetricsCollector struct {
	config       *config.Config
	registry     *prometheus.Registry
	meterProvider *metric.MeterProvider
	tracer       trace.Tracer
	meter        metric.Meter
	
	// Prometheus metrics
	scansTotal         prometheus.Counter
	scanDuration       prometheus.Histogram
	pluginExecutions   *prometheus.CounterVec
	pluginDuration     *prometheus.HistogramVec
	pluginErrors       *prometheus.CounterVec
	findingsTotal      *prometheus.CounterVec
	cacheHits          *prometheus.CounterVec
	cacheMisses        *prometheus.CounterVec
	queueSizes         *prometheus.GaugeVec
	systemResources    *prometheus.GaugeVec
	httpRequests       *prometheus.CounterVec
	httpDuration       *prometheus.HistogramVec
	
	// OpenTelemetry metrics
	otelScansCounter    metric.Int64Counter
	otelScanDuration    metric.Float64Histogram
	otelPluginCounter   metric.Int64Counter
	otelFindingsGauge   metric.Int64UpDownCounter
	otelSystemGauge     metric.Float64ObservableGauge
	
	mutex sync.RWMutex
}

type TelemetryManager struct {
	collector *MetricsCollector
	config    *config.Config
	ctx       context.Context
	cancel    context.CancelFunc
}

func NewTelemetryManager(cfg *config.Config) (*TelemetryManager, error) {
	ctx, cancel := context.WithCancel(context.Background())
	
	collector, err := NewMetricsCollector(cfg)
	if err != nil {
		cancel()
		return nil, fmt.Errorf("failed to create metrics collector: %w", err)
	}
	
	return &TelemetryManager{
		collector: collector,
		config:    cfg,
		ctx:       ctx,
		cancel:    cancel,
	}, nil
}

func NewMetricsCollector(cfg *config.Config) (*MetricsCollector, error) {
	registry := prometheus.NewRegistry()
	
	// Initialize Prometheus metrics
	scansTotal := promauto.With(registry).NewCounter(prometheus.CounterOpts{
		Name: "gorecon_scans_total",
		Help: "Total number of scans executed",
	})
	
	scanDuration := promauto.With(registry).NewHistogram(prometheus.HistogramOpts{
		Name:    "gorecon_scan_duration_seconds",
		Help:    "Duration of scan execution",
		Buckets: prometheus.DefBuckets,
	})
	
	pluginExecutions := promauto.With(registry).NewCounterVec(prometheus.CounterOpts{
		Name: "gorecon_plugin_executions_total",
		Help: "Total number of plugin executions",
	}, []string{"plugin", "status"})
	
	pluginDuration := promauto.With(registry).NewHistogramVec(prometheus.HistogramOpts{
		Name:    "gorecon_plugin_duration_seconds",
		Help:    "Duration of plugin execution",
		Buckets: prometheus.DefBuckets,
	}, []string{"plugin"})
	
	pluginErrors := promauto.With(registry).NewCounterVec(prometheus.CounterOpts{
		Name: "gorecon_plugin_errors_total",
		Help: "Total number of plugin errors",
	}, []string{"plugin", "error_type"})
	
	findingsTotal := promauto.With(registry).NewCounterVec(prometheus.CounterOpts{
		Name: "gorecon_findings_total",
		Help: "Total number of findings discovered",
	}, []string{"plugin", "severity", "category"})
	
	cacheHits := promauto.With(registry).NewCounterVec(prometheus.CounterOpts{
		Name: "gorecon_cache_hits_total",
		Help: "Total number of cache hits",
	}, []string{"cache_type"})
	
	cacheMisses := promauto.With(registry).NewCounterVec(prometheus.CounterOpts{
		Name: "gorecon_cache_misses_total",
		Help: "Total number of cache misses",
	}, []string{"cache_type"})
	
	queueSizes := promauto.With(registry).NewGaugeVec(prometheus.GaugeOpts{
		Name: "gorecon_queue_size",
		Help: "Current size of various queues",
	}, []string{"queue_type"})
	
	systemResources := promauto.With(registry).NewGaugeVec(prometheus.GaugeOpts{
		Name: "gorecon_system_resources",
		Help: "System resource usage",
	}, []string{"resource_type"})
	
	httpRequests := promauto.With(registry).NewCounterVec(prometheus.CounterOpts{
		Name: "gorecon_http_requests_total",
		Help: "Total number of HTTP requests",
	}, []string{"method", "endpoint", "status"})
	
	httpDuration := promauto.With(registry).NewHistogramVec(prometheus.HistogramOpts{
		Name:    "gorecon_http_duration_seconds",
		Help:    "Duration of HTTP requests",
		Buckets: prometheus.DefBuckets,
	}, []string{"method", "endpoint"})
	
	// Initialize OpenTelemetry
	var meterProvider *metric.MeterProvider
	var tracer trace.Tracer
	var otelMeter metric.Meter
	
	if cfg.Telemetry.OpenTelemetry.Enabled {
		// Setup Prometheus exporter for OpenTelemetry
		promExporter, err := prometheus.New()
		if err != nil {
			return nil, fmt.Errorf("failed to create prometheus exporter: %w", err)
		}
		
		meterProvider = metric.NewMeterProvider(metric.WithReader(promExporter))
		otel.SetMeterProvider(meterProvider)
		
		// Setup Jaeger tracer if configured
		if cfg.Telemetry.Jaeger.Endpoint != "" {
			tracerProvider, err := jaeger.NewRawExporter(
				jaeger.WithCollectorEndpoint(jaeger.WithEndpoint(cfg.Telemetry.Jaeger.Endpoint)),
			)
			if err != nil {
				log.Warn().Err(err).Msg("Failed to setup Jaeger exporter")
			} else {
				otel.SetTracerProvider(tracerProvider)
			}
		}
		
		tracer = otel.Tracer("gorecon")
		otelMeter = otel.Meter("gorecon")
		
		// Initialize OpenTelemetry metrics
		otelScansCounter, err := otelMeter.Int64Counter(
			"gorecon.scans.total",
			metric.WithDescription("Total number of scans"),
		)
		if err != nil {
			return nil, fmt.Errorf("failed to create otel scans counter: %w", err)
		}
		
		otelScanDuration, err := otelMeter.Float64Histogram(
			"gorecon.scan.duration",
			metric.WithDescription("Duration of scan execution"),
			metric.WithUnit("s"),
		)
		if err != nil {
			return nil, fmt.Errorf("failed to create otel scan duration: %w", err)
		}
		
		otelPluginCounter, err := otelMeter.Int64Counter(
			"gorecon.plugins.executions",
			metric.WithDescription("Plugin execution count"),
		)
		if err != nil {
			return nil, fmt.Errorf("failed to create otel plugin counter: %w", err)
		}
		
		otelFindingsGauge, err := otelMeter.Int64UpDownCounter(
			"gorecon.findings.count",
			metric.WithDescription("Number of findings"),
		)
		if err != nil {
			return nil, fmt.Errorf("failed to create otel findings gauge: %w", err)
		}
		
		otelSystemGauge, err := otelMeter.Float64ObservableGauge(
			"gorecon.system.resources",
			metric.WithDescription("System resource usage"),
		)
		if err != nil {
			return nil, fmt.Errorf("failed to create otel system gauge: %w", err)
		}
	}
	
	collector := &MetricsCollector{
		config:           cfg,
		registry:         registry,
		meterProvider:    meterProvider,
		tracer:           tracer,
		meter:            otelMeter,
		scansTotal:       scansTotal,
		scanDuration:     scanDuration,
		pluginExecutions: pluginExecutions,
		pluginDuration:   pluginDuration,
		pluginErrors:     pluginErrors,
		findingsTotal:    findingsTotal,
		cacheHits:        cacheHits,
		cacheMisses:      cacheMisses,
		queueSizes:       queueSizes,
		systemResources:  systemResources,
		httpRequests:     httpRequests,
		httpDuration:     httpDuration,
		otelScansCounter: otelScansCounter,
		otelScanDuration: otelScanDuration,
		otelPluginCounter: otelPluginCounter,
		otelFindingsGauge: otelFindingsGauge,
		otelSystemGauge:   otelSystemGauge,
	}
	
	return collector, nil
}

func (tm *TelemetryManager) Start() error {
	// Start background metrics collection
	go tm.systemMetricsCollector()
	go tm.resourceMonitor()
	
	log.Info().
		Bool("prometheus", tm.config.Telemetry.Prometheus.Enabled).
		Bool("opentelemetry", tm.config.Telemetry.OpenTelemetry.Enabled).
		Msg("Telemetry manager started")
	
	return nil
}

func (tm *TelemetryManager) Stop() error {
	tm.cancel()
	
	if tm.collector.meterProvider != nil {
		if err := tm.collector.meterProvider.Shutdown(context.Background()); err != nil {
			log.Error().Err(err).Msg("Failed to shutdown meter provider")
		}
	}
	
	log.Info().Msg("Telemetry manager stopped")
	return nil
}

func (tm *TelemetryManager) GetRegistry() *prometheus.Registry {
	return tm.collector.registry
}

func (tm *TelemetryManager) GetCollector() *MetricsCollector {
	return tm.collector
}

func (tm *TelemetryManager) systemMetricsCollector() {
	ticker := time.NewTicker(15 * time.Second)
	defer ticker.Stop()
	
	for {
		select {
		case <-tm.ctx.Done():
			return
		case <-ticker.C:
			tm.collectSystemMetrics()
		}
	}
}

func (tm *TelemetryManager) collectSystemMetrics() {
	var m runtime.MemStats
	runtime.ReadMemStats(&m)
	
	// Memory metrics
	tm.collector.systemResources.WithLabelValues("memory_alloc").Set(float64(m.Alloc))
	tm.collector.systemResources.WithLabelValues("memory_sys").Set(float64(m.Sys))
	tm.collector.systemResources.WithLabelValues("memory_heap_alloc").Set(float64(m.HeapAlloc))
	tm.collector.systemResources.WithLabelValues("memory_heap_sys").Set(float64(m.HeapSys))
	
	// Goroutine metrics
	tm.collector.systemResources.WithLabelValues("goroutines").Set(float64(runtime.NumGoroutine()))
	
	// GC metrics
	tm.collector.systemResources.WithLabelValues("gc_cycles").Set(float64(m.NumGC))
	tm.collector.systemResources.WithLabelValues("gc_pause_total").Set(float64(m.PauseTotalNs))
	
	// CPU metrics (if available)
	if cpuUsage := tm.getCPUUsage(); cpuUsage >= 0 {
		tm.collector.systemResources.WithLabelValues("cpu_usage").Set(cpuUsage)
	}
}

func (tm *TelemetryManager) resourceMonitor() {
	ticker := time.NewTicker(30 * time.Second)
	defer ticker.Stop()
	
	for {
		select {
		case <-tm.ctx.Done():
			return
		case <-ticker.C:
			tm.monitorResources()
		}
	}
}

func (tm *TelemetryManager) monitorResources() {
	var m runtime.MemStats
	runtime.ReadMemStats(&m)
	
	// Check for memory pressure
	memoryUsageMB := float64(m.Alloc) / 1024 / 1024
	if memoryUsageMB > 1000 { // 1GB threshold
		log.Warn().
			Float64("memory_mb", memoryUsageMB).
			Msg("High memory usage detected")
	}
	
	// Check for goroutine leaks
	goroutineCount := runtime.NumGoroutine()
	if goroutineCount > 1000 { // Threshold for goroutine leak detection
		log.Warn().
			Int("goroutines", goroutineCount).
			Msg("High goroutine count detected")
	}
	
	// Check GC pressure
	gcPauseMicros := float64(m.PauseNs[(m.NumGC+255)%256]) / 1000
	if gcPauseMicros > 10000 { // 10ms threshold
		log.Warn().
			Float64("gc_pause_micros", gcPauseMicros).
			Msg("Long GC pause detected")
	}
}

func (tm *TelemetryManager) getCPUUsage() float64 {
	// This would implement actual CPU usage collection
	// For now, return -1 to indicate unavailable
	return -1
}

// Metric recording methods

func (mc *MetricsCollector) RecordScanStart() {
	mc.scansTotal.Inc()
	
	if mc.otelScansCounter != nil {
		mc.otelScansCounter.Add(context.Background(), 1, 
			metric.WithAttributes(attribute.String("status", "started")))
	}
}

func (mc *MetricsCollector) RecordScanDuration(duration time.Duration, success bool) {
	mc.scanDuration.Observe(duration.Seconds())
	
	if mc.otelScanDuration != nil {
		status := "success"
		if !success {
			status = "failure"
		}
		
		mc.otelScanDuration.Record(context.Background(), duration.Seconds(),
			metric.WithAttributes(attribute.String("status", status)))
	}
}

func (mc *MetricsCollector) RecordPluginExecution(pluginID string, duration time.Duration, success bool, errorType string) {
	status := "success"
	if !success {
		status = "failure"
		mc.pluginErrors.WithLabelValues(pluginID, errorType).Inc()
	}
	
	mc.pluginExecutions.WithLabelValues(pluginID, status).Inc()
	mc.pluginDuration.WithLabelValues(pluginID).Observe(duration.Seconds())
	
	if mc.otelPluginCounter != nil {
		mc.otelPluginCounter.Add(context.Background(), 1,
			metric.WithAttributes(
				attribute.String("plugin", pluginID),
				attribute.String("status", status),
			))
	}
}

func (mc *MetricsCollector) RecordFinding(pluginID, severity, category string) {
	mc.findingsTotal.WithLabelValues(pluginID, severity, category).Inc()
	
	if mc.otelFindingsGauge != nil {
		mc.otelFindingsGauge.Add(context.Background(), 1,
			metric.WithAttributes(
				attribute.String("plugin", pluginID),
				attribute.String("severity", severity),
				attribute.String("category", category),
			))
	}
}

func (mc *MetricsCollector) RecordCacheHit(cacheType string) {
	mc.cacheHits.WithLabelValues(cacheType).Inc()
}

func (mc *MetricsCollector) RecordCacheMiss(cacheType string) {
	mc.cacheMisses.WithLabelValues(cacheType).Inc()
}

func (mc *MetricsCollector) SetQueueSize(queueType string, size int) {
	mc.queueSizes.WithLabelValues(queueType).Set(float64(size))
}

func (mc *MetricsCollector) RecordHTTPRequest(method, endpoint, status string, duration time.Duration) {
	mc.httpRequests.WithLabelValues(method, endpoint, status).Inc()
	mc.httpDuration.WithLabelValues(method, endpoint).Observe(duration.Seconds())
}

// Tracing methods

func (mc *MetricsCollector) StartSpan(ctx context.Context, name string, opts ...trace.SpanStartOption) (context.Context, trace.Span) {
	if mc.tracer == nil {
		return ctx, trace.SpanFromContext(ctx)
	}
	return mc.tracer.Start(ctx, name, opts...)
}

func (mc *MetricsCollector) SpanFromContext(ctx context.Context) trace.Span {
	return trace.SpanFromContext(ctx)
}

// Utility methods

func (mc *MetricsCollector) AddSpanAttributes(span trace.Span, attributes ...attribute.KeyValue) {
	if span != nil {
		span.SetAttributes(attributes...)
	}
}

func (mc *MetricsCollector) AddSpanEvent(span trace.Span, name string, attributes ...attribute.KeyValue) {
	if span != nil {
		span.AddEvent(name, trace.WithAttributes(attributes...))
	}
}

func (mc *MetricsCollector) RecordSpanError(span trace.Span, err error) {
	if span != nil && err != nil {
		span.RecordError(err)
		span.SetStatus(trace.StatusError, err.Error())
	}
}
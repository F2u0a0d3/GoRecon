package performance

import (
	"context"
	"runtime"
	"sync"
	"time"

	"github.com/f2u0a0d3/GoRecon/pkg/config"
	"github.com/rs/zerolog/log"
)

type Optimizer interface {
	OptimizeForTarget(target string, workload WorkloadProfile) OptimizationSettings
	MonitorPerformance(ctx context.Context) <-chan PerformanceMetrics
	AdjustSettings(metrics PerformanceMetrics) OptimizationSettings
	GetCurrentSettings() OptimizationSettings
}

type SystemOptimizer struct {
	config            *config.Config
	currentSettings   OptimizationSettings
	metrics           chan PerformanceMetrics
	adjustmentHistory []OptimizationAdjustment
	mutex             sync.RWMutex
}

type OptimizationSettings struct {
	MaxConcurrency    int               `json:"max_concurrency"`
	WorkerPoolSize    int               `json:"worker_pool_size"`
	BufferSizes       BufferConfig      `json:"buffer_sizes"`
	TimeoutSettings   TimeoutConfig     `json:"timeout_settings"`
	RateLimiting      RateLimitConfig   `json:"rate_limiting"`
	MemoryManagement  MemoryConfig      `json:"memory_management"`
	CacheSettings     CacheConfig       `json:"cache_settings"`
	NetworkSettings   NetworkConfig     `json:"network_settings"`
	CPUSettings       CPUConfig         `json:"cpu_settings"`
}

type BufferConfig struct {
	PluginQueue    int `json:"plugin_queue"`
	ResultQueue    int `json:"result_queue"`
	CacheWrite     int `json:"cache_write"`
	NetworkBuffer  int `json:"network_buffer"`
	LogBuffer      int `json:"log_buffer"`
}

type TimeoutConfig struct {
	PluginExecution time.Duration `json:"plugin_execution"`
	NetworkRequest  time.Duration `json:"network_request"`
	CacheOperation  time.Duration `json:"cache_operation"`
	HealthCheck     time.Duration `json:"health_check"`
}

type RateLimitConfig struct {
	GlobalRPS    float64 `json:"global_rps"`
	PerPluginRPS float64 `json:"per_plugin_rps"`
	PerDomainRPS float64 `json:"per_domain_rps"`
	BurstSize    int     `json:"burst_size"`
}

type MemoryConfig struct {
	MaxHeapSize     int64 `json:"max_heap_size"`
	GCTarget        int   `json:"gc_target"`
	BufferPoolSize  int   `json:"buffer_pool_size"`
	CacheMaxSize    int64 `json:"cache_max_size"`
}

type CacheConfig struct {
	L1Size        int           `json:"l1_size"`
	L1TTL         time.Duration `json:"l1_ttl"`
	L2Size        int           `json:"l2_size"`
	L2TTL         time.Duration `json:"l2_ttl"`
	PrefetchRatio float64       `json:"prefetch_ratio"`
}

type NetworkConfig struct {
	ConnectionPoolSize int           `json:"connection_pool_size"`
	KeepAliveTimeout   time.Duration `json:"keep_alive_timeout"`
	IdleConnTimeout    time.Duration `json:"idle_conn_timeout"`
	MaxIdleConns       int           `json:"max_idle_conns"`
	MaxIdleConnsPerHost int          `json:"max_idle_conns_per_host"`
}

type CPUConfig struct {
	MaxProcs      int     `json:"max_procs"`
	CPUQuota      float64 `json:"cpu_quota"`
	AffinityMask  int     `json:"affinity_mask"`
}

type WorkloadProfile struct {
	Type              WorkloadType `json:"type"`
	ExpectedTargets   int          `json:"expected_targets"`
	PluginCount       int          `json:"plugin_count"`
	NetworkIntensive  bool         `json:"network_intensive"`
	CPUIntensive      bool         `json:"cpu_intensive"`
	MemoryIntensive   bool         `json:"memory_intensive"`
	CacheHitRatio     float64      `json:"cache_hit_ratio"`
	AverageRespTime   time.Duration `json:"average_resp_time"`
}

type WorkloadType string

const (
	WorkloadTypeLight      WorkloadType = "light"
	WorkloadTypeMedium     WorkloadType = "medium"
	WorkloadTypeHeavy      WorkloadType = "heavy"
	WorkloadTypeIntensive  WorkloadType = "intensive"
)

type PerformanceMetrics struct {
	Timestamp       time.Time     `json:"timestamp"`
	CPUUsage        float64       `json:"cpu_usage"`
	MemoryUsage     int64         `json:"memory_usage"`
	MemoryPercent   float64       `json:"memory_percent"`
	GoroutineCount  int           `json:"goroutine_count"`
	HeapSize        int64         `json:"heap_size"`
	GCPauseTime     time.Duration `json:"gc_pause_time"`
	RequestRate     float64       `json:"request_rate"`
	ResponseTime    time.Duration `json:"response_time"`
	ErrorRate       float64       `json:"error_rate"`
	CacheHitRate    float64       `json:"cache_hit_rate"`
	QueueDepths     QueueMetrics  `json:"queue_depths"`
	NetworkMetrics  NetworkMetrics `json:"network_metrics"`
}

type QueueMetrics struct {
	PluginQueue int `json:"plugin_queue"`
	ResultQueue int `json:"result_queue"`
	CacheQueue  int `json:"cache_queue"`
}

type NetworkMetrics struct {
	ActiveConnections int           `json:"active_connections"`
	ConnectionErrors  int           `json:"connection_errors"`
	AverageLatency    time.Duration `json:"average_latency"`
	BytesTransferred  int64         `json:"bytes_transferred"`
}

type OptimizationAdjustment struct {
	Timestamp   time.Time            `json:"timestamp"`
	Trigger     string               `json:"trigger"`
	OldSettings OptimizationSettings `json:"old_settings"`
	NewSettings OptimizationSettings `json:"new_settings"`
	Reason      string               `json:"reason"`
}

func NewSystemOptimizer(cfg *config.Config) *SystemOptimizer {
	return &SystemOptimizer{
		config:            cfg,
		currentSettings:   getDefaultSettings(),
		metrics:           make(chan PerformanceMetrics, 100),
		adjustmentHistory: make([]OptimizationAdjustment, 0),
	}
}

func (so *SystemOptimizer) OptimizeForTarget(target string, workload WorkloadProfile) OptimizationSettings {
	so.mutex.Lock()
	defer so.mutex.Unlock()

	oldSettings := so.currentSettings
	newSettings := so.calculateOptimalSettings(workload)

	if !settingsEqual(oldSettings, newSettings) {
		adjustment := OptimizationAdjustment{
			Timestamp:   time.Now(),
			Trigger:     "workload_optimization",
			OldSettings: oldSettings,
			NewSettings: newSettings,
			Reason:      fmt.Sprintf("Optimizing for %s workload with %d plugins", workload.Type, workload.PluginCount),
		}

		so.adjustmentHistory = append(so.adjustmentHistory, adjustment)
		so.currentSettings = newSettings

		log.Info().
			Str("target", target).
			Str("workload_type", string(workload.Type)).
			Int("concurrency", newSettings.MaxConcurrency).
			Int("workers", newSettings.WorkerPoolSize).
			Msg("Applied performance optimization")
	}

	return newSettings
}

func (so *SystemOptimizer) MonitorPerformance(ctx context.Context) <-chan PerformanceMetrics {
	go func() {
		ticker := time.NewTicker(5 * time.Second)
		defer ticker.Stop()

		for {
			select {
			case <-ctx.Done():
				return
			case <-ticker.C:
				metrics := so.collectMetrics()
				select {
				case so.metrics <- metrics:
				default:
					log.Warn().Msg("Performance metrics channel full")
				}

				// Auto-adjust if needed
				if adjustment := so.shouldAdjust(metrics); adjustment != nil {
					so.applyAdjustment(*adjustment)
				}
			}
		}
	}()

	return so.metrics
}

func (so *SystemOptimizer) AdjustSettings(metrics PerformanceMetrics) OptimizationSettings {
	so.mutex.Lock()
	defer so.mutex.Unlock()

	oldSettings := so.currentSettings
	newSettings := so.adjustBasedOnMetrics(metrics)

	if !settingsEqual(oldSettings, newSettings) {
		adjustment := OptimizationAdjustment{
			Timestamp:   time.Now(),
			Trigger:     "metrics_based",
			OldSettings: oldSettings,
			NewSettings: newSettings,
			Reason:      so.generateAdjustmentReason(metrics),
		}

		so.adjustmentHistory = append(so.adjustmentHistory, adjustment)
		so.currentSettings = newSettings

		log.Info().
			Float64("cpu_usage", metrics.CPUUsage).
			Float64("memory_percent", metrics.MemoryPercent).
			Msg("Adjusted settings based on metrics")
	}

	return newSettings
}

func (so *SystemOptimizer) GetCurrentSettings() OptimizationSettings {
	so.mutex.RLock()
	defer so.mutex.RUnlock()
	return so.currentSettings
}

func (so *SystemOptimizer) calculateOptimalSettings(workload WorkloadProfile) OptimizationSettings {
	settings := getDefaultSettings()

	// Adjust based on workload type
	switch workload.Type {
	case WorkloadTypeLight:
		settings.MaxConcurrency = min(runtime.NumCPU()*2, 8)
		settings.WorkerPoolSize = min(runtime.NumCPU(), 4)
		settings.RateLimiting.GlobalRPS = 10.0
		settings.BufferSizes.PluginQueue = 50
		settings.BufferSizes.ResultQueue = 100

	case WorkloadTypeMedium:
		settings.MaxConcurrency = runtime.NumCPU() * 4
		settings.WorkerPoolSize = runtime.NumCPU() * 2
		settings.RateLimiting.GlobalRPS = 25.0
		settings.BufferSizes.PluginQueue = 100
		settings.BufferSizes.ResultQueue = 200

	case WorkloadTypeHeavy:
		settings.MaxConcurrency = runtime.NumCPU() * 8
		settings.WorkerPoolSize = runtime.NumCPU() * 4
		settings.RateLimiting.GlobalRPS = 50.0
		settings.BufferSizes.PluginQueue = 200
		settings.BufferSizes.ResultQueue = 500

	case WorkloadTypeIntensive:
		settings.MaxConcurrency = runtime.NumCPU() * 12
		settings.WorkerPoolSize = runtime.NumCPU() * 6
		settings.RateLimiting.GlobalRPS = 100.0
		settings.BufferSizes.PluginQueue = 500
		settings.BufferSizes.ResultQueue = 1000
	}

	// Adjust based on workload characteristics
	if workload.NetworkIntensive {
		settings.NetworkSettings.ConnectionPoolSize *= 2
		settings.NetworkSettings.MaxIdleConns *= 2
		settings.TimeoutSettings.NetworkRequest *= 2
	}

	if workload.CPUIntensive {
		settings.CPUSettings.MaxProcs = runtime.NumCPU()
		settings.MaxConcurrency = min(settings.MaxConcurrency, runtime.NumCPU()*2)
	}

	if workload.MemoryIntensive {
		settings.MemoryManagement.MaxHeapSize *= 2
		settings.CacheSettings.L1Size /= 2 // Reduce cache to save memory
		settings.BufferSizes.NetworkBuffer /= 2
	}

	// Adjust based on expected cache performance
	if workload.CacheHitRatio > 0.8 {
		settings.CacheSettings.L1Size *= 2
		settings.CacheSettings.PrefetchRatio = 0.3
	}

	return settings
}

func (so *SystemOptimizer) collectMetrics() PerformanceMetrics {
	var m runtime.MemStats
	runtime.ReadMemStats(&m)

	return PerformanceMetrics{
		Timestamp:      time.Now(),
		CPUUsage:       getCurrentCPUUsage(),
		MemoryUsage:    int64(m.Alloc),
		MemoryPercent:  float64(m.Alloc) / float64(m.Sys) * 100,
		GoroutineCount: runtime.NumGoroutine(),
		HeapSize:       int64(m.HeapInuse),
		GCPauseTime:    time.Duration(m.PauseNs[(m.NumGC+255)%256]),
		QueueDepths:    so.getQueueDepths(),
	}
}

func (so *SystemOptimizer) shouldAdjust(metrics PerformanceMetrics) *OptimizationAdjustment {
	currentSettings := so.GetCurrentSettings()
	
	// High CPU usage - reduce concurrency
	if metrics.CPUUsage > 90.0 {
		newSettings := currentSettings
		newSettings.MaxConcurrency = max(newSettings.MaxConcurrency*8/10, 1)
		newSettings.WorkerPoolSize = max(newSettings.WorkerPoolSize*8/10, 1)
		
		return &OptimizationAdjustment{
			Timestamp:   time.Now(),
			Trigger:     "high_cpu",
			OldSettings: currentSettings,
			NewSettings: newSettings,
			Reason:      fmt.Sprintf("CPU usage too high: %.1f%%", metrics.CPUUsage),
		}
	}

	// High memory usage - reduce buffers and cache
	if metrics.MemoryPercent > 85.0 {
		newSettings := currentSettings
		newSettings.BufferSizes.PluginQueue /= 2
		newSettings.BufferSizes.ResultQueue /= 2
		newSettings.CacheSettings.L1Size /= 2
		
		return &OptimizationAdjustment{
			Timestamp:   time.Now(),
			Trigger:     "high_memory",
			OldSettings: currentSettings,
			NewSettings: newSettings,
			Reason:      fmt.Sprintf("Memory usage too high: %.1f%%", metrics.MemoryPercent),
		}
	}

	// Too many goroutines - reduce concurrency
	if metrics.GoroutineCount > runtime.NumCPU()*50 {
		newSettings := currentSettings
		newSettings.MaxConcurrency = max(newSettings.MaxConcurrency*7/10, 1)
		
		return &OptimizationAdjustment{
			Timestamp:   time.Now(),
			Trigger:     "high_goroutines",
			OldSettings: currentSettings,
			NewSettings: newSettings,
			Reason:      fmt.Sprintf("Too many goroutines: %d", metrics.GoroutineCount),
		}
	}

	// Low resource usage - can increase performance
	if metrics.CPUUsage < 30.0 && metrics.MemoryPercent < 50.0 && metrics.GoroutineCount < runtime.NumCPU()*10 {
		newSettings := currentSettings
		newSettings.MaxConcurrency = min(newSettings.MaxConcurrency*11/10, runtime.NumCPU()*16)
		newSettings.WorkerPoolSize = min(newSettings.WorkerPoolSize*11/10, runtime.NumCPU()*8)
		
		return &OptimizationAdjustment{
			Timestamp:   time.Now(),
			Trigger:     "low_utilization",
			OldSettings: currentSettings,
			NewSettings: newSettings,
			Reason:      "Resources underutilized, increasing performance",
		}
	}

	return nil
}

func (so *SystemOptimizer) adjustBasedOnMetrics(metrics PerformanceMetrics) OptimizationSettings {
	settings := so.currentSettings

	// CPU-based adjustments
	if metrics.CPUUsage > 85 {
		settings.MaxConcurrency = max(settings.MaxConcurrency*9/10, 1)
		settings.RateLimiting.GlobalRPS *= 0.9
	} else if metrics.CPUUsage < 20 {
		settings.MaxConcurrency = min(settings.MaxConcurrency*11/10, runtime.NumCPU()*16)
		settings.RateLimiting.GlobalRPS *= 1.1
	}

	// Memory-based adjustments
	if metrics.MemoryPercent > 80 {
		settings.BufferSizes.PluginQueue = max(settings.BufferSizes.PluginQueue*9/10, 10)
		settings.BufferSizes.ResultQueue = max(settings.BufferSizes.ResultQueue*9/10, 20)
		settings.CacheSettings.L1Size = max(settings.CacheSettings.L1Size*9/10, 100)
	}

	// GC-based adjustments
	if metrics.GCPauseTime > 100*time.Millisecond {
		settings.MemoryManagement.GCTarget = max(settings.MemoryManagement.GCTarget-5, 50)
	} else if metrics.GCPauseTime < 10*time.Millisecond {
		settings.MemoryManagement.GCTarget = min(settings.MemoryManagement.GCTarget+5, 500)
	}

	return settings
}

func (so *SystemOptimizer) applyAdjustment(adjustment OptimizationAdjustment) {
	so.mutex.Lock()
	defer so.mutex.Unlock()

	so.adjustmentHistory = append(so.adjustmentHistory, adjustment)
	so.currentSettings = adjustment.NewSettings

	// Limit history size
	if len(so.adjustmentHistory) > 100 {
		so.adjustmentHistory = so.adjustmentHistory[len(so.adjustmentHistory)-100:]
	}

	log.Debug().
		Str("trigger", adjustment.Trigger).
		Str("reason", adjustment.Reason).
		Msg("Applied performance adjustment")
}

func (so *SystemOptimizer) generateAdjustmentReason(metrics PerformanceMetrics) string {
	reasons := []string{}
	
	if metrics.CPUUsage > 80 {
		reasons = append(reasons, fmt.Sprintf("high CPU: %.1f%%", metrics.CPUUsage))
	}
	if metrics.MemoryPercent > 75 {
		reasons = append(reasons, fmt.Sprintf("high memory: %.1f%%", metrics.MemoryPercent))
	}
	if metrics.GoroutineCount > runtime.NumCPU()*40 {
		reasons = append(reasons, fmt.Sprintf("many goroutines: %d", metrics.GoroutineCount))
	}
	if metrics.GCPauseTime > 50*time.Millisecond {
		reasons = append(reasons, fmt.Sprintf("long GC pause: %v", metrics.GCPauseTime))
	}

	if len(reasons) == 0 {
		return "periodic optimization"
	}
	
	return fmt.Sprintf("adjusting due to: %s", strings.Join(reasons, ", "))
}

func (so *SystemOptimizer) getQueueDepths() QueueMetrics {
	// This would integrate with actual queue monitoring
	// For now, return placeholder values
	return QueueMetrics{
		PluginQueue: 0,
		ResultQueue: 0,
		CacheQueue:  0,
	}
}

func getDefaultSettings() OptimizationSettings {
	numCPU := runtime.NumCPU()
	
	return OptimizationSettings{
		MaxConcurrency: numCPU * 4,
		WorkerPoolSize: numCPU * 2,
		BufferSizes: BufferConfig{
			PluginQueue:   100,
			ResultQueue:   200,
			CacheWrite:    50,
			NetworkBuffer: 8192,
			LogBuffer:     1000,
		},
		TimeoutSettings: TimeoutConfig{
			PluginExecution: 5 * time.Minute,
			NetworkRequest:  30 * time.Second,
			CacheOperation:  1 * time.Second,
			HealthCheck:     10 * time.Second,
		},
		RateLimiting: RateLimitConfig{
			GlobalRPS:    20.0,
			PerPluginRPS: 5.0,
			PerDomainRPS: 2.0,
			BurstSize:    10,
		},
		MemoryManagement: MemoryConfig{
			MaxHeapSize:    1024 * 1024 * 1024, // 1GB
			GCTarget:       100,
			BufferPoolSize: 1000,
			CacheMaxSize:   512 * 1024 * 1024, // 512MB
		},
		CacheSettings: CacheConfig{
			L1Size:        10000,
			L1TTL:         10 * time.Minute,
			L2Size:        100000,
			L2TTL:         1 * time.Hour,
			PrefetchRatio: 0.1,
		},
		NetworkSettings: NetworkConfig{
			ConnectionPoolSize:      100,
			KeepAliveTimeout:        30 * time.Second,
			IdleConnTimeout:         90 * time.Second,
			MaxIdleConns:           100,
			MaxIdleConnsPerHost:     10,
		},
		CPUSettings: CPUConfig{
			MaxProcs:     numCPU,
			CPUQuota:     1.0,
			AffinityMask: -1,
		},
	}
}

func getCurrentCPUUsage() float64 {
	// This would implement actual CPU usage monitoring
	// For now, return a placeholder value
	return 0.0
}

func settingsEqual(a, b OptimizationSettings) bool {
	return a.MaxConcurrency == b.MaxConcurrency &&
		   a.WorkerPoolSize == b.WorkerPoolSize &&
		   a.BufferSizes == b.BufferSizes
	// Add more detailed comparison if needed
}

func min(a, b int) int {
	if a < b {
		return a
	}
	return b
}

func max(a, b int) int {
	if a > b {
		return a
	}
	return b
}
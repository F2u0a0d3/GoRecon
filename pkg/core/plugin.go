package core

import (
	"context"
	"sync"
	"time"

	"github.com/f2u0a0d3/GoRecon/pkg/config"
	"github.com/f2u0a0d3/GoRecon/pkg/models"
)

// Plugin defines the interface that all plugins must implement
type Plugin interface {
	// Metadata methods
	Name() string
	Category() string
	Description() string
	Version() string
	Author() string
	
	// Dependency methods
	RequiredBinaries() []string
	RequiredEnvVars() []string
	SupportedTargetTypes() []string
	Dependencies() []PluginDependency
	Provides() []string
	Consumes() []string
	
	// Lifecycle methods
	Validate(ctx context.Context, cfg *config.Config) error
	Prepare(ctx context.Context, target *models.Target, cfg *config.Config, shared *SharedContext) error
	Run(ctx context.Context, target *models.Target, results chan<- models.PluginResult, shared *SharedContext) error
	Teardown(ctx context.Context) error
	
	// Capability methods
	IsPassive() bool
	RequiresConfirmation() bool
	EstimatedDuration() time.Duration
	MaxConcurrency() int
	Priority() int
	ResourceRequirements() Resources
	
	// Intelligence methods
	ProcessDiscovery(ctx context.Context, discovery models.Discovery) error
	GetIntelligencePatterns() []Pattern
}

// PluginDependency defines plugin ordering requirements
type PluginDependency struct {
	Plugin   string `json:"plugin"`
	Required bool   `json:"required"`
	Reason   string `json:"reason"`
}

// Resources defines plugin resource requirements
type Resources struct {
	CPUCores         int    `json:"cpu_cores"`
	MemoryMB         int    `json:"memory_mb"`
	DiskMB           int    `json:"disk_mb"`
	NetworkBandwidth string `json:"network_bandwidth"`
	MaxFileHandles   int    `json:"max_file_handles"`
	MaxProcesses     int    `json:"max_processes"`
	RequiresRoot     bool   `json:"requires_root"`
	NetworkAccess    bool   `json:"network_access"`
}

// BasePlugin provides a default implementation for common plugin functionality
type BasePlugin struct {
	name         string
	category     string
	description  string
	version      string
	author       string
	binaries     []string
	envVars      []string
	targetTypes  []string
	dependencies []PluginDependency
	provides     []string
	consumes     []string
	isPassive    bool
	needsConfirm bool
	duration     time.Duration
	maxConcur    int
	priority     int
	resources    Resources
	patterns     []Pattern
}

// NewBasePlugin creates a new base plugin with common defaults
func NewBasePlugin(name, category string, binaries []string) BasePlugin {
	return BasePlugin{
		name:         name,
		category:     category,
		description:  "Plugin for " + category,
		version:      "1.0.0",
		author:       "GoRecon Team",
		binaries:     binaries,
		envVars:      []string{},
		targetTypes:  []string{"web"},
		dependencies: []PluginDependency{},
		provides:     []string{},
		consumes:     []string{},
		isPassive:    true,
		needsConfirm: false,
		duration:     10 * time.Minute,
		maxConcur:    5,
		priority:     5,
		resources: Resources{
			CPUCores:         1,
			MemoryMB:         512,
			DiskMB:           100,
			NetworkBandwidth: "1Mbps",
			MaxFileHandles:   100,
			MaxProcesses:     5,
			RequiresRoot:     false,
			NetworkAccess:    true,
		},
		patterns: []Pattern{},
	}
}

// Pattern defines intelligence patterns for correlation
type Pattern struct {
	Name        string                 `json:"name"`
	Type        string                 `json:"type"`
	Regex       string                 `json:"regex,omitempty"`
	Keywords    []string               `json:"keywords,omitempty"`
	Conditions  []PatternCondition     `json:"conditions,omitempty"`
	Confidence  float64                `json:"confidence"`
	Description string                 `json:"description"`
	Metadata    map[string]interface{} `json:"metadata,omitempty"`
}

// PatternCondition defines conditional logic for patterns
type PatternCondition struct {
	Field    string      `json:"field"`
	Operator string      `json:"operator"` // equals, contains, regex, gt, lt
	Value    interface{} `json:"value"`
}

// SharedContext enables plugins to share discoveries and communicate
type SharedContext struct {
	discoveries  *sync.Map              // Thread-safe discovery sharing
	events       chan ContextEvent      // Real-time event bus
	cache        CacheInterface         // Shared cache layer
	intelligence IntelligenceInterface  // Correlation engine
	logger       Logger                 // Shared logger
	metrics      MetricsInterface       // Metrics collection
	mutex        sync.RWMutex          // Protect shared resources
}

// NewSharedContext creates a new shared context
func NewSharedContext(cache CacheInterface, intelligence IntelligenceInterface, logger Logger, metrics MetricsInterface) *SharedContext {
	return &SharedContext{
		discoveries:  &sync.Map{},
		events:       make(chan ContextEvent, 1000),
		cache:        cache,
		intelligence: intelligence,
		logger:       logger,
		metrics:      metrics,
	}
}

// AddDiscovery adds a discovery to the shared context
func (sc *SharedContext) AddDiscovery(discovery models.Discovery) {
	key := discovery.Type + ":" + discovery.Source
	sc.discoveries.Store(key, discovery)
	
	// Notify other plugins via event bus
	select {
	case sc.events <- ContextEvent{
		Type:      EventTypeDiscovery,
		Source:    discovery.Source,
		Data:      discovery,
		Timestamp: time.Now(),
	}:
	default:
		// Event channel full, continue without blocking
		sc.logger.Warn("Event channel full, dropping discovery event")
	}
}

// GetDiscoveries returns all discoveries of a specific type
func (sc *SharedContext) GetDiscoveries(discoveryType string) []models.Discovery {
	var discoveries []models.Discovery
	
	sc.discoveries.Range(func(key, value interface{}) bool {
		if discovery, ok := value.(models.Discovery); ok {
			if discovery.Type == discoveryType {
				discoveries = append(discoveries, discovery)
			}
		}
		return true
	})
	
	return discoveries
}

// GetDiscoveriesBySource returns all discoveries from a specific source
func (sc *SharedContext) GetDiscoveriesBySource(source string) []models.Discovery {
	var discoveries []models.Discovery
	
	sc.discoveries.Range(func(key, value interface{}) bool {
		if discovery, ok := value.(models.Discovery); ok {
			if discovery.Source == source {
				discoveries = append(discoveries, discovery)
			}
		}
		return true
	})
	
	return discoveries
}

// Subscribe returns a channel to receive context events
func (sc *SharedContext) Subscribe() <-chan ContextEvent {
	return sc.events
}

// GetCache returns the shared cache interface
func (sc *SharedContext) GetCache() CacheInterface {
	return sc.cache
}

// GetIntelligence returns the intelligence interface
func (sc *SharedContext) GetIntelligence() IntelligenceInterface {
	return sc.intelligence
}

// GetLogger returns the shared logger
func (sc *SharedContext) GetLogger() Logger {
	return sc.logger
}

// GetMetrics returns the metrics interface
func (sc *SharedContext) GetMetrics() MetricsInterface {
	return sc.metrics
}

// ContextEvent represents events in the shared context
type ContextEvent struct {
	Type      EventType              `json:"type"`
	Source    string                 `json:"source"`
	Data      interface{}            `json:"data"`
	Timestamp time.Time              `json:"timestamp"`
	Metadata  map[string]interface{} `json:"metadata,omitempty"`
}

// EventType represents different types of context events
type EventType string

const (
	EventTypeDiscovery    EventType = "discovery"
	EventTypeCorrelation  EventType = "correlation"
	EventTypeAnomaly      EventType = "anomaly"
	EventTypeError        EventType = "error"
	EventTypeProgress     EventType = "progress"
)

// Interfaces for dependency injection

// CacheInterface defines cache operations
type CacheInterface interface {
	Get(ctx context.Context, key string) (interface{}, error)
	Set(ctx context.Context, key string, value interface{}, ttl time.Duration) error
	Delete(ctx context.Context, key string) error
	Exists(ctx context.Context, key string) (bool, error)
	Clear(ctx context.Context) error
}

// IntelligenceInterface defines intelligence operations
type IntelligenceInterface interface {
	Correlate(ctx context.Context, results []models.PluginResult) ([]models.Correlation, error)
	DetectAnomalies(ctx context.Context, results []models.PluginResult) ([]Anomaly, error)
	AnalyzeAttackPaths(ctx context.Context, results []models.PluginResult) ([]AttackPath, error)
	ScoreRisk(ctx context.Context, result models.PluginResult) (float64, error)
}

// Logger interface for structured logging
type Logger interface {
	Debug(msg string, fields ...interface{})
	Info(msg string, fields ...interface{})
	Warn(msg string, fields ...interface{})
	Error(msg string, err error, fields ...interface{})
	Fatal(msg string, err error, fields ...interface{})
	WithField(key string, value interface{}) Logger
	WithFields(fields map[string]interface{}) Logger
}

// MetricsInterface defines metrics collection
type MetricsInterface interface {
	Counter(name string) Counter
	Histogram(name string) Histogram
	Gauge(name string) Gauge
	Timer(name string) Timer
}

// Metrics interfaces
type Counter interface {
	Inc()
	Add(float64)
}

type Histogram interface {
	Observe(float64)
}

type Gauge interface {
	Set(float64)
	Inc()
	Dec()
	Add(float64)
	Sub(float64)
}

type Timer interface {
	Start() func()
	Record(time.Duration)
}

// Anomaly represents detected anomalous behavior
type Anomaly struct {
	ID          string                 `json:"id"`
	Type        string                 `json:"type"`
	Severity    string                 `json:"severity"`
	Description string                 `json:"description"`
	Evidence    []models.PluginResult  `json:"evidence"`
	Confidence  float64                `json:"confidence"`
	Indicators  []string               `json:"indicators"`
	Timestamp   time.Time              `json:"timestamp"`
	Metadata    map[string]interface{} `json:"metadata,omitempty"`
}

// AttackPath represents a potential attack chain
type AttackPath struct {
	ID          string                 `json:"id"`
	Name        string                 `json:"name"`
	Entry       models.PluginResult    `json:"entry"`
	Steps       []AttackStep           `json:"steps"`
	Goal        string                 `json:"goal"`
	Likelihood  float64                `json:"likelihood"`
	Impact      float64                `json:"impact"`
	RiskScore   float64                `json:"risk_score"`
	Mitigations []Mitigation           `json:"mitigations"`
	Timeline    []TimelineEvent        `json:"timeline"`
}

// AttackStep represents a step in an attack path
type AttackStep struct {
	Finding     models.PluginResult    `json:"finding"`
	Technique   models.MITRETechnique  `json:"technique"`
	Requirement string                 `json:"requirement"`
	Achieved    bool                   `json:"achieved"`
	Confidence  float64                `json:"confidence"`
}

// Mitigation represents a security mitigation
type Mitigation struct {
	ID           string   `json:"id"`
	Name         string   `json:"name"`
	Description  string   `json:"description"`
	Type         string   `json:"type"` // preventive, detective, corrective
	Effectiveness float64 `json:"effectiveness"` // 0-1
	Cost         string   `json:"cost"` // low, medium, high
	Complexity   string   `json:"complexity"` // low, medium, high
	References   []string `json:"references"`
}

// TimelineEvent represents an event in a timeline
type TimelineEvent struct {
	Timestamp   time.Time              `json:"timestamp"`
	Event       string                 `json:"event"`
	Description string                 `json:"description"`
	Source      string                 `json:"source"`
	Metadata    map[string]interface{} `json:"metadata,omitempty"`
}

// PluginStatus represents the current status of a plugin
type PluginStatus struct {
	Name        string    `json:"name"`
	State       string    `json:"state"` // pending, running, completed, failed
	StartTime   time.Time `json:"start_time"`
	EndTime     time.Time `json:"end_time"`
	Duration    time.Duration `json:"duration"`
	ResultCount int       `json:"result_count"`
	Error       string    `json:"error,omitempty"`
}

// PluginMetrics represents metrics for a plugin execution
type PluginMetrics struct {
	Name             string        `json:"name"`
	ExecutionTime    time.Duration `json:"execution_time"`
	ResultCount      int           `json:"result_count"`
	ErrorCount       int           `json:"error_count"`
	CPUUsage         float64       `json:"cpu_usage"`
	MemoryUsage      int64         `json:"memory_usage"`
	NetworkRequests  int           `json:"network_requests"`
	CacheHits        int           `json:"cache_hits"`
	CacheMisses      int           `json:"cache_misses"`
}

// Default resource requirements for plugins
var DefaultResources = Resources{
	CPUCores:         1,
	MemoryMB:         256,
	DiskMB:           100,
	NetworkBandwidth: "1Mbps",
	MaxFileHandles:   100,
	MaxProcesses:     5,
	RequiresRoot:     false,
	NetworkAccess:    true,
}

// BasePlugin method implementations

// Metadata methods
func (b BasePlugin) Name() string { return b.name }
func (b BasePlugin) Category() string { return b.category }
func (b BasePlugin) Description() string { return b.description }
func (b BasePlugin) Version() string { return b.version }
func (b BasePlugin) Author() string { return b.author }

// Dependency methods
func (b BasePlugin) RequiredBinaries() []string { return b.binaries }
func (b BasePlugin) RequiredEnvVars() []string { return b.envVars }
func (b BasePlugin) SupportedTargetTypes() []string { return b.targetTypes }
func (b BasePlugin) Dependencies() []PluginDependency { return b.dependencies }
func (b BasePlugin) Provides() []string { return b.provides }
func (b BasePlugin) Consumes() []string { return b.consumes }

// Capability methods
func (b BasePlugin) IsPassive() bool { return b.isPassive }
func (b BasePlugin) RequiresConfirmation() bool { return b.needsConfirm }
func (b BasePlugin) EstimatedDuration() time.Duration { return b.duration }
func (b BasePlugin) MaxConcurrency() int { return b.maxConcur }
func (b BasePlugin) Priority() int { return b.priority }
func (b BasePlugin) ResourceRequirements() Resources { return b.resources }

// Intelligence methods
func (b BasePlugin) GetIntelligencePatterns() []Pattern { return b.patterns }

// Default implementations for lifecycle methods (must be overridden)
func (b BasePlugin) Validate(ctx context.Context, cfg *config.Config) error {
	return nil // Default: no validation needed
}

func (b BasePlugin) Prepare(ctx context.Context, target *models.Target, cfg *config.Config, shared *SharedContext) error {
	return nil // Default: no preparation needed
}

func (b BasePlugin) Run(ctx context.Context, target *models.Target, results chan<- models.PluginResult, shared *SharedContext) error {
	return nil // Default: no-op
}

func (b BasePlugin) Teardown(ctx context.Context) error {
	return nil // Default: no cleanup needed
}

func (b BasePlugin) ProcessDiscovery(ctx context.Context, discovery models.Discovery) error {
	return nil // Default: no discovery processing
}
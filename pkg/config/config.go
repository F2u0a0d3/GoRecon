package config

import (
	"fmt"
	"time"
)

// Config represents the main configuration structure
type Config struct {
	Global        GlobalConfig                  `yaml:"global" validate:"required"`
	Profiles      map[string]ProfileConfig      `yaml:"profiles"`
	Plugins       map[string]PluginConfig       `yaml:"plugins"`
	Tools         map[string]ToolConfig         `yaml:"tools"`
	Intelligence  IntelligenceConfig            `yaml:"intelligence"`
	Security      SecurityConfig                `yaml:"security"`
	Environment   map[string]string             `yaml:"environment"`
	Targets       map[string]TargetConfig       `yaml:"targets"`
}

// GlobalConfig contains global settings
type GlobalConfig struct {
	Version              string                 `yaml:"version"`
	Workdir              string                 `yaml:"workdir" validate:"required"`
	Outdir               string                 `yaml:"outdir" validate:"required"`
	
	// Execution control
	Concurrency          int                    `yaml:"concurrency" validate:"min=1,max=100"`
	PluginTimeout        time.Duration          `yaml:"plugin_timeout"`
	GlobalTimeout        time.Duration          `yaml:"global_timeout"`
	RetryAttempts        int                    `yaml:"retry_attempts" validate:"min=0,max=10"`
	RetryDelay           time.Duration          `yaml:"retry_delay"`
	
	// Safety settings
	ConfirmActiveScans   bool                   `yaml:"confirm_active_scans"`
	ScopeEnforcement     bool                   `yaml:"scope_enforcement"`
	ScopeFile            string                 `yaml:"scope_file"`
	DefaultScope         []string               `yaml:"default_scope"`
	DenylistTargets      []string               `yaml:"denylist_targets"`
	
	// Resource limits
	MaxMemoryMB          int                    `yaml:"max_memory_mb" validate:"min=256"`
	MaxDiskMB            int                    `yaml:"max_disk_mb" validate:"min=100"`
	MaxProcesses         int                    `yaml:"max_processes" validate:"min=1"`
	
	// Performance
	Cache                CacheConfig            `yaml:"cache"`
	
	// Intelligence
	Intelligence         IntelligenceConfig     `yaml:"intelligence"`
	
	// Distributed mode
	Distributed          DistributedConfig      `yaml:"distributed"`
	
	// API settings
	API                  APIConfig              `yaml:"api"`
	
	// Streaming
	Streaming            StreamingConfig        `yaml:"streaming"`
	
	// Output settings
	LogLevel             string                 `yaml:"log_level" validate:"oneof=debug info warn error fatal"`
	LogFormat            string                 `yaml:"log_format" validate:"oneof=json text"`
	RedactSecrets        bool                   `yaml:"redact_secrets"`
	SaveRawOutput        bool                   `yaml:"save_raw_output"`
	CompressOutput       bool                   `yaml:"compress_output"`
	
	// Telemetry
	Telemetry            TelemetryConfig        `yaml:"telemetry"`
}

// ProfileConfig defines scanning profiles
type ProfileConfig struct {
	Name                 string                 `yaml:"name"`
	Description          string                 `yaml:"description"`
	InheritFrom          string                 `yaml:"inherit_from,omitempty"`
	RateLimit            RateLimitConfig        `yaml:"rate_limit"`
	Plugins              ProfilePluginConfig    `yaml:"plugins"`
	Evasion              EvasionConfig          `yaml:"evasion"`
	ResourceLimits       ResourceLimitsConfig   `yaml:"resource_limits"`
	Overrides            map[string]interface{} `yaml:"overrides"`
}

// PluginConfig contains plugin-specific configuration
type PluginConfig struct {
	Enabled              bool                   `yaml:"enabled"`
	PrimaryTool          string                 `yaml:"primary_tool"`
	FallbackTools        []string               `yaml:"fallback_tools"`
	ValidateFindings     bool                   `yaml:"validate_findings"`
	MaxFindings          int                    `yaml:"max_findings"`
	CacheTTL             time.Duration          `yaml:"cache_ttl"`
	Intelligence         PluginIntelligenceConfig `yaml:"intelligence"`
	Sandboxed            bool                   `yaml:"sandboxed"`
	ResourceLimits       ResourceLimitsConfig   `yaml:"resource_limits"`
}

// ToolConfig contains tool-specific settings
type ToolConfig struct {
	Path                 string                 `yaml:"path"`
	Enabled              bool                   `yaml:"enabled"`
	Timeout              time.Duration          `yaml:"timeout"`
	Args                 []string               `yaml:"args"`
	JSONSupport          bool                   `yaml:"json_support"`
	JSONFlags            []string               `yaml:"json_flags"`
	VersionCheck         bool                   `yaml:"version_check"`
	InstallCommand       string                 `yaml:"install_command"`
	RateLimit            string                 `yaml:"rate_limit"`
	RequiresConfirmation bool                   `yaml:"requires_confirmation"`
}

// IntelligenceConfig contains intelligence analysis settings
type IntelligenceConfig struct {
	CorrelationEnabled   bool                   `yaml:"correlation_enabled"`
	AnomalyDetection     bool                   `yaml:"anomaly_detection"`
	AttackPathAnalysis   bool                   `yaml:"attack_path_analysis"`
	RiskScoring          bool                   `yaml:"risk_scoring"`
	MLModelsPath         string                 `yaml:"ml_models_path"`
	CorrelationRules     []CorrelationRule      `yaml:"correlation_rules"`
	AnomalyDetectionConf AnomalyDetectionConfig `yaml:"anomaly_detection"`
	AttackPaths          AttackPathsConfig      `yaml:"attack_paths"`
	RiskScoringConf      RiskScoringConfig      `yaml:"risk_scoring"`
}

// CacheConfig contains caching configuration
type CacheConfig struct {
	Enabled              bool                   `yaml:"enabled"`
	L1SizeMB             int                    `yaml:"l1_size_mb"`
	L2Enabled            bool                   `yaml:"l2_enabled"`
	L2RedisURL           string                 `yaml:"l2_redis_url"`
	L3Enabled            bool                   `yaml:"l3_enabled"`
	L3S3Bucket           string                 `yaml:"l3_s3_bucket"`
}

// DistributedConfig contains distributed scanning settings
type DistributedConfig struct {
	Enabled              bool                   `yaml:"enabled"`
	Mode                 string                 `yaml:"mode" validate:"oneof=coordinator worker"`
	CoordinatorURL       string                 `yaml:"coordinator_url"`
	NATSURL              string                 `yaml:"nats_url"`
	WorkerID             string                 `yaml:"worker_id"`
}

// APIConfig contains API server settings
type APIConfig struct {
	Enabled              bool                   `yaml:"enabled"`
	RESTPort             int                    `yaml:"rest_port" validate:"min=1,max=65535"`
	GraphQLPort          int                    `yaml:"graphql_port" validate:"min=1,max=65535"`
	GRPCPort             int                    `yaml:"grpc_port" validate:"min=1,max=65535"`
	AuthEnabled          bool                   `yaml:"auth_enabled"`
	RateLimitRPS         int                    `yaml:"rate_limit_rps" validate:"min=1"`
}

// StreamingConfig contains streaming settings
type StreamingConfig struct {
	Enabled              bool                   `yaml:"enabled"`
	WebSocketPort        int                    `yaml:"websocket_port" validate:"min=1,max=65535"`
	SSEEnabled           bool                   `yaml:"sse_enabled"`
	BufferSize           int                    `yaml:"buffer_size" validate:"min=100"`
}

// TelemetryConfig contains telemetry settings
type TelemetryConfig struct {
	MetricsEnabled       bool                   `yaml:"metrics_enabled"`
	MetricsPort          int                    `yaml:"metrics_port" validate:"min=1,max=65535"`
	TracingEnabled       bool                   `yaml:"tracing_enabled"`
	TracingEndpoint      string                 `yaml:"tracing_endpoint"`
}

// RateLimitConfig contains rate limiting configuration
type RateLimitConfig struct {
	RequestsPerSecond    int                    `yaml:"requests_per_second" validate:"min=1"`
	BurstSize            int                    `yaml:"burst_size" validate:"min=1"`
	Jitter               string                 `yaml:"jitter"`
	HumanMode            bool                   `yaml:"human_mode"`
}

// ProfilePluginConfig contains plugin settings for profiles
type ProfilePluginConfig struct {
	PassiveOnly          bool                   `yaml:"passive_only"`
	EnableAll            bool                   `yaml:"enable_all"`
	Categories           []string               `yaml:"categories"`
	Include              []string               `yaml:"include"`
	Exclude              []string               `yaml:"exclude"`
	ExcludeActive        bool                   `yaml:"exclude_active"`
	ParallelExecution    bool                   `yaml:"parallel_execution"`
	MaxWorkers           int                    `yaml:"max_workers" validate:"min=1"`
}

// EvasionConfig contains evasion technique settings
type EvasionConfig struct {
	RotateUserAgents     bool                   `yaml:"rotate_user_agents"`
	UseProxies           bool                   `yaml:"use_proxies"`
	RandomizeHeaders     bool                   `yaml:"randomize_headers"`
	DelayPattern         string                 `yaml:"delay_pattern" validate:"oneof=constant random human burst"`
}

// ResourceLimitsConfig contains resource limits
type ResourceLimitsConfig struct {
	MaxMemoryMB          int                    `yaml:"max_memory_mb"`
	MaxCPUCores          int                    `yaml:"max_cpu_cores"`
	MaxCPUPercent        float64                `yaml:"max_cpu_percent"`
}

// PluginIntelligenceConfig contains plugin-specific intelligence settings
type PluginIntelligenceConfig struct {
	CorrelateWith        []string               `yaml:"correlate_with"`
	RiskWeight           float64                `yaml:"risk_weight"`
	ExtractPatterns      bool                   `yaml:"extract_patterns"`
	IdentifyAPIEndpoints bool                   `yaml:"identify_api_endpoints"`
	MapAPIEndpoints      bool                   `yaml:"map_api_endpoints"`
	DetectFrameworks     bool                   `yaml:"detect_frameworks"`
	ExtractDependencies  bool                   `yaml:"extract_dependencies"`
}

// SecurityConfig contains security policy settings
type SecurityConfig struct {
	Sandboxing           SandboxingConfig       `yaml:"sandboxing"`
	SecretSanitization   SecretSanitizationConfig `yaml:"secret_sanitization"`
	Compliance           ComplianceConfig       `yaml:"compliance"`
}

// SandboxingConfig contains sandboxing settings
type SandboxingConfig struct {
	Enabled              bool                   `yaml:"enabled"`
	DefaultPolicy        string                 `yaml:"default_policy" validate:"oneof=restricted moderate unrestricted"`
	Policies             map[string]SandboxPolicy `yaml:"policies"`
}

// SandboxPolicy defines sandbox restrictions
type SandboxPolicy struct {
	AllowNetwork         []string               `yaml:"allow_network"`
	DenySyscalls         []string               `yaml:"deny_syscalls"`
	MaxMemoryMB          int                    `yaml:"max_memory_mb"`
	MaxCPUPercent        float64                `yaml:"max_cpu_percent"`
	AllowAll             bool                   `yaml:"allow_all"`
}

// SecretSanitizationConfig contains secret sanitization patterns
type SecretSanitizationConfig struct {
	Patterns             []SecretPattern        `yaml:"patterns"`
}

// SecretPattern defines patterns for secret detection
type SecretPattern struct {
	Name                 string                 `yaml:"name"`
	Regex                string                 `yaml:"regex"`
	Action               string                 `yaml:"action" validate:"oneof=redact remove alert"`
}

// ComplianceConfig contains compliance settings
type ComplianceConfig struct {
	Mode                 string                 `yaml:"mode" validate:"oneof=standard gdpr hipaa pci"`
	DataRetentionDays    int                    `yaml:"data_retention_days" validate:"min=1"`
	EncryptionAtRest     bool                   `yaml:"encryption_at_rest"`
	AuditLogging         bool                   `yaml:"audit_logging"`
}

// TargetConfig contains target-specific overrides
type TargetConfig struct {
	Profile              string                 `yaml:"profile"`
	Plugins              map[string]PluginConfig `yaml:"plugins"`
	Scope                ScopeConfig            `yaml:"scope"`
	RateLimit            RateLimitConfig        `yaml:"rate_limit"`
}

// ScopeConfig defines target scope
type ScopeConfig struct {
	Include              []string               `yaml:"include"`
	Exclude              []string               `yaml:"exclude"`
}

// Intelligence sub-configurations

// CorrelationRule defines correlation rules
type CorrelationRule struct {
	Name                 string                 `yaml:"name"`
	Description          string                 `yaml:"description"`
	Conditions           []RuleCondition        `yaml:"conditions"`
	CorrelateWith        []string               `yaml:"correlate_with"`
	RiskMultiplier       float64                `yaml:"risk_multiplier"`
}

// RuleCondition defines conditions for correlation rules
type RuleCondition struct {
	Plugin               string                 `yaml:"plugin"`
	Field                string                 `yaml:"field"`
	Value                interface{}            `yaml:"value"`
}

// AnomalyDetectionConfig contains anomaly detection settings
type AnomalyDetectionConfig struct {
	Enabled              bool                   `yaml:"enabled"`
	Models               []AnomalyModel         `yaml:"models"`
}

// AnomalyModel defines anomaly detection models
type AnomalyModel struct {
	Type                 string                 `yaml:"type" validate:"oneof=response_time content_change behavioral"`
	Threshold            float64                `yaml:"threshold"`
	Window               string                 `yaml:"window"`
	Sensitivity          float64                `yaml:"sensitivity"`
	BaselinePeriod       string                 `yaml:"baseline_period"`
}

// AttackPathsConfig contains attack path analysis settings
type AttackPathsConfig struct {
	MaxDepth             int                    `yaml:"max_depth" validate:"min=1,max=20"`
	MinLikelihood        float64                `yaml:"min_likelihood" validate:"min=0,max=1"`
	ConsiderMitigations  bool                   `yaml:"consider_mitigations"`
}

// RiskScoringConfig contains risk scoring settings
type RiskScoringConfig struct {
	Algorithm            string                 `yaml:"algorithm" validate:"oneof=weighted_average bayesian ml"`
	Factors              []RiskFactor           `yaml:"factors"`
}

// RiskFactor defines risk scoring factors
type RiskFactor struct {
	Name                 string                 `yaml:"name"`
	Weight               float64                `yaml:"weight" validate:"min=0,max=1"`
}

// Default configurations

// NewDefaultConfig creates a default configuration
func NewDefaultConfig() *Config {
	return &Config{
		Global: GlobalConfig{
			Version:              "2.0.0",
			Workdir:              "~/.gorecon/work",
			Outdir:               "~/.gorecon/reports",
			Concurrency:          8,
			PluginTimeout:        15 * time.Minute,
			GlobalTimeout:        2 * time.Hour,
			RetryAttempts:        3,
			RetryDelay:           30 * time.Second,
			ConfirmActiveScans:   false,
			ScopeEnforcement:     true,
			ScopeFile:            "~/.gorecon/scope.txt",
			MaxMemoryMB:          2048,
			MaxDiskMB:            10240,
			MaxProcesses:         50,
			LogLevel:             "info",
			LogFormat:            "json",
			RedactSecrets:        true,
			SaveRawOutput:        true,
			CompressOutput:       true,
			Cache: CacheConfig{
				Enabled:      true,
				L1SizeMB:     512,
				L2Enabled:    true,
				L2RedisURL:   "redis://localhost:6379",
				L3Enabled:    false,
			},
			Intelligence: IntelligenceConfig{
				CorrelationEnabled:   true,
				AnomalyDetection:     true,
				AttackPathAnalysis:   true,
				RiskScoring:          true,
				MLModelsPath:         "~/.gorecon/models",
			},
			Distributed: DistributedConfig{
				Enabled:        false,
				Mode:           "coordinator",
				NATSURL:        "nats://localhost:4222",
			},
			API: APIConfig{
				Enabled:      true,
				RESTPort:     8080,
				GraphQLPort:  8081,
				GRPCPort:     50051,
				AuthEnabled:  true,
				RateLimitRPS: 100,
			},
			Streaming: StreamingConfig{
				Enabled:       true,
				WebSocketPort: 8082,
				SSEEnabled:    true,
				BufferSize:    1000,
			},
			Telemetry: TelemetryConfig{
				MetricsEnabled:  true,
				MetricsPort:     9090,
				TracingEnabled:  true,
				TracingEndpoint: "http://localhost:14268/api/traces",
			},
		},
		Profiles: map[string]ProfileConfig{
			"stealth": {
				Name:        "Stealth Mode",
				Description: "Low and slow scanning to avoid detection",
				RateLimit: RateLimitConfig{
					RequestsPerSecond: 1,
					BurstSize:         5,
					Jitter:            "1s-5s",
					HumanMode:         true,
				},
				Plugins: ProfilePluginConfig{
					PassiveOnly:   true,
					Exclude:       []string{"portscan", "vuln"},
				},
				Evasion: EvasionConfig{
					RotateUserAgents: true,
					UseProxies:       true,
					RandomizeHeaders: true,
					DelayPattern:     "human",
				},
			},
			"aggressive": {
				Name:        "Aggressive Mode",
				Description: "Fast, comprehensive scanning",
				RateLimit: RateLimitConfig{
					RequestsPerSecond: 50,
					BurstSize:         100,
				},
				Plugins: ProfilePluginConfig{
					EnableAll:         true,
					ParallelExecution: true,
					MaxWorkers:        20,
				},
				ResourceLimits: ResourceLimitsConfig{
					MaxMemoryMB:  4096,
					MaxCPUCores:  8,
				},
			},
			"passive": {
				Name:        "Passive Only",
				Description: "No active scanning, only passive reconnaissance",
				Plugins: ProfilePluginConfig{
					Categories:    []string{"wayback", "github", "js"},
					ExcludeActive: true,
				},
				RateLimit: RateLimitConfig{
					RequestsPerSecond: 10,
					BurstSize:         20,
				},
			},
		},
		Security: SecurityConfig{
			Sandboxing: SandboxingConfig{
				Enabled:       true,
				DefaultPolicy: "restricted",
				Policies: map[string]SandboxPolicy{
					"restricted": {
						AllowNetwork:  []string{"tcp:80", "tcp:443", "udp:53"},
						DenySyscalls:  []string{"ptrace", "mount"},
						MaxMemoryMB:   256,
						MaxCPUPercent: 25,
					},
					"moderate": {
						AllowNetwork:  []string{"tcp:*", "udp:53"},
						MaxMemoryMB:   512,
						MaxCPUPercent: 50,
					},
					"unrestricted": {
						AllowAll: true,
					},
				},
			},
			SecretSanitization: SecretSanitizationConfig{
				Patterns: []SecretPattern{
					{
						Name:   "aws_key",
						Regex:  "AKIA[0-9A-Z]{16}",
						Action: "redact",
					},
					{
						Name:   "github_token",
						Regex:  "ghp_[0-9a-zA-Z]{36}",
						Action: "redact",
					},
				},
			},
			Compliance: ComplianceConfig{
				Mode:              "standard",
				DataRetentionDays: 90,
				EncryptionAtRest:  true,
				AuditLogging:      true,
			},
		},
		Intelligence: IntelligenceConfig{
			CorrelationRules: []CorrelationRule{
				{
					Name:        "Cloud Storage Exposure",
					Description: "Correlate exposed cloud storage with sensitive data",
					Conditions: []RuleCondition{
						{Plugin: "cloud", Field: "public", Value: true},
						{Plugin: "js", Field: "secrets_found", Value: true},
					},
					RiskMultiplier: 2.0,
				},
			},
			AnomalyDetectionConf: AnomalyDetectionConfig{
				Enabled: true,
				Models: []AnomalyModel{
					{Type: "response_time", Threshold: 3.0, Window: "5m"},
					{Type: "content_change", Sensitivity: 0.7},
					{Type: "behavioral", BaselinePeriod: "24h"},
				},
			},
			AttackPaths: AttackPathsConfig{
				MaxDepth:            5,
				MinLikelihood:       0.3,
				ConsiderMitigations: true,
			},
			RiskScoringConf: RiskScoringConfig{
				Algorithm: "weighted_average",
				Factors: []RiskFactor{
					{Name: "exposure", Weight: 0.3},
					{Name: "exploitability", Weight: 0.4},
					{Name: "impact", Weight: 0.3},
				},
			},
		},
	}
}

// Validation methods

// Validate validates the entire configuration
func (c *Config) Validate() error {
	// Validate global config
	if err := c.Global.Validate(); err != nil {
		return fmt.Errorf("global config validation failed: %w", err)
	}
	
	// Validate profiles
	for name, profile := range c.Profiles {
		if err := profile.Validate(); err != nil {
			return fmt.Errorf("profile '%s' validation failed: %w", name, err)
		}
	}
	
	// Validate plugins
	for name, plugin := range c.Plugins {
		if err := plugin.Validate(); err != nil {
			return fmt.Errorf("plugin '%s' validation failed: %w", name, err)
		}
	}
	
	return nil
}

// Validate validates global configuration
func (gc *GlobalConfig) Validate() error {
	if gc.Concurrency < 1 || gc.Concurrency > 100 {
		return fmt.Errorf("concurrency must be between 1 and 100")
	}
	
	if gc.MaxMemoryMB < 256 {
		return fmt.Errorf("max_memory_mb must be at least 256")
	}
	
	if gc.LogLevel != "debug" && gc.LogLevel != "info" && gc.LogLevel != "warn" && gc.LogLevel != "error" && gc.LogLevel != "fatal" {
		return fmt.Errorf("log_level must be one of: debug, info, warn, error, fatal")
	}
	
	return nil
}

// Validate validates profile configuration
func (pc *ProfileConfig) Validate() error {
	if pc.Name == "" {
		return fmt.Errorf("profile name cannot be empty")
	}
	
	if pc.RateLimit.RequestsPerSecond < 1 {
		return fmt.Errorf("requests_per_second must be at least 1")
	}
	
	return nil
}

// Validate validates plugin configuration
func (pc *PluginConfig) Validate() error {
	if pc.MaxFindings < 0 {
		return fmt.Errorf("max_findings cannot be negative")
	}
	
	return nil
}

// GetProfile returns a profile by name, with inheritance resolved
func (c *Config) GetProfile(name string) (*ProfileConfig, error) {
	profile, exists := c.Profiles[name]
	if !exists {
		return nil, fmt.Errorf("profile '%s' not found", name)
	}
	
	// Handle inheritance
	if profile.InheritFrom != "" {
		parent, err := c.GetProfile(profile.InheritFrom)
		if err != nil {
			return nil, fmt.Errorf("failed to resolve parent profile '%s': %w", profile.InheritFrom, err)
		}
		
		// Merge parent and child profiles
		merged := c.mergeProfiles(parent, &profile)
		return merged, nil
	}
	
	return &profile, nil
}

// mergeProfiles merges parent and child profiles
func (c *Config) mergeProfiles(parent, child *ProfileConfig) *ProfileConfig {
	merged := *parent
	
	// Override with child values
	if child.Name != "" {
		merged.Name = child.Name
	}
	if child.Description != "" {
		merged.Description = child.Description
	}
	
	// Merge rate limit settings
	if child.RateLimit.RequestsPerSecond != 0 {
		merged.RateLimit.RequestsPerSecond = child.RateLimit.RequestsPerSecond
	}
	if child.RateLimit.BurstSize != 0 {
		merged.RateLimit.BurstSize = child.RateLimit.BurstSize
	}
	
	// Apply overrides
	for key, value := range child.Overrides {
		if merged.Overrides == nil {
			merged.Overrides = make(map[string]interface{})
		}
		merged.Overrides[key] = value
	}
	
	return &merged
}

// GetPluginConfig returns plugin configuration with overrides applied
func (c *Config) GetPluginConfig(name string, target string) *PluginConfig {
	// Start with global plugin config
	config := c.Plugins[name]
	
	// Apply target-specific overrides
	if targetConfig, exists := c.Targets[target]; exists {
		if pluginOverride, exists := targetConfig.Plugins[name]; exists {
			// Merge plugin configurations
			if pluginOverride.Enabled {
				config.Enabled = pluginOverride.Enabled
			}
			if pluginOverride.MaxFindings != 0 {
				config.MaxFindings = pluginOverride.MaxFindings
			}
			if pluginOverride.CacheTTL != 0 {
				config.CacheTTL = pluginOverride.CacheTTL
			}
		}
	}
	
	return &config
}
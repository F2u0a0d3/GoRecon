package config

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/go-playground/validator/v10"
	"github.com/spf13/viper"
)

// Loader handles configuration loading from multiple sources
type Loader struct {
	viper     *viper.Viper
	validator *validator.Validate
}

// NewLoader creates a new configuration loader
func NewLoader() *Loader {
	return &Loader{
		viper:     viper.New(),
		validator: validator.New(),
	}
}

// Load loads configuration from file, environment variables, and defaults
func (l *Loader) Load(configPath string) (*Config, error) {
	// Set up Viper
	l.setupViper(configPath)
	
	// Load configuration
	if err := l.viper.ReadInConfig(); err != nil {
		if _, ok := err.(viper.ConfigFileNotFoundError); !ok {
			return nil, fmt.Errorf("failed to read config file: %w", err)
		}
		// Config file not found, use defaults
	}
	
	// Unmarshal into config struct
	var config Config
	if err := l.viper.Unmarshal(&config); err != nil {
		return nil, fmt.Errorf("failed to unmarshal config: %w", err)
	}
	
	// Apply defaults if config is empty
	if l.isEmptyConfig(&config) {
		defaultConfig := NewDefaultConfig()
		config = *defaultConfig
	}
	
	// Expand environment variables in string fields
	if err := l.expandEnvironmentVars(&config); err != nil {
		return nil, fmt.Errorf("failed to expand environment variables: %w", err)
	}
	
	// Validate configuration
	if err := l.validator.Struct(&config); err != nil {
		return nil, fmt.Errorf("config validation failed: %w", err)
	}
	
	// Custom validation
	if err := config.Validate(); err != nil {
		return nil, fmt.Errorf("custom config validation failed: %w", err)
	}
	
	return &config, nil
}

// setupViper configures Viper with search paths and environment variables
func (l *Loader) setupViper(configPath string) {
	// Set config name and type
	l.viper.SetConfigName("config")
	l.viper.SetConfigType("yaml")
	
	// Add config paths
	if configPath != "" {
		if filepath.Ext(configPath) != "" {
			// Specific file path
			l.viper.SetConfigFile(configPath)
		} else {
			// Directory path
			l.viper.AddConfigPath(configPath)
		}
	}
	
	// Default config paths
	l.viper.AddConfigPath(".")
	l.viper.AddConfigPath("./configs")
	l.viper.AddConfigPath("$HOME/.gorecon")
	l.viper.AddConfigPath("/etc/gorecon")
	
	// Environment variables
	l.viper.SetEnvPrefix("GORECON")
	l.viper.AutomaticEnv()
	l.viper.SetEnvKeyReplacer(strings.NewReplacer(".", "_", "-", "_"))
	
	// Set defaults
	l.setDefaults()
}

// setDefaults sets default values in Viper
func (l *Loader) setDefaults() {
	// Global defaults
	l.viper.SetDefault("global.version", "2.0.0")
	l.viper.SetDefault("global.workdir", "~/.gorecon/work")
	l.viper.SetDefault("global.outdir", "~/.gorecon/reports")
	l.viper.SetDefault("global.concurrency", 8)
	l.viper.SetDefault("global.plugin_timeout", "15m")
	l.viper.SetDefault("global.global_timeout", "2h")
	l.viper.SetDefault("global.retry_attempts", 3)
	l.viper.SetDefault("global.retry_delay", "30s")
	l.viper.SetDefault("global.confirm_active_scans", false)
	l.viper.SetDefault("global.scope_enforcement", true)
	l.viper.SetDefault("global.max_memory_mb", 2048)
	l.viper.SetDefault("global.max_disk_mb", 10240)
	l.viper.SetDefault("global.max_processes", 50)
	l.viper.SetDefault("global.log_level", "info")
	l.viper.SetDefault("global.log_format", "json")
	l.viper.SetDefault("global.redact_secrets", true)
	l.viper.SetDefault("global.save_raw_output", true)
	l.viper.SetDefault("global.compress_output", true)
	
	// Cache defaults
	l.viper.SetDefault("global.cache.enabled", true)
	l.viper.SetDefault("global.cache.l1_size_mb", 512)
	l.viper.SetDefault("global.cache.l2_enabled", true)
	l.viper.SetDefault("global.cache.l2_redis_url", "redis://localhost:6379")
	l.viper.SetDefault("global.cache.l3_enabled", false)
	
	// Intelligence defaults
	l.viper.SetDefault("global.intelligence.correlation_enabled", true)
	l.viper.SetDefault("global.intelligence.anomaly_detection", true)
	l.viper.SetDefault("global.intelligence.attack_path_analysis", true)
	l.viper.SetDefault("global.intelligence.risk_scoring", true)
	
	// API defaults
	l.viper.SetDefault("global.api.enabled", true)
	l.viper.SetDefault("global.api.rest_port", 8080)
	l.viper.SetDefault("global.api.graphql_port", 8081)
	l.viper.SetDefault("global.api.grpc_port", 50051)
	l.viper.SetDefault("global.api.auth_enabled", true)
	l.viper.SetDefault("global.api.rate_limit_rps", 100)
	
	// Streaming defaults
	l.viper.SetDefault("global.streaming.enabled", true)
	l.viper.SetDefault("global.streaming.websocket_port", 8082)
	l.viper.SetDefault("global.streaming.sse_enabled", true)
	l.viper.SetDefault("global.streaming.buffer_size", 1000)
	
	// Telemetry defaults
	l.viper.SetDefault("global.telemetry.metrics_enabled", true)
	l.viper.SetDefault("global.telemetry.metrics_port", 9090)
	l.viper.SetDefault("global.telemetry.tracing_enabled", true)
}

// isEmptyConfig checks if the config is essentially empty
func (l *Loader) isEmptyConfig(config *Config) bool {
	return config.Global.Version == "" && len(config.Profiles) == 0 && len(config.Plugins) == 0
}

// expandEnvironmentVars expands environment variables in configuration strings
func (l *Loader) expandEnvironmentVars(config *Config) error {
	// Expand paths
	config.Global.Workdir = l.expandPath(config.Global.Workdir)
	config.Global.Outdir = l.expandPath(config.Global.Outdir)
	config.Global.ScopeFile = l.expandPath(config.Global.ScopeFile)
	config.Global.Intelligence.MLModelsPath = l.expandPath(config.Global.Intelligence.MLModelsPath)
	
	// Expand cache settings
	config.Global.Cache.L2RedisURL = l.expandEnvVars(config.Global.Cache.L2RedisURL)
	config.Global.Cache.L3S3Bucket = l.expandEnvVars(config.Global.Cache.L3S3Bucket)
	
	// Expand distributed settings
	config.Global.Distributed.CoordinatorURL = l.expandEnvVars(config.Global.Distributed.CoordinatorURL)
	config.Global.Distributed.NATSURL = l.expandEnvVars(config.Global.Distributed.NATSURL)
	
	// Expand environment variables map
	for key, value := range config.Environment {
		config.Environment[key] = l.expandEnvVars(value)
	}
	
	// Expand tool paths
	for name, tool := range config.Tools {
		tool.Path = l.expandEnvVars(tool.Path)
		config.Tools[name] = tool
	}
	
	return nil
}

// expandPath expands ~ and environment variables in file paths
func (l *Loader) expandPath(path string) string {
	if path == "" {
		return path
	}
	
	// Expand ~
	if strings.HasPrefix(path, "~/") {
		home, err := os.UserHomeDir()
		if err == nil {
			path = filepath.Join(home, path[2:])
		}
	}
	
	// Expand environment variables
	return l.expandEnvVars(path)
}

// expandEnvVars expands environment variables in strings
func (l *Loader) expandEnvVars(s string) string {
	return os.ExpandEnv(s)
}

// SaveConfig saves the configuration to a file
func (l *Loader) SaveConfig(config *Config, path string) error {
	l.viper.SetConfigFile(path)
	
	// Convert config back to map for saving
	configMap := make(map[string]interface{})
	
	// This is a simplified save - in practice you'd need to convert
	// the struct to a map preserving the YAML structure
	configMap["global"] = config.Global
	configMap["profiles"] = config.Profiles
	configMap["plugins"] = config.Plugins
	configMap["tools"] = config.Tools
	configMap["intelligence"] = config.Intelligence
	configMap["security"] = config.Security
	configMap["environment"] = config.Environment
	configMap["targets"] = config.Targets
	
	// Merge into Viper
	if err := l.viper.MergeConfigMap(configMap); err != nil {
		return fmt.Errorf("failed to merge config map: %w", err)
	}
	
	// Write config file
	if err := l.viper.WriteConfig(); err != nil {
		return fmt.Errorf("failed to write config file: %w", err)
	}
	
	return nil
}

// LoadProfile loads a specific profile configuration
func (l *Loader) LoadProfile(profilePath string) (*ProfileConfig, error) {
	v := viper.New()
	v.SetConfigFile(profilePath)
	
	if err := v.ReadInConfig(); err != nil {
		return nil, fmt.Errorf("failed to read profile file: %w", err)
	}
	
	var profile ProfileConfig
	if err := v.Unmarshal(&profile); err != nil {
		return nil, fmt.Errorf("failed to unmarshal profile: %w", err)
	}
	
	if err := l.validator.Struct(&profile); err != nil {
		return nil, fmt.Errorf("profile validation failed: %w", err)
	}
	
	return &profile, nil
}

// LoadScope loads scope configuration from file
func (l *Loader) LoadScope(scopeFile string) (*ScopeConfig, error) {
	if scopeFile == "" {
		return &ScopeConfig{}, nil
	}
	
	data, err := os.ReadFile(l.expandPath(scopeFile))
	if err != nil {
		if os.IsNotExist(err) {
			return &ScopeConfig{}, nil
		}
		return nil, fmt.Errorf("failed to read scope file: %w", err)
	}
	
	scope := &ScopeConfig{}
	lines := strings.Split(string(data), "\n")
	
	for _, line := range lines {
		line = strings.TrimSpace(line)
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		
		// Simple format: +include or -exclude or just include
		if strings.HasPrefix(line, "+") {
			scope.Include = append(scope.Include, line[1:])
		} else if strings.HasPrefix(line, "-") {
			scope.Exclude = append(scope.Exclude, line[1:])
		} else {
			scope.Include = append(scope.Include, line)
		}
	}
	
	return scope, nil
}

// MergeConfigs merges multiple configurations
func (l *Loader) MergeConfigs(configs ...*Config) *Config {
	if len(configs) == 0 {
		return NewDefaultConfig()
	}
	
	base := configs[0]
	
	for _, config := range configs[1:] {
		// Merge global settings (last one wins for most fields)
		if config.Global.Concurrency != 0 {
			base.Global.Concurrency = config.Global.Concurrency
		}
		if config.Global.LogLevel != "" {
			base.Global.LogLevel = config.Global.LogLevel
		}
		
		// Merge profiles (additive)
		if base.Profiles == nil {
			base.Profiles = make(map[string]ProfileConfig)
		}
		for name, profile := range config.Profiles {
			base.Profiles[name] = profile
		}
		
		// Merge plugins (additive)
		if base.Plugins == nil {
			base.Plugins = make(map[string]PluginConfig)
		}
		for name, plugin := range config.Plugins {
			base.Plugins[name] = plugin
		}
		
		// Merge tools (additive)
		if base.Tools == nil {
			base.Tools = make(map[string]ToolConfig)
		}
		for name, tool := range config.Tools {
			base.Tools[name] = tool
		}
		
		// Merge environment variables (additive)
		if base.Environment == nil {
			base.Environment = make(map[string]string)
		}
		for key, value := range config.Environment {
			base.Environment[key] = value
		}
		
		// Merge targets (additive)
		if base.Targets == nil {
			base.Targets = make(map[string]TargetConfig)
		}
		for key, target := range config.Targets {
			base.Targets[key] = target
		}
	}
	
	return base
}

// ValidateConfigFile validates a configuration file without loading it
func (l *Loader) ValidateConfigFile(path string) error {
	config, err := l.Load(path)
	if err != nil {
		return err
	}
	
	return config.Validate()
}

// GetConfigPaths returns the list of paths where config files are searched
func (l *Loader) GetConfigPaths() []string {
	return []string{
		"./config.yaml",
		"./configs/config.yaml",
		"$HOME/.gorecon/config.yaml",
		"/etc/gorecon/config.yaml",
	}
}

// CreateDefaultConfigFile creates a default configuration file
func (l *Loader) CreateDefaultConfigFile(path string) error {
	defaultConfig := NewDefaultConfig()
	return l.SaveConfig(defaultConfig, path)
}
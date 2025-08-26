package base

import (
	"context"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"time"

	"github.com/google/uuid"
	"github.com/f2u0a0d3/GoRecon/pkg/config"
	"github.com/f2u0a0d3/GoRecon/pkg/core"
	"github.com/f2u0a0d3/GoRecon/pkg/models"
)

// BaseAdapter provides common functionality for plugin adapters
type BaseAdapter struct {
	name          string
	category      string
	description   string
	version       string
	author        string
	toolName      string
	toolPath      string
	toolArgs      []string
	passive       bool
	confirmation  bool
	duration      time.Duration
	concurrency   int
	priority      int
	resources     core.Resources
	dependencies  []core.PluginDependency
	provides      []string
	consumes      []string
	patterns      []core.Pattern
	
	// Runtime state
	logger        core.Logger
	shared        *core.SharedContext
}

// BaseAdapterConfig contains configuration for base adapter
type BaseAdapterConfig struct {
	Name          string
	Category      string
	Description   string
	Version       string
	Author        string
	ToolName      string
	ToolPath      string
	ToolArgs      []string
	Passive       bool
	Confirmation  bool
	Duration      time.Duration
	Concurrency   int
	Priority      int
	Resources     core.Resources
	Dependencies  []core.PluginDependency
	Provides      []string
	Consumes      []string
	Patterns      []core.Pattern
}

// NewBaseAdapter creates a new base adapter with the given configuration
func NewBaseAdapter(config BaseAdapterConfig) *BaseAdapter {
	return &BaseAdapter{
		name:         config.Name,
		category:     config.Category,
		description:  config.Description,
		version:      config.Version,
		author:       config.Author,
		toolName:     config.ToolName,
		toolPath:     config.ToolPath,
		toolArgs:     config.ToolArgs,
		passive:      config.Passive,
		confirmation: config.Confirmation,
		duration:     config.Duration,
		concurrency:  config.Concurrency,
		priority:     config.Priority,
		resources:    config.Resources,
		dependencies: config.Dependencies,
		provides:     config.Provides,
		consumes:     config.Consumes,
		patterns:     config.Patterns,
	}
}

// Metadata methods
func (ba *BaseAdapter) Name() string                      { return ba.name }
func (ba *BaseAdapter) Category() string                  { return ba.category }
func (ba *BaseAdapter) Description() string               { return ba.description }
func (ba *BaseAdapter) Version() string                   { return ba.version }
func (ba *BaseAdapter) Author() string                    { return ba.author }

// Dependency methods
func (ba *BaseAdapter) RequiredBinaries() []string        { return []string{ba.toolName} }
func (ba *BaseAdapter) RequiredEnvVars() []string         { return []string{} }
func (ba *BaseAdapter) SupportedTargetTypes() []string    { return []string{"web", "api", "subdomain"} }
func (ba *BaseAdapter) Dependencies() []core.PluginDependency { return ba.dependencies }
func (ba *BaseAdapter) Provides() []string                { return ba.provides }
func (ba *BaseAdapter) Consumes() []string                { return ba.consumes }

// Capability methods
func (ba *BaseAdapter) IsPassive() bool                   { return ba.passive }
func (ba *BaseAdapter) RequiresConfirmation() bool        { return ba.confirmation }
func (ba *BaseAdapter) EstimatedDuration() time.Duration  { return ba.duration }
func (ba *BaseAdapter) MaxConcurrency() int               { return ba.concurrency }
func (ba *BaseAdapter) Priority() int                     { return ba.priority }
func (ba *BaseAdapter) ResourceRequirements() core.Resources { return ba.resources }

// Intelligence methods
func (ba *BaseAdapter) GetIntelligencePatterns() []core.Pattern { return ba.patterns }

// Validate checks if the plugin can run in the current environment
func (ba *BaseAdapter) Validate(ctx context.Context, cfg *config.Config) error {
	// Check if binary exists
	if ba.toolPath == "" {
		toolPath, err := ba.findBinary(ba.toolName)
		if err != nil {
			return fmt.Errorf("tool %s not found in PATH: %w", ba.toolName, err)
		}
		ba.toolPath = toolPath
	}
	
	// Verify binary is executable
	if err := ba.checkExecutable(ba.toolPath); err != nil {
		return fmt.Errorf("tool %s is not executable: %w", ba.toolPath, err)
	}
	
	// Check required environment variables
	for _, envVar := range ba.RequiredEnvVars() {
		if os.Getenv(envVar) == "" {
			return fmt.Errorf("required environment variable %s is not set", envVar)
		}
	}
	
	return nil
}

// Prepare sets up the plugin for execution
func (ba *BaseAdapter) Prepare(ctx context.Context, target *models.Target, cfg *config.Config, shared *core.SharedContext) error {
	ba.shared = shared
	ba.logger = shared.GetLogger().WithField("plugin", ba.name)
	
	ba.logger.Info("Plugin prepared for execution",
		"target", target.URL,
		"tool", ba.toolName,
		"passive", ba.passive)
	
	return nil
}

// Teardown cleans up after plugin execution
func (ba *BaseAdapter) Teardown(ctx context.Context) error {
	ba.logger.Info("Plugin execution completed")
	return nil
}

// ProcessDiscovery processes discoveries from other plugins
func (ba *BaseAdapter) ProcessDiscovery(ctx context.Context, discovery models.Discovery) error {
	// Default implementation - log discovery
	ba.logger.Debug("Received discovery",
		"type", discovery.Type,
		"value", discovery.Value,
		"source", discovery.Source,
		"confidence", discovery.Confidence)
	return nil
}

// ExecuteCommand executes the tool command with given arguments
func (ba *BaseAdapter) ExecuteCommand(ctx context.Context, args []string) ([]byte, error) {
	// Build full command
	cmdArgs := append(ba.toolArgs, args...)
	cmd := exec.CommandContext(ctx, ba.toolPath, cmdArgs...)
	
	ba.logger.Debug("Executing command",
		"tool", ba.toolPath,
		"args", strings.Join(cmdArgs, " "))
	
	// Start metrics timer (only if metrics is available)
	var timer func()
	if ba.shared.GetMetrics() != nil {
		timer = ba.shared.GetMetrics().Timer("plugin.execution_time").Start()
		defer timer()
	}
	
	// Execute command
	output, err := cmd.CombinedOutput()
	if err != nil {
		ba.logger.Error("Command execution failed", err,
			"tool", ba.toolPath,
			"args", strings.Join(cmdArgs, " "),
			"output", string(output))
		return nil, fmt.Errorf("command execution failed: %w", err)
	}
	
	ba.logger.Debug("Command executed successfully",
		"output_size", len(output))
	
	return output, nil
}

// CreateResult creates a standard plugin result
func (ba *BaseAdapter) CreateResult(target *models.Target, title, description string, severity string, data map[string]interface{}) models.PluginResult {
	result := models.PluginResult{
		ID:          uuid.New().String(),
		Plugin:      ba.name,
		Tool:        ba.toolName,
		Category:    ba.category,
		Target:      target.URL,
		Timestamp:   time.Now(),
		Severity:    severity,
		Title:       title,
		Description: description,
		Data:        data,
		Confidence:  0.8, // Default confidence
		Tags:        []string{},
		False:       false,
		Verified:    false,
	}
	
	return result
}

// CreateEvidence creates evidence for a finding
func (ba *BaseAdapter) CreateEvidence(evidenceType, content, url string, statusCode int, headers map[string]string) models.Evidence {
	return models.Evidence{
		Type:       evidenceType,
		Content:    content,
		URL:        url,
		StatusCode: statusCode,
		Headers:    headers,
		Metadata:   make(map[string]interface{}),
	}
}

// Helper methods

// findBinary searches for a binary in PATH
func (ba *BaseAdapter) findBinary(name string) (string, error) {
	path, err := exec.LookPath(name)
	if err != nil {
		return "", err
	}
	return path, nil
}

// checkExecutable verifies that a file is executable
func (ba *BaseAdapter) checkExecutable(path string) error {
	info, err := os.Stat(path)
	if err != nil {
		return err
	}
	
	if info.Mode()&0111 == 0 {
		return fmt.Errorf("file is not executable")
	}
	
	return nil
}

// GetCacheKey generates a cache key for the plugin and target
func (ba *BaseAdapter) GetCacheKey(target *models.Target, suffix string) string {
	key := fmt.Sprintf("%s:%s", ba.name, target.Domain)
	if suffix != "" {
		key = fmt.Sprintf("%s:%s", key, suffix)
	}
	return key
}

// CheckCache checks if results are cached
func (ba *BaseAdapter) CheckCache(ctx context.Context, key string) (interface{}, bool) {
	if ba.shared == nil || ba.shared.GetCache() == nil {
		return nil, false
	}
	
	result, err := ba.shared.GetCache().Get(ctx, key)
	if err != nil {
		ba.logger.Debug("Cache miss", "key", key, "error", err.Error())
		return nil, false
	}
	
	ba.logger.Debug("Cache hit", "key", key)
	ba.shared.GetMetrics().Counter("plugin.cache_hits").Inc()
	return result, true
}

// SetCache stores results in cache
func (ba *BaseAdapter) SetCache(ctx context.Context, key string, value interface{}, ttl time.Duration) {
	if ba.shared == nil || ba.shared.GetCache() == nil {
		return
	}
	
	err := ba.shared.GetCache().Set(ctx, key, value, ttl)
	if err != nil {
		ba.logger.Error("Failed to set cache", err, "key", key)
	} else {
		ba.logger.Debug("Cached result", "key", key, "ttl", ttl)
	}
}

// AddDiscovery adds a discovery to the shared context
func (ba *BaseAdapter) AddDiscovery(discoveryType string, value interface{}, confidence float64) {
	if ba.shared == nil {
		return
	}
	
	discovery := models.Discovery{
		Type:       discoveryType,
		Value:      value,
		Source:     ba.name,
		Confidence: confidence,
		Timestamp:  time.Now(),
		Metadata:   make(map[string]interface{}),
	}
	
	ba.shared.AddDiscovery(discovery)
	ba.logger.Debug("Added discovery", "type", discoveryType, "value", value)
}

// GetDiscoveries retrieves discoveries of a specific type
func (ba *BaseAdapter) GetDiscoveries(discoveryType string) []models.Discovery {
	if ba.shared == nil {
		return nil
	}
	return ba.shared.GetDiscoveries(discoveryType)
}

// NormalizeURL normalizes a URL for consistent processing
func (ba *BaseAdapter) NormalizeURL(rawURL string) string {
	// Remove trailing slashes
	rawURL = strings.TrimRight(rawURL, "/")
	
	// Add protocol if missing
	if !strings.HasPrefix(rawURL, "http://") && !strings.HasPrefix(rawURL, "https://") {
		rawURL = "https://" + rawURL
	}
	
	return rawURL
}

// ExtractDomain extracts domain from URL
func (ba *BaseAdapter) ExtractDomain(rawURL string) string {
	// Remove protocol
	url := strings.TrimPrefix(rawURL, "https://")
	url = strings.TrimPrefix(url, "http://")
	
	// Remove path
	if idx := strings.Index(url, "/"); idx != -1 {
		url = url[:idx]
	}
	
	// Remove port
	if idx := strings.Index(url, ":"); idx != -1 {
		url = url[:idx]
	}
	
	return url
}

// CreateWorkspace creates a temporary workspace for the plugin
func (ba *BaseAdapter) CreateWorkspace() (string, error) {
	workspaceDir := filepath.Join(os.TempDir(), "gorecon", ba.name, uuid.New().String())
	
	err := os.MkdirAll(workspaceDir, 0755)
	if err != nil {
		return "", fmt.Errorf("failed to create workspace: %w", err)
	}
	
	ba.logger.Debug("Created workspace", "path", workspaceDir)
	return workspaceDir, nil
}

// CleanupWorkspace removes the temporary workspace
func (ba *BaseAdapter) CleanupWorkspace(workspaceDir string) {
	err := os.RemoveAll(workspaceDir)
	if err != nil {
		ba.logger.Error("Failed to cleanup workspace", err, "path", workspaceDir)
	} else {
		ba.logger.Debug("Cleaned up workspace", "path", workspaceDir)
	}
}

// ValidateTargetType checks if the target type is supported
func (ba *BaseAdapter) ValidateTargetType(target *models.Target) bool {
	supportedTypes := ba.SupportedTargetTypes()
	for _, supportedType := range supportedTypes {
		if string(target.Type) == supportedType {
			return true
		}
	}
	return false
}

// RecordMetrics records execution metrics
func (ba *BaseAdapter) RecordMetrics(duration time.Duration, resultCount int, errorCount int) {
	metrics := ba.shared.GetMetrics()
	
	metrics.Histogram("plugin.execution_duration").Observe(duration.Seconds())
	metrics.Counter("plugin.executions").Inc()
	metrics.Gauge("plugin.results").Set(float64(resultCount))
	
	if errorCount > 0 {
		metrics.Counter("plugin.errors").Add(float64(errorCount))
	}
}
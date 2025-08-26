package core

import (
	"context"
	"fmt"
	"sync"
	"time"

	"github.com/f2u0a0d3/GoRecon/pkg/config"
	"github.com/f2u0a0d3/GoRecon/pkg/models"
	"github.com/rs/zerolog"
)

// Pipeline orchestrates penetration testing stages according to the security workflow
type Pipeline struct {
	config      *config.Config
	registry    *PluginRegistry
	workspace   *Workspace
	logger      zerolog.Logger
	
	// Stage management
	stages      []Stage
	checkpoint  *Checkpoint
	mutex       sync.RWMutex
	
	// Execution state
	status      PipelineStatus
	startTime   time.Time
	endTime     time.Time
	results     chan models.PluginResult
	errors      chan error
}

// Stage represents a phase in the penetration testing workflow
type Stage struct {
	Name        string        `json:"name"`
	Category    string        `json:"category"`
	Plugins     []string      `json:"plugins"`
	Required    bool          `json:"required"`
	NeedsConfirm bool         `json:"needs_confirm"`
	DependsOn   []string      `json:"depends_on"`
	Timeout     time.Duration `json:"timeout"`
	Passive     bool          `json:"passive"`
	Description string        `json:"description"`
}

// PipelineStatus represents the current pipeline execution status
type PipelineStatus struct {
	State       string                    `json:"state"` // pending, running, completed, failed, paused
	CurrentStage string                   `json:"current_stage"`
	Progress    float64                   `json:"progress"`
	StageStatus map[string]StageStatus    `json:"stage_status"`
	StartTime   time.Time                 `json:"start_time"`
	EndTime     time.Time                 `json:"end_time"`
	Duration    time.Duration             `json:"duration"`
	Error       string                    `json:"error,omitempty"`
}

// StageStatus represents the status of a single stage
type StageStatus struct {
	State       string        `json:"state"` // pending, running, completed, failed, skipped
	StartTime   time.Time     `json:"start_time"`
	EndTime     time.Time     `json:"end_time"`
	Duration    time.Duration `json:"duration"`
	Results     int           `json:"results"`
	Error       string        `json:"error,omitempty"`
}

// Checkpoint enables resuming interrupted scans
type Checkpoint struct {
	Target        string                    `json:"target"`
	CompletedStages []string                `json:"completed_stages"`
	CurrentStage  string                    `json:"current_stage"`
	Timestamp     time.Time                 `json:"timestamp"`
	Results       []models.PluginResult     `json:"results"`
	Workspace     string                    `json:"workspace"`
}

// Note: Workspace type is defined in workspace.go

// NewPipeline creates a new penetration testing pipeline
func NewPipeline(cfg *config.Config, registry *PluginRegistry, logger zerolog.Logger) *Pipeline {
	return &Pipeline{
		config:    cfg,
		registry:  registry,
		logger:    logger.With().Str("component", "pipeline").Logger(),
		results:   make(chan models.PluginResult, 1000),
		errors:    make(chan error, 100),
		status: PipelineStatus{
			State:       "pending",
			StageStatus: make(map[string]StageStatus),
		},
	}
}

// InitStages initializes the standard penetration testing workflow stages
func (p *Pipeline) InitStages() {
	p.stages = []Stage{
		{
			Name:        "Subdomain Takeover Check",
			Category:    "takeover",
			Plugins:     []string{"subzy"},
			Required:    true,
			Passive:     true,
			Description: "Check for subdomain takeover vulnerabilities using subzy with verification",
			Timeout:     3 * time.Minute,
		},
		{
			Name:        "Cloud Asset Discovery",
			Category:    "cloud",
			Plugins:     []string{"cloud_enum", "sni_scanner"},
			Required:    true,
			Passive:     true,
			Description: "Discover cloud assets and services",
			Timeout:     25 * time.Minute, // Increased for comprehensive cloud enumeration
		},
		{
			Name:        "Historical URL Collection",
			Category:    "wayback",
			Plugins:     []string{"wayback"},
			Required:    true,
			Passive:     true,
			Description: "Collect URLs from web archives using waybackurls, gau, and waymore",
			Timeout:     20 * time.Minute,
		},
		{
			Name:        "Port Scanning",
			Category:    "portscan",
			Plugins:     []string{"portscan"},
			NeedsConfirm: true,
			Passive:     false,
			Description: "Comprehensive port scanning using smap, masscan, and naabu",
			Timeout:     30 * time.Minute,
		},
		{
			Name:        "HTTP Service Probing",
			Category:    "httpprobe",
			Plugins:     []string{"httpprobe"},
			Required:    true,
			Passive:     false,
			Description: "Probe HTTP services and enumerate technologies using httpx",
			Timeout:     20 * time.Minute,
			DependsOn:   []string{"wayback", "portscan"},
		},
		{
			Name:        "JavaScript Analysis",
			Category:    "js",
			Plugins:     []string{"jsanalysis"},
			Required:    true,
			Passive:     false,
			Description: "Analyze JavaScript files for endpoints and secrets using jsluice and linkfinder",
			Timeout:     15 * time.Minute,
			DependsOn:   []string{"httpprobe"},
		},
		{
			Name:        "Web Crawling",
			Category:    "crawl",
			Plugins:     []string{"crawl"},
			Passive:     false,
			Description: "Crawl web applications for additional endpoints using hakrawler",
			Timeout:     25 * time.Minute,
			DependsOn:   []string{"httpprobe"},
		},
		{
			Name:        "Broken Link Check",
			Category:    "blc",
			Plugins:     []string{"blc"},
			Passive:     false,
			Description: "Check for broken links and potential issues",
			Timeout:     10 * time.Minute,
			DependsOn:   []string{"crawl"},
		},
		{
			Name:        "Directory Fuzzing",
			Category:    "dirfuzz",
			Plugins:     []string{"dirfuzz"},
			NeedsConfirm: true,
			Passive:     false,
			Description: "Fuzz directories and files using ffuf",
			Timeout:     45 * time.Minute,
			DependsOn:   []string{"httpprobe"},
		},
		{
			Name:        "Parameter Discovery",
			Category:    "params",
			Plugins:     []string{"paramspider"},
			Passive:     false,
			Description: "Discover URL parameters and endpoints",
			Timeout:     20 * time.Minute,
			DependsOn:   []string{"crawl", "js"},
		},
		{
			Name:        "Vulnerability Scanning",
			Category:    "vuln",
			Plugins:     []string{"vuln"},
			NeedsConfirm: true,
			Passive:     false,
			Description: "Scan for known vulnerabilities using nuclei",
			Timeout:     60 * time.Minute,
			DependsOn:   []string{"httpprobe", "dirfuzz"},
		},
	}
	
	// Initialize stage status
	for _, stage := range p.stages {
		p.status.StageStatus[stage.Category] = StageStatus{
			State: "pending",
		}
	}
}

// RunAll executes the complete penetration testing pipeline
func (p *Pipeline) RunAll(ctx context.Context, target *models.Target) error {
	p.logger.Info().
		Str("target", target.URL).
		Str("domain", target.Domain).
		Msg("Starting complete penetration testing pipeline")
	
	// Initialize workspace
	workspace, err := p.createWorkspace(target)
	if err != nil {
		return fmt.Errorf("failed to create workspace: %w", err)
	}
	p.workspace = workspace
	
	// Update status
	p.status.State = "running"
	p.status.StartTime = time.Now()
	p.startTime = time.Now()
	
	// Execute stages in order
	for _, stage := range p.stages {
		// Check context cancellation
		select {
		case <-ctx.Done():
			return ctx.Err()
		default:
		}
		
		// Check if stage needs confirmation and hasn't been confirmed
		if stage.NeedsConfirm && !p.config.Global.ConfirmActiveScans {
			p.logger.Warn().
				Str("stage", stage.Name).
				Msg("Skipping stage - requires confirmation (use --confirm flag)")
			
			p.status.StageStatus[stage.Category] = StageStatus{
				State: "skipped",
			}
			continue
		}
		
		// Check dependencies
		if !p.areDependenciesMet(stage) {
			p.logger.Warn().
				Str("stage", stage.Name).
				Strs("depends_on", stage.DependsOn).
				Msg("Skipping stage - dependencies not met")
			
			p.status.StageStatus[stage.Category] = StageStatus{
				State: "skipped",
			}
			continue
		}
		
		// Execute stage
		p.status.CurrentStage = stage.Category
		
		if err := p.runStage(ctx, stage, target); err != nil {
			if stage.Required {
				p.status.State = "failed"
				p.status.Error = fmt.Sprintf("Required stage %s failed: %v", stage.Name, err)
				return fmt.Errorf("required stage %s failed: %w", stage.Name, err)
			}
			
			p.logger.Error().Err(err).
				Str("stage", stage.Name).
				Msg("Stage failed, continuing")
			
			p.status.StageStatus[stage.Category] = StageStatus{
				State: "failed",
				Error: err.Error(),
			}
		}
		
		// Save checkpoint
		if err := p.saveCheckpoint(stage.Category, target); err != nil {
			p.logger.Warn().Err(err).Msg("Failed to save checkpoint")
		}
		
		// Update progress
		p.updateProgress()
	}
	
	// Complete pipeline
	p.status.State = "completed"
	p.status.EndTime = time.Now()
	p.status.Duration = time.Since(p.startTime)
	p.endTime = time.Now()
	
	p.logger.Info().
		Dur("duration", p.status.Duration).
		Str("target", target.URL).
		Msg("Pipeline completed successfully")
	
	return nil
}

// RunStep executes a single stage of the pipeline
func (p *Pipeline) RunStep(ctx context.Context, stageCategory string, target *models.Target) error {
	p.logger.Info().
		Str("stage", stageCategory).
		Str("target", target.URL).
		Msg("Running single stage")
	
	// Find the stage
	var stage *Stage
	for _, s := range p.stages {
		if s.Category == stageCategory {
			stage = &s
			break
		}
	}
	
	if stage == nil {
		return fmt.Errorf("stage %s not found", stageCategory)
	}
	
	// Check confirmation requirements
	if stage.NeedsConfirm && !p.config.Global.ConfirmActiveScans {
		return fmt.Errorf("stage %s requires --confirm flag for active scanning", stage.Name)
	}
	
	// Initialize workspace if needed
	if p.workspace == nil {
		workspace, err := p.createWorkspace(target)
		if err != nil {
			return fmt.Errorf("failed to create workspace: %w", err)
		}
		p.workspace = workspace
	}
	
	// Execute the stage
	return p.runStage(ctx, *stage, target)
}

// runStage executes a single stage
func (p *Pipeline) runStage(ctx context.Context, stage Stage, target *models.Target) error {
	p.logger.Info().
		Str("stage", stage.Name).
		Str("category", stage.Category).
		Strs("plugins", stage.Plugins).
		Msg("Starting stage")
	
	// Update stage status
	stageStatus := StageStatus{
		State:     "running",
		StartTime: time.Now(),
	}
	p.status.StageStatus[stage.Category] = stageStatus
	
	// Create context with timeout
	stageCtx, cancel := context.WithTimeout(ctx, stage.Timeout)
	defer cancel()
	
	// Execute plugins in the stage
	resultCount := 0
	for _, pluginName := range stage.Plugins {
		plugin, exists := p.registry.Get(pluginName)
		if !exists {
			p.logger.Warn().
				Str("plugin", pluginName).
				Msg("Plugin not found in registry, skipping")
			continue
		}
		
		p.logger.Debug().
			Str("plugin", pluginName).
			Str("stage", stage.Category).
			Msg("Executing plugin")
		
		// Create shared context for plugin
		loggerAdapter := &ZerologAdapter{logger: p.logger}
		sharedCtx := NewSharedContext(nil, nil, loggerAdapter, nil)
		
		// Prepare plugin
		if err := plugin.Prepare(stageCtx, target, p.config, sharedCtx); err != nil {
			p.logger.Error().Err(err).
				Str("plugin", pluginName).
				Msg("Plugin preparation failed")
			continue
		}
		
		// Run plugin
		pluginResults := make(chan models.PluginResult, 100)
		go func() {
			defer close(pluginResults)
			if err := plugin.Run(stageCtx, target, pluginResults, sharedCtx); err != nil {
				p.logger.Error().Err(err).
					Str("plugin", pluginName).
					Msg("Plugin execution failed")
			}
		}()
		
		// Collect results
		for result := range pluginResults {
			resultCount++
			p.results <- result
		}
		
		// Teardown plugin
		if err := plugin.Teardown(stageCtx); err != nil {
			p.logger.Warn().Err(err).
				Str("plugin", pluginName).
				Msg("Plugin teardown failed")
		}
	}
	
	// Update stage status
	stageStatus.State = "completed"
	stageStatus.EndTime = time.Now()
	stageStatus.Duration = time.Since(stageStatus.StartTime)
	stageStatus.Results = resultCount
	p.status.StageStatus[stage.Category] = stageStatus
	
	p.logger.Info().
		Str("stage", stage.Name).
		Int("results", resultCount).
		Dur("duration", stageStatus.Duration).
		Msg("Stage completed")
	
	return nil
}

// Resume continues a previously interrupted scan
func (p *Pipeline) Resume(ctx context.Context, checkpointPath string) error {
	checkpoint, err := p.loadCheckpoint(checkpointPath)
	if err != nil {
		return fmt.Errorf("failed to load checkpoint: %w", err)
	}
	
	target, err := models.NewTarget(checkpoint.Target)
	if err != nil {
		return fmt.Errorf("failed to create target from checkpoint: %w", err)
	}
	
	p.logger.Info().
		Str("target", checkpoint.Target).
		Str("current_stage", checkpoint.CurrentStage).
		Int("completed_stages", len(checkpoint.CompletedStages)).
		Msg("Resuming scan from checkpoint")
	
	// Find the stage to resume from
	var resumeIndex int
	for i, stage := range p.stages {
		if stage.Category == checkpoint.CurrentStage {
			resumeIndex = i
			break
		}
	}
	
	// Execute remaining stages
	for i := resumeIndex; i < len(p.stages); i++ {
		stage := p.stages[i]
		
		// Skip if already completed
		for _, completed := range checkpoint.CompletedStages {
			if stage.Category == completed {
				continue
			}
		}
		
		if err := p.runStage(ctx, stage, target); err != nil && stage.Required {
			return fmt.Errorf("stage %s failed during resume: %w", stage.Name, err)
		}
	}
	
	return nil
}

// Helper methods

func (p *Pipeline) createWorkspace(target *models.Target) (*Workspace, error) {
	workspace := &Workspace{
		ID:          fmt.Sprintf("ws-%d", time.Now().Unix()),
		Target:      target.Domain,
		BasePath:    p.config.Global.Workdir,
		ScanID:      fmt.Sprintf("scan-%d", time.Now().Unix()),
		CreatedAt:   time.Now(),
		Directories: make(map[string]string),
		Files:       make(map[string][]string),
		Metadata:    make(map[string]interface{}),
	}
	
	// Create workspace directories
	dirs := []string{
		"http/req", "http/res", "js", "urls", "endpoints",
		"vulns", "secrets", "reports", "logs", "checkpoints",
	}
	
	for _, dir := range dirs {
		fullPath := fmt.Sprintf("%s/%s/%s/%s", workspace.BasePath, workspace.Target, workspace.ScanID, dir)
		workspace.Directories[dir] = fullPath
		// Directory creation would be handled by OS-specific code
	}
	
	return workspace, nil
}

func (p *Pipeline) areDependenciesMet(stage Stage) bool {
	if len(stage.DependsOn) == 0 {
		return true
	}
	
	for _, dep := range stage.DependsOn {
		if status, exists := p.status.StageStatus[dep]; !exists || status.State != "completed" {
			return false
		}
	}
	
	return true
}

func (p *Pipeline) saveCheckpoint(currentStage string, target *models.Target) error {
	checkpoint := &Checkpoint{
		Target:       target.URL,
		CurrentStage: currentStage,
		Timestamp:    time.Now(),
		Workspace:    p.workspace.BasePath,
	}
	
	// Add completed stages
	for category, status := range p.status.StageStatus {
		if status.State == "completed" {
			checkpoint.CompletedStages = append(checkpoint.CompletedStages, category)
		}
	}
	
	// Save checkpoint (implementation would depend on storage backend)
	p.logger.Debug().
		Str("stage", currentStage).
		Int("completed", len(checkpoint.CompletedStages)).
		Msg("Checkpoint saved")
	
	return nil
}

func (p *Pipeline) loadCheckpoint(path string) (*Checkpoint, error) {
	// Implementation would load checkpoint from file
	return &Checkpoint{}, nil
}

func (p *Pipeline) updateProgress() {
	total := len(p.stages)
	completed := 0
	
	for _, status := range p.status.StageStatus {
		if status.State == "completed" {
			completed++
		}
	}
	
	p.status.Progress = float64(completed) / float64(total) * 100.0
}

// GetStatus returns the current pipeline status
func (p *Pipeline) GetStatus() PipelineStatus {
	p.mutex.RLock()
	defer p.mutex.RUnlock()
	return p.status
}

// GetResults returns the results channel
func (p *Pipeline) GetResults() <-chan models.PluginResult {
	return p.results
}

// GetErrors returns the errors channel
func (p *Pipeline) GetErrors() <-chan error {
	return p.errors
}

// GetStages returns the configured stages
func (p *Pipeline) GetStages() []Stage {
	return p.stages
}

// GetWorkspace returns the current workspace
func (p *Pipeline) GetWorkspace() *Workspace {
	return p.workspace
}

// ZerologAdapter adapts zerolog.Logger to the Logger interface
type ZerologAdapter struct {
	logger zerolog.Logger
}

func (z *ZerologAdapter) Debug(msg string, fields ...interface{}) {
	event := z.logger.Debug()
	for i := 0; i < len(fields); i += 2 {
		if i+1 < len(fields) {
			if key, ok := fields[i].(string); ok {
				event = event.Interface(key, fields[i+1])
			}
		}
	}
	event.Msg(msg)
}

func (z *ZerologAdapter) Info(msg string, fields ...interface{}) {
	event := z.logger.Info()
	for i := 0; i < len(fields); i += 2 {
		if i+1 < len(fields) {
			if key, ok := fields[i].(string); ok {
				event = event.Interface(key, fields[i+1])
			}
		}
	}
	event.Msg(msg)
}

func (z *ZerologAdapter) Warn(msg string, fields ...interface{}) {
	event := z.logger.Warn()
	for i := 0; i < len(fields); i += 2 {
		if i+1 < len(fields) {
			if key, ok := fields[i].(string); ok {
				event = event.Interface(key, fields[i+1])
			}
		}
	}
	event.Msg(msg)
}

func (z *ZerologAdapter) Error(msg string, err error, fields ...interface{}) {
	event := z.logger.Error()
	if err != nil {
		event = event.Err(err)
	}
	for i := 0; i < len(fields); i += 2 {
		if i+1 < len(fields) {
			if key, ok := fields[i].(string); ok {
				event = event.Interface(key, fields[i+1])
			}
		}
	}
	event.Msg(msg)
}

func (z *ZerologAdapter) Fatal(msg string, err error, fields ...interface{}) {
	event := z.logger.Fatal()
	if err != nil {
		event = event.Err(err)
	}
	for i := 0; i < len(fields); i += 2 {
		if i+1 < len(fields) {
			if key, ok := fields[i].(string); ok {
				event = event.Interface(key, fields[i+1])
			}
		}
	}
	event.Msg(msg)
}

func (z *ZerologAdapter) WithField(key string, value interface{}) Logger {
	return &ZerologAdapter{logger: z.logger.With().Interface(key, value).Logger()}
}

func (z *ZerologAdapter) WithFields(fields map[string]interface{}) Logger {
	ctx := z.logger.With()
	for k, v := range fields {
		ctx = ctx.Interface(k, v)
	}
	return &ZerologAdapter{logger: ctx.Logger()}
}
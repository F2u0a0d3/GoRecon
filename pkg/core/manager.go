package core

import (
	"context"
	"fmt"
	"sort"
	"sync"
	"time"

	"github.com/f2u0a0d3/GoRecon/pkg/config"
	"github.com/f2u0a0d3/GoRecon/pkg/models"
)

// PluginManager manages plugin lifecycle, dependencies, and execution
type PluginManager struct {
	plugins       map[string]Plugin
	registry      *PluginRegistry
	scheduler     *Scheduler
	shared        *SharedContext
	config        *config.Config
	logger        Logger
	metrics       MetricsInterface
	
	// Execution state
	running       map[string]*PluginExecution
	mutex         sync.RWMutex
}

// PluginExecution tracks the execution state of a plugin
type PluginExecution struct {
	Plugin      Plugin
	Target      *models.Target
	Status      ExecutionStatus
	StartTime   time.Time
	EndTime     time.Time
	Results     []models.PluginResult
	Error       error
	Context     context.Context
	CancelFunc  context.CancelFunc
	ResultChan  chan models.PluginResult
	
	mutex       sync.RWMutex
}

// ExecutionStatus represents the current status of plugin execution
type ExecutionStatus string

const (
	StatusPending   ExecutionStatus = "pending"
	StatusRunning   ExecutionStatus = "running"
	StatusCompleted ExecutionStatus = "completed"
	StatusFailed    ExecutionStatus = "failed"
	StatusCancelled ExecutionStatus = "cancelled"
)

// NewPluginManager creates a new plugin manager
func NewPluginManager(config *config.Config, shared *SharedContext, logger Logger, metrics MetricsInterface) *PluginManager {
	return &PluginManager{
		plugins:   make(map[string]Plugin),
		registry:  NewPluginRegistry(),
		scheduler: NewScheduler(logger),
		shared:    shared,
		config:    config,
		logger:    logger.WithField("component", "plugin-manager"),
		metrics:   metrics,
		running:   make(map[string]*PluginExecution),
	}
}

// RegisterPlugin registers a plugin with the manager
func (pm *PluginManager) RegisterPlugin(plugin Plugin) error {
	pm.mutex.Lock()
	defer pm.mutex.Unlock()
	
	name := plugin.Name()
	if _, exists := pm.plugins[name]; exists {
		return fmt.Errorf("plugin %s is already registered", name)
	}
	
	// Validate plugin
	ctx := context.Background()
	if err := plugin.Validate(ctx, pm.config); err != nil {
		return fmt.Errorf("plugin validation failed for %s: %w", name, err)
	}
	
	pm.plugins[name] = plugin
	pm.registry.Register(plugin)
	
	pm.logger.Info("Plugin registered successfully", "plugin", name)
	pm.metrics.Counter("plugins.registered").Inc()
	
	return nil
}

// UnregisterPlugin removes a plugin from the manager
func (pm *PluginManager) UnregisterPlugin(name string) error {
	pm.mutex.Lock()
	defer pm.mutex.Unlock()
	
	// Check if plugin is currently running
	if execution, exists := pm.running[name]; exists {
		if execution.Status == StatusRunning {
			return fmt.Errorf("cannot unregister plugin %s: currently running", name)
		}
	}
	
	delete(pm.plugins, name)
	pm.registry.Unregister(name)
	
	pm.logger.Info("Plugin unregistered", "plugin", name)
	pm.metrics.Counter("plugins.unregistered").Inc()
	
	return nil
}

// GetPlugin returns a registered plugin by name
func (pm *PluginManager) GetPlugin(name string) (Plugin, error) {
	pm.mutex.RLock()
	defer pm.mutex.RUnlock()
	
	plugin, exists := pm.plugins[name]
	if !exists {
		return nil, fmt.Errorf("plugin %s not found", name)
	}
	
	return plugin, nil
}

// ListPlugins returns all registered plugins
func (pm *PluginManager) ListPlugins() []Plugin {
	pm.mutex.RLock()
	defer pm.mutex.RUnlock()
	
	plugins := make([]Plugin, 0, len(pm.plugins))
	for _, plugin := range pm.plugins {
		plugins = append(plugins, plugin)
	}
	
	// Sort by name for consistent ordering
	sort.Slice(plugins, func(i, j int) bool {
		return plugins[i].Name() < plugins[j].Name()
	})
	
	return plugins
}

// GetPluginsByCategory returns plugins filtered by category
func (pm *PluginManager) GetPluginsByCategory(category string) []Plugin {
	plugins := pm.ListPlugins()
	filtered := make([]Plugin, 0)
	
	for _, plugin := range plugins {
		if plugin.Category() == category {
			filtered = append(filtered, plugin)
		}
	}
	
	return filtered
}

// GetEnabledPlugins returns plugins that are enabled in the configuration
func (pm *PluginManager) GetEnabledPlugins(target *models.Target) []Plugin {
	plugins := pm.ListPlugins()
	enabled := make([]Plugin, 0)
	
	for _, plugin := range plugins {
		pluginConfig := pm.config.GetPluginConfig(plugin.Name(), target.Domain)
		if pluginConfig.Enabled {
			enabled = append(enabled, plugin)
		}
	}
	
	return enabled
}

// ExecutePlugins executes a set of plugins against a target
func (pm *PluginManager) ExecutePlugins(ctx context.Context, target *models.Target, plugins []Plugin) (*ExecutionPlan, error) {
	// Create execution plan
	plan, err := pm.scheduler.CreateExecutionPlan(plugins, []*models.Target{target})
	if err != nil {
		return nil, fmt.Errorf("failed to create execution plan: %w", err)
	}
	
	// Execute plan
	resultChan := make(chan models.PluginResult, 1000)
	go pm.executePlan(ctx, plan, target, resultChan)
	
	plan.ResultChan = resultChan
	return plan, nil
}

// ExecutePlugin executes a single plugin against a target
func (pm *PluginManager) ExecutePlugin(ctx context.Context, pluginName string, target *models.Target) (*PluginExecution, error) {
	plugin, err := pm.GetPlugin(pluginName)
	if err != nil {
		return nil, err
	}
	
	// Create execution context
	execCtx, cancelFunc := context.WithCancel(ctx)
	
	execution := &PluginExecution{
		Plugin:     plugin,
		Target:     target,
		Status:     StatusPending,
		Context:    execCtx,
		CancelFunc: cancelFunc,
		ResultChan: make(chan models.PluginResult, 100),
		Results:    make([]models.PluginResult, 0),
	}
	
	// Store execution
	pm.mutex.Lock()
	pm.running[pluginName] = execution
	pm.mutex.Unlock()
	
	// Execute plugin asynchronously
	go pm.executePlugin(execution)
	
	return execution, nil
}

// CancelPlugin cancels a running plugin
func (pm *PluginManager) CancelPlugin(pluginName string) error {
	pm.mutex.RLock()
	execution, exists := pm.running[pluginName]
	pm.mutex.RUnlock()
	
	if !exists {
		return fmt.Errorf("plugin %s is not running", pluginName)
	}
	
	execution.mutex.Lock()
	defer execution.mutex.Unlock()
	
	if execution.Status == StatusRunning {
		execution.CancelFunc()
		execution.Status = StatusCancelled
		execution.EndTime = time.Now()
		
		pm.logger.Info("Plugin cancelled", "plugin", pluginName)
		pm.metrics.Counter("plugins.cancelled").Inc()
	}
	
	return nil
}

// GetExecutionStatus returns the status of a plugin execution
func (pm *PluginManager) GetExecutionStatus(pluginName string) (*PluginExecution, error) {
	pm.mutex.RLock()
	defer pm.mutex.RUnlock()
	
	execution, exists := pm.running[pluginName]
	if !exists {
		return nil, fmt.Errorf("plugin %s execution not found", pluginName)
	}
	
	return execution, nil
}

// GetAllExecutionStatuses returns the status of all running plugins
func (pm *PluginManager) GetAllExecutionStatuses() map[string]*PluginExecution {
	pm.mutex.RLock()
	defer pm.mutex.RUnlock()
	
	statuses := make(map[string]*PluginExecution)
	for name, execution := range pm.running {
		statuses[name] = execution
	}
	
	return statuses
}

// WaitForCompletion waits for all plugins to complete
func (pm *PluginManager) WaitForCompletion(ctx context.Context) error {
	ticker := time.NewTicker(1 * time.Second)
	defer ticker.Stop()
	
	for {
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-ticker.C:
			if pm.allPluginsCompleted() {
				return nil
			}
		}
	}
}

// ValidatePluginDependencies validates that plugin dependencies are satisfied
func (pm *PluginManager) ValidatePluginDependencies(plugins []Plugin) error {
	graph := NewDependencyGraph()
	
	// Build dependency graph
	for _, plugin := range plugins {
		node := &PluginNode{
			Plugin:       plugin,
			Dependencies: extractDependencies(plugin.Dependencies()),
			Provides:     plugin.Provides(),
			Requires:     plugin.Consumes(),
		}
		graph.AddNode(plugin.Name(), node)
	}
	
	// Validate dependencies
	for _, plugin := range plugins {
		for _, dep := range plugin.Dependencies() {
			if dep.Required {
				if _, err := pm.GetPlugin(dep.Plugin); err != nil {
					return fmt.Errorf("required dependency %s for plugin %s not found", dep.Plugin, plugin.Name())
				}
			}
		}
	}
	
	// Check for circular dependencies
	if cycles := graph.DetectCycles(); len(cycles) > 0 {
		return fmt.Errorf("circular dependencies detected: %v", cycles)
	}
	
	return nil
}

// Internal methods

func (pm *PluginManager) executePlan(ctx context.Context, plan *ExecutionPlan, target *models.Target, resultChan chan models.PluginResult) {
	defer close(resultChan)
	
	pm.logger.Info("Executing plugin plan", "phases", len(plan.Phases))
	
	for i, phase := range plan.Phases {
		pm.logger.Info("Starting execution phase", "phase", i+1, "plugins", len(phase.Plugins))
		
		if err := pm.executePhase(ctx, phase, target, resultChan); err != nil {
			pm.logger.Error("Phase execution failed", err, "phase", i+1)
			return
		}
		
		pm.logger.Info("Phase completed", "phase", i+1)
	}
	
	pm.logger.Info("Plugin plan execution completed")
}

func (pm *PluginManager) executePhase(ctx context.Context, phase *ExecutionPhase, target *models.Target, resultChan chan models.PluginResult) error {
	if phase.Parallel {
		return pm.executePhaseParallel(ctx, phase, target, resultChan)
	}
	return pm.executePhaseSequential(ctx, phase, target, resultChan)
}

func (pm *PluginManager) executePhaseParallel(ctx context.Context, phase *ExecutionPhase, target *models.Target, resultChan chan models.PluginResult) error {
	var wg sync.WaitGroup
	errChan := make(chan error, len(phase.Plugins))
	
	// Limit concurrent executions
	semaphore := make(chan struct{}, phase.MaxWorkers)
	
	for _, plugin := range phase.Plugins {
		wg.Add(1)
		go func(p Plugin) {
			defer wg.Done()
			
			semaphore <- struct{}{} // Acquire
			defer func() { <-semaphore }() // Release
			
			if err := pm.executePluginSync(ctx, p, target, resultChan); err != nil {
				errChan <- err
			}
		}(plugin)
	}
	
	wg.Wait()
	close(errChan)
	
	// Check for errors
	for err := range errChan {
		if err != nil {
			return err
		}
	}
	
	return nil
}

func (pm *PluginManager) executePhaseSequential(ctx context.Context, phase *ExecutionPhase, target *models.Target, resultChan chan models.PluginResult) error {
	for _, plugin := range phase.Plugins {
		if err := pm.executePluginSync(ctx, plugin, target, resultChan); err != nil {
			return err
		}
	}
	return nil
}

func (pm *PluginManager) executePluginSync(ctx context.Context, plugin Plugin, target *models.Target, resultChan chan models.PluginResult) error {
	execution, err := pm.ExecutePlugin(ctx, plugin.Name(), target)
	if err != nil {
		return err
	}
	
	// Forward results
	go func() {
		for result := range execution.ResultChan {
			resultChan <- result
		}
	}()
	
	// Wait for completion
	for {
		execution.mutex.RLock()
		status := execution.Status
		execution.mutex.RUnlock()
		
		if status == StatusCompleted || status == StatusFailed || status == StatusCancelled {
			break
		}
		
		time.Sleep(100 * time.Millisecond)
	}
	
	return execution.Error
}

func (pm *PluginManager) executePlugin(execution *PluginExecution) {
	execution.mutex.Lock()
	execution.Status = StatusRunning
	execution.StartTime = time.Now()
	execution.mutex.Unlock()
	
	defer func() {
		execution.mutex.Lock()
		execution.EndTime = time.Now()
		close(execution.ResultChan)
		execution.mutex.Unlock()
		
		// Clean up from running map
		pm.mutex.Lock()
		delete(pm.running, execution.Plugin.Name())
		pm.mutex.Unlock()
	}()
	
	plugin := execution.Plugin
	target := execution.Target
	
	pm.logger.Info("Starting plugin execution", "plugin", plugin.Name(), "target", target.URL)
	pm.metrics.Counter("plugins.started").Inc()
	
	// Prepare plugin
	if err := plugin.Prepare(execution.Context, target, pm.config, pm.shared); err != nil {
		pm.logger.Error("Plugin preparation failed", err, "plugin", plugin.Name())
		execution.mutex.Lock()
		execution.Status = StatusFailed
		execution.Error = err
		execution.mutex.Unlock()
		pm.metrics.Counter("plugins.failed").Inc()
		return
	}
	
	// Create result collection channel
	internalResultChan := make(chan models.PluginResult, 100)
	
	// Forward results to execution
	go func() {
		for result := range internalResultChan {
			execution.mutex.Lock()
			execution.Results = append(execution.Results, result)
			execution.mutex.Unlock()
			
			// Forward to external channel
			select {
			case execution.ResultChan <- result:
			default:
				pm.logger.Warn("Result channel full, dropping result", "plugin", plugin.Name())
			}
		}
	}()
	
	// Execute plugin
	err := plugin.Run(execution.Context, target, internalResultChan, pm.shared)
	close(internalResultChan)
	
	// Teardown plugin
	if teardownErr := plugin.Teardown(execution.Context); teardownErr != nil {
		pm.logger.Error("Plugin teardown failed", teardownErr, "plugin", plugin.Name())
	}
	
	execution.mutex.Lock()
	if err != nil {
		pm.logger.Error("Plugin execution failed", err, "plugin", plugin.Name())
		execution.Status = StatusFailed
		execution.Error = err
		pm.metrics.Counter("plugins.failed").Inc()
	} else {
		pm.logger.Info("Plugin execution completed", 
			"plugin", plugin.Name(), 
			"results", len(execution.Results),
			"duration", execution.EndTime.Sub(execution.StartTime))
		execution.Status = StatusCompleted
		pm.metrics.Counter("plugins.completed").Inc()
		pm.metrics.Histogram("plugins.duration").Observe(execution.EndTime.Sub(execution.StartTime).Seconds())
	}
	execution.mutex.Unlock()
}

func (pm *PluginManager) allPluginsCompleted() bool {
	pm.mutex.RLock()
	defer pm.mutex.RUnlock()
	
	for _, execution := range pm.running {
		execution.mutex.RLock()
		status := execution.Status
		execution.mutex.RUnlock()
		
		if status == StatusPending || status == StatusRunning {
			return false
		}
	}
	
	return true
}

func extractDependencies(deps []PluginDependency) []string {
	dependencies := make([]string, len(deps))
	for i, dep := range deps {
		dependencies[i] = dep.Plugin
	}
	return dependencies
}

// GetPluginMetrics returns execution metrics for plugins
func (pm *PluginManager) GetPluginMetrics() map[string]PluginMetrics {
	pm.mutex.RLock()
	defer pm.mutex.RUnlock()
	
	metrics := make(map[string]PluginMetrics)
	
	for name, execution := range pm.running {
		execution.mutex.RLock()
		
		var duration time.Duration
		if !execution.EndTime.IsZero() {
			duration = execution.EndTime.Sub(execution.StartTime)
		} else if !execution.StartTime.IsZero() {
			duration = time.Since(execution.StartTime)
		}
		
		errorCount := 0
		if execution.Error != nil {
			errorCount = 1
		}
		
		metrics[name] = PluginMetrics{
			Name:          name,
			ExecutionTime: duration,
			ResultCount:   len(execution.Results),
			ErrorCount:    errorCount,
		}
		
		execution.mutex.RUnlock()
	}
	
	return metrics
}
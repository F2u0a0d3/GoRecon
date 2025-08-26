package core

import (
	"fmt"
	"sort"
	"time"

	"github.com/f2u0a0d3/GoRecon/pkg/models"
)

// Scheduler manages intelligent plugin execution planning and optimization
type Scheduler struct {
	dependencyGraph *DependencyGraph
	optimizer       *ExecutionOptimizer
	predictor       *PerformancePredictor
	resourceManager *ResourceManager
	logger          Logger
}

// ExecutionPlan represents a complete plugin execution plan
type ExecutionPlan struct {
	ID          string
	Target      *models.Target
	Phases      []*ExecutionPhase
	Order       []Plugin
	Allocations map[string]ResourceAllocation
	Graph       *DependencyGraph
	Metadata    ExecutionMetadata
	ResultChan  chan models.PluginResult
}

// ExecutionPhase represents a phase of plugin execution
type ExecutionPhase struct {
	ID          string
	Name        string
	Plugins     []Plugin
	Parallel    bool
	MaxWorkers  int
	Timeout     time.Duration
	Resources   ResourceAllocation
	Dependencies []string
	Priority    int
}

// ExecutionMetadata contains metadata about the execution plan
type ExecutionMetadata struct {
	CreatedAt        time.Time
	EstimatedDuration time.Duration
	TotalPlugins     int
	ParallelPhases   int
	SequentialPhases int
	ResourcesRequired Resources
	CriticalPath     []string
	OptimizationLevel string
}

// ResourceAllocation represents allocated resources for execution
type ResourceAllocation struct {
	CPUCores    int
	MemoryMB    int
	DiskMB      int
	NetworkBW   string
	Processes   int
}

// NewScheduler creates a new intelligent scheduler
func NewScheduler(logger Logger) *Scheduler {
	return &Scheduler{
		dependencyGraph: NewDependencyGraph(),
		optimizer:       NewExecutionOptimizer(),
		predictor:       NewPerformancePredictor(),
		resourceManager: NewResourceManager(),
		logger:          logger.WithField("component", "scheduler"),
	}
}

// CreateExecutionPlan creates an optimized execution plan for plugins
func (s *Scheduler) CreateExecutionPlan(plugins []Plugin, targets []*models.Target) (*ExecutionPlan, error) {
	if len(plugins) == 0 {
		return nil, fmt.Errorf("no plugins provided")
	}
	
	if len(targets) == 0 {
		return nil, fmt.Errorf("no targets provided")
	}
	
	// For now, support single target (multi-target support can be added later)
	target := targets[0]
	
	s.logger.Info("Creating execution plan", 
		"plugins", len(plugins), 
		"target", target.Domain)
	
	// Build dependency graph
	if err := s.buildDependencyGraph(plugins); err != nil {
		return nil, fmt.Errorf("failed to build dependency graph: %w", err)
	}
	
	// Validate dependencies
	if err := s.dependencyGraph.ValidateGraph(); err != nil {
		return nil, fmt.Errorf("dependency validation failed: %w", err)
	}
	
	// Get performance predictions
	predictions := s.predictor.GetPredictions(plugins)
	
	// Create execution phases
	phases, err := s.createExecutionPhases(plugins, predictions)
	if err != nil {
		return nil, fmt.Errorf("failed to create execution phases: %w", err)
	}
	
	// Optimize execution order
	optimizedPhases := s.optimizer.OptimizePhases(phases, predictions)
	
	// Allocate resources
	allocations := s.resourceManager.AllocateResources(optimizedPhases)
	
	// Calculate metadata
	metadata := s.calculateMetadata(plugins, optimizedPhases, predictions)
	
	plan := &ExecutionPlan{
		ID:          generateExecutionID(),
		Target:      target,
		Phases:      optimizedPhases,
		Order:       s.flattenPhases(optimizedPhases),
		Allocations: allocations,
		Graph:       s.dependencyGraph,
		Metadata:    metadata,
	}
	
	s.logger.Info("Execution plan created successfully",
		"plan_id", plan.ID,
		"phases", len(plan.Phases),
		"estimated_duration", plan.Metadata.EstimatedDuration,
		"optimization", plan.Metadata.OptimizationLevel)
	
	return plan, nil
}

func (s *Scheduler) buildDependencyGraph(plugins []Plugin) error {
	// Add all plugins as nodes
	for _, plugin := range plugins {
		node := &PluginNode{
			Plugin:       plugin,
			Dependencies: extractDependencyNames(plugin.Dependencies()),
			Provides:     plugin.Provides(),
			Requires:     plugin.Consumes(),
			Weight:       plugin.Priority(),
			Status:       StatusPending,
		}
		
		s.dependencyGraph.AddNode(plugin.Name(), node)
	}
	
	// Add dependency edges
	for _, plugin := range plugins {
		for _, dep := range plugin.Dependencies() {
			s.dependencyGraph.AddDependency(plugin.Name(), dep.Plugin)
		}
	}
	
	return nil
}

func (s *Scheduler) createExecutionPhases(plugins []Plugin, predictions map[string]PerformancePrediction) ([]*ExecutionPhase, error) {
	// Get execution order from dependency graph
	phaseOrder := s.dependencyGraph.GetExecutionOrder()
	
	phases := make([]*ExecutionPhase, 0, len(phaseOrder))
	
	for i, phasePlugins := range phaseOrder {
		phase, err := s.createPhase(i+1, phasePlugins, predictions)
		if err != nil {
			return nil, fmt.Errorf("failed to create phase %d: %w", i+1, err)
		}
		phases = append(phases, phase)
	}
	
	return phases, nil
}

func (s *Scheduler) createPhase(phaseNum int, pluginNames []string, predictions map[string]PerformancePrediction) (*ExecutionPhase, error) {
	plugins := make([]Plugin, 0, len(pluginNames))
	
	// Convert plugin names to plugin objects
	for _, name := range pluginNames {
		node, exists := s.dependencyGraph.GetNode(name)
		if !exists {
			return nil, fmt.Errorf("plugin %s not found in dependency graph", name)
		}
		plugins = append(plugins, node.Plugin)
	}
	
	// Determine if phase can run in parallel
	parallel := len(plugins) > 1 && s.canRunInParallel(plugins)
	
	// Calculate resource requirements
	resources := s.calculatePhaseResources(plugins)
	
	// Determine max workers for parallel execution
	maxWorkers := s.calculateMaxWorkers(plugins, parallel)
	
	// Calculate phase timeout
	timeout := s.calculatePhaseTimeout(plugins, predictions, parallel)
	
	phase := &ExecutionPhase{
		ID:         fmt.Sprintf("phase-%d", phaseNum),
		Name:       fmt.Sprintf("Phase %d", phaseNum),
		Plugins:    plugins,
		Parallel:   parallel,
		MaxWorkers: maxWorkers,
		Timeout:    timeout,
		Resources:  resources,
		Priority:   s.calculatePhasePriority(plugins),
	}
	
	s.logger.Debug("Created execution phase",
		"phase_id", phase.ID,
		"plugins", len(phase.Plugins),
		"parallel", phase.Parallel,
		"max_workers", phase.MaxWorkers,
		"timeout", phase.Timeout)
	
	return phase, nil
}

func (s *Scheduler) canRunInParallel(plugins []Plugin) bool {
	// Check if any plugin requires sequential execution
	for _, plugin := range plugins {
		if plugin.MaxConcurrency() == 1 {
			return false
		}
	}
	
	// Check if plugins have conflicting resource requirements
	totalCPU := 0
	totalMemory := 0
	
	for _, plugin := range plugins {
		reqs := plugin.ResourceRequirements()
		totalCPU += reqs.CPUCores
		totalMemory += reqs.MemoryMB
	}
	
	// Simple heuristic - don't run too many resource-intensive plugins in parallel
	if totalCPU > 8 || totalMemory > 4096 {
		return false
	}
	
	return true
}

func (s *Scheduler) calculatePhaseResources(plugins []Plugin) ResourceAllocation {
	allocation := ResourceAllocation{}
	
	for _, plugin := range plugins {
		reqs := plugin.ResourceRequirements()
		allocation.CPUCores += reqs.CPUCores
		allocation.MemoryMB += reqs.MemoryMB
		allocation.DiskMB += reqs.DiskMB
		allocation.Processes += reqs.MaxProcesses
	}
	
	// Set network bandwidth to highest requirement
	for _, plugin := range plugins {
		reqs := plugin.ResourceRequirements()
		if reqs.NetworkBandwidth != "" {
			allocation.NetworkBW = reqs.NetworkBandwidth // Simplified - take last one
		}
	}
	
	return allocation
}

func (s *Scheduler) calculateMaxWorkers(plugins []Plugin, parallel bool) int {
	if !parallel {
		return 1
	}
	
	// Start with number of plugins
	maxWorkers := len(plugins)
	
	// Limit based on plugin concurrency settings
	for _, plugin := range plugins {
		if plugin.MaxConcurrency() > 0 && plugin.MaxConcurrency() < maxWorkers {
			maxWorkers = plugin.MaxConcurrency()
		}
	}
	
	// System-based limits (simplified)
	systemLimit := 10 // Could be configurable
	if maxWorkers > systemLimit {
		maxWorkers = systemLimit
	}
	
	return maxWorkers
}

func (s *Scheduler) calculatePhaseTimeout(plugins []Plugin, predictions map[string]PerformancePrediction, parallel bool) time.Duration {
	var maxDuration time.Duration
	var totalDuration time.Duration
	
	for _, plugin := range plugins {
		duration := plugin.EstimatedDuration()
		
		// Use prediction if available
		if pred, exists := predictions[plugin.Name()]; exists {
			duration = pred.Duration
		}
		
		totalDuration += duration
		if duration > maxDuration {
			maxDuration = duration
		}
	}
	
	// For parallel execution, use max duration + buffer
	// For sequential execution, use total duration + buffer
	var timeout time.Duration
	if parallel {
		timeout = maxDuration
	} else {
		timeout = totalDuration
	}
	
	// Add 50% buffer
	timeout = timeout + (timeout / 2)
	
	// Minimum timeout of 30 seconds
	if timeout < 30*time.Second {
		timeout = 30 * time.Second
	}
	
	return timeout
}

func (s *Scheduler) calculatePhasePriority(plugins []Plugin) int {
	totalPriority := 0
	for _, plugin := range plugins {
		totalPriority += plugin.Priority()
	}
	
	if len(plugins) > 0 {
		return totalPriority / len(plugins)
	}
	
	return 5 // Default priority
}

func (s *Scheduler) calculateMetadata(plugins []Plugin, phases []*ExecutionPhase, predictions map[string]PerformancePrediction) ExecutionMetadata {
	var estimatedDuration time.Duration
	var totalResources Resources
	parallelPhases := 0
	sequentialPhases := 0
	
	// Calculate total estimated duration
	for _, phase := range phases {
		if phase.Parallel {
			parallelPhases++
			// For parallel phases, use the longest plugin duration
			var maxDuration time.Duration
			for _, plugin := range phase.Plugins {
				duration := plugin.EstimatedDuration()
				if pred, exists := predictions[plugin.Name()]; exists {
					duration = pred.Duration
				}
				if duration > maxDuration {
					maxDuration = duration
				}
			}
			estimatedDuration += maxDuration
		} else {
			sequentialPhases++
			// For sequential phases, sum all plugin durations
			for _, plugin := range phase.Plugins {
				duration := plugin.EstimatedDuration()
				if pred, exists := predictions[plugin.Name()]; exists {
					duration = pred.Duration
				}
				estimatedDuration += duration
			}
		}
	}
	
	// Calculate total resource requirements
	for _, plugin := range plugins {
		reqs := plugin.ResourceRequirements()
		if reqs.CPUCores > totalResources.CPUCores {
			totalResources.CPUCores = reqs.CPUCores
		}
		totalResources.MemoryMB += reqs.MemoryMB
		totalResources.DiskMB += reqs.DiskMB
		totalResources.MaxProcesses += reqs.MaxProcesses
	}
	
	// Calculate critical path
	criticalPath := s.dependencyGraph.GetCriticalPath()
	
	// Determine optimization level
	optimizationLevel := "standard"
	if parallelPhases > sequentialPhases {
		optimizationLevel = "high"
	} else if parallelPhases == 0 {
		optimizationLevel = "minimal"
	}
	
	return ExecutionMetadata{
		CreatedAt:         time.Now(),
		EstimatedDuration: estimatedDuration,
		TotalPlugins:      len(plugins),
		ParallelPhases:    parallelPhases,
		SequentialPhases:  sequentialPhases,
		ResourcesRequired: totalResources,
		CriticalPath:      criticalPath,
		OptimizationLevel: optimizationLevel,
	}
}

func (s *Scheduler) flattenPhases(phases []*ExecutionPhase) []Plugin {
	plugins := make([]Plugin, 0)
	
	for _, phase := range phases {
		plugins = append(plugins, phase.Plugins...)
	}
	
	return plugins
}

// ExecutionOptimizer optimizes execution plans
type ExecutionOptimizer struct {
	strategies []OptimizationStrategy
}

// OptimizationStrategy defines optimization approaches
type OptimizationStrategy interface {
	Apply(phases []*ExecutionPhase, predictions map[string]PerformancePrediction) []*ExecutionPhase
	Name() string
}

func NewExecutionOptimizer() *ExecutionOptimizer {
	return &ExecutionOptimizer{
		strategies: []OptimizationStrategy{
			&ParallelizationStrategy{},
			&ResourceOptimizationStrategy{},
			&PriorityOptimizationStrategy{},
		},
	}
}

func (eo *ExecutionOptimizer) OptimizePhases(phases []*ExecutionPhase, predictions map[string]PerformancePrediction) []*ExecutionPhase {
	optimized := phases
	
	for _, strategy := range eo.strategies {
		optimized = strategy.Apply(optimized, predictions)
	}
	
	return optimized
}

// ParallelizationStrategy maximizes parallel execution opportunities
type ParallelizationStrategy struct{}

func (ps *ParallelizationStrategy) Name() string {
	return "parallelization"
}

func (ps *ParallelizationStrategy) Apply(phases []*ExecutionPhase, predictions map[string]PerformancePrediction) []*ExecutionPhase {
	optimized := make([]*ExecutionPhase, 0, len(phases))
	
	for _, phase := range phases {
		if len(phase.Plugins) > 1 && !phase.Parallel {
			// Check if we can make this phase parallel
			if ps.canParallelize(phase.Plugins) {
				phase.Parallel = true
				phase.MaxWorkers = len(phase.Plugins)
			}
		}
		optimized = append(optimized, phase)
	}
	
	return optimized
}

func (ps *ParallelizationStrategy) canParallelize(plugins []Plugin) bool {
	// Simple check - ensure no plugin requires exclusive access
	for _, plugin := range plugins {
		if plugin.MaxConcurrency() == 1 {
			return false
		}
	}
	return true
}

// ResourceOptimizationStrategy optimizes based on resource usage
type ResourceOptimizationStrategy struct{}

func (ros *ResourceOptimizationStrategy) Name() string {
	return "resource_optimization"
}

func (ros *ResourceOptimizationStrategy) Apply(phases []*ExecutionPhase, predictions map[string]PerformancePrediction) []*ExecutionPhase {
	optimized := make([]*ExecutionPhase, 0, len(phases))
	
	for _, phase := range phases {
		if phase.Parallel {
			// Sort plugins within parallel phases by resource efficiency
			sort.Slice(phase.Plugins, func(i, j int) bool {
				effI := ros.calculateEfficiency(phase.Plugins[i], predictions)
				effJ := ros.calculateEfficiency(phase.Plugins[j], predictions)
				return effI > effJ
			})
		}
		optimized = append(optimized, phase)
	}
	
	return optimized
}

func (ros *ResourceOptimizationStrategy) calculateEfficiency(plugin Plugin, predictions map[string]PerformancePrediction) float64 {
	reqs := plugin.ResourceRequirements()
	duration := plugin.EstimatedDuration().Seconds()
	
	if pred, exists := predictions[plugin.Name()]; exists {
		duration = pred.Duration.Seconds()
	}
	
	if duration == 0 {
		duration = 1
	}
	
	// Higher efficiency = less resource usage per second
	resourceCost := float64(reqs.CPUCores + reqs.MemoryMB/100)
	efficiency := 1.0 / (resourceCost + duration/60) // Normalize duration to minutes
	
	return efficiency
}

// PriorityOptimizationStrategy optimizes based on plugin priorities
type PriorityOptimizationStrategy struct{}

func (pos *PriorityOptimizationStrategy) Name() string {
	return "priority_optimization"
}

func (pos *PriorityOptimizationStrategy) Apply(phases []*ExecutionPhase, predictions map[string]PerformancePrediction) []*ExecutionPhase {
	// Sort phases by priority (higher priority first)
	sort.Slice(phases, func(i, j int) bool {
		return phases[i].Priority > phases[j].Priority
	})
	
	// Within each phase, sort plugins by priority
	for _, phase := range phases {
		sort.Slice(phase.Plugins, func(i, j int) bool {
			return phase.Plugins[i].Priority() > phase.Plugins[j].Priority()
		})
	}
	
	return phases
}

// PerformancePredictor predicts plugin execution performance
type PerformancePredictor struct {
	history map[string][]PerformanceRecord
}

type PerformanceRecord struct {
	PluginName      string
	Duration        time.Duration
	CPUUsage        float64
	MemoryUsage     int64
	NetworkRequests int
	Timestamp       time.Time
}

type PerformancePrediction struct {
	PluginName      string
	Duration        time.Duration
	CPUUsage        float64
	MemoryUsage     int64
	NetworkRequests int
	Confidence      float64
}

func NewPerformancePredictor() *PerformancePredictor {
	return &PerformancePredictor{
		history: make(map[string][]PerformanceRecord),
	}
}

func (pp *PerformancePredictor) GetPredictions(plugins []Plugin) map[string]PerformancePrediction {
	predictions := make(map[string]PerformancePrediction)
	
	for _, plugin := range plugins {
		name := plugin.Name()
		prediction := pp.predictPerformance(plugin)
		predictions[name] = prediction
	}
	
	return predictions
}

func (pp *PerformancePredictor) predictPerformance(plugin Plugin) PerformancePrediction {
	name := plugin.Name()
	
	// Check historical data
	if records, exists := pp.history[name]; exists && len(records) > 0 {
		return pp.calculatePredictionFromHistory(name, records)
	}
	
	// Fall back to plugin estimates
	return PerformancePrediction{
		PluginName:  name,
		Duration:    plugin.EstimatedDuration(),
		CPUUsage:    float64(plugin.ResourceRequirements().CPUCores),
		MemoryUsage: int64(plugin.ResourceRequirements().MemoryMB),
		Confidence:  0.5, // Low confidence without historical data
	}
}

func (pp *PerformancePredictor) calculatePredictionFromHistory(pluginName string, records []PerformanceRecord) PerformancePrediction {
	if len(records) == 0 {
		return PerformancePrediction{
			PluginName: pluginName,
			Confidence: 0.0,
		}
	}
	
	// Calculate averages from historical data
	var totalDuration time.Duration
	var totalCPU, totalMemory, totalRequests float64
	
	for _, record := range records {
		totalDuration += record.Duration
		totalCPU += record.CPUUsage
		totalMemory += float64(record.MemoryUsage)
		totalRequests += float64(record.NetworkRequests)
	}
	
	count := float64(len(records))
	confidence := pp.calculateConfidence(records)
	
	return PerformancePrediction{
		PluginName:      pluginName,
		Duration:        time.Duration(float64(totalDuration) / count),
		CPUUsage:        totalCPU / count,
		MemoryUsage:     int64(totalMemory / count),
		NetworkRequests: int(totalRequests / count),
		Confidence:      confidence,
	}
}

func (pp *PerformancePredictor) calculateConfidence(records []PerformanceRecord) float64 {
	if len(records) < 2 {
		return 0.3
	}
	
	// Calculate variance in durations to determine confidence
	durations := make([]float64, len(records))
	var mean float64
	
	for i, record := range records {
		durations[i] = record.Duration.Seconds()
		mean += durations[i]
	}
	mean /= float64(len(records))
	
	var variance float64
	for _, duration := range durations {
		variance += (duration - mean) * (duration - mean)
	}
	variance /= float64(len(records))
	
	// Lower variance = higher confidence
	// Normalize confidence between 0.3 and 0.9
	confidence := 0.9 - (variance / (mean + 1.0))
	if confidence < 0.3 {
		confidence = 0.3
	}
	if confidence > 0.9 {
		confidence = 0.9
	}
	
	return confidence
}

// ResourceManager manages resource allocation
type ResourceManager struct {
	systemResources SystemResources
}

type SystemResources struct {
	TotalCPUCores int
	TotalMemoryMB int
	TotalDiskMB   int
	MaxProcesses  int
}

func NewResourceManager() *ResourceManager {
	return &ResourceManager{
		systemResources: SystemResources{
			TotalCPUCores: 8,   // Default - should be detected
			TotalMemoryMB: 8192, // Default - should be detected
			TotalDiskMB:   10240, // Default - should be detected
			MaxProcesses:  100,  // Default - should be detected
		},
	}
}

func (rm *ResourceManager) AllocateResources(phases []*ExecutionPhase) map[string]ResourceAllocation {
	allocations := make(map[string]ResourceAllocation)
	
	for _, phase := range phases {
		allocation := phase.Resources
		
		// Ensure allocations don't exceed system limits
		if allocation.CPUCores > rm.systemResources.TotalCPUCores {
			allocation.CPUCores = rm.systemResources.TotalCPUCores
		}
		
		if allocation.MemoryMB > rm.systemResources.TotalMemoryMB {
			allocation.MemoryMB = rm.systemResources.TotalMemoryMB
		}
		
		if allocation.Processes > rm.systemResources.MaxProcesses {
			allocation.Processes = rm.systemResources.MaxProcesses
		}
		
		allocations[phase.ID] = allocation
	}
	
	return allocations
}

// Helper functions
func generateExecutionID() string {
	return fmt.Sprintf("exec-%d", time.Now().Unix())
}

func extractDependencyNames(deps []PluginDependency) []string {
	names := make([]string, len(deps))
	for i, dep := range deps {
		names[i] = dep.Plugin
	}
	return names
}
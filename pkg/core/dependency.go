package core

import (
	"fmt"
	"sort"
	
	"github.com/f2u0a0d3/GoRecon/pkg/models"
)

// DependencyGraph manages plugin execution dependencies
type DependencyGraph struct {
	nodes map[string]*PluginNode
	edges map[string][]string // plugin -> dependencies
}

// PluginNode represents a plugin in the dependency graph
type PluginNode struct {
	Plugin       Plugin
	Dependencies []string
	Dependents   []string
	Provides     []string
	Requires     []string
	Weight       int
	Status       ExecutionStatus
	Results      []models.PluginResult
}

// NewDependencyGraph creates a new dependency graph
func NewDependencyGraph() *DependencyGraph {
	return &DependencyGraph{
		nodes: make(map[string]*PluginNode),
		edges: make(map[string][]string),
	}
}

// AddNode adds a plugin node to the graph
func (dg *DependencyGraph) AddNode(name string, node *PluginNode) {
	dg.nodes[name] = node
	dg.edges[name] = node.Dependencies
}

// AddDependency adds a dependency relationship
func (dg *DependencyGraph) AddDependency(from, to string) {
	if deps, exists := dg.edges[from]; exists {
		// Check if dependency already exists
		for _, dep := range deps {
			if dep == to {
				return
			}
		}
		dg.edges[from] = append(deps, to)
	} else {
		dg.edges[from] = []string{to}
	}
}

// GetNode returns a node by name
func (dg *DependencyGraph) GetNode(name string) (*PluginNode, bool) {
	node, exists := dg.nodes[name]
	return node, exists
}

// GetDependencies returns direct dependencies of a plugin
func (dg *DependencyGraph) GetDependencies(name string) []string {
	deps, exists := dg.edges[name]
	if !exists {
		return []string{}
	}
	
	// Return a copy to prevent external modification
	result := make([]string, len(deps))
	copy(result, deps)
	return result
}

// GetAllDependencies returns all dependencies (recursive) of a plugin
func (dg *DependencyGraph) GetAllDependencies(name string) []string {
	visited := make(map[string]bool)
	dependencies := []string{}
	
	dg.getAllDependenciesRecursive(name, visited, &dependencies)
	
	return dependencies
}

func (dg *DependencyGraph) getAllDependenciesRecursive(name string, visited map[string]bool, dependencies *[]string) {
	if visited[name] {
		return
	}
	
	visited[name] = true
	
	for _, dep := range dg.edges[name] {
		*dependencies = append(*dependencies, dep)
		dg.getAllDependenciesRecursive(dep, visited, dependencies)
	}
}

// GetDependents returns plugins that depend on the specified plugin
func (dg *DependencyGraph) GetDependents(name string) []string {
	dependents := []string{}
	
	for plugin, deps := range dg.edges {
		for _, dep := range deps {
			if dep == name {
				dependents = append(dependents, plugin)
				break
			}
		}
	}
	
	return dependents
}

// TopologicalSort returns plugins in dependency order
func (dg *DependencyGraph) TopologicalSort() []string {
	// Kahn's algorithm for topological sorting
	inDegree := make(map[string]int)
	
	// Initialize in-degree count
	for node := range dg.nodes {
		inDegree[node] = 0
	}
	
	// Calculate in-degrees
	for _, deps := range dg.edges {
		for _, dep := range deps {
			inDegree[dep]++
		}
	}
	
	// Find nodes with no incoming edges
	queue := []string{}
	for node, degree := range inDegree {
		if degree == 0 {
			queue = append(queue, node)
		}
	}
	
	// Process queue
	result := []string{}
	
	for len(queue) > 0 {
		// Remove node with no incoming edges
		current := queue[0]
		queue = queue[1:]
		result = append(result, current)
		
		// Remove edges from current node
		for _, neighbor := range dg.edges[current] {
			inDegree[neighbor]--
			if inDegree[neighbor] == 0 {
				queue = append(queue, neighbor)
			}
		}
	}
	
	// Check for cycles (if we haven't processed all nodes)
	if len(result) != len(dg.nodes) {
		// Cycle detected - return partial result
		return result
	}
	
	return result
}

// DetectCycles detects circular dependencies in the graph
func (dg *DependencyGraph) DetectCycles() [][]string {
	color := make(map[string]int) // 0: white, 1: gray, 2: black
	cycles := [][]string{}
	path := []string{}
	
	for node := range dg.nodes {
		if color[node] == 0 {
			dg.detectCyclesRecursive(node, color, &path, &cycles)
		}
	}
	
	return cycles
}

func (dg *DependencyGraph) detectCyclesRecursive(node string, color map[string]int, path *[]string, cycles *[][]string) {
	color[node] = 1 // gray
	*path = append(*path, node)
	
	for _, neighbor := range dg.edges[node] {
		if color[neighbor] == 1 {
			// Back edge found - cycle detected
			cycleStart := -1
			for i, n := range *path {
				if n == neighbor {
					cycleStart = i
					break
				}
			}
			
			if cycleStart >= 0 {
				cycle := make([]string, len(*path)-cycleStart)
				copy(cycle, (*path)[cycleStart:])
				*cycles = append(*cycles, cycle)
			}
		} else if color[neighbor] == 0 {
			dg.detectCyclesRecursive(neighbor, color, path, cycles)
		}
	}
	
	color[node] = 2 // black
	*path = (*path)[:len(*path)-1]
}

// GetExecutionOrder returns plugins ordered by dependencies and priorities
func (dg *DependencyGraph) GetExecutionOrder() [][]string {
	// First, get topological order
	topoOrder := dg.TopologicalSort()
	
	// Group plugins into execution phases
	phases := [][]string{}
	processed := make(map[string]bool)
	
	for len(processed) < len(topoOrder) {
		phase := []string{}
		
		for _, plugin := range topoOrder {
			if processed[plugin] {
				continue
			}
			
			// Check if all dependencies are satisfied
			canExecute := true
			for _, dep := range dg.edges[plugin] {
				if !processed[dep] {
					canExecute = false
					break
				}
			}
			
			if canExecute {
				phase = append(phase, plugin)
				processed[plugin] = true
			}
		}
		
		if len(phase) > 0 {
			// Sort phase by priority (higher priority first)
			sort.Slice(phase, func(i, j int) bool {
				nodeI, _ := dg.GetNode(phase[i])
				nodeJ, _ := dg.GetNode(phase[j])
				
				if nodeI != nil && nodeJ != nil {
					return nodeI.Plugin.Priority() > nodeJ.Plugin.Priority()
				}
				
				return phase[i] < phase[j]
			})
			
			phases = append(phases, phase)
		} else {
			// No progress made - might be cycles or missing dependencies
			break
		}
	}
	
	return phases
}

// ValidateGraph checks the graph for consistency
func (dg *DependencyGraph) ValidateGraph() error {
	// Check for missing dependencies
	for plugin, deps := range dg.edges {
		for _, dep := range deps {
			if _, exists := dg.nodes[dep]; !exists {
				return fmt.Errorf("plugin %s depends on missing plugin %s", plugin, dep)
			}
		}
	}
	
	// Check for cycles
	cycles := dg.DetectCycles()
	if len(cycles) > 0 {
		return fmt.Errorf("circular dependencies detected: %v", cycles)
	}
	
	return nil
}

// GetDataFlow analyzes data flow between plugins
func (dg *DependencyGraph) GetDataFlow() map[string][]DataFlowEdge {
	dataFlow := make(map[string][]DataFlowEdge)
	
	for pluginName, node := range dg.nodes {
		edges := []DataFlowEdge{}
		
		// For each data type this plugin provides
		for _, provided := range node.Provides {
			// Find plugins that consume this data type
			for consumerName, consumerNode := range dg.nodes {
				if consumerName == pluginName {
					continue
				}
				
				for _, consumed := range consumerNode.Requires {
					if consumed == provided {
						edges = append(edges, DataFlowEdge{
							From:     pluginName,
							To:       consumerName,
							DataType: provided,
						})
					}
				}
			}
		}
		
		dataFlow[pluginName] = edges
	}
	
	return dataFlow
}

// DataFlowEdge represents data flow between plugins
type DataFlowEdge struct {
	From     string `json:"from"`
	To       string `json:"to"`
	DataType string `json:"data_type"`
}

// GetOptimalExecutionOrder returns an optimized execution order
func (dg *DependencyGraph) GetOptimalExecutionOrder() [][]string {
	phases := dg.GetExecutionOrder()
	
	// Optimize each phase for parallel execution
	optimizedPhases := make([][]string, len(phases))
	
	for i, phase := range phases {
		optimizedPhase := dg.optimizePhase(phase)
		optimizedPhases[i] = optimizedPhase
	}
	
	return optimizedPhases
}

func (dg *DependencyGraph) optimizePhase(phase []string) []string {
	// Sort by resource requirements and estimated duration
	sort.Slice(phase, func(i, j int) bool {
		nodeI, _ := dg.GetNode(phase[i])
		nodeJ, _ := dg.GetNode(phase[j])
		
		if nodeI != nil && nodeJ != nil {
			// Prioritize by resource efficiency
			efficiencyI := dg.calculateEfficiency(nodeI)
			efficiencyJ := dg.calculateEfficiency(nodeJ)
			
			if efficiencyI != efficiencyJ {
				return efficiencyI > efficiencyJ
			}
			
			// Then by priority
			return nodeI.Plugin.Priority() > nodeJ.Plugin.Priority()
		}
		
		return phase[i] < phase[j]
	})
	
	return phase
}

func (dg *DependencyGraph) calculateEfficiency(node *PluginNode) float64 {
	// Simple efficiency calculation based on resource requirements
	resources := node.Plugin.ResourceRequirements()
	duration := node.Plugin.EstimatedDuration().Seconds()
	
	if duration == 0 {
		duration = 1 // Avoid division by zero
	}
	
	// Lower resource usage and shorter duration = higher efficiency
	efficiency := 1.0 / (float64(resources.MemoryMB+resources.CPUCores*100) + duration)
	
	return efficiency
}

// GetCriticalPath finds the critical path in the dependency graph
func (dg *DependencyGraph) GetCriticalPath() []string {
	// Use longest path algorithm to find critical path
	distances := make(map[string]float64)
	predecessors := make(map[string]string)
	
	// Initialize distances
	for node := range dg.nodes {
		distances[node] = 0
	}
	
	// Get topological order
	topoOrder := dg.TopologicalSort()
	
	// Calculate longest paths
	for _, node := range topoOrder {
		nodeInfo, exists := dg.GetNode(node)
		if !exists {
			continue
		}
		
		duration := nodeInfo.Plugin.EstimatedDuration().Seconds()
		
		for _, neighbor := range dg.edges[node] {
			newDistance := distances[node] + duration
			if newDistance > distances[neighbor] {
				distances[neighbor] = newDistance
				predecessors[neighbor] = node
			}
		}
	}
	
	// Find the node with maximum distance
	var maxNode string
	var maxDistance float64
	
	for node, distance := range distances {
		if distance > maxDistance {
			maxDistance = distance
			maxNode = node
		}
	}
	
	// Reconstruct critical path
	path := []string{}
	current := maxNode
	
	for current != "" {
		path = append([]string{current}, path...)
		current = predecessors[current]
	}
	
	return path
}

// GetParallelizationOpportunities identifies plugins that can run in parallel
func (dg *DependencyGraph) GetParallelizationOpportunities() [][]string {
	phases := dg.GetExecutionOrder()
	opportunities := [][]string{}
	
	for _, phase := range phases {
		if len(phase) > 1 {
			// Check which plugins in this phase can actually run in parallel
			parallelGroups := dg.findParallelGroups(phase)
			opportunities = append(opportunities, parallelGroups...)
		}
	}
	
	return opportunities
}

func (dg *DependencyGraph) findParallelGroups(plugins []string) [][]string {
	groups := [][]string{}
	
	// Simple approach: group plugins that don't depend on each other
	used := make(map[string]bool)
	
	for _, plugin := range plugins {
		if used[plugin] {
			continue
		}
		
		group := []string{plugin}
		used[plugin] = true
		
		// Find plugins that can run with this one
		for _, other := range plugins {
			if used[other] {
				continue
			}
			
			// Check if they have any dependencies on each other
			if !dg.hasPath(plugin, other) && !dg.hasPath(other, plugin) {
				group = append(group, other)
				used[other] = true
			}
		}
		
		if len(group) > 1 {
			groups = append(groups, group)
		}
	}
	
	return groups
}

func (dg *DependencyGraph) hasPath(from, to string) bool {
	visited := make(map[string]bool)
	return dg.hasPathRecursive(from, to, visited)
}

func (dg *DependencyGraph) hasPathRecursive(current, target string, visited map[string]bool) bool {
	if current == target {
		return true
	}
	
	if visited[current] {
		return false
	}
	
	visited[current] = true
	
	for _, neighbor := range dg.edges[current] {
		if dg.hasPathRecursive(neighbor, target, visited) {
			return true
		}
	}
	
	return false
}
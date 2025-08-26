package core

import (
	"fmt"
	"sync"
)

// PluginRegistry maintains a registry of available plugins
type PluginRegistry struct {
	plugins     map[string]Plugin
	categories  map[string][]string
	metadata    map[string]PluginMetadata
	mutex       sync.RWMutex
}

// PluginMetadata contains additional metadata about plugins
type PluginMetadata struct {
	Name         string
	Category     string
	Description  string
	Version      string
	Author       string
	Dependencies []PluginDependency
	Provides     []string
	Consumes     []string
	Passive      bool
	Confirmed    bool
	Resources    Resources
}

// NewPluginRegistry creates a new plugin registry
func NewPluginRegistry() *PluginRegistry {
	return &PluginRegistry{
		plugins:    make(map[string]Plugin),
		categories: make(map[string][]string),
		metadata:   make(map[string]PluginMetadata),
	}
}

// Register registers a plugin in the registry
func (pr *PluginRegistry) Register(plugin Plugin) {
	pr.mutex.Lock()
	defer pr.mutex.Unlock()
	
	name := plugin.Name()
	category := plugin.Category()
	
	// Store plugin
	pr.plugins[name] = plugin
	
	// Update category mapping
	if _, exists := pr.categories[category]; !exists {
		pr.categories[category] = make([]string, 0)
	}
	pr.categories[category] = append(pr.categories[category], name)
	
	// Store metadata
	pr.metadata[name] = PluginMetadata{
		Name:         plugin.Name(),
		Category:     plugin.Category(),
		Description:  plugin.Description(),
		Version:      plugin.Version(),
		Author:       plugin.Author(),
		Dependencies: plugin.Dependencies(),
		Provides:     plugin.Provides(),
		Consumes:     plugin.Consumes(),
		Passive:      plugin.IsPassive(),
		Confirmed:    plugin.RequiresConfirmation(),
		Resources:    plugin.ResourceRequirements(),
	}
}

// Unregister removes a plugin from the registry
func (pr *PluginRegistry) Unregister(name string) {
	pr.mutex.Lock()
	defer pr.mutex.Unlock()
	
	// Get plugin metadata
	metadata, exists := pr.metadata[name]
	if !exists {
		return
	}
	
	// Remove from plugins map
	delete(pr.plugins, name)
	delete(pr.metadata, name)
	
	// Remove from category mapping
	category := metadata.Category
	if pluginList, exists := pr.categories[category]; exists {
		filtered := make([]string, 0, len(pluginList)-1)
		for _, pluginName := range pluginList {
			if pluginName != name {
				filtered = append(filtered, pluginName)
			}
		}
		
		if len(filtered) == 0 {
			delete(pr.categories, category)
		} else {
			pr.categories[category] = filtered
		}
	}
}

// Get returns a plugin by name
func (pr *PluginRegistry) Get(name string) (Plugin, bool) {
	pr.mutex.RLock()
	defer pr.mutex.RUnlock()
	
	plugin, exists := pr.plugins[name]
	return plugin, exists
}

// GetAll returns all registered plugins
func (pr *PluginRegistry) GetAll() map[string]Plugin {
	pr.mutex.RLock()
	defer pr.mutex.RUnlock()
	
	// Return a copy to prevent external modifications
	plugins := make(map[string]Plugin)
	for name, plugin := range pr.plugins {
		plugins[name] = plugin
	}
	
	return plugins
}

// GetByCategory returns all plugins in a specific category
func (pr *PluginRegistry) GetByCategory(category string) []Plugin {
	pr.mutex.RLock()
	defer pr.mutex.RUnlock()
	
	pluginNames, exists := pr.categories[category]
	if !exists {
		return []Plugin{}
	}
	
	plugins := make([]Plugin, 0, len(pluginNames))
	for _, name := range pluginNames {
		if plugin, exists := pr.plugins[name]; exists {
			plugins = append(plugins, plugin)
		}
	}
	
	return plugins
}

// GetCategories returns all available categories
func (pr *PluginRegistry) GetCategories() []string {
	pr.mutex.RLock()
	defer pr.mutex.RUnlock()
	
	categories := make([]string, 0, len(pr.categories))
	for category := range pr.categories {
		categories = append(categories, category)
	}
	
	return categories
}

// GetMetadata returns metadata for a plugin
func (pr *PluginRegistry) GetMetadata(name string) (PluginMetadata, bool) {
	pr.mutex.RLock()
	defer pr.mutex.RUnlock()
	
	metadata, exists := pr.metadata[name]
	return metadata, exists
}

// GetAllMetadata returns metadata for all plugins
func (pr *PluginRegistry) GetAllMetadata() map[string]PluginMetadata {
	pr.mutex.RLock()
	defer pr.mutex.RUnlock()
	
	// Return a copy to prevent external modifications
	metadata := make(map[string]PluginMetadata)
	for name, meta := range pr.metadata {
		metadata[name] = meta
	}
	
	return metadata
}

// GetPassivePlugins returns all passive plugins
func (pr *PluginRegistry) GetPassivePlugins() []Plugin {
	pr.mutex.RLock()
	defer pr.mutex.RUnlock()
	
	passive := make([]Plugin, 0)
	for _, plugin := range pr.plugins {
		if plugin.IsPassive() {
			passive = append(passive, plugin)
		}
	}
	
	return passive
}

// GetActivePlugins returns all active (non-passive) plugins
func (pr *PluginRegistry) GetActivePlugins() []Plugin {
	pr.mutex.RLock()
	defer pr.mutex.RUnlock()
	
	active := make([]Plugin, 0)
	for _, plugin := range pr.plugins {
		if !plugin.IsPassive() {
			active = append(active, plugin)
		}
	}
	
	return active
}

// GetPluginsRequiringConfirmation returns plugins that require confirmation
func (pr *PluginRegistry) GetPluginsRequiringConfirmation() []Plugin {
	pr.mutex.RLock()
	defer pr.mutex.RUnlock()
	
	confirmed := make([]Plugin, 0)
	for _, plugin := range pr.plugins {
		if plugin.RequiresConfirmation() {
			confirmed = append(confirmed, plugin)
		}
	}
	
	return confirmed
}

// GetPluginsByProvider returns plugins that provide specific data types
func (pr *PluginRegistry) GetPluginsByProvider(dataType string) []Plugin {
	pr.mutex.RLock()
	defer pr.mutex.RUnlock()
	
	providers := make([]Plugin, 0)
	for _, plugin := range pr.plugins {
		for _, provided := range plugin.Provides() {
			if provided == dataType {
				providers = append(providers, plugin)
				break
			}
		}
	}
	
	return providers
}

// GetPluginsByConsumer returns plugins that consume specific data types
func (pr *PluginRegistry) GetPluginsByConsumer(dataType string) []Plugin {
	pr.mutex.RLock()
	defer pr.mutex.RUnlock()
	
	consumers := make([]Plugin, 0)
	for _, plugin := range pr.plugins {
		for _, consumed := range plugin.Consumes() {
			if consumed == dataType {
				consumers = append(consumers, plugin)
				break
			}
		}
	}
	
	return consumers
}

// GetPluginDependencies returns the dependency chain for a plugin
func (pr *PluginRegistry) GetPluginDependencies(name string) []string {
	pr.mutex.RLock()
	defer pr.mutex.RUnlock()
	
	metadata, exists := pr.metadata[name]
	if !exists {
		return []string{}
	}
	
	dependencies := make([]string, 0, len(metadata.Dependencies))
	for _, dep := range metadata.Dependencies {
		dependencies = append(dependencies, dep.Plugin)
	}
	
	return dependencies
}

// GetPluginDependents returns plugins that depend on the specified plugin
func (pr *PluginRegistry) GetPluginDependents(name string) []string {
	pr.mutex.RLock()
	defer pr.mutex.RUnlock()
	
	dependents := make([]string, 0)
	
	for pluginName, metadata := range pr.metadata {
		for _, dep := range metadata.Dependencies {
			if dep.Plugin == name {
				dependents = append(dependents, pluginName)
				break
			}
		}
	}
	
	return dependents
}

// ValidatePlugin checks if a plugin meets registration requirements
func (pr *PluginRegistry) ValidatePlugin(plugin Plugin) error {
	// Check required fields
	if plugin.Name() == "" {
		return fmt.Errorf("plugin name cannot be empty")
	}
	
	if plugin.Category() == "" {
		return fmt.Errorf("plugin category cannot be empty")
	}
	
	if plugin.Version() == "" {
		return fmt.Errorf("plugin version cannot be empty")
	}
	
	// Check for duplicate registration
	pr.mutex.RLock()
	_, exists := pr.plugins[plugin.Name()]
	pr.mutex.RUnlock()
	
	if exists {
		return fmt.Errorf("plugin %s is already registered", plugin.Name())
	}
	
	// Validate dependencies exist
	for _, dep := range plugin.Dependencies() {
		if dep.Required {
			pr.mutex.RLock()
			_, exists := pr.plugins[dep.Plugin]
			pr.mutex.RUnlock()
			
			if !exists {
				return fmt.Errorf("required dependency %s not found", dep.Plugin)
			}
		}
	}
	
	return nil
}

// GetPluginCount returns the total number of registered plugins
func (pr *PluginRegistry) GetPluginCount() int {
	pr.mutex.RLock()
	defer pr.mutex.RUnlock()
	
	return len(pr.plugins)
}

// GetCategoryCount returns the number of plugins in a category
func (pr *PluginRegistry) GetCategoryCount(category string) int {
	pr.mutex.RLock()
	defer pr.mutex.RUnlock()
	
	pluginNames, exists := pr.categories[category]
	if !exists {
		return 0
	}
	
	return len(pluginNames)
}

// IsRegistered checks if a plugin is registered
func (pr *PluginRegistry) IsRegistered(name string) bool {
	pr.mutex.RLock()
	defer pr.mutex.RUnlock()
	
	_, exists := pr.plugins[name]
	return exists
}

// List returns a list of all plugin names
func (pr *PluginRegistry) List() []string {
	pr.mutex.RLock()
	defer pr.mutex.RUnlock()
	
	names := make([]string, 0, len(pr.plugins))
	for name := range pr.plugins {
		names = append(names, name)
	}
	
	return names
}

// GetPluginStats returns statistics about registered plugins
func (pr *PluginRegistry) GetPluginStats() RegistryStats {
	pr.mutex.RLock()
	defer pr.mutex.RUnlock()
	
	stats := RegistryStats{
		Total:      len(pr.plugins),
		Categories: make(map[string]int),
		Passive:    0,
		Active:     0,
		Confirmed:  0,
	}
	
	// Count by category
	for category, plugins := range pr.categories {
		stats.Categories[category] = len(plugins)
	}
	
	// Count by type
	for _, metadata := range pr.metadata {
		if metadata.Passive {
			stats.Passive++
		} else {
			stats.Active++
		}
		
		if metadata.Confirmed {
			stats.Confirmed++
		}
	}
	
	return stats
}

// RegistryStats contains statistics about the plugin registry
type RegistryStats struct {
	Total      int            `json:"total"`
	Categories map[string]int `json:"categories"`
	Passive    int            `json:"passive"`
	Active     int            `json:"active"`
	Confirmed  int            `json:"confirmed"`
}
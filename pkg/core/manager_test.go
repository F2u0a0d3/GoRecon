package core

import (
	"context"
	"testing"
	"time"

	"github.com/f2u0a0d3/GoRecon/pkg/config"
	"github.com/f2u0a0d3/GoRecon/pkg/models"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"
)

// MockPlugin for testing
type MockPlugin struct {
	mock.Mock
}

func (m *MockPlugin) ID() string {
	args := m.Called()
	return args.String(0)
}

func (m *MockPlugin) Name() string {
	args := m.Called()
	return args.String(0)
}

func (m *MockPlugin) Description() string {
	args := m.Called()
	return args.String(0)
}

func (m *MockPlugin) Version() string {
	args := m.Called()
	return args.String(0)
}

func (m *MockPlugin) Author() string {
	args := m.Called()
	return args.String(0)
}

func (m *MockPlugin) Category() string {
	args := m.Called()
	return args.String(0)
}

func (m *MockPlugin) GetDependencies() []Dependency {
	args := m.Called()
	return args.Get(0).([]Dependency)
}

func (m *MockPlugin) GetRequiredResources() ResourceRequirements {
	args := m.Called()
	return args.Get(0).(ResourceRequirements)
}

func (m *MockPlugin) Validate() error {
	args := m.Called()
	return args.Error(0)
}

func (m *MockPlugin) Execute(ctx context.Context, target models.Target, sharedCtx *SharedContext) (*models.PluginResult, error) {
	args := m.Called(ctx, target, sharedCtx)
	return args.Get(0).(*models.PluginResult), args.Error(1)
}

func (m *MockPlugin) GetIntelligencePatterns() []IntelligencePattern {
	args := m.Called()
	return args.Get(0).([]IntelligencePattern)
}

func (m *MockPlugin) SupportsTarget(target models.Target) bool {
	args := m.Called(target)
	return args.Bool(0)
}

func (m *MockPlugin) GetMetadata() PluginMetadata {
	args := m.Called()
	return args.Get(0).(PluginMetadata)
}

func TestNewPluginManager(t *testing.T) {
	cfg := &config.Config{
		Plugins: config.PluginConfig{
			MaxConcurrent: 5,
			Timeout:       30 * time.Second,
		},
	}

	manager := NewPluginManager(cfg)

	assert.NotNil(t, manager)
	assert.Equal(t, 5, manager.maxConcurrent)
	assert.Equal(t, 30*time.Second, manager.timeout)
	assert.NotNil(t, manager.plugins)
	assert.NotNil(t, manager.executions)
	assert.NotNil(t, manager.sharedContext)
}

func TestRegisterPlugin(t *testing.T) {
	cfg := &config.Config{
		Plugins: config.PluginConfig{
			MaxConcurrent: 5,
			Timeout:       30 * time.Second,
		},
	}

	manager := NewPluginManager(cfg)
	mockPlugin := new(MockPlugin)

	mockPlugin.On("ID").Return("test-plugin")
	mockPlugin.On("Validate").Return(nil)

	err := manager.RegisterPlugin(mockPlugin)

	assert.NoError(t, err)
	assert.Contains(t, manager.plugins, "test-plugin")

	mockPlugin.AssertExpectations(t)
}

func TestRegisterPluginDuplicate(t *testing.T) {
	cfg := &config.Config{
		Plugins: config.PluginConfig{
			MaxConcurrent: 5,
			Timeout:       30 * time.Second,
		},
	}

	manager := NewPluginManager(cfg)
	mockPlugin := new(MockPlugin)

	mockPlugin.On("ID").Return("test-plugin")
	mockPlugin.On("Validate").Return(nil)

	// Register first time
	err := manager.RegisterPlugin(mockPlugin)
	assert.NoError(t, err)

	// Register second time - should fail
	err = manager.RegisterPlugin(mockPlugin)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "already registered")

	mockPlugin.AssertExpectations(t)
}

func TestExecutePlugin(t *testing.T) {
	cfg := &config.Config{
		Plugins: config.PluginConfig{
			MaxConcurrent: 5,
			Timeout:       30 * time.Second,
		},
	}

	manager := NewPluginManager(cfg)
	mockPlugin := new(MockPlugin)

	// Setup mock expectations
	mockPlugin.On("ID").Return("test-plugin")
	mockPlugin.On("Validate").Return(nil)
	mockPlugin.On("SupportsTarget", mock.AnythingOfType("models.Target")).Return(true)
	
	expectedResult := &models.PluginResult{
		ID:          "result-1",
		Plugin:      "test-plugin",
		Target:      models.Target{Domain: "example.com"},
		Finding:     "Test finding",
		Severity:    "medium",
		Confidence:  0.8,
		Timestamp:   time.Now(),
		Category:    "test",
		Description: "Test description",
	}

	mockPlugin.On("Execute", mock.AnythingOfType("*context.timerCtx"), mock.AnythingOfType("models.Target"), mock.AnythingOfType("*core.SharedContext")).Return(expectedResult, nil)

	// Register plugin
	err := manager.RegisterPlugin(mockPlugin)
	assert.NoError(t, err)

	// Execute plugin
	ctx := context.Background()
	target := models.Target{Domain: "example.com"}
	
	result, err := manager.ExecutePlugin(ctx, "test-plugin", target)

	assert.NoError(t, err)
	assert.NotNil(t, result)
	assert.Equal(t, "result-1", result.ID)
	assert.Equal(t, "test-plugin", result.Plugin)
	assert.Equal(t, "Test finding", result.Finding)

	mockPlugin.AssertExpectations(t)
}

func TestExecutePluginNotFound(t *testing.T) {
	cfg := &config.Config{
		Plugins: config.PluginConfig{
			MaxConcurrent: 5,
			Timeout:       30 * time.Second,
		},
	}

	manager := NewPluginManager(cfg)
	ctx := context.Background()
	target := models.Target{Domain: "example.com"}

	result, err := manager.ExecutePlugin(ctx, "non-existent-plugin", target)

	assert.Error(t, err)
	assert.Nil(t, result)
	assert.Contains(t, err.Error(), "plugin not found")
}

func TestExecutePluginUnsupportedTarget(t *testing.T) {
	cfg := &config.Config{
		Plugins: config.PluginConfig{
			MaxConcurrent: 5,
			Timeout:       30 * time.Second,
		},
	}

	manager := NewPluginManager(cfg)
	mockPlugin := new(MockPlugin)

	mockPlugin.On("ID").Return("test-plugin")
	mockPlugin.On("Validate").Return(nil)
	mockPlugin.On("SupportsTarget", mock.AnythingOfType("models.Target")).Return(false)

	// Register plugin
	err := manager.RegisterPlugin(mockPlugin)
	assert.NoError(t, err)

	// Execute plugin with unsupported target
	ctx := context.Background()
	target := models.Target{Domain: "example.com"}
	
	result, err := manager.ExecutePlugin(ctx, "test-plugin", target)

	assert.Error(t, err)
	assert.Nil(t, result)
	assert.Contains(t, err.Error(), "target not supported")

	mockPlugin.AssertExpectations(t)
}

func TestExecutePluginsConcurrently(t *testing.T) {
	cfg := &config.Config{
		Plugins: config.PluginConfig{
			MaxConcurrent: 2,
			Timeout:       30 * time.Second,
		},
	}

	manager := NewPluginManager(cfg)

	// Create multiple mock plugins
	plugins := make([]*MockPlugin, 3)
	for i := range plugins {
		plugins[i] = new(MockPlugin)
		pluginID := fmt.Sprintf("test-plugin-%d", i)
		
		plugins[i].On("ID").Return(pluginID)
		plugins[i].On("Validate").Return(nil)
		plugins[i].On("SupportsTarget", mock.AnythingOfType("models.Target")).Return(true)
		
		expectedResult := &models.PluginResult{
			ID:          fmt.Sprintf("result-%d", i),
			Plugin:      pluginID,
			Target:      models.Target{Domain: "example.com"},
			Finding:     fmt.Sprintf("Test finding %d", i),
			Severity:    "medium",
			Confidence:  0.8,
			Timestamp:   time.Now(),
			Category:    "test",
			Description: fmt.Sprintf("Test description %d", i),
		}

		plugins[i].On("Execute", mock.AnythingOfType("*context.timerCtx"), mock.AnythingOfType("models.Target"), mock.AnythingOfType("*core.SharedContext")).Return(expectedResult, nil)

		// Register plugin
		err := manager.RegisterPlugin(plugins[i])
		assert.NoError(t, err)
	}

	// Execute plugins concurrently
	ctx := context.Background()
	target := models.Target{Domain: "example.com"}
	pluginIDs := []string{"test-plugin-0", "test-plugin-1", "test-plugin-2"}

	results, err := manager.ExecutePluginsConcurrently(ctx, pluginIDs, target)

	assert.NoError(t, err)
	assert.Len(t, results, 3)

	// Verify results
	for i, result := range results {
		assert.NotNil(t, result)
		assert.Contains(t, result.Plugin, "test-plugin-")
		assert.Contains(t, result.Finding, "Test finding")
	}

	// Verify all mocks
	for _, plugin := range plugins {
		plugin.AssertExpectations(t)
	}
}

func TestGetPluginInfo(t *testing.T) {
	cfg := &config.Config{
		Plugins: config.PluginConfig{
			MaxConcurrent: 5,
			Timeout:       30 * time.Second,
		},
	}

	manager := NewPluginManager(cfg)
	mockPlugin := new(MockPlugin)

	mockPlugin.On("ID").Return("test-plugin")
	mockPlugin.On("Name").Return("Test Plugin")
	mockPlugin.On("Description").Return("A test plugin")
	mockPlugin.On("Version").Return("1.0.0")
	mockPlugin.On("Author").Return("Test Author")
	mockPlugin.On("Category").Return("test")
	mockPlugin.On("Validate").Return(nil)

	// Register plugin
	err := manager.RegisterPlugin(mockPlugin)
	assert.NoError(t, err)

	// Get plugin info
	info := manager.GetPluginInfo("test-plugin")

	assert.NotNil(t, info)
	assert.Equal(t, "test-plugin", info.ID)
	assert.Equal(t, "Test Plugin", info.Name)
	assert.Equal(t, "A test plugin", info.Description)
	assert.Equal(t, "1.0.0", info.Version)
	assert.Equal(t, "Test Author", info.Author)
	assert.Equal(t, "test", info.Category)

	mockPlugin.AssertExpectations(t)
}

func TestListPlugins(t *testing.T) {
	cfg := &config.Config{
		Plugins: config.PluginConfig{
			MaxConcurrent: 5,
			Timeout:       30 * time.Second,
		},
	}

	manager := NewPluginManager(cfg)

	// Initially no plugins
	plugins := manager.ListPlugins()
	assert.Empty(t, plugins)

	// Add plugins
	mockPlugin1 := new(MockPlugin)
	mockPlugin1.On("ID").Return("plugin-1")
	mockPlugin1.On("Validate").Return(nil)

	mockPlugin2 := new(MockPlugin)
	mockPlugin2.On("ID").Return("plugin-2")
	mockPlugin2.On("Validate").Return(nil)

	err := manager.RegisterPlugin(mockPlugin1)
	assert.NoError(t, err)

	err = manager.RegisterPlugin(mockPlugin2)
	assert.NoError(t, err)

	// List plugins
	plugins = manager.ListPlugins()
	assert.Len(t, plugins, 2)
	assert.Contains(t, plugins, "plugin-1")
	assert.Contains(t, plugins, "plugin-2")

	mockPlugin1.AssertExpectations(t)
	mockPlugin2.AssertExpectations(t)
}

func TestSharedContext(t *testing.T) {
	cfg := &config.Config{
		Plugins: config.PluginConfig{
			MaxConcurrent: 5,
			Timeout:       30 * time.Second,
		},
	}

	manager := NewPluginManager(cfg)

	// Test shared context operations
	manager.sharedContext.SetData("test-key", "test-value")
	value := manager.sharedContext.GetData("test-key")
	assert.Equal(t, "test-value", value)

	// Test non-existent key
	value = manager.sharedContext.GetData("non-existent")
	assert.Nil(t, value)

	// Test adding finding to shared context
	finding := models.PluginResult{
		ID:      "finding-1",
		Plugin:  "test-plugin",
		Finding: "Test finding",
	}

	manager.sharedContext.AddFinding(finding)
	findings := manager.sharedContext.GetFindings()
	assert.Len(t, findings, 1)
	assert.Equal(t, "finding-1", findings[0].ID)
}

func TestPluginMetrics(t *testing.T) {
	cfg := &config.Config{
		Plugins: config.PluginConfig{
			MaxConcurrent: 5,
			Timeout:       30 * time.Second,
		},
	}

	manager := NewPluginManager(cfg)
	mockPlugin := new(MockPlugin)

	mockPlugin.On("ID").Return("test-plugin")
	mockPlugin.On("Validate").Return(nil)
	mockPlugin.On("SupportsTarget", mock.AnythingOfType("models.Target")).Return(true)

	expectedResult := &models.PluginResult{
		ID:          "result-1",
		Plugin:      "test-plugin",
		Target:      models.Target{Domain: "example.com"},
		Finding:     "Test finding",
		Severity:    "medium",
		Confidence:  0.8,
		Timestamp:   time.Now(),
		Category:    "test",
		Description: "Test description",
	}

	mockPlugin.On("Execute", mock.AnythingOfType("*context.timerCtx"), mock.AnythingOfType("models.Target"), mock.AnythingOfType("*core.SharedContext")).Return(expectedResult, nil)

	// Register and execute plugin
	err := manager.RegisterPlugin(mockPlugin)
	assert.NoError(t, err)

	ctx := context.Background()
	target := models.Target{Domain: "example.com"}

	_, err = manager.ExecutePlugin(ctx, "test-plugin", target)
	assert.NoError(t, err)

	// Check metrics
	stats := manager.GetStatistics()
	assert.NotNil(t, stats)
	assert.Equal(t, 1, stats.TotalExecutions)
	assert.Equal(t, 1, stats.SuccessfulExecutions)
	assert.Equal(t, 0, stats.FailedExecutions)
	assert.Contains(t, stats.PluginStats, "test-plugin")

	pluginStat := stats.PluginStats["test-plugin"]
	assert.Equal(t, 1, pluginStat.Executions)
	assert.Equal(t, 1, pluginStat.Successes)
	assert.Equal(t, 0, pluginStat.Failures)

	mockPlugin.AssertExpectations(t)
}

func TestConcurrencyLimit(t *testing.T) {
	cfg := &config.Config{
		Plugins: config.PluginConfig{
			MaxConcurrent: 1, // Limit to 1 concurrent execution
			Timeout:       30 * time.Second,
		},
	}

	manager := NewPluginManager(cfg)

	// Create a slow plugin
	mockPlugin := new(MockPlugin)
	mockPlugin.On("ID").Return("slow-plugin")
	mockPlugin.On("Validate").Return(nil)
	mockPlugin.On("SupportsTarget", mock.AnythingOfType("models.Target")).Return(true)

	expectedResult := &models.PluginResult{
		ID:          "result-1",
		Plugin:      "slow-plugin",
		Target:      models.Target{Domain: "example.com"},
		Finding:     "Test finding",
		Severity:    "medium",
		Confidence:  0.8,
		Timestamp:   time.Now(),
		Category:    "test",
		Description: "Test description",
	}

	// Make the plugin execution slow
	mockPlugin.On("Execute", mock.AnythingOfType("*context.timerCtx"), mock.AnythingOfType("models.Target"), mock.AnythingOfType("*core.SharedContext")).Return(expectedResult, nil).After(100 * time.Millisecond)

	// Register plugin
	err := manager.RegisterPlugin(mockPlugin)
	assert.NoError(t, err)

	// Test that only 1 execution runs at a time
	ctx := context.Background()
	target := models.Target{Domain: "example.com"}
	pluginIDs := []string{"slow-plugin", "slow-plugin"}

	start := time.Now()
	results, err := manager.ExecutePluginsConcurrently(ctx, pluginIDs, target)
	duration := time.Since(start)

	assert.NoError(t, err)
	assert.Len(t, results, 2)
	// Should take at least 200ms due to sequential execution
	assert.True(t, duration >= 200*time.Millisecond)

	mockPlugin.AssertExpectations(t)
}
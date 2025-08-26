package intelligence

import (
	"context"
	"testing"
	"time"

	"github.com/f2u0a0d3/GoRecon/pkg/models"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestNewIntelligenceCorrelator(t *testing.T) {
	config := CorrelationConfig{
		EnableMLAnalysis:      true,
		EnableThreatIntel:     true,
		EnableRiskScoring:     true,
		CorrelationWindow:     24 * time.Hour,
		MinConfidence:         0.7,
		MaxResults:            1000,
		CacheResults:          true,
		CacheTTL:              1 * time.Hour,
		MitreMapping:          true,
		AttackPathAnalysis:    true,
		FalsePositiveFiltering: true,
	}

	correlator, err := NewIntelligenceCorrelator(config)

	assert.NoError(t, err)
	assert.NotNil(t, correlator)
	assert.Equal(t, config, correlator.config)
	assert.NotNil(t, correlator.rules)
	assert.NotNil(t, correlator.patterns)
	assert.NotNil(t, correlator.knowledgeBase)
	assert.NotNil(t, correlator.correlationCache)
}

func TestCorrelateFindings(t *testing.T) {
	config := CorrelationConfig{
		EnableMLAnalysis:       false, // Disable ML for simpler testing
		EnableThreatIntel:      false, // Disable threat intel for simpler testing
		EnableRiskScoring:      true,
		CorrelationWindow:      24 * time.Hour,
		MinConfidence:          0.7,
		MaxResults:            1000,
		CacheResults:          false, // Disable cache for testing
		MitreMapping:          true,
		AttackPathAnalysis:    true,
		FalsePositiveFiltering: false, // Disable for testing
	}

	correlator, err := NewIntelligenceCorrelator(config)
	require.NoError(t, err)

	// Create test findings
	findings := []models.PluginResult{
		{
			ID:          "finding-1",
			Plugin:      "cloud_enum",
			Target:      models.Target{Domain: "example.com"},
			Finding:     "S3 bucket with public read access",
			Severity:    "high",
			Confidence:  0.9,
			Timestamp:   time.Now(),
			Category:    "cloud-misconfiguration",
			Description: "Found publicly accessible S3 bucket",
			CVSSScore:   7.5,
			MITRETechniques: []string{"T1580"},
		},
		{
			ID:          "finding-2",
			Plugin:      "cloud_enum",
			Target:      models.Target{Domain: "example.com"},
			Finding:     "IAM user with excessive permissions",
			Severity:    "high",
			Confidence:  0.8,
			Timestamp:   time.Now().Add(-10 * time.Minute),
			Category:    "cloud-misconfiguration",
			Description: "IAM user has admin privileges",
			CVSSScore:   8.0,
			MITRETechniques: []string{"T1078.004"},
		},
		{
			ID:          "finding-3",
			Plugin:      "httpprobe",
			Target:      models.Target{Domain: "example.com", Port: "80"},
			Finding:     "HTTP service on port 80",
			Severity:    "info",
			Confidence:  0.95,
			Timestamp:   time.Now().Add(-5 * time.Minute),
			Category:    "service-discovery",
			Description: "HTTP service detected",
			CVSSScore:   0.0,
			MITRETechniques: []string{"T1046"},
		},
	}

	ctx := context.Background()
	result, err := correlator.CorrelateFindings(ctx, findings)

	assert.NoError(t, err)
	assert.NotNil(t, result)
	assert.Len(t, result.Findings, 3)
	assert.NotEmpty(t, result.ID)
	assert.True(t, result.RiskScore > 0)
	assert.True(t, result.Confidence > 0)
	assert.NotEmpty(t, result.Summary)

	// Should have at least one correlated group
	assert.NotEmpty(t, result.CorrelatedGroups)
	
	// Should have MITRE techniques mapped
	assert.NotEmpty(t, result.MitreTechniques)

	// Should have some recommendations
	assert.NotEmpty(t, result.Recommendations)
}

func TestApplyCorrelationRules(t *testing.T) {
	config := CorrelationConfig{
		MinConfidence: 0.7,
	}

	correlator, err := NewIntelligenceCorrelator(config)
	require.NoError(t, err)

	// Create findings that should trigger correlation rules
	findings := []models.PluginResult{
		{
			ID:          "finding-1",
			Plugin:      "vuln_scanner",
			Target:      models.Target{Domain: "example.com"},
			Finding:     "SQL injection vulnerability",
			Severity:    "high",
			Confidence:  0.9,
			Timestamp:   time.Now(),
			Category:    "vulnerability",
			Description: "SQL injection in login form",
		},
		{
			ID:          "finding-2",
			Plugin:      "vuln_scanner",
			Target:      models.Target{Domain: "example.com"},
			Finding:     "Cross-site scripting vulnerability",
			Severity:    "high",
			Confidence:  0.8,
			Timestamp:   time.Now().Add(-5 * time.Minute),
			Category:    "vulnerability",
			Description: "XSS in user input field",
		},
		{
			ID:          "finding-3",
			Plugin:      "info_gatherer",
			Target:      models.Target{Domain: "example.com"},
			Finding:     "Server version disclosure",
			Severity:    "low",
			Confidence:  0.7,
			Timestamp:   time.Now().Add(-10 * time.Minute),
			Category:    "information-disclosure",
			Description: "Apache version exposed in headers",
		},
	}

	groups, err := correlator.applyCorrelationRules(findings)

	assert.NoError(t, err)
	assert.NotEmpty(t, groups)

	// Should have found vulnerability cluster
	vulnerabilityGroupFound := false
	for _, group := range groups {
		if group.Name == "Vulnerability Cluster" {
			vulnerabilityGroupFound = true
			assert.Len(t, group.Findings, 2) // The two high severity vulnerabilities
			assert.True(t, group.Correlation.Confidence >= 0.7)
		}
	}
	assert.True(t, vulnerabilityGroupFound, "Should find vulnerability cluster correlation")
}

func TestMatchThreatPatterns(t *testing.T) {
	config := CorrelationConfig{}
	correlator, err := NewIntelligenceCorrelator(config)
	require.NoError(t, err)

	// Create findings that should match threat patterns
	findings := []models.PluginResult{
		{
			ID:          "finding-1",
			Plugin:      "scanner",
			Finding:     "systematic enumeration detected",
			Description: "Multiple discovery tools used for reconnaissance",
			Category:    "reconnaissance",
			MITRETechniques: []string{"T1595"},
		},
		{
			ID:          "finding-2",
			Plugin:      "scanner",
			Finding:     "infrastructure mapping discovered",
			Description: "Network topology discovery",
			Category:    "discovery",
			MITRETechniques: []string{"T1590"},
		},
	}

	matchedPatterns := correlator.matchThreatPatterns(findings)

	assert.NotEmpty(t, matchedPatterns)
	
	// Should match APT reconnaissance pattern
	aptPatternFound := false
	for _, patternID := range matchedPatterns {
		if patternID == "apt-reconnaissance-pattern" {
			aptPatternFound = true
			break
		}
	}
	assert.True(t, aptPatternFound, "Should match APT reconnaissance pattern")
}

func TestTemporalCorrelation(t *testing.T) {
	config := CorrelationConfig{}
	correlator, err := NewIntelligenceCorrelator(config)
	require.NoError(t, err)

	baseTime := time.Now()
	
	// Create findings within a short time window
	findings := []models.PluginResult{
		{
			ID:        "finding-1",
			Timestamp: baseTime,
			Target:    models.Target{Domain: "example.com"},
		},
		{
			ID:        "finding-2",
			Timestamp: baseTime.Add(5 * time.Minute),
			Target:    models.Target{Domain: "example.com"},
		},
		{
			ID:        "finding-3",
			Timestamp: baseTime.Add(10 * time.Minute),
			Target:    models.Target{Domain: "example.com"},
		},
		{
			ID:        "finding-4",
			Timestamp: baseTime.Add(15 * time.Minute),
			Target:    models.Target{Domain: "example.com"},
		},
	}

	temporalGroups := correlator.applyTemporalCorrelation(findings)

	assert.NotEmpty(t, temporalGroups)
	
	// Should group findings that occurred close in time
	found := false
	for _, group := range temporalGroups {
		if len(group.Findings) >= 3 {
			found = true
			assert.Equal(t, "temporal", group.Correlation.Type)
			assert.True(t, group.Correlation.Confidence > 0)
		}
	}
	assert.True(t, found, "Should find temporal correlation group")
}

func TestSpatialCorrelation(t *testing.T) {
	config := CorrelationConfig{}
	correlator, err := NewIntelligenceCorrelator(config)
	require.NoError(t, err)

	// Create findings for the same target
	findings := []models.PluginResult{
		{
			ID:     "finding-1",
			Target: models.Target{Domain: "example.com"},
			Plugin: "plugin-1",
		},
		{
			ID:     "finding-2", 
			Target: models.Target{Domain: "example.com"},
			Plugin: "plugin-2",
		},
		{
			ID:     "finding-3",
			Target: models.Target{Domain: "different.com"},
			Plugin: "plugin-1",
		},
	}

	spatialGroups := correlator.applySpatialCorrelation(findings)

	assert.NotEmpty(t, spatialGroups)
	
	// Should group findings by target
	exampleComGroupFound := false
	for _, group := range spatialGroups {
		if strings.Contains(group.Description, "example.com") {
			exampleComGroupFound = true
			assert.Len(t, group.Findings, 2) // Two findings for example.com
			assert.Equal(t, "spatial", group.Correlation.Type)
		}
	}
	assert.True(t, exampleComGroupFound, "Should find spatial correlation for example.com")
}

func TestMitreTechniqueMapping(t *testing.T) {
	config := CorrelationConfig{
		MitreMapping: true,
	}
	correlator, err := NewIntelligenceCorrelator(config)
	require.NoError(t, err)

	// Load MITRE data
	err = correlator.knowledgeBase.LoadMitreData()
	require.NoError(t, err)

	findings := []models.PluginResult{
		{
			ID:              "finding-1",
			Finding:         "SQL injection vulnerability",
			MITRETechniques: []string{"T1190"}, // Exploit Public-Facing Application
		},
		{
			ID:              "finding-2",
			Finding:         "Command injection",
			MITRETechniques: []string{"T1059"}, // Command and Scripting Interpreter
		},
	}

	groups := []CorrelatedFindingGroup{
		{
			Findings: findings,
		},
	}

	techniques := correlator.mapToMitreTechniques(findings, groups)

	assert.NotEmpty(t, techniques)
	
	// Should map known techniques
	foundT1190 := false
	foundT1059 := false
	
	for _, technique := range techniques {
		if technique.ID == "T1190" {
			foundT1190 = true
			assert.Equal(t, "Exploit Public-Facing Application", technique.Name)
		}
		if technique.ID == "T1059" {
			foundT1059 = true
			assert.Equal(t, "Command and Scripting Interpreter", technique.Name)
		}
	}
	
	assert.True(t, foundT1190, "Should map T1190 technique")
	assert.True(t, foundT1059, "Should map T1059 technique")
}

func TestAttackPathAnalysis(t *testing.T) {
	config := CorrelationConfig{
		AttackPathAnalysis: true,
	}
	correlator, err := NewIntelligenceCorrelator(config)
	require.NoError(t, err)

	groups := []CorrelatedFindingGroup{
		{
			ID:   "group-1",
			Name: "Initial Access Group",
			Findings: []models.PluginResult{
				{
					ID:       "finding-1",
					Category: "vulnerability",
					Severity: "high",
				},
			},
		},
		{
			ID:   "group-2", 
			Name: "Privilege Escalation Group",
			Findings: []models.PluginResult{
				{
					ID:       "finding-2",
					Category: "misconfiguration",
					Severity: "medium",
				},
			},
		},
	}

	techniques := []MitreTechnique{
		{
			ID:   "T1190",
			Name: "Exploit Public-Facing Application",
		},
		{
			ID:   "T1055",
			Name: "Process Injection",
		},
	}

	attackPaths := correlator.analyzeAttackPaths(groups, techniques)

	assert.NotEmpty(t, attackPaths)
	
	for _, path := range attackPaths {
		assert.NotEmpty(t, path.ID)
		assert.NotEmpty(t, path.Name)
		assert.NotEmpty(t, path.Steps)
		assert.True(t, path.RiskScore > 0)
		assert.True(t, path.Likelihood > 0)
		assert.True(t, path.Impact > 0)
		assert.NotEmpty(t, path.Mitigations)
	}
}

func TestRiskScoring(t *testing.T) {
	config := CorrelationConfig{
		EnableRiskScoring: true,
	}
	correlator, err := NewIntelligenceCorrelator(config)
	require.NoError(t, err)

	findings := []models.PluginResult{
		{
			ID:         "finding-1",
			Severity:   "critical",
			Confidence: 0.9,
			CVSSScore:  9.8,
		},
		{
			ID:         "finding-2",
			Severity:   "high",
			Confidence: 0.8,
			CVSSScore:  7.5,
		},
		{
			ID:         "finding-3",
			Severity:   "medium",
			Confidence: 0.7,
			CVSSScore:  5.0,
		},
	}

	groups := []CorrelatedFindingGroup{
		{
			Findings: findings,
			Correlation: CorrelationMetadata{
				Strength:   0.8,
				Confidence: 0.9,
			},
		},
	}

	riskScore := correlator.riskScorer.CalculateRiskScore(findings, groups)

	assert.True(t, riskScore > 0)
	assert.True(t, riskScore <= 10.0) // Should be within expected range
	
	// Critical findings should result in high risk score
	assert.True(t, riskScore > 7.0, "Critical findings should result in high risk score")
}

func TestCacheResults(t *testing.T) {
	config := CorrelationConfig{
		CacheResults: true,
		CacheTTL:     1 * time.Hour,
	}

	correlator, err := NewIntelligenceCorrelator(config)
	require.NoError(t, err)

	findings := []models.PluginResult{
		{
			ID:       "finding-1",
			Severity: "medium",
		},
	}

	ctx := context.Background()

	// First correlation - should compute and cache
	result1, err := correlator.CorrelateFindings(ctx, findings)
	assert.NoError(t, err)
	assert.NotNil(t, result1)

	// Second correlation with same findings - should use cache
	result2, err := correlator.CorrelateFindings(ctx, findings)
	assert.NoError(t, err)
	assert.NotNil(t, result2)

	// Results should be identical (from cache)
	assert.Equal(t, result1.ID, result2.ID)
}

func TestFilterFalsePositives(t *testing.T) {
	config := CorrelationConfig{
		FalsePositiveFiltering: true,
	}
	correlator, err := NewIntelligenceCorrelator(config)
	require.NoError(t, err)

	findings := []models.PluginResult{
		{
			ID:      "finding-1",
			Finding: "Valid security finding",
			Confidence: 0.9,
		},
		{
			ID:      "finding-2", 
			Finding: "test page detected", // Should be filtered as false positive
			Confidence: 0.8,
		},
		{
			ID:      "finding-3",
			Finding: "example.com reference", // Should be filtered as false positive
			Confidence: 0.7,
		},
		{
			ID:      "finding-4",
			Finding: "Low confidence wayback result",
			Plugin:  "wayback",
			Confidence: 0.2, // Should be filtered as false positive
		},
	}

	filtered := correlator.filterFalsePositives(findings)

	assert.Len(t, filtered, 1) // Only the valid finding should remain
	assert.Equal(t, "finding-1", filtered[0].ID)
}

func TestEvaluateConditions(t *testing.T) {
	config := CorrelationConfig{}
	correlator, err := NewIntelligenceCorrelator(config)
	require.NoError(t, err)

	finding := models.PluginResult{
		Plugin:      "test-plugin",
		Category:    "vulnerability",
		Severity:    "high",
		Target:      models.Target{Domain: "example.com"},
		Finding:     "SQL injection vulnerability",
		Description: "Critical SQL injection found",
		Confidence:  0.9,
	}

	conditions := []CorrelationCondition{
		{
			Field:    "category",
			Operator: "equals",
			Value:    "vulnerability",
			Weight:   0.8,
			Required: true,
		},
		{
			Field:    "severity",
			Operator: "equals",
			Value:    "high",
			Weight:   0.6,
			Required: false,
		},
		{
			Field:    "finding",
			Operator: "contains",
			Value:    "SQL",
			Weight:   0.7,
			Required: false,
		},
	}

	result := correlator.evaluateConditions(finding, conditions)

	assert.True(t, result, "Should match all conditions")
}

func BenchmarkCorrelateFindings(b *testing.B) {
	config := CorrelationConfig{
		EnableMLAnalysis:       false,
		EnableThreatIntel:      false,
		EnableRiskScoring:      true,
		FalsePositiveFiltering: false,
		CacheResults:          false,
	}

	correlator, _ := NewIntelligenceCorrelator(config)

	// Create a realistic set of findings
	findings := make([]models.PluginResult, 100)
	for i := range findings {
		findings[i] = models.PluginResult{
			ID:          fmt.Sprintf("finding-%d", i),
			Plugin:      fmt.Sprintf("plugin-%d", i%10),
			Target:      models.Target{Domain: fmt.Sprintf("target-%d.com", i%20)},
			Finding:     fmt.Sprintf("Test finding %d", i),
			Severity:    []string{"low", "medium", "high", "critical"}[i%4],
			Confidence:  float64(i%100) / 100.0,
			Timestamp:   time.Now().Add(time.Duration(i) * time.Minute),
			Category:    []string{"vulnerability", "misconfiguration", "information"}[i%3],
		}
	}

	ctx := context.Background()

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_, err := correlator.CorrelateFindings(ctx, findings)
		if err != nil {
			b.Fatal(err)
		}
	}
}
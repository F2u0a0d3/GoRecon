package takeover

import (
	"encoding/json"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestParseSubzyOutput(t *testing.T) {
	tests := []struct {
		name           string
		input          string
		expectedCount  int
		expectedError  bool
		expectedVuln   bool
	}{
		{
			name:          "Empty input",
			input:         "",
			expectedCount: 0,
			expectedError: false,
		},
		{
			name:          "Single vulnerable result",
			input:         `{"subdomain":"test.example.com","service":"GitHub Pages","status_code":404,"vulnerable":true,"verified":true,"fingerprint":"There isn't a GitHub Pages site here."}`,
			expectedCount: 1,
			expectedError: false,
			expectedVuln:  true,
		},
		{
			name:          "Array of results",
			input:         `[{"subdomain":"test1.example.com","service":"S3","status_code":404,"vulnerable":true,"verified":false},{"subdomain":"test2.example.com","service":"Heroku","status_code":200,"vulnerable":false,"verified":false}]`,
			expectedCount: 2,
			expectedError: false,
			expectedVuln:  true,
		},
		{
			name:          "Line-delimited JSON",
			input:         `{"subdomain":"test1.example.com","service":"S3","status_code":404,"vulnerable":true,"verified":true}` + "\n" + `{"subdomain":"test2.example.com","service":"Heroku","status_code":200,"vulnerable":false,"verified":false}`,
			expectedCount: 2,
			expectedError: false,
			expectedVuln:  true,
		},
		{
			name:          "Wrapped response format",
			input:         `{"results":[{"subdomain":"test.example.com","service":"GitHub Pages","status_code":404,"vulnerable":true,"verified":true}],"summary":{"total":1,"vulnerable":1,"verified":1}}`,
			expectedCount: 1,
			expectedError: false,
			expectedVuln:  true,
		},
		{
			name:          "Invalid JSON",
			input:         `{invalid json}`,
			expectedCount: 0,
			expectedError: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			results, err := ParseSubzyOutput(tt.input)
			
			if tt.expectedError {
				assert.Error(t, err)
				return
			}
			
			require.NoError(t, err)
			assert.Len(t, results, tt.expectedCount)
			
			if tt.expectedVuln && len(results) > 0 {
				found := false
				for _, result := range results {
					if result.Vulnerable {
						found = true
						break
					}
				}
				assert.True(t, found, "Expected at least one vulnerable result")
			}
		})
	}
}

func TestSubzyResult_IsVulnerable(t *testing.T) {
	tests := []struct {
		name     string
		result   SubzyResult
		expected bool
	}{
		{
			name:     "Vulnerable result",
			result:   SubzyResult{Vulnerable: true},
			expected: true,
		},
		{
			name:     "Not vulnerable result",
			result:   SubzyResult{Vulnerable: false},
			expected: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			assert.Equal(t, tt.expected, tt.result.IsVulnerable())
		})
	}
}

func TestSubzyResult_IsVerified(t *testing.T) {
	tests := []struct {
		name     string
		result   SubzyResult
		expected bool
	}{
		{
			name:     "Verified result",
			result:   SubzyResult{Verified: true},
			expected: true,
		},
		{
			name:     "Not verified result",
			result:   SubzyResult{Verified: false},
			expected: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			assert.Equal(t, tt.expected, tt.result.IsVerified())
		})
	}
}

func TestSubzyResult_GetSeverityLevel(t *testing.T) {
	tests := []struct {
		name     string
		result   SubzyResult
		expected string
	}{
		{
			name:     "Critical - verified vulnerable",
			result:   SubzyResult{Vulnerable: true, Verified: true},
			expected: "critical",
		},
		{
			name:     "High - vulnerable but not verified",
			result:   SubzyResult{Vulnerable: true, Verified: false},
			expected: "high",
		},
		{
			name:     "Medium - 404 status",
			result:   SubzyResult{StatusCode: 404},
			expected: "medium",
		},
		{
			name:     "Medium - 403 status",
			result:   SubzyResult{StatusCode: 403},
			expected: "medium",
		},
		{
			name:     "Info - normal status",
			result:   SubzyResult{StatusCode: 200},
			expected: "info",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			assert.Equal(t, tt.expected, tt.result.GetSeverityLevel())
		})
	}
}

func TestSubzyResult_GetConfidenceScore(t *testing.T) {
	tests := []struct {
		name     string
		result   SubzyResult
		minScore float64
		maxScore float64
	}{
		{
			name:     "High confidence - verified vulnerable with known service",
			result:   SubzyResult{Vulnerable: true, Verified: true, Service: "GitHub Pages", StatusCode: 404, Fingerprint: "test"},
			minScore: 0.9,
			maxScore: 0.95,
		},
		{
			name:     "Medium confidence - vulnerable but not verified",
			result:   SubzyResult{Vulnerable: true, Verified: false, Service: "S3", StatusCode: 404},
			minScore: 0.7,
			maxScore: 0.9,
		},
		{
			name:     "Low confidence - just status code",
			result:   SubzyResult{StatusCode: 404},
			minScore: 0.5,
			maxScore: 0.7,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			score := tt.result.GetConfidenceScore()
			assert.GreaterOrEqual(t, score, tt.minScore)
			assert.LessOrEqual(t, score, tt.maxScore)
		})
	}
}

func TestSubzyResult_GetServiceProvider(t *testing.T) {
	tests := []struct {
		name     string
		service  string
		expected string
	}{
		{
			name:     "GitHub Pages",
			service:  "GitHub Pages",
			expected: "GitHub Pages",
		},
		{
			name:     "S3",
			service:  "S3",
			expected: "Amazon Web Services",
		},
		{
			name:     "Heroku",
			service:  "Heroku",
			expected: "Heroku",
		},
		{
			name:     "Azure",
			service:  "Azure",
			expected: "Microsoft Azure",
		},
		{
			name:     "Unknown service",
			service:  "CustomService",
			expected: "CustomService",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := SubzyResult{Service: tt.service}
			assert.Equal(t, tt.expected, result.GetServiceProvider())
		})
	}
}

func TestSubzyResult_GetTakeoverRisk(t *testing.T) {
	tests := []struct {
		name     string
		result   SubzyResult
		expected string
	}{
		{
			name:     "Immediate risk - verified vulnerable",
			result:   SubzyResult{Vulnerable: true, Verified: true},
			expected: "immediate",
		},
		{
			name:     "High risk - vulnerable but not verified",
			result:   SubzyResult{Vulnerable: true, Verified: false},
			expected: "high",
		},
		{
			name:     "Medium risk - 404 status",
			result:   SubzyResult{StatusCode: 404},
			expected: "medium",
		},
		{
			name:     "Low risk - 403 status",
			result:   SubzyResult{StatusCode: 403},
			expected: "low",
		},
		{
			name:     "Minimal risk - normal response",
			result:   SubzyResult{StatusCode: 200},
			expected: "minimal",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			assert.Equal(t, tt.expected, tt.result.GetTakeoverRisk())
		})
	}
}

func TestSubzyResult_GetRecommendedActions(t *testing.T) {
	tests := []struct {
		name        string
		result      SubzyResult
		minActions  int
		containsUrgent bool
	}{
		{
			name:           "Verified vulnerable - urgent actions",
			result:         SubzyResult{Vulnerable: true, Verified: true},
			minActions:     3,
			containsUrgent: true,
		},
		{
			name:           "Vulnerable but not verified",
			result:         SubzyResult{Vulnerable: true, Verified: false},
			minActions:     2,
			containsUrgent: false,
		},
		{
			name:           "404 status - investigation needed",
			result:         SubzyResult{StatusCode: 404},
			minActions:     2,
			containsUrgent: false,
		},
		{
			name:       "Normal response - minimal actions",
			result:     SubzyResult{StatusCode: 200},
			minActions: 0,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			actions := tt.result.GetRecommendedActions()
			assert.GreaterOrEqual(t, len(actions), tt.minActions)
			
			if tt.containsUrgent {
				found := false
				for _, action := range actions {
					if strings.Contains(action, "URGENT") {
						found = true
						break
					}
				}
				assert.True(t, found, "Expected urgent action for verified vulnerability")
			}
		})
	}
}

func TestSubzyResult_ValidateResult(t *testing.T) {
	tests := []struct {
		name        string
		result      SubzyResult
		expectError bool
		errorMsg    string
	}{
		{
			name:        "Valid result",
			result:      SubzyResult{Subdomain: "test.example.com", StatusCode: 200},
			expectError: false,
		},
		{
			name:        "Missing subdomain",
			result:      SubzyResult{StatusCode: 200},
			expectError: true,
			errorMsg:    "subdomain field is required",
		},
		{
			name:        "Invalid status code - negative",
			result:      SubzyResult{Subdomain: "test.example.com", StatusCode: -1},
			expectError: true,
			errorMsg:    "invalid status code",
		},
		{
			name:        "Invalid status code - too high",
			result:      SubzyResult{Subdomain: "test.example.com", StatusCode: 1000},
			expectError: true,
			errorMsg:    "invalid status code",
		},
		{
			name:        "Invalid state - verified but not vulnerable",
			result:      SubzyResult{Subdomain: "test.example.com", StatusCode: 200, Vulnerable: false, Verified: true},
			expectError: true,
			errorMsg:    "result cannot be verified but not vulnerable",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := tt.result.ValidateResult()
			
			if tt.expectError {
				assert.Error(t, err)
				if tt.errorMsg != "" {
					assert.Contains(t, err.Error(), tt.errorMsg)
				}
			} else {
				assert.NoError(t, err)
			}
		})
	}
}

func TestSubzyResult_ToJSON(t *testing.T) {
	result := SubzyResult{
		Subdomain:   "test.example.com",
		Service:     "GitHub Pages",
		StatusCode:  404,
		Vulnerable:  true,
		Verified:    true,
		Fingerprint: "There isn't a GitHub Pages site here.",
	}

	jsonStr, err := result.ToJSON()
	require.NoError(t, err)
	assert.NotEmpty(t, jsonStr)

	// Verify it's valid JSON by parsing it back
	var parsed SubzyResult
	err = json.Unmarshal([]byte(jsonStr), &parsed)
	require.NoError(t, err)
	assert.Equal(t, result.Subdomain, parsed.Subdomain)
	assert.Equal(t, result.Service, parsed.Service)
	assert.Equal(t, result.Vulnerable, parsed.Vulnerable)
}

func TestSubzyResult_HasError(t *testing.T) {
	tests := []struct {
		name     string
		result   SubzyResult
		expected bool
	}{
		{
			name:     "No error",
			result:   SubzyResult{},
			expected: false,
		},
		{
			name:     "Has error",
			result:   SubzyResult{Error: "Connection timeout"},
			expected: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			assert.Equal(t, tt.expected, tt.result.HasError())
		})
	}
}

func TestSubzyResult_IsServiceKnown(t *testing.T) {
	tests := []struct {
		name     string
		service  string
		expected bool
	}{
		{
			name:     "Known service - GitHub",
			service:  "GitHub Pages",
			expected: true,
		},
		{
			name:     "Known service - S3",
			service:  "S3",
			expected: true,
		},
		{
			name:     "Known service - Heroku",
			service:  "Heroku App",
			expected: true,
		},
		{
			name:     "Unknown service",
			service:  "CustomUnknownService",
			expected: false,
		},
		{
			name:     "Empty service",
			service:  "",
			expected: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := SubzyResult{Service: tt.service}
			assert.Equal(t, tt.expected, result.IsServiceKnown())
		})
	}
}

// Benchmark tests for performance
func BenchmarkParseSubzyOutput(b *testing.B) {
	jsonInput := `[{"subdomain":"test1.example.com","service":"S3","status_code":404,"vulnerable":true,"verified":false},{"subdomain":"test2.example.com","service":"Heroku","status_code":200,"vulnerable":false,"verified":false}]`
	
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_, err := ParseSubzyOutput(jsonInput)
		if err != nil {
			b.Fatal(err)
		}
	}
}

func BenchmarkSubzyResult_GetConfidenceScore(b *testing.B) {
	result := SubzyResult{
		Vulnerable:  true,
		Verified:    true,
		Service:     "GitHub Pages",
		StatusCode:  404,
		Fingerprint: "test",
	}
	
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_ = result.GetConfidenceScore()
	}
}

// Test fixtures for integration testing
var TestFixtures = struct {
	VulnerableGitHub    string
	VulnerableS3        string
	VulnerableHeroku    string
	NotVulnerable       string
	MultipleResults     string
	ErrorResult         string
	LineDelimited       string
}{
	VulnerableGitHub: `{
		"subdomain": "test.example.com",
		"service": "GitHub Pages",
		"status_code": 404,
		"vulnerable": true,
		"verified": true,
		"fingerprint": "There isn't a GitHub Pages site here.",
		"timestamp": "2024-01-01T12:00:00Z"
	}`,
	
	VulnerableS3: `{
		"subdomain": "files.example.com",
		"service": "Amazon S3",
		"status_code": 404,
		"vulnerable": true,
		"verified": false,
		"fingerprint": "NoSuchBucket",
		"timestamp": "2024-01-01T12:00:00Z"
	}`,
	
	VulnerableHeroku: `{
		"subdomain": "app.example.com",
		"service": "Heroku",
		"status_code": 404,
		"vulnerable": true,
		"verified": true,
		"fingerprint": "No such app",
		"timestamp": "2024-01-01T12:00:00Z"
	}`,
	
	NotVulnerable: `{
		"subdomain": "www.example.com",
		"service": "CloudFlare",
		"status_code": 200,
		"vulnerable": false,
		"verified": false,
		"timestamp": "2024-01-01T12:00:00Z"
	}`,
	
	MultipleResults: `[
		{
			"subdomain": "test1.example.com",
			"service": "GitHub Pages",
			"status_code": 404,
			"vulnerable": true,
			"verified": true,
			"fingerprint": "There isn't a GitHub Pages site here."
		},
		{
			"subdomain": "test2.example.com",
			"service": "CloudFlare",
			"status_code": 200,
			"vulnerable": false,
			"verified": false
		}
	]`,
	
	ErrorResult: `{
		"subdomain": "timeout.example.com",
		"service": "Unknown",
		"status_code": 0,
		"vulnerable": false,
		"verified": false,
		"error": "Connection timeout after 30 seconds"
	}`,
	
	LineDelimited: `{"subdomain":"test1.example.com","service":"GitHub Pages","status_code":404,"vulnerable":true,"verified":true}
{"subdomain":"test2.example.com","service":"S3","status_code":404,"vulnerable":true,"verified":false}
{"subdomain":"test3.example.com","service":"CloudFlare","status_code":200,"vulnerable":false,"verified":false}`,
}
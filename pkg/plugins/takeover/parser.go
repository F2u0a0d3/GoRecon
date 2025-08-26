package takeover

import (
	"encoding/json"
	"fmt"
	"strings"
	"time"
)

// SubzyResult represents the JSON output structure from subzy tool
type SubzyResult struct {
	Subdomain   string `json:"subdomain"`
	Service     string `json:"service"`
	StatusCode  int    `json:"status_code"`
	Vulnerable  bool   `json:"vulnerable"`
	Verified    bool   `json:"verified"`
	Fingerprint string `json:"fingerprint"`
	Response    string `json:"response,omitempty"`
	Error       string `json:"error,omitempty"`
	Timestamp   string `json:"timestamp,omitempty"`
}

// SubzyResponse represents the complete response from subzy
type SubzyResponse struct {
	Results []SubzyResult `json:"results,omitempty"`
	Summary SubzySummary  `json:"summary,omitempty"`
}

// SubzySummary provides statistics about the scan
type SubzySummary struct {
	Total       int `json:"total"`
	Vulnerable  int `json:"vulnerable"`
	Verified    int `json:"verified"`
	Potential   int `json:"potential"`
	Duration    int `json:"duration_ms"`
	Timestamp   string `json:"timestamp"`
}

// ParseSubzyOutput parses subzy JSON output into structured results
func ParseSubzyOutput(jsonOutput string) ([]SubzyResult, error) {
	if strings.TrimSpace(jsonOutput) == "" {
		return []SubzyResult{}, nil
	}
	
	// Clean up the JSON output
	jsonOutput = strings.TrimSpace(jsonOutput)
	
	// Try parsing as array first (multiple results)
	var results []SubzyResult
	if err := json.Unmarshal([]byte(jsonOutput), &results); err == nil {
		return results, nil
	}
	
	// Try parsing as SubzyResponse (wrapper format) before single result
	var response SubzyResponse
	if err := json.Unmarshal([]byte(jsonOutput), &response); err == nil {
		if len(response.Results) > 0 {
			return response.Results, nil
		}
		// Only return empty if this actually looks like a wrapper (has "results" or "summary" field)
		if strings.Contains(jsonOutput, `"results"`) || strings.Contains(jsonOutput, `"summary"`) {
			return []SubzyResult{}, nil
		}
	}
	
	// Try parsing as single result
	var singleResult SubzyResult
	if err := json.Unmarshal([]byte(jsonOutput), &singleResult); err == nil {
		// Validate that this is actually a valid SubzyResult and not a wrapper object
		if singleResult.Subdomain != "" {
			return []SubzyResult{singleResult}, nil
		}
	}
	
	// If all else fails, try to extract JSON objects from lines
	return parseLineDelimitedJSON(jsonOutput)
}

// parseLineDelimitedJSON handles cases where subzy outputs line-delimited JSON
func parseLineDelimitedJSON(output string) ([]SubzyResult, error) {
	var results []SubzyResult
	lines := strings.Split(output, "\n")
	
	for _, line := range lines {
		line = strings.TrimSpace(line)
		if line == "" || !strings.HasPrefix(line, "{") {
			continue
		}
		
		var result SubzyResult
		if err := json.Unmarshal([]byte(line), &result); err == nil {
			results = append(results, result)
		}
	}
	
	if len(results) == 0 {
		return nil, fmt.Errorf("no valid JSON objects found in output")
	}
	
	return results, nil
}

// IsVulnerable checks if the result indicates a vulnerability
func (r *SubzyResult) IsVulnerable() bool {
	return r.Vulnerable
}

// IsVerified checks if the vulnerability has been verified
func (r *SubzyResult) IsVerified() bool {
	return r.Verified
}

// GetSeverityLevel returns a severity assessment based on the result
func (r *SubzyResult) GetSeverityLevel() string {
	if r.Vulnerable && r.Verified {
		return "critical"
	} else if r.Vulnerable {
		return "high"
	} else if r.StatusCode == 404 || r.StatusCode == 403 {
		return "medium"
	}
	return "info"
}

// GetConfidenceScore calculates a confidence score for the result
func (r *SubzyResult) GetConfidenceScore() float64 {
	confidence := 0.5 // Base confidence
	
	if r.Verified {
		confidence += 0.4 // Verified results get high confidence boost
	} else if r.Vulnerable {
		confidence += 0.2 // Unverified but marked vulnerable
	}
	
	if r.Service != "" && r.Service != "Unknown" {
		confidence += 0.1 // Known service adds confidence
	}
	
	if r.StatusCode == 404 || r.StatusCode == 403 {
		confidence += 0.1 // Common takeover indicators
	}
	
	if r.Fingerprint != "" {
		confidence += 0.1 // Fingerprint detection
	}
	
	// Cap at 0.95 to leave room for manual verification
	if confidence > 0.95 {
		confidence = 0.95
	}
	
	return confidence
}

// GetServiceProvider extracts the service provider from the service field
func (r *SubzyResult) GetServiceProvider() string {
	service := strings.ToLower(r.Service)
	
	// Map known services to providers
	providers := map[string]string{
		"s3":                    "Amazon Web Services",
		"github":                "GitHub Pages",
		"githubpages":           "GitHub Pages",
		"heroku":                "Heroku",
		"herokuapp":             "Heroku",
		"wordpress":             "WordPress.com",
		"tumblr":                "Tumblr",
		"shopify":               "Shopify",
		"desk":                  "Salesforce Desk.com",
		"teamwork":              "Teamwork",
		"helpjuice":             "HelpJuice",
		"helpscout":             "Help Scout",
		"cargo":                 "Cargo Collective",
		"statuspage":            "Atlassian StatusPage",
		"uservoice":             "UserVoice",
		"surge":                 "Surge.sh",
		"bitbucket":             "Atlassian Bitbucket",
		"zendesk":               "Zendesk",
		"azure":                 "Microsoft Azure",
		"azurewebsites":         "Microsoft Azure",
		"webflow":               "Webflow",
		"intercom":              "Intercom",
		"campaignmonitor":       "Campaign Monitor",
		"tictail":               "Tictail",
		"cloudfront":            "Amazon CloudFront",
		"fastly":                "Fastly",
		"smartling":             "Smartling",
		"acquia":                "Acquia",
		"pantheon":              "Pantheon",
		"mailgun":               "Mailgun",
		"pingdom":               "Pingdom",
		"netlify":               "Netlify",
		"vercel":                "Vercel",
		"firebase":              "Google Firebase",
	}
	
	for key, provider := range providers {
		if strings.Contains(service, key) {
			return provider
		}
	}
	
	return r.Service
}

// GetTakeoverRisk assesses the risk level of a potential takeover
func (r *SubzyResult) GetTakeoverRisk() string {
	if r.Vulnerable && r.Verified {
		return "immediate" // Confirmed exploitable
	} else if r.Vulnerable {
		return "high" // Likely exploitable but needs verification
	} else if r.StatusCode == 404 {
		return "medium" // Potential takeover indicator
	} else if r.StatusCode == 403 {
		return "low" // Possible misconfiguration
	}
	return "minimal"
}

// GetRecommendedActions returns recommended actions based on the result
func (r *SubzyResult) GetRecommendedActions() []string {
	var actions []string
	
	if r.Vulnerable && r.Verified {
		actions = append(actions, []string{
			"URGENT: Remove the dangling DNS record immediately",
			"Check if the service resource has been claimed by an attacker",
			"Monitor for any malicious content on the subdomain",
			"Implement DNS monitoring to prevent future occurrences",
			"Audit all other subdomains for similar issues",
		}...)
	} else if r.Vulnerable {
		actions = append(actions, []string{
			"Verify the vulnerability manually",
			"Attempt to claim the service resource to confirm exploitability", 
			"If confirmed, remove the dangling DNS record",
			"Implement monitoring for this subdomain",
		}...)
	} else if r.StatusCode == 404 || r.StatusCode == 403 {
		actions = append(actions, []string{
			"Investigate the subdomain configuration",
			"Verify if the service resource exists and is properly configured",
			"Consider removing unused DNS records",
			"Monitor for changes in subdomain status",
		}...)
	}
	
	return actions
}

// ToJSON converts the result back to JSON format
func (r *SubzyResult) ToJSON() (string, error) {
	data, err := json.MarshalIndent(r, "", "  ")
	if err != nil {
		return "", err
	}
	return string(data), nil
}

// ValidateResult performs basic validation on the SubzyResult
func (r *SubzyResult) ValidateResult() error {
	if r.Subdomain == "" {
		return fmt.Errorf("subdomain field is required")
	}
	
	if r.StatusCode < 0 || r.StatusCode > 999 {
		return fmt.Errorf("invalid status code: %d", r.StatusCode)
	}
	
	if r.Verified && !r.Vulnerable {
		return fmt.Errorf("result cannot be verified but not vulnerable")
	}
	
	return nil
}

// GetTimestamp returns the parsed timestamp or current time if not set
func (r *SubzyResult) GetTimestamp() time.Time {
	if r.Timestamp != "" {
		if t, err := time.Parse(time.RFC3339, r.Timestamp); err == nil {
			return t
		}
	}
	return time.Now()
}

// HasError checks if the result contains an error
func (r *SubzyResult) HasError() bool {
	return r.Error != ""
}

// GetErrorMessage returns the error message if present
func (r *SubzyResult) GetErrorMessage() string {
	return r.Error
}

// IsServiceKnown checks if the detected service is a known takeover target
func (r *SubzyResult) IsServiceKnown() bool {
	knownServices := []string{
		"s3", "github", "githubpages", "heroku", "herokuapp", "wordpress",
		"tumblr", "shopify", "desk", "teamwork", "helpjuice", "helpscout",
		"cargo", "statuspage", "uservoice", "surge", "bitbucket", "zendesk",
		"azure", "azurewebsites", "webflow", "intercom", "campaignmonitor",
		"tictail", "cloudfront", "fastly", "netlify", "vercel", "firebase",
	}
	
	serviceLower := strings.ToLower(r.Service)
	for _, known := range knownServices {
		if strings.Contains(serviceLower, known) {
			return true
		}
	}
	
	return false
}
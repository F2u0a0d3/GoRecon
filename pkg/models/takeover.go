package models

import (
	"strings"
	"time"
)

// SubdomainTakeoverResult represents a structured result from subdomain takeover detection
type SubdomainTakeoverResult struct {
	// Core identification
	Subdomain   string    `json:"subdomain" validate:"required,fqdn"`
	Service     string    `json:"service" validate:"required"`
	Provider    string    `json:"provider,omitempty"`
	StatusCode  int       `json:"status_code" validate:"min=0,max=999"`
	Timestamp   time.Time `json:"timestamp" validate:"required"`

	// Vulnerability assessment
	Vulnerable  bool      `json:"vulnerable"`
	Verified    bool      `json:"verified"`
	Confidence  float64   `json:"confidence" validate:"min=0,max=1"`
	RiskLevel   string    `json:"risk_level" validate:"oneof=minimal low medium high immediate"`
	
	// Detection evidence
	Fingerprint string    `json:"fingerprint,omitempty"`
	Response    string    `json:"response,omitempty"`
	ErrorMsg    string    `json:"error_message,omitempty"`
	
	// Technical details
	DNSRecords  []DNSRecord `json:"dns_records,omitempty"`
	HTTPHeaders map[string]string `json:"http_headers,omitempty"`
	
	// Security analysis
	AttackScenario   string   `json:"attack_scenario,omitempty"`
	BusinessImpact   string   `json:"business_impact,omitempty"`
	RecommendedActions []string `json:"recommended_actions,omitempty"`
	
	// Metadata
	ScanDuration time.Duration `json:"scan_duration,omitempty"`
	Tool         string        `json:"tool" validate:"required"`
	PluginVersion string       `json:"plugin_version,omitempty"`
}

// DNSRecord represents DNS resolution information
type DNSRecord struct {
	Type   string `json:"type" validate:"oneof=A AAAA CNAME MX TXT SOA NS PTR"`
	Name   string `json:"name" validate:"required"`
	Value  string `json:"value" validate:"required"`
	TTL    int    `json:"ttl,omitempty"`
}

// TakeoverVulnerabilityDetails provides detailed vulnerability information
type TakeoverVulnerabilityDetails struct {
	// Classification
	CVEReferences    []string `json:"cve_references,omitempty"`
	OWASP_Category   string   `json:"owasp_category,omitempty"`
	CWE_ID           string   `json:"cwe_id,omitempty"`
	
	// Exploitation details
	ExploitComplexity string   `json:"exploit_complexity" validate:"oneof=low medium high"`
	RequiredSkills    []string `json:"required_skills,omitempty"`
	ExploitMethods    []string `json:"exploit_methods,omitempty"`
	
	// Impact assessment
	DataExfiltrationRisk    bool     `json:"data_exfiltration_risk"`
	PhishingPotential       bool     `json:"phishing_potential"`
	CSPBypassPossible       bool     `json:"csp_bypass_possible"`
	SessionHijackingRisk    bool     `json:"session_hijacking_risk"`
	BrandReputationImpact   string   `json:"brand_reputation_impact" validate:"oneof=none low medium high critical"`
	
	// Mitigation
	ImmediateActions       []string `json:"immediate_actions,omitempty"`
	LongTermMitigations    []string `json:"long_term_mitigations,omitempty"`
	MonitoringRequirements []string `json:"monitoring_requirements,omitempty"`
}

// ServiceFingerprint contains service-specific detection patterns
type ServiceFingerprint struct {
	ServiceName     string            `json:"service_name"`
	Provider        string            `json:"provider"`
	DetectionRule   string            `json:"detection_rule"`
	FingerprintType string            `json:"fingerprint_type" validate:"oneof=http_response dns_error certificate_error"`
	Patterns        []string          `json:"patterns"`
	Confidence      float64           `json:"confidence" validate:"min=0,max=1"`
	Metadata        map[string]string `json:"metadata,omitempty"`
}

// TakeoverScanSummary provides aggregated results
type TakeoverScanSummary struct {
	TotalSubdomains    int                          `json:"total_subdomains"`
	VulnerableCount    int                          `json:"vulnerable_count"`
	VerifiedCount      int                          `json:"verified_count"`
	ServiceBreakdown   map[string]int               `json:"service_breakdown"`
	SeverityBreakdown  map[string]int               `json:"severity_breakdown"`
	ScanDuration       time.Duration                `json:"scan_duration"`
	Results            []SubdomainTakeoverResult    `json:"results"`
	Errors             []string                     `json:"errors,omitempty"`
	RecommendedActions []string                     `json:"recommended_actions"`
}

// Risk assessment methods
func (str *SubdomainTakeoverResult) GetRiskScore() float64 {
	baseScore := 5.0 // Medium risk baseline
	
	if str.Vulnerable {
		baseScore += 2.0 // High risk for vulnerabilities
		
		if str.Verified {
			baseScore += 2.0 // Critical risk for verified vulnerabilities
		}
	}
	
	// Service-specific risk adjustments
	switch str.Service {
	case "GitHub Pages", "Heroku", "Netlify":
		baseScore += 1.0 // Popular services higher risk
	case "Amazon S3", "Azure":
		baseScore += 1.5 // Cloud storage higher risk due to data exposure
	}
	
	// Status code adjustments
	if str.StatusCode == 404 {
		baseScore += 0.5 // 404 indicates likely takeover
	}
	
	// Cap at 10.0
	if baseScore > 10.0 {
		baseScore = 10.0
	}
	
	return baseScore
}

// GetSeverityLevel returns severity based on verification and risk factors
func (str *SubdomainTakeoverResult) GetSeverityLevel() string {
	if !str.Vulnerable {
		return SeverityInfo
	}
	
	if str.Verified {
		return SeverityCritical
	}
	
	// High confidence unverified vulnerabilities
	if str.Confidence >= 0.8 {
		return SeverityHigh
	}
	
	// Medium confidence potential vulnerabilities
	if str.Confidence >= 0.6 {
		return SeverityMedium
	}
	
	return SeverityLow
}

// IsExploitable determines if the vulnerability is immediately exploitable
func (str *SubdomainTakeoverResult) IsExploitable() bool {
	return str.Vulnerable && str.Verified && str.StatusCode == 404
}

// GetExploitationTimeframe estimates time needed for exploitation
func (str *SubdomainTakeoverResult) GetExploitationTimeframe() string {
	if !str.Vulnerable {
		return "not_exploitable"
	}
	
	if str.Verified && str.StatusCode == 404 {
		return "immediate" // Minutes to hours
	}
	
	if str.Vulnerable && str.Confidence >= 0.8 {
		return "short_term" // Hours to days
	}
	
	return "medium_term" // Days to weeks (requires verification)
}

// GetBusinessImpactLevel assesses business impact
func (str *SubdomainTakeoverResult) GetBusinessImpactLevel() string {
	if !str.Vulnerable {
		return "none"
	}
	
	// Domain reputation factors
	if str.IsSubdomainOfMainDomain() {
		if str.Verified {
			return "critical" // Main domain subdomain verified vulnerable
		}
		return "high" // Main domain subdomain potentially vulnerable
	}
	
	// Service-specific impact
	switch str.Service {
	case "Amazon S3", "Azure":
		return "high" // Potential data exposure
	case "GitHub Pages", "Netlify":
		return "medium" // Brand reputation impact
	default:
		return "low"
	}
}

// Helper method to check if subdomain is directly under main domain
func (str *SubdomainTakeoverResult) IsSubdomainOfMainDomain() bool {
	// Simple heuristic: if subdomain has only one dot more than expected
	// e.g., "api.example.com" vs "test.staging.example.com"
	parts := len(strings.Split(str.Subdomain, "."))
	return parts <= 3 // domain.tld = 2, subdomain.domain.tld = 3
}

// GetCVSSVector generates CVSS 3.1 vector for verified vulnerabilities
func (str *SubdomainTakeoverResult) GetCVSSVector() string {
	if !str.Verified || !str.Vulnerable {
		return ""
	}
	
	// CVSS 3.1 for subdomain takeover
	// AV:N (Network) - accessible over network
	// AC:L (Low) - no special access conditions required
	// PR:N (None) - no privileges required
	// UI:N (None) - no user interaction required  
	// S:C (Changed) - scope changes (impacts other resources)
	// C:H (High) - total loss of confidentiality
	// I:H (High) - total loss of integrity
	// A:N (None) - no availability impact
	
	return "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:N"
}

// GetRecommendations returns prioritized recommendations
func (str *SubdomainTakeoverResult) GetRecommendations() []string {
	if !str.Vulnerable {
		return []string{
			"No immediate action required",
			"Continue regular subdomain monitoring",
		}
	}
	
	recommendations := []string{}
	
	if str.Verified {
		recommendations = append(recommendations,
			"🚨 CRITICAL: Remove dangling DNS record immediately",
			"🔍 Investigate if the service resource has been claimed by an attacker",
			"📧 Notify security team and domain administrators",
			"🔒 Implement emergency DNS monitoring",
		)
	}
	
	recommendations = append(recommendations,
		"📋 Audit all DNS records for similar issues",
		"⚡ Implement automated DNS monitoring and alerting",
		"🛡️ Consider using CAA DNS records to restrict certificate issuance",
		"📊 Monitor certificate transparency logs for unauthorized certificates",
		"🔄 Implement subdomain validation in CI/CD pipelines",
	)
	
	return recommendations
}
package models

import (
	"time"
)

// PluginResult represents an enhanced finding from a plugin
type PluginResult struct {
	// Core fields
	ID          string                 `json:"id" validate:"required,uuid4"`
	Plugin      string                 `json:"plugin" validate:"required,min=2,max=50"`
	Tool        string                 `json:"tool" validate:"required,min=2,max=50"`
	Category    string                 `json:"category" validate:"required,oneof=takeover cloud wayback portscan httpprobe js vuln github param crawl brokenlink"`
	Target      string                 `json:"target" validate:"required,url"`
	Timestamp   time.Time              `json:"timestamp" validate:"required"`

	// Enhanced severity and scoring
	Severity    string                 `json:"severity" validate:"required,oneof=info low medium high critical error"`
	CVSS        *CVSSScore             `json:"cvss,omitempty"`
	RiskScore   float64                `json:"risk_score" validate:"min=0,max=10"`

	// Content
	Title       string                 `json:"title" validate:"required,min=5,max=200"`
	Description string                 `json:"description" validate:"required,min=10,max=1000"`
	Evidence    Evidence               `json:"evidence" validate:"required"`
	Data        map[string]interface{} `json:"data" validate:"required"`

	// Intelligence correlation
	Correlations []Correlation         `json:"correlations,omitempty"`
	AttackVector *AttackVector         `json:"attack_vector,omitempty"`
	TTP          *MITRETechnique       `json:"ttp,omitempty"`

	// Metadata
	References  []string               `json:"references" validate:"dive,url"`
	Raw         interface{}            `json:"raw,omitempty"`
	Confidence  float64                `json:"confidence" validate:"min=0,max=1"`
	Tags        []string               `json:"tags,omitempty"`
	False       bool                   `json:"false_positive"`
	Verified    bool                   `json:"verified"`
}

// Evidence contains proof of the finding
type Evidence struct {
	Type        string                 `json:"type"` // http_response, file_content, command_output
	Content     string                 `json:"content"`
	URL         string                 `json:"url,omitempty"`
	StatusCode  int                    `json:"status_code,omitempty"`
	Headers     map[string]string      `json:"headers,omitempty"`
	Body        string                 `json:"body,omitempty"`
	Screenshot  string                 `json:"screenshot,omitempty"` // base64 encoded
	Metadata    map[string]interface{} `json:"metadata,omitempty"`
}

// CVSSScore for vulnerability scoring
type CVSSScore struct {
	Version              string  `json:"version"`
	BaseScore            float64 `json:"base_score"`
	TemporalScore        float64 `json:"temporal_score"`
	EnvironmentalScore   float64 `json:"environmental_score"`
	Vector               string  `json:"vector"`
	AttackVector         string  `json:"attack_vector"`
	AttackComplexity     string  `json:"attack_complexity"`
	PrivilegesRequired   string  `json:"privileges_required"`
	UserInteraction      string  `json:"user_interaction"`
	Scope                string  `json:"scope"`
	ConfidentialityImpact string `json:"confidentiality_impact"`
	IntegrityImpact      string  `json:"integrity_impact"`
	AvailabilityImpact   string  `json:"availability_impact"`
}

// Correlation represents a relationship between findings
type Correlation struct {
	ID          string                 `json:"id"`
	Type        string                 `json:"type"` // temporal, spatial, behavioral, causal
	RelatedID   string                 `json:"related_id"`
	Strength    float64                `json:"strength"` // 0-1
	Description string                 `json:"description"`
	Evidence    []string               `json:"evidence"`
	Metadata    map[string]interface{} `json:"metadata,omitempty"`
}

// AttackVector for attack path modeling
type AttackVector struct {
	Entry           string   `json:"entry"`
	Technique       string   `json:"technique"`
	Likelihood      float64  `json:"likelihood"`
	RequiredAccess  string   `json:"required_access"`
	NextSteps       []string `json:"next_steps"`
	Mitigations     []string `json:"mitigations"`
	ExploitCode     string   `json:"exploit_code,omitempty"`
	Prerequisites   []string `json:"prerequisites"`
}

// MITRETechnique for ATT&CK framework mapping
type MITRETechnique struct {
	ID          string   `json:"id"`
	Name        string   `json:"name"`
	Tactic      string   `json:"tactic"`
	Description string   `json:"description"`
	References  []string `json:"references"`
	SubTechniques []string `json:"sub_techniques"`
	Platforms   []string `json:"platforms"`
	DataSources []string `json:"data_sources"`
}

// Discovery represents shared information between plugins
type Discovery struct {
	Type        string                 `json:"type"`  // subdomain, endpoint, technology, etc.
	Value       interface{}            `json:"value"`
	Source      string                 `json:"source"`
	Confidence  float64                `json:"confidence"`
	Timestamp   time.Time              `json:"timestamp"`
	Metadata    map[string]interface{} `json:"metadata"`
	TTL         time.Duration          `json:"ttl"`
}

// DiscoveryType constants for type safety
const (
	DiscoveryTypeSubdomain    = "subdomain"
	DiscoveryTypeEndpoint     = "endpoint"
	DiscoveryTypeTechnology   = "technology"
	DiscoveryTypeCredential   = "credential"
	DiscoveryTypeVulnerability = "vulnerability"
	DiscoveryTypeFile         = "file"
	DiscoveryTypeService      = "service"
	DiscoveryTypeParameter    = "parameter"
	DiscoveryTypeSecret       = "secret"
	DiscoveryTypeEmail        = "email"
)

// SeverityLevel constants
const (
	SeverityInfo     = "info"
	SeverityLow      = "low"
	SeverityMedium   = "medium"
	SeverityHigh     = "high"
	SeverityCritical = "critical"
	SeverityError    = "error"
)

// CategoryType constants
const (
	CategoryTakeover   = "takeover"
	CategoryCloud      = "cloud"
	CategoryWayback    = "wayback"
	CategoryPortscan   = "portscan"
	CategoryHTTPProbe  = "httpprobe"
	CategoryJS         = "js"
	CategoryVuln       = "vuln"
	CategoryGithub     = "github"
	CategoryParam      = "param"
	CategoryCrawl      = "crawl"
	CategoryBrokenLink = "brokenlink"
)

// GetSeverityWeight returns numeric weight for severity comparison
func (pr *PluginResult) GetSeverityWeight() int {
	switch pr.Severity {
	case SeverityError:
		return 0
	case SeverityInfo:
		return 1
	case SeverityLow:
		return 2
	case SeverityMedium:
		return 3
	case SeverityHigh:
		return 4
	case SeverityCritical:
		return 5
	default:
		return 0
	}
}

// HasCVSS returns true if the result has CVSS scoring
func (pr *PluginResult) HasCVSS() bool {
	return pr.CVSS != nil && pr.CVSS.BaseScore > 0
}

// IsHighRisk returns true if the finding is high risk
func (pr *PluginResult) IsHighRisk() bool {
	return pr.RiskScore >= 7.0 || pr.Severity == SeverityCritical || pr.Severity == SeverityHigh
}

// AddTag adds a tag to the result if not already present
func (pr *PluginResult) AddTag(tag string) {
	for _, existingTag := range pr.Tags {
		if existingTag == tag {
			return
		}
	}
	pr.Tags = append(pr.Tags, tag)
}

// HasTag checks if the result has a specific tag
func (pr *PluginResult) HasTag(tag string) bool {
	for _, existingTag := range pr.Tags {
		if existingTag == tag {
			return true
		}
	}
	return false
}

// AddCorrelation adds a correlation if not already present
func (pr *PluginResult) AddCorrelation(correlation Correlation) {
	for _, existing := range pr.Correlations {
		if existing.ID == correlation.ID {
			return
		}
	}
	pr.Correlations = append(pr.Correlations, correlation)
}

// GetCorrelationsByType returns correlations of a specific type
func (pr *PluginResult) GetCorrelationsByType(correlationType string) []Correlation {
	var results []Correlation
	for _, correlation := range pr.Correlations {
		if correlation.Type == correlationType {
			results = append(results, correlation)
		}
	}
	return results
}
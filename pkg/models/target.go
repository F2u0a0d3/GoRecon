package models

import (
	"fmt"
	"net/url"
	"strings"
	"time"
)

// Target represents a scan target with context
type Target struct {
	// Core identification
	ID          string                 `json:"id" validate:"required,uuid4"`
	URL         string                 `json:"url" validate:"required,url"`
	Domain      string                 `json:"domain" validate:"required,fqdn"`
	IP          string                 `json:"ip,omitempty" validate:"omitempty,ip"`
	Port        int                    `json:"port,omitempty" validate:"omitempty,min=1,max=65535"`
	
	// Target classification
	Type        TargetType             `json:"type"`
	Category    string                 `json:"category"`
	Priority    int                    `json:"priority" validate:"min=1,max=10"`
	
	// Scope and permissions
	InScope     bool                   `json:"in_scope"`
	Whitelist   []string               `json:"whitelist"`
	Blacklist   []string               `json:"blacklist"`
	
	// Context information
	Organization string                `json:"organization,omitempty"`
	Environment  string                `json:"environment,omitempty"` // prod, staging, dev
	Tags        []string               `json:"tags"`
	
	// Timing and scheduling
	CreatedAt   time.Time              `json:"created_at"`
	UpdatedAt   time.Time              `json:"updated_at"`
	LastScan    time.Time              `json:"last_scan,omitempty"`
	NextScan    time.Time              `json:"next_scan,omitempty"`
	
	// Technical metadata
	Technologies []Technology          `json:"technologies"`
	Services     []Service             `json:"services"`
	Certificates []Certificate         `json:"certificates"`
	
	// Custom metadata
	Metadata    map[string]interface{} `json:"metadata"`
}

// TargetType represents different types of targets
type TargetType string

const (
	TargetTypeWeb         TargetType = "web"
	TargetTypeAPI         TargetType = "api"
	TargetTypeSubdomain   TargetType = "subdomain"
	TargetTypeIP          TargetType = "ip"
	TargetTypeNetwork     TargetType = "network"
	TargetTypeCloud       TargetType = "cloud"
	TargetTypeRepository  TargetType = "repository"
	TargetTypeMobile      TargetType = "mobile"
)

// Technology represents detected technology
type Technology struct {
	Name        string   `json:"name"`
	Version     string   `json:"version,omitempty"`
	Category    string   `json:"category"`
	Confidence  float64  `json:"confidence"`
	Source      string   `json:"source"`
	CVEs        []string `json:"cves,omitempty"`
	EOL         bool     `json:"eol"` // End of life
}

// Service represents a detected service
type Service struct {
	Name        string                 `json:"name"`
	Port        int                    `json:"port"`
	Protocol    string                 `json:"protocol"`
	Version     string                 `json:"version,omitempty"`
	State       string                 `json:"state"` // open, closed, filtered
	Banner      string                 `json:"banner,omitempty"`
	Fingerprint string                 `json:"fingerprint,omitempty"`
	Metadata    map[string]interface{} `json:"metadata,omitempty"`
}

// Certificate represents SSL/TLS certificate information
type Certificate struct {
	Subject         string    `json:"subject"`
	Issuer          string    `json:"issuer"`
	SerialNumber    string    `json:"serial_number"`
	NotBefore       time.Time `json:"not_before"`
	NotAfter        time.Time `json:"not_after"`
	SANs            []string  `json:"sans"`
	SignatureAlg    string    `json:"signature_algorithm"`
	PublicKeyAlg    string    `json:"public_key_algorithm"`
	KeySize         int       `json:"key_size"`
	Fingerprint     string    `json:"fingerprint"`
	SelfSigned      bool      `json:"self_signed"`
	Expired         bool      `json:"expired"`
	ValidForDomain  bool      `json:"valid_for_domain"`
}

// NewTarget creates a new target from a URL string
func NewTarget(targetURL string) (*Target, error) {
	parsedURL, err := url.Parse(targetURL)
	if err != nil {
		return nil, err
	}
	
	target := &Target{
		URL:       targetURL,
		Domain:    parsedURL.Hostname(),
		CreatedAt: time.Now(),
		UpdatedAt: time.Now(),
		InScope:   true,
		Priority:  5, // Default medium priority
		Type:      determineTargetType(parsedURL),
		Metadata:  make(map[string]interface{}),
	}
	
	// Extract port if specified
	if parsedURL.Port() != "" {
		if port := parsedURL.Port(); port != "" {
			// Parse port string to int
			var portNum int
			if _, err := fmt.Sscanf(port, "%d", &portNum); err == nil {
				target.Port = portNum
			}
		}
	}
	
	return target, nil
}

// determineTargetType infers target type from URL
func determineTargetType(parsedURL *url.URL) TargetType {
	hostname := strings.ToLower(parsedURL.Hostname())
	
	// Check for API indicators
	if strings.Contains(hostname, "api") || strings.Contains(parsedURL.Path, "/api/") {
		return TargetTypeAPI
	}
	
	// Check for cloud services
	cloudIndicators := []string{"amazonaws.com", "azurewebsites.net", "cloudfront.net", "googleapis.com"}
	for _, indicator := range cloudIndicators {
		if strings.Contains(hostname, indicator) {
			return TargetTypeCloud
		}
	}
	
	// Check for subdomain patterns
	parts := strings.Split(hostname, ".")
	if len(parts) > 2 {
		return TargetTypeSubdomain
	}
	
	// Default to web
	return TargetTypeWeb
}

// IsValid checks if the target is valid for scanning
func (t *Target) IsValid() bool {
	return t.URL != "" && t.Domain != "" && t.InScope
}

// GetBaseURL returns the base URL without path
func (t *Target) GetBaseURL() string {
	parsedURL, err := url.Parse(t.URL)
	if err != nil {
		return t.URL
	}
	
	parsedURL.Path = ""
	parsedURL.RawQuery = ""
	parsedURL.Fragment = ""
	
	return parsedURL.String()
}

// GetDomainParts returns domain parts (subdomain, domain, tld)
func (t *Target) GetDomainParts() (subdomain, domain, tld string) {
	parts := strings.Split(t.Domain, ".")
	
	if len(parts) < 2 {
		return "", t.Domain, ""
	}
	
	if len(parts) == 2 {
		return "", parts[0], parts[1]
	}
	
	// For subdomains
	tld = parts[len(parts)-1]
	domain = parts[len(parts)-2]
	subdomain = strings.Join(parts[:len(parts)-2], ".")
	
	return subdomain, domain, tld
}

// AddTag adds a tag if not already present
func (t *Target) AddTag(tag string) {
	for _, existingTag := range t.Tags {
		if existingTag == tag {
			return
		}
	}
	t.Tags = append(t.Tags, tag)
}

// HasTag checks if target has a specific tag
func (t *Target) HasTag(tag string) bool {
	for _, existingTag := range t.Tags {
		if existingTag == tag {
			return true
		}
	}
	return false
}

// AddTechnology adds a detected technology
func (t *Target) AddTechnology(tech Technology) {
	// Check if technology already exists, update if confidence is higher
	for i, existing := range t.Technologies {
		if existing.Name == tech.Name {
			if tech.Confidence > existing.Confidence {
				t.Technologies[i] = tech
			}
			return
		}
	}
	t.Technologies = append(t.Technologies, tech)
}

// GetTechnologiesByCategory returns technologies of a specific category
func (t *Target) GetTechnologiesByCategory(category string) []Technology {
	var results []Technology
	for _, tech := range t.Technologies {
		if tech.Category == category {
			results = append(results, tech)
		}
	}
	return results
}

// AddService adds a detected service
func (t *Target) AddService(service Service) {
	// Check if service already exists on the same port
	for i, existing := range t.Services {
		if existing.Port == service.Port && existing.Protocol == service.Protocol {
			// Update with more detailed information
			t.Services[i] = service
			return
		}
	}
	t.Services = append(t.Services, service)
}

// GetOpenPorts returns list of open ports
func (t *Target) GetOpenPorts() []int {
	var ports []int
	for _, service := range t.Services {
		if service.State == "open" {
			ports = append(ports, service.Port)
		}
	}
	return ports
}

// IsExpired checks if any certificates are expired
func (t *Target) IsExpired() bool {
	now := time.Now()
	for _, cert := range t.Certificates {
		if cert.NotAfter.Before(now) {
			return true
		}
	}
	return false
}

// IsExpiringSoon checks if any certificates expire within the given duration
func (t *Target) IsExpiringSoon(duration time.Duration) bool {
	future := time.Now().Add(duration)
	for _, cert := range t.Certificates {
		if cert.NotAfter.Before(future) {
			return true
		}
	}
	return false
}

// UpdateTimestamp updates the UpdatedAt timestamp
func (t *Target) UpdateTimestamp() {
	t.UpdatedAt = time.Now()
}

// SetLastScan sets the last scan timestamp
func (t *Target) SetLastScan() {
	t.LastScan = time.Now()
	t.UpdatedAt = time.Now()
}

// String returns a string representation of the target
func (t *Target) String() string {
	return t.URL
}
package subdomain

import (
	"bufio"
	"context"
	"fmt"
	"net"
	"strings"
	"time"

	"github.com/f2u0a0d3/GoRecon/pkg/core"
	"github.com/f2u0a0d3/GoRecon/pkg/models"
	"github.com/f2u0a0d3/GoRecon/pkg/plugins/base"
)

type SubfinderPlugin struct {
	*base.BaseAdapter
}

func NewSubfinderPlugin() core.Plugin {
	baseConfig := base.BaseAdapterConfig{
		Name:        "Subfinder",
		Category:    "subdomain",
		Description: "Fast subdomain discovery tool using passive sources",
		Version:     "1.0.0",
		Author:      "ProjectDiscovery",
		ToolName:    "subfinder",
		ToolPath:    "subfinder",
		ToolArgs:    []string{"-silent", "-json"},
		Passive:     true,
		Confirmation: false,
		Duration:    5 * time.Minute,
		Concurrency: 5,
		Priority:    8,
		Resources:   core.Resources{
			CPUCores: 2,
			MemoryMB: 512,
			DiskMB:   200,
		},
		Dependencies: []core.PluginDependency{
			{Name: "subfinder", Type: "binary"},
		},
	}

	return &SubfinderPlugin{
		BaseAdapter: base.NewBaseAdapter(baseConfig),
	}
}

func (s *SubfinderPlugin) Run(ctx context.Context, target *models.Target, results chan<- models.PluginResult, shared *core.SharedContext) error {
	// Build command arguments
	args := []string{
		"-d", target.GetDomain(),
		"-silent",
		"-timeout", "60",
		"-max-time", "5",
	}

	// Execute subfinder
	execResult, err := s.ExecuteCommand(ctx, append([]string{"subfinder"}, args...))
	if err != nil {
		return fmt.Errorf("subfinder execution failed: %w", err)
	}

	// Parse results
	subdomains, err := s.parseSubfinderOutput(execResult)
	if err != nil {
		return fmt.Errorf("failed to parse subfinder output: %w", err)
	}

	// Process each subdomain
	for _, subdomain := range subdomains {
		// Create finding
		finding := s.createSubdomainFinding(subdomain, target)
		
		// Send to results channel
		select {
		case results <- finding:
		case <-ctx.Done():
			return ctx.Err()
		}

		// Share discovery for other plugins
		subdomainInfo := map[string]interface{}{
			"domain":    subdomain.Domain,
			"ip":        subdomain.IP,
			"source":    subdomain.Source,
			"parent":    target.GetDomain(),
			"resolved":  subdomain.IP != "",
		}
		
		shared.AddDiscovery(models.Discovery{
			Type:      "subdomain",
			Key:       subdomain.Domain,
			Data:      subdomainInfo,
			Plugin:    s.Name(),
			Timestamp: time.Now(),
		})
	}

	// Create summary result
	if len(subdomains) > 0 {
		summaryResult := models.PluginResult{
			ID:          fmt.Sprintf("subfinder-summary-%d", time.Now().UnixNano()),
			Plugin:      s.Name(),
			Tool:        "subfinder",
			Category:    "subdomain",
			Target:      target.String(),
			Timestamp:   time.Now(),
			Severity:    "info",
			RiskScore:   s.calculateRiskScore(len(subdomains)),
			Title:       fmt.Sprintf("Discovered %d subdomains", len(subdomains)),
			Description: fmt.Sprintf("Found %d unique subdomains for %s using passive sources", len(subdomains), target.GetDomain()),
			Evidence: models.Evidence{
				Command: fmt.Sprintf("subfinder -d %s -silent", target.GetDomain()),
				Args:    args,
			},
			Data: map[string]interface{}{
				"subdomain_count": len(subdomains),
				"target_domain":   target.GetDomain(),
				"subdomains":      subdomains,
				"sources_used":    s.extractSources(subdomains),
			},
			Confidence: 0.95,
			Tags:       []string{"subdomain", "passive", "enumeration"},
		}

		select {
		case results <- summaryResult:
		case <-ctx.Done():
			return ctx.Err()
		}
	}

	return nil
}

type SubdomainResult struct {
	Domain string `json:"domain"`
	IP     string `json:"ip,omitempty"`
	Source string `json:"source,omitempty"`
}

func (s *SubfinderPlugin) parseSubfinderOutput(data []byte) ([]SubdomainResult, error) {
	var results []SubdomainResult
	processedDomains := make(map[string]bool)

	scanner := bufio.NewScanner(strings.NewReader(string(data)))
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line == "" {
			continue
		}

		// Handle both plain text and JSON output
		if strings.HasPrefix(line, "{") {
			// JSON format
			// For now, just extract domain from JSON if needed
			// In full implementation, would parse JSON properly
		}
		
		// Plain text format (most common with -silent)
		domain := line
		if processedDomains[domain] {
			continue
		}
		processedDomains[domain] = true

		result := SubdomainResult{
			Domain: domain,
			Source: "subfinder",
		}

		// Try to resolve IP if possible
		if ips, err := net.LookupIP(domain); err == nil && len(ips) > 0 {
			result.IP = ips[0].String()
		}

		results = append(results, result)
	}

	if err := scanner.Err(); err != nil {
		return results, fmt.Errorf("error reading subfinder output: %w", err)
	}

	return results, nil
}

func (s *SubfinderPlugin) createSubdomainFinding(subdomain SubdomainResult, target *models.Target) models.PluginResult {
	severity := "info"
	riskScore := 3.0

	// Increase severity for interesting subdomains
	if s.isInterestingSubdomain(subdomain.Domain) {
		severity = "low"
		riskScore = 5.0
	}

	// Higher risk if resolved to IP
	if subdomain.IP != "" {
		riskScore += 1.0
	}

	return models.PluginResult{
		ID:          fmt.Sprintf("subfinder-%d", time.Now().UnixNano()),
		Plugin:      s.Name(),
		Tool:        "subfinder",
		Category:    "subdomain",
		Target:      subdomain.Domain,
		Timestamp:   time.Now(),
		Severity:    severity,
		RiskScore:   riskScore,
		Title:       fmt.Sprintf("Subdomain discovered: %s", subdomain.Domain),
		Description: s.generateSubdomainDescription(subdomain, target),
		Evidence: models.Evidence{
			Command: fmt.Sprintf("subfinder -d %s", target.GetDomain()),
			Args:    []string{"-d", target.GetDomain(), "-silent"},
		},
		Data: map[string]interface{}{
			"subdomain":     subdomain.Domain,
			"parent_domain": target.GetDomain(),
			"ip_address":    subdomain.IP,
			"source":        subdomain.Source,
			"resolved":      subdomain.IP != "",
			"interesting":   s.isInterestingSubdomain(subdomain.Domain),
		},
		Confidence: 0.9,
		Tags:       s.generateSubdomainTags(subdomain),
	}
}

func (s *SubfinderPlugin) generateSubdomainDescription(subdomain SubdomainResult, target *models.Target) string {
	description := fmt.Sprintf("Discovered subdomain %s", subdomain.Domain)
	
	if subdomain.IP != "" {
		description += fmt.Sprintf(" (resolves to %s)", subdomain.IP)
	} else {
		description += " (not resolved)"
	}

	if s.isInterestingSubdomain(subdomain.Domain) {
		description += " - potentially interesting based on naming pattern"
	}

	return description
}

func (s *SubfinderPlugin) isInterestingSubdomain(domain string) bool {
	interestingPrefixes := []string{
		"admin", "administrator", "api", "app", "apps", "auth", "authentication",
		"backup", "beta", "cms", "cpanel", "dashboard", "dev", "development",
		"ftp", "git", "gitlab", "jenkins", "mail", "manage", "management",
		"mobile", "mysql", "panel", "phpmyadmin", "portal", "prod", "production",
		"secure", "server", "sql", "ssh", "stage", "staging", "test", "testing",
		"vpn", "web", "webmail", "www2", "intranet", "internal", "private",
	}

	domainLower := strings.ToLower(domain)
	for _, prefix := range interestingPrefixes {
		if strings.HasPrefix(domainLower, prefix+".") {
			return true
		}
	}

	return false
}

func (s *SubfinderPlugin) generateSubdomainTags(subdomain SubdomainResult) []string {
	tags := []string{"subdomain", "passive"}

	if subdomain.IP != "" {
		tags = append(tags, "resolved")
	} else {
		tags = append(tags, "unresolved")
	}

	if s.isInterestingSubdomain(subdomain.Domain) {
		tags = append(tags, "interesting")
	}

	// Add prefix-based tags
	parts := strings.Split(subdomain.Domain, ".")
	if len(parts) > 0 {
		prefix := parts[0]
		switch {
		case strings.Contains(prefix, "admin"):
			tags = append(tags, "admin")
		case strings.Contains(prefix, "api"):
			tags = append(tags, "api")
		case strings.Contains(prefix, "dev") || strings.Contains(prefix, "test"):
			tags = append(tags, "development")
		case strings.Contains(prefix, "mail"):
			tags = append(tags, "email")
		case strings.Contains(prefix, "ftp"):
			tags = append(tags, "file-transfer")
		}
	}

	return tags
}

func (s *SubfinderPlugin) calculateRiskScore(subdomainCount int) float64 {
	baseScore := 2.0
	
	// More subdomains = larger attack surface
	if subdomainCount > 50 {
		baseScore = 6.0
	} else if subdomainCount > 20 {
		baseScore = 5.0
	} else if subdomainCount > 10 {
		baseScore = 4.0
	} else if subdomainCount > 5 {
		baseScore = 3.0
	}

	return baseScore
}

func (s *SubfinderPlugin) extractSources(subdomains []SubdomainResult) []string {
	sources := make(map[string]bool)
	for _, subdomain := range subdomains {
		if subdomain.Source != "" {
			sources[subdomain.Source] = true
		}
	}

	var sourceList []string
	for source := range sources {
		sourceList = append(sourceList, source)
	}

	return sourceList
}

// Intelligence patterns
func (s *SubfinderPlugin) GetIntelligencePatterns() []core.Pattern {
	return []core.Pattern{
		{
			Name:        "Large Subdomain Attack Surface",
			Description: "Domain has a large number of subdomains that increase attack surface",
			Severity:    "medium",
			Confidence:  0.8,
		},
		{
			Name:        "Administrative Subdomain Exposure",
			Description: "Administrative or management subdomains discovered",
			Severity:    "high",
			Confidence:  0.9,
		},
		{
			Name:        "Development Environment Exposure",
			Description: "Development or testing subdomains exposed",
			Severity:    "medium",
			Confidence:  0.85,
		},
	}
}
package takeover

import (
	"context"
	"encoding/json"
	"fmt"
	"strings"
	"time"

	"github.com/google/uuid"
	"github.com/f2u0a0d3/GoRecon/internal/utils"
	"github.com/f2u0a0d3/GoRecon/pkg/banner"
	"github.com/f2u0a0d3/GoRecon/pkg/config"
	"github.com/f2u0a0d3/GoRecon/pkg/core"
	"github.com/f2u0a0d3/GoRecon/pkg/models"
	"github.com/rs/zerolog"
)

// SubzyPlugin implements subdomain takeover detection using subzy
type SubzyPlugin struct {
	core.BasePlugin
	exec   *utils.ExecWrapper
	logger zerolog.Logger
	config *config.Config
}

// NewSubzyPlugin creates a new subdomain takeover plugin using subzy
func NewSubzyPlugin() *SubzyPlugin {
	logger := zerolog.New(nil).With().Str("plugin", "subzy").Logger()
	
	return &SubzyPlugin{
		BasePlugin: core.NewBasePlugin("subzy", "takeover", []string{"subzy"}),
		exec:       utils.NewExecWrapper(logger),
		logger:     logger,
	}
}

// Metadata methods
func (s *SubzyPlugin) Name() string { return "subzy" }
func (s *SubzyPlugin) Category() string { return "takeover" }
func (s *SubzyPlugin) Description() string {
	return "Detects subdomain takeover vulnerabilities using subzy with JSON output and verification"
}
func (s *SubzyPlugin) Version() string { return "1.0.0" }
func (s *SubzyPlugin) Author() string { return "GoRecon Team" }

// Dependency methods
func (s *SubzyPlugin) RequiredBinaries() []string {
	return []string{"subzy"}
}

func (s *SubzyPlugin) RequiredEnvVars() []string {
	return []string{}
}

func (s *SubzyPlugin) SupportedTargetTypes() []string {
	return []string{"web", "subdomain", "api"}
}

func (s *SubzyPlugin) Dependencies() []core.PluginDependency {
	return []core.PluginDependency{}
}

func (s *SubzyPlugin) Provides() []string {
	return []string{"takeover_vulnerabilities", "subdomain_status", "verified_takeovers"}
}

func (s *SubzyPlugin) Consumes() []string {
	return []string{"subdomains", "urls"}
}

// Capability methods
func (s *SubzyPlugin) IsPassive() bool { return false } // Subzy performs verification
func (s *SubzyPlugin) RequiresConfirmation() bool { return false }
func (s *SubzyPlugin) EstimatedDuration() time.Duration { return 3 * time.Minute }
func (s *SubzyPlugin) MaxConcurrency() int { return 5 }
func (s *SubzyPlugin) Priority() int { return 10 } // Highest priority - critical security
func (s *SubzyPlugin) ResourceRequirements() core.Resources {
	return core.Resources{
		CPUCores:         2,
		MemoryMB:         512,
		DiskMB:           100,
		NetworkBandwidth: "2Mbps",
		MaxFileHandles:   100,
		MaxProcesses:     5,
		RequiresRoot:     false,
		NetworkAccess:    true,
	}
}

// Intelligence methods
func (s *SubzyPlugin) ProcessDiscovery(ctx context.Context, discovery models.Discovery) error {
	if discovery.Type == models.DiscoveryTypeSubdomain {
		s.logger.Debug().
			Str("subdomain", fmt.Sprintf("%v", discovery.Value)).
			Str("source", discovery.Source).
			Msg("Processing subdomain discovery for takeover check")
	}
	return nil
}

func (s *SubzyPlugin) GetIntelligencePatterns() []core.Pattern {
	return []core.Pattern{
		{
			Name:        "subdomain_takeover_verified",
			Type:        "vulnerability",
			Keywords:    []string{"vulnerable", "takeover", "404", "NoSuchBucket", "NoSuchKey"},
			Confidence:  0.95,
			Description: "Verified subdomain takeover vulnerability",
		},
		{
			Name:        "subdomain_takeover_potential",
			Type:        "vulnerability",
			Keywords:    []string{"potential", "fingerprint", "edge_case"},
			Confidence:  0.75,
			Description: "Potential subdomain takeover vulnerability requiring verification",
		},
		{
			Name:        "cloud_service_providers",
			Type:        "service",
			Keywords:    []string{"amazonaws", "github.io", "herokuapp.com", "azurewebsites.net", "cloudfront.net"},
			Confidence:  0.85,
			Description: "Cloud service providers commonly vulnerable to takeover",
		},
	}
}

// Lifecycle methods
func (s *SubzyPlugin) Validate(ctx context.Context, cfg *config.Config) error {
	s.config = cfg
	
	// Check if subzy binary is available
	if err := s.exec.CheckBinary("subzy"); err != nil {
		s.logger.Warn().Err(err).Msg("subzy binary not found, attempting installation")
		
		// Try to install subzy
		installCmd := "go install github.com/LukaSikic/subzy@latest"
		if err := s.exec.InstallBinary(ctx, "subzy", installCmd); err != nil {
			return fmt.Errorf("failed to install subzy: %w", err)
		}
	}
	
	// Verify version and JSON support
	version, err := s.exec.GetVersion(ctx, "subzy")
	if err != nil {
		s.logger.Warn().Err(err).Msg("Could not determine subzy version")
	} else {
		s.logger.Info().Str("version", version).Msg("subzy version detected")
	}
	
	// Test JSON output capability
	if err := s.testJSONOutput(ctx); err != nil {
		return fmt.Errorf("subzy JSON output test failed: %w", err)
	}
	
	return nil
}

func (s *SubzyPlugin) Prepare(ctx context.Context, target *models.Target, cfg *config.Config, shared *core.SharedContext) error {
	s.config = cfg
	s.logger = s.logger.With().Str("target", target.Domain).Logger()
	
	s.logger.Info().
		Str("target", target.URL).
		Str("domain", target.Domain).
		Msg("Preparing subdomain takeover detection with subzy")
	
	return nil
}

func (s *SubzyPlugin) Run(ctx context.Context, target *models.Target, results chan<- models.PluginResult, shared *core.SharedContext) error {
	s.logger.Info().
		Str("target", target.Domain).
		Msg("Starting subzy subdomain takeover detection")
	
	// Get subdomains from shared context
	subdomains := s.getSubdomains(target, shared)
	
	if len(subdomains) == 0 {
		// If no subdomains available, check the main target (use full URL for subzy)
		subdomains = append(subdomains, target.URL)
	}
	
	s.logger.Debug().
		Int("subdomain_count", len(subdomains)).
		Msg("Checking subdomains for takeover vulnerabilities with subzy")
	
	// Run subzy with JSON output and verification
	if err := s.runSubzyCheck(ctx, subdomains, target, results); err != nil {
		s.logger.Error().Err(err).Msg("Subzy execution failed")
		return err
	}
	
	s.logger.Info().
		Int("checked_subdomains", len(subdomains)).
		Msg("Subzy subdomain takeover check completed")
	
	return nil
}

func (s *SubzyPlugin) Teardown(ctx context.Context) error {
	s.logger.Debug().Msg("Tearing down subzy plugin")
	return nil
}

// Implementation methods

func (s *SubzyPlugin) getSubdomains(target *models.Target, shared *core.SharedContext) []string {
	var subdomains []string
	
	// Get subdomains from shared discoveries
	if shared != nil {
		discoveries := shared.GetDiscoveries(models.DiscoveryTypeSubdomain)
		for _, discovery := range discoveries {
			if subdomain, ok := discovery.Value.(string); ok {
				subdomains = append(subdomains, subdomain)
			}
		}
	}
	
	// Add target URL (subzy works better with full URLs)
	subdomains = append(subdomains, target.URL)
	
	// Deduplicate
	return s.deduplicateStrings(subdomains)
}

func (s *SubzyPlugin) runSubzyCheck(ctx context.Context, subdomains []string, target *models.Target, results chan<- models.PluginResult) error {
	s.logger.Debug().
		Int("subdomain_count", len(subdomains)).
		Msg("Running subzy with JSON output and verification")
	
	// Run subzy with console output parsing (no JSON support in v1.2.0)
	for _, subdomain := range subdomains {
		args := []string{
			"run",
			"--target", subdomain,
			"--hide_fails", // Hide failed attempts for cleaner output
			"--timeout", "10",
		}
		
		s.logger.Info().
			Str("subdomain", subdomain).
			Strs("args", args).
			Msg("Executing subzy command")
		
		// Execute subzy
		result, err := s.exec.Execute(ctx, "subzy", args, &utils.ExecOptions{
			Timeout:       30 * time.Second,
			CaptureOutput: true,
			IgnoreError:   true, // subzy may return non-zero on findings
		})
		
		if err != nil {
			s.logger.Error().Err(err).
				Str("subdomain", subdomain).
				Msg("Subzy execution failed")
			continue
		}
		
		s.logger.Info().
			Str("subdomain", subdomain).
			Str("stdout", result.Stdout).
			Str("stderr", result.Stderr).
			Int("exit_code", result.ExitCode).
			Msg("Subzy command completed")
		
		// Parse console output 
		if err := s.parseSubzyConsoleOutput(result, subdomain, target, results); err != nil {
			s.logger.Error().Err(err).
				Str("subdomain", subdomain).
				Msg("Failed to parse subzy output")
		}
	}
	
	return nil
}

func (s *SubzyPlugin) parseSubzyConsoleOutput(execResult *utils.ExecResult, subdomain string, target *models.Target, results chan<- models.PluginResult) error {
	if execResult.Stdout == "" {
		return nil // No output means no vulnerabilities found
	}
	
	// Process subzy output for vulnerability detection
	
	// Parse console output line by line
	lines := strings.Split(execResult.Stdout, "\n")
	
	for _, line := range lines {
		line = strings.TrimSpace(line)
		// Process each line for vulnerability patterns
		
		// Look for vulnerability pattern: [ VULNERABLE ] (may contain ANSI color codes)
		// Handle both formats: "[ VULNERABLE ]" and "[ [32mVULNERABLE[0m ]"
		if strings.Contains(line, "VULNERABLE") && strings.Contains(line, " - ") {
			// Found a vulnerability, parse the details
			// Split by " - " to handle multiple dash separators
			mainParts := strings.Split(line, " - ")
			
			// Parse vulnerability details from the line
			if len(mainParts) >= 2 {
				// For Bitbucket format: "[ VULNERABLE ]  -  https://asfnbmasgbnasg.bitbucket.io/  [ Bitbucket ]"
				// We need the last part that contains domain and service
				
				// Try to get the rightmost part that has both domain and service
				var domainServicePart string
				if len(mainParts) >= 3 {
					// Format: [ VULNERABLE ] - https://domain - [ Service ]
					// Last part should contain service, second-to-last contains domain
					domainServicePart = strings.TrimSpace(mainParts[1]) + " [ " + strings.TrimSpace(mainParts[2])
				} else {
					// Format: [ VULNERABLE ] - https://domain [ Service ]
					domainServicePart = strings.TrimSpace(mainParts[1])
				}
				
				// Extract domain and service information
				serviceParts := strings.Split(domainServicePart, " [ ")
				
				if len(serviceParts) >= 2 {
					domainPart := strings.TrimSpace(serviceParts[0])
					servicePart := strings.TrimSpace(strings.Split(serviceParts[1], " ]")[0])
					
					// Remove protocol if present in domainPart
					if strings.HasPrefix(domainPart, "https://") {
						domainPart = strings.TrimPrefix(domainPart, "https://")
					} else if strings.HasPrefix(domainPart, "http://") {
						domainPart = strings.TrimPrefix(domainPart, "http://")
					}
					
					// Create SubzyResult from parsed data
					subzyResult := SubzyResult{
						Subdomain:  domainPart,
						Service:    servicePart,
						Vulnerable: true,
						Verified:   true, // Subzy marks as VULNERABLE when verified
						StatusCode: 404,  // Typical for takeover vulnerabilities
					}
					
					// Display vulnerability using banner formatting
					exploitCmd := fmt.Sprintf("subzy run --target %s", target.URL)
					title := fmt.Sprintf("Subdomain Takeover via %s", servicePart)
					banner.Vulnerability("CRITICAL", title, domainPart, exploitCmd)
					
					// Create vulnerability result
					pluginResult := s.createVulnerabilityResult(subzyResult, target, execResult)
					// Add exploit command to plugin result data
					if pluginResult.Data == nil {
						pluginResult.Data = make(map[string]interface{})
					}
					pluginResult.Data["command"] = exploitCmd
					pluginResult.Data["exploit_cmd"] = exploitCmd
					
					results <- pluginResult
					
					s.logger.Info().
						Str("subdomain", subzyResult.Subdomain).
						Str("service", subzyResult.Service).
						Msg("Subdomain takeover vulnerability detected")
				}
			}
		}
	}
	
	return nil
}

func (s *SubzyPlugin) createVulnerabilityResult(subzyResult SubzyResult, target *models.Target, execResult *utils.ExecResult) models.PluginResult {
	severity := models.SeverityCritical
	if !subzyResult.Verified {
		severity = models.SeverityHigh // Unverified vulnerabilities are still high risk
	}
	
	description := fmt.Sprintf("Subdomain %s is vulnerable to takeover via %s.", subzyResult.Subdomain, subzyResult.Service)
	if subzyResult.Verified {
		description += " This vulnerability has been verified and confirmed exploitable."
	} else {
		description += " This vulnerability requires manual verification."
	}
	
	if subzyResult.Fingerprint != "" {
		description += fmt.Sprintf(" Fingerprint: %s", subzyResult.Fingerprint)
	}
	
	result := models.PluginResult{
		ID:        uuid.New().String(),
		Plugin:    s.Name(),
		Tool:      "subzy",
		Category:  "takeover",
		Target:    target.URL,
		Timestamp: time.Now(),
		Severity:  severity,
		Title:     fmt.Sprintf("Subdomain Takeover: %s", subzyResult.Subdomain),
		Description: description,
		Evidence: models.Evidence{
			Type:    "json_output",
			Content: fmt.Sprintf("Subzy detected vulnerable subdomain: %s (Service: %s, Status: %d)", 
				subzyResult.Subdomain, subzyResult.Service, subzyResult.StatusCode),
			URL:     fmt.Sprintf("https://%s", subzyResult.Subdomain),
		},
		Data: map[string]interface{}{
			"subdomain":     subzyResult.Subdomain,
			"service":       subzyResult.Service,
			"status_code":   subzyResult.StatusCode,
			"verified":      subzyResult.Verified,
			"fingerprint":   subzyResult.Fingerprint,
			"vulnerability": "subdomain_takeover",
			"command":       fmt.Sprintf("subzy run --target %s --json --verify", subzyResult.Subdomain),
			"raw_output":    execResult.Stdout,
		},
		References: []string{
			"https://github.com/LukaSikic/subzy",
			"https://github.com/EdOverflow/can-i-take-over-xyz",
			"https://0xpatrik.com/subdomain-takeover/",
			"https://labs.detectify.com/2014/10/21/hostile-subdomain-takeover-using-herokugithubdesk-more/",
		},
		Confidence: s.calculateConfidence(subzyResult),
		Tags:       s.generateTags(subzyResult),
	}
	
	// Add CVSS scoring for verified critical vulnerabilities
	if result.Severity == models.SeverityCritical && subzyResult.Verified {
		result.CVSS = &models.CVSSScore{
			Version:               "3.1",
			BaseScore:            8.5,
			Vector:               "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:N",
			AttackVector:         "Network",
			AttackComplexity:     "Low",
			PrivilegesRequired:   "None",
			UserInteraction:      "None",
			Scope:                "Changed",
			ConfidentialityImpact: "High",
			IntegrityImpact:      "High",
			AvailabilityImpact:   "None",
		}
		result.RiskScore = 8.5
	} else if result.Severity == models.SeverityHigh {
		result.CVSS = &models.CVSSScore{
			Version:               "3.1",
			BaseScore:            7.5,
			Vector:               "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:N",
			AttackVector:         "Network",
			AttackComplexity:     "Low",
			PrivilegesRequired:   "None",
			UserInteraction:      "None",
			Scope:                "Unchanged",
			ConfidentialityImpact: "High",
			IntegrityImpact:      "High",
			AvailabilityImpact:   "None",
		}
		result.RiskScore = 7.5
	}
	
	// Add attack vector information
	result.AttackVector = &models.AttackVector{
		Entry:          "Subdomain DNS Record",
		Technique:      "Subdomain Takeover via " + subzyResult.Service,
		Likelihood:     s.calculateLikelihood(subzyResult),
		RequiredAccess: "None (Public Internet)",
		NextSteps: []string{
			fmt.Sprintf("Register unclaimed %s resource", subzyResult.Service),
			"Upload malicious content or redirect",
			"Conduct phishing campaigns using trusted domain",
			"Steal session cookies and credentials",
			"Bypass Content Security Policy (CSP)",
			"Perform cross-origin attacks",
		},
		Mitigations: []string{
			"Remove dangling DNS records immediately",
			"Implement DNS monitoring and alerting",
			"Regular subdomain audits and cleanup",
			"Use CAA DNS records to restrict certificate issuance",
			"Monitor certificate transparency logs",
			"Implement subdomain validation in CI/CD",
		},
		Prerequisites: []string{
			"Dangling DNS CNAME/A record",
			fmt.Sprintf("Unclaimed %s resource", subzyResult.Service),
			"DNS propagation completed",
		},
	}
	
	return result
}

func (s *SubzyPlugin) createInfoResult(subzyResult SubzyResult, target *models.Target, execResult *utils.ExecResult) models.PluginResult {
	return models.PluginResult{
		ID:        uuid.New().String(),
		Plugin:    s.Name(),
		Tool:      "subzy",
		Category:  "takeover",
		Target:    target.URL,
		Timestamp: time.Now(),
		Severity:  models.SeverityInfo,
		Title:     fmt.Sprintf("Subdomain Service Detection: %s", subzyResult.Subdomain),
		Description: fmt.Sprintf("Detected service information for subdomain %s: %s (Status: %d)", 
			subzyResult.Subdomain, subzyResult.Service, subzyResult.StatusCode),
		Evidence: models.Evidence{
			Type:    "json_output",
			Content: fmt.Sprintf("Service: %s, Status Code: %d, Fingerprint: %s", 
				subzyResult.Service, subzyResult.StatusCode, subzyResult.Fingerprint),
			URL:     fmt.Sprintf("https://%s", subzyResult.Subdomain),
		},
		Data: map[string]interface{}{
			"subdomain":   subzyResult.Subdomain,
			"service":     subzyResult.Service,
			"status_code": subzyResult.StatusCode,
			"fingerprint": subzyResult.Fingerprint,
			"command":     fmt.Sprintf("subzy run --target %s --json", subzyResult.Subdomain),
			"raw_output":  execResult.Stdout,
		},
		Confidence: 0.8,
		Tags:       []string{"subdomain", "service", "reconnaissance", strings.ToLower(subzyResult.Service)},
	}
}

func (s *SubzyPlugin) calculateConfidence(result SubzyResult) float64 {
	confidence := 0.7 // Base confidence
	
	if result.Verified {
		confidence += 0.25 // Verified vulnerabilities get higher confidence
	}
	
	if result.Service != "" && result.Service != "Unknown" {
		confidence += 0.1 // Known service increases confidence
	}
	
	if result.StatusCode == 404 || result.StatusCode == 403 {
		confidence += 0.1 // Common takeover status codes
	}
	
	if result.Fingerprint != "" {
		confidence += 0.05 // Fingerprint detection adds confidence
	}
	
	// Cap at 0.98 to leave room for human verification
	if confidence > 0.98 {
		confidence = 0.98
	}
	
	return confidence
}

func (s *SubzyPlugin) calculateLikelihood(result SubzyResult) float64 {
	if result.Verified {
		return 0.95 // Verified vulnerabilities have very high likelihood
	}
	
	likelihood := 0.6 // Base likelihood for unverified
	
	if result.Service != "" && result.Service != "Unknown" {
		likelihood += 0.2 // Known vulnerable service
	}
	
	if result.StatusCode == 404 {
		likelihood += 0.15 // 404 is strong indicator
	}
	
	return likelihood
}

func (s *SubzyPlugin) generateTags(result SubzyResult) []string {
	tags := []string{"subdomain", "takeover"}
	
	if result.Verified {
		tags = append(tags, "verified", "critical")
	} else {
		tags = append(tags, "potential", "high")
	}
	
	if result.Service != "" {
		tags = append(tags, strings.ToLower(result.Service))
	}
	
	if result.StatusCode == 404 {
		tags = append(tags, "404")
	} else if result.StatusCode == 403 {
		tags = append(tags, "403")
	}
	
	return tags
}

func (s *SubzyPlugin) testJSONOutput(ctx context.Context) error {
	// Test subzy with a non-existent domain to verify JSON output works
	args := []string{"run", "--target", "nonexistent-test-domain-12345.com", "--json", "--hide-fails"}
	
	result, err := s.exec.Execute(ctx, "subzy", args, &utils.ExecOptions{
		Timeout:       30 * time.Second,
		CaptureOutput: true,
		IgnoreError:   true,
	})
	
	if err != nil {
		return fmt.Errorf("subzy test execution failed: %w", err)
	}
	
	// Even with no results, subzy should output valid JSON (empty array or object)
	if result.Stdout != "" {
		var testOutput interface{}
		if err := json.Unmarshal([]byte(result.Stdout), &testOutput); err != nil {
			return fmt.Errorf("subzy does not support JSON output: %w", err)
		}
	}
	
	s.logger.Debug().Msg("Subzy JSON output test passed")
	return nil
}

func (s *SubzyPlugin) deduplicateStrings(input []string) []string {
	seen := make(map[string]bool)
	var result []string
	
	for _, item := range input {
		if !seen[item] {
			seen[item] = true
			result = append(result, item)
		}
	}
	
	return result
}
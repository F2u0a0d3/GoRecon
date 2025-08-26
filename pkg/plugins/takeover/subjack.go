package takeover

import (
	"context"
	"fmt"
	"strings"
	"time"

	"github.com/google/uuid"
	"github.com/f2u0a0d3/GoRecon/internal/utils"
	"github.com/f2u0a0d3/GoRecon/pkg/config"
	"github.com/f2u0a0d3/GoRecon/pkg/core"
	"github.com/f2u0a0d3/GoRecon/pkg/models"
	"github.com/rs/zerolog"
)

// SubjackPlugin implements subdomain takeover detection using subjack
type SubjackPlugin struct {
	core.BasePlugin
	exec    *utils.ExecWrapper
	logger  zerolog.Logger
	config  *config.Config
}

// NewSubjackPlugin creates a new subdomain takeover plugin
func NewSubjackPlugin() *SubjackPlugin {
	logger := zerolog.New(nil).With().Str("plugin", "subjack").Logger()
	
	return &SubjackPlugin{
		BasePlugin: core.NewBasePlugin("subjack", "takeover", []string{"subjack"}),
		exec:      utils.NewExecWrapper(logger),
		logger:    logger,
	}
}

// Metadata methods
func (s *SubjackPlugin) Name() string { return "subjack" }
func (s *SubjackPlugin) Category() string { return "takeover" }
func (s *SubjackPlugin) Description() string {
	return "Detects subdomain takeover vulnerabilities using subjack"
}
func (s *SubjackPlugin) Version() string { return "1.0.0" }
func (s *SubjackPlugin) Author() string { return "GoRecon Team" }

// Dependency methods
func (s *SubjackPlugin) RequiredBinaries() []string {
	return []string{"subjack"}
}

func (s *SubjackPlugin) RequiredEnvVars() []string {
	return []string{}
}

func (s *SubjackPlugin) SupportedTargetTypes() []string {
	return []string{"web", "subdomain", "api"}
}

func (s *SubjackPlugin) Dependencies() []core.PluginDependency {
	return []core.PluginDependency{}
}

func (s *SubjackPlugin) Provides() []string {
	return []string{"takeover_vulnerabilities", "subdomain_status"}
}

func (s *SubjackPlugin) Consumes() []string {
	return []string{"subdomains", "urls"}
}

// Capability methods
func (s *SubjackPlugin) IsPassive() bool { return true }
func (s *SubjackPlugin) RequiresConfirmation() bool { return false }
func (s *SubjackPlugin) EstimatedDuration() time.Duration { return 5 * time.Minute }
func (s *SubjackPlugin) MaxConcurrency() int { return 3 }
func (s *SubjackPlugin) Priority() int { return 9 } // High priority - security critical
func (s *SubjackPlugin) ResourceRequirements() core.Resources {
	return core.Resources{
		CPUCores:         1,
		MemoryMB:         256,
		DiskMB:           50,
		NetworkBandwidth: "1Mbps",
		MaxFileHandles:   50,
		MaxProcesses:     3,
		RequiresRoot:     false,
		NetworkAccess:    true,
	}
}

// Intelligence methods
func (s *SubjackPlugin) ProcessDiscovery(ctx context.Context, discovery models.Discovery) error {
	// Process discoveries from other plugins (e.g., subdomain enumeration)
	if discovery.Type == models.DiscoveryTypeSubdomain {
		s.logger.Debug().
			Str("subdomain", fmt.Sprintf("%v", discovery.Value)).
			Str("source", discovery.Source).
			Msg("Processing subdomain discovery for takeover check")
	}
	return nil
}

func (s *SubjackPlugin) GetIntelligencePatterns() []core.Pattern {
	return []core.Pattern{
		{
			Name:        "subdomain_takeover",
			Type:        "vulnerability",
			Keywords:    []string{"NXDOMAIN", "NoSuchBucket", "NoSuchKey", "is not a website", "repository not found"},
			Confidence:  0.9,
			Description: "Potential subdomain takeover vulnerability indicators",
		},
		{
			Name:        "cloud_service_indicators",
			Type:        "service",
			Keywords:    []string{"s3.amazonaws.com", "herokuapp.com", "github.io", "azurewebsites.net"},
			Confidence:  0.8,
			Description: "Cloud service indicators that may be vulnerable to takeover",
		},
	}
}

// Lifecycle methods
func (s *SubjackPlugin) Validate(ctx context.Context, cfg *config.Config) error {
	s.config = cfg
	
	// Check if subjack binary is available
	if err := s.exec.CheckBinary("subjack"); err != nil {
		s.logger.Warn().Err(err).Msg("subjack binary not found, attempting installation")
		
		// Try to install subjack
		installCmd := "go install github.com/haccer/subjack@latest"
		if err := s.exec.InstallBinary(ctx, "subjack", installCmd); err != nil {
			return fmt.Errorf("failed to install subjack: %w", err)
		}
	}
	
	// Verify version
	version, err := s.exec.GetVersion(ctx, "subjack")
	if err != nil {
		s.logger.Warn().Err(err).Msg("Could not determine subjack version")
	} else {
		s.logger.Info().Str("version", version).Msg("subjack version detected")
	}
	
	return nil
}

func (s *SubjackPlugin) Prepare(ctx context.Context, target *models.Target, cfg *config.Config, shared *core.SharedContext) error {
	s.config = cfg
	s.logger = s.logger.With().Str("target", target.Domain).Logger()
	
	s.logger.Info().
		Str("target", target.URL).
		Str("domain", target.Domain).
		Msg("Preparing subdomain takeover check")
	
	return nil
}

func (s *SubjackPlugin) Run(ctx context.Context, target *models.Target, results chan<- models.PluginResult, shared *core.SharedContext) error {
	s.logger.Info().
		Str("target", target.Domain).
		Msg("Starting subdomain takeover detection")
	
	// Get subdomains from shared context
	subdomains := s.getSubdomains(target, shared)
	
	if len(subdomains) == 0 {
		// If no subdomains available, check the main domain
		subdomains = append(subdomains, target.Domain)
	}
	
	s.logger.Debug().
		Int("subdomain_count", len(subdomains)).
		Msg("Checking subdomains for takeover vulnerabilities")
	
	// Run subjack on the subdomains
	for _, subdomain := range subdomains {
		if err := s.checkSubdomainTakeover(ctx, subdomain, target, results); err != nil {
			s.logger.Error().Err(err).
				Str("subdomain", subdomain).
				Msg("Failed to check subdomain for takeover")
		}
	}
	
	s.logger.Info().
		Int("checked_subdomains", len(subdomains)).
		Msg("Subdomain takeover check completed")
	
	return nil
}

func (s *SubjackPlugin) Teardown(ctx context.Context) error {
	s.logger.Debug().Msg("Tearing down subjack plugin")
	return nil
}

// Implementation methods

func (s *SubjackPlugin) getSubdomains(target *models.Target, shared *core.SharedContext) []string {
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
	
	// Add target domain variants
	subdomains = append(subdomains, target.Domain)
	if target.GetDomainParts(); len(subdomains) == 1 {
		// Add common subdomains if none found
		commonSubs := []string{"www", "api", "app", "mail", "admin", "dev", "staging"}
		for _, sub := range commonSubs {
			subdomains = append(subdomains, fmt.Sprintf("%s.%s", sub, target.Domain))
		}
	}
	
	// Deduplicate
	return s.deduplicateStrings(subdomains)
}

func (s *SubjackPlugin) checkSubdomainTakeover(ctx context.Context, subdomain string, target *models.Target, results chan<- models.PluginResult) error {
	s.logger.Debug().
		Str("subdomain", subdomain).
		Msg("Checking subdomain for takeover vulnerability")
	
	// Prepare subjack command
	args := []string{
		"-d", subdomain,
		"-t", "30",      // 30 second timeout
		"-v",            // Verbose output
		"-ssl",          // Check SSL as well
	}
	
	// Execute subjack
	result, err := s.exec.Execute(ctx, "subjack", args, &utils.ExecOptions{
		Timeout:       2 * time.Minute,
		CaptureOutput: true,
		IgnoreError:   true, // subjack may return non-zero on findings
	})
	
	if err != nil {
		return fmt.Errorf("subjack execution failed: %w", err)
	}
	
	// Parse subjack output
	s.parseSubjackOutput(result, subdomain, target, results)
	
	return nil
}

func (s *SubjackPlugin) parseSubjackOutput(execResult *utils.ExecResult, subdomain string, target *models.Target, results chan<- models.PluginResult) {
	output := execResult.Stdout + execResult.Stderr
	lines := strings.Split(output, "\n")
	
	for _, line := range lines {
		line = strings.TrimSpace(line)
		if line == "" {
			continue
		}
		
		// Check for vulnerability indicators
		if s.isVulnerabilityLine(line) {
			result := s.createVulnerabilityResult(line, subdomain, target, execResult)
			results <- result
		} else if s.isInfoLine(line) {
			result := s.createInfoResult(line, subdomain, target, execResult)
			results <- result
		}
	}
}

func (s *SubjackPlugin) isVulnerabilityLine(line string) bool {
	vulnIndicators := []string{
		"[VULN]",
		"[VULNERABLE]",
		"SUBDOMAIN TAKEOVER",
		"NoSuchBucket",
		"NoSuchKey",
		"is not a website",
		"repository not found",
		"project not found",
	}
	
	lineUpper := strings.ToUpper(line)
	for _, indicator := range vulnIndicators {
		if strings.Contains(lineUpper, strings.ToUpper(indicator)) {
			return true
		}
	}
	
	return false
}

func (s *SubjackPlugin) isInfoLine(line string) bool {
	infoIndicators := []string{
		"[INFO]",
		"[FINGERPRINT]",
		"[SERVICE]",
	}
	
	lineUpper := strings.ToUpper(line)
	for _, indicator := range infoIndicators {
		if strings.Contains(lineUpper, strings.ToUpper(indicator)) {
			return true
		}
	}
	
	return false
}

func (s *SubjackPlugin) createVulnerabilityResult(line, subdomain string, target *models.Target, execResult *utils.ExecResult) models.PluginResult {
	service := s.extractService(line)
	
	result := models.PluginResult{
		ID:        uuid.New().String(),
		Plugin:    s.Name(),
		Tool:      "subjack",
		Category:  "takeover",
		Target:    target.URL,
		Timestamp: time.Now(),
		Severity:  models.SeverityCritical,
		Title:     fmt.Sprintf("Subdomain Takeover: %s", subdomain),
		Description: fmt.Sprintf("Subdomain %s is vulnerable to takeover via %s. "+
			"This could allow an attacker to host malicious content on your domain.", subdomain, service),
		Evidence: models.Evidence{
			Type:    "command_output",
			Content: line,
			URL:     fmt.Sprintf("https://%s", subdomain),
		},
		Data: map[string]interface{}{
			"subdomain":     subdomain,
			"service":       service,
			"vulnerability": "subdomain_takeover",
			"command":       fmt.Sprintf("subjack -d %s", subdomain),
			"raw_output":    execResult.Stdout,
		},
		References: []string{
			"https://github.com/EdOverflow/can-i-take-over-xyz",
			"https://0xpatrik.com/subdomain-takeover/",
		},
		Confidence: 0.95,
		Tags:       []string{"subdomain", "takeover", "critical", service},
	}
	
	// Add CVSS scoring for critical vulnerabilities
	if result.Severity == models.SeverityCritical {
		result.CVSS = &models.CVSSScore{
			Version:               "3.1",
			BaseScore:            8.1,
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
		result.RiskScore = 8.1
	}
	
	// Add attack vector information
	result.AttackVector = &models.AttackVector{
		Entry:          "Subdomain DNS",
		Technique:      "Subdomain Takeover",
		Likelihood:     0.8,
		RequiredAccess: "None",
		NextSteps: []string{
			"Register the service account (e.g., S3 bucket, GitHub Pages)",
			"Host malicious content",
			"Conduct phishing attacks",
			"Steal cookies/credentials",
		},
		Mitigations: []string{
			"Remove dangling DNS records",
			"Monitor subdomain DNS changes",
			"Implement DNS monitoring",
			"Regular subdomain audits",
		},
		Prerequisites: []string{
			"Dangling DNS record",
			"Unclaimed service resource",
		},
	}
	
	return result
}

func (s *SubjackPlugin) createInfoResult(line, subdomain string, target *models.Target, execResult *utils.ExecResult) models.PluginResult {
	return models.PluginResult{
		ID:        uuid.New().String(),
		Plugin:    s.Name(),
		Tool:      "subjack",
		Category:  "takeover",
		Target:    target.URL,
		Timestamp: time.Now(),
		Severity:  models.SeverityInfo,
		Title:     fmt.Sprintf("Subdomain Service Detection: %s", subdomain),
		Description: fmt.Sprintf("Detected service information for subdomain %s", subdomain),
		Evidence: models.Evidence{
			Type:    "command_output",
			Content: line,
			URL:     fmt.Sprintf("https://%s", subdomain),
		},
		Data: map[string]interface{}{
			"subdomain":  subdomain,
			"service":    s.extractService(line),
			"command":    fmt.Sprintf("subjack -d %s", subdomain),
			"raw_output": execResult.Stdout,
		},
		Confidence: 0.7,
		Tags:       []string{"subdomain", "service", "reconnaissance"},
	}
}

func (s *SubjackPlugin) extractService(line string) string {
	// Extract service name from subjack output
	services := map[string]string{
		"s3":                    "Amazon S3",
		"github":                "GitHub Pages",
		"heroku":                "Heroku",
		"wordpress":             "WordPress.com",
		"tumblr":                "Tumblr",
		"shopify":               "Shopify",
		"desk":                  "Desk.com",
		"teamwork":              "Teamwork",
		"helpjuice":             "Helpjuice",
		"helpscout":             "Help Scout",
		"cargo":                 "Cargo Collective",
		"statuspage":            "StatusPage",
		"uservoice":             "UserVoice",
		"surge":                 "Surge.sh",
		"bitbucket":             "Bitbucket",
		"zendesk":               "Zendesk",
		"azure":                 "Microsoft Azure",
		"webflow":               "Webflow",
		"intercom":              "Intercom",
		"campaign_monitor":      "Campaign Monitor",
		"tictail":               "Tictail",
		"aws":                   "Amazon Web Services",
		"cloudfront":            "Amazon CloudFront",
		"smartling":             "Smartling",
		"acquia":                "Acquia",
		"fastly":                "Fastly",
		"pantheon":              "Pantheon",
		"mailgun":               "Mailgun",
		"pingdom":               "Pingdom",
	}
	
	lineUpper := strings.ToUpper(line)
	for key, service := range services {
		if strings.Contains(lineUpper, strings.ToUpper(key)) {
			return service
		}
	}
	
	return "Unknown Service"
}

func (s *SubjackPlugin) deduplicateStrings(input []string) []string {
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
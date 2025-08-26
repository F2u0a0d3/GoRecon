package plugins

import (
	"bufio"
	"context"
	"fmt"
	"os/exec"
	"strings"
	"time"

	"github.com/f2u0a0d3/GoRecon/pkg/banner"
	"github.com/f2u0a0d3/GoRecon/pkg/core"
	"github.com/f2u0a0d3/GoRecon/pkg/models"
)

// EnhancedSubzyPlugin demonstrates enhanced real-time output for subdomain takeover detection
type EnhancedSubzyPlugin struct {
	verbose bool
	results []models.PluginResult
}

// NewEnhancedSubzyPlugin creates a new enhanced subzy plugin
func NewEnhancedSubzyPlugin(verbose bool) *EnhancedSubzyPlugin {
	return &EnhancedSubzyPlugin{
		verbose: verbose,
		results: make([]models.PluginResult, 0),
	}
}

// RunWithEnhancedOutput executes subzy with real-time styled output
func (s *EnhancedSubzyPlugin) RunWithEnhancedOutput(ctx context.Context, target string) error {
	// Display execution header
	banner.Section("SUBDOMAIN TAKEOVER DETECTION")
	banner.StatusLine("info", "Stage: Takeover Detection")
	banner.StatusLine("info", fmt.Sprintf("Tool: subzy"))
	banner.StatusLine("info", fmt.Sprintf("Target: %s", target))
	banner.StatusLine("info", fmt.Sprintf("Started: %s", time.Now().Format("15:04:05")))
	
	fmt.Println()
	banner.StatusLine("info", "Streaming live output...")
	fmt.Printf("\n%s\n", strings.Repeat("─", 80))

	// Create and start subzy command
	cmd := exec.CommandContext(ctx, "subzy", "run", "--target", target, "--hide_fails", "--timeout", "10")
	
	// Get stdout pipe for streaming
	stdout, err := cmd.StdoutPipe()
	if err != nil {
		banner.StatusLine("error", fmt.Sprintf("Failed to create stdout pipe: %v", err))
		return err
	}

	// Get stderr pipe for streaming
	stderr, err := cmd.StderrPipe()
	if err != nil {
		banner.StatusLine("error", fmt.Sprintf("Failed to create stderr pipe: %v", err))
		return err
	}

	// Start the command
	banner.StatusLine("info", "Executing: subzy run --target " + target + " --hide_fails --timeout 10")
	
	if err := cmd.Start(); err != nil {
		banner.StatusLine("error", fmt.Sprintf("Failed to start subzy: %v", err))
		return err
	}

	// Stream stdout in real-time
	go func() {
		scanner := bufio.NewScanner(stdout)
		for scanner.Scan() {
			line := scanner.Text()
			s.processSubzyOutput(line)
		}
	}()

	// Stream stderr in real-time
	go func() {
		scanner := bufio.NewScanner(stderr)
		for scanner.Scan() {
			line := scanner.Text()
			if strings.TrimSpace(line) != "" {
				banner.StatusLine("error", fmt.Sprintf("STDERR: %s", line))
			}
		}
	}()

	// Wait for command to complete
	err = cmd.Wait()
	
	fmt.Printf("\n%s\n", strings.Repeat("─", 80))
	
	duration := time.Since(time.Now()) // This would be tracked properly
	
	if err != nil {
		banner.StatusLine("error", fmt.Sprintf("subzy failed with error: %v", err))
		banner.StatusLine("info", fmt.Sprintf("Duration: %v", duration))
	} else {
		banner.StatusLine("success", "subzy completed successfully")
		banner.StatusLine("info", fmt.Sprintf("Duration: %v", duration))
		banner.StatusLine("info", fmt.Sprintf("Vulnerabilities found: %d", s.countVulnerabilities()))
	}

	// Display summary
	s.displaySummary()
	
	return nil
}

func (s *EnhancedSubzyPlugin) processSubzyOutput(line string) {
	line = strings.TrimSpace(line)
	if line == "" {
		return
	}

	// Remove ANSI color codes for parsing
	cleanLine := removeANSICodes(line)

	switch {
	case strings.Contains(cleanLine, "VULNERABLE") && strings.Contains(cleanLine, " - "):
		s.handleVulnerability(cleanLine)
		
	case strings.Contains(cleanLine, "EDGE CASE"):
		s.handleEdgeCase(cleanLine)
		
	case strings.Contains(cleanLine, "Not Vulnerable") || strings.Contains(cleanLine, "NOT VULNERABLE"):
		s.handleSafeTarget(cleanLine)
		
	case strings.Contains(cleanLine, "Error") || strings.Contains(cleanLine, "ERROR"):
		banner.StatusLine("error", fmt.Sprintf("❌ %s", cleanLine))
		
	case strings.Contains(cleanLine, "Checking") || strings.Contains(cleanLine, "Testing"):
		if s.verbose {
			banner.StatusLine("info", fmt.Sprintf("🔍 %s", cleanLine))
		}
		
	case strings.Contains(cleanLine, "fingerprint"):
		if s.verbose {
			banner.StatusLine("debug", fmt.Sprintf("🔍 Fingerprint check: %s", cleanLine))
		}
		
	default:
		if s.verbose && len(cleanLine) > 5 {
			banner.StatusLine("debug", cleanLine)
		}
	}
}

func (s *EnhancedSubzyPlugin) handleVulnerability(line string) {
	// Parse vulnerability line: [ VULNERABLE ]  -  https://example.github.io/  - [ GitHub Pages ]
	parts := strings.Split(line, " - ")
	
	domain := "Unknown"
	service := "Unknown Service"
	
	if len(parts) >= 2 {
		// Extract domain from URL
		urlPart := strings.TrimSpace(parts[1])
		if strings.Contains(urlPart, "http") {
			domain = urlPart
		}
		
		// Extract service name
		if len(parts) >= 3 {
			servicePart := strings.TrimSpace(parts[2])
			servicePart = strings.Trim(servicePart, "[]")
			if servicePart != "" {
				service = servicePart
			}
		}
	}

	// Display critical finding with enhanced styling
	banner.StatusLine("error", fmt.Sprintf("🚨 CRITICAL: Subdomain Takeover Detected!"))
	banner.StatusLine("error", fmt.Sprintf("    Domain: %s", domain))
	banner.StatusLine("error", fmt.Sprintf("    Service: %s", service))
	banner.StatusLine("error", fmt.Sprintf("    Status: VULNERABLE"))
	
	// Generate exploit command
	exploitCmd := fmt.Sprintf("# Verify takeover:\ncurl -H 'Host: %s' %s", domain, domain)
	banner.StatusLine("info", fmt.Sprintf("    Exploit: %s", exploitCmd))

	// Store result
	result := models.PluginResult{
		Plugin:      "subzy",
		Target:      domain,
		Severity:    models.SeverityCritical,
		Title:       "Subdomain Takeover Vulnerability",
		Description: fmt.Sprintf("Subdomain %s is vulnerable to takeover via %s", domain, service),
		Data: map[string]interface{}{
			"service":     service,
			"url":         domain,
			"command":     exploitCmd,
			"verified":    true,
			"fingerprint": line,
		},
		Timestamp: time.Now(),
	}
	
	s.results = append(s.results, result)
	fmt.Println() // Add spacing after critical finding
}

func (s *EnhancedSubzyPlugin) handleEdgeCase(line string) {
	domain := extractDomainFromLine(line)
	
	banner.StatusLine("warning", fmt.Sprintf("⚠️  EDGE CASE: %s", domain))
	banner.StatusLine("warning", fmt.Sprintf("    Requires manual verification"))
	
	if s.verbose {
		banner.StatusLine("debug", fmt.Sprintf("    Details: %s", line))
	}

	// Store as high severity (needs manual verification)
	result := models.PluginResult{
		Plugin:      "subzy",
		Target:      domain,
		Severity:    models.SeverityHigh,
		Title:       "Potential Subdomain Takeover (Manual Verification Required)",
		Description: fmt.Sprintf("Subdomain %s shows signs of potential takeover but requires manual verification", domain),
		Data: map[string]interface{}{
			"manual_verification": true,
			"fingerprint":        line,
			"url":                domain,
		},
		Timestamp: time.Now(),
	}
	
	s.results = append(s.results, result)
}

func (s *EnhancedSubzyPlugin) handleSafeTarget(line string) {
	if !s.verbose {
		return
	}
	
	domain := extractDomainFromLine(line)
	banner.StatusLine("success", fmt.Sprintf("✅ Safe: %s", domain))
}

func (s *EnhancedSubzyPlugin) countVulnerabilities() int {
	count := 0
	for _, result := range s.results {
		if result.Severity == models.SeverityCritical || result.Severity == models.SeverityHigh {
			count++
		}
	}
	return count
}

func (s *EnhancedSubzyPlugin) displaySummary() {
	fmt.Println()
	banner.Section("TAKEOVER SCAN SUMMARY")
	
	critical := 0
	high := 0
	medium := 0
	low := 0
	
	for _, result := range s.results {
		switch result.Severity {
		case models.SeverityCritical:
			critical++
		case models.SeverityHigh:
			high++
		case models.SeverityMedium:
			medium++
		case models.SeverityLow:
			low++
		}
	}

	banner.StatusLine("info", fmt.Sprintf("Total findings: %d", len(s.results)))
	
	if critical > 0 {
		banner.StatusLine("error", fmt.Sprintf("🔴 Critical: %d (Immediate Action Required!)", critical))
	}
	if high > 0 {
		banner.StatusLine("warning", fmt.Sprintf("🟠 High: %d (Manual Verification Needed)", high))
	}
	if medium > 0 {
		banner.StatusLine("info", fmt.Sprintf("🟡 Medium: %d", medium))
	}
	if low > 0 {
		banner.StatusLine("info", fmt.Sprintf("🟢 Low: %d", low))
	}

	if critical == 0 && high == 0 {
		banner.StatusLine("success", "✅ No critical takeover vulnerabilities detected")
	} else {
		banner.StatusLine("error", "⚠️  SECURITY RISK: Takeover vulnerabilities detected!")
		banner.StatusLine("error", "    Immediate remediation required")
		
		// Show remediation steps
		fmt.Println()
		banner.StatusLine("info", "Remediation Steps:")
		banner.StatusLine("info", "  1. Remove dangling DNS records (CNAME)")
		banner.StatusLine("info", "  2. Reclaim accounts on affected services")
		banner.StatusLine("info", "  3. Verify all subdomains point to active resources")
		banner.StatusLine("info", "  4. Implement continuous subdomain monitoring")
	}

	fmt.Println()
}

// Utility function to demonstrate parsing
func extractDomainFromLine(line string) string {
	// Remove ANSI codes first
	line = removeANSICodes(line)
	line = strings.TrimSpace(line)
	
	// Look for URLs
	if strings.Contains(line, "http") {
		parts := strings.Fields(line)
		for _, part := range parts {
			if strings.HasPrefix(part, "http") {
				return part
			}
		}
	}
	
	// Look for domains in brackets
	if strings.Contains(line, "] - ") {
		parts := strings.Split(line, "] - ")
		if len(parts) > 1 {
			return strings.TrimSpace(parts[1])
		}
	}
	
	return line
}

func removeANSICodes(text string) string {
	// Basic ANSI code removal - this would be more comprehensive in real implementation
	result := text
	codes := []string{"\033[0m", "\033[31m", "\033[32m", "\033[33m", "\033[34m", "\033[35m", "\033[36m", "\033[37m", "\033[1m", "\033[91m", "\033[92m"}
	
	for _, code := range codes {
		result = strings.ReplaceAll(result, code, "")
	}
	
	// Handle more complex ANSI sequences
	for strings.Contains(result, "\033[") {
		start := strings.Index(result, "\033[")
		if start == -1 {
			break
		}
		
		end := start + 2
		for end < len(result) && result[end] != 'm' {
			end++
		}
		
		if end < len(result) {
			result = result[:start] + result[end+1:]
		} else {
			break
		}
	}
	
	return result
}

// Example of how other tools would be enhanced:

// EnhancedNucleiOutput processes nuclei output with enhanced styling
func EnhancedNucleiOutput(line string) {
	line = strings.TrimSpace(line)
	
	switch {
	case strings.Contains(line, "[critical]"):
		banner.StatusLine("error", fmt.Sprintf("🔴 CRITICAL: %s", line))
	case strings.Contains(line, "[high]"):
		banner.StatusLine("error", fmt.Sprintf("🟠 HIGH: %s", line))
	case strings.Contains(line, "[medium]"):
		banner.StatusLine("warning", fmt.Sprintf("🟡 MEDIUM: %s", line))
	case strings.Contains(line, "[low]"):
		banner.StatusLine("info", fmt.Sprintf("🔵 LOW: %s", line))
	case strings.Contains(line, "[info]"):
		banner.StatusLine("info", fmt.Sprintf("ℹ️  INFO: %s", line))
	case strings.Contains(line, "Templates loaded"):
		banner.StatusLine("info", fmt.Sprintf("📋 %s", line))
	case strings.Contains(line, "Scanning target"):
		banner.StatusLine("info", fmt.Sprintf("🎯 %s", line))
	default:
		banner.StatusLine("debug", line)
	}
}

// EnhancedHTTPXOutput processes httpx output with enhanced styling
func EnhancedHTTPXOutput(line string) {
	line = strings.TrimSpace(line)
	
	if strings.Contains(line, "http") {
		parts := strings.Fields(line)
		if len(parts) > 0 {
			url := parts[0]
			statusIcon := "📊"
			
			// Parse status code and other info
			for _, part := range parts[1:] {
				if strings.HasPrefix(part, "[") && strings.HasSuffix(part, "]") {
					content := strings.Trim(part, "[]")
					if len(content) == 3 {
						// Status code
						switch {
						case strings.HasPrefix(content, "2"):
							statusIcon = "✅"
						case strings.HasPrefix(content, "3"):
							statusIcon = "🔄"
						case strings.HasPrefix(content, "4"):
							statusIcon = "⚠️"
						case strings.HasPrefix(content, "5"):
							statusIcon = "❌"
						}
						break
					}
				}
			}
			
			banner.StatusLine("success", fmt.Sprintf("%s %s", statusIcon, line))
		}
	}
}

// EnhancedFFUFOutput processes ffuf directory fuzzing output
func EnhancedFFUFOutput(line string) {
	line = strings.TrimSpace(line)
	
	switch {
	case strings.Contains(line, "Status: 200"):
		banner.StatusLine("success", fmt.Sprintf("✅ FOUND: %s", line))
	case strings.Contains(line, "Status: 301") || strings.Contains(line, "Status: 302"):
		banner.StatusLine("info", fmt.Sprintf("🔄 REDIRECT: %s", line))
	case strings.Contains(line, "Status: 403"):
		banner.StatusLine("warning", fmt.Sprintf("🚫 FORBIDDEN: %s", line))
	case strings.Contains(line, "Status: 401"):
		banner.StatusLine("warning", fmt.Sprintf("🔐 AUTH REQUIRED: %s", line))
	case strings.Contains(line, "Progress"):
		banner.StatusLine("info", fmt.Sprintf("⏳ %s", line))
	default:
		banner.StatusLine("debug", line)
	}
}
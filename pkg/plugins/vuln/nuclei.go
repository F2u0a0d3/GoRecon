package vuln

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"sort"
	"strings"
	"time"

	"github.com/fatih/color"
	"github.com/f2u0a0d3/GoRecon/pkg/core"
	"github.com/f2u0a0d3/GoRecon/pkg/models"
	"github.com/f2u0a0d3/GoRecon/pkg/plugins/base"
)

// VulnScanPlugin implements vulnerability scanning
type VulnScanPlugin struct {
	*base.BaseAdapter
	config *VulnScanConfig
}

// VulnScanConfig contains vulnerability scanning configuration
type VulnScanConfig struct {
	EnableNuclei       bool          `json:"enable_nuclei"`
	Threads            int           `json:"threads"`
	Timeout            time.Duration `json:"timeout"`
	Templates          []string      `json:"templates"`
	Severity           []string      `json:"severity"`
	ExcludeTags        []string      `json:"exclude_tags"`
	IncludeTags        []string      `json:"include_tags"`
	RateLimit          int           `json:"rate_limit"`
	BulkSize           int           `json:"bulk_size"`
	UserAgent          string        `json:"user_agent"`
	FollowRedirects    bool          `json:"follow_redirects"`
	UpdateTemplates    bool          `json:"update_templates"`
	DisableClustering  bool          `json:"disable_clustering"`
}

// VulnResult represents a vulnerability scan result
type VulnResult struct {
	TemplateID      string                 `json:"template_id"`
	TemplateName    string                 `json:"template_name"`
	Description     string                 `json:"description"`
	Severity        string                 `json:"severity"`
	Tags            []string               `json:"tags"`
	URL             string                 `json:"url"`
	Method          string                 `json:"method"`
	Status          int                    `json:"status"`
	ContentLength   int                    `json:"content_length"`
	Words           int                    `json:"words"`
	Lines           int                    `json:"lines"`
	ResponseTime    time.Duration          `json:"response_time"`
	MatchedAt       string                 `json:"matched_at"`
	ExtractedData   map[string]interface{} `json:"extracted_data"`
	Request         string                 `json:"request"`
	Response        string                 `json:"response"`
	CurlCommand     string                 `json:"curl_command"`
	Reference       []string               `json:"reference"`
	Classification  map[string]interface{} `json:"classification"`
	Metadata        map[string]string      `json:"metadata"`
	Tool            string                 `json:"tool"`
	Timestamp       time.Time              `json:"timestamp"`
	Confidence      float64                `json:"confidence"`
}

// VulnScanStats contains vulnerability scanning statistics
type VulnScanStats struct {
	TotalTargets      int                    `json:"total_targets"`
	ScannedTargets    int                    `json:"scanned_targets"`
	TotalFindings     int                    `json:"total_findings"`
	TotalTemplates    int                    `json:"total_templates"`
	BySeverity        map[string]int         `json:"by_severity"`
	ByTag             map[string]int         `json:"by_tag"`
	ByTemplate        map[string]int         `json:"by_template"`
	ScanDuration      time.Duration          `json:"scan_duration"`
}

// NewVulnScanPlugin creates a new vulnerability scanning plugin
func NewVulnScanPlugin() *VulnScanPlugin {
	config := &VulnScanConfig{
		EnableNuclei:      true,
		Threads:           25,
		Timeout:           30 * time.Second,
		Templates:         []string{}, // Use all default templates
		Severity:          []string{"info", "low", "medium", "high", "critical"},
		ExcludeTags:       []string{"dos", "intrusive"},
		IncludeTags:       []string{},
		RateLimit:         150,
		BulkSize:          25,
		UserAgent:         "GORECON/2.0 Vulnerability Scanner",
		FollowRedirects:   true,
		UpdateTemplates:   false,
		DisableClustering: false,
	}

	baseAdapter := base.NewBaseAdapter(base.BaseAdapterConfig{
		Name:        "vuln",
		Category:    "vuln",
		Description: "Vulnerability scanning using nuclei",
		Version:     "1.0.0",
		Author:      "GoRecon Team",
		ToolName:    "nuclei",
		Passive:     false,
		Duration:    90 * time.Minute,
		Concurrency: 1,
		Priority:    15,
		Resources: core.Resources{
			CPUCores:      4,
			MemoryMB:      4096,
			NetworkAccess: true,
		},
		Provides: []string{"vulnerabilities", "security_issues", "exposures"},
		Consumes: []string{"http_services", "web_pages", "endpoints"},
	})

	return &VulnScanPlugin{
		BaseAdapter: baseAdapter,
		config:      config,
	}
}

// Run executes vulnerability scanning
func (v *VulnScanPlugin) Run(ctx context.Context, target *models.Target, results chan<- models.PluginResult, shared *core.SharedContext) error {
	logger := shared.GetLogger().WithField("plugin", "vuln")
	
	cyan := color.New(color.FgCyan).SprintFunc()
	white := color.New(color.FgWhite, color.Bold).SprintFunc()

	domain := target.Domain
	if domain == "" {
		domain = v.ExtractDomain(target.URL)
	}

	fmt.Printf("\n%s\n", white("[GORECON] Vulnerability Scanner v1.0"))
	fmt.Printf("%s\n", strings.Repeat("=", 36))
	fmt.Printf("[%s] Using nuclei for comprehensive vulnerability assessment\n", cyan("*"))

	scanTargets := v.collectScanTargets(shared, domain, target)
	fmt.Printf("[%s] Scanning %d targets from previous discovery steps...\n\n", cyan("*"), len(scanTargets))

	workDir := filepath.Join("./work", domain, "vuln")
	if err := os.MkdirAll(workDir, 0755); err != nil {
		return fmt.Errorf("failed to create workspace: %w", err)
	}
	
	rawDir := filepath.Join(workDir, "raw")
	if err := os.MkdirAll(rawDir, 0755); err != nil {
		return fmt.Errorf("failed to create directory: %w", err)
	}

	vulnResults, stats, err := v.runVulnerabilityScanning(ctx, scanTargets, rawDir, domain)
	if err != nil {
		logger.Error("Vulnerability scanning failed", err)
		return err
	}

	v.displayResults(vulnResults, stats)
	v.generatePluginResults(target, vulnResults, results)
	v.addDiscoveries(shared, domain, vulnResults)

	logger.Info("Vulnerability scanning completed",
		"target", domain,
		"scanned_targets", stats.ScannedTargets,
		"total_findings", stats.TotalFindings,
		"critical", stats.BySeverity["critical"],
		"high", stats.BySeverity["high"])

	return nil
}

func (v *VulnScanPlugin) collectScanTargets(shared *core.SharedContext, domain string, target *models.Target) []string {
	urlSet := make(map[string]bool)

	// Add target URL
	if target.URL != "" {
		urlSet[target.URL] = true
	}

	// Add root domain URLs
	urlSet[fmt.Sprintf("https://%s", domain)] = true
	urlSet[fmt.Sprintf("http://%s", domain)] = true

	// Collect targets from discoveries
	discoveries := shared.GetDiscoveries("")
	for _, discovery := range discoveries {
		value, ok := discovery.Value.(string)
		if !ok {
			continue
		}

		switch discovery.Type {
		case "http_service":
			if strings.Contains(value, domain) {
				urlSet[value] = true
			}
		case "web_page":
			if strings.Contains(value, domain) && (strings.HasPrefix(value, "http://") || strings.HasPrefix(value, "https://")) {
				urlSet[value] = true
			}
		case "endpoint":
			if strings.Contains(value, domain) && (strings.HasPrefix(value, "http://") || strings.HasPrefix(value, "https://")) {
				urlSet[value] = true
			}
		case "directory", "file":
			if strings.Contains(value, domain) && (strings.HasPrefix(value, "http://") || strings.HasPrefix(value, "https://")) {
				urlSet[value] = true
			}
		}
	}

	var urlList []string
	for url := range urlSet {
		urlList = append(urlList, url)
	}
	sort.Strings(urlList)

	return urlList
}

func (v *VulnScanPlugin) runVulnerabilityScanning(ctx context.Context, scanTargets []string, rawDir string, domain string) ([]VulnResult, VulnScanStats, error) {
	white := color.New(color.FgWhite, color.Bold).SprintFunc()
	cyan := color.New(color.FgCyan).SprintFunc()
	red := color.New(color.FgRed).SprintFunc()

	fmt.Printf("%s\n", white("[GORECON::NUCLEI] Vulnerability Assessment"))
	fmt.Printf("%s\n", strings.Repeat("=", 42))

	if _, err := exec.LookPath("nuclei"); err != nil {
		fmt.Printf("[%s] nuclei not found\n", red("!"))
		fmt.Printf("[%s] Install: go install github.com/projectdiscovery/nuclei/v3/cmd/nuclei@latest\n", cyan("*"))
		return nil, VulnScanStats{}, fmt.Errorf("nuclei not installed")
	}

	startTime := time.Now()

	// Run nuclei with simple target
	vulnResults, err := v.runNuclei(ctx, domain, rawDir)
	if err != nil {
		return nil, VulnScanStats{}, err
	}

	// Generate statistics
	stats := VulnScanStats{
		TotalTargets:   1,
		ScannedTargets: 1,
		TotalFindings:  len(vulnResults),
		BySeverity:     make(map[string]int),
		ByTag:          make(map[string]int),
		ByTemplate:     make(map[string]int),
		ScanDuration:   time.Since(startTime),
	}

	for _, result := range vulnResults {
		stats.BySeverity[result.Severity]++
		stats.ByTemplate[result.TemplateID]++
		for _, tag := range result.Tags {
			stats.ByTag[tag]++
		}
	}

	return vulnResults, stats, nil
}

func (v *VulnScanPlugin) runNuclei(ctx context.Context, domain, rawDir string) ([]VulnResult, error) {
	outputFile := filepath.Join(rawDir, "nuclei_output.json")
	cyan := color.New(color.FgCyan).SprintFunc()
	
	args := []string{
		"-target", domain,
		"-jsonl", "-o", outputFile,
		"-silent",
		"-tags", "tech",
		"-severity", "info,low,medium,high,critical",
	}

	fmt.Printf("[%s] Running: nuclei %s\n", cyan("*"), strings.Join(args, " "))

	cmd := exec.CommandContext(ctx, "nuclei", args...)
	
	// Get command output for debugging
	output, err := cmd.CombinedOutput()
	if err != nil {
		fmt.Printf("[%s] Nuclei error: %v\n", color.New(color.FgRed).SprintFunc()("!"), err)
		fmt.Printf("[%s] Nuclei output: %s\n", color.New(color.FgRed).SprintFunc()("!"), string(output))
		
		// Check if output file exists and has content
		if stat, statErr := os.Stat(outputFile); statErr != nil || stat.Size() == 0 {
			return nil, fmt.Errorf("nuclei failed: %w", err)
		}
	} else {
		fmt.Printf("[%s] Nuclei completed successfully\n", color.New(color.FgGreen).SprintFunc()("+"))
	}

	// Parse results
	results, err := v.parseNucleiOutput(outputFile)
	if err != nil {
		return nil, err
	}

	return results, nil
}

func (v *VulnScanPlugin) parseNucleiOutput(filename string) ([]VulnResult, error) {
	data, err := os.ReadFile(filename)
	if err != nil {
		return nil, err
	}

	var results []VulnResult
	lines := strings.Split(string(data), "\n")

	for _, line := range lines {
		line = strings.TrimSpace(line)
		if line == "" {
			continue
		}

		var raw map[string]interface{}
		if err := json.Unmarshal([]byte(line), &raw); err != nil {
			continue
		}

		result := VulnResult{
			Tool:       "nuclei",
			Timestamp:  time.Now(),
			Confidence: 0.95,
			Metadata:   make(map[string]string),
		}

		// Parse main fields
		if templateID, ok := raw["template-id"].(string); ok {
			result.TemplateID = templateID
		}
		if templateInfo, ok := raw["info"].(map[string]interface{}); ok {
			if name, ok := templateInfo["name"].(string); ok {
				result.TemplateName = name
			}
			if description, ok := templateInfo["description"].(string); ok {
				result.Description = description
			}
			if severity, ok := templateInfo["severity"].(string); ok {
				result.Severity = severity
			}
			if tags, ok := templateInfo["tags"].([]interface{}); ok {
				for _, tag := range tags {
					if tagStr, ok := tag.(string); ok {
						result.Tags = append(result.Tags, tagStr)
					}
				}
			}
			if reference, ok := templateInfo["reference"].([]interface{}); ok {
				for _, ref := range reference {
					if refStr, ok := ref.(string); ok {
						result.Reference = append(result.Reference, refStr)
					}
				}
			}
			if classification, ok := templateInfo["classification"].(map[string]interface{}); ok {
				result.Classification = classification
			}
		}

		// Parse match information
		if url, ok := raw["matched-at"].(string); ok {
			result.URL = url
			result.MatchedAt = url
		}

		// Parse request/response information
		if method, ok := raw["method"].(string); ok {
			result.Method = method
		}
		if status, ok := raw["status"].(float64); ok {
			result.Status = int(status)
		}
		if length, ok := raw["content-length"].(float64); ok {
			result.ContentLength = int(length)
		}
		if words, ok := raw["words"].(float64); ok {
			result.Words = int(words)
		}
		if lines, ok := raw["lines"].(float64); ok {
			result.Lines = int(lines)
		}
		if responseTime, ok := raw["response-time"].(string); ok {
			if duration, err := time.ParseDuration(responseTime); err == nil {
				result.ResponseTime = duration
			}
		}

		// Parse extracted data
		if extractedData, ok := raw["extracted-results"].([]interface{}); ok {
			result.ExtractedData = make(map[string]interface{})
			for i, data := range extractedData {
				result.ExtractedData[fmt.Sprintf("extract_%d", i)] = data
			}
		}

		// Parse request/response
		if request, ok := raw["request"].(string); ok {
			result.Request = request
		}
		if response, ok := raw["response"].(string); ok {
			result.Response = response
		}

		// Parse curl command
		if curlCommand, ok := raw["curl-command"].(string); ok {
			result.CurlCommand = curlCommand
		}

		results = append(results, result)
	}

	return results, nil
}


func (v *VulnScanPlugin) displayResults(results []VulnResult, stats VulnScanStats) {
	green := color.New(color.FgGreen).SprintFunc()
	yellow := color.New(color.FgYellow).SprintFunc()
	red := color.New(color.FgRed).SprintFunc()

	for _, result := range results {
		severityColor := green
		switch strings.ToLower(result.Severity) {
		case "critical":
			severityColor = color.New(color.FgMagenta, color.Bold).SprintFunc()
		case "high":
			severityColor = red
		case "medium":
			severityColor = yellow
		case "low":
			severityColor = color.New(color.FgBlue).SprintFunc()
		}

		fmt.Printf("[%s] %s [%s] [%s]\n",
			red("!"),
			result.URL,
			severityColor(strings.ToUpper(result.Severity)),
			result.TemplateID)

		fmt.Printf("    %s\n", result.TemplateName)
		
		if result.Description != "" {
			fmt.Printf("    Description: %s\n", result.Description)
		}
		
		if len(result.Tags) > 0 {
			fmt.Printf("    Tags: %s\n", strings.Join(result.Tags, ", "))
		}
		
		if result.Status > 0 {
			fmt.Printf("    Status: %d\n", result.Status)
		}
		
		if result.ResponseTime > 0 {
			fmt.Printf("    Response Time: %v\n", result.ResponseTime)
		}
		
		if len(result.Reference) > 0 {
			fmt.Printf("    References: %s\n", strings.Join(result.Reference, ", "))
		}
		
		fmt.Printf("    Confidence: %.0f%%\n", result.Confidence*100)
		fmt.Println()
	}

	// Display summary
	if stats.TotalFindings > 0 {
		fmt.Printf("📊 Vulnerability Summary:\n")
		fmt.Printf("Critical: %d, High: %d, Medium: %d, Low: %d, Info: %d\n",
			stats.BySeverity["critical"],
			stats.BySeverity["high"],
			stats.BySeverity["medium"],
			stats.BySeverity["low"],
			stats.BySeverity["info"])
	}
}

func (v *VulnScanPlugin) generatePluginResults(target *models.Target, results []VulnResult, resultsChan chan<- models.PluginResult) {
	for _, result := range results {
		severity := v.mapSeverity(result.Severity)

		pluginResult := models.PluginResult{
			Plugin:      "vuln",
			Target:      target.URL,
			Severity:    severity,
			Title:       fmt.Sprintf("%s: %s", result.Severity, result.TemplateName),
			Description: result.Description,
			Data: map[string]interface{}{
				"template_id":      result.TemplateID,
				"template_name":    result.TemplateName,
				"url":              result.URL,
				"severity":         result.Severity,
				"tags":             result.Tags,
				"method":           result.Method,
				"status_code":      result.Status,
				"response_time":    result.ResponseTime,
				"extracted_data":   result.ExtractedData,
				"reference":        result.Reference,
				"classification":   result.Classification,
				"request":          result.Request,
				"response":         result.Response,
				"curl_command":     result.CurlCommand,
				"tool":             result.Tool,
			},
			Timestamp: time.Now(),
		}
		resultsChan <- pluginResult
	}
}

func (v *VulnScanPlugin) addDiscoveries(shared *core.SharedContext, domain string, results []VulnResult) {
	for _, result := range results {
		// Add vulnerability discovery
		shared.AddDiscovery(models.Discovery{
			Type:       "vulnerability",
			Value:      result.TemplateID,
			Source:     "vuln",
			Confidence: result.Confidence,
			Timestamp:  time.Now(),
			Metadata: map[string]interface{}{
				"template_name": result.TemplateName,
				"description":   result.Description,
				"severity":      result.Severity,
				"tags":          result.Tags,
				"url":           result.URL,
				"status_code":   result.Status,
				"method":        result.Method,
				"reference":     result.Reference,
				"tool":          result.Tool,
				"domain":        domain,
			},
		})

		// Add security issue discovery for high/critical findings
		if result.Severity == "high" || result.Severity == "critical" {
			shared.AddDiscovery(models.Discovery{
				Type:       "security_issue",
				Value:      result.URL,
				Source:     "vuln",
				Confidence: result.Confidence,
				Timestamp:  time.Now(),
				Metadata: map[string]interface{}{
					"issue_type":    result.TemplateID,
					"issue_name":    result.TemplateName,
					"severity":      result.Severity,
					"description":   result.Description,
					"reference":     result.Reference,
					"tool":          result.Tool,
					"domain":        domain,
				},
			})
		}
	}
}

func (v *VulnScanPlugin) mapSeverity(nucleiSeverity string) string {
	switch strings.ToLower(nucleiSeverity) {
	case "critical":
		return models.SeverityCritical
	case "high":
		return models.SeverityHigh
	case "medium":
		return models.SeverityMedium
	case "low":
		return models.SeverityLow
	case "info":
		return models.SeverityInfo
	default:
		return models.SeverityLow
	}
}
package cloud

import (
	"bufio"
	"context"
	"encoding/json"
	"fmt"
	"os/exec"
	"strings"
	"sync"
	"time"

	"github.com/f2u0a0d3/GoRecon/pkg/core"
	"github.com/f2u0a0d3/GoRecon/pkg/models"
	"github.com/f2u0a0d3/GoRecon/pkg/plugins/base"
	"github.com/fatih/color"
)

// CloudEnumPlugin implements cloud storage enumeration using cloud_enum
type CloudEnumPlugin struct {
	*base.BaseAdapter
}

// CloudFinding represents a comprehensive cloud resource finding
type CloudFinding struct {
	Provider     string                 `json:"provider"`      // AWS, Azure, GCP
	Service      string                 `json:"service"`       // S3, Blob, GCS, Firebase
	URL          string                 `json:"url"`           // Resource URL
	Status       string                 `json:"status"`        // Open, Protected, HTTPS-Only
	Files        []string               `json:"files"`         // File listings if available
	Severity     string                 `json:"severity"`      // Critical for open, Info for protected
	ResourceName string                 `json:"resource_name"` // Bucket/resource name
	Details      map[string]interface{} `json:"details"`       // Additional metadata
}

// CloudEnumSummary represents the complete scan summary
type CloudEnumSummary struct {
	Duration         string             `json:"duration"`
	TotalResources   int                `json:"total_resources"`
	AWSResources     CloudProviderStats `json:"aws_resources"`
	AzureResources   CloudProviderStats `json:"azure_resources"`
	GoogleResources  CloudProviderStats `json:"google_resources"`
	CriticalFindings []string           `json:"critical_findings"`
}

// CloudProviderStats represents statistics for each cloud provider
type CloudProviderStats struct {
	Total     int            `json:"total"`
	Services  map[string]int `json:"services"`
	OpenCount int            `json:"open_count"`
}

// Legacy CloudEnumResult for backward compatibility
type CloudEnumResult struct {
	Service string `json:"service"`
	Bucket  string `json:"bucket"`
	Region  string `json:"region"`
	Public  bool   `json:"public"`
	Exists  bool   `json:"exists"`
	URL     string `json:"url"`
	Error   string `json:"error,omitempty"`
}

// NewCloudEnumPlugin creates a new cloud enumeration plugin
func NewCloudEnumPlugin() *CloudEnumPlugin {
	baseConfig := base.BaseAdapterConfig{
		Name:         "cloud_enum",
		Category:     models.CategoryCloud,
		Description:  "Cloud storage bucket enumeration and discovery",
		Version:      "1.0.0",
		Author:       "initstring",
		ToolName:     "python3",
		ToolPath:     "",         // Will be discovered during validation
		ToolArgs:     []string{}, // Args will be built in enumerateCloudStorage
		Passive:      false,      // Makes external requests
		Confirmation: false,
		Duration:     20 * time.Minute, // Increased for comprehensive scan
		Concurrency:  5,
		Priority:     7,
		Resources: core.Resources{
			CPUCores:      1,
			MemoryMB:      256,
			DiskMB:        50,
			NetworkAccess: true,
			MaxProcesses:  5,
		},
		Dependencies: []core.PluginDependency{},
		Provides: []string{
			models.DiscoveryTypeFile,
			"cloud_storage",
			"bucket",
		},
		Consumes: []string{
			models.DiscoveryTypeSubdomain,
		},
		Patterns: []core.Pattern{
			{
				Name:        "aws_s3_bucket",
				Type:        "cloud_storage",
				Regex:       `https?://([^\.]+)\.s3[^\.]*\.amazonaws\.com`,
				Confidence:  0.9,
				Description: "AWS S3 bucket URL pattern",
			},
			{
				Name:        "gcp_storage_bucket",
				Type:        "cloud_storage",
				Regex:       `https?://storage\.googleapis\.com/([^/]+)`,
				Confidence:  0.9,
				Description: "Google Cloud Storage bucket pattern",
			},
		},
	}

	return &CloudEnumPlugin{
		BaseAdapter: base.NewBaseAdapter(baseConfig),
	}
}

// RequiredEnvVars returns required environment variables
func (c *CloudEnumPlugin) RequiredEnvVars() []string {
	return []string{
		"AWS_ACCESS_KEY_ID",     // Optional but improves results
		"AWS_SECRET_ACCESS_KEY", // Optional but improves results
	}
}

// SupportedTargetTypes returns supported target types
func (c *CloudEnumPlugin) SupportedTargetTypes() []string {
	return []string{"web", "api", "subdomain", "cloud"}
}

// Run executes the cloud enumeration plugin with GORECON styling
func (c *CloudEnumPlugin) Run(ctx context.Context, target *models.Target, results chan<- models.PluginResult, shared *core.SharedContext) error {
	logger := shared.GetLogger().WithField("plugin", "cloud_enum")

	// Initialize color functions
	red := color.New(color.FgRed).SprintFunc()
	green := color.New(color.FgGreen).SprintFunc()
	cyan := color.New(color.FgCyan).SprintFunc()
	white := color.New(color.FgWhite, color.Bold).SprintFunc()

	// Display GORECON header
	fmt.Printf("\n%s\n", white("[GORECON] Cloud Resource Enumeration v1.0"))
	fmt.Printf("%s\n\n", strings.Repeat("=", 40))

	// Extract keyword and show initialization
	// Use URL if Domain is empty (common when target is passed as domain only)
	targetString := target.Domain
	if targetString == "" {
		targetString = target.URL
	}
	keyword := c.extractDomainKeyword(targetString)
	fmt.Printf("[%s] Initializing cloud_enum engine...\n", cyan("*"))
	fmt.Printf("[%s] Target keyword: %s\n", green("+"), keyword)
	fmt.Printf("[%s] Mutations: loading...\n", cyan("*"))
	fmt.Printf("[%s] Brute-list: generating combinations...\n", cyan("*"))

	// Check cache first
	cacheKey := c.GetCacheKey(target, "enumerate")
	if cachedResults, found := c.CheckCache(ctx, cacheKey); found {
		if findings, ok := cachedResults.([]CloudFinding); ok {
			logger.Info("Using cached cloud enumeration results", "count", len(findings))
			c.displayCachedResults(findings)
			for _, finding := range findings {
				pluginResult := c.convertFindingToPluginResult(target, finding)
				results <- pluginResult
			}
			return nil
		}
	}

	// Execute cloud enumeration
	cloudOutput, err := c.executeCloudEnum(ctx, keyword, shared)
	if err != nil {
		fmt.Printf("\n%s\n", red("[GORECON::ERROR] Cloud enumeration failed"))
		fmt.Printf("%s\n", strings.Repeat("=", 40))
		fmt.Printf("[%s] %s\n", red("-"), err.Error())
		return fmt.Errorf("cloud enumeration failed: %w", err)
	}

	// Parse comprehensive results
	findings, summary, err := c.parseComprehensiveOutput(cloudOutput)
	if err != nil {
		logger.Warn("Failed to parse cloud_enum output", "error", err.Error())
		return fmt.Errorf("failed to parse output: %w", err)
	}
	
	// Log the number of findings captured
	logger.Info("Comprehensive parsing completed",
		"total_findings_parsed", len(findings),
		"aws_findings", c.countProviderResources(findings, "AWS"),
		"azure_findings", c.countProviderResources(findings, "Azure"),
		"google_findings", c.countProviderResources(findings, "Google"))

	// Display final summary (live results already shown during execution)
	c.displayFinalSummary(findings, summary)

	// Convert ALL findings to plugin results (don't filter any findings)
	validFindings := make([]CloudFinding, 0)
	for _, finding := range findings {
		// Accept ALL findings - every cloud resource discovered is valuable
		validFindings = append(validFindings, finding)
		pluginResult := c.convertFindingToPluginResult(target, finding)
		results <- pluginResult

		// Add discoveries for all findings
		c.AddDiscovery("cloud_resource", finding.URL, 0.9)
		if finding.Status == "Open" {
			c.AddDiscovery("open_cloud_resource", finding.URL, 0.95)
		} else if finding.Status == "Protected" || finding.Status == "HTTPS-Only" {
			c.AddDiscovery("protected_cloud_resource", finding.URL, 0.85)
		}
	}

	// Cache results
	c.SetCache(ctx, cacheKey, validFindings, 24*time.Hour)

	logger.Info("Cloud enumeration completed",
		"total_findings", len(validFindings),
		"critical", c.countCriticalFindings(validFindings))

	return nil
}

// executeCloudEnum runs the cloud_enum tool and returns raw output
func (c *CloudEnumPlugin) executeCloudEnum(ctx context.Context, keyword string, shared *core.SharedContext) ([]byte, error) {
	// Execute cloud_enum directly with python3
	scriptPath := "./cloud_enum/cloud_enum.py"

	// Build args - comprehensive scan ONLY (no quickscan for complete results)
	args := []string{scriptPath, "-k", keyword, "-t", "15"}

	// Comprehensive scan enabled - this takes 10-20 minutes but gives ALL results
	// NEVER use --quickscan as it gives incomplete/false results

	// Use python3 directly since BaseAdapter toolPath discovery is failing
	output, err := c.executeCommandDirect(ctx, "python3", args, shared)
	if err != nil {
		return nil, err
	}

	return output, nil
}

// executeCommandDirect executes a command with real-time output streaming
func (c *CloudEnumPlugin) executeCommandDirect(ctx context.Context, command string, args []string, shared *core.SharedContext) ([]byte, error) {
	cmd := exec.CommandContext(ctx, command, args...)

	logger := shared.GetLogger().WithField("plugin", "cloud_enum")
	logger.Info("Starting cloud_enum comprehensive scan",
		"command", command,
		"args", strings.Join(args, " "),
		"estimated_duration", "5-15 minutes")

	// Initialize color functions for live output
	red := color.New(color.FgRed).SprintFunc()
	yellow := color.New(color.FgYellow).SprintFunc()
	green := color.New(color.FgGreen).SprintFunc()
	cyan := color.New(color.FgCyan).SprintFunc()
	white := color.New(color.FgWhite, color.Bold).SprintFunc()

	fmt.Printf("\n[%s] Starting comprehensive cloud enumeration...\n", cyan("*"))
	fmt.Printf("[%s] Live results will appear below:\n\n", cyan("*"))

	// Setup pipes for real-time output
	stdout, err := cmd.StdoutPipe()
	if err != nil {
		return nil, fmt.Errorf("failed to create stdout pipe: %w", err)
	}

	stderr, err := cmd.StderrPipe()
	if err != nil {
		return nil, fmt.Errorf("failed to create stderr pipe: %w", err)
	}

	// Start the command
	if err := cmd.Start(); err != nil {
		return nil, fmt.Errorf("failed to start command: %w", err)
	}

	// Collect all output for parsing later
	var outputBuffer strings.Builder
	var realtimeFindings []string // Store findings seen in real-time
	var wg sync.WaitGroup
	var mu sync.Mutex

	startTime := time.Now()
	currentProvider := ""

	// Function to process each line in real-time
	processLine := func(line string, isStderr bool) {
		mu.Lock()
		defer mu.Unlock()

		// Add to buffer for later comprehensive parsing
		outputBuffer.WriteString(line + "\n")

		// Clean the line for display
		cleanLine := c.removeANSIColors(line)
		cleanLine = strings.TrimSpace(cleanLine)

		if cleanLine == "" {
			return
		}


		// Detect provider sections
		if strings.Contains(strings.ToLower(cleanLine), "amazon") || strings.Contains(strings.ToLower(cleanLine), "aws") {
			if currentProvider != "AWS" {
				currentProvider = "AWS"
				fmt.Printf("\n%s\n", white("[GORECON::CLOUD] Amazon AWS Enumeration"))
				fmt.Printf("%s\n", strings.Repeat("=", 40))
			}
		} else if strings.Contains(strings.ToLower(cleanLine), "azure") {
			if currentProvider != "Azure" {
				currentProvider = "Azure"
				fmt.Printf("\n%s\n", white("[GORECON::CLOUD] Azure Enumeration"))
				fmt.Printf("%s\n", strings.Repeat("=", 35))
			}
		} else if strings.Contains(strings.ToLower(cleanLine), "google") || strings.Contains(strings.ToLower(cleanLine), "gcp") {
			if currentProvider != "Google" {
				currentProvider = "Google"
				fmt.Printf("\n%s\n", white("[GORECON::CLOUD] Google Cloud Enumeration"))
				fmt.Printf("%s\n", strings.Repeat("=", 42))
			}
		}

		// Display progress and findings in real-time
		if strings.Contains(cleanLine, "Checking for") || strings.Contains(cleanLine, "Brute-forcing") {
			fmt.Printf("[%s] %s\n", cyan("*"), cleanLine)
		} else if strings.Contains(cleanLine, "Protected") || strings.Contains(cleanLine, "Open") ||
			strings.Contains(cleanLine, "Found") || strings.Contains(cleanLine, "HTTP-OK") ||
			strings.Contains(cleanLine, "Registered") || strings.Contains(cleanLine, "Unauthorized") ||
			strings.Contains(cleanLine, "AWS App") || strings.Contains(cleanLine, "Firebase RTDB") ||
			strings.Contains(cleanLine, "HTTPS-Only") || strings.Contains(cleanLine, "Account:") ||
			strings.Contains(cleanLine, "S3 Bucket:") || strings.Contains(cleanLine, "Bucket:") {

			// Parse and display the finding immediately based on actual cloud_enum patterns
			lowerLine := strings.ToLower(cleanLine)
			
			// Store this finding for comprehensive parsing
			realtimeFindings = append(realtimeFindings, cleanLine)
			
			if strings.Contains(lowerLine, "open") {
				fmt.Printf("    [%s] %s\n", red("CRITICAL"), cleanLine)
			} else if strings.Contains(lowerLine, "protected") {
				fmt.Printf("    [%s] %s\n", yellow("INFO"), cleanLine)
			} else if strings.Contains(lowerLine, "found") || strings.Contains(lowerLine, "registered") {
				fmt.Printf("    [%s] %s\n", green("MEDIUM"), cleanLine)
			} else if strings.Contains(lowerLine, "unauthorized") || strings.Contains(lowerLine, "unathorized") {
				fmt.Printf("    [%s] %s\n", yellow("MEDIUM"), cleanLine)
			} else if strings.Contains(lowerLine, "http-ok") {
				fmt.Printf("    [%s] %s\n", red("HIGH"), cleanLine)
			} else if strings.Contains(lowerLine, "https-only") {
				fmt.Printf("    [%s] %s\n", yellow("MEDIUM"), cleanLine)
			} else {
				fmt.Printf("    [%s] %s\n", cyan("LOW"), cleanLine)
			}
		} else if strings.Contains(cleanLine, "complete...") && strings.Contains(cleanLine, "/") {
			// Show progress exactly like cloud_enum tool
			fmt.Printf("    %s\r", cleanLine)
			// Force flush to show progress immediately
		} else if strings.Contains(cleanLine, "Elapsed time:") {
			// Show timing info
			fmt.Printf("    [%s] %s\n", cyan("*"), cleanLine)
		}
	}

	// Start goroutines to read stdout and stderr with character-level streaming
	wg.Add(2)

	go func() {
		defer wg.Done()
		reader := bufio.NewReader(stdout)
		var lineBuffer strings.Builder
		for {
			char, err := reader.ReadByte()
			if err != nil {
				break
			}
			
			if char == '\n' {
				// Complete line
				processLine(lineBuffer.String(), false)
				lineBuffer.Reset()
			} else if char == '\r' {
				// Progress update on same line
				line := lineBuffer.String()
				if strings.Contains(line, "complete...") {
					processLine(line, false)
				}
				lineBuffer.Reset()
			} else {
				lineBuffer.WriteByte(char)
			}
		}
		// Process any remaining content
		if lineBuffer.Len() > 0 {
			processLine(lineBuffer.String(), false)
		}
	}()

	go func() {
		defer wg.Done()
		scanner := bufio.NewScanner(stderr)
		for scanner.Scan() {
			processLine(scanner.Text(), true)
		}
	}()

	// Wait for command to complete
	cmdErr := cmd.Wait()
	wg.Wait() // Wait for all output to be processed

	duration := time.Since(startTime)
	output := outputBuffer.String()

	if cmdErr != nil {
		logger.Error("Cloud enumeration execution failed", cmdErr,
			"duration", duration,
			"output_size", len(output))

		if ctx.Err() == context.DeadlineExceeded {
			return nil, fmt.Errorf("cloud enumeration timed out after %v", duration)
		}

		return nil, fmt.Errorf("cloud enumeration failed after %v: %w", duration, cmdErr)
	}

	logger.Info("Cloud enumeration completed successfully",
		"duration", duration,
		"output_size", len(output))

	fmt.Printf("\n[%s] Cloud enumeration completed in %v\n", green("+"), duration.Round(time.Second))

	return []byte(output), nil
}

// extractDomainKeyword extracts the keyword from a domain for cloud_enum
func (c *CloudEnumPlugin) extractDomainKeyword(domain string) string {
	// Remove protocol if present
	domain = strings.TrimPrefix(domain, "https://")
	domain = strings.TrimPrefix(domain, "http://")

	// Remove www prefix
	domain = strings.TrimPrefix(domain, "www.")

	// Remove path and query parameters
	if idx := strings.Index(domain, "/"); idx != -1 {
		domain = domain[:idx]
	}
	if idx := strings.Index(domain, "?"); idx != -1 {
		domain = domain[:idx]
	}

	// Handle subdomains - extract main domain
	parts := strings.Split(domain, ".")
	if len(parts) >= 2 {
		// For domains like api.example.com or sub.example.com, extract "example"
		// For simple domains like example.com, extract "example"
		mainPart := parts[len(parts)-2]
		return mainPart
	}

	return domain
}

// parseComprehensiveOutput parses cloud_enum output into detailed findings
func (c *CloudEnumPlugin) parseComprehensiveOutput(output []byte) ([]CloudFinding, CloudEnumSummary, error) {
	var findings []CloudFinding
	var summary CloudEnumSummary

	lines := strings.Split(string(output), "\n")
	currentProvider := ""
	currentService := ""

	// Initialize provider stats
	summary.AWSResources.Services = make(map[string]int)
	summary.AzureResources.Services = make(map[string]int)
	summary.GoogleResources.Services = make(map[string]int)

	for _, line := range lines {
		line = strings.TrimSpace(line)
		if line == "" {
			continue
		}

		// Remove ANSI colors
		cleanLine := c.removeANSIColors(line)

		// Detect provider sections
		if strings.Contains(strings.ToLower(cleanLine), "amazon") || strings.Contains(strings.ToLower(cleanLine), "aws") {
			currentProvider = "AWS"
		} else if strings.Contains(strings.ToLower(cleanLine), "azure") {
			currentProvider = "Azure"
		} else if strings.Contains(strings.ToLower(cleanLine), "google") || strings.Contains(strings.ToLower(cleanLine), "gcp") {
			currentProvider = "Google"
		}

		// Detect service types from actual cloud_enum output patterns
		if strings.Contains(strings.ToLower(cleanLine), "s3") || strings.Contains(strings.ToLower(cleanLine), "bucket") {
			currentService = "S3/Storage"
		} else if strings.Contains(strings.ToLower(cleanLine), "blob") || strings.Contains(strings.ToLower(cleanLine), "storage account") {
			currentService = "Blob Storage"
		} else if strings.Contains(strings.ToLower(cleanLine), "file") && strings.Contains(strings.ToLower(cleanLine), "account") {
			currentService = "File Storage"
		} else if strings.Contains(strings.ToLower(cleanLine), "queue") && strings.Contains(strings.ToLower(cleanLine), "account") {
			currentService = "Queue Storage"
		} else if strings.Contains(strings.ToLower(cleanLine), "table") && strings.Contains(strings.ToLower(cleanLine), "account") {
			currentService = "Table Storage"
		} else if strings.Contains(strings.ToLower(cleanLine), "firebase") {
			currentService = "Firebase"
		} else if strings.Contains(strings.ToLower(cleanLine), "website") {
			currentService = "Website"
		} else if strings.Contains(strings.ToLower(cleanLine), "database") {
			currentService = "Database"
		} else if strings.Contains(strings.ToLower(cleanLine), "aws app") || strings.Contains(strings.ToLower(cleanLine), "awsapps") {
			currentService = "AWS Apps"
		} else if strings.Contains(strings.ToLower(cleanLine), "key vault") {
			currentService = "Key Vault"
		}

		// Parse findings
		finding := c.parseFindingLine(cleanLine, currentProvider, currentService)
		if finding != nil {
			findings = append(findings, *finding)
			c.updateProviderStats(&summary, currentProvider, currentService, finding.Status)
		}
	}

	// Calculate summary statistics
	summary.TotalResources = len(findings)
	summary.AWSResources.Total = c.countProviderResources(findings, "AWS")
	summary.AzureResources.Total = c.countProviderResources(findings, "Azure")
	summary.GoogleResources.Total = c.countProviderResources(findings, "Google")

	return findings, summary, nil
}

func (c *CloudEnumPlugin) parseCloudEnumOutput(output []byte) ([]CloudEnumResult, error) {
	var results []CloudEnumResult

	// Try parsing as JSON array first
	if err := json.Unmarshal(output, &results); err == nil {
		return results, nil
	}

	// Try parsing line by line
	lines := strings.Split(string(output), "\n")
	for _, line := range lines {
		line = strings.TrimSpace(line)
		if line == "" {
			continue
		}

		var result CloudEnumResult
		if err := json.Unmarshal([]byte(line), &result); err == nil {
			results = append(results, result)
		} else {
			// Parse text format as fallback
			if textResult := c.parseTextLine(line); textResult != nil {
				results = append(results, *textResult)
			}
		}
	}

	return results, nil
}

func (c *CloudEnumPlugin) parseTextLine(line string) *CloudEnumResult {
	// Remove ANSI color codes
	cleanLine := c.removeANSIColors(line)

	// Parse various cloud_enum output formats:

	// AWS S3 Buckets:
	// "Protected S3 Bucket: http://example.s3.amazonaws.com/"
	// "Open S3 Bucket: http://example.s3.amazonaws.com/" (for public buckets)
	if strings.Contains(cleanLine, "S3 Bucket:") {
		if urlStart := strings.Index(cleanLine, "http://"); urlStart != -1 {
			urlEnd := len(cleanLine)
			if idx := strings.Index(cleanLine[urlStart:], " "); idx != -1 {
				urlEnd = urlStart + idx
			}
			bucketURL := strings.TrimSuffix(cleanLine[urlStart:urlEnd], "/")

			// Extract bucket name from URL
			bucketName := c.extractBucketFromURL(bucketURL)
			if bucketName == "" {
				return nil
			}

			// Determine if public or protected
			public := strings.Contains(cleanLine, "Open S3 Bucket")

			return &CloudEnumResult{
				Service: "aws",
				Bucket:  bucketName,
				Public:  public,
				Exists:  true,
				URL:     bucketURL,
			}
		}
	}

	// Azure Storage Accounts:
	// "HTTP-OK Account: http://example.blob.core.windows.net/"
	// "HTTP-OK Account: http://example.file.core.windows.net/"
	// "HTTP-OK Account: http://example.queue.core.windows.net/"
	if strings.Contains(cleanLine, "HTTP-OK Account:") {
		if urlStart := strings.Index(cleanLine, "http://"); urlStart != -1 {
			urlEnd := len(cleanLine)
			if idx := strings.Index(cleanLine[urlStart:], " "); idx != -1 {
				urlEnd = urlStart + idx
			}
			accountURL := strings.TrimSuffix(cleanLine[urlStart:urlEnd], "/")

			// Extract account name from URL
			accountName := c.extractAzureAccountFromURL(accountURL)
			if accountName == "" {
				return nil
			}

			return &CloudEnumResult{
				Service: "azure",
				Bucket:  accountName,
				Public:  true, // HTTP-OK typically indicates accessible
				Exists:  true,
				URL:     accountURL,
			}
		}
	}

	// Azure Database Names:
	// "Registered Azure Database DNS Name: example.database.windows.net"
	if strings.Contains(cleanLine, "Registered Azure Database DNS Name:") {
		parts := strings.Split(cleanLine, ":")
		if len(parts) >= 2 {
			dnsName := strings.TrimSpace(parts[1])
			accountName := c.extractAzureDBFromDNS(dnsName)
			if accountName != "" {
				return &CloudEnumResult{
					Service: "azure",
					Bucket:  accountName,
					Public:  false, // Database typically not public
					Exists:  true,
					URL:     "https://" + dnsName,
				}
			}
		}
	}

	// Azure VM DNS Names:
	// "Registered Azure Virtual Machine DNS Name: example.eastus.cloudapp.azure.com"
	if strings.Contains(cleanLine, "Registered Azure Virtual Machine DNS Name:") {
		parts := strings.Split(cleanLine, ":")
		if len(parts) >= 2 {
			dnsName := strings.TrimSpace(parts[1])
			vmName := c.extractAzureVMFromDNS(dnsName)
			if vmName != "" {
				return &CloudEnumResult{
					Service: "azure",
					Bucket:  vmName,
					Public:  false, // VM typically not directly accessible
					Exists:  true,
					URL:     "https://" + dnsName,
				}
			}
		}
	}

	// GCP Storage Buckets (if found):
	// Similar patterns can be added for GCP

	return nil
}

func (c *CloudEnumPlugin) buildBucketURL(service, bucket string) string {
	switch service {
	case "aws", "s3":
		return fmt.Sprintf("https://%s.s3.amazonaws.com", bucket)
	case "gcp", "gcs":
		return fmt.Sprintf("https://storage.googleapis.com/%s", bucket)
	case "azure":
		return fmt.Sprintf("https://%s.blob.core.windows.net", bucket)
	default:
		return ""
	}
}

func (c *CloudEnumPlugin) convertToPluginResult(target *models.Target, result CloudEnumResult) models.PluginResult {
	severity := models.SeverityMedium
	if result.Public {
		severity = models.SeverityHigh
	}

	title := fmt.Sprintf("Cloud storage bucket found: %s", result.Bucket)
	if result.Public {
		title += " (PUBLIC)"
	}

	description := fmt.Sprintf("Discovered %s cloud storage bucket '%s'",
		strings.ToUpper(result.Service), result.Bucket)
	if result.Public {
		description += " with public read access"
	}

	data := map[string]interface{}{
		"service": result.Service,
		"bucket":  result.Bucket,
		"region":  result.Region,
		"public":  result.Public,
		"url":     result.URL,
		"exists":  result.Exists,
	}

	evidence := c.CreateEvidence("cloud_storage", result.URL, result.URL, 200, nil)

	pluginResult := c.CreateResult(target, title, description, severity, data)
	pluginResult.Evidence = evidence

	// Add tags
	pluginResult.AddTag("cloud-storage")
	pluginResult.AddTag(result.Service)
	if result.Public {
		pluginResult.AddTag("public")
		pluginResult.AddTag("exposure")
	}

	// Set risk score
	if result.Public {
		pluginResult.RiskScore = 8.5 // High risk for public buckets
	} else {
		pluginResult.RiskScore = 5.0 // Medium risk for private buckets
	}

	// Add MITRE ATT&CK mapping
	pluginResult.TTP = &models.MITRETechnique{
		ID:          "T1530",
		Name:        "Data from Cloud Storage Object",
		Tactic:      "Collection",
		Description: "Adversaries may access data objects from improperly secured cloud storage.",
	}

	return pluginResult
}

func (c *CloudEnumPlugin) countPublicBuckets(results []CloudEnumResult) int {
	count := 0
	for _, result := range results {
		if result.Public {
			count++
		}
	}
	return count
}

// ProcessDiscovery processes discoveries from other plugins
func (c *CloudEnumPlugin) ProcessDiscovery(ctx context.Context, discovery models.Discovery) error {
	// React to subdomain discoveries by checking for cloud storage
	if discovery.Type == models.DiscoveryTypeSubdomain {
		if _, ok := discovery.Value.(string); ok {
			// Could trigger additional enumeration here
			// For now, just log the discovery via shared context
		}
	}

	return nil
}

// parseFindingLine parses a single line from cloud_enum output into a finding
func (c *CloudEnumPlugin) parseFindingLine(line, provider, service string) *CloudFinding {
	// Skip progress lines
	if strings.Contains(line, "complete...") || strings.Contains(line, "Elapsed time:") {
		return nil
	}
	
	// Look for actual findings - must contain domain/URL patterns
	if !strings.Contains(line, "http") && !strings.Contains(line, "https") && !strings.Contains(line, ".com") && !strings.Contains(line, ".net") && !strings.Contains(line, ".org") {
		return nil
	}

	finding := &CloudFinding{
		Provider: provider,
		Service:  service,
		Files:    []string{},
		Details:  make(map[string]interface{}),
	}

	// Extract URL - handle both full URLs and domain names
	if urlStart := strings.Index(line, "http"); urlStart != -1 {
		urlEnd := len(line)
		if idx := strings.Index(line[urlStart:], " "); idx != -1 {
			urlEnd = urlStart + idx
		}
		finding.URL = strings.TrimSuffix(line[urlStart:urlEnd], "/")
		finding.ResourceName = c.extractResourceName(finding.URL)
	} else {
		// Handle domain-only findings like "Registered Azure Website DNS Name: example.azurewebsites.net"
		if colonIndex := strings.Index(line, ":"); colonIndex != -1 && colonIndex < len(line)-1 {
			domainPart := strings.TrimSpace(line[colonIndex+1:])
			// Clean up any trailing text
			if spaceIndex := strings.Index(domainPart, " "); spaceIndex != -1 {
				domainPart = domainPart[:spaceIndex]
			}
			if domainPart != "" && (strings.Contains(domainPart, ".") || strings.Contains(domainPart, "http")) {
				finding.URL = domainPart
				if !strings.HasPrefix(finding.URL, "http") {
					finding.URL = "https://" + finding.URL
				}
				finding.ResourceName = c.extractResourceName(finding.URL)
			}
		}
	}

	// Determine status and severity based on actual cloud_enum patterns
	lowerLine := strings.ToLower(line)
	if strings.Contains(lowerLine, "open") || strings.Contains(line, "OPEN") {
		finding.Status = "Open"
		finding.Severity = "Critical"
	} else if strings.Contains(lowerLine, "protected") {
		finding.Status = "Protected"
		finding.Severity = "Info"
	} else if strings.Contains(lowerLine, "found") || strings.Contains(lowerLine, "registered") || strings.Contains(lowerLine, "unauthorized") {
		finding.Status = "Found"
		finding.Severity = "Medium"
	} else if strings.Contains(lowerLine, "https-only") {
		finding.Status = "HTTPS-Only"
		finding.Severity = "Medium"
	} else if strings.Contains(lowerLine, "http-ok") {
		finding.Status = "HTTP-OK"
		finding.Severity = "High"
	} else if strings.Contains(lowerLine, "disabled") {
		finding.Status = "Disabled"
		finding.Severity = "Low"
	} else if strings.Contains(lowerLine, "registered") || strings.Contains(lowerLine, "found") {
		finding.Status = "Found"
		finding.Severity = "Info"
	} else if strings.Contains(lowerLine, "http-ok") {
		finding.Status = "Open"
		finding.Severity = "High"
	} else {
		finding.Status = "Unknown"
		finding.Severity = "Info"
	}

	// Check for file listings (indented lines after open buckets)
	// This would need to be handled in the main parser loop

	return finding
}

// updateProviderStats updates statistics for a cloud provider
func (c *CloudEnumPlugin) updateProviderStats(summary *CloudEnumSummary, provider, service, status string) {
	var stats *CloudProviderStats

	switch provider {
	case "AWS":
		stats = &summary.AWSResources
	case "Azure":
		stats = &summary.AzureResources
	case "Google":
		stats = &summary.GoogleResources
	default:
		return
	}

	if stats.Services[service] == 0 {
		stats.Services[service] = 0
	}
	stats.Services[service]++

	if status == "Open" || status == "HTTPS-Only" {
		stats.OpenCount++
	}
}

// countProviderResources counts resources for a specific provider
func (c *CloudEnumPlugin) countProviderResources(findings []CloudFinding, provider string) int {
	count := 0
	for _, finding := range findings {
		if finding.Provider == provider {
			count++
		}
	}
	return count
}

// extractResourceName extracts resource name from URL
func (c *CloudEnumPlugin) extractResourceName(url string) string {
	// Extract from S3 URLs
	if strings.Contains(url, ".s3.amazonaws.com") {
		url = strings.TrimPrefix(url, "https://")
		url = strings.TrimPrefix(url, "http://")
		parts := strings.Split(url, ".")
		if len(parts) > 0 {
			return parts[0]
		}
	}

	// Extract from Azure Storage URLs
	if strings.Contains(url, ".blob.core.windows.net") || strings.Contains(url, ".file.core.windows.net") {
		url = strings.TrimPrefix(url, "https://")
		url = strings.TrimPrefix(url, "http://")
		parts := strings.Split(url, ".")
		if len(parts) > 0 {
			return parts[0]
		}
	}

	// Extract from GCP URLs
	if strings.Contains(url, "storage.googleapis.com/") {
		parts := strings.Split(url, "/")
		for i, part := range parts {
			if part == "storage.googleapis.com" && i+1 < len(parts) {
				return parts[i+1]
			}
		}
	}

	return ""
}

// countCriticalFindings counts critical severity findings
func (c *CloudEnumPlugin) countCriticalFindings(findings []CloudFinding) int {
	count := 0
	for _, finding := range findings {
		if finding.Severity == "Critical" || finding.Severity == "High" {
			count++
		}
	}
	return count
}

// displayFinalSummary displays final summary after live results
func (c *CloudEnumPlugin) displayFinalSummary(findings []CloudFinding, summary CloudEnumSummary) {
	red := color.New(color.FgRed).SprintFunc()
	white := color.New(color.FgWhite, color.Bold).SprintFunc()

	// Group findings by provider for final count
	awsFindings := c.filterFindingsByProvider(findings, "AWS")
	azureFindings := c.filterFindingsByProvider(findings, "Azure")
	gcpFindings := c.filterFindingsByProvider(findings, "Google")

	// Display final summary
	fmt.Printf("\n%s\n", white("[GORECON::CLOUD] Final Summary"))
	fmt.Printf("%s\n", strings.Repeat("=", 30))
	fmt.Printf("Total Resources Found: %d\n\n", len(findings))

	criticalCount := c.countCriticalFindings(findings)
	if criticalCount > 0 {
		fmt.Printf("%s\n", white("Critical Findings:"))
		fmt.Printf("%s\n", strings.Repeat("-", 18))
		fmt.Printf("[%s] %d Critical/High severity resources found\n\n", red("!"), criticalCount)
	}

	if len(awsFindings) > 0 {
		fmt.Printf("AWS Resources: %d\n", len(awsFindings))
	}
	if len(azureFindings) > 0 {
		fmt.Printf("Azure Resources: %d\n", len(azureFindings))
	}
	if len(gcpFindings) > 0 {
		fmt.Printf("Google Resources: %d\n", len(gcpFindings))
	}
	fmt.Println()
}

// displayFormattedResults displays findings with GORECON styling (kept for cached results)
func (c *CloudEnumPlugin) displayFormattedResults(findings []CloudFinding, summary CloudEnumSummary) {
	red := color.New(color.FgRed).SprintFunc()
	white := color.New(color.FgWhite, color.Bold).SprintFunc()

	// Group findings by provider
	awsFindings := c.filterFindingsByProvider(findings, "AWS")
	azureFindings := c.filterFindingsByProvider(findings, "Azure")
	gcpFindings := c.filterFindingsByProvider(findings, "Google")

	// Display AWS findings
	if len(awsFindings) > 0 {
		fmt.Printf("\n%s\n", white("[GORECON::CLOUD] Amazon AWS Enumeration"))
		fmt.Printf("%s\n", strings.Repeat("=", 40))
		c.displayProviderFindings(awsFindings)
	}

	// Display Azure findings
	if len(azureFindings) > 0 {
		fmt.Printf("\n%s\n", white("[GORECON::CLOUD] Azure Enumeration"))
		fmt.Printf("%s\n", strings.Repeat("=", 35))
		c.displayProviderFindings(azureFindings)
	}

	// Display Google findings
	if len(gcpFindings) > 0 {
		fmt.Printf("\n%s\n", white("[GORECON::CLOUD] Google Cloud Enumeration"))
		fmt.Printf("%s\n", strings.Repeat("=", 42))
		c.displayProviderFindings(gcpFindings)
	}

	// Display summary
	fmt.Printf("\n%s\n", white("[GORECON::CLOUD] Summary"))
	fmt.Printf("%s\n", strings.Repeat("=", 24))
	fmt.Printf("Total Resources Found: %d\n\n", summary.TotalResources)

	criticalCount := c.countCriticalFindings(findings)
	if criticalCount > 0 {
		fmt.Printf("%s\n", white("Critical Findings:"))
		fmt.Printf("%s\n", strings.Repeat("-", 18))
		fmt.Printf("[%s] %d Critical/High severity resources found\n\n", red("!"), criticalCount)
	}

	if len(awsFindings) > 0 {
		fmt.Printf("AWS Resources: %d\n", len(awsFindings))
	}
	if len(azureFindings) > 0 {
		fmt.Printf("Azure Resources: %d\n", len(azureFindings))
	}
	if len(gcpFindings) > 0 {
		fmt.Printf("Google Resources: %d\n", len(gcpFindings))
	}
}

// filterFindingsByProvider filters findings for a specific provider
func (c *CloudEnumPlugin) filterFindingsByProvider(findings []CloudFinding, provider string) []CloudFinding {
	var filtered []CloudFinding
	for _, finding := range findings {
		if finding.Provider == provider {
			filtered = append(filtered, finding)
		}
	}
	return filtered
}

// displayProviderFindings displays findings for a provider
func (c *CloudEnumPlugin) displayProviderFindings(findings []CloudFinding) {
	red := color.New(color.FgRed).SprintFunc()
	yellow := color.New(color.FgYellow).SprintFunc()
	green := color.New(color.FgGreen).SprintFunc()
	cyan := color.New(color.FgCyan).SprintFunc()

	currentService := ""
	for _, finding := range findings {
		// Print service header if changed
		if finding.Service != currentService {
			currentService = finding.Service
			fmt.Printf("[%s] Checking %s...\n", cyan("*"), finding.Service)
		}

		// Display finding with appropriate color
		var symbol string
		var symbolColor func(...interface{}) string

		switch finding.Status {
		case "Open":
			symbol = "!"
			symbolColor = red
		case "Protected":
			symbol = "-"
			symbolColor = yellow
		case "Found":
			symbol = "+"
			symbolColor = green
		case "HTTPS-Only":
			symbol = "!"
			symbolColor = yellow
		default:
			symbol = "-"
			symbolColor = yellow
		}

		fmt.Printf("    [%s] %s: %s\n", symbolColor(symbol), strings.ToUpper(finding.Status), finding.URL)

		// Display file listings if available
		for _, file := range finding.Files {
			fmt.Printf("        ├─ %s\n", file)
		}
	}
}

// displayCachedResults displays cached results
func (c *CloudEnumPlugin) displayCachedResults(findings []CloudFinding) {
	green := color.New(color.FgGreen).SprintFunc()

	fmt.Printf("[%s] Using cached results (%d findings)\n", green("+"), len(findings))

	// Still display the results for user visibility
	summary := CloudEnumSummary{TotalResources: len(findings)}
	c.displayFormattedResults(findings, summary)
}

// convertFindingToPluginResult converts CloudFinding to PluginResult
func (c *CloudEnumPlugin) convertFindingToPluginResult(target *models.Target, finding CloudFinding) models.PluginResult {
	title := fmt.Sprintf("Cloud resource found: %s (%s)", finding.ResourceName, finding.Provider)

	description := fmt.Sprintf("Discovered %s %s resource '%s' with status: %s",
		finding.Provider, finding.Service, finding.ResourceName, finding.Status)

	data := map[string]interface{}{
		"provider":      finding.Provider,
		"service":       finding.Service,
		"url":           finding.URL,
		"status":        finding.Status,
		"resource_name": finding.ResourceName,
		"files":         finding.Files,
		"details":       finding.Details,
	}

	evidence := c.CreateEvidence("cloud_resource", finding.URL, finding.URL, 200, nil)

	pluginResult := c.CreateResult(target, title, description, finding.Severity, data)
	pluginResult.Evidence = evidence

	// Add tags
	pluginResult.AddTag("cloud-resource")
	pluginResult.AddTag(strings.ToLower(finding.Provider))
	pluginResult.AddTag(strings.ToLower(finding.Service))
	if finding.Status == "Open" {
		pluginResult.AddTag("public")
		pluginResult.AddTag("exposure")
	}

	// Set risk score based on severity
	switch finding.Severity {
	case "Critical":
		pluginResult.RiskScore = 9.0
	case "High":
		pluginResult.RiskScore = 7.5
	case "Medium":
		pluginResult.RiskScore = 5.0
	case "Low":
		pluginResult.RiskScore = 2.0
	default:
		pluginResult.RiskScore = 3.0
	}

	return pluginResult
}

// extractDomainName extracts the domain name from a URL or domain string
func (c *CloudEnumPlugin) extractDomainName(target string) string {
	// Remove protocol if present
	domain := strings.TrimPrefix(target, "https://")
	domain = strings.TrimPrefix(domain, "http://")

	// Remove www prefix
	domain = strings.TrimPrefix(domain, "www.")

	// Remove path and query parameters
	if idx := strings.Index(domain, "/"); idx != -1 {
		domain = domain[:idx]
	}
	if idx := strings.Index(domain, "?"); idx != -1 {
		domain = domain[:idx]
	}

	// Extract just the domain name part (remove subdomains for keyword)
	parts := strings.Split(domain, ".")
	if len(parts) >= 2 {
		// Return domain without TLD for keyword (e.g., "example" from "example.com")
		return parts[len(parts)-2]
	}

	return domain
}

// removeANSIColors removes ANSI escape sequences from text
func (c *CloudEnumPlugin) removeANSIColors(text string) string {
	// Remove all ANSI escape sequences
	for {
		start := strings.Index(text, "\x1b[")
		if start == -1 {
			// Also look for patterns like [1m, [33m, [92m, [0m without escape char
			patterns := []string{"[1m", "[0m", "[33m", "[92m", "[91m", "[32m", "[31m", "[34m", "[35m", "[36m", "[37m"}
			found := false
			for _, pattern := range patterns {
				if idx := strings.Index(text, pattern); idx != -1 {
					text = strings.Replace(text, pattern, "", 1)
					found = true
					break
				}
			}
			if !found {
				break
			}
			continue
		}

		end := start + 1
		for end < len(text) && text[end] != 'm' {
			end++
		}
		if end < len(text) {
			end++ // Include the 'm'
		}

		text = text[:start] + text[end:]
	}
	return text
}

// extractBucketFromURL extracts bucket name from S3 URL
func (c *CloudEnumPlugin) extractBucketFromURL(url string) string {
	// Remove protocol
	url = strings.TrimPrefix(url, "http://")
	url = strings.TrimPrefix(url, "https://")

	// Extract bucket name from URLs like "example.s3.amazonaws.com/"
	if strings.Contains(url, ".s3.amazonaws.com") {
		parts := strings.Split(url, ".")
		if len(parts) > 0 {
			return parts[0]
		}
	}

	return ""
}

// extractAzureAccountFromURL extracts account name from Azure storage URL
func (c *CloudEnumPlugin) extractAzureAccountFromURL(url string) string {
	// Remove protocol
	url = strings.TrimPrefix(url, "http://")
	url = strings.TrimPrefix(url, "https://")

	// Extract account name from URLs like:
	// "example.blob.core.windows.net"
	// "example.file.core.windows.net"
	// "example.queue.core.windows.net"
	if strings.Contains(url, ".core.windows.net") {
		parts := strings.Split(url, ".")
		if len(parts) > 0 {
			return parts[0]
		}
	}

	return ""
}

// extractAzureDBFromDNS extracts database name from Azure database DNS
func (c *CloudEnumPlugin) extractAzureDBFromDNS(dns string) string {
	// Extract database name from DNS like "example.database.windows.net"
	if strings.Contains(dns, ".database.windows.net") {
		parts := strings.Split(dns, ".")
		if len(parts) > 0 {
			return parts[0]
		}
	}

	return ""
}

// extractAzureVMFromDNS extracts VM name from Azure VM DNS
func (c *CloudEnumPlugin) extractAzureVMFromDNS(dns string) string {
	// Extract VM name from DNS like "example.eastus.cloudapp.azure.com"
	if strings.Contains(dns, ".cloudapp.azure.com") {
		parts := strings.Split(dns, ".")
		if len(parts) > 0 {
			return parts[0]
		}
	}

	return ""
}

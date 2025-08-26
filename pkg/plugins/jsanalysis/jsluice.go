package jsanalysis

import (
	"bufio"
	"context"
	"crypto/tls"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/fatih/color"
	"github.com/f2u0a0d3/GoRecon/pkg/core"
	"github.com/f2u0a0d3/GoRecon/pkg/models"
	"github.com/f2u0a0d3/GoRecon/pkg/plugins/base"
)

// JSAnalysisPlugin implements JavaScript analysis and endpoint discovery
type JSAnalysisPlugin struct {
	*base.BaseAdapter
	config *JSAnalysisConfig
}

// JSAnalysisConfig contains JavaScript analysis configuration
type JSAnalysisConfig struct {
	EnableJsluice    bool          `json:"enable_jsluice"`
	EnableLinkfinder bool          `json:"enable_linkfinder"`
	Threads          int           `json:"threads"`
	Timeout          time.Duration `json:"timeout"`
	MaxDepth         int           `json:"max_depth"`
	FollowRedirects  bool          `json:"follow_redirects"`
}

// JSResult represents a JavaScript analysis result
type JSResult struct {
	URL         string            `json:"url"`
	Endpoints   []string          `json:"endpoints"`
	Secrets     []SecretResult    `json:"secrets"`
	Functions   []string          `json:"functions"`
	Variables   []string          `json:"variables"`
	Comments    []string          `json:"comments"`
	Imports     []string          `json:"imports"`
	SourceMaps  []string          `json:"source_maps"`
	Metadata    map[string]string `json:"metadata"`
	Tool        string            `json:"tool"`
	Timestamp   time.Time         `json:"timestamp"`
	Confidence  float64           `json:"confidence"`
}

// SecretResult represents a discovered secret in JavaScript
type SecretResult struct {
	Type        string `json:"type"`
	Value       string `json:"value"`
	Line        int    `json:"line"`
	Context     string `json:"context"`
	Confidence  float64 `json:"confidence"`
}

// JSAnalysisStats contains JavaScript analysis statistics
type JSAnalysisStats struct {
	TotalURLs     int                    `json:"total_urls"`
	AnalyzedURLs  int                    `json:"analyzed_urls"`
	TotalEndpoints int                   `json:"total_endpoints"`
	TotalSecrets  int                    `json:"total_secrets"`
	ByTool        map[string]int         `json:"by_tool"`
	BySecretType  map[string]int         `json:"by_secret_type"`
	Duration      time.Duration          `json:"duration"`
}

// ToolScanResult represents results from individual tools
type ToolScanResult struct {
	Tool     string     `json:"tool"`
	Results  []JSResult `json:"results"`
	Error    error      `json:"error,omitempty"`
	Duration time.Duration `json:"duration"`
}

// NewJSAnalysisPlugin creates a new JavaScript analysis plugin
func NewJSAnalysisPlugin() *JSAnalysisPlugin {
	config := &JSAnalysisConfig{
		EnableJsluice:    true,
		EnableLinkfinder: true,
		Threads:          10,
		Timeout:          30 * time.Second,
		MaxDepth:         3,
		FollowRedirects:  true,
	}

	baseAdapter := base.NewBaseAdapter(base.BaseAdapterConfig{
		Name:        "jsanalysis",
		Category:    "js",
		Description: "JavaScript analysis and endpoint discovery",
		Version:     "1.0.0",
		Author:      "GoRecon Team",
		ToolName:    "jsluice",
		Passive:     false,
		Duration:    30 * time.Minute,
		Concurrency: 1,
		Priority:    8,
		Resources: core.Resources{
			CPUCores:      2,
			MemoryMB:      1024,
			NetworkAccess: true,
		},
		Provides: []string{"js_endpoints", "js_secrets", "js_functions"},
		Consumes: []string{"http_services", "urls"},
	})

	return &JSAnalysisPlugin{
		BaseAdapter: baseAdapter,
		config:      config,
	}
}

// Run executes JavaScript analysis
func (j *JSAnalysisPlugin) Run(ctx context.Context, target *models.Target, results chan<- models.PluginResult, shared *core.SharedContext) error {
	logger := shared.GetLogger().WithField("plugin", "jsanalysis")
	
	cyan := color.New(color.FgCyan).SprintFunc()
	white := color.New(color.FgWhite, color.Bold).SprintFunc()

	domain := target.Domain
	if domain == "" {
		domain = j.ExtractDomain(target.URL)
	}

	fmt.Printf("\n%s\n", white("[GORECON] JavaScript Analyzer v1.0"))
	fmt.Printf("%s\n", strings.Repeat("=", 32))
	fmt.Printf("[%s] Using jsluice and linkfinder for JavaScript analysis\n", cyan("*"))

	jsURLs := j.collectJavaScriptURLs(shared, domain, target)
	fmt.Printf("[%s] Analyzing %d JavaScript URLs from previous steps...\n\n", cyan("*"), len(jsURLs))

	workDir := filepath.Join("./work", domain, "jsanalysis")
	if err := os.MkdirAll(workDir, 0755); err != nil {
		return fmt.Errorf("failed to create workspace: %w", err)
	}
	
	rawDir := filepath.Join(workDir, "raw")
	if err := os.MkdirAll(rawDir, 0755); err != nil {
		return fmt.Errorf("failed to create directory: %w", err)
	}

	jsResults, stats, err := j.runJSAnalysis(ctx, jsURLs, rawDir)
	if err != nil {
		logger.Error("JavaScript analysis failed", err)
		return err
	}

	j.displayResults(jsResults, stats)
	j.generatePluginResults(target, jsResults, results)
	j.addDiscoveries(shared, domain, jsResults)

	logger.Info("JavaScript analysis completed",
		"target", domain,
		"analyzed_urls", stats.AnalyzedURLs,
		"total_endpoints", stats.TotalEndpoints,
		"total_secrets", stats.TotalSecrets)

	return nil
}

func (j *JSAnalysisPlugin) collectJavaScriptURLs(shared *core.SharedContext, domain string, target *models.Target) []string {
	urlSet := make(map[string]bool)
	cyan := color.New(color.FgCyan).SprintFunc()

	// First, try to parse HTML from the target to find actual JS files
	if target.URL != "" && strings.HasPrefix(target.URL, "http") {
		fmt.Printf("[%s] Fetching HTML from %s to discover JavaScript files...\n", cyan("*"), target.URL)
		jsURLs := j.extractJavaScriptFromHTML(target.URL)
		for _, url := range jsURLs {
			urlSet[url] = true
		}
		fmt.Printf("[%s] Found %d JavaScript files from HTML analysis\n", cyan("*"), len(jsURLs))
	}

	// Add common JS paths for the target domain (only if HTML parsing found nothing)
	if len(urlSet) == 0 {
		fmt.Printf("[%s] No JS files found in HTML, checking common paths...\n", cyan("*"))
		commonPaths := []string{
			"/js/main.js", "/js/app.js", "/js/bundle.js", "/js/script.js",
			"/assets/js/main.js", "/assets/js/app.js", "/static/js/main.js",
			"/dist/js/main.js", "/build/js/main.js",
			// Add httpbin.org specific paths
			"/flasgger_static/swagger-ui-bundle.js",
			"/flasgger_static/swagger-ui-standalone-preset.js",
			"/flasgger_static/lib/jquery.min.js",
		}

		baseURL := target.URL
		if baseURL == "" {
			baseURL = fmt.Sprintf("https://%s", domain)
		}
		baseURL = strings.TrimRight(baseURL, "/")

		for _, path := range commonPaths {
			testURL := baseURL + path
			// Test if the JS file actually exists
			if j.verifyJSFileExists(testURL) {
				urlSet[testURL] = true
				fmt.Printf("[%s] Verified JS file exists: %s\n", cyan("+"), testURL)
			}
		}
	}

	// Collect JS URLs from discoveries
	discoveries := shared.GetDiscoveries("")
	for _, discovery := range discoveries {
		value, ok := discovery.Value.(string)
		if !ok {
			continue
		}

		switch discovery.Type {
		case "http_service", "historical_url":
			if strings.Contains(value, domain) && (strings.Contains(value, ".js") || strings.Contains(value, "javascript")) {
				urlSet[value] = true
			}
		case "endpoint":
			if strings.Contains(value, domain) && strings.HasSuffix(value, ".js") {
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

func (j *JSAnalysisPlugin) extractJavaScriptFromHTML(targetURL string) []string {
	client := &http.Client{
		Timeout: 10 * time.Second,
		Transport: &http.Transport{
			TLSClientConfig: &tls.Config{InsecureSkipVerify: true},
		},
	}

	resp, err := client.Get(targetURL)
	if err != nil {
		return nil
	}
	defer resp.Body.Close()

	if resp.StatusCode != 200 {
		return nil
	}

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil
	}

	var jsURLs []string
	baseURL := targetURL
	if u, err := url.Parse(targetURL); err == nil {
		baseURL = fmt.Sprintf("%s://%s", u.Scheme, u.Host)
	}

	// Parse HTML to find script tags
	content := string(body)
	
	// Find script tags with src attribute
	scriptRegex := regexp.MustCompile(`<script[^>]+src=["']([^"']+)["'][^>]*>`)
	matches := scriptRegex.FindAllStringSubmatch(content, -1)
	
	for _, match := range matches {
		if len(match) > 1 {
			scriptSrc := match[1]
			
			// Convert relative URLs to absolute
			if strings.HasPrefix(scriptSrc, "//") {
				if u, err := url.Parse(targetURL); err == nil {
					scriptSrc = u.Scheme + ":" + scriptSrc
				}
			} else if strings.HasPrefix(scriptSrc, "/") {
				scriptSrc = baseURL + scriptSrc
			} else if !strings.HasPrefix(scriptSrc, "http") {
				scriptSrc = baseURL + "/" + scriptSrc
			}
			
			// Only include .js files
			if strings.HasSuffix(scriptSrc, ".js") || strings.Contains(scriptSrc, ".js?") {
				jsURLs = append(jsURLs, scriptSrc)
			}
		}
	}
	
	// Also find inline JavaScript that might reference external JS files
	jsRefRegex := regexp.MustCompile(`["']([^"']*\.js(?:\?[^"']*)??)["']`)
	jsMatches := jsRefRegex.FindAllStringSubmatch(content, -1)
	
	for _, match := range jsMatches {
		if len(match) > 1 {
			jsRef := match[1]
			
			// Skip if it's already a full URL or looks like a script tag
			if strings.HasPrefix(jsRef, "http") || strings.Contains(jsRef, "<") {
				continue
			}
			
			// Convert to absolute URL
			if strings.HasPrefix(jsRef, "/") {
				jsRef = baseURL + jsRef
			} else {
				jsRef = baseURL + "/" + jsRef
			}
			
			jsURLs = append(jsURLs, jsRef)
		}
	}

	// Remove duplicates
	urlSet := make(map[string]bool)
	var uniqueURLs []string
	for _, jsURL := range jsURLs {
		if !urlSet[jsURL] {
			urlSet[jsURL] = true
			uniqueURLs = append(uniqueURLs, jsURL)
		}
	}

	return uniqueURLs
}

func (j *JSAnalysisPlugin) verifyJSFileExists(jsURL string) bool {
	client := &http.Client{
		Timeout: 5 * time.Second,
		Transport: &http.Transport{
			TLSClientConfig: &tls.Config{InsecureSkipVerify: true},
		},
	}

	req, err := http.NewRequest("HEAD", jsURL, nil)
	if err != nil {
		return false
	}

	req.Header.Set("User-Agent", "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36")
	
	resp, err := client.Do(req)
	if err != nil {
		return false
	}
	defer resp.Body.Close()

	// Consider 200 OK and 403 Forbidden as existing files
	// 403 might mean the file exists but access is restricted
	return resp.StatusCode == 200 || resp.StatusCode == 403
}

func (j *JSAnalysisPlugin) runJSAnalysis(ctx context.Context, jsURLs []string, rawDir string) ([]JSResult, JSAnalysisStats, error) {
	white := color.New(color.FgWhite, color.Bold).SprintFunc()
	cyan := color.New(color.FgCyan).SprintFunc()

	fmt.Printf("%s\n", white("[GORECON::JS] JavaScript Analysis"))
	fmt.Printf("%s\n", strings.Repeat("=", 35))

	startTime := time.Now()
	var allResults []JSResult
	var wg sync.WaitGroup
	var mu sync.Mutex

	// Define analysis tools
	analysisTools := []struct {
		name    string
		enabled bool
		fn      func() ToolScanResult
	}{
		{"jsluice", j.config.EnableJsluice, func() ToolScanResult { return j.runJsluice(ctx, jsURLs, rawDir) }},
		{"linkfinder", j.config.EnableLinkfinder, func() ToolScanResult { return j.runLinkfinder(ctx, jsURLs, rawDir) }},
	}

	// Run enabled tools in parallel
	toolResults := make([]ToolScanResult, 0)
	for _, tool := range analysisTools {
		if !tool.enabled {
			continue
		}

		wg.Add(1)
		go func(toolName string, toolFn func() ToolScanResult) {
			defer wg.Done()
			
			fmt.Printf("[%s] Running %s analysis...\n", cyan("*"), toolName)
			result := toolFn()
			
			mu.Lock()
			toolResults = append(toolResults, result)
			mu.Unlock()
			
			if result.Error != nil {
				fmt.Printf("[%s] %s analysis failed: %v\n", cyan("-"), toolName, result.Error)
			} else {
				fmt.Printf("[%s] %s found %d results\n", cyan("+"), toolName, len(result.Results))
			}
		}(tool.name, tool.fn)
	}

	wg.Wait()

	// Merge and deduplicate results
	resultMap := make(map[string]*JSResult)
	for _, toolResult := range toolResults {
		for _, result := range toolResult.Results {
			existing, exists := resultMap[result.URL]
			if exists {
				// Merge results from multiple tools
				existing.Endpoints = j.mergeStringSlices(existing.Endpoints, result.Endpoints)
				existing.Secrets = j.mergeSecrets(existing.Secrets, result.Secrets)
				existing.Functions = j.mergeStringSlices(existing.Functions, result.Functions)
				existing.Variables = j.mergeStringSlices(existing.Variables, result.Variables)
				existing.Comments = j.mergeStringSlices(existing.Comments, result.Comments)
				existing.Imports = j.mergeStringSlices(existing.Imports, result.Imports)
				existing.SourceMaps = j.mergeStringSlices(existing.SourceMaps, result.SourceMaps)
				existing.Confidence = (existing.Confidence + result.Confidence) / 2
			} else {
				resultCopy := result
				resultMap[result.URL] = &resultCopy
			}
		}
	}

	// Convert map to slice
	for _, result := range resultMap {
		allResults = append(allResults, *result)
	}

	// Generate statistics
	stats := JSAnalysisStats{
		TotalURLs:      len(jsURLs),
		AnalyzedURLs:   len(allResults),
		ByTool:         make(map[string]int),
		BySecretType:   make(map[string]int),
		Duration:       time.Since(startTime),
	}

	for _, result := range allResults {
		stats.TotalEndpoints += len(result.Endpoints)
		stats.TotalSecrets += len(result.Secrets)
		stats.ByTool[result.Tool]++
		
		for _, secret := range result.Secrets {
			stats.BySecretType[secret.Type]++
		}
	}

	return allResults, stats, nil
}

func (j *JSAnalysisPlugin) runJsluice(ctx context.Context, jsURLs []string, rawDir string) ToolScanResult {
	red := color.New(color.FgRed).SprintFunc()
	cyan := color.New(color.FgCyan).SprintFunc()

	if _, err := exec.LookPath("jsluice"); err != nil {
		fmt.Printf("[%s] jsluice not found\n", red("!"))
		fmt.Printf("[%s] Install: go install github.com/BishopFox/jsluice/cmd/jsluice@latest\n", cyan("*"))
		return ToolScanResult{
			Tool:    "jsluice",
			Results: []JSResult{},
			Error:   fmt.Errorf("jsluice not installed"),
		}
	}

	startTime := time.Now()
	var results []JSResult

	// Save URLs to file
	inputFile := filepath.Join(rawDir, "js_urls.txt")
	if err := j.saveURLsToFile(jsURLs, inputFile); err != nil {
		return ToolScanResult{Tool: "jsluice", Results: []JSResult{}, Error: err}
	}

	// Run jsluice for each URL
	var allJsluiceResults []JSResult
	
	for _, url := range jsURLs {
		// For HTTP URLs, jsluice can fetch directly
		args := []string{
			"urls", 
			"-c", strconv.Itoa(j.config.Threads),
			url,
		}
		
		cmd := exec.CommandContext(ctx, "jsluice", args...)
		output, err := cmd.Output()
		if err != nil {
			fmt.Printf("[%s] jsluice failed for URL %s: %v\n", red("-"), url, err)
			continue
		}
		
		// Parse jsluice JSON output directly
		jsluiceResults, err := j.parseJsluiceJSONOutput(output, url)
		if err != nil {
			fmt.Printf("[%s] Failed to parse jsluice output for %s: %v\n", red("-"), url, err)
			continue
		}
		
		allJsluiceResults = append(allJsluiceResults, jsluiceResults...)
	}

	results = append(results, allJsluiceResults...)

	return ToolScanResult{
		Tool:     "jsluice",
		Results:  results,
		Duration: time.Since(startTime),
	}
}

func (j *JSAnalysisPlugin) runLinkfinder(ctx context.Context, jsURLs []string, rawDir string) ToolScanResult {
	red := color.New(color.FgRed).SprintFunc()
	cyan := color.New(color.FgCyan).SprintFunc()

	// Check for linkfinder (Python tool) - check both PATH and ~/bin
	linkfinderPath := "linkfinder"
	if _, err := exec.LookPath("linkfinder"); err != nil {
		// Try ~/bin/linkfinder
		homeDir, _ := os.UserHomeDir()
		altPath := filepath.Join(homeDir, "bin", "linkfinder")
		if _, err := os.Stat(altPath); err != nil {
			fmt.Printf("[%s] linkfinder not found\n", red("!"))
			fmt.Printf("[%s] Install: pip install linkfinder\n", cyan("*"))
			return ToolScanResult{
				Tool:    "linkfinder",
				Results: []JSResult{},
				Error:   fmt.Errorf("linkfinder not installed"),
			}
		}
		linkfinderPath = altPath
	}

	startTime := time.Now()
	var results []JSResult

	// Run linkfinder for each URL
	for _, jsURL := range jsURLs {
		outputFile := filepath.Join(rawDir, fmt.Sprintf("linkfinder_%d.txt", time.Now().UnixNano()))
		
		args := []string{
			"-i", jsURL,
			"-o", outputFile,
		}

		cmd := exec.CommandContext(ctx, linkfinderPath, args...)
		if err := cmd.Run(); err != nil {
			continue // Skip failed URLs
		}

		// Parse linkfinder output
		linkfinderResults, err := j.parseLinkfinderOutput(outputFile, jsURL)
		if err != nil {
			continue
		}

		results = append(results, linkfinderResults...)
		
		// Clean up temporary file
		os.Remove(outputFile)
	}

	return ToolScanResult{
		Tool:     "linkfinder",
		Results:  results,
		Duration: time.Since(startTime),
	}
}

func (j *JSAnalysisPlugin) parseJsluiceJSONOutput(output []byte, sourceURL string) ([]JSResult, error) {
	var results []JSResult
	lines := strings.Split(string(output), "\n")

	for _, line := range lines {
		line = strings.TrimSpace(line)
		if line == "" {
			continue
		}

		var raw map[string]interface{}
		if err := json.Unmarshal([]byte(line), &raw); err != nil {
			continue
		}

		result := JSResult{
			URL:        sourceURL,
			Tool:       "jsluice",
			Timestamp:  time.Now(),
			Confidence: 0.8,
			Metadata:   make(map[string]string),
		}

		// Extract URL from jsluice output
		if url, ok := raw["url"].(string); ok {
			result.Endpoints = append(result.Endpoints, url)
			
			// Categorize the finding type
			if method, hasMethod := raw["method"].(string); hasMethod && method != "" {
				result.Metadata["method"] = method
			}
			
			if findingType, hasType := raw["type"].(string); hasType {
				result.Metadata["type"] = findingType
			}
		}

		results = append(results, result)
	}

	return results, nil
}

func (j *JSAnalysisPlugin) parseJsluiceOutput(filename string) ([]JSResult, error) {
	data, err := os.ReadFile(filename)
	if err != nil {
		return nil, err
	}

	var results []JSResult
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

		result := JSResult{
			Tool:       "jsluice",
			Timestamp:  time.Now(),
			Confidence: 0.8,
			Metadata:   make(map[string]string),
		}

		if url, ok := raw["url"].(string); ok {
			result.URL = url
		}

		if endpoints, ok := raw["endpoints"].([]interface{}); ok {
			for _, ep := range endpoints {
				if epStr, ok := ep.(string); ok {
					result.Endpoints = append(result.Endpoints, epStr)
				}
			}
		}

		if secrets, ok := raw["secrets"].([]interface{}); ok {
			for _, secret := range secrets {
				if secretMap, ok := secret.(map[string]interface{}); ok {
					secretResult := SecretResult{
						Type:       getStringFromMap(secretMap, "type"),
						Value:      getStringFromMap(secretMap, "value"),
						Context:    getStringFromMap(secretMap, "context"),
						Confidence: 0.7,
					}
					if line, ok := secretMap["line"].(float64); ok {
						secretResult.Line = int(line)
					}
					result.Secrets = append(result.Secrets, secretResult)
				}
			}
		}

		results = append(results, result)
	}

	return results, nil
}

func (j *JSAnalysisPlugin) parseLinkfinderOutput(filename, jsURL string) ([]JSResult, error) {
	data, err := os.ReadFile(filename)
	if err != nil {
		return nil, err
	}

	result := JSResult{
		URL:        jsURL,
		Tool:       "linkfinder",
		Timestamp:  time.Now(),
		Confidence: 0.75,
		Metadata:   make(map[string]string),
	}

	lines := strings.Split(string(data), "\n")
	for _, line := range lines {
		line = strings.TrimSpace(line)
		if line == "" {
			continue
		}
		
		// Linkfinder outputs endpoints, one per line
		if strings.HasPrefix(line, "/") || strings.HasPrefix(line, "http") {
			result.Endpoints = append(result.Endpoints, line)
		}
	}

	if len(result.Endpoints) == 0 {
		return []JSResult{}, nil
	}

	return []JSResult{result}, nil
}

func (j *JSAnalysisPlugin) saveURLsToFile(urls []string, filename string) error {
	file, err := os.Create(filename)
	if err != nil {
		return err
	}
	defer file.Close()

	writer := bufio.NewWriter(file)
	defer writer.Flush()

	for _, url := range urls {
		if _, err := writer.WriteString(url + "\n"); err != nil {
			return err
		}
	}
	return nil
}

func (j *JSAnalysisPlugin) displayResults(results []JSResult, stats JSAnalysisStats) {
	green := color.New(color.FgGreen).SprintFunc()
	yellow := color.New(color.FgYellow).SprintFunc()

	for _, result := range results {
		fmt.Printf("[%s] %s [%s]\n", green("+"), result.URL, result.Tool)
		
		if len(result.Endpoints) > 0 {
			fmt.Printf("    Endpoints (%d): %s\n", len(result.Endpoints), 
				strings.Join(result.Endpoints[:min(5, len(result.Endpoints))], ", "))
			if len(result.Endpoints) > 5 {
				fmt.Printf("    ... and %d more\n", len(result.Endpoints)-5)
			}
		}
		
		if len(result.Secrets) > 0 {
			fmt.Printf("    %s Found %d potential secrets\n", yellow("!"), len(result.Secrets))
			for i, secret := range result.Secrets {
				if i >= 3 { // Show only first 3 secrets
					fmt.Printf("    ... and %d more secrets\n", len(result.Secrets)-3)
					break
				}
				fmt.Printf("      %s: %s (line %d)\n", secret.Type, 
					truncateString(secret.Value, 50), secret.Line)
			}
		}
		
		if len(result.Functions) > 0 {
			fmt.Printf("    Functions: %s\n", 
				strings.Join(result.Functions[:min(3, len(result.Functions))], ", "))
		}
		
		fmt.Printf("    Confidence: %.0f%%\n", result.Confidence*100)
		fmt.Println()
	}
}

func (j *JSAnalysisPlugin) generatePluginResults(target *models.Target, results []JSResult, resultsChan chan<- models.PluginResult) {
	for _, result := range results {
		severity := models.SeverityLow
		if len(result.Secrets) > 0 {
			severity = models.SeverityMedium
			for _, secret := range result.Secrets {
				if secret.Type == "api_key" || secret.Type == "password" || secret.Type == "token" {
					severity = models.SeverityHigh
					break
				}
			}
		}

		pluginResult := models.PluginResult{
			Plugin:      "jsanalysis",
			Target:      target.URL,
			Severity:    severity,
			Title:       fmt.Sprintf("JavaScript Analysis: %s", result.URL),
			Description: fmt.Sprintf("Analyzed JavaScript file with %d endpoints and %d secrets", len(result.Endpoints), len(result.Secrets)),
			Data: map[string]interface{}{
				"url":        result.URL,
				"endpoints":  result.Endpoints,
				"secrets":    result.Secrets,
				"functions":  result.Functions,
				"variables":  result.Variables,
				"tool":       result.Tool,
			},
			Timestamp: time.Now(),
		}
		resultsChan <- pluginResult
	}
}

func (j *JSAnalysisPlugin) addDiscoveries(shared *core.SharedContext, domain string, results []JSResult) {
	for _, result := range results {
		// Add endpoint discoveries
		for _, endpoint := range result.Endpoints {
			shared.AddDiscovery(models.Discovery{
				Type:       "js_endpoint",
				Value:      endpoint,
				Source:     "jsanalysis",
				Confidence: result.Confidence,
				Timestamp:  time.Now(),
				Metadata: map[string]interface{}{
					"js_url": result.URL,
					"tool":   result.Tool,
					"domain": domain,
				},
			})
		}

		// Add secret discoveries
		for _, secret := range result.Secrets {
			shared.AddDiscovery(models.Discovery{
				Type:       "js_secret",
				Value:      secret.Value,
				Source:     "jsanalysis",
				Confidence: secret.Confidence,
				Timestamp:  time.Now(),
				Metadata: map[string]interface{}{
					"secret_type": secret.Type,
					"js_url":      result.URL,
					"line":        secret.Line,
					"context":     secret.Context,
					"tool":        result.Tool,
					"domain":      domain,
				},
			})
		}

		// Add function discoveries
		for _, function := range result.Functions {
			shared.AddDiscovery(models.Discovery{
				Type:       "js_function",
				Value:      function,
				Source:     "jsanalysis",
				Confidence: result.Confidence * 0.8,
				Timestamp:  time.Now(),
				Metadata: map[string]interface{}{
					"js_url": result.URL,
					"tool":   result.Tool,
					"domain": domain,
				},
			})
		}
	}
}

// Helper functions
func (j *JSAnalysisPlugin) mergeStringSlices(slice1, slice2 []string) []string {
	set := make(map[string]bool)
	for _, item := range slice1 {
		set[item] = true
	}
	for _, item := range slice2 {
		set[item] = true
	}
	
	var result []string
	for item := range set {
		result = append(result, item)
	}
	return result
}

func (j *JSAnalysisPlugin) mergeSecrets(secrets1, secrets2 []SecretResult) []SecretResult {
	set := make(map[string]SecretResult)
	
	for _, secret := range secrets1 {
		key := fmt.Sprintf("%s:%s", secret.Type, secret.Value)
		set[key] = secret
	}
	
	for _, secret := range secrets2 {
		key := fmt.Sprintf("%s:%s", secret.Type, secret.Value)
		if existing, exists := set[key]; exists {
			// Keep higher confidence
			if secret.Confidence > existing.Confidence {
				set[key] = secret
			}
		} else {
			set[key] = secret
		}
	}
	
	var result []SecretResult
	for _, secret := range set {
		result = append(result, secret)
	}
	return result
}

func getStringFromMap(m map[string]interface{}, key string) string {
	if val, ok := m[key].(string); ok {
		return val
	}
	return ""
}

func min(a, b int) int {
	if a < b {
		return a
	}
	return b
}

func truncateString(s string, maxLen int) string {
	if len(s) <= maxLen {
		return s
	}
	return s[:maxLen] + "..."
}
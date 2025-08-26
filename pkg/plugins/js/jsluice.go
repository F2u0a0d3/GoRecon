package js

import (
	"context"
	"crypto/sha256"
	"encoding/json"
	"fmt"
	"net/http"
	"net/url"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"time"

	"github.com/google/uuid"
	"github.com/f2u0a0d3/GoRecon/internal/utils"
	"github.com/f2u0a0d3/GoRecon/pkg/config"
	"github.com/f2u0a0d3/GoRecon/pkg/core"
	"github.com/f2u0a0d3/GoRecon/pkg/httpcap"
	"github.com/f2u0a0d3/GoRecon/pkg/models"
	"github.com/rs/zerolog"
)

// JSluicePlugin implements JavaScript analysis for endpoints, secrets, and vulnerabilities
type JSluicePlugin struct {
	core.BasePlugin
	exec     *utils.ExecWrapper
	capture  *httpcap.CaptureClient
	logger   zerolog.Logger
	config   *config.Config
	patterns *JSPatterns
}

// JSluiceResult represents the JSON output from jsluice
type JSluiceResult struct {
	URL         string   `json:"url"`
	Endpoints   []string `json:"endpoints"`
	Secrets     []string `json:"secrets"`
	DOMSinks    []string `json:"dom_sinks"`
	Variables   []string `json:"variables"`
	Comments    []string `json:"comments"`
	Functions   []string `json:"functions"`
	APIs        []string `json:"apis"`
	Frameworks  []string `json:"frameworks"`
	Libraries   []string `json:"libraries"`
	Suspicious  []string `json:"suspicious"`
}

// JSPatterns contains regex patterns for JavaScript analysis
type JSPatterns struct {
	APIKeys     []*regexp.Regexp
	Endpoints   []*regexp.Regexp
	Secrets     []*regexp.Regexp
	DOMSinks    []*regexp.Regexp
	Frameworks  []*regexp.Regexp
	Suspicious  []*regexp.Regexp
}

// SecretMatch represents a found secret
type SecretMatch struct {
	Type       string  `json:"type"`
	Value      string  `json:"value"`
	Context    string  `json:"context"`
	Line       int     `json:"line"`
	Confidence float64 `json:"confidence"`
	Severity   string  `json:"severity"`
}

// EndpointMatch represents a found endpoint
type EndpointMatch struct {
	URL        string   `json:"url"`
	Method     string   `json:"method"`
	Parameters []string `json:"parameters"`
	Context    string   `json:"context"`
	Line       int      `json:"line"`
}

// NewJSluicePlugin creates a new jsluice plugin
func NewJSluicePlugin() *JSluicePlugin {
	logger := zerolog.New(nil).With().Str("plugin", "jsluice").Logger()
	
	return &JSluicePlugin{
		BasePlugin: core.NewBasePlugin("jsluice", "js", []string{"jsluice", "curl"}),
		exec:       utils.NewExecWrapper(logger),
		logger:     logger,
		patterns:   initJSPatterns(),
	}
}

// Metadata methods
func (j *JSluicePlugin) Name() string { return "jsluice" }
func (j *JSluicePlugin) Category() string { return "js" }
func (j *JSluicePlugin) Description() string {
	return "JavaScript analysis for endpoints, secrets, and vulnerabilities using jsluice"
}
func (j *JSluicePlugin) Version() string { return "1.0.0" }
func (j *JSluicePlugin) Author() string { return "GoRecon Team" }

// Dependency methods
func (j *JSluicePlugin) RequiredBinaries() []string {
	return []string{"jsluice"}
}

func (j *JSluicePlugin) RequiredEnvVars() []string {
	return []string{}
}

func (j *JSluicePlugin) SupportedTargetTypes() []string {
	return []string{"web", "api", "js"}
}

func (j *JSluicePlugin) Dependencies() []core.PluginDependency {
	return []core.PluginDependency{
		{
			Plugin:   "httpx",
			Required: false,
			Reason:   "Provides HTTP services for JavaScript discovery",
		},
		{
			Plugin:   "crawler",
			Required: false,
			Reason:   "Provides URLs with JavaScript files",
		},
	}
}

func (j *JSluicePlugin) Provides() []string {
	return []string{
		"js_endpoints", "js_secrets", "js_vulnerabilities", 
		"api_endpoints", "dom_sinks", "js_libraries",
	}
}

func (j *JSluicePlugin) Consumes() []string {
	return []string{"urls", "js_files", "endpoints"}
}

// Capability methods
func (j *JSluicePlugin) IsPassive() bool { return false } // Downloads and analyzes JS
func (j *JSluicePlugin) RequiresConfirmation() bool { return false }
func (j *JSluicePlugin) EstimatedDuration() time.Duration { return 15 * time.Minute }
func (j *JSluicePlugin) MaxConcurrency() int { return 5 }
func (j *JSluicePlugin) Priority() int { return 6 } // Medium priority
func (j *JSluicePlugin) ResourceRequirements() core.Resources {
	return core.Resources{
		CPUCores:         2,
		MemoryMB:         1024,
		DiskMB:           500,
		NetworkBandwidth: "5Mbps",
		MaxFileHandles:   300,
		MaxProcesses:     15,
		RequiresRoot:     false,
		NetworkAccess:    true,
	}
}

// Intelligence methods
func (j *JSluicePlugin) ProcessDiscovery(ctx context.Context, discovery models.Discovery) error {
	if discovery.Type == models.DiscoveryTypeEndpoint {
		if url, ok := discovery.Value.(string); ok && j.isJavaScriptFile(url) {
			j.logger.Debug().
				Str("url", url).
				Str("source", discovery.Source).
				Msg("Processing JavaScript file for analysis")
		}
	}
	return nil
}

func (j *JSluicePlugin) GetIntelligencePatterns() []core.Pattern {
	return []core.Pattern{
		{
			Name:        "js_api_endpoint",
			Type:        "endpoint",
			Keywords:    []string{"api/", "/api", "graphql", "rest", "endpoint"},
			Confidence:  0.8,
			Description: "API endpoints discovered in JavaScript",
		},
		{
			Name:        "js_secret_exposure",
			Type:        "secret",
			Keywords:    []string{"key", "token", "secret", "password", "api_key"},
			Confidence:  0.9,
			Description: "Potential secrets exposed in JavaScript",
		},
		{
			Name:        "dom_xss_sink",
			Type:        "vulnerability",
			Keywords:    []string{"innerHTML", "outerHTML", "eval", "setTimeout", "setInterval"},
			Confidence:  0.7,
			Description: "DOM XSS sinks in JavaScript code",
		},
		{
			Name:        "js_framework",
			Type:        "technology",
			Keywords:    []string{"react", "angular", "vue", "jquery", "bootstrap"},
			Confidence:  0.8,
			Description: "JavaScript frameworks and libraries",
		},
	}
}

// Lifecycle methods
func (j *JSluicePlugin) Validate(ctx context.Context, cfg *config.Config) error {
	j.config = cfg
	
	// Check if jsluice binary is available
	if err := j.exec.CheckBinary("jsluice"); err != nil {
		j.logger.Warn().Err(err).Msg("jsluice binary not found, attempting installation")
		
		// Try to install jsluice
		installCmd := "go install github.com/BishopFox/jsluice/cmd/jsluice@latest"
		if err := j.exec.InstallBinary(ctx, "jsluice", installCmd); err != nil {
			return fmt.Errorf("failed to install jsluice: %w", err)
		}
	}
	
	// Verify version
	version, err := j.exec.GetVersion(ctx, "jsluice")
	if err != nil {
		j.logger.Warn().Err(err).Msg("Could not determine jsluice version")
	} else {
		j.logger.Info().Str("version", version).Msg("jsluice version detected")
	}
	
	return nil
}

func (j *JSluicePlugin) Prepare(ctx context.Context, target *models.Target, cfg *config.Config, shared *core.SharedContext) error {
	j.config = cfg
	j.logger = j.logger.With().Str("target", target.Domain).Logger()
	
	// Initialize HTTP capture client if workspace is available
	if workspace := shared.GetWorkspace(); workspace != nil {
		captureConfig := httpcap.DefaultCaptureConfig()
		j.capture = httpcap.NewCaptureClient(workspace, captureConfig, j.logger)
	}
	
	j.logger.Info().
		Str("target", target.URL).
		Msg("Preparing jsluice for JavaScript analysis")
	
	return nil
}

func (j *JSluicePlugin) Run(ctx context.Context, target *models.Target, results chan<- models.PluginResult, shared *core.SharedContext) error {
	j.logger.Info().
		Str("target", target.Domain).
		Msg("Starting JavaScript analysis with jsluice")
	
	// Collect JavaScript URLs to analyze
	jsURLs := j.collectJavaScriptURLs(target, shared)
	
	if len(jsURLs) == 0 {
		// Try to discover JS files from the main page
		jsURLs = j.discoverJavaScriptFiles(ctx, target)
	}
	
	j.logger.Debug().
		Int("js_urls", len(jsURLs)).
		Msg("Analyzing JavaScript files")
	
	// Analyze each JavaScript file
	for _, jsURL := range jsURLs {
		if err := j.analyzeJavaScriptFile(ctx, jsURL, target, results); err != nil {
			j.logger.Error().Err(err).
				Str("url", jsURL).
				Msg("Failed to analyze JavaScript file")
		}
	}
	
	j.logger.Info().
		Int("analyzed_files", len(jsURLs)).
		Msg("JavaScript analysis completed")
	
	return nil
}

func (j *JSluicePlugin) Teardown(ctx context.Context) error {
	j.logger.Debug().Msg("Tearing down jsluice plugin")
	return nil
}

// Implementation methods

func (j *JSluicePlugin) collectJavaScriptURLs(target *models.Target, shared *core.SharedContext) []string {
	var jsURLs []string
	
	// Get URLs from shared context
	if shared != nil {
		discoveries := shared.GetDiscoveries(models.DiscoveryTypeEndpoint)
		for _, discovery := range discoveries {
			if url, ok := discovery.Value.(string); ok && j.isJavaScriptFile(url) {
				jsURLs = append(jsURLs, url)
			}
		}
	}
	
	// Add common JavaScript file paths
	baseURL := target.GetBaseURL()
	commonPaths := []string{
		"/js/app.js", "/js/main.js", "/js/bundle.js", "/js/vendor.js",
		"/assets/app.js", "/assets/main.js", "/assets/bundle.js",
		"/static/js/app.js", "/static/js/main.js", "/static/js/bundle.js",
		"/dist/app.js", "/dist/main.js", "/dist/bundle.js",
	}
	
	for _, path := range commonPaths {
		jsURLs = append(jsURLs, baseURL+path)
	}
	
	return j.deduplicateStrings(jsURLs)
}

func (j *JSluicePlugin) discoverJavaScriptFiles(ctx context.Context, target *models.Target) []string {
	var jsURLs []string
	
	if j.capture == nil {
		return jsURLs
	}
	
	// Fetch the main page to look for script tags
	resp, _, capturedResp, err := j.capture.Get(ctx, target.URL)
	if err != nil {
		j.logger.Debug().Err(err).Msg("Failed to fetch target page for JS discovery")
		return jsURLs
	}
	defer resp.Body.Close()
	
	if capturedResp != nil && capturedResp.Body != "" {
		jsURLs = j.extractJavaScriptURLs(capturedResp.Body, target.GetBaseURL())
	}
	
	return jsURLs
}

func (j *JSluicePlugin) extractJavaScriptURLs(htmlContent, baseURL string) []string {
	var jsURLs []string
	
	// Regex for script src attributes
	scriptRegex := regexp.MustCompile(`<script[^>]+src\s*=\s*["']([^"']+)["']`)
	matches := scriptRegex.FindAllStringSubmatch(htmlContent, -1)
	
	for _, match := range matches {
		if len(match) > 1 {
			scriptURL := match[1]
			if j.isJavaScriptFile(scriptURL) {
				// Convert relative URLs to absolute
				if !strings.HasPrefix(scriptURL, "http") {
					if strings.HasPrefix(scriptURL, "//") {
						scriptURL = "https:" + scriptURL
					} else if strings.HasPrefix(scriptURL, "/") {
						scriptURL = baseURL + scriptURL
					} else {
						scriptURL = baseURL + "/" + scriptURL
					}
				}
				jsURLs = append(jsURLs, scriptURL)
			}
		}
	}
	
	return j.deduplicateStrings(jsURLs)
}

func (j *JSluicePlugin) analyzeJavaScriptFile(ctx context.Context, jsURL string, target *models.Target, results chan<- models.PluginResult) error {
	j.logger.Debug().
		Str("url", jsURL).
		Msg("Analyzing JavaScript file")
	
	// Download JavaScript content
	jsContent, err := j.downloadJavaScript(ctx, jsURL)
	if err != nil {
		return fmt.Errorf("failed to download JavaScript: %w", err)
	}
	
	if jsContent == "" {
		return fmt.Errorf("empty JavaScript content")
	}
	
	// Run jsluice analysis
	jsluiceResult, err := j.runJSluice(ctx, jsURL, jsContent)
	if err != nil {
		j.logger.Warn().Err(err).Msg("jsluice analysis failed, using custom patterns")
		// Fallback to custom analysis
		jsluiceResult = j.customJSAnalysis(jsContent, jsURL)
	}
	
	// Process results
	j.processEndpoints(jsluiceResult, jsURL, target, results)
	j.processSecrets(jsluiceResult, jsURL, target, results)
	j.processDOMSinks(jsluiceResult, jsURL, target, results)
	j.processFrameworks(jsluiceResult, jsURL, target, results)
	
	// Create main analysis result
	mainResult := j.createMainResult(jsluiceResult, jsURL, target, jsContent)
	results <- mainResult
	
	return nil
}

func (j *JSluicePlugin) downloadJavaScript(ctx context.Context, jsURL string) (string, error) {
	if j.capture != nil {
		// Use capture client if available
		resp, _, capturedResp, err := j.capture.Get(ctx, jsURL)
		if err != nil {
			return "", err
		}
		defer resp.Body.Close()
		
		if capturedResp != nil {
			return capturedResp.Body, nil
		}
	}
	
	// Fallback to basic HTTP client
	client := &http.Client{Timeout: 30 * time.Second}
	resp, err := client.Get(jsURL)
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()
	
	if resp.StatusCode != http.StatusOK {
		return "", fmt.Errorf("HTTP %d", resp.StatusCode)
	}
	
	// Read content (limit to 10MB)
	content := make([]byte, 10*1024*1024)
	n, _ := resp.Body.Read(content)
	
	return string(content[:n]), nil
}

func (j *JSluicePlugin) runJSluice(ctx context.Context, jsURL, jsContent string) (*JSluiceResult, error) {
	// Create temporary file for JavaScript content
	tempFile := fmt.Sprintf("/tmp/jsluice-%s.js", j.generateFileID())
	if err := j.exec.WriteFile(tempFile, []byte(jsContent)); err != nil {
		return nil, fmt.Errorf("failed to write temp file: %w", err)
	}
	defer j.exec.RemoveFile(tempFile)
	
	// Run jsluice
	args := []string{
		"urls",
		"-i", tempFile,
		"--json",
	}
	
	result, err := j.exec.Execute(ctx, "jsluice", args, &utils.ExecOptions{
		Timeout:       2 * time.Minute,
		CaptureOutput: true,
		MaxOutputSize: 10 * 1024 * 1024, // 10MB max output
	})
	
	if err != nil {
		return nil, fmt.Errorf("jsluice execution failed: %w", err)
	}
	
	return j.parseJSluiceOutput(result.Stdout, jsURL)
}

func (j *JSluicePlugin) parseJSluiceOutput(output, jsURL string) (*JSluiceResult, error) {
	// Parse jsluice JSON output
	lines := strings.Split(output, "\n")
	result := &JSluiceResult{URL: jsURL}
	
	for _, line := range lines {
		line = strings.TrimSpace(line)
		if line == "" {
			continue
		}
		
		// jsluice outputs URLs one per line
		if j.isValidURL(line) {
			result.Endpoints = append(result.Endpoints, line)
		}
	}
	
	return result, nil
}

func (j *JSluicePlugin) customJSAnalysis(jsContent, jsURL string) *JSluiceResult {
	result := &JSluiceResult{URL: jsURL}
	
	// Extract endpoints using patterns
	result.Endpoints = j.extractEndpoints(jsContent)
	result.Secrets = j.extractSecrets(jsContent)
	result.DOMSinks = j.extractDOMSinks(jsContent)
	result.Frameworks = j.extractFrameworks(jsContent)
	result.Suspicious = j.extractSuspicious(jsContent)
	
	return result
}

func (j *JSluicePlugin) extractEndpoints(content string) []string {
	var endpoints []string
	
	for _, pattern := range j.patterns.Endpoints {
		matches := pattern.FindAllString(content, -1)
		endpoints = append(endpoints, matches...)
	}
	
	return j.deduplicateStrings(endpoints)
}

func (j *JSluicePlugin) extractSecrets(content string) []string {
	var secrets []string
	
	for _, pattern := range j.patterns.Secrets {
		matches := pattern.FindAllString(content, -1)
		secrets = append(secrets, matches...)
	}
	
	return j.deduplicateStrings(secrets)
}

func (j *JSluicePlugin) extractDOMSinks(content string) []string {
	var sinks []string
	
	for _, pattern := range j.patterns.DOMSinks {
		matches := pattern.FindAllString(content, -1)
		sinks = append(sinks, matches...)
	}
	
	return j.deduplicateStrings(sinks)
}

func (j *JSluicePlugin) extractFrameworks(content string) []string {
	var frameworks []string
	
	for _, pattern := range j.patterns.Frameworks {
		matches := pattern.FindAllString(content, -1)
		frameworks = append(frameworks, matches...)
	}
	
	return j.deduplicateStrings(frameworks)
}

func (j *JSluicePlugin) extractSuspicious(content string) []string {
	var suspicious []string
	
	for _, pattern := range j.patterns.Suspicious {
		matches := pattern.FindAllString(content, -1)
		suspicious = append(suspicious, matches...)
	}
	
	return j.deduplicateStrings(suspicious)
}

func (j *JSluicePlugin) processEndpoints(result *JSluiceResult, jsURL string, target *models.Target, results chan<- models.PluginResult) {
	for _, endpoint := range result.Endpoints {
		if endpoint == "" {
			continue
		}
		
		pluginResult := models.PluginResult{
			ID:        uuid.New().String(),
			Plugin:    j.Name(),
			Tool:      "jsluice",
			Category:  "js",
			Target:    target.URL,
			Timestamp: time.Now(),
			Severity:  models.SeverityInfo,
			Title:     fmt.Sprintf("JS Endpoint: %s", endpoint),
			Description: fmt.Sprintf("API endpoint discovered in JavaScript: %s", endpoint),
			Evidence: models.Evidence{
				Type:    "js_endpoint",
				Content: fmt.Sprintf("Found in: %s", jsURL),
				URL:     jsURL,
			},
			Data: map[string]interface{}{
				"endpoint":    endpoint,
				"source_file": jsURL,
				"type":        "api_endpoint",
			},
			Confidence: 0.8,
			Tags:       []string{"javascript", "endpoint", "api"},
		}
		
		results <- pluginResult
	}
}

func (j *JSluicePlugin) processSecrets(result *JSluiceResult, jsURL string, target *models.Target, results chan<- models.PluginResult) {
	for _, secret := range result.Secrets {
		if secret == "" {
			continue
		}
		
		severity := models.SeverityMedium
		if j.isHighValueSecret(secret) {
			severity = models.SeverityHigh
		}
		
		pluginResult := models.PluginResult{
			ID:        uuid.New().String(),
			Plugin:    j.Name(),
			Tool:      "jsluice",
			Category:  "js",
			Target:    target.URL,
			Timestamp: time.Now(),
			Severity:  severity,
			Title:     fmt.Sprintf("JS Secret: %s", j.maskSecret(secret)),
			Description: fmt.Sprintf("Potential secret exposed in JavaScript: %s", j.maskSecret(secret)),
			Evidence: models.Evidence{
				Type:    "js_secret",
				Content: fmt.Sprintf("Found in: %s", jsURL),
				URL:     jsURL,
			},
			Data: map[string]interface{}{
				"secret_type": j.classifySecret(secret),
				"source_file": jsURL,
				"masked_value": j.maskSecret(secret),
			},
			Confidence: 0.7,
			Tags:       []string{"javascript", "secret", "exposure"},
		}
		
		results <- pluginResult
	}
}

func (j *JSluicePlugin) processDOMSinks(result *JSluiceResult, jsURL string, target *models.Target, results chan<- models.PluginResult) {
	for _, sink := range result.DOMSinks {
		if sink == "" {
			continue
		}
		
		pluginResult := models.PluginResult{
			ID:        uuid.New().String(),
			Plugin:    j.Name(),
			Tool:      "jsluice",
			Category:  "js",
			Target:    target.URL,
			Timestamp: time.Now(),
			Severity:  models.SeverityMedium,
			Title:     fmt.Sprintf("DOM Sink: %s", sink),
			Description: fmt.Sprintf("DOM XSS sink found in JavaScript: %s", sink),
			Evidence: models.Evidence{
				Type:    "dom_sink",
				Content: fmt.Sprintf("Found in: %s", jsURL),
				URL:     jsURL,
			},
			Data: map[string]interface{}{
				"sink":        sink,
				"source_file": jsURL,
				"vuln_type":   "dom_xss",
			},
			Confidence: 0.6,
			Tags:       []string{"javascript", "vulnerability", "xss", "dom"},
		}
		
		results <- pluginResult
	}
}

func (j *JSluicePlugin) processFrameworks(result *JSluiceResult, jsURL string, target *models.Target, results chan<- models.PluginResult) {
	for _, framework := range result.Frameworks {
		if framework == "" {
			continue
		}
		
		pluginResult := models.PluginResult{
			ID:        uuid.New().String(),
			Plugin:    j.Name(),
			Tool:      "jsluice",
			Category:  "js",
			Target:    target.URL,
			Timestamp: time.Now(),
			Severity:  models.SeverityInfo,
			Title:     fmt.Sprintf("JS Framework: %s", framework),
			Description: fmt.Sprintf("JavaScript framework/library detected: %s", framework),
			Evidence: models.Evidence{
				Type:    "js_technology",
				Content: fmt.Sprintf("Found in: %s", jsURL),
				URL:     jsURL,
			},
			Data: map[string]interface{}{
				"framework":   framework,
				"source_file": jsURL,
				"type":        "technology",
			},
			Confidence: 0.8,
			Tags:       []string{"javascript", "framework", "technology"},
		}
		
		results <- pluginResult
	}
}

func (j *JSluicePlugin) createMainResult(result *JSluiceResult, jsURL string, target *models.Target, jsContent string) models.PluginResult {
	// Calculate content hash and size
	contentHash := fmt.Sprintf("%x", sha256.Sum256([]byte(jsContent)))
	contentSize := len(jsContent)
	
	// Determine overall severity
	severity := models.SeverityInfo
	if len(result.Secrets) > 0 {
		severity = models.SeverityMedium
	}
	if len(result.DOMSinks) > 0 {
		severity = models.SeverityMedium
	}
	
	return models.PluginResult{
		ID:        uuid.New().String(),
		Plugin:    j.Name(),
		Tool:      "jsluice",
		Category:  "js",
		Target:    target.URL,
		Timestamp: time.Now(),
		Severity:  severity,
		Title:     fmt.Sprintf("JavaScript Analysis: %s", filepath.Base(jsURL)),
		Description: fmt.Sprintf("JavaScript file analyzed: %d endpoints, %d secrets, %d DOM sinks found", 
			len(result.Endpoints), len(result.Secrets), len(result.DOMSinks)),
		Evidence: models.Evidence{
			Type:    "js_analysis",
			Content: fmt.Sprintf("File: %s (%d bytes)", jsURL, contentSize),
			URL:     jsURL,
		},
		Data: map[string]interface{}{
			"file_url":      jsURL,
			"file_size":     contentSize,
			"file_hash":     contentHash,
			"endpoints":     result.Endpoints,
			"secrets_count": len(result.Secrets),
			"sinks_count":   len(result.DOMSinks),
			"frameworks":    result.Frameworks,
			"analysis_summary": map[string]int{
				"endpoints": len(result.Endpoints),
				"secrets":   len(result.Secrets),
				"dom_sinks": len(result.DOMSinks),
				"frameworks": len(result.Frameworks),
			},
		},
		Confidence: 0.9,
		Tags:       []string{"javascript", "analysis", "security"},
	}
}

// Helper methods

func (j *JSluicePlugin) isJavaScriptFile(url string) bool {
	return strings.HasSuffix(strings.ToLower(url), ".js") || 
		   strings.Contains(strings.ToLower(url), ".js?") ||
		   strings.Contains(strings.ToLower(url), "/js/")
}

func (j *JSluicePlugin) isValidURL(s string) bool {
	_, err := url.Parse(s)
	return err == nil && (strings.HasPrefix(s, "http") || strings.HasPrefix(s, "/"))
}

func (j *JSluicePlugin) isHighValueSecret(secret string) bool {
	highValuePatterns := []string{
		"api_key", "secret_key", "private_key", "access_token",
		"auth_token", "bearer", "password", "credentials",
	}
	
	secretLower := strings.ToLower(secret)
	for _, pattern := range highValuePatterns {
		if strings.Contains(secretLower, pattern) {
			return true
		}
	}
	
	return false
}

func (j *JSluicePlugin) maskSecret(secret string) string {
	if len(secret) <= 8 {
		return strings.Repeat("*", len(secret))
	}
	
	return secret[:4] + strings.Repeat("*", len(secret)-8) + secret[len(secret)-4:]
}

func (j *JSluicePlugin) classifySecret(secret string) string {
	secretLower := strings.ToLower(secret)
	
	if strings.Contains(secretLower, "api") && strings.Contains(secretLower, "key") {
		return "api_key"
	}
	if strings.Contains(secretLower, "token") {
		return "token"
	}
	if strings.Contains(secretLower, "password") {
		return "password"
	}
	if strings.Contains(secretLower, "secret") {
		return "secret"
	}
	
	return "unknown"
}

func (j *JSluicePlugin) generateFileID() string {
	return fmt.Sprintf("%d", time.Now().UnixNano())
}

func (j *JSluicePlugin) deduplicateStrings(input []string) []string {
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

// Pattern initialization
func initJSPatterns() *JSPatterns {
	return &JSPatterns{
		APIKeys: []*regexp.Regexp{
			regexp.MustCompile(`[aA][pP][iI][_\-]?[kK][eE][yY]\s*[:=]\s*["']([^"']+)["']`),
			regexp.MustCompile(`[sS][eE][cC][rR][eE][tT][_\-]?[kK][eE][yY]\s*[:=]\s*["']([^"']+)["']`),
			regexp.MustCompile(`[aA][cC][cC][eE][sS][sS][_\-]?[tT][oO][kK][eE][nN]\s*[:=]\s*["']([^"']+)["']`),
		},
		Endpoints: []*regexp.Regexp{
			regexp.MustCompile(`["'](/[a-zA-Z0-9_\-/]+)["']`),
			regexp.MustCompile(`["'](https?://[^"']+)["']`),
			regexp.MustCompile(`fetch\s*\(\s*["']([^"']+)["']`),
			regexp.MustCompile(`axios\.[a-z]+\s*\(\s*["']([^"']+)["']`),
			regexp.MustCompile(`\$\.ajax\s*\(\s*["']([^"']+)["']`),
		},
		Secrets: []*regexp.Regexp{
			regexp.MustCompile(`[pP][aA][sS][sS][wW][oO][rR][dD]\s*[:=]\s*["']([^"']+)["']`),
			regexp.MustCompile(`[tT][oO][kK][eE][nN]\s*[:=]\s*["']([^"']+)["']`),
			regexp.MustCompile(`[kK][eE][yY]\s*[:=]\s*["']([^"']+)["']`),
			regexp.MustCompile(`[bB][eE][aA][rR][eE][rR]\s+([a-zA-Z0-9_\-]+)`),
		},
		DOMSinks: []*regexp.Regexp{
			regexp.MustCompile(`innerHTML\s*=`),
			regexp.MustCompile(`outerHTML\s*=`),
			regexp.MustCompile(`eval\s*\(`),
			regexp.MustCompile(`setTimeout\s*\(`),
			regexp.MustCompile(`setInterval\s*\(`),
			regexp.MustCompile(`document\.write\s*\(`),
		},
		Frameworks: []*regexp.Regexp{
			regexp.MustCompile(`(React|react)[\.\s]`),
			regexp.MustCompile(`(Angular|angular)[\.\s]`),
			regexp.MustCompile(`(Vue|vue)[\.\s]`),
			regexp.MustCompile(`(jQuery|jquery|\$)[\.\s]`),
			regexp.MustCompile(`(Bootstrap|bootstrap)[\.\s]`),
		},
		Suspicious: []*regexp.Regexp{
			regexp.MustCompile(`btoa\s*\(`),
			regexp.MustCompile(`atob\s*\(`),
			regexp.MustCompile(`fromCharCode\s*\(`),
			regexp.MustCompile(`unescape\s*\(`),
			regexp.MustCompile(`escape\s*\(`),
		},
	}
}
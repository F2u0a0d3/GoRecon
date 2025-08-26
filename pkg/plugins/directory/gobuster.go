package directory

import (
	"bufio"
	"context"
	"encoding/json"
	"fmt"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/f2u0a0d3/GoRecon/pkg/plugins/base"
	"github.com/f2u0a0d3/GoRecon/pkg/core"
	"github.com/f2u0a0d3/GoRecon/pkg/models"
)

type GobusterPlugin struct {
	*base.BaseAdapter
	config *GobusterConfig
}

type GobusterConfig struct {
	Wordlist        string   `json:"wordlist"`
	Extensions      []string `json:"extensions"`
	StatusCodes     []string `json:"status_codes"`
	ExcludeLength   []string `json:"exclude_length"`
	Threads         int      `json:"threads"`
	Timeout         int      `json:"timeout"`
	UserAgent       string   `json:"user_agent"`
	Headers         []string `json:"headers"`
	Cookies         string   `json:"cookies"`
	Username        string   `json:"username"`
	Password        string   `json:"password"`
	Proxy           string   `json:"proxy"`
	FollowRedirects bool     `json:"follow_redirects"`
	Quiet           bool     `json:"quiet"`
	NoProgress      bool     `json:"no_progress"`
	NoError         bool     `json:"no_error"`
	Expanded        bool     `json:"expanded"`
	HideLength      bool     `json:"hide_length"`
	WildcardForced  bool     `json:"wildcard_forced"`
	OutputFormat    string   `json:"output_format"`
}

type GobusterResult struct {
	URL         string `json:"url"`
	Status      int    `json:"status"`
	Size        int    `json:"size"`
	Path        string `json:"path"`
	Redirected  string `json:"redirected,omitempty"`
	Extension   string `json:"extension,omitempty"`
	Timestamp   time.Time `json:"timestamp"`
}

func NewGobusterPlugin() *GobusterPlugin {
	config := &GobusterConfig{
		Wordlist:        "/usr/share/wordlists/dirb/common.txt", // Default wordlist
		Extensions:      []string{"php", "html", "txt", "js", "css", "asp", "aspx", "jsp"},
		StatusCodes:     []string{"200", "204", "301", "302", "307", "401", "403"},
		ExcludeLength:   []string{},
		Threads:         10,
		Timeout:         10,
		UserAgent:       "gobuster/3.8",
		Headers:         []string{},
		FollowRedirects: false,
		Quiet:           true,
		NoProgress:      true,
		NoError:         true,
		Expanded:        true,
		HideLength:      false,
		WildcardForced:  false,
		OutputFormat:    "json",
	}

	return &GobusterPlugin{
		BaseAdapter: base.NewBaseAdapter("gobuster", "Directory and File Enumeration"),
		config:      config,
	}
}

func (g *GobusterPlugin) GetMetadata() models.PluginMetadata {
	return models.PluginMetadata{
		Name:        "Gobuster",
		Version:     "3.8",
		Description: "Directory/file & DNS busting tool written in Go",
		Author:      "Christian Mehlmauer & OJ Reeves",
		Tags:        []string{"directory", "enumeration", "brute-force", "discovery", "files"},
		Category:    "directory_discovery",
		Priority:    8,
		Timeout:     300,
		RateLimit:   50,
		Dependencies: []string{"gobuster"},
		Capabilities: []string{
			"directory_enumeration",
			"file_discovery",
			"brute_force_discovery",
			"status_code_filtering",
			"custom_wordlists",
			"extension_enumeration",
		},
	}
}

func (g *GobusterPlugin) Configure(config map[string]interface{}) error {
	if wordlist, ok := config["wordlist"].(string); ok {
		g.config.Wordlist = wordlist
	}

	if extensions, ok := config["extensions"].([]interface{}); ok {
		g.config.Extensions = make([]string, len(extensions))
		for i, e := range extensions {
			g.config.Extensions[i] = fmt.Sprintf("%v", e)
		}
	}

	if statusCodes, ok := config["status_codes"].([]interface{}); ok {
		g.config.StatusCodes = make([]string, len(statusCodes))
		for i, s := range statusCodes {
			g.config.StatusCodes[i] = fmt.Sprintf("%v", s)
		}
	}

	if excludeLength, ok := config["exclude_length"].([]interface{}); ok {
		g.config.ExcludeLength = make([]string, len(excludeLength))
		for i, e := range excludeLength {
			g.config.ExcludeLength[i] = fmt.Sprintf("%v", e)
		}
	}

	if threads, ok := config["threads"].(int); ok {
		g.config.Threads = threads
	}

	if timeout, ok := config["timeout"].(int); ok {
		g.config.Timeout = timeout
	}

	if userAgent, ok := config["user_agent"].(string); ok {
		g.config.UserAgent = userAgent
	}

	if headers, ok := config["headers"].([]interface{}); ok {
		g.config.Headers = make([]string, len(headers))
		for i, h := range headers {
			g.config.Headers[i] = fmt.Sprintf("%v", h)
		}
	}

	if cookies, ok := config["cookies"].(string); ok {
		g.config.Cookies = cookies
	}

	if username, ok := config["username"].(string); ok {
		g.config.Username = username
	}

	if password, ok := config["password"].(string); ok {
		g.config.Password = password
	}

	if proxy, ok := config["proxy"].(string); ok {
		g.config.Proxy = proxy
	}

	if followRedirects, ok := config["follow_redirects"].(bool); ok {
		g.config.FollowRedirects = followRedirects
	}

	if quiet, ok := config["quiet"].(bool); ok {
		g.config.Quiet = quiet
	}

	if noProgress, ok := config["no_progress"].(bool); ok {
		g.config.NoProgress = noProgress
	}

	if noError, ok := config["no_error"].(bool); ok {
		g.config.NoError = noError
	}

	if expanded, ok := config["expanded"].(bool); ok {
		g.config.Expanded = expanded
	}

	if hideLength, ok := config["hide_length"].(bool); ok {
		g.config.HideLength = hideLength
	}

	if wildcardForced, ok := config["wildcard_forced"].(bool); ok {
		g.config.WildcardForced = wildcardForced
	}

	return nil
}

func (g *GobusterPlugin) Run(ctx context.Context, target *models.Target, results chan<- models.PluginResult, shared *core.SharedContext) error {
	g.SetStatus("running")
	defer g.SetStatus("completed")

	targetURLs := g.getTargetURLs(target, shared)
	if len(targetURLs) == 0 {
		targetURLs = []string{target.String()}
	}

	// Process URLs
	var wg sync.WaitGroup
	semaphore := make(chan struct{}, 3) // Limit concurrent scans

	for _, targetURL := range targetURLs {
		wg.Add(1)
		go func(url string) {
			defer wg.Done()
			semaphore <- struct{}{}
			defer func() { <-semaphore }()

			if err := g.scanURL(ctx, url, results, shared); err != nil {
				g.LogError("Failed to scan URL %s: %v", url, err)
			}
		}(targetURL)
	}

	wg.Wait()
	return nil
}

func (g *GobusterPlugin) getTargetURLs(target *models.Target, shared *core.SharedContext) []string {
	var urls []string

	// Get URLs from shared discoveries
	discoveries := shared.GetDiscoveriesByType("url", "subdomain", "service")
	for _, discovery := range discoveries {
		if discovery.Data != nil {
			if url, ok := discovery.Data["url"].(string); ok && url != "" {
				urls = append(urls, url)
			}
			if host, ok := discovery.Data["host"].(string); ok && host != "" {
				// Add both HTTP and HTTPS variants
				urls = append(urls, "http://"+host, "https://"+host)
			}
			if subdomain, ok := discovery.Data["subdomain"].(string); ok && subdomain != "" {
				urls = append(urls, "http://"+subdomain, "https://"+subdomain)
			}
		}
	}

	// Remove duplicates
	urlSet := make(map[string]bool)
	uniqueURLs := []string{}
	for _, url := range urls {
		if !urlSet[url] {
			urlSet[url] = true
			uniqueURLs = append(uniqueURLs, url)
		}
	}

	return uniqueURLs
}

func (g *GobusterPlugin) scanURL(ctx context.Context, targetURL string, results chan<- models.PluginResult, shared *core.SharedContext) error {
	args := []string{
		"gobuster", "dir",
		"-u", targetURL,
		"-w", g.config.Wordlist,
		"-t", strconv.Itoa(g.config.Threads),
		"--timeout", fmt.Sprintf("%ds", g.config.Timeout),
		"-a", g.config.UserAgent,
	}

	// Add extensions
	if len(g.config.Extensions) > 0 {
		args = append(args, "-x", strings.Join(g.config.Extensions, ","))
	}

	// Add status codes
	if len(g.config.StatusCodes) > 0 {
		args = append(args, "-s", strings.Join(g.config.StatusCodes, ","))
	}

	// Add exclude length
	if len(g.config.ExcludeLength) > 0 {
		args = append(args, "-b", strings.Join(g.config.ExcludeLength, ","))
	}

	// Add headers
	for _, header := range g.config.Headers {
		args = append(args, "-H", header)
	}

	// Add cookies
	if g.config.Cookies != "" {
		args = append(args, "-c", g.config.Cookies)
	}

	// Add authentication
	if g.config.Username != "" && g.config.Password != "" {
		args = append(args, "-U", g.config.Username, "-P", g.config.Password)
	}

	// Add proxy
	if g.config.Proxy != "" {
		args = append(args, "-p", g.config.Proxy)
	}

	// Add flags
	if g.config.FollowRedirects {
		args = append(args, "-r")
	}

	if g.config.Quiet {
		args = append(args, "-q")
	}

	if g.config.NoProgress {
		args = append(args, "-n")
	}

	if g.config.NoError {
		args = append(args, "-z")
	}

	if g.config.Expanded {
		args = append(args, "-e")
	}

	if g.config.HideLength {
		args = append(args, "-l")
	}

	if g.config.WildcardForced {
		args = append(args, "-fw")
	}

	execResult, err := g.ExecuteCommand(ctx, args)
	if err != nil {
		return fmt.Errorf("failed to execute gobuster: %w", err)
	}

	return g.parseOutput(execResult.Stdout, targetURL, results, shared)
}

func (g *GobusterPlugin) parseOutput(output, targetURL string, results chan<- models.PluginResult, shared *core.SharedContext) error {
	scanner := bufio.NewScanner(strings.NewReader(output))
	
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line == "" || strings.HasPrefix(line, "=") || strings.Contains(line, "Starting") || strings.Contains(line, "Finished") {
			continue
		}

		result := g.parseOutputLine(line, targetURL)
		if result != nil {
			pluginResult := g.createPluginResult(*result, targetURL)
			
			select {
			case results <- pluginResult:
			case <-ctx.Done():
				return ctx.Err()
			}

			// Share directory/file discoveries
			g.shareDirectoryDiscovery(shared, *result)
		}
	}

	return scanner.Err()
}

func (g *GobusterPlugin) parseOutputLine(line, targetURL string) *GobusterResult {
	// Parse gobuster output format
	// Example: "/admin               (Status: 200) [Size: 1234]"
	// Example: "/config.php          (Status: 200) [Size: 0]"
	
	if !strings.Contains(line, "(Status:") {
		return nil
	}

	result := &GobusterResult{
		Timestamp: time.Now(),
	}

	// Extract path
	parts := strings.Split(line, "(Status:")
	if len(parts) < 2 {
		return nil
	}

	result.Path = strings.TrimSpace(parts[0])
	result.URL = strings.TrimSuffix(targetURL, "/") + result.Path

	// Extract status code
	statusPart := parts[1]
	if statusEnd := strings.Index(statusPart, ")"); statusEnd != -1 {
		statusStr := strings.TrimSpace(statusPart[:statusEnd])
		if status, err := strconv.Atoi(statusStr); err == nil {
			result.Status = status
		}
	}

	// Extract size
	if sizeStart := strings.Index(line, "[Size: "); sizeStart != -1 {
		sizeEnd := strings.Index(line[sizeStart:], "]")
		if sizeEnd != -1 {
			sizeStr := strings.TrimSpace(line[sizeStart+7 : sizeStart+sizeEnd])
			if size, err := strconv.Atoi(sizeStr); err == nil {
				result.Size = size
			}
		}
	}

	// Extract redirect information
	if strings.Contains(line, "-> ") {
		redirectParts := strings.Split(line, "-> ")
		if len(redirectParts) > 1 {
			result.Redirected = strings.TrimSpace(redirectParts[len(redirectParts)-1])
		}
	}

	// Extract extension
	if strings.Contains(result.Path, ".") {
		pathParts := strings.Split(result.Path, ".")
		if len(pathParts) > 1 {
			result.Extension = pathParts[len(pathParts)-1]
		}
	}

	return result
}

func (g *GobusterPlugin) createPluginResult(result GobusterResult, targetURL string) models.PluginResult {
	severity := g.calculateSeverity(result)
	
	data := map[string]interface{}{
		"url":        result.URL,
		"path":       result.Path,
		"status":     result.Status,
		"size":       result.Size,
		"extension":  result.Extension,
		"redirected": result.Redirected,
	}

	title := fmt.Sprintf("Directory Discovery: %s", result.Path)
	description := fmt.Sprintf("Found path %s with status %d", result.Path, result.Status)
	
	if result.Size > 0 {
		description += fmt.Sprintf(" (size: %d bytes)", result.Size)
	}
	
	if result.Redirected != "" {
		description += fmt.Sprintf(" -> %s", result.Redirected)
	}

	return models.PluginResult{
		Plugin:      g.GetName(),
		Target:      targetURL,
		Type:        "directory_discovery",
		Severity:    severity,
		Title:       title,
		Description: description,
		Data:        data,
		Timestamp:   time.Now(),
		Confidence:  g.calculateConfidence(result),
		Risk:        g.calculateRisk(result),
	}
}

func (g *GobusterPlugin) calculateSeverity(result GobusterResult) models.Severity {
	// Check for sensitive paths
	pathLower := strings.ToLower(result.Path)
	
	// High severity paths
	highRiskPaths := []string{"admin", "config", "backup", "database", "db", "sql", ".env", "secret", "password", "key"}
	for _, riskPath := range highRiskPaths {
		if strings.Contains(pathLower, riskPath) {
			return models.SeverityHigh
		}
	}

	// Medium severity paths
	mediumRiskPaths := []string{"upload", "private", "internal", "dev", "test", "debug", "log", "tmp", "temp"}
	for _, riskPath := range mediumRiskPaths {
		if strings.Contains(pathLower, riskPath) {
			return models.SeverityMedium
		}
	}

	// Check status codes
	switch result.Status {
	case 200:
		return models.SeverityMedium // Accessible content
	case 301, 302, 307:
		return models.SeverityLow // Redirects
	case 401:
		return models.SeverityMedium // Authentication required
	case 403:
		return models.SeverityLow // Forbidden but exists
	}

	// Check file extensions
	if result.Extension != "" {
		sensitiveExts := []string{"sql", "bak", "old", "config", "ini", "log", "key", "pem"}
		for _, ext := range sensitiveExts {
			if result.Extension == ext {
				return models.SeverityHigh
			}
		}
	}

	return models.SeverityInfo
}

func (g *GobusterPlugin) calculateConfidence(result GobusterResult) float64 {
	confidence := 0.8 // Base confidence for directory discovery

	// Higher confidence for successful responses
	if result.Status >= 200 && result.Status < 300 {
		confidence += 0.1
	}

	// Higher confidence for content with size
	if result.Size > 0 {
		confidence += 0.1
	}

	// Cap at 1.0
	if confidence > 1.0 {
		confidence = 1.0
	}

	return confidence
}

func (g *GobusterPlugin) calculateRisk(result GobusterResult) float64 {
	risk := 0.3 // Base risk

	// Higher risk for sensitive paths
	pathLower := strings.ToLower(result.Path)
	
	// Critical paths
	criticalPaths := []string{"admin", "config", "database", "backup", ".env", "secret", "password"}
	for _, criticalPath := range criticalPaths {
		if strings.Contains(pathLower, criticalPath) {
			risk += 0.5
			break
		}
	}

	// Medium risk paths
	mediumRiskPaths := []string{"upload", "private", "internal", "dev", "test"}
	for _, riskPath := range mediumRiskPaths {
		if strings.Contains(pathLower, riskPath) {
			risk += 0.3
			break
		}
	}

	// Risk based on status codes
	switch result.Status {
	case 200:
		risk += 0.2 // Direct access
	case 401:
		risk += 0.2 // Protected resource exists
	}

	// Risk based on file extensions
	if result.Extension != "" {
		highRiskExts := []string{"sql", "bak", "old", "config", "log"}
		for _, ext := range highRiskExts {
			if result.Extension == ext {
				risk += 0.3
				break
			}
		}
	}

	// Cap at 1.0
	if risk > 1.0 {
		risk = 1.0
	}

	return risk
}

func (g *GobusterPlugin) shareDirectoryDiscovery(shared *core.SharedContext, result GobusterResult) {
	discoveryData := map[string]interface{}{
		"url":        result.URL,
		"path":       result.Path,
		"status":     result.Status,
		"size":       result.Size,
		"extension":  result.Extension,
		"redirected": result.Redirected,
	}

	discovery := &models.Discovery{
		Type:       "directory",
		Value:      result.Path,
		Source:     g.GetName(),
		Confidence: g.calculateConfidence(result),
		Timestamp:  time.Now(),
		Data:       discoveryData,
	}

	shared.AddDiscovery(discovery)

	// Also add as endpoint discovery
	endpointDiscovery := &models.Discovery{
		Type:       "endpoint",
		Value:      result.URL,
		Source:     g.GetName(),
		Confidence: g.calculateConfidence(result),
		Timestamp:  time.Now(),
		Data:       discoveryData,
	}
	shared.AddDiscovery(endpointDiscovery)

	// Add file discovery if it has an extension
	if result.Extension != "" {
		fileDiscovery := &models.Discovery{
			Type:       "file",
			Value:      result.Path,
			Source:     g.GetName(),
			Confidence: g.calculateConfidence(result),
			Timestamp:  time.Now(),
			Data:       discoveryData,
		}
		shared.AddDiscovery(fileDiscovery)
	}
}

func (g *GobusterPlugin) GetIntelligencePatterns() []models.IntelligencePattern {
	return []models.IntelligencePattern{
		{
			Name:        "Admin Path Detection",
			Pattern:     `"path":".*/(admin|administrator|manage|dashboard|panel)"`,
			Confidence:  0.9,
			Description: "Administrative path detected",
			Tags:        []string{"admin", "path", "management"},
		},
		{
			Name:        "Config File Detection",
			Pattern:     `"path":".*\.(config|cfg|ini|conf|settings)"`,
			Confidence:  0.85,
			Description: "Configuration file detected",
			Tags:        []string{"config", "file", "settings"},
		},
		{
			Name:        "Backup File Detection",
			Pattern:     `"path":".*\.(bak|backup|old|tmp|~)"`,
			Confidence:  0.8,
			Description: "Backup file detected",
			Tags:        []string{"backup", "file", "old"},
		},
		{
			Name:        "Database File Detection",
			Pattern:     `"path":".*\.(sql|db|sqlite|mdb)"`,
			Confidence:  0.9,
			Description: "Database file detected",
			Tags:        []string{"database", "file", "data"},
		},
		{
			Name:        "Upload Directory Detection",
			Pattern:     `"path":".*/(upload|uploads|files|attachments)"`,
			Confidence:  0.7,
			Description: "Upload directory detected",
			Tags:        []string{"upload", "directory", "files"},
		},
		{
			Name:        "Development Path Detection",
			Pattern:     `"path":".*/(dev|test|debug|staging|beta)"`,
			Confidence:  0.75,
			Description: "Development path detected",
			Tags:        []string{"development", "test", "debug"},
		},
	}
}
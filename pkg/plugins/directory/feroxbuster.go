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

type FeroxbusterPlugin struct {
	*base.BaseAdapter
	config *FeroxbusterConfig
}

type FeroxbusterConfig struct {
	Wordlist        string   `json:"wordlist"`
	Extensions      []string `json:"extensions"`
	StatusCodes     []string `json:"status_codes"`
	FilterStatus    []string `json:"filter_status"`
	FilterSize      []string `json:"filter_size"`
	FilterWords     []string `json:"filter_words"`
	FilterLines     []string `json:"filter_lines"`
	Threads         int      `json:"threads"`
	Depth           int      `json:"depth"`
	Timeout         int      `json:"timeout"`
	UserAgent       string   `json:"user_agent"`
	Headers         []string `json:"headers"`
	Cookies         string   `json:"cookies"`
	Proxy           string   `json:"proxy"`
	RedirectLimit   int      `json:"redirect_limit"`
	RateLimit       int      `json:"rate_limit"`
	TimeDelay       int      `json:"time_delay"`
	Silent          bool     `json:"silent"`
	Quiet           bool     `json:"quiet"`
	NoRecursion     bool     `json:"no_recursion"`
	AddSlash        bool     `json:"add_slash"`
	ExtractLinks    bool     `json:"extract_links"`
	Random          bool     `json:"random"`
	AutoTune        bool     `json:"auto_tune"`
	AutoBail        bool     `json:"auto_bail"`
	OutputJSON      bool     `json:"output_json"`
	ScanLimit       int      `json:"scan_limit"`
}

type FeroxbusterResult struct {
	URL           string    `json:"url"`
	Path          string    `json:"path"`
	Status        int       `json:"status"`
	ContentLength int       `json:"content_length"`
	LineCount     int       `json:"line_count"`
	WordCount     int       `json:"word_count"`
	Headers       map[string]string `json:"headers,omitempty"`
	Extension     string    `json:"extension,omitempty"`
	Type          string    `json:"type"` // file, directory, etc.
	Redirected    string    `json:"redirected,omitempty"`
	Timestamp     time.Time `json:"timestamp"`
	Method        string    `json:"method"`
	WildcardTest  bool      `json:"wildcard_test,omitempty"`
}

func NewFeroxbusterPlugin() *FeroxbusterPlugin {
	config := &FeroxbusterConfig{
		Wordlist:      "/usr/share/wordlists/dirb/common.txt", // Default wordlist
		Extensions:    []string{"php", "html", "txt", "js", "css", "asp", "aspx", "jsp", "json", "xml"},
		StatusCodes:   []string{"200", "204", "301", "302", "307", "401", "403", "405"},
		FilterStatus:  []string{"404"},
		FilterSize:    []string{},
		FilterWords:   []string{},
		FilterLines:   []string{},
		Threads:       50,
		Depth:         4,
		Timeout:       7,
		UserAgent:     "feroxbuster/2.11.0",
		Headers:       []string{},
		RedirectLimit: 4,
		RateLimit:     100,
		TimeDelay:     0,
		Silent:        false,
		Quiet:         true,
		NoRecursion:   false,
		AddSlash:      false,
		ExtractLinks:  true,
		Random:        false,
		AutoTune:      true,
		AutoBail:      true,
		OutputJSON:    true,
		ScanLimit:     0,
	}

	return &FeroxbusterPlugin{
		BaseAdapter: base.NewBaseAdapter("feroxbuster", "Fast, Simple, Recursive Content Discovery"),
		config:      config,
	}
}

func (f *FeroxbusterPlugin) GetMetadata() models.PluginMetadata {
	return models.PluginMetadata{
		Name:        "Feroxbuster",
		Version:     "2.11.0",
		Description: "Fast, simple, recursive content discovery tool written in Rust",
		Author:      "epi052",
		Tags:        []string{"directory", "enumeration", "recursive", "discovery", "content", "brute-force"},
		Category:    "directory_discovery",
		Priority:    9,
		Timeout:     600,
		RateLimit:   100,
		Dependencies: []string{"feroxbuster"},
		Capabilities: []string{
			"recursive_discovery",
			"content_enumeration",
			"link_extraction",
			"auto_filtering",
			"auto_tuning",
			"wildcard_detection",
			"status_filtering",
		},
	}
}

func (f *FeroxbusterPlugin) Configure(config map[string]interface{}) error {
	if wordlist, ok := config["wordlist"].(string); ok {
		f.config.Wordlist = wordlist
	}

	if extensions, ok := config["extensions"].([]interface{}); ok {
		f.config.Extensions = make([]string, len(extensions))
		for i, e := range extensions {
			f.config.Extensions[i] = fmt.Sprintf("%v", e)
		}
	}

	if statusCodes, ok := config["status_codes"].([]interface{}); ok {
		f.config.StatusCodes = make([]string, len(statusCodes))
		for i, s := range statusCodes {
			f.config.StatusCodes[i] = fmt.Sprintf("%v", s)
		}
	}

	if filterStatus, ok := config["filter_status"].([]interface{}); ok {
		f.config.FilterStatus = make([]string, len(filterStatus))
		for i, s := range filterStatus {
			f.config.FilterStatus[i] = fmt.Sprintf("%v", s)
		}
	}

	if filterSize, ok := config["filter_size"].([]interface{}); ok {
		f.config.FilterSize = make([]string, len(filterSize))
		for i, s := range filterSize {
			f.config.FilterSize[i] = fmt.Sprintf("%v", s)
		}
	}

	if filterWords, ok := config["filter_words"].([]interface{}); ok {
		f.config.FilterWords = make([]string, len(filterWords))
		for i, w := range filterWords {
			f.config.FilterWords[i] = fmt.Sprintf("%v", w)
		}
	}

	if filterLines, ok := config["filter_lines"].([]interface{}); ok {
		f.config.FilterLines = make([]string, len(filterLines))
		for i, l := range filterLines {
			f.config.FilterLines[i] = fmt.Sprintf("%v", l)
		}
	}

	if threads, ok := config["threads"].(int); ok {
		f.config.Threads = threads
	}

	if depth, ok := config["depth"].(int); ok {
		f.config.Depth = depth
	}

	if timeout, ok := config["timeout"].(int); ok {
		f.config.Timeout = timeout
	}

	if userAgent, ok := config["user_agent"].(string); ok {
		f.config.UserAgent = userAgent
	}

	if headers, ok := config["headers"].([]interface{}); ok {
		f.config.Headers = make([]string, len(headers))
		for i, h := range headers {
			f.config.Headers[i] = fmt.Sprintf("%v", h)
		}
	}

	if cookies, ok := config["cookies"].(string); ok {
		f.config.Cookies = cookies
	}

	if proxy, ok := config["proxy"].(string); ok {
		f.config.Proxy = proxy
	}

	if redirectLimit, ok := config["redirect_limit"].(int); ok {
		f.config.RedirectLimit = redirectLimit
	}

	if rateLimit, ok := config["rate_limit"].(int); ok {
		f.config.RateLimit = rateLimit
	}

	if timeDelay, ok := config["time_delay"].(int); ok {
		f.config.TimeDelay = timeDelay
	}

	if silent, ok := config["silent"].(bool); ok {
		f.config.Silent = silent
	}

	if quiet, ok := config["quiet"].(bool); ok {
		f.config.Quiet = quiet
	}

	if noRecursion, ok := config["no_recursion"].(bool); ok {
		f.config.NoRecursion = noRecursion
	}

	if addSlash, ok := config["add_slash"].(bool); ok {
		f.config.AddSlash = addSlash
	}

	if extractLinks, ok := config["extract_links"].(bool); ok {
		f.config.ExtractLinks = extractLinks
	}

	if random, ok := config["random"].(bool); ok {
		f.config.Random = random
	}

	if autoTune, ok := config["auto_tune"].(bool); ok {
		f.config.AutoTune = autoTune
	}

	if autoBail, ok := config["auto_bail"].(bool); ok {
		f.config.AutoBail = autoBail
	}

	if outputJSON, ok := config["output_json"].(bool); ok {
		f.config.OutputJSON = outputJSON
	}

	if scanLimit, ok := config["scan_limit"].(int); ok {
		f.config.ScanLimit = scanLimit
	}

	return nil
}

func (f *FeroxbusterPlugin) Run(ctx context.Context, target *models.Target, results chan<- models.PluginResult, shared *core.SharedContext) error {
	f.SetStatus("running")
	defer f.SetStatus("completed")

	targetURLs := f.getTargetURLs(target, shared)
	if len(targetURLs) == 0 {
		targetURLs = []string{target.String()}
	}

	// Process URLs
	var wg sync.WaitGroup
	semaphore := make(chan struct{}, 2) // Limit concurrent scans (feroxbuster is resource intensive)

	for _, targetURL := range targetURLs {
		wg.Add(1)
		go func(url string) {
			defer wg.Done()
			semaphore <- struct{}{}
			defer func() { <-semaphore }()

			if err := f.scanURL(ctx, url, results, shared); err != nil {
				f.LogError("Failed to scan URL %s: %v", url, err)
			}
		}(targetURL)
	}

	wg.Wait()
	return nil
}

func (f *FeroxbusterPlugin) getTargetURLs(target *models.Target, shared *core.SharedContext) []string {
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

func (f *FeroxbusterPlugin) scanURL(ctx context.Context, targetURL string, results chan<- models.PluginResult, shared *core.SharedContext) error {
	args := []string{
		"feroxbuster",
		"-u", targetURL,
		"-w", f.config.Wordlist,
		"-t", strconv.Itoa(f.config.Threads),
		"-d", strconv.Itoa(f.config.Depth),
		"-T", strconv.Itoa(f.config.Timeout),
		"-a", f.config.UserAgent,
		"-r", strconv.Itoa(f.config.RedirectLimit),
		"-L", strconv.Itoa(f.config.RateLimit),
	}

	// Add extensions
	if len(f.config.Extensions) > 0 {
		args = append(args, "-x", strings.Join(f.config.Extensions, ","))
	}

	// Add status codes
	if len(f.config.StatusCodes) > 0 {
		args = append(args, "-s", strings.Join(f.config.StatusCodes, ","))
	}

	// Add filter status codes
	if len(f.config.FilterStatus) > 0 {
		args = append(args, "-C", strings.Join(f.config.FilterStatus, ","))
	}

	// Add filter sizes
	if len(f.config.FilterSize) > 0 {
		args = append(args, "-S", strings.Join(f.config.FilterSize, ","))
	}

	// Add filter words
	if len(f.config.FilterWords) > 0 {
		args = append(args, "-W", strings.Join(f.config.FilterWords, ","))
	}

	// Add filter lines
	if len(f.config.FilterLines) > 0 {
		args = append(args, "-N", strings.Join(f.config.FilterLines, ","))
	}

	// Add headers
	for _, header := range f.config.Headers {
		args = append(args, "-H", header)
	}

	// Add cookies
	if f.config.Cookies != "" {
		args = append(args, "-b", f.config.Cookies)
	}

	// Add proxy
	if f.config.Proxy != "" {
		args = append(args, "-p", f.config.Proxy)
	}

	// Add time delay
	if f.config.TimeDelay > 0 {
		args = append(args, "--time-delay", strconv.Itoa(f.config.TimeDelay))
	}

	// Add scan limit
	if f.config.ScanLimit > 0 {
		args = append(args, "--scan-limit", strconv.Itoa(f.config.ScanLimit))
	}

	// Add flags
	if f.config.Silent {
		args = append(args, "--silent")
	}

	if f.config.Quiet {
		args = append(args, "-q")
	}

	if f.config.NoRecursion {
		args = append(args, "-n")
	}

	if f.config.AddSlash {
		args = append(args, "-f")
	}

	if f.config.ExtractLinks {
		args = append(args, "-e")
	}

	if f.config.Random {
		args = append(args, "--random-agent")
	}

	if f.config.AutoTune {
		args = append(args, "--auto-tune")
	}

	if f.config.AutoBail {
		args = append(args, "--auto-bail")
	}

	// Add JSON output
	if f.config.OutputJSON {
		args = append(args, "--json")
	}

	execResult, err := f.ExecuteCommand(ctx, args)
	if err != nil {
		return fmt.Errorf("failed to execute feroxbuster: %w", err)
	}

	return f.parseOutput(execResult.Stdout, targetURL, results, shared)
}

func (f *FeroxbusterPlugin) parseOutput(output, targetURL string, results chan<- models.PluginResult, shared *core.SharedContext) error {
	scanner := bufio.NewScanner(strings.NewReader(output))
	
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line == "" {
			continue
		}

		var feroxResult FeroxbusterResult
		
		// Try to parse as JSON if configured
		if f.config.OutputJSON && strings.HasPrefix(line, "{") {
			if err := json.Unmarshal([]byte(line), &feroxResult); err != nil {
				// Fall back to text parsing
				feroxResult = f.parseTextLine(line, targetURL)
			}
		} else {
			feroxResult = f.parseTextLine(line, targetURL)
		}

		if feroxResult.URL == "" {
			continue
		}

		result := f.createPluginResult(feroxResult, targetURL)
		
		select {
		case results <- result:
		case <-ctx.Done():
			return ctx.Err()
		}

		// Share directory/file discoveries
		f.shareDirectoryDiscovery(shared, feroxResult)
	}

	return scanner.Err()
}

func (f *FeroxbusterPlugin) parseTextLine(line, targetURL string) FeroxbusterResult {
	// Parse feroxbuster text output format
	// Example: "200      GET        7l       12w      166c http://example.com/admin"
	
	result := FeroxbusterResult{
		Timestamp: time.Now(),
		Method:    "GET",
	}

	parts := strings.Fields(line)
	if len(parts) < 6 {
		return result
	}

	// Parse status code
	if status, err := strconv.Atoi(parts[0]); err == nil {
		result.Status = status
	}

	// Parse method
	if len(parts) > 1 {
		result.Method = parts[1]
	}

	// Parse line count (if available)
	if len(parts) > 2 && strings.HasSuffix(parts[2], "l") {
		lineStr := strings.TrimSuffix(parts[2], "l")
		if lines, err := strconv.Atoi(lineStr); err == nil {
			result.LineCount = lines
		}
	}

	// Parse word count (if available)
	if len(parts) > 3 && strings.HasSuffix(parts[3], "w") {
		wordStr := strings.TrimSuffix(parts[3], "w")
		if words, err := strconv.Atoi(wordStr); err == nil {
			result.WordCount = words
		}
	}

	// Parse content length (if available)
	if len(parts) > 4 && strings.HasSuffix(parts[4], "c") {
		sizeStr := strings.TrimSuffix(parts[4], "c")
		if size, err := strconv.Atoi(sizeStr); err == nil {
			result.ContentLength = size
		}
	}

	// Parse URL (usually the last field)
	if len(parts) > 5 {
		result.URL = parts[len(parts)-1]
		if strings.Contains(result.URL, targetURL) {
			result.Path = strings.TrimPrefix(result.URL, strings.TrimSuffix(targetURL, "/"))
		}
	}

	// Extract extension
	if strings.Contains(result.Path, ".") {
		pathParts := strings.Split(result.Path, ".")
		if len(pathParts) > 1 {
			result.Extension = pathParts[len(pathParts)-1]
		}
	}

	// Determine type
	if result.Extension != "" {
		result.Type = "file"
	} else if strings.HasSuffix(result.Path, "/") {
		result.Type = "directory"
	} else {
		result.Type = "unknown"
	}

	return result
}

func (f *FeroxbusterPlugin) createPluginResult(result FeroxbusterResult, targetURL string) models.PluginResult {
	severity := f.calculateSeverity(result)
	
	data := map[string]interface{}{
		"url":            result.URL,
		"path":           result.Path,
		"status":         result.Status,
		"content_length": result.ContentLength,
		"line_count":     result.LineCount,
		"word_count":     result.WordCount,
		"extension":      result.Extension,
		"type":           result.Type,
		"method":         result.Method,
		"redirected":     result.Redirected,
		"headers":        result.Headers,
		"wildcard_test":  result.WildcardTest,
	}

	title := fmt.Sprintf("Content Discovery: %s", result.Path)
	if result.Type != "unknown" {
		title = fmt.Sprintf("Content Discovery: %s (%s)", result.Path, result.Type)
	}

	description := fmt.Sprintf("Found %s %s with status %d", result.Type, result.Path, result.Status)
	
	if result.ContentLength > 0 {
		description += fmt.Sprintf(" (size: %d bytes)", result.ContentLength)
	}
	
	if result.Redirected != "" {
		description += fmt.Sprintf(" -> %s", result.Redirected)
	}

	return models.PluginResult{
		Plugin:      f.GetName(),
		Target:      targetURL,
		Type:        "directory_discovery",
		Severity:    severity,
		Title:       title,
		Description: description,
		Data:        data,
		Timestamp:   time.Now(),
		Confidence:  f.calculateConfidence(result),
		Risk:        f.calculateRisk(result),
	}
}

func (f *FeroxbusterPlugin) calculateSeverity(result FeroxbusterResult) models.Severity {
	// Check for sensitive paths
	pathLower := strings.ToLower(result.Path)
	
	// Critical paths
	criticalPaths := []string{"admin", "config", "backup", "database", "db", "sql", ".env", "secret", "password", "key", "private"}
	for _, criticalPath := range criticalPaths {
		if strings.Contains(pathLower, criticalPath) {
			return models.SeverityCritical
		}
	}

	// High severity paths
	highRiskPaths := []string{"upload", "internal", "dev", "test", "debug", "log", "tmp", "temp", "api", "admin"}
	for _, riskPath := range highRiskPaths {
		if strings.Contains(pathLower, riskPath) {
			return models.SeverityHigh
		}
	}

	// Check status codes
	switch result.Status {
	case 200:
		if result.Type == "file" {
			return models.SeverityMedium // Accessible file
		}
		return models.SeverityLow // Accessible directory
	case 301, 302, 307:
		return models.SeverityLow // Redirects
	case 401:
		return models.SeverityMedium // Authentication required
	case 403:
		return models.SeverityLow // Forbidden but exists
	case 405:
		return models.SeverityLow // Method not allowed but exists
	}

	// Check file extensions
	if result.Extension != "" {
		sensitiveExts := []string{"sql", "bak", "old", "config", "ini", "log", "key", "pem", "env", "conf"}
		for _, ext := range sensitiveExts {
			if result.Extension == ext {
				return models.SeverityHigh
			}
		}
		
		scriptExts := []string{"php", "asp", "aspx", "jsp", "py", "pl", "rb"}
		for _, ext := range scriptExts {
			if result.Extension == ext {
				return models.SeverityMedium
			}
		}
	}

	return models.SeverityInfo
}

func (f *FeroxbusterPlugin) calculateConfidence(result FeroxbusterResult) float64 {
	confidence := 0.85 // Base confidence for feroxbuster (has good filtering)

	// Higher confidence for successful responses
	if result.Status >= 200 && result.Status < 300 {
		confidence += 0.1
	}

	// Higher confidence for content with size
	if result.ContentLength > 0 {
		confidence += 0.05
	}

	// Cap at 1.0
	if confidence > 1.0 {
		confidence = 1.0
	}

	return confidence
}

func (f *FeroxbusterPlugin) calculateRisk(result FeroxbusterResult) float64 {
	risk := 0.3 // Base risk

	// Higher risk for sensitive paths
	pathLower := strings.ToLower(result.Path)
	
	// Critical paths
	criticalPaths := []string{"admin", "config", "database", "backup", ".env", "secret", "password", "private"}
	for _, criticalPath := range criticalPaths {
		if strings.Contains(pathLower, criticalPath) {
			risk += 0.6
			break
		}
	}

	// High risk paths
	highRiskPaths := []string{"upload", "internal", "dev", "test", "api"}
	for _, riskPath := range highRiskPaths {
		if strings.Contains(pathLower, riskPath) {
			risk += 0.4
			break
		}
	}

	// Risk based on status codes
	switch result.Status {
	case 200:
		risk += 0.3 // Direct access
	case 401:
		risk += 0.2 // Protected resource exists
	case 403:
		risk += 0.1 // Forbidden but discoverable
	}

	// Risk based on file type and extensions
	if result.Type == "file" {
		risk += 0.2
		
		if result.Extension != "" {
			highRiskExts := []string{"sql", "bak", "old", "config", "log", "env", "key"}
			for _, ext := range highRiskExts {
				if result.Extension == ext {
					risk += 0.4
					break
				}
			}
			
			scriptExts := []string{"php", "asp", "aspx", "jsp"}
			for _, ext := range scriptExts {
				if result.Extension == ext {
					risk += 0.2
					break
				}
			}
		}
	}

	// Cap at 1.0
	if risk > 1.0 {
		risk = 1.0
	}

	return risk
}

func (f *FeroxbusterPlugin) shareDirectoryDiscovery(shared *core.SharedContext, result FeroxbusterResult) {
	discoveryData := map[string]interface{}{
		"url":            result.URL,
		"path":           result.Path,
		"status":         result.Status,
		"content_length": result.ContentLength,
		"line_count":     result.LineCount,
		"word_count":     result.WordCount,
		"extension":      result.Extension,
		"type":           result.Type,
		"method":         result.Method,
		"redirected":     result.Redirected,
	}

	// Add directory discovery
	discovery := &models.Discovery{
		Type:       "directory",
		Value:      result.Path,
		Source:     f.GetName(),
		Confidence: f.calculateConfidence(result),
		Timestamp:  time.Now(),
		Data:       discoveryData,
	}
	shared.AddDiscovery(discovery)

	// Add endpoint discovery
	endpointDiscovery := &models.Discovery{
		Type:       "endpoint",
		Value:      result.URL,
		Source:     f.GetName(),
		Confidence: f.calculateConfidence(result),
		Timestamp:  time.Now(),
		Data:       discoveryData,
	}
	shared.AddDiscovery(endpointDiscovery)

	// Add file discovery if it's a file
	if result.Type == "file" || result.Extension != "" {
		fileDiscovery := &models.Discovery{
			Type:       "file",
			Value:      result.Path,
			Source:     f.GetName(),
			Confidence: f.calculateConfidence(result),
			Timestamp:  time.Now(),
			Data:       discoveryData,
		}
		shared.AddDiscovery(fileDiscovery)
	}
}

func (f *FeroxbusterPlugin) GetIntelligencePatterns() []models.IntelligencePattern {
	return []models.IntelligencePattern{
		{
			Name:        "Admin Interface Detection",
			Pattern:     `"path":".*/(admin|administrator|manage|dashboard|panel|control)"`,
			Confidence:  0.95,
			Description: "Administrative interface detected",
			Tags:        []string{"admin", "interface", "management"},
		},
		{
			Name:        "API Endpoint Detection",
			Pattern:     `"path":".*/(api|rest|graphql|v[0-9]+)"`,
			Confidence:  0.85,
			Description: "API endpoint detected",
			Tags:        []string{"api", "endpoint", "service"},
		},
		{
			Name:        "Config File Detection",
			Pattern:     `"extension":"(config|cfg|ini|conf|env)"`,
			Confidence:  0.9,
			Description: "Configuration file detected",
			Tags:        []string{"config", "file", "settings"},
		},
		{
			Name:        "Database File Detection",
			Pattern:     `"extension":"(sql|db|sqlite|mdb|dump)"`,
			Confidence:  0.95,
			Description: "Database file detected",
			Tags:        []string{"database", "file", "data"},
		},
		{
			Name:        "Backup File Detection",
			Pattern:     `"extension":"(bak|backup|old|tmp|~)"`,
			Confidence:  0.85,
			Description: "Backup file detected",
			Tags:        []string{"backup", "file", "old"},
		},
		{
			Name:        "Upload Directory Detection",
			Pattern:     `"path":".*/(upload|uploads|files|attachments|media)"`,
			Confidence:  0.8,
			Description: "Upload directory detected",
			Tags:        []string{"upload", "directory", "files"},
		},
		{
			Name:        "Development Path Detection",
			Pattern:     `"path":".*/(dev|test|debug|staging|beta|development)"`,
			Confidence:  0.8,
			Description: "Development path detected",
			Tags:        []string{"development", "test", "debug"},
		},
	}
}
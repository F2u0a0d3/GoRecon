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

type FFUFPlugin struct {
	*base.BaseAdapter
	config *FFUFConfig
}

type FFUFConfig struct {
	Wordlist        string            `json:"wordlist"`
	Extensions      []string          `json:"extensions"`
	FilterStatus    []string          `json:"filter_status"`
	FilterSize      []string          `json:"filter_size"`
	FilterWords     []string          `json:"filter_words"`
	FilterLines     []string          `json:"filter_lines"`
	FilterRegex     []string          `json:"filter_regex"`
	MatchStatus     []string          `json:"match_status"`
	MatchSize       []string          `json:"match_size"`
	MatchWords      []string          `json:"match_words"`
	MatchLines      []string          `json:"match_lines"`
	MatchRegex      []string          `json:"match_regex"`
	Threads         int               `json:"threads"`
	Timeout         int               `json:"timeout"`
	Delay           int               `json:"delay"`
	UserAgent       string            `json:"user_agent"`
	Headers         map[string]string `json:"headers"`
	Data            string            `json:"data"`
	Method          string            `json:"method"`
	Proxy           string            `json:"proxy"`
	FollowRedirects bool              `json:"follow_redirects"`
	MaxRedirects    int               `json:"max_redirects"`
	Rate            int               `json:"rate"`
	Silent          bool              `json:"silent"`
	Colors          bool              `json:"colors"`
	Verbose         bool              `json:"verbose"`
	OutputFormat    string            `json:"output_format"`
	AutoCalibrate   bool              `json:"auto_calibrate"`
	StopOn403       bool              `json:"stop_on_403"`
	StopOnErrors    bool              `json:"stop_on_errors"`
	StopOnAll       bool              `json:"stop_on_all"`
	Recursion       bool              `json:"recursion"`
	RecursionDepth  int               `json:"recursion_depth"`
}

type FFUFResult struct {
	Input    FFUFInput  `json:"input"`
	Position int        `json:"position"`
	Status   int        `json:"status"`
	Length   int        `json:"length"`
	Words    int        `json:"words"`
	Lines    int        `json:"lines"`
	URL      string     `json:"url"`
	Host     string     `json:"host"`
	Redirects []string  `json:"redirects,omitempty"`
	Duration time.Duration `json:"duration"`
	ResultFile string   `json:"resultfile,omitempty"`
}

type FFUFInput struct {
	FUZZ string `json:"FUZZ"`
}

type FFUFOutput struct {
	CommandLine string       `json:"commandline"`
	Time        string       `json:"time"`
	Results     []FFUFResult `json:"results"`
	Config      interface{}  `json:"config"`
}

func NewFFUFPlugin() *FFUFPlugin {
	config := &FFUFConfig{
		Wordlist:        "/usr/share/wordlists/dirb/common.txt", // Default wordlist
		Extensions:      []string{"php", "html", "txt", "js", "css", "asp", "aspx", "jsp", "json", "xml"},
		FilterStatus:    []string{"404"},
		FilterSize:      []string{},
		FilterWords:     []string{},
		FilterLines:     []string{},
		FilterRegex:     []string{},
		MatchStatus:     []string{},
		MatchSize:       []string{},
		MatchWords:      []string{},
		MatchLines:      []string{},
		MatchRegex:      []string{},
		Threads:         40,
		Timeout:         10,
		Delay:           0,
		UserAgent:       "ffuf/2.1.0-dev",
		Headers:         make(map[string]string),
		Method:          "GET",
		FollowRedirects: false,
		MaxRedirects:    0,
		Rate:            0,
		Silent:          false,
		Colors:          false,
		Verbose:         false,
		OutputFormat:    "json",
		AutoCalibrate:   true,
		StopOn403:       false,
		StopOnErrors:    false,
		StopOnAll:       false,
		Recursion:       false,
		RecursionDepth:  2,
	}

	return &FFUFPlugin{
		BaseAdapter: base.NewBaseAdapter("ffuf", "Fast web fuzzer written in Go"),
		config:      config,
	}
}

func (f *FFUFPlugin) GetMetadata() models.PluginMetadata {
	return models.PluginMetadata{
		Name:        "FFUF",
		Version:     "2.1.0-dev",
		Description: "Fast web fuzzer written in Go with advanced filtering and matching capabilities",
		Author:      "Joona Hoikkala",
		Tags:        []string{"fuzzing", "directory", "enumeration", "brute-force", "discovery", "web"},
		Category:    "directory_discovery",
		Priority:    9,
		Timeout:     600,
		RateLimit:   200,
		Dependencies: []string{"ffuf"},
		Capabilities: []string{
			"web_fuzzing",
			"directory_enumeration",
			"advanced_filtering",
			"pattern_matching",
			"auto_calibration",
			"recursive_discovery",
			"custom_payloads",
		},
	}
}

func (f *FFUFPlugin) Configure(config map[string]interface{}) error {
	if wordlist, ok := config["wordlist"].(string); ok {
		f.config.Wordlist = wordlist
	}

	if extensions, ok := config["extensions"].([]interface{}); ok {
		f.config.Extensions = make([]string, len(extensions))
		for i, e := range extensions {
			f.config.Extensions[i] = fmt.Sprintf("%v", e)
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

	if filterRegex, ok := config["filter_regex"].([]interface{}); ok {
		f.config.FilterRegex = make([]string, len(filterRegex))
		for i, r := range filterRegex {
			f.config.FilterRegex[i] = fmt.Sprintf("%v", r)
		}
	}

	if matchStatus, ok := config["match_status"].([]interface{}); ok {
		f.config.MatchStatus = make([]string, len(matchStatus))
		for i, s := range matchStatus {
			f.config.MatchStatus[i] = fmt.Sprintf("%v", s)
		}
	}

	if matchSize, ok := config["match_size"].([]interface{}); ok {
		f.config.MatchSize = make([]string, len(matchSize))
		for i, s := range matchSize {
			f.config.MatchSize[i] = fmt.Sprintf("%v", s)
		}
	}

	if matchWords, ok := config["match_words"].([]interface{}); ok {
		f.config.MatchWords = make([]string, len(matchWords))
		for i, w := range matchWords {
			f.config.MatchWords[i] = fmt.Sprintf("%v", w)
		}
	}

	if matchLines, ok := config["match_lines"].([]interface{}); ok {
		f.config.MatchLines = make([]string, len(matchLines))
		for i, l := range matchLines {
			f.config.MatchLines[i] = fmt.Sprintf("%v", l)
		}
	}

	if matchRegex, ok := config["match_regex"].([]interface{}); ok {
		f.config.MatchRegex = make([]string, len(matchRegex))
		for i, r := range matchRegex {
			f.config.MatchRegex[i] = fmt.Sprintf("%v", r)
		}
	}

	if threads, ok := config["threads"].(int); ok {
		f.config.Threads = threads
	}

	if timeout, ok := config["timeout"].(int); ok {
		f.config.Timeout = timeout
	}

	if delay, ok := config["delay"].(int); ok {
		f.config.Delay = delay
	}

	if userAgent, ok := config["user_agent"].(string); ok {
		f.config.UserAgent = userAgent
	}

	if headers, ok := config["headers"].(map[string]interface{}); ok {
		f.config.Headers = make(map[string]string)
		for k, v := range headers {
			f.config.Headers[k] = fmt.Sprintf("%v", v)
		}
	}

	if data, ok := config["data"].(string); ok {
		f.config.Data = data
	}

	if method, ok := config["method"].(string); ok {
		f.config.Method = method
	}

	if proxy, ok := config["proxy"].(string); ok {
		f.config.Proxy = proxy
	}

	if followRedirects, ok := config["follow_redirects"].(bool); ok {
		f.config.FollowRedirects = followRedirects
	}

	if maxRedirects, ok := config["max_redirects"].(int); ok {
		f.config.MaxRedirects = maxRedirects
	}

	if rate, ok := config["rate"].(int); ok {
		f.config.Rate = rate
	}

	if silent, ok := config["silent"].(bool); ok {
		f.config.Silent = silent
	}

	if colors, ok := config["colors"].(bool); ok {
		f.config.Colors = colors
	}

	if verbose, ok := config["verbose"].(bool); ok {
		f.config.Verbose = verbose
	}

	if outputFormat, ok := config["output_format"].(string); ok {
		f.config.OutputFormat = outputFormat
	}

	if autoCalibrate, ok := config["auto_calibrate"].(bool); ok {
		f.config.AutoCalibrate = autoCalibrate
	}

	if stopOn403, ok := config["stop_on_403"].(bool); ok {
		f.config.StopOn403 = stopOn403
	}

	if stopOnErrors, ok := config["stop_on_errors"].(bool); ok {
		f.config.StopOnErrors = stopOnErrors
	}

	if stopOnAll, ok := config["stop_on_all"].(bool); ok {
		f.config.StopOnAll = stopOnAll
	}

	if recursion, ok := config["recursion"].(bool); ok {
		f.config.Recursion = recursion
	}

	if recursionDepth, ok := config["recursion_depth"].(int); ok {
		f.config.RecursionDepth = recursionDepth
	}

	return nil
}

func (f *FFUFPlugin) Run(ctx context.Context, target *models.Target, results chan<- models.PluginResult, shared *core.SharedContext) error {
	f.SetStatus("running")
	defer f.SetStatus("completed")

	targetURLs := f.getTargetURLs(target, shared)
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

			if err := f.scanURL(ctx, url, results, shared); err != nil {
				f.LogError("Failed to scan URL %s: %v", url, err)
			}
		}(targetURL)
	}

	wg.Wait()
	return nil
}

func (f *FFUFPlugin) getTargetURLs(target *models.Target, shared *core.SharedContext) []string {
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

func (f *FFUFPlugin) scanURL(ctx context.Context, targetURL string, results chan<- models.PluginResult, shared *core.SharedContext) error {
	// Build URL with FUZZ keyword for directory fuzzing
	fuzzURL := strings.TrimSuffix(targetURL, "/") + "/FUZZ"
	
	args := []string{
		"ffuf",
		"-u", fuzzURL,
		"-w", f.config.Wordlist,
		"-t", strconv.Itoa(f.config.Threads),
		"-timeout", strconv.Itoa(f.config.Timeout),
		"-X", f.config.Method,
		"-H", "User-Agent: " + f.config.UserAgent,
	}

	// Add extensions (create separate wordlist with extensions)
	if len(f.config.Extensions) > 0 {
		// Use ffuf's extension functionality
		args = append(args, "-e", strings.Join(f.config.Extensions, ","))
	}

	// Add filter status codes
	if len(f.config.FilterStatus) > 0 {
		args = append(args, "-fc", strings.Join(f.config.FilterStatus, ","))
	}

	// Add filter sizes
	if len(f.config.FilterSize) > 0 {
		args = append(args, "-fs", strings.Join(f.config.FilterSize, ","))
	}

	// Add filter words
	if len(f.config.FilterWords) > 0 {
		args = append(args, "-fw", strings.Join(f.config.FilterWords, ","))
	}

	// Add filter lines
	if len(f.config.FilterLines) > 0 {
		args = append(args, "-fl", strings.Join(f.config.FilterLines, ","))
	}

	// Add filter regex
	if len(f.config.FilterRegex) > 0 {
		for _, regex := range f.config.FilterRegex {
			args = append(args, "-fr", regex)
		}
	}

	// Add match status codes
	if len(f.config.MatchStatus) > 0 {
		args = append(args, "-mc", strings.Join(f.config.MatchStatus, ","))
	}

	// Add match sizes
	if len(f.config.MatchSize) > 0 {
		args = append(args, "-ms", strings.Join(f.config.MatchSize, ","))
	}

	// Add match words
	if len(f.config.MatchWords) > 0 {
		args = append(args, "-mw", strings.Join(f.config.MatchWords, ","))
	}

	// Add match lines
	if len(f.config.MatchLines) > 0 {
		args = append(args, "-ml", strings.Join(f.config.MatchLines, ","))
	}

	// Add match regex
	if len(f.config.MatchRegex) > 0 {
		for _, regex := range f.config.MatchRegex {
			args = append(args, "-mr", regex)
		}
	}

	// Add custom headers
	for key, value := range f.config.Headers {
		args = append(args, "-H", fmt.Sprintf("%s: %s", key, value))
	}

	// Add POST data
	if f.config.Data != "" {
		args = append(args, "-d", f.config.Data)
	}

	// Add proxy
	if f.config.Proxy != "" {
		args = append(args, "-x", f.config.Proxy)
	}

	// Add delay
	if f.config.Delay > 0 {
		args = append(args, "-p", fmt.Sprintf("%d", f.config.Delay))
	}

	// Add rate limiting
	if f.config.Rate > 0 {
		args = append(args, "-rate", strconv.Itoa(f.config.Rate))
	}

	// Add redirect settings
	if f.config.FollowRedirects {
		args = append(args, "-r")
		if f.config.MaxRedirects > 0 {
			args = append(args, "-recursion-depth", strconv.Itoa(f.config.MaxRedirects))
		}
	}

	// Add flags
	if f.config.Silent {
		args = append(args, "-s")
	}

	if f.config.Colors {
		args = append(args, "-c")
	}

	if f.config.Verbose {
		args = append(args, "-v")
	}

	if f.config.AutoCalibrate {
		args = append(args, "-ac")
	}

	if f.config.StopOn403 {
		args = append(args, "-sf")
	}

	if f.config.StopOnErrors {
		args = append(args, "-se")
	}

	if f.config.StopOnAll {
		args = append(args, "-sa")
	}

	// Add recursion
	if f.config.Recursion {
		args = append(args, "-recursion")
		args = append(args, "-recursion-depth", strconv.Itoa(f.config.RecursionDepth))
	}

	// Add JSON output
	if f.config.OutputFormat == "json" {
		args = append(args, "-of", "json")
	}

	execResult, err := f.ExecuteCommand(ctx, args)
	if err != nil {
		return fmt.Errorf("failed to execute ffuf: %w", err)
	}

	return f.parseOutput(execResult.Stdout, targetURL, results, shared)
}

func (f *FFUFPlugin) parseOutput(output, targetURL string, results chan<- models.PluginResult, shared *core.SharedContext) error {
	if f.config.OutputFormat == "json" {
		return f.parseJSONOutput(output, targetURL, results, shared)
	}
	return f.parseTextOutput(output, targetURL, results, shared)
}

func (f *FFUFPlugin) parseJSONOutput(output, targetURL string, results chan<- models.PluginResult, shared *core.SharedContext) error {
	var ffufOutput FFUFOutput
	
	if err := json.Unmarshal([]byte(output), &ffufOutput); err != nil {
		return f.parseTextOutput(output, targetURL, results, shared)
	}

	for _, result := range ffufOutput.Results {
		pluginResult := f.createPluginResult(result, targetURL)
		
		select {
		case results <- pluginResult:
		case <-ctx.Done():
			return ctx.Err()
		}

		// Share directory/file discoveries
		f.shareDirectoryDiscovery(shared, result, targetURL)
	}

	return nil
}

func (f *FFUFPlugin) parseTextOutput(output, targetURL string, results chan<- models.PluginResult, shared *core.SharedContext) error {
	scanner := bufio.NewScanner(strings.NewReader(output))
	
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line == "" || strings.HasPrefix(line, "::") || strings.Contains(line, "Progress:") {
			continue
		}

		result := f.parseTextLine(line, targetURL)
		if result.URL == "" {
			continue
		}

		pluginResult := f.createPluginResult(result, targetURL)
		
		select {
		case results <- pluginResult:
		case <-ctx.Done():
			return ctx.Err()
		}

		// Share directory/file discoveries
		f.shareDirectoryDiscovery(shared, result, targetURL)
	}

	return scanner.Err()
}

func (f *FFUFPlugin) parseTextLine(line, targetURL string) FFUFResult {
	// Parse ffuf text output format
	// Example: "admin                   [Status: 200, Size: 4567, Words: 123, Lines: 45]"
	
	result := FFUFResult{}

	parts := strings.Fields(line)
	if len(parts) < 2 {
		return result
	}

	// Extract the path/word
	result.Input.FUZZ = parts[0]
	result.URL = strings.Replace(strings.TrimSuffix(targetURL, "/")+"/FUZZ", "FUZZ", result.Input.FUZZ, 1)

	// Parse the status information
	statusPart := strings.Join(parts[1:], " ")
	
	// Extract status code
	if statusStart := strings.Index(statusPart, "Status: "); statusStart != -1 {
		statusEnd := strings.Index(statusPart[statusStart:], ",")
		if statusEnd == -1 {
			statusEnd = strings.Index(statusPart[statusStart:], "]")
		}
		if statusEnd != -1 {
			statusStr := strings.TrimSpace(statusPart[statusStart+8 : statusStart+statusEnd])
			if status, err := strconv.Atoi(statusStr); err == nil {
				result.Status = status
			}
		}
	}

	// Extract size
	if sizeStart := strings.Index(statusPart, "Size: "); sizeStart != -1 {
		sizeEnd := strings.Index(statusPart[sizeStart:], ",")
		if sizeEnd == -1 {
			sizeEnd = strings.Index(statusPart[sizeStart:], "]")
		}
		if sizeEnd != -1 {
			sizeStr := strings.TrimSpace(statusPart[sizeStart+6 : sizeStart+sizeEnd])
			if size, err := strconv.Atoi(sizeStr); err == nil {
				result.Length = size
			}
		}
	}

	// Extract words
	if wordsStart := strings.Index(statusPart, "Words: "); wordsStart != -1 {
		wordsEnd := strings.Index(statusPart[wordsStart:], ",")
		if wordsEnd == -1 {
			wordsEnd = strings.Index(statusPart[wordsStart:], "]")
		}
		if wordsEnd != -1 {
			wordsStr := strings.TrimSpace(statusPart[wordsStart+7 : wordsStart+wordsEnd])
			if words, err := strconv.Atoi(wordsStr); err == nil {
				result.Words = words
			}
		}
	}

	// Extract lines
	if linesStart := strings.Index(statusPart, "Lines: "); linesStart != -1 {
		linesEnd := strings.Index(statusPart[linesStart:], "]")
		if linesEnd != -1 {
			linesStr := strings.TrimSpace(statusPart[linesStart+7 : linesStart+linesEnd])
			if lines, err := strconv.Atoi(linesStr); err == nil {
				result.Lines = lines
			}
		}
	}

	return result
}

func (f *FFUFPlugin) createPluginResult(result FFUFResult, targetURL string) models.PluginResult {
	severity := f.calculateSeverity(result)
	
	// Extract path from URL
	path := "/" + result.Input.FUZZ
	extension := ""
	if strings.Contains(result.Input.FUZZ, ".") {
		parts := strings.Split(result.Input.FUZZ, ".")
		if len(parts) > 1 {
			extension = parts[len(parts)-1]
		}
	}

	data := map[string]interface{}{
		"url":        result.URL,
		"path":       path,
		"fuzz_word":  result.Input.FUZZ,
		"status":     result.Status,
		"length":     result.Length,
		"words":      result.Words,
		"lines":      result.Lines,
		"extension":  extension,
		"redirects":  result.Redirects,
		"duration":   result.Duration,
		"position":   result.Position,
	}

	title := fmt.Sprintf("Web Fuzzing Discovery: %s", path)
	description := fmt.Sprintf("Found path %s with status %d", path, result.Status)
	
	if result.Length > 0 {
		description += fmt.Sprintf(" (size: %d bytes, words: %d, lines: %d)", result.Length, result.Words, result.Lines)
	}
	
	if len(result.Redirects) > 0 {
		description += fmt.Sprintf(" -> %s", strings.Join(result.Redirects, " -> "))
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

func (f *FFUFPlugin) calculateSeverity(result FFUFResult) models.Severity {
	// Check for sensitive paths
	fuzzLower := strings.ToLower(result.Input.FUZZ)
	
	// Critical paths
	criticalPaths := []string{"admin", "config", "backup", "database", "db", "sql", ".env", "secret", "password", "key", "private"}
	for _, criticalPath := range criticalPaths {
		if strings.Contains(fuzzLower, criticalPath) {
			return models.SeverityCritical
		}
	}

	// High severity paths
	highRiskPaths := []string{"upload", "internal", "dev", "test", "debug", "log", "tmp", "temp", "api", "management"}
	for _, riskPath := range highRiskPaths {
		if strings.Contains(fuzzLower, riskPath) {
			return models.SeverityHigh
		}
	}

	// Check status codes
	switch result.Status {
	case 200:
		return models.SeverityMedium // Accessible content
	case 301, 302, 307, 308:
		return models.SeverityLow // Redirects
	case 401:
		return models.SeverityMedium // Authentication required
	case 403:
		return models.SeverityLow // Forbidden but exists
	case 405:
		return models.SeverityLow // Method not allowed but exists
	}

	// Check for file extensions
	if strings.Contains(result.Input.FUZZ, ".") {
		extension := ""
		parts := strings.Split(result.Input.FUZZ, ".")
		if len(parts) > 1 {
			extension = strings.ToLower(parts[len(parts)-1])
		}
		
		sensitiveExts := []string{"sql", "bak", "old", "config", "ini", "log", "key", "pem", "env", "conf"}
		for _, ext := range sensitiveExts {
			if extension == ext {
				return models.SeverityHigh
			}
		}
		
		scriptExts := []string{"php", "asp", "aspx", "jsp", "py", "pl", "rb"}
		for _, ext := range scriptExts {
			if extension == ext {
				return models.SeverityMedium
			}
		}
	}

	return models.SeverityInfo
}

func (f *FFUFPlugin) calculateConfidence(result FFUFResult) float64 {
	confidence := 0.9 // Base confidence for ffuf (has excellent filtering)

	// Higher confidence for successful responses
	if result.Status >= 200 && result.Status < 300 {
		confidence += 0.05
	}

	// Higher confidence for content with reasonable size
	if result.Length > 0 && result.Length < 10000000 { // Avoid huge responses
		confidence += 0.05
	}

	// Cap at 1.0
	if confidence > 1.0 {
		confidence = 1.0
	}

	return confidence
}

func (f *FFUFPlugin) calculateRisk(result FFUFResult) float64 {
	risk := 0.3 // Base risk

	// Higher risk for sensitive paths
	fuzzLower := strings.ToLower(result.Input.FUZZ)
	
	// Critical paths
	criticalPaths := []string{"admin", "config", "database", "backup", ".env", "secret", "password", "private"}
	for _, criticalPath := range criticalPaths {
		if strings.Contains(fuzzLower, criticalPath) {
			risk += 0.6
			break
		}
	}

	// High risk paths
	highRiskPaths := []string{"upload", "internal", "dev", "test", "api", "management"}
	for _, riskPath := range highRiskPaths {
		if strings.Contains(fuzzLower, riskPath) {
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

	// Risk based on file extensions
	if strings.Contains(result.Input.FUZZ, ".") {
		extension := ""
		parts := strings.Split(result.Input.FUZZ, ".")
		if len(parts) > 1 {
			extension = strings.ToLower(parts[len(parts)-1])
		}
		
		highRiskExts := []string{"sql", "bak", "old", "config", "log", "env", "key"}
		for _, ext := range highRiskExts {
			if extension == ext {
				risk += 0.4
				break
			}
		}
		
		scriptExts := []string{"php", "asp", "aspx", "jsp"}
		for _, ext := range scriptExts {
			if extension == ext {
				risk += 0.2
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

func (f *FFUFPlugin) shareDirectoryDiscovery(shared *core.SharedContext, result FFUFResult, targetURL string) {
	path := "/" + result.Input.FUZZ
	extension := ""
	if strings.Contains(result.Input.FUZZ, ".") {
		parts := strings.Split(result.Input.FUZZ, ".")
		if len(parts) > 1 {
			extension = parts[len(parts)-1]
		}
	}

	discoveryData := map[string]interface{}{
		"url":        result.URL,
		"path":       path,
		"fuzz_word":  result.Input.FUZZ,
		"status":     result.Status,
		"length":     result.Length,
		"words":      result.Words,
		"lines":      result.Lines,
		"extension":  extension,
		"redirects":  result.Redirects,
	}

	// Add directory discovery
	discovery := &models.Discovery{
		Type:       "directory",
		Value:      path,
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

	// Add file discovery if it has an extension
	if extension != "" {
		fileDiscovery := &models.Discovery{
			Type:       "file",
			Value:      path,
			Source:     f.GetName(),
			Confidence: f.calculateConfidence(result),
			Timestamp:  time.Now(),
			Data:       discoveryData,
		}
		shared.AddDiscovery(fileDiscovery)
	}
}

func (f *FFUFPlugin) GetIntelligencePatterns() []models.IntelligencePattern {
	return []models.IntelligencePattern{
		{
			Name:        "Admin Panel Fuzzing",
			Pattern:     `"fuzz_word":".*admin.*"`,
			Confidence:  0.9,
			Description: "Administrative panel found through fuzzing",
			Tags:        []string{"admin", "fuzzing", "panel"},
		},
		{
			Name:        "Config File Fuzzing",
			Pattern:     `"fuzz_word":".*\.(config|cfg|ini|conf)"`,
			Confidence:  0.85,
			Description: "Configuration file found through fuzzing",
			Tags:        []string{"config", "file", "fuzzing"},
		},
		{
			Name:        "Backup File Fuzzing",
			Pattern:     `"fuzz_word":".*\.(bak|backup|old|~)"`,
			Confidence:  0.8,
			Description: "Backup file found through fuzzing",
			Tags:        []string{"backup", "file", "fuzzing"},
		},
		{
			Name:        "API Endpoint Fuzzing",
			Pattern:     `"fuzz_word":".*/(api|rest|v[0-9]+)"`,
			Confidence:  0.85,
			Description: "API endpoint found through fuzzing",
			Tags:        []string{"api", "endpoint", "fuzzing"},
		},
		{
			Name:        "Database File Fuzzing",
			Pattern:     `"fuzz_word":".*\.(sql|db|sqlite)"`,
			Confidence:  0.9,
			Description: "Database file found through fuzzing",
			Tags:        []string{"database", "file", "fuzzing"},
		},
		{
			Name:        "Development Path Fuzzing",
			Pattern:     `"fuzz_word":".*/(dev|test|debug|staging)"`,
			Confidence:  0.75,
			Description: "Development path found through fuzzing",
			Tags:        []string{"development", "test", "fuzzing"},
		},
	}
}
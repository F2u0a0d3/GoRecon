package crawl

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

// CrawlPlugin implements web crawling and content discovery
type CrawlPlugin struct {
	*base.BaseAdapter
	config *CrawlConfig
}

// CrawlConfig contains crawling configuration
type CrawlConfig struct {
	EnableHakrawler bool          `json:"enable_hakrawler"`
	EnableGospider  bool          `json:"enable_gospider"`
	Depth           int           `json:"depth"`
	Threads         int           `json:"threads"`
	Timeout         time.Duration `json:"timeout"`
	FollowRedirects bool          `json:"follow_redirects"`
	UserAgent       string        `json:"user_agent"`
	IncludeSubdomains bool        `json:"include_subdomains"`
}

// CrawlResult represents a crawling result
type CrawlResult struct {
	URL         string            `json:"url"`
	Source      string            `json:"source"`
	StatusCode  int               `json:"status_code"`
	ContentType string            `json:"content_type"`
	Title       string            `json:"title"`
	Words       int               `json:"words"`
	Lines       int               `json:"lines"`
	Length      int               `json:"length"`
	Links       []string          `json:"links"`
	Forms       []FormResult      `json:"forms"`
	Comments    []string          `json:"comments"`
	JSFiles     []string          `json:"js_files"`
	CSSFiles    []string          `json:"css_files"`
	Images      []string          `json:"images"`
	Metadata    map[string]string `json:"metadata"`
	Tool        string            `json:"tool"`
	Timestamp   time.Time         `json:"timestamp"`
	Confidence  float64           `json:"confidence"`
}

// FormResult represents a discovered form
type FormResult struct {
	Action     string              `json:"action"`
	Method     string              `json:"method"`
	Fields     []FormField         `json:"fields"`
	Attributes map[string]string   `json:"attributes"`
}

// FormField represents a form input field
type FormField struct {
	Name        string `json:"name"`
	Type        string `json:"type"`
	Value       string `json:"value"`
	Required    bool   `json:"required"`
	Placeholder string `json:"placeholder"`
}

// CrawlStats contains crawling statistics
type CrawlStats struct {
	TotalURLs        int                    `json:"total_urls"`
	CrawledURLs      int                    `json:"crawled_urls"`
	TotalLinks       int                    `json:"total_links"`
	TotalForms       int                    `json:"total_forms"`
	TotalJSFiles     int                    `json:"total_js_files"`
	ByStatusCode     map[int]int            `json:"by_status_code"`
	ByContentType    map[string]int         `json:"by_content_type"`
	ByTool           map[string]int         `json:"by_tool"`
	CrawlDuration    time.Duration          `json:"crawl_duration"`
}

// ToolCrawlResult represents results from individual crawling tools
type ToolCrawlResult struct {
	Tool     string       `json:"tool"`
	Results  []CrawlResult `json:"results"`
	Error    error        `json:"error,omitempty"`
	Duration time.Duration `json:"duration"`
}

// NewCrawlPlugin creates a new web crawling plugin
func NewCrawlPlugin() *CrawlPlugin {
	config := &CrawlConfig{
		EnableHakrawler:   true,
		EnableGospider:    false,
		Depth:             3,
		Threads:           10,
		Timeout:           60 * time.Second,
		FollowRedirects:   true,
		UserAgent:         "GORECON/2.0 Web Crawler",
		IncludeSubdomains: true,
	}

	baseAdapter := base.NewBaseAdapter(base.BaseAdapterConfig{
		Name:        "crawl",
		Category:    "crawl",
		Description: "Web crawling and content discovery",
		Version:     "1.0.0",
		Author:      "GoRecon Team",
		ToolName:    "hakrawler",
		Passive:     false,
		Duration:    45 * time.Minute,
		Concurrency: 1,
		Priority:    9,
		Resources: core.Resources{
			CPUCores:      2,
			MemoryMB:      2048,
			NetworkAccess: true,
		},
		Provides: []string{"web_pages", "endpoints", "forms", "links"},
		Consumes: []string{"http_services", "urls"},
	})

	return &CrawlPlugin{
		BaseAdapter: baseAdapter,
		config:      config,
	}
}

// Run executes web crawling
func (c *CrawlPlugin) Run(ctx context.Context, target *models.Target, results chan<- models.PluginResult, shared *core.SharedContext) error {
	logger := shared.GetLogger().WithField("plugin", "crawl")
	
	cyan := color.New(color.FgCyan).SprintFunc()
	white := color.New(color.FgWhite, color.Bold).SprintFunc()

	domain := target.Domain
	if domain == "" {
		domain = c.ExtractDomain(target.URL)
	}

	fmt.Printf("\n%s\n", white("[GORECON] Web Crawler v1.0"))
	fmt.Printf("%s\n", strings.Repeat("=", 28))
	fmt.Printf("[%s] Using hakrawler for comprehensive web crawling\n", cyan("*"))

	crawlURLs := c.collectCrawlURLs(shared, domain, target)
	fmt.Printf("[%s] Crawling %d HTTP services from previous steps...\n\n", cyan("*"), len(crawlURLs))

	workDir := filepath.Join("./work", domain, "crawl")
	if err := os.MkdirAll(workDir, 0755); err != nil {
		return fmt.Errorf("failed to create workspace: %w", err)
	}
	
	rawDir := filepath.Join(workDir, "raw")
	if err := os.MkdirAll(rawDir, 0755); err != nil {
		return fmt.Errorf("failed to create directory: %w", err)
	}

	crawlResults, stats, err := c.runWebCrawling(ctx, crawlURLs, rawDir)
	if err != nil {
		logger.Error("Web crawling failed", err)
		return err
	}

	c.displayResults(crawlResults, stats)
	c.generatePluginResults(target, crawlResults, results)
	c.addDiscoveries(shared, domain, crawlResults)

	logger.Info("Web crawling completed",
		"target", domain,
		"crawled_urls", stats.CrawledURLs,
		"total_links", stats.TotalLinks,
		"total_forms", stats.TotalForms)

	return nil
}

func (c *CrawlPlugin) collectCrawlURLs(shared *core.SharedContext, domain string, target *models.Target) []string {
	urlSet := make(map[string]bool)

	// Add target URL
	if target.URL != "" {
		urlSet[target.URL] = true
	}

	// Add root domain URLs
	urlSet[fmt.Sprintf("https://%s", domain)] = true
	urlSet[fmt.Sprintf("http://%s", domain)] = true

	// Collect HTTP services from discoveries
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
		case "historical_url":
			if strings.Contains(value, domain) && (strings.HasPrefix(value, "http://") || strings.HasPrefix(value, "https://")) {
				urlSet[value] = true
			}
		case "open_port":
			if metadata, ok := discovery.Metadata["port"].(int); ok {
				if metadata == 80 || metadata == 8080 {
					urlSet[fmt.Sprintf("http://%s:%d", domain, metadata)] = true
				} else if metadata == 443 || metadata == 8443 {
					urlSet[fmt.Sprintf("https://%s:%d", domain, metadata)] = true
				}
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

func (c *CrawlPlugin) runWebCrawling(ctx context.Context, crawlURLs []string, rawDir string) ([]CrawlResult, CrawlStats, error) {
	white := color.New(color.FgWhite, color.Bold).SprintFunc()
	cyan := color.New(color.FgCyan).SprintFunc()

	fmt.Printf("%s\n", white("[GORECON::CRAWL] Web Content Discovery"))
	fmt.Printf("%s\n", strings.Repeat("=", 40))

	startTime := time.Now()
	var allResults []CrawlResult
	var wg sync.WaitGroup
	var mu sync.Mutex

	// Check if hakrawler is available
	hakrawlerAvailable := false
	if _, err := exec.LookPath("hakrawler"); err == nil {
		hakrawlerAvailable = true
	}

	// Define crawling tools
	var crawlTools []struct {
		name    string
		enabled bool
		fn      func() ToolCrawlResult
	}

	if c.config.EnableHakrawler && hakrawlerAvailable {
		crawlTools = append(crawlTools, struct {
			name    string
			enabled bool
			fn      func() ToolCrawlResult
		}{"hakrawler", true, func() ToolCrawlResult { return c.runHakrawler(ctx, crawlURLs, rawDir) }})
	} else {
		// Use built-in crawler as fallback
		fmt.Printf("[%s] hakrawler not found, using built-in HTTP crawler\n", cyan("*"))
		crawlTools = append(crawlTools, struct {
			name    string
			enabled bool
			fn      func() ToolCrawlResult
		}{"builtin", true, func() ToolCrawlResult { return c.runBuiltinCrawler(ctx, crawlURLs, rawDir) }})
	}

	// Run enabled tools in parallel
	toolResults := make([]ToolCrawlResult, 0)
	for _, tool := range crawlTools {
		if !tool.enabled {
			continue
		}

		wg.Add(1)
		go func(toolName string, toolFn func() ToolCrawlResult) {
			defer wg.Done()
			
			fmt.Printf("[%s] Running %s crawler...\n", cyan("*"), toolName)
			result := toolFn()
			
			mu.Lock()
			toolResults = append(toolResults, result)
			mu.Unlock()
			
			if result.Error != nil {
				fmt.Printf("[%s] %s crawling failed: %v\n", cyan("-"), toolName, result.Error)
			} else {
				fmt.Printf("[%s] %s found %d pages\n", cyan("+"), toolName, len(result.Results))
			}
		}(tool.name, tool.fn)
	}

	wg.Wait()

	// Merge and deduplicate results
	resultMap := make(map[string]*CrawlResult)
	for _, toolResult := range toolResults {
		for _, result := range toolResult.Results {
			existing, exists := resultMap[result.URL]
			if exists {
				// Merge results from multiple tools
				existing.Links = c.mergeStringSlices(existing.Links, result.Links)
				existing.Comments = c.mergeStringSlices(existing.Comments, result.Comments)
				existing.JSFiles = c.mergeStringSlices(existing.JSFiles, result.JSFiles)
				existing.CSSFiles = c.mergeStringSlices(existing.CSSFiles, result.CSSFiles)
				existing.Images = c.mergeStringSlices(existing.Images, result.Images)
				existing.Forms = c.mergeForms(existing.Forms, result.Forms)
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
	stats := CrawlStats{
		TotalURLs:        len(crawlURLs),
		CrawledURLs:      len(allResults),
		ByStatusCode:     make(map[int]int),
		ByContentType:    make(map[string]int),
		ByTool:           make(map[string]int),
		CrawlDuration:    time.Since(startTime),
	}

	for _, result := range allResults {
		stats.TotalLinks += len(result.Links)
		stats.TotalForms += len(result.Forms)
		stats.TotalJSFiles += len(result.JSFiles)
		stats.ByStatusCode[result.StatusCode]++
		if result.ContentType != "" {
			stats.ByContentType[result.ContentType]++
		}
		stats.ByTool[result.Tool]++
	}

	return allResults, stats, nil
}

func (c *CrawlPlugin) runHakrawler(ctx context.Context, crawlURLs []string, rawDir string) ToolCrawlResult {
	red := color.New(color.FgRed).SprintFunc()
	cyan := color.New(color.FgCyan).SprintFunc()

	if _, err := exec.LookPath("hakrawler"); err != nil {
		fmt.Printf("[%s] hakrawler not found\n", red("!"))
		fmt.Printf("[%s] Install: go install github.com/hakluke/hakrawler@latest\n", cyan("*"))
		return ToolCrawlResult{
			Tool:    "hakrawler",
			Results: []CrawlResult{},
			Error:   fmt.Errorf("hakrawler not installed"),
		}
	}

	startTime := time.Now()
	var results []CrawlResult

	// Run hakrawler with URLs from stdin
	outputFile := filepath.Join(rawDir, "hakrawler_output.txt")
	args := []string{
		"-d", strconv.Itoa(c.config.Depth),
		"-insecure",
		"-u", // unique URLs only
	}

	if c.config.IncludeSubdomains {
		args = append(args, "-subs")
	}

	cmd := exec.CommandContext(ctx, "hakrawler", args...)
	
	// Provide URLs via stdin
	urlInput := strings.Join(crawlURLs, "\n")
	cmd.Stdin = strings.NewReader(urlInput)
	
	output, err := cmd.Output()
	if err != nil {
		return ToolCrawlResult{Tool: "hakrawler", Results: []CrawlResult{}, Error: fmt.Errorf("hakrawler failed: %w", err)}
	}

	// Save output
	if err := os.WriteFile(outputFile, output, 0644); err != nil {
		return ToolCrawlResult{Tool: "hakrawler", Results: []CrawlResult{}, Error: err}
	}

	// Parse hakrawler output
	hakrawlerResults, err := c.parseHakrawlerOutput(outputFile)
	if err != nil {
		return ToolCrawlResult{Tool: "hakrawler", Results: []CrawlResult{}, Error: err}
	}

	results = append(results, hakrawlerResults...)

	return ToolCrawlResult{
		Tool:     "hakrawler",
		Results:  results,
		Duration: time.Since(startTime),
	}
}

func (c *CrawlPlugin) runGospider(ctx context.Context, crawlURLs []string, rawDir string) ToolCrawlResult {
	red := color.New(color.FgRed).SprintFunc()
	cyan := color.New(color.FgCyan).SprintFunc()

	if _, err := exec.LookPath("gospider"); err != nil {
		fmt.Printf("[%s] gospider not found\n", red("!"))
		fmt.Printf("[%s] Install: go install github.com/jaeles-project/gospider@latest\n", cyan("*"))
		return ToolCrawlResult{
			Tool:    "gospider",
			Results: []CrawlResult{},
			Error:   fmt.Errorf("gospider not installed"),
		}
	}

	startTime := time.Now()
	var results []CrawlResult

	// Run gospider for each URL
	for i, url := range crawlURLs {
		urlOutputFile := filepath.Join(rawDir, fmt.Sprintf("gospider_%d.json", i))
		
		args := []string{
			"-s", url,
			"-d", strconv.Itoa(c.config.Depth),
			"-t", strconv.Itoa(c.config.Threads),
			"-o", urlOutputFile,
			"-json",
			"--no-redirect",
		}

		if c.config.IncludeSubdomains {
			args = append(args, "--include-subs")
		}

		cmd := exec.CommandContext(ctx, "gospider", args...)
		if err := cmd.Run(); err != nil {
			continue // Skip failed URLs
		}

		// Parse individual output
		gospiderResults, err := c.parseGospiderOutput(urlOutputFile)
		if err != nil {
			continue
		}

		results = append(results, gospiderResults...)
		
		// Clean up individual file
		os.Remove(urlOutputFile)
	}

	return ToolCrawlResult{
		Tool:     "gospider",
		Results:  results,
		Duration: time.Since(startTime),
	}
}

func (c *CrawlPlugin) runBuiltinCrawler(ctx context.Context, crawlURLs []string, rawDir string) ToolCrawlResult {
	startTime := time.Now()
	var results []CrawlResult

	client := &http.Client{
		Timeout: c.config.Timeout,
		Transport: &http.Transport{
			TLSClientConfig: &tls.Config{InsecureSkipVerify: true},
		},
	}

	for _, url := range crawlURLs {
		select {
		case <-ctx.Done():
			break
		default:
		}

		result, err := c.crawlURL(client, url)
		if err != nil {
			continue
		}
		results = append(results, result)
	}

	return ToolCrawlResult{
		Tool:     "builtin",
		Results:  results,
		Duration: time.Since(startTime),
	}
}

func (c *CrawlPlugin) crawlURL(client *http.Client, targetURL string) (CrawlResult, error) {
	req, err := http.NewRequest("GET", targetURL, nil)
	if err != nil {
		return CrawlResult{}, err
	}

	req.Header.Set("User-Agent", c.config.UserAgent)
	req.Header.Set("Accept", "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8")

	resp, err := client.Do(req)
	if err != nil {
		return CrawlResult{}, err
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return CrawlResult{}, err
	}

	content := string(body)
	result := CrawlResult{
		URL:         targetURL,
		Source:      targetURL,
		StatusCode:  resp.StatusCode,
		ContentType: resp.Header.Get("Content-Type"),
		Length:      len(content),
		Tool:        "builtin",
		Timestamp:   time.Now(),
		Confidence:  0.9,
		Metadata:    make(map[string]string),
	}

	// Extract title
	if titleMatch := regexp.MustCompile(`<title[^>]*>([^<]+)</title>`).FindStringSubmatch(content); len(titleMatch) > 1 {
		result.Title = strings.TrimSpace(titleMatch[1])
	}

	// Extract links
	linkRegex := regexp.MustCompile(`href=["']([^"']+)["']`)
	linkMatches := linkRegex.FindAllStringSubmatch(content, -1)
	for _, match := range linkMatches {
		if len(match) > 1 {
			link := c.resolveURL(targetURL, match[1])
			if link != "" && !c.containsString(result.Links, link) {
				result.Links = append(result.Links, link)
			}
		}
	}

	// Extract JS files
	jsRegex := regexp.MustCompile(`<script[^>]+src=["']([^"']+)["'][^>]*>`)
	jsMatches := jsRegex.FindAllStringSubmatch(content, -1)
	for _, match := range jsMatches {
		if len(match) > 1 {
			jsFile := c.resolveURL(targetURL, match[1])
			if jsFile != "" && !c.containsString(result.JSFiles, jsFile) {
				result.JSFiles = append(result.JSFiles, jsFile)
			}
		}
	}

	// Extract CSS files
	cssRegex := regexp.MustCompile(`<link[^>]+href=["']([^"']+\.css[^"']*)["'][^>]*>`)
	cssMatches := cssRegex.FindAllStringSubmatch(content, -1)
	for _, match := range cssMatches {
		if len(match) > 1 {
			cssFile := c.resolveURL(targetURL, match[1])
			if cssFile != "" && !c.containsString(result.CSSFiles, cssFile) {
				result.CSSFiles = append(result.CSSFiles, cssFile)
			}
		}
	}

	// Extract forms
	formRegex := regexp.MustCompile(`<form[^>]*action=["']([^"']+)["'][^>]*method=["']([^"']+)["'][^>]*>(.*?)</form>`)
	formMatches := formRegex.FindAllStringSubmatch(content, -1)
	for _, match := range formMatches {
		if len(match) > 3 {
			form := FormResult{
				Action:     c.resolveURL(targetURL, match[1]),
				Method:     strings.ToUpper(match[2]),
				Attributes: make(map[string]string),
			}

			// Extract form fields
			fieldRegex := regexp.MustCompile(`<input[^>]+name=["']([^"']+)["'][^>]*(?:type=["']([^"']+)["'][^>]*)?(?:value=["']([^"']+)["'][^>]*)?(?:placeholder=["']([^"']+)["'][^>]*)?(?:required[^>]*)?/>`)
			fieldMatches := fieldRegex.FindAllStringSubmatch(match[3], -1)
			for _, fieldMatch := range fieldMatches {
				field := FormField{
					Name: fieldMatch[1],
				}
				if len(fieldMatch) > 2 && fieldMatch[2] != "" {
					field.Type = fieldMatch[2]
				}
				if len(fieldMatch) > 3 && fieldMatch[3] != "" {
					field.Value = fieldMatch[3]
				}
				if len(fieldMatch) > 4 && fieldMatch[4] != "" {
					field.Placeholder = fieldMatch[4]
				}
				form.Fields = append(form.Fields, field)
			}

			result.Forms = append(result.Forms, form)
		}
	}

	// Count words and lines
	words := strings.Fields(content)
	result.Words = len(words)
	result.Lines = len(strings.Split(content, "\n"))

	return result, nil
}

func (c *CrawlPlugin) parseHakrawlerOutput(filename string) ([]CrawlResult, error) {
	data, err := os.ReadFile(filename)
	if err != nil {
		return nil, err
	}

	var results []CrawlResult
	lines := strings.Split(string(data), "\n")
	
	urlPattern := regexp.MustCompile(`^https?://[^\s]+$`)

	for _, line := range lines {
		line = strings.TrimSpace(line)
		if line == "" {
			continue
		}

		if urlPattern.MatchString(line) {
			result := CrawlResult{
				URL:        line,
				Source:     line,
				Tool:       "hakrawler",
				Timestamp:  time.Now(),
				Confidence: 0.8,
				Metadata:   make(map[string]string),
			}

			// Classify URL type
			if strings.HasSuffix(line, ".js") {
				result.JSFiles = append(result.JSFiles, line)
			} else if strings.HasSuffix(line, ".css") {
				result.CSSFiles = append(result.CSSFiles, line)
			} else if c.isImageURL(line) {
				result.Images = append(result.Images, line)
			} else {
				result.Links = append(result.Links, line)
			}

			results = append(results, result)
		}
	}

	return results, nil
}

func (c *CrawlPlugin) parseGospiderOutput(filename string) ([]CrawlResult, error) {
	data, err := os.ReadFile(filename)
	if err != nil {
		return nil, err
	}

	var results []CrawlResult
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

		result := CrawlResult{
			Tool:       "gospider",
			Timestamp:  time.Now(),
			Confidence: 0.85,
			Metadata:   make(map[string]string),
		}

		if url, ok := raw["url"].(string); ok {
			result.URL = url
		}
		if source, ok := raw["source"].(string); ok {
			result.Source = source
		}
		if statusCode, ok := raw["status_code"].(float64); ok {
			result.StatusCode = int(statusCode)
		}
		if contentType, ok := raw["content_type"].(string); ok {
			result.ContentType = contentType
		}
		if title, ok := raw["title"].(string); ok {
			result.Title = title
		}
		if length, ok := raw["content_length"].(float64); ok {
			result.Length = int(length)
		}

		results = append(results, result)
	}

	return results, nil
}

func (c *CrawlPlugin) saveURLsToFile(urls []string, filename string) error {
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

func (c *CrawlPlugin) displayResults(results []CrawlResult, stats CrawlStats) {
	green := color.New(color.FgGreen).SprintFunc()

	for _, result := range results {
		fmt.Printf("[%s] %s\n", green("+"), result.URL)
	}
}

func (c *CrawlPlugin) generatePluginResults(target *models.Target, results []CrawlResult, resultsChan chan<- models.PluginResult) {
	for _, result := range results {
		severity := models.SeverityLow
		if len(result.Forms) > 0 {
			severity = models.SeverityMedium
		}
		if result.StatusCode >= 500 {
			severity = models.SeverityMedium
		} else if result.StatusCode == 401 || result.StatusCode == 403 {
			severity = models.SeverityMedium
		}

		pluginResult := models.PluginResult{
			Plugin:      "crawl",
			Target:      target.URL,
			Severity:    severity,
			Title:       fmt.Sprintf("Web Page: %s", result.URL),
			Description: fmt.Sprintf("Discovered web page with %d links and %d forms", len(result.Links), len(result.Forms)),
			Data: map[string]interface{}{
				"url":          result.URL,
				"source":       result.Source,
				"status_code":  result.StatusCode,
				"content_type": result.ContentType,
				"title":        result.Title,
				"links":        result.Links,
				"forms":        result.Forms,
				"js_files":     result.JSFiles,
				"css_files":    result.CSSFiles,
				"images":       result.Images,
				"tool":         result.Tool,
			},
			Timestamp: time.Now(),
		}
		resultsChan <- pluginResult
	}
}

func (c *CrawlPlugin) addDiscoveries(shared *core.SharedContext, domain string, results []CrawlResult) {
	for _, result := range results {
		// Add page discovery
		shared.AddDiscovery(models.Discovery{
			Type:       "web_page",
			Value:      result.URL,
			Source:     "crawl",
			Confidence: result.Confidence,
			Timestamp:  time.Now(),
			Metadata: map[string]interface{}{
				"status_code":  result.StatusCode,
				"content_type": result.ContentType,
				"title":        result.Title,
				"tool":         result.Tool,
				"domain":       domain,
			},
		})

		// Add link discoveries
		for _, link := range result.Links {
			shared.AddDiscovery(models.Discovery{
				Type:       "endpoint",
				Value:      link,
				Source:     "crawl",
				Confidence: result.Confidence * 0.9,
				Timestamp:  time.Now(),
				Metadata: map[string]interface{}{
					"source_page": result.URL,
					"tool":        result.Tool,
					"domain":      domain,
				},
			})
		}

		// Add form discoveries
		for _, form := range result.Forms {
			shared.AddDiscovery(models.Discovery{
				Type:       "form",
				Value:      form.Action,
				Source:     "crawl",
				Confidence: result.Confidence,
				Timestamp:  time.Now(),
				Metadata: map[string]interface{}{
					"method":      form.Method,
					"fields":      len(form.Fields),
					"source_page": result.URL,
					"tool":        result.Tool,
					"domain":      domain,
				},
			})
		}

		// Add JS file discoveries
		for _, jsFile := range result.JSFiles {
			shared.AddDiscovery(models.Discovery{
				Type:       "js_file",
				Value:      jsFile,
				Source:     "crawl",
				Confidence: result.Confidence,
				Timestamp:  time.Now(),
				Metadata: map[string]interface{}{
					"source_page": result.URL,
					"tool":        result.Tool,
					"domain":      domain,
				},
			})
		}
	}
}

// Helper functions
func (c *CrawlPlugin) mergeStringSlices(slice1, slice2 []string) []string {
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

func (c *CrawlPlugin) mergeForms(forms1, forms2 []FormResult) []FormResult {
	set := make(map[string]FormResult)
	
	for _, form := range forms1 {
		key := fmt.Sprintf("%s:%s", form.Method, form.Action)
		set[key] = form
	}
	
	for _, form := range forms2 {
		key := fmt.Sprintf("%s:%s", form.Method, form.Action)
		if _, exists := set[key]; !exists {
			set[key] = form
		}
	}
	
	var result []FormResult
	for _, form := range set {
		result = append(result, form)
	}
	return result
}

func (c *CrawlPlugin) isImageURL(url string) bool {
	imageExts := []string{".jpg", ".jpeg", ".png", ".gif", ".bmp", ".svg", ".webp", ".ico"}
	lowerURL := strings.ToLower(url)
	
	for _, ext := range imageExts {
		if strings.HasSuffix(lowerURL, ext) {
			return true
		}
	}
	return false
}

func (c *CrawlPlugin) resolveURL(baseURL, targetURL string) string {
	// Skip non-HTTP URLs
	if strings.HasPrefix(targetURL, "javascript:") || strings.HasPrefix(targetURL, "mailto:") || strings.HasPrefix(targetURL, "tel:") {
		return ""
	}

	// Skip empty or fragment-only URLs
	if targetURL == "" || strings.HasPrefix(targetURL, "#") {
		return ""
	}

	base, err := url.Parse(baseURL)
	if err != nil {
		return ""
	}

	target, err := url.Parse(targetURL)
	if err != nil {
		return ""
	}

	resolved := base.ResolveReference(target)
	return resolved.String()
}

func (c *CrawlPlugin) containsString(slice []string, str string) bool {
	for _, item := range slice {
		if item == str {
			return true
		}
	}
	return false
}
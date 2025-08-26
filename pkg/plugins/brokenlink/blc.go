package brokenlink

import (
	"bufio"
	"context"
	"crypto/tls"
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

// BLCPlugin implements broken link checking
type BLCPlugin struct {
	*base.BaseAdapter
	config *BLCConfig
}

// BLCConfig contains broken link check configuration
type BLCConfig struct {
	MaxConcurrency int           `json:"max_concurrency"`
	Timeout        time.Duration `json:"timeout"`
	UserAgent      string        `json:"user_agent"`
	FollowRedirects bool         `json:"follow_redirects"`
	MaxRedirects    int          `json:"max_redirects"`
	CheckExternal   bool         `json:"check_external"`
}

// BLCResult represents a broken link check result
type BLCResult struct {
	URL          string            `json:"url"`
	SourceURL    string            `json:"source_url"`
	StatusCode   int               `json:"status_code"`
	Error        string            `json:"error,omitempty"`
	ResponseTime time.Duration     `json:"response_time"`
	ContentType  string            `json:"content_type"`
	Title        string            `json:"title"`
	RedirectChain []string         `json:"redirect_chain,omitempty"`
	Metadata     map[string]string `json:"metadata"`
	Tool         string            `json:"tool"`
	Timestamp    time.Time         `json:"timestamp"`
	IsBroken     bool              `json:"is_broken"`
}

// BLCStats contains broken link check statistics
type BLCStats struct {
	TotalLinks    int                    `json:"total_links"`
	BrokenLinks   int                    `json:"broken_links"`
	CheckedLinks  int                    `json:"checked_links"`
	ByStatusCode  map[int]int            `json:"by_status_code"`
	AverageTime   time.Duration          `json:"average_time"`
	CheckDuration time.Duration          `json:"check_duration"`
}

// NewBLCPlugin creates a new broken link checker plugin
func NewBLCPlugin() *BLCPlugin {
	config := &BLCConfig{
		MaxConcurrency:  5,
		Timeout:         10 * time.Second,
		UserAgent:       "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36",
		FollowRedirects: true,
		MaxRedirects:    3,
		CheckExternal:   false,
	}

	baseAdapter := base.NewBaseAdapter(base.BaseAdapterConfig{
		Name:        "blc",
		Category:    "blc",
		Description: "Broken link checking and validation",
		Version:     "1.0.0",
		Author:      "GoRecon Team",
		ToolName:    "blc",
		Passive:     false,
		Duration:    10 * time.Minute,
		Concurrency: 1,
		Priority:    6,
		Resources: core.Resources{
			CPUCores:      1,
			MemoryMB:      512,
			NetworkAccess: true,
		},
		Provides: []string{"broken_links", "link_status"},
		Consumes: []string{"web_pages", "endpoints", "links"},
	})

	return &BLCPlugin{
		BaseAdapter: baseAdapter,
		config:      config,
	}
}

// Run executes broken link checking
func (b *BLCPlugin) Run(ctx context.Context, target *models.Target, results chan<- models.PluginResult, shared *core.SharedContext) error {
	logger := shared.GetLogger().WithField("plugin", "blc")
	
	cyan := color.New(color.FgCyan).SprintFunc()
	white := color.New(color.FgWhite, color.Bold).SprintFunc()

	domain := target.Domain
	if domain == "" {
		domain = b.ExtractDomain(target.URL)
	}

	fmt.Printf("\n%s\n", white("[GORECON] Broken Link Checker v1.0"))
	fmt.Printf("%s\n", strings.Repeat("=", 35))
	fmt.Printf("[%s] Checking links for broken responses and issues\n", cyan("*"))

	links := b.collectLinksToCheck(shared, domain, target)
	
	fmt.Printf("[%s] Checking %d links from crawling and discovery steps...\n\n", cyan("*"), len(links))

	if len(links) == 0 {
		fmt.Printf("[%s] No links found to check\n", cyan("!"))
		return nil
	}

	blcResults, stats, err := b.runBrokenLinkCheck(ctx, links)
	if err != nil {
		logger.Error("Broken link check failed", err)
		return err
	}

	b.displayResults(blcResults, stats)
	b.generatePluginResults(target, blcResults, results)
	b.addDiscoveries(shared, domain, blcResults)

	logger.Info("Broken link check completed",
		"target", domain,
		"checked_links", stats.CheckedLinks,
		"broken_links", stats.BrokenLinks)

	return nil
}

func (b *BLCPlugin) collectLinksToCheck(shared *core.SharedContext, domain string, target *models.Target) []string {
	linkSet := make(map[string]string) // URL -> source URL

	// Add target URL
	if target.URL != "" {
		linkSet[target.URL] = "target"
	}

	// Try to get links by crawling the target page
	if target.URL != "" && (len(linkSet) <= 1) {
		pageLinks := b.extractLinksFromPage(target.URL, domain)
		for _, link := range pageLinks {
			linkSet[link] = target.URL
		}
	}

	// Collect links from discoveries
	discoveries := shared.GetDiscoveries("")
	for _, discovery := range discoveries {
		value, ok := discovery.Value.(string)
		if !ok {
			continue
		}

		var sourceURL string
		if source, exists := discovery.Metadata["source_page"]; exists {
			if srcStr, ok := source.(string); ok {
				sourceURL = srcStr
			}
		}
		if sourceURL == "" {
			sourceURL = "discovery"
		}

		switch discovery.Type {
		case "web_page", "endpoint":
			if strings.Contains(value, domain) && (strings.HasPrefix(value, "http://") || strings.HasPrefix(value, "https://")) {
				linkSet[value] = sourceURL
			}
		case "js_file":
			if strings.Contains(value, domain) {
				linkSet[value] = sourceURL
			}
		}
	}

	var links []string
	for link := range linkSet {
		links = append(links, link)
	}
	sort.Strings(links)

	return links
}

func (b *BLCPlugin) extractLinksFromPage(targetURL, domain string) []string {
	client := &http.Client{
		Timeout: 5 * time.Second,
		Transport: &http.Transport{
			TLSClientConfig: &tls.Config{InsecureSkipVerify: true},
		},
	}

	req, err := http.NewRequest("GET", targetURL, nil)
	if err != nil {
		return nil
	}

	req.Header.Set("User-Agent", b.config.UserAgent)
	
	resp, err := client.Do(req)
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

	var links []string
	content := string(body)
	
	// Extract links from href attributes
	linkRegex := regexp.MustCompile(`href=["']([^"']+)["']`)
	matches := linkRegex.FindAllStringSubmatch(content, -1)
	
	for _, match := range matches {
		if len(match) > 1 {
			link := match[1]
			
			// Convert relative to absolute URLs
			if strings.HasPrefix(link, "/") {
				if u, err := url.Parse(targetURL); err == nil {
					link = fmt.Sprintf("%s://%s%s", u.Scheme, u.Host, link)
				}
			} else if !strings.HasPrefix(link, "http") && !strings.Contains(link, "javascript:") && !strings.Contains(link, "mailto:") {
				if u, err := url.Parse(targetURL); err == nil {
					link = fmt.Sprintf("%s://%s/%s", u.Scheme, u.Host, strings.TrimPrefix(link, "/"))
				}
			}
			
			// Only include links from the same domain
			if strings.Contains(link, domain) && (strings.HasPrefix(link, "http://") || strings.HasPrefix(link, "https://")) {
				links = append(links, link)
			}
		}
	}
	
	// Limit to first 10 links to avoid too many requests
	if len(links) > 10 {
		links = links[:10]
	}
	
	return links
}

func (b *BLCPlugin) runBrokenLinkCheck(ctx context.Context, links []string) ([]BLCResult, BLCStats, error) {
	white := color.New(color.FgWhite, color.Bold).SprintFunc()
	cyan := color.New(color.FgCyan).SprintFunc()
	red := color.New(color.FgRed).SprintFunc()

	fmt.Printf("%s\n", white("[GORECON::BLC] Broken Link Analysis"))
	fmt.Printf("%s\n", strings.Repeat("=", 35))

	// Check if blc tool is available
	if _, err := exec.LookPath("blc"); err != nil {
		fmt.Printf("[%s] blc tool not found\n", red("!"))
		fmt.Printf("[%s] Install: npm install -g broken-link-checker\n", cyan("*"))
		return nil, BLCStats{}, fmt.Errorf("blc tool not installed")
	}

	startTime := time.Now()
	var allResults []BLCResult

	fmt.Printf("[%s] Starting broken link check using blc tool...\n", cyan("*"))

	// Create working directory
	workDir := "./work/blc"
	if err := os.MkdirAll(workDir, 0755); err != nil {
		return nil, BLCStats{}, fmt.Errorf("failed to create work directory: %w", err)
	}

	// Run blc for each domain/URL
	domains := make(map[string]bool)
	for _, link := range links {
		if u, err := url.Parse(link); err == nil {
			domains[u.Host] = true
		}
	}

	for domain := range domains {
		results, err := b.runBLCCommand(ctx, domain, workDir)
		if err != nil {
			fmt.Printf("[%s] blc failed for %s: %v\n", red("!"), domain, err)
			continue
		}
		allResults = append(allResults, results...)
	}

	// Generate statistics
	stats := BLCStats{
		TotalLinks:    len(links),
		CheckedLinks:  len(allResults),
		ByStatusCode:  make(map[int]int),
		CheckDuration: time.Since(startTime),
	}

	for _, result := range allResults {
		if result.IsBroken {
			stats.BrokenLinks++
		}
		stats.ByStatusCode[result.StatusCode]++
	}

	fmt.Printf("[%s] Broken link check completed: %d broken out of %d links\n", cyan("+"), stats.BrokenLinks, stats.CheckedLinks)

	return allResults, stats, nil
}

func (b *BLCPlugin) runBLCCommand(ctx context.Context, domain, workDir string) ([]BLCResult, error) {
	green := color.New(color.FgGreen).SprintFunc()
	red := color.New(color.FgRed).SprintFunc()
	yellow := color.New(color.FgYellow).SprintFunc()
	cyan := color.New(color.FgCyan).SprintFunc()
	
	// Create output file
	outputFile := filepath.Join(workDir, fmt.Sprintf("blc_%s.txt", strings.ReplaceAll(domain, ".", "_")))
	
	// Build blc command with specified parameters
	args := []string{
		"-rfoi",
		"--filter-level", "3",
		"--user-agent", "Mozilla/5.0 (Macintosh; Intel Mac OS X 10.15; rv:125.0) Gecko/20100101 Firefox/125.0",
		fmt.Sprintf("https://%s", domain),
	}
	
	cmd := exec.CommandContext(ctx, "blc", args...)
	
	// Create pipes for real-time output streaming
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
		return nil, fmt.Errorf("failed to start blc command: %w", err)
	}
	
	var allResults []BLCResult
	var outputLines []string
	var mu sync.Mutex
	var wg sync.WaitGroup
	
	wg.Add(2) // for stdout and stderr goroutines
	
	// Read stdout in real-time
	go func() {
		defer wg.Done()
		scanner := bufio.NewScanner(stdout)
		for scanner.Scan() {
			line := scanner.Text()
			
			mu.Lock()
			outputLines = append(outputLines, line)
			mu.Unlock()
			
			// Parse and display line in real-time with styling
			b.displayBLCLine(line, green, red, yellow, cyan)
		}
	}()
	
	// Read stderr in real-time
	go func() {
		defer wg.Done()
		scanner := bufio.NewScanner(stderr)
		for scanner.Scan() {
			line := scanner.Text()
			
			mu.Lock()
			outputLines = append(outputLines, line)
			mu.Unlock()
		}
	}()
	
	// Wait for goroutines to finish reading
	wg.Wait()
	
	// Wait for command to complete
	err = cmd.Wait()
	if err != nil {
		// blc returns non-zero exit code when broken links are found, so don't treat as error
		if _, ok := err.(*exec.ExitError); !ok {
			return nil, fmt.Errorf("blc command failed: %w", err)
		}
	}
	
	// Save complete output to file
	mu.Lock()
	completeOutput := strings.Join(outputLines, "\n")
	mu.Unlock()
	if err := os.WriteFile(outputFile, []byte(completeOutput), 0644); err != nil {
		return nil, fmt.Errorf("failed to save blc output: %w", err)
	}
	
	// Parse all collected output
	allResults, _ = b.parseBLCOutput(completeOutput, domain)
	
	return allResults, nil
}

func (b *BLCPlugin) displayBLCLine(line string, green, red, yellow, cyan func(...interface{}) string) {
	line = strings.TrimSpace(line)
	if line == "" {
		return
	}
	
	// Skip progress/info lines
	if strings.HasPrefix(line, "Getting links from:") {
		fmt.Printf("[%s] %s\n", cyan("*"), line)
		return
	}
	
	if strings.HasPrefix(line, "Finished!") {
		fmt.Printf("[%s] %s\n", cyan("*"), line)
		return
	}
	
	// Parse BLC tree output format - look for ├─ or └─ patterns
	if strings.Contains(line, "├─") || strings.Contains(line, "└─") {
		// Extract URL from the line
		urlRegex := regexp.MustCompile(`https?://[^\s]+`)
		urlMatch := urlRegex.FindString(line)
		
		if strings.Contains(line, "─BROKEN─") {
			// Extract the complete error information in parentheses
			errorRegex := regexp.MustCompile(`\(([^)]+)\)`)
			errorMatch := errorRegex.FindStringSubmatch(line)
			
			if len(errorMatch) > 1 && urlMatch != "" {
				// Make broken links highly visible with bold red text and background
				boldRed := color.New(color.FgRed, color.Bold).SprintFunc()
				redBg := color.New(color.BgRed, color.FgWhite, color.Bold).SprintFunc()
				
				fmt.Printf("\n%s %s %s\n", 
					redBg(" BROKEN "), 
					boldRed(urlMatch), 
					boldRed("→ "+errorMatch[1]))
			} else if urlMatch != "" {
				boldRed := color.New(color.FgRed, color.Bold).SprintFunc()
				redBg := color.New(color.BgRed, color.FgWhite, color.Bold).SprintFunc()
				
				fmt.Printf("\n%s %s\n", 
					redBg(" BROKEN "), 
					boldRed(urlMatch))
			}
		} else if strings.Contains(line, "─OK─") && urlMatch != "" {
			fmt.Printf("[%s] %s\n", green("+"), urlMatch)
		}
	}
}

func (b *BLCPlugin) parseBLCOutput(output, domain string) ([]BLCResult, error) {
	var results []BLCResult
	lines := strings.Split(output, "\n")
	
	for _, line := range lines {
		line = strings.TrimSpace(line)
		if line == "" {
			continue
		}
		
		// Parse different types of blc output
		if strings.Contains(line, "BROKEN") || strings.Contains(line, "HTTP_") {
			result := b.parseBLCLine(line, domain)
			if result.URL != "" {
				results = append(results, result)
			}
		}
	}
	
	return results, nil
}

func (b *BLCPlugin) parseBLCLine(line, domain string) BLCResult {
	result := BLCResult{
		Timestamp: time.Now(),
		Metadata:  make(map[string]string),
		Tool:      "blc",
	}
	
	// Extract URL from blc output (format varies)
	urlRegex := regexp.MustCompile(`https?://[^\s]+`)
	if match := urlRegex.FindString(line); match != "" {
		result.URL = match
	}
	
	// Check if it's broken based on keywords
	if strings.Contains(line, "BROKEN") || strings.Contains(line, "HTTP_4") || strings.Contains(line, "HTTP_5") {
		result.IsBroken = true
		
		// Extract status code
		statusRegex := regexp.MustCompile(`HTTP_(\d+)`)
		if match := statusRegex.FindStringSubmatch(line); len(match) > 1 {
			if code, err := strconv.Atoi(match[1]); err == nil {
				result.StatusCode = code
			}
		}
	}
	
	return result
}

func (b *BLCPlugin) checkLink(client *http.Client, targetURL string) BLCResult {
	startTime := time.Now()
	result := BLCResult{
		URL:       targetURL,
		Timestamp: time.Now(),
		Metadata:  make(map[string]string),
	}

	req, err := http.NewRequest("HEAD", targetURL, nil)
	if err != nil {
		result.Error = fmt.Sprintf("Invalid URL: %v", err)
		result.IsBroken = true
		result.ResponseTime = time.Since(startTime)
		return result
	}

	req.Header.Set("User-Agent", b.config.UserAgent)
	req.Header.Set("Accept", "*/*")
	req.Header.Set("Accept-Language", "en-US,en;q=0.9")

	resp, err := client.Do(req)
	if err != nil {
		// Don't treat connection timeouts as broken links for major sites
		if strings.Contains(err.Error(), "timeout") || strings.Contains(err.Error(), "deadline exceeded") {
			result.Error = "Connection timeout"
			result.IsBroken = false // Not necessarily broken, might be rate limited
		} else {
			result.Error = fmt.Sprintf("Request failed: %v", err)
			result.IsBroken = true
		}
		result.ResponseTime = time.Since(startTime)
		return result
	}
	defer resp.Body.Close()

	result.StatusCode = resp.StatusCode
	result.ContentType = resp.Header.Get("Content-Type")
	result.ResponseTime = time.Since(startTime)

	// Check if link is broken based on status code
	result.IsBroken = result.StatusCode >= 400 && result.StatusCode != 403

	// For 200 responses, try GET to get title if it's HTML
	if result.StatusCode == 200 && strings.Contains(result.ContentType, "text/html") {
		if title := b.getTitleFromURL(client, targetURL); title != "" {
			result.Title = title
		}
	}

	return result
}

func (b *BLCPlugin) getTitleFromURL(client *http.Client, targetURL string) string {
	req, err := http.NewRequest("GET", targetURL, nil)
	if err != nil {
		return ""
	}

	req.Header.Set("User-Agent", b.config.UserAgent)
	
	resp, err := client.Do(req)
	if err != nil {
		return ""
	}
	defer resp.Body.Close()

	if resp.StatusCode != 200 {
		return ""
	}

	// Read first 8KB to find title
	body := make([]byte, 8192)
	n, _ := io.ReadAtLeast(resp.Body, body, len(body))
	if n > 0 {
		content := string(body[:n])
		if start := strings.Index(strings.ToLower(content), "<title>"); start != -1 {
			start += 7
			if end := strings.Index(strings.ToLower(content[start:]), "</title>"); end != -1 {
				return strings.TrimSpace(content[start : start+end])
			}
		}
	}

	return ""
}

func (b *BLCPlugin) displayResults(results []BLCResult, stats BLCStats) {
	// Results are now displayed in real-time, so just show summary
	green := color.New(color.FgGreen).SprintFunc()
	
	if stats.BrokenLinks == 0 {
		fmt.Printf("[%s] No broken links found\n", green("+"))
	}
}

func (b *BLCPlugin) generatePluginResults(target *models.Target, results []BLCResult, resultsChan chan<- models.PluginResult) {
	brokenCount := 0
	for _, result := range results {
		if !result.IsBroken {
			continue // Only report broken links
		}

		brokenCount++
		severity := models.SeverityLow
		if result.StatusCode == 500 || result.StatusCode >= 502 {
			severity = models.SeverityMedium
		}

		description := fmt.Sprintf("Broken link found: HTTP %d", result.StatusCode)
		if result.Error != "" {
			description = fmt.Sprintf("Broken link found: %s", result.Error)
		}

		pluginResult := models.PluginResult{
			Plugin:      "blc",
			Target:      target.URL,
			Severity:    severity,
			Title:       fmt.Sprintf("Broken Link: %s", result.URL),
			Description: description,
			Data: map[string]interface{}{
				"url":           result.URL,
				"status_code":   result.StatusCode,
				"error":         result.Error,
				"response_time": result.ResponseTime.Milliseconds(),
				"content_type":  result.ContentType,
				"title":         result.Title,
			},
			Timestamp: time.Now(),
		}
		resultsChan <- pluginResult
	}
	
	// fmt.Printf("[DEBUG] Generated %d plugin results for broken links\n", brokenCount)
}

func (b *BLCPlugin) addDiscoveries(shared *core.SharedContext, domain string, results []BLCResult) {
	for _, result := range results {
		discoveryType := "working_link"
		if result.IsBroken {
			discoveryType = "broken_link"
		}

		shared.AddDiscovery(models.Discovery{
			Type:       discoveryType,
			Value:      result.URL,
			Source:     "blc",
			Confidence: 1.0,
			Timestamp:  time.Now(),
			Metadata: map[string]interface{}{
				"status_code":   result.StatusCode,
				"response_time": result.ResponseTime.Milliseconds(),
				"error":         result.Error,
				"domain":        domain,
			},
		})
	}
}
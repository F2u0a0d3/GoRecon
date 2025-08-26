package httpprobe

import (
	"bufio"
	"context"
	"encoding/json"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	"github.com/fatih/color"
	"github.com/f2u0a0d3/GoRecon/pkg/core"
	"github.com/f2u0a0d3/GoRecon/pkg/models"
	"github.com/f2u0a0d3/GoRecon/pkg/plugins/base"
)

// HakCheckURLPlugin implements HTTP status code checking using hakcheckurl
type HakCheckURLPlugin struct {
	*base.BaseAdapter
	config *HakCheckURLConfig
}

// HakCheckURLConfig contains hakcheckurl configuration
type HakCheckURLConfig struct {
	Threads       int           `json:"threads"`
	Timeout       time.Duration `json:"timeout"`
	FollowRedirect bool         `json:"follow_redirect"`
	StatusCodes   []int         `json:"status_codes"`
}

// HakCheckURLResult represents a status check result
type HakCheckURLResult struct {
	URL        string `json:"url"`
	StatusCode int    `json:"status_code"`
	Length     int    `json:"content_length"`
	Title      string `json:"title"`
	Server     string `json:"server"`
	Tech       string `json:"tech"`
	Timestamp  time.Time `json:"timestamp"`
}

// NewHakCheckURLPlugin creates a new hakcheckurl plugin
func NewHakCheckURLPlugin() *HakCheckURLPlugin {
	config := &HakCheckURLConfig{
		Threads:       50,
		Timeout:       10 * time.Second,
		FollowRedirect: true,
		StatusCodes:   []int{200, 301, 302, 401, 403, 404, 500},
	}

	baseAdapter := base.NewBaseAdapter(base.BaseAdapterConfig{
		Name:        "hakcheckurl",
		Category:    "httpprobe",
		Description: "HTTP status code checking using hakcheckurl",
		Version:     "1.0.0",
		Author:      "GoRecon Team",
		ToolName:    "hakcheckurl",
		Passive:     false,
		Duration:    20 * time.Minute,
		Concurrency: 1,
		Priority:    5,
		Resources: core.Resources{
			CPUCores:      2,
			MemoryMB:      512,
			NetworkAccess: true,
		},
		Provides: []string{"http_status", "bypass_candidates"},
		Consumes: []string{"http_services", "urls"},
	})

	return &HakCheckURLPlugin{
		BaseAdapter: baseAdapter,
		config:      config,
	}
}

// Run executes hakcheckurl status checking
func (h *HakCheckURLPlugin) Run(ctx context.Context, target *models.Target, results chan<- models.PluginResult, shared *core.SharedContext) error {
	logger := shared.GetLogger().WithField("plugin", "hakcheckurl")
	
	cyan := color.New(color.FgCyan).SprintFunc()
	white := color.New(color.FgWhite, color.Bold).SprintFunc()
	red := color.New(color.FgRed).SprintFunc()

	domain := target.Domain
	if domain == "" {
		domain = h.ExtractDomain(target.URL)
	}

	fmt.Printf("\n%s\n", white("[GORECON] HTTP Status Checker v1.0"))
	fmt.Printf("%s\n", strings.Repeat("=", 34))

	// Check if hakcheckurl is installed
	if _, err := exec.LookPath("hakcheckurl"); err != nil {
		fmt.Printf("[%s] hakcheckurl not found\n", red("!"))
		fmt.Printf("[%s] Install: go install github.com/hakluke/hakcheckurl@latest\n", cyan("*"))
		return fmt.Errorf("hakcheckurl not installed")
	}

	// Collect URLs from previous stages
	urls := h.collectURLs(shared, domain, target)
	fmt.Printf("[%s] Checking status codes for %d URLs...\n\n", cyan("*"), len(urls))

	workDir := filepath.Join("./work", domain, "httpprobe")
	if err := os.MkdirAll(workDir, 0755); err != nil {
		return fmt.Errorf("failed to create workspace: %w", err)
	}
	
	rawDir := filepath.Join(workDir, "raw")
	if err := os.MkdirAll(rawDir, 0755); err != nil {
		return fmt.Errorf("failed to create directory: %w", err)
	}

	// Run hakcheckurl
	results_list, err := h.runHakCheckURL(ctx, urls, rawDir)
	if err != nil {
		logger.Error("hakcheckurl failed", err)
		return err
	}

	// Process results for bypass candidates
	bypassCandidates := h.identifyBypassCandidates(results_list)

	h.displayResults(results_list, bypassCandidates)
	h.generatePluginResults(target, results_list, bypassCandidates, results)
	h.addDiscoveries(shared, domain, results_list, bypassCandidates)

	logger.Info("hakcheckurl completed",
		"target", domain,
		"total_urls", len(urls),
		"checked_urls", len(results_list),
		"bypass_candidates", len(bypassCandidates))

	return nil
}

func (h *HakCheckURLPlugin) collectURLs(shared *core.SharedContext, domain string, target *models.Target) []string {
	urlSet := make(map[string]bool)

	// Add target URL
	if target.URL != "" {
		urlSet[target.URL] = true
	}

	// Collect URLs from discoveries
	discoveries := shared.GetDiscoveries("")
	for _, discovery := range discoveries {
		value, ok := discovery.Value.(string)
		if !ok {
			continue
		}

		switch discovery.Type {
		case "http_service", "historical_url", "endpoint":
			if strings.Contains(value, domain) && (strings.HasPrefix(value, "http://") || strings.HasPrefix(value, "https://")) {
				urlSet[value] = true
			}
		}
	}

	var urlList []string
	for url := range urlSet {
		urlList = append(urlList, url)
	}

	return urlList
}

func (h *HakCheckURLPlugin) runHakCheckURL(ctx context.Context, urls []string, rawDir string) ([]HakCheckURLResult, error) {
	if len(urls) == 0 {
		return []HakCheckURLResult{}, nil
	}

	// Create input file
	inputFile := filepath.Join(rawDir, "urls.txt")
	if err := h.saveURLsToFile(urls, inputFile); err != nil {
		return nil, fmt.Errorf("failed to save URLs: %w", err)
	}

	// Run hakcheckurl
	outputFile := filepath.Join(rawDir, "hakcheckurl_output.json")
	args := []string{
		"-i", inputFile,
		"-o", outputFile,
		"-t", strconv.Itoa(h.config.Threads),
		"-timeout", strconv.Itoa(int(h.config.Timeout.Seconds())),
		"-json",
	}

	cmd := exec.CommandContext(ctx, "hakcheckurl", args...)
	if err := cmd.Run(); err != nil {
		return nil, fmt.Errorf("hakcheckurl failed: %w", err)
	}

	// Parse results
	return h.parseHakCheckURLOutput(outputFile)
}

func (h *HakCheckURLPlugin) parseHakCheckURLOutput(filename string) ([]HakCheckURLResult, error) {
	file, err := os.Open(filename)
	if err != nil {
		return nil, err
	}
	defer file.Close()

	var results []HakCheckURLResult
	scanner := bufio.NewScanner(file)

	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line == "" {
			continue
		}

		var raw map[string]interface{}
		if err := json.Unmarshal([]byte(line), &raw); err != nil {
			continue
		}

		result := HakCheckURLResult{
			Timestamp: time.Now(),
		}

		if url, ok := raw["url"].(string); ok {
			result.URL = url
		}

		if statusCode, ok := raw["status_code"].(float64); ok {
			result.StatusCode = int(statusCode)
		}

		if length, ok := raw["content_length"].(float64); ok {
			result.Length = int(length)
		}

		if title, ok := raw["title"].(string); ok {
			result.Title = title
		}

		if server, ok := raw["server"].(string); ok {
			result.Server = server
		}

		if tech, ok := raw["tech"].(string); ok {
			result.Tech = tech
		}

		results = append(results, result)
	}

	return results, scanner.Err()
}

func (h *HakCheckURLPlugin) identifyBypassCandidates(results []HakCheckURLResult) []HakCheckURLResult {
	var candidates []HakCheckURLResult

	for _, result := range results {
		// Identify 403/401 responses as bypass candidates
		if result.StatusCode == 403 || result.StatusCode == 401 {
			candidates = append(candidates, result)
		}
	}

	return candidates
}

func (h *HakCheckURLPlugin) saveURLsToFile(urls []string, filename string) error {
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

func (h *HakCheckURLPlugin) displayResults(results []HakCheckURLResult, bypassCandidates []HakCheckURLResult) {
	green := color.New(color.FgGreen).SprintFunc()
	red := color.New(color.FgRed).SprintFunc()
	yellow := color.New(color.FgYellow).SprintFunc()
	cyan := color.New(color.FgCyan).SprintFunc()

	fmt.Printf("[%s] Status code summary:\n", cyan("*"))
	
	// Group by status code
	statusCount := make(map[int]int)
	for _, result := range results {
		statusCount[result.StatusCode]++
	}

	for status, count := range statusCount {
		var colorFunc func(...interface{}) string
		switch {
		case status >= 200 && status < 300:
			colorFunc = green
		case status >= 300 && status < 400:
			colorFunc = yellow
		case status >= 400:
			colorFunc = red
		default:
			colorFunc = cyan
		}
		
		fmt.Printf("    [%s] %d: %d URLs\n", colorFunc("*"), status, count)
	}

	if len(bypassCandidates) > 0 {
		fmt.Printf("\n[%s] Found %d bypass candidates (401/403):\n", yellow("!"), len(bypassCandidates))
		for i, candidate := range bypassCandidates {
			if i >= 10 { // Show only first 10
				fmt.Printf("    ... and %d more\n", len(bypassCandidates)-10)
				break
			}
			fmt.Printf("    [%d] %s -> %s\n", candidate.StatusCode, candidate.URL, candidate.Title)
		}
	}
}

func (h *HakCheckURLPlugin) generatePluginResults(target *models.Target, results []HakCheckURLResult, bypassCandidates []HakCheckURLResult, resultsChan chan<- models.PluginResult) {
	// Generate findings for bypass candidates
	for _, candidate := range bypassCandidates {
		severity := models.SeverityMedium
		if candidate.StatusCode == 403 {
			severity = models.SeverityHigh // 403 may be bypassable
		}

		pluginResult := models.PluginResult{
			Plugin:      "hakcheckurl",
			Target:      candidate.URL,
			Severity:    severity,
			Title:       fmt.Sprintf("Access Control Detected: %d", candidate.StatusCode),
			Description: fmt.Sprintf("URL returned %d status code - potential bypass candidate", candidate.StatusCode),
			Data: map[string]interface{}{
				"url":         candidate.URL,
				"status_code": candidate.StatusCode,
				"title":       candidate.Title,
				"server":      candidate.Server,
				"length":      candidate.Length,
			},
			Timestamp: time.Now(),
		}
		resultsChan <- pluginResult
	}

	// Generate summary result
	if len(results) > 0 {
		pluginResult := models.PluginResult{
			Plugin:      "hakcheckurl",
			Target:      target.URL,
			Severity:    models.SeverityInfo,
			Title:       fmt.Sprintf("HTTP Status Check Complete: %d URLs", len(results)),
			Description: fmt.Sprintf("Checked status codes for %d URLs, found %d bypass candidates", len(results), len(bypassCandidates)),
			Data: map[string]interface{}{
				"total_urls":        len(results),
				"bypass_candidates": len(bypassCandidates),
				"results":           results,
			},
			Timestamp: time.Now(),
		}
		resultsChan <- pluginResult
	}
}

func (h *HakCheckURLPlugin) addDiscoveries(shared *core.SharedContext, domain string, results []HakCheckURLResult, bypassCandidates []HakCheckURLResult) {
	// Add bypass candidates as discoveries for the bypass stage
	for _, candidate := range bypassCandidates {
		shared.AddDiscovery(models.Discovery{
			Type:       "bypass_candidate",
			Value:      candidate.URL,
			Source:     "hakcheckurl",
			Confidence: 0.9,
			Timestamp:  time.Now(),
			Metadata: map[string]interface{}{
				"status_code": candidate.StatusCode,
				"title":       candidate.Title,
				"server":      candidate.Server,
				"domain":      domain,
			},
		})
	}

	// Add all HTTP status results
	for _, result := range results {
		shared.AddDiscovery(models.Discovery{
			Type:       "http_status",
			Value:      result.URL,
			Source:     "hakcheckurl",
			Confidence: 0.95,
			Timestamp:  time.Now(),
			Metadata: map[string]interface{}{
				"status_code": result.StatusCode,
				"title":       result.Title,
				"server":      result.Server,
				"tech":        result.Tech,
				"length":      result.Length,
				"domain":      domain,
			},
		})
	}
}
package wayback

import (
	"context"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/fatih/color"
	"github.com/f2u0a0d3/GoRecon/pkg/core"
	"github.com/f2u0a0d3/GoRecon/pkg/models"
	"github.com/f2u0a0d3/GoRecon/pkg/plugins/base"
)

// WaybackPlugin implements historical URL discovery
type WaybackPlugin struct {
	*base.BaseAdapter
	config *WaybackConfig
}

// WaybackConfig contains configuration for wayback discovery
type WaybackConfig struct {
	EnableWaybackurls bool          `json:"enable_waybackurls"`
	EnableGAU         bool          `json:"enable_gau"`
	EnableWaymore     bool          `json:"enable_waymore"`
	GAUThreads        int           `json:"gau_threads"`
	GAUTimeout        int           `json:"gau_timeout"`
	GAUBlacklist      []string      `json:"gau_blacklist"`
	WaymoreAPIKey     string        `json:"waymore_api_key"`
	MaxURLs           int           `json:"max_urls"`
	OutputDir         string        `json:"output_dir"`
	Timeout           time.Duration `json:"timeout"`
}

// URLAnalysis represents analyzed URL data
type URLAnalysis struct {
	URL          string            `json:"url"`
	Source       string            `json:"source"`
	FirstSeen    string            `json:"first_seen"`
	LastSeen     string            `json:"last_seen"`
	Parameters   []string          `json:"parameters"`
	Extension    string            `json:"extension"`
	Category     string            `json:"category"`
	Interesting  bool              `json:"interesting"`
	StatusCode   int               `json:"status_code,omitempty"`
	ContentType  string            `json:"content_type,omitempty"`
	Metadata     map[string]interface{} `json:"metadata"`
}

// URLStats contains statistics about discovered URLs
type URLStats struct {
	TotalURLs       int                    `json:"total_urls"`
	UniqueURLs      int                    `json:"unique_urls"`
	BySource        map[string]int         `json:"by_source"`
	ByExtension     map[string]int         `json:"by_extension"`
	ByCategory      map[string]int         `json:"by_category"`
	Parameters      map[string]int         `json:"parameters"`
	InterestingURLs int                    `json:"interesting_urls"`
	TimeRange       map[string]string      `json:"time_range"`
}

// ToolResult represents results from individual tools
type ToolResult struct {
	Tool     string    `json:"tool"`
	URLs     []string  `json:"urls"`
	Count    int       `json:"count"`
	Duration time.Duration `json:"duration"`
	Error    string    `json:"error,omitempty"`
}

// NewWaybackPlugin creates a new wayback discovery plugin
func NewWaybackPlugin() *WaybackPlugin {
	config := &WaybackConfig{
		EnableWaybackurls: true,
		EnableGAU:         true,
		EnableWaymore:     false, // Optional, requires Python
		GAUThreads:        10,
		GAUTimeout:        45,
		GAUBlacklist:      []string{"ttf", "woff", "svg", "png", "jpg", "jpeg", "gif", "css", "js", "ico"},
		MaxURLs:           10000,
		Timeout:           15 * time.Minute,
	}

	baseAdapter := base.NewBaseAdapter(base.BaseAdapterConfig{
		Name:        "wayback",
		Category:    "discovery",
		Description: "Historical URL discovery using multiple archive sources",
		Version:     "1.0.0",
		Author:      "GoRecon Team",
		ToolName:    "waybackurls",
		Passive:     true,
		Duration:    config.Timeout,
		Concurrency: 3,
		Priority:    5,
		Resources: core.Resources{
			CPUCores:      2,
			MemoryMB:      1024,
			NetworkAccess: true,
		},
		Provides: []string{"historical_urls", "url_parameters", "interesting_paths"},
		Consumes: []string{"domain", "subdomain"},
	})

	return &WaybackPlugin{
		BaseAdapter: baseAdapter,
		config:      config,
	}
}

// Run executes the wayback URL discovery
func (w *WaybackPlugin) Run(ctx context.Context, target *models.Target, results chan<- models.PluginResult, shared *core.SharedContext) error {
	logger := shared.GetLogger().WithField("plugin", "wayback")
	
	// Create color functions
	cyan := color.New(color.FgCyan).SprintFunc()
	green := color.New(color.FgGreen).SprintFunc()
	white := color.New(color.FgWhite, color.Bold).SprintFunc()

	// Display header
	fmt.Printf("\n%s\n", white("[GORECON] Historical URL Discovery v1.0"))
	fmt.Printf("%s\n\n", strings.Repeat("=", 40))

	fmt.Printf("[%s] Initializing wayback enumeration...\n", cyan("*"))
	
	// Extract domain from target
	domain := target.Domain
	if domain == "" {
		domain = w.ExtractDomain(target.URL)
	}
	
	fmt.Printf("[%s] Target: %s\n", green("+"), domain)
	fmt.Printf("[%s] Running multiple archive sources...\n\n", cyan("*"))

	// Create workspace
	workDir := filepath.Join("./work", domain, "wayback")
	if err := os.MkdirAll(workDir, 0755); err != nil {
		return fmt.Errorf("failed to create workspace: %w", err)
	}
	
	// Create subdirectories
	rawDir := filepath.Join(workDir, "raw")
	processedDir := filepath.Join(workDir, "processed")
	byExtDir := filepath.Join(processedDir, "by_extension")
	byCatDir := filepath.Join(processedDir, "by_category")
	
	for _, dir := range []string{rawDir, processedDir, byExtDir, byCatDir} {
		if err := os.MkdirAll(dir, 0755); err != nil {
			return fmt.Errorf("failed to create directory %s: %w", dir, err)
		}
	}

	startTime := time.Now()
	var toolResults []ToolResult
	var wg sync.WaitGroup
	var mu sync.Mutex

	// Run tools in parallel
	tools := []struct {
		name    string
		enabled bool
		fn      func() ToolResult
	}{
		{"waybackurls", w.config.EnableWaybackurls, func() ToolResult { return w.runWaybackurls(ctx, domain, rawDir) }},
		{"gau", w.config.EnableGAU, func() ToolResult { return w.runGAU(ctx, domain, rawDir) }},
		{"waymore", w.config.EnableWaymore, func() ToolResult { return w.runWaymore(ctx, domain, rawDir) }},
	}

	for _, tool := range tools {
		if !tool.enabled {
			continue
		}
		
		wg.Add(1)
		go func(t struct {
			name    string
			enabled bool
			fn      func() ToolResult
		}) {
			defer wg.Done()
			result := t.fn()
			mu.Lock()
			toolResults = append(toolResults, result)
			mu.Unlock()
		}(tool)
	}

	wg.Wait()

	// Process and analyze results
	allURLs, stats, err := w.processResults(toolResults, processedDir, byExtDir, byCatDir)
	if err != nil {
		logger.Error("Failed to process results", err)
		return err
	}

	// Display results
	w.displayResults(stats, time.Since(startTime))

	// Generate plugin results
	w.generatePluginResults(target, allURLs, stats, results)

	// Add discoveries
	w.addDiscoveries(shared, allURLs, stats)

	logger.Info("Wayback discovery completed",
		"total_urls", stats.TotalURLs,
		"unique_urls", stats.UniqueURLs,
		"duration", time.Since(startTime))

	return nil
}

// runWaybackurls executes waybackurls tool
func (w *WaybackPlugin) runWaybackurls(ctx context.Context, domain string, rawDir string) ToolResult {
	cyan := color.New(color.FgCyan).SprintFunc()
	green := color.New(color.FgGreen).SprintFunc()
	red := color.New(color.FgRed).SprintFunc()
	white := color.New(color.FgWhite, color.Bold).SprintFunc()

	fmt.Printf("%s\n", white("[GORECON::WAYBACK] waybackurls"))
	fmt.Printf("%s\n", strings.Repeat("=", 31))

	startTime := time.Now()
	outputFile := filepath.Join(rawDir, "waybackurls.txt")

	// Check if waybackurls is installed
	if _, err := exec.LookPath("waybackurls"); err != nil {
		fmt.Printf("[%s] waybackurls not found\n", red("-"))
		fmt.Printf("[%s] Install: go install github.com/tomnomnom/waybackurls@latest\n", cyan("*"))
		return ToolResult{
			Tool:  "waybackurls",
			Error: "tool not installed",
		}
	}

	fmt.Printf("[%s] Querying Wayback Machine archives...\n", cyan("*"))

	// Execute waybackurls
	cmd := exec.CommandContext(ctx, "bash", "-c", fmt.Sprintf("echo '%s' | waybackurls", domain))
	output, err := cmd.Output()
	if err != nil {
		fmt.Printf("[%s] waybackurls failed: %v\n", red("-"), err)
		return ToolResult{
			Tool:     "waybackurls",
			Error:    err.Error(),
			Duration: time.Since(startTime),
		}
	}

	// Parse URLs
	urls := strings.Split(strings.TrimSpace(string(output)), "\n")
	var validURLs []string
	for _, u := range urls {
		if u = strings.TrimSpace(u); u != "" && w.isValidURL(u) {
			validURLs = append(validURLs, u)
		}
	}

	// Save to file
	if err := w.saveURLsToFile(validURLs, outputFile); err != nil {
		fmt.Printf("[%s] Failed to save waybackurls results: %v\n", red("-"), err)
	}

	duration := time.Since(startTime)
	fmt.Printf("[%s] Found %d unique URLs\n", green("*"), len(validURLs))
	if len(validURLs) > 0 {
		fmt.Printf("[%s] Time range: %s\n", green("*"), w.getTimeRange(validURLs))
	}
	fmt.Println()

	return ToolResult{
		Tool:     "waybackurls",
		URLs:     validURLs,
		Count:    len(validURLs),
		Duration: duration,
	}
}

// runGAU executes gau (Get All URLs) tool
func (w *WaybackPlugin) runGAU(ctx context.Context, domain string, rawDir string) ToolResult {
	cyan := color.New(color.FgCyan).SprintFunc()
	green := color.New(color.FgGreen).SprintFunc()
	red := color.New(color.FgRed).SprintFunc()
	white := color.New(color.FgWhite, color.Bold).SprintFunc()

	fmt.Printf("%s\n", white("[GORECON::WAYBACK] gau (Get All URLs)"))
	fmt.Printf("%s\n", strings.Repeat("=", 38))

	startTime := time.Now()
	outputFile := filepath.Join(rawDir, "gau.txt")

	// Check if gau is installed
	if _, err := exec.LookPath("gau"); err != nil {
		fmt.Printf("[%s] gau not found\n", red("-"))
		fmt.Printf("[%s] Install: go install github.com/lc/gau/v2/cmd/gau@latest\n", cyan("*"))
		return ToolResult{
			Tool:  "gau",
			Error: "tool not installed",
		}
	}

	fmt.Printf("[%s] Sources: Wayback, Common Crawl, URLScan, AlienVault\n", cyan("*"))
	fmt.Printf("[%s] Fetching from 4 sources...\n", cyan("*"))

	// Build gau command
	blacklist := strings.Join(w.config.GAUBlacklist, ",")
	cmd := exec.CommandContext(ctx, "gau",
		"--threads", strconv.Itoa(w.config.GAUThreads),
		"--timeout", strconv.Itoa(w.config.GAUTimeout),
		"--blacklist", blacklist,
		domain)

	output, err := cmd.Output()
	if err != nil {
		fmt.Printf("[%s] gau failed: %v\n", red("-"), err)
		return ToolResult{
			Tool:     "gau",
			Error:    err.Error(),
			Duration: time.Since(startTime),
		}
	}

	// Parse URLs
	urls := strings.Split(strings.TrimSpace(string(output)), "\n")
	var validURLs []string
	sourceCounts := make(map[string]int)

	for _, u := range urls {
		if u = strings.TrimSpace(u); u != "" && w.isValidURL(u) {
			validURLs = append(validURLs, u)
			// Estimate source based on URL patterns (simplified)
			if strings.Contains(u, "web.archive.org") {
				sourceCounts["Wayback Machine"]++
			} else if strings.Contains(u, "commoncrawl") {
				sourceCounts["Common Crawl"]++
			} else {
				sourceCounts["Other Sources"]++
			}
		}
	}

	// Save to file
	if err := w.saveURLsToFile(validURLs, outputFile); err != nil {
		fmt.Printf("[%s] Failed to save gau results: %v\n", red("-"), err)
	}

	duration := time.Since(startTime)

	// Display source breakdown
	for source, count := range sourceCounts {
		fmt.Printf("    ├─ %s: %d URLs\n", source, count)
	}
	fmt.Printf("[%s] Total: %d URLs discovered\n", green("+"), len(validURLs))
	fmt.Println()

	return ToolResult{
		Tool:     "gau",
		URLs:     validURLs,
		Count:    len(validURLs),
		Duration: duration,
	}
}

// runWaymore executes waymore tool (Python-based)
func (w *WaybackPlugin) runWaymore(ctx context.Context, domain string, rawDir string) ToolResult {
	cyan := color.New(color.FgCyan).SprintFunc()
	green := color.New(color.FgGreen).SprintFunc()
	red := color.New(color.FgRed).SprintFunc()
	white := color.New(color.FgWhite, color.Bold).SprintFunc()

	fmt.Printf("%s\n", white("[GORECON::WAYBACK] waymore"))
	fmt.Printf("%s\n", strings.Repeat("=", 27))

	startTime := time.Now()
	outputFile := filepath.Join(rawDir, "waymore.txt")

	// Check if waymore is installed
	if _, err := exec.LookPath("waymore"); err != nil {
		fmt.Printf("[%s] waymore not found\n", red("-"))
		fmt.Printf("[%s] Install: pip install waymore\n", cyan("*"))
		return ToolResult{
			Tool:  "waymore",
			Error: "tool not installed",
		}
	}

	fmt.Printf("[%s] Extended search with waymore...\n", cyan("*"))
	fmt.Printf("[%s] Additional sources: VirusTotal, Alien Vault\n", cyan("*"))

	// Execute waymore
	cmd := exec.CommandContext(ctx, "waymore", "-i", domain, "-mode", "U", "-oU", outputFile)
	if err := cmd.Run(); err != nil {
		fmt.Printf("[%s] waymore failed: %v\n", red("-"), err)
		return ToolResult{
			Tool:     "waymore",
			Error:    err.Error(),
			Duration: time.Since(startTime),
		}
	}

	// Read results
	urls, err := w.readURLsFromFile(outputFile)
	if err != nil {
		fmt.Printf("[%s] Failed to read waymore results: %v\n", red("-"), err)
		return ToolResult{
			Tool:     "waymore",
			Error:    err.Error(),
			Duration: time.Since(startTime),
		}
	}

	duration := time.Since(startTime)
	fmt.Printf("[%s] Found %d additional unique URLs\n", green("+"), len(urls))
	fmt.Println()

	return ToolResult{
		Tool:     "waymore",
		URLs:     urls,
		Count:    len(urls),
		Duration: duration,
	}
}

// processResults processes and deduplicates results from all tools
func (w *WaybackPlugin) processResults(toolResults []ToolResult, processedDir, byExtDir, byCatDir string) ([]URLAnalysis, URLStats, error) {
	white := color.New(color.FgWhite, color.Bold).SprintFunc()
	cyan := color.New(color.FgCyan).SprintFunc()
	green := color.New(color.FgGreen).SprintFunc()

	fmt.Printf("%s\n", white("[GORECON::ANALYSIS] URL Processing"))
	fmt.Printf("%s\n", strings.Repeat("=", 35))

	fmt.Printf("[%s] Deduplicating URLs...\n", cyan("*"))

	// Collect and deduplicate URLs
	urlMap := make(map[string]*URLAnalysis)
	stats := URLStats{
		BySource:    make(map[string]int),
		ByExtension: make(map[string]int),
		ByCategory:  make(map[string]int),
		Parameters:  make(map[string]int),
	}

	for _, result := range toolResults {
		if result.Error != "" {
			continue
		}
		
		stats.BySource[result.Tool] = result.Count
		
		for _, rawURL := range result.URLs {
			normalizedURL := w.normalizeURL(rawURL)
			if normalizedURL == "" {
				continue
			}

			if existing, exists := urlMap[normalizedURL]; exists {
				// URL exists, update source info
				if !strings.Contains(existing.Source, result.Tool) {
					existing.Source += "," + result.Tool
				}
			} else {
				// New URL, analyze it
				analysis := w.analyzeURL(rawURL, result.Tool)
				urlMap[normalizedURL] = &analysis
				
				// Update stats
				stats.ByExtension[analysis.Extension]++
				stats.ByCategory[analysis.Category]++
				if analysis.Interesting {
					stats.InterestingURLs++
				}
				
				// Count parameters
				for _, param := range analysis.Parameters {
					stats.Parameters[param]++
				}
			}
		}
	}

	// Convert to slice
	var allURLs []URLAnalysis
	for _, analysis := range urlMap {
		allURLs = append(allURLs, *analysis)
	}

	stats.TotalURLs = len(allURLs)
	stats.UniqueURLs = len(allURLs)

	fmt.Printf("[%s] Total unique URLs: %d\n", cyan("*"), stats.UniqueURLs)
	fmt.Printf("[%s] Extracting parameters...\n", cyan("*"))
	fmt.Printf("[%s] Unique parameters found: %d\n", green("+"), len(stats.Parameters))

	// Save processed results
	if err := w.saveProcessedResults(allURLs, stats, processedDir, byExtDir, byCatDir); err != nil {
		return allURLs, stats, err
	}

	return allURLs, stats, nil
}

// Continue with helper methods...
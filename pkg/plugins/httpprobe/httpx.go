package httpprobe

import (
	"bufio"
	"context"
	"encoding/json"
	"fmt"
	"io/ioutil"
	"os"
	"os/exec"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/fatih/color"
	"github.com/f2u0a0d3/GoRecon/pkg/core"
	"github.com/f2u0a0d3/GoRecon/pkg/models"
	"github.com/f2u0a0d3/GoRecon/pkg/plugins/base"
)

// HTTPProbePlugin implements HTTP service probing
type HTTPProbePlugin struct {
	*base.BaseAdapter
	config *HTTPProbeConfig
}

// HTTPProbeConfig contains HTTP probing configuration
type HTTPProbeConfig struct {
	EnableHTTPX   bool          `json:"enable_httpx"`
	Threads       int           `json:"threads"`
	Timeout       time.Duration `json:"timeout"`
	UserAgent     string        `json:"user_agent"`
	TechDetection bool          `json:"tech_detection"`
}

// HTTPResult represents an HTTP probe result
type HTTPResult struct {
	URL           string    `json:"url"`
	StatusCode    int       `json:"status_code"`
	ContentLength int       `json:"content_length"`
	ContentType   string    `json:"content_type"`
	Server        string    `json:"server"`
	Title         string    `json:"title"`
	Technologies  []string  `json:"technologies"`
	Timestamp     time.Time `json:"timestamp"`
}

// HTTPProbeStats contains HTTP probing statistics
type HTTPProbeStats struct {
	TotalURLs     int                    `json:"total_urls"`
	AliveURLs     int                    `json:"alive_urls"`
	ByStatusCode  map[int]int            `json:"by_status_code"`
	ByServer      map[string]int         `json:"by_server"`
	ByTechnology  map[string]int         `json:"by_technology"`
	ProbeDuration time.Duration          `json:"probe_duration"`
}

// NewHTTPProbePlugin creates a new HTTP probing plugin
func NewHTTPProbePlugin() *HTTPProbePlugin {
	config := &HTTPProbeConfig{
		EnableHTTPX:   true,
		Threads:       50,
		Timeout:       10 * time.Second,
		UserAgent:     "GORECON/2.0",
		TechDetection: true,
	}

	baseAdapter := base.NewBaseAdapter(base.BaseAdapterConfig{
		Name:        "httpprobe",
		Category:    "httpprobe", 
		Description: "HTTP service probing and enumeration",
		Version:     "1.0.0",
		Author:      "GoRecon Team",
		ToolName:    "httpx",
		Passive:     false,
		Duration:    20 * time.Minute,
		Concurrency: 1,
		Priority:    7,
		Resources: core.Resources{
			CPUCores:      2,
			MemoryMB:      1024,
			NetworkAccess: true,
		},
		Provides: []string{"http_services", "technologies"},
		Consumes: []string{"urls", "open_ports"},
	})

	return &HTTPProbePlugin{
		BaseAdapter: baseAdapter,
		config:      config,
	}
}

// Run executes HTTP probing
func (h *HTTPProbePlugin) Run(ctx context.Context, target *models.Target, results chan<- models.PluginResult, shared *core.SharedContext) error {
	logger := shared.GetLogger().WithField("plugin", "httpprobe")
	
	cyan := color.New(color.FgCyan).SprintFunc()
	white := color.New(color.FgWhite, color.Bold).SprintFunc()

	domain := target.Domain
	if domain == "" {
		domain = h.ExtractDomain(target.URL)
	}

	fmt.Printf("\n%s\n", white("[GORECON] HTTP Prober v1.0"))
	fmt.Printf("%s\n", strings.Repeat("=", 26))
	fmt.Printf("[%s] Using httpx for comprehensive web analysis\n", cyan("*"))

	urlList := h.collectURLs(shared, domain, target)
	fmt.Printf("[%s] Probing %d URLs from previous steps...\n\n", cyan("*"), len(urlList))

	workDir := filepath.Join("./work", domain, "httpprobe")
	if err := os.MkdirAll(workDir, 0755); err != nil {
		return fmt.Errorf("failed to create workspace: %w", err)
	}
	
	rawDir := filepath.Join(workDir, "raw")
	if err := os.MkdirAll(rawDir, 0755); err != nil {
		return fmt.Errorf("failed to create directory: %w", err)
	}

	httpResults, stats, err := h.runHTTPX(ctx, urlList, rawDir)
	if err != nil {
		logger.Error("HTTP probing failed", err)
		return err
	}

	h.displayResults(httpResults, stats)
	h.generatePluginResults(target, httpResults, results)
	h.addDiscoveries(shared, domain, httpResults)

	logger.Info("HTTP probing completed",
		"target", domain,
		"alive_urls", stats.AliveURLs,
		"total_urls", stats.TotalURLs)

	return nil
}

func (h *HTTPProbePlugin) collectURLs(shared *core.SharedContext, domain string, target *models.Target) []string {
	urlSet := make(map[string]bool)

	if target.URL != "" {
		urlSet[target.URL] = true
	}

	urlSet[fmt.Sprintf("http://%s", domain)] = true
	urlSet[fmt.Sprintf("https://%s", domain)] = true

	discoveries := shared.GetDiscoveries("")
	for _, discovery := range discoveries {
		value, ok := discovery.Value.(string)
		if !ok {
			continue
		}
		switch discovery.Type {
		case "historical_url", "http_service":
			if strings.Contains(value, domain) {
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

func (h *HTTPProbePlugin) runHTTPX(ctx context.Context, urlList []string, rawDir string) ([]HTTPResult, HTTPProbeStats, error) {
	white := color.New(color.FgWhite, color.Bold).SprintFunc()
	cyan := color.New(color.FgCyan).SprintFunc()
	red := color.New(color.FgRed).SprintFunc()

	fmt.Printf("%s\n", white("[GORECON::HTTPX] Web Services"))
	fmt.Printf("%s\n", strings.Repeat("=", 30))

	if _, err := exec.LookPath("httpx"); err != nil {
		fmt.Printf("[%s] httpx not found\n", red("-"))
		fmt.Printf("[%s] Install: go install github.com/projectdiscovery/httpx/cmd/httpx@latest\n", cyan("*"))
		return nil, HTTPProbeStats{}, fmt.Errorf("httpx not installed")
	}

	inputFile := filepath.Join(rawDir, "urls.txt")
	if err := h.saveURLsToFile(urlList, inputFile); err != nil {
		return nil, HTTPProbeStats{}, err
	}

	jsonOutput := filepath.Join(rawDir, "httpx.json")
	args := []string{
		"-list", inputFile,
		"-json",
		"-o", jsonOutput,
		"-threads", strconv.Itoa(h.config.Threads),
		"-timeout", strconv.Itoa(int(h.config.Timeout.Seconds())),
		"-silent",
	}

	if h.config.TechDetection {
		args = append(args, "-tech-detect")
	}

	startTime := time.Now()
	cmd := exec.CommandContext(ctx, "httpx", args...)
	if err := cmd.Run(); err != nil {
		return nil, HTTPProbeStats{}, fmt.Errorf("httpx failed: %w", err)
	}

	httpResults, err := h.parseHTTPXOutput(jsonOutput)
	if err != nil {
		return nil, HTTPProbeStats{}, err
	}

	stats := HTTPProbeStats{
		TotalURLs:     len(urlList),
		AliveURLs:     len(httpResults),
		ByStatusCode:  make(map[int]int),
		ByServer:      make(map[string]int),
		ByTechnology:  make(map[string]int),
		ProbeDuration: time.Since(startTime),
	}

	for _, result := range httpResults {
		stats.ByStatusCode[result.StatusCode]++
		if result.Server != "" {
			stats.ByServer[result.Server]++
		}
		for _, tech := range result.Technologies {
			stats.ByTechnology[tech]++
		}
	}

	return httpResults, stats, nil
}

func (h *HTTPProbePlugin) saveURLsToFile(urls []string, filename string) error {
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

func (h *HTTPProbePlugin) parseHTTPXOutput(filename string) ([]HTTPResult, error) {
	data, err := ioutil.ReadFile(filename)
	if err != nil {
		return nil, err
	}

	var results []HTTPResult
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

		result := HTTPResult{Timestamp: time.Now()}
		if url, ok := raw["url"].(string); ok {
			result.URL = url
		}
		if statusCode, ok := raw["status-code"].(float64); ok {
			result.StatusCode = int(statusCode)
		}
		if length, ok := raw["content-length"].(float64); ok {
			result.ContentLength = int(length)
		}
		if contentType, ok := raw["content-type"].(string); ok {
			result.ContentType = contentType
		}
		if server, ok := raw["webserver"].(string); ok {
			result.Server = server
		}
		if title, ok := raw["title"].(string); ok {
			result.Title = title
		}
		if tech, ok := raw["tech"].([]interface{}); ok {
			for _, t := range tech {
				if techStr, ok := t.(string); ok {
					result.Technologies = append(result.Technologies, techStr)
				}
			}
		}
		results = append(results, result)
	}

	return results, nil
}

func (h *HTTPProbePlugin) displayResults(results []HTTPResult, stats HTTPProbeStats) {
	green := color.New(color.FgGreen).SprintFunc()
	red := color.New(color.FgRed).SprintFunc()
	cyan := color.New(color.FgCyan).SprintFunc()

	for _, result := range results {
		statusColor := green
		if result.StatusCode >= 400 {
			statusColor = red
		} else if result.StatusCode >= 300 {
			statusColor = cyan
		}

		fmt.Printf("[%s] %s [%s] [%s]\n",
			green("+"),
			result.URL,
			statusColor(strconv.Itoa(result.StatusCode)),
			result.Server)

		if result.Title != "" {
			fmt.Printf("    Title: %s\n", result.Title)
		}
		if len(result.Technologies) > 0 {
			fmt.Printf("    Tech: %s\n", strings.Join(result.Technologies, ", "))
		}
		if result.ContentLength > 0 {
			fmt.Printf("    Length: %d bytes\n", result.ContentLength)
		}
		fmt.Println()
	}
}

func (h *HTTPProbePlugin) generatePluginResults(target *models.Target, results []HTTPResult, resultsChan chan<- models.PluginResult) {
	for _, result := range results {
		severity := models.SeverityLow
		if result.StatusCode >= 500 {
			severity = models.SeverityMedium
		} else if result.StatusCode == 401 || result.StatusCode == 403 {
			severity = models.SeverityMedium
		}

		pluginResult := models.PluginResult{
			Plugin:      "httpprobe",
			Target:      target.URL,
			Severity:    severity,
			Title:       fmt.Sprintf("HTTP Service: %d %s", result.StatusCode, result.URL),
			Description: fmt.Sprintf("Found HTTP service: %s", result.URL),
			Data: map[string]interface{}{
				"url":            result.URL,
				"status_code":    result.StatusCode,
				"content_length": result.ContentLength,
				"server":         result.Server,
				"title":          result.Title,
				"technologies":   result.Technologies,
			},
			Timestamp: time.Now(),
		}
		resultsChan <- pluginResult
	}
}

func (h *HTTPProbePlugin) addDiscoveries(shared *core.SharedContext, domain string, results []HTTPResult) {
	for _, result := range results {
		shared.AddDiscovery(models.Discovery{
			Type:       "http_service",
			Value:      result.URL,
			Source:     "httpprobe",
			Confidence: 0.95,
			Timestamp:  time.Now(),
			Metadata: map[string]interface{}{
				"status_code":  result.StatusCode,
				"server":       result.Server,
				"title":        result.Title,
				"technologies": result.Technologies,
				"domain":       domain,
			},
		})

		for _, tech := range result.Technologies {
			shared.AddDiscovery(models.Discovery{
				Type:       "technology",
				Value:      tech,
				Source:     "httpprobe",
				Confidence: 0.9,
				Timestamp:  time.Now(),
				Metadata: map[string]interface{}{
					"url":    result.URL,
					"domain": domain,
				},
			})
		}
	}
}
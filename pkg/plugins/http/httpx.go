package http

import (
	"bufio"
	"context"
	"encoding/json"
	"fmt"
	"strings"
	"time"

	"github.com/f2u0a0d3/GoRecon/pkg/core"
	"github.com/f2u0a0d3/GoRecon/pkg/models"
	"github.com/f2u0a0d3/GoRecon/pkg/plugins/base"
)

type HttpxPlugin struct {
	*base.BaseAdapter
}

type HttpxResult struct {
	URL          string            `json:"url"`
	StatusCode   int               `json:"status_code"`
	ContentType  string            `json:"content_type"`
	ContentLength int              `json:"content_length"`
	ResponseTime string            `json:"response_time"`
	Title        string            `json:"title"`
	WebServer    string            `json:"webserver"`
	Technologies []string          `json:"tech"`
	Hash         map[string]string `json:"hash"`
	IP           string            `json:"ip"`
	CNAME        string            `json:"cname"`
	ASN          string            `json:"asn"`
	CDN          []string          `json:"cdn"`
	Location     string            `json:"location"`
	Method       string            `json:"method"`
	FaviconHash  string            `json:"favicon_hash"`
	BodyPreview  string            `json:"body_preview"`
	LineCount    int               `json:"lines"`
	WordCount    int               `json:"words"`
}

func NewHttpxPlugin() core.Plugin {
	baseConfig := base.BaseAdapterConfig{
		Name:        "HTTPX",
		Category:    "http",
		Description: "Fast HTTP toolkit for probing web services and gathering information",
		Version:     "1.0.0",
		Author:      "ProjectDiscovery",
		ToolName:    "httpx",
		ToolPath:    "httpx",
		ToolArgs:    []string{"-json", "-sc", "-cl", "-ct", "-title", "-server", "-tech-detect"},
		Passive:     true,
		Confirmation: false,
		Duration:    3 * time.Minute,
		Concurrency: 10,
		Priority:    7,
		Resources:   core.Resources{
			CPUCores: 2,
			MemoryMB: 256,
			DiskMB:   100,
		},
		Dependencies: []core.PluginDependency{
			{Name: "httpx", Type: "binary"},
		},
	}

	return &HttpxPlugin{
		BaseAdapter: base.NewBaseAdapter(baseConfig),
	}
}

func (h *HttpxPlugin) Run(ctx context.Context, target *models.Target, results chan<- models.PluginResult, shared *core.SharedContext) error {
	// Get target URLs - either from target or from shared discoveries
	targetURLs := h.getTargetURLs(target, shared)
	if len(targetURLs) == 0 {
		targetURLs = []string{target.String()}
	}

	// Build command arguments
	args := []string{
		"-json",
		"-sc", "-cl", "-ct", "-rt", "-title", "-server", "-tech-detect",
		"-ip", "-cname", "-asn", "-cdn", "-location", "-method",
		"-favicon", "-body-preview", "-line-count", "-word-count",
		"-hash", "sha256",
		"-threads", "10",
		"-timeout", "10",
		"-retries", "2",
	}

	// Add targets as input
	for _, targetURL := range targetURLs {
		args = append(args, "-target", targetURL)
	}

	// Execute httpx
	execResult, err := h.ExecuteCommand(ctx, append([]string{"httpx"}, args...))
	if err != nil {
		return fmt.Errorf("httpx execution failed: %w", err)
	}

	// Parse results
	httpxResults, err := h.parseHttpxOutput(execResult)
	if err != nil {
		return fmt.Errorf("failed to parse httpx output: %w", err)
	}

	// Process each result
	for _, httpxResult := range httpxResults {
		// Create finding
		finding := h.createHttpFinding(httpxResult, target)
		
		// Send to results channel
		select {
		case results <- finding:
		case <-ctx.Done():
			return ctx.Err()
		}

		// Share discovery for other plugins
		httpInfo := map[string]interface{}{
			"url":           httpxResult.URL,
			"status_code":   httpxResult.StatusCode,
			"title":         httpxResult.Title,
			"technologies":  httpxResult.Technologies,
			"web_server":    httpxResult.WebServer,
			"ip":            httpxResult.IP,
			"content_type":  httpxResult.ContentType,
			"alive":         httpxResult.StatusCode > 0,
		}
		
		shared.AddDiscovery(models.Discovery{
			Type:      "http",
			Key:       httpxResult.URL,
			Data:      httpInfo,
			Plugin:    h.Name(),
			Timestamp: time.Now(),
		})
	}

	// Create summary result
	if len(httpxResults) > 0 {
		aliveCount := h.countAliveServices(httpxResults)
		summaryResult := models.PluginResult{
			ID:          fmt.Sprintf("httpx-summary-%d", time.Now().UnixNano()),
			Plugin:      h.Name(),
			Tool:        "httpx",
			Category:    "http",
			Target:      target.String(),
			Timestamp:   time.Now(),
			Severity:    "info",
			RiskScore:   h.calculateRiskScore(httpxResults),
			Title:       fmt.Sprintf("HTTP probe completed: %d services found", aliveCount),
			Description: fmt.Sprintf("Probed %d targets, found %d alive HTTP services", len(targetURLs), aliveCount),
			Evidence: models.Evidence{
				Command: "httpx",
				Args:    args,
			},
			Data: map[string]interface{}{
				"targets_probed":    len(targetURLs),
				"services_alive":    aliveCount,
				"technologies_found": h.extractTechnologies(httpxResults),
				"status_codes":      h.extractStatusCodes(httpxResults),
				"web_servers":       h.extractWebServers(httpxResults),
			},
			Confidence: 0.95,
			Tags:       []string{"http", "web", "probe"},
		}

		select {
		case results <- summaryResult:
		case <-ctx.Done():
			return ctx.Err()
		}
	}

	return nil
}

func (h *HttpxPlugin) getTargetURLs(target *models.Target, shared *core.SharedContext) []string {
	var urls []string

	// Get subdomains from shared discoveries
	subdomainDiscoveries := shared.GetDiscoveries("subdomain")
	for _, discovery := range subdomainDiscoveries {
		if subdomainData, ok := discovery.Data.(map[string]interface{}); ok {
			if domain, exists := subdomainData["domain"]; exists {
				if domainStr, ok := domain.(string); ok {
					urls = append(urls, "http://"+domainStr)
					urls = append(urls, "https://"+domainStr)
				}
			}
		}
	}

	// Get URLs from wayback discoveries
	waybackDiscoveries := shared.GetDiscoveries("wayback")
	for _, discovery := range waybackDiscoveries {
		if waybackData, ok := discovery.Data.(map[string]interface{}); ok {
			if url, exists := waybackData["url"]; exists {
				if urlStr, ok := url.(string); ok {
					urls = append(urls, urlStr)
				}
			}
		}
	}

	// Deduplicate
	uniqueURLs := make(map[string]bool)
	var result []string
	for _, url := range urls {
		if !uniqueURLs[url] {
			uniqueURLs[url] = true
			result = append(result, url)
		}
	}

	return result
}

func (h *HttpxPlugin) parseHttpxOutput(data []byte) ([]HttpxResult, error) {
	var results []HttpxResult

	scanner := bufio.NewScanner(strings.NewReader(string(data)))
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line == "" || !strings.HasPrefix(line, "{") {
			continue
		}

		var result HttpxResult
		if err := json.Unmarshal([]byte(line), &result); err != nil {
			// Skip malformed JSON lines
			continue
		}

		results = append(results, result)
	}

	if err := scanner.Err(); err != nil {
		return results, fmt.Errorf("error reading httpx output: %w", err)
	}

	return results, nil
}

func (h *HttpxPlugin) createHttpFinding(httpxResult HttpxResult, target *models.Target) models.PluginResult {
	severity := h.determineSeverity(httpxResult)
	riskScore := h.calculateServiceRiskScore(httpxResult)

	return models.PluginResult{
		ID:          fmt.Sprintf("httpx-%d", time.Now().UnixNano()),
		Plugin:      h.Name(),
		Tool:        "httpx",
		Category:    "http",
		Target:      httpxResult.URL,
		Timestamp:   time.Now(),
		Severity:    severity,
		RiskScore:   riskScore,
		Title:       h.generateTitle(httpxResult),
		Description: h.generateDescription(httpxResult),
		Evidence: models.Evidence{
			Command: "httpx",
			Args:    []string{"-target", httpxResult.URL, "-json"},
		},
		Data: map[string]interface{}{
			"url":            httpxResult.URL,
			"status_code":    httpxResult.StatusCode,
			"content_type":   httpxResult.ContentType,
			"content_length": httpxResult.ContentLength,
			"response_time":  httpxResult.ResponseTime,
			"title":          httpxResult.Title,
			"web_server":     httpxResult.WebServer,
			"technologies":   httpxResult.Technologies,
			"ip":             httpxResult.IP,
			"cname":          httpxResult.CNAME,
			"asn":            httpxResult.ASN,
			"cdn":            httpxResult.CDN,
			"location":       httpxResult.Location,
			"favicon_hash":   httpxResult.FaviconHash,
			"body_preview":   httpxResult.BodyPreview,
			"line_count":     httpxResult.LineCount,
			"word_count":     httpxResult.WordCount,
			"hash":           httpxResult.Hash,
		},
		Confidence: h.calculateConfidence(httpxResult),
		Tags:       h.generateTags(httpxResult),
	}
}

func (h *HttpxPlugin) determineSeverity(result HttpxResult) string {
	// Base severity on status code and content
	switch {
	case result.StatusCode >= 500:
		return "medium" // Server errors might indicate issues
	case result.StatusCode >= 400:
		return "low" // Client errors
	case result.StatusCode >= 300:
		return "info" // Redirects
	case result.StatusCode >= 200:
		return "info" // Success codes
	case result.StatusCode > 0:
		return "low" // Other codes
	default:
		return "info" // No response
	}
}

func (h *HttpxPlugin) generateTitle(result HttpxResult) string {
	if result.StatusCode > 0 {
		title := fmt.Sprintf("HTTP service [%d] - %s", result.StatusCode, result.URL)
		if result.Title != "" {
			title += fmt.Sprintf(" (%s)", result.Title)
		}
		return title
	}
	return fmt.Sprintf("HTTP probe - %s", result.URL)
}

func (h *HttpxPlugin) generateDescription(result HttpxResult) string {
	if result.StatusCode == 0 {
		return fmt.Sprintf("HTTP probe failed for %s", result.URL)
	}

	desc := fmt.Sprintf("HTTP service discovered at %s", result.URL)
	desc += fmt.Sprintf(" - Status: %d", result.StatusCode)
	
	if result.WebServer != "" {
		desc += fmt.Sprintf(", Server: %s", result.WebServer)
	}
	
	if len(result.Technologies) > 0 {
		desc += fmt.Sprintf(", Technologies: %s", strings.Join(result.Technologies, ", "))
	}
	
	if result.Title != "" {
		desc += fmt.Sprintf(", Title: %s", result.Title)
	}

	return desc
}

func (h *HttpxPlugin) calculateServiceRiskScore(result HttpxResult) float64 {
	baseScore := 3.0

	// Status code impact
	switch {
	case result.StatusCode >= 500:
		baseScore += 2.0 // Server errors
	case result.StatusCode >= 400:
		baseScore += 1.0 // Client errors
	case result.StatusCode >= 200 && result.StatusCode < 300:
		baseScore += 1.5 // Working service
	}

	// Technology-based risk
	for _, tech := range result.Technologies {
		techLower := strings.ToLower(tech)
		switch {
		case strings.Contains(techLower, "admin"):
			baseScore += 2.0
		case strings.Contains(techLower, "phpmyadmin"):
			baseScore += 3.0
		case strings.Contains(techLower, "wordpress"):
			baseScore += 1.5
		case strings.Contains(techLower, "jenkins"):
			baseScore += 2.0
		}
	}

	// Server-based risk
	serverLower := strings.ToLower(result.WebServer)
	if strings.Contains(serverLower, "apache") || strings.Contains(serverLower, "nginx") {
		baseScore += 0.5
	}

	// Title-based risk
	titleLower := strings.ToLower(result.Title)
	if strings.Contains(titleLower, "admin") || strings.Contains(titleLower, "login") {
		baseScore += 1.5
	}

	// Cap at 10.0
	if baseScore > 10.0 {
		baseScore = 10.0
	}

	return baseScore
}

func (h *HttpxPlugin) calculateRiskScore(results []HttpxResult) float64 {
	if len(results) == 0 {
		return 2.0
	}

	aliveCount := h.countAliveServices(results)
	baseScore := 3.0

	// More alive services = larger attack surface
	if aliveCount > 20 {
		baseScore = 7.0
	} else if aliveCount > 10 {
		baseScore = 6.0
	} else if aliveCount > 5 {
		baseScore = 5.0
	} else if aliveCount > 1 {
		baseScore = 4.0
	}

	return baseScore
}

func (h *HttpxPlugin) calculateConfidence(result HttpxResult) float64 {
	if result.StatusCode > 0 {
		return 0.95
	}
	return 0.7
}

func (h *HttpxPlugin) generateTags(result HttpxResult) []string {
	tags := []string{"http", "web"}

	if result.StatusCode > 0 {
		tags = append(tags, "alive")
		
		// Status code tags
		if result.StatusCode >= 200 && result.StatusCode < 300 {
			tags = append(tags, "success")
		} else if result.StatusCode >= 300 && result.StatusCode < 400 {
			tags = append(tags, "redirect")
		} else if result.StatusCode >= 400 && result.StatusCode < 500 {
			tags = append(tags, "client-error")
		} else if result.StatusCode >= 500 {
			tags = append(tags, "server-error")
		}
	} else {
		tags = append(tags, "down")
	}

	// Technology tags
	for _, tech := range result.Technologies {
		techLower := strings.ToLower(tech)
		if strings.Contains(techLower, "admin") {
			tags = append(tags, "admin")
		}
		if strings.Contains(techLower, "cms") {
			tags = append(tags, "cms")
		}
	}

	// Server tags
	if result.WebServer != "" {
		serverLower := strings.ToLower(result.WebServer)
		if strings.Contains(serverLower, "apache") {
			tags = append(tags, "apache")
		} else if strings.Contains(serverLower, "nginx") {
			tags = append(tags, "nginx")
		} else if strings.Contains(serverLower, "iis") {
			tags = append(tags, "iis")
		}
	}

	// CDN tags
	if len(result.CDN) > 0 {
		tags = append(tags, "cdn")
	}

	return tags
}

func (h *HttpxPlugin) countAliveServices(results []HttpxResult) int {
	count := 0
	for _, result := range results {
		if result.StatusCode > 0 {
			count++
		}
	}
	return count
}

func (h *HttpxPlugin) extractTechnologies(results []HttpxResult) []string {
	techMap := make(map[string]bool)
	for _, result := range results {
		for _, tech := range result.Technologies {
			techMap[tech] = true
		}
	}

	var technologies []string
	for tech := range techMap {
		technologies = append(technologies, tech)
	}
	return technologies
}

func (h *HttpxPlugin) extractStatusCodes(results []HttpxResult) []int {
	codeMap := make(map[int]bool)
	for _, result := range results {
		if result.StatusCode > 0 {
			codeMap[result.StatusCode] = true
		}
	}

	var codes []int
	for code := range codeMap {
		codes = append(codes, code)
	}
	return codes
}

func (h *HttpxPlugin) extractWebServers(results []HttpxResult) []string {
	serverMap := make(map[string]bool)
	for _, result := range results {
		if result.WebServer != "" {
			serverMap[result.WebServer] = true
		}
	}

	var servers []string
	for server := range serverMap {
		servers = append(servers, server)
	}
	return servers
}

// Intelligence patterns
func (h *HttpxPlugin) GetIntelligencePatterns() []core.Pattern {
	return []core.Pattern{
		{
			Name:        "Administrative Interface Exposure",
			Description: "Administrative interfaces or panels discovered",
			Severity:    "high",
			Confidence:  0.9,
		},
		{
			Name:        "Large HTTP Attack Surface",
			Description: "Large number of HTTP services exposed",
			Severity:    "medium",
			Confidence:  0.8,
		},
		{
			Name:        "Development Environment Exposure",
			Description: "Development or staging environments exposed",
			Severity:    "medium",
			Confidence:  0.85,
		},
	}
}
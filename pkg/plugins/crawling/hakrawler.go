package crawling

import (
	"bufio"
	"context"
	"fmt"
	"net/url"
	"strconv"
	"strings"
	"time"

	"github.com/f2u0a0d3/GoRecon/pkg/plugins/base"
	"github.com/f2u0a0d3/GoRecon/pkg/core"
	"github.com/f2u0a0d3/GoRecon/pkg/models"
)

type HakrawlerPlugin struct {
	base.BaseAdapter
	config *HakrawlerConfig
}

type HakrawlerConfig struct {
	Depth          int
	Threads        int
	Timeout        int
	IncludeSubdomains bool
	IncludeJS      bool
	IncludeForms   bool
	IncludeRobots  bool
	UniqueOutput   bool
	PlainOutput    bool
	UserAgent      string
	Headers        map[string]string
}

func NewHakrawlerPlugin() *HakrawlerPlugin {
	return &HakrawlerPlugin{
		BaseAdapter: base.BaseAdapter{
			PluginName:        "hakrawler",
			PluginVersion:     "1.0.0",
			PluginDescription: "Fast web crawler for discovering endpoints and assets",
			PluginAuthor:     "GoRecon Team",
			SupportedTargets: []string{"domain", "url"},
		},
		config: &HakrawlerConfig{
			Depth:             3,
			Threads:           8,
			Timeout:           10,
			IncludeSubdomains: true,
			IncludeJS:         true,
			IncludeForms:      true,
			IncludeRobots:     true,
			UniqueOutput:      true,
			PlainOutput:       false,
			UserAgent:         "GoRecon-Hakrawler/1.0",
			Headers:           make(map[string]string),
		},
	}
}

func (h *HakrawlerPlugin) SetConfig(configMap map[string]interface{}) error {
	if depth, ok := configMap["depth"].(int); ok && depth > 0 && depth <= 10 {
		h.config.Depth = depth
	}
	if threads, ok := configMap["threads"].(int); ok && threads > 0 && threads <= 50 {
		h.config.Threads = threads
	}
	if timeout, ok := configMap["timeout"].(int); ok && timeout > 0 && timeout <= 300 {
		h.config.Timeout = timeout
	}
	if includeSubdomains, ok := configMap["include_subdomains"].(bool); ok {
		h.config.IncludeSubdomains = includeSubdomains
	}
	if includeJS, ok := configMap["include_js"].(bool); ok {
		h.config.IncludeJS = includeJS
	}
	if includeForms, ok := configMap["include_forms"].(bool); ok {
		h.config.IncludeForms = includeForms
	}
	if includeRobots, ok := configMap["include_robots"].(bool); ok {
		h.config.IncludeRobots = includeRobots
	}
	if uniqueOutput, ok := configMap["unique_output"].(bool); ok {
		h.config.UniqueOutput = uniqueOutput
	}
	if userAgent, ok := configMap["user_agent"].(string); ok && userAgent != "" {
		h.config.UserAgent = userAgent
	}
	if headers, ok := configMap["headers"].(map[string]interface{}); ok {
		h.config.Headers = make(map[string]string)
		for key, value := range headers {
			if strValue, ok := value.(string); ok {
				h.config.Headers[key] = strValue
			}
		}
	}
	return nil
}

func (h *HakrawlerPlugin) Execute(ctx context.Context, target models.Target, sharedCtx *core.SharedContext) (*models.PluginResult, error) {
	targetStr := h.getTargetString(target)
	if targetStr == "" {
		return nil, fmt.Errorf("invalid target for hakrawler")
	}

	args := h.buildHakrawlerArgs(targetStr)
	
	output, err := h.ExecuteCommand(ctx, "hakrawler", args, time.Duration(h.config.Timeout)*time.Second)
	if err != nil {
		return nil, fmt.Errorf("hakrawler execution failed: %w", err)
	}

	result, err := h.parseHakrawlerOutput(output, target)
	if err != nil {
		return nil, fmt.Errorf("failed to parse hakrawler output: %w", err)
	}

	h.populateSharedContext(result, sharedCtx)

	return result, nil
}

func (h *HakrawlerPlugin) getTargetString(target models.Target) string {
	switch target.GetType() {
	case "domain":
		return "https://" + target.GetDomain()
	case "url":
		return target.GetURL()
	default:
		return ""
	}
}

func (h *HakrawlerPlugin) buildHakrawlerArgs(target string) []string {
	args := []string{
		"-url", target,
		"-d", strconv.Itoa(h.config.Depth),
		"-t", strconv.Itoa(h.config.Threads),
	}

	if h.config.IncludeSubdomains {
		args = append(args, "-s")
	}

	if h.config.IncludeJS {
		args = append(args, "-js")
	}

	if h.config.IncludeForms {
		args = append(args, "-forms")
	}

	if h.config.IncludeRobots {
		args = append(args, "-robots")
	}

	if h.config.UniqueOutput {
		args = append(args, "-u")
	}

	if h.config.PlainOutput {
		args = append(args, "-plain")
	}

	if h.config.UserAgent != "" {
		args = append(args, "-ua", h.config.UserAgent)
	}

	for key, value := range h.config.Headers {
		args = append(args, "-h", fmt.Sprintf("%s: %s", key, value))
	}

	return args
}

func (h *HakrawlerPlugin) parseHakrawlerOutput(output string, target models.Target) (*models.PluginResult, error) {
	result := &models.PluginResult{
		PluginName: h.PluginName,
		Target:     target,
		Status:     models.StatusSuccess,
		Timestamp:  time.Now(),
		Results:    make(map[string]interface{}),
		RawOutput:  output,
	}

	if strings.TrimSpace(output) == "" {
		result.Status = models.StatusError
		result.Error = "empty hakrawler output"
		return result, nil
	}

	urls := make([]string, 0)
	endpoints := make([]string, 0)
	jsFiles := make([]string, 0)
	forms := make([]string, 0)
	subdomains := make([]string, 0)
	
	urlCategories := make(map[string][]string)
	extensions := make(map[string]int)

	scanner := bufio.NewScanner(strings.NewReader(output))
	seenURLs := make(map[string]bool)

	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line == "" {
			continue
		}

		select {
		case <-ctx.Done():
			return result, ctx.Err()
		default:
		}

		if h.config.UniqueOutput && seenURLs[line] {
			continue
		}
		seenURLs[line] = true

		parsedURL, err := url.Parse(line)
		if err != nil {
			continue
		}

		urls = append(urls, line)

		category := h.categorizeURL(line)
		if urlCategories[category] == nil {
			urlCategories[category] = make([]string, 0)
		}
		urlCategories[category] = append(urlCategories[category], line)

		ext := h.getFileExtension(parsedURL.Path)
		if ext != "" {
			extensions[ext]++
		}

		if strings.Contains(line, ".js") {
			jsFiles = append(jsFiles, line)
		}

		if strings.Contains(line, "form") || strings.Contains(line, "submit") {
			forms = append(forms, line)
		}

		if parsedURL.Host != "" && h.isSubdomain(parsedURL.Host, target) {
			subdomains = append(subdomains, parsedURL.Host)
		}

		if parsedURL.Path != "" && parsedURL.Path != "/" {
			endpoints = append(endpoints, parsedURL.Path)
		}
	}

	urlStats := h.calculateURLStats(urls, urlCategories, extensions)
	riskAssessment := h.assessRisk(urls, jsFiles, forms, endpoints)

	result.Results["urls"] = urls
	result.Results["endpoints"] = endpoints
	result.Results["js_files"] = jsFiles
	result.Results["forms"] = forms
	result.Results["subdomains"] = h.uniqueStrings(subdomains)
	result.Results["url_categories"] = urlCategories
	result.Results["statistics"] = urlStats
	result.Results["risk_assessment"] = riskAssessment

	return result, nil
}

func (h *HakrawlerPlugin) categorizeURL(urlStr string) string {
	parsedURL, err := url.Parse(urlStr)
	if err != nil {
		return "unknown"
	}

	path := strings.ToLower(parsedURL.Path)
	
	if strings.Contains(path, "admin") || strings.Contains(path, "manage") {
		return "admin"
	}
	if strings.Contains(path, "api") || strings.Contains(path, "/v1/") || strings.Contains(path, "/v2/") {
		return "api"
	}
	if strings.Contains(path, "login") || strings.Contains(path, "auth") || strings.Contains(path, "signin") {
		return "authentication"
	}
	if strings.Contains(path, "upload") || strings.Contains(path, "file") {
		return "file_operations"
	}
	if strings.HasSuffix(path, ".js") {
		return "javascript"
	}
	if strings.HasSuffix(path, ".css") {
		return "stylesheets"
	}
	if strings.Contains(path, "image") || strings.HasSuffix(path, ".jpg") || strings.HasSuffix(path, ".png") {
		return "images"
	}
	if parsedURL.RawQuery != "" {
		return "dynamic"
	}
	
	return "static"
}

func (h *HakrawlerPlugin) getFileExtension(path string) string {
	parts := strings.Split(path, ".")
	if len(parts) > 1 {
		ext := strings.ToLower(parts[len(parts)-1])
		if len(ext) <= 4 && ext != "" {
			return ext
		}
	}
	return ""
}

func (h *HakrawlerPlugin) isSubdomain(host string, target models.Target) bool {
	if target.GetType() == "domain" {
		domain := target.GetDomain()
		return strings.HasSuffix(host, "."+domain) || host == domain
	}
	return false
}

func (h *HakrawlerPlugin) uniqueStrings(slice []string) []string {
	seen := make(map[string]bool)
	result := make([]string, 0)
	
	for _, str := range slice {
		if !seen[str] {
			seen[str] = true
			result = append(result, str)
		}
	}
	
	return result
}

func (h *HakrawlerPlugin) calculateURLStats(urls []string, categories map[string][]string, extensions map[string]int) map[string]interface{} {
	stats := map[string]interface{}{
		"total_urls":        len(urls),
		"unique_extensions": len(extensions),
		"category_counts":   make(map[string]int),
		"top_extensions":    h.getTopExtensions(extensions, 10),
	}

	categoryCounts := make(map[string]int)
	for category, urlList := range categories {
		categoryCounts[category] = len(urlList)
	}
	stats["category_counts"] = categoryCounts

	return stats
}

func (h *HakrawlerPlugin) getTopExtensions(extensions map[string]int, limit int) []map[string]interface{} {
	type ExtCount struct {
		Extension string
		Count     int
	}

	extList := make([]ExtCount, 0, len(extensions))
	for ext, count := range extensions {
		extList = append(extList, ExtCount{Extension: ext, Count: count})
	}

	for i := 0; i < len(extList)-1; i++ {
		for j := i + 1; j < len(extList); j++ {
			if extList[j].Count > extList[i].Count {
				extList[i], extList[j] = extList[j], extList[i]
			}
		}
	}

	result := make([]map[string]interface{}, 0)
	maxItems := limit
	if len(extList) < maxItems {
		maxItems = len(extList)
	}

	for i := 0; i < maxItems; i++ {
		result = append(result, map[string]interface{}{
			"extension": extList[i].Extension,
			"count":     extList[i].Count,
		})
	}

	return result
}

func (h *HakrawlerPlugin) assessRisk(urls, jsFiles, forms, endpoints []string) map[string]interface{} {
	riskScore := 0.0
	riskFactors := make([]string, 0)

	if len(jsFiles) > 20 {
		riskScore += 2.0
		riskFactors = append(riskFactors, "High number of JavaScript files")
	}

	if len(forms) > 5 {
		riskScore += 1.5
		riskFactors = append(riskFactors, "Multiple forms detected")
	}

	adminEndpoints := 0
	apiEndpoints := 0
	for _, endpoint := range endpoints {
		endpoint = strings.ToLower(endpoint)
		if strings.Contains(endpoint, "admin") || strings.Contains(endpoint, "manage") {
			adminEndpoints++
		}
		if strings.Contains(endpoint, "api") {
			apiEndpoints++
		}
	}

	if adminEndpoints > 0 {
		riskScore += 3.0
		riskFactors = append(riskFactors, "Administrative endpoints detected")
	}

	if apiEndpoints > 10 {
		riskScore += 2.0
		riskFactors = append(riskFactors, "Multiple API endpoints detected")
	}

	if len(endpoints) > 100 {
		riskScore += 1.0
		riskFactors = append(riskFactors, "Large attack surface")
	}

	normalizedScore := riskScore
	if normalizedScore > 10.0 {
		normalizedScore = 10.0
	}

	riskLevel := "LOW"
	if normalizedScore >= 7.0 {
		riskLevel = "HIGH"
	} else if normalizedScore >= 4.0 {
		riskLevel = "MEDIUM"
	}

	return map[string]interface{}{
		"risk_score":    normalizedScore,
		"risk_level":    riskLevel,
		"risk_factors":  riskFactors,
		"admin_endpoints": adminEndpoints,
		"api_endpoints":   apiEndpoints,
	}
}

func (h *HakrawlerPlugin) populateSharedContext(result *models.PluginResult, sharedCtx *core.SharedContext) {
	if urls, ok := result.Results["urls"].([]string); ok {
		for _, urlStr := range urls {
			sharedCtx.AddURL(urlStr)
		}
	}

	if endpoints, ok := result.Results["endpoints"].([]string); ok {
		for _, endpoint := range endpoints {
			sharedCtx.AddPath(endpoint)
		}
	}

	if subdomains, ok := result.Results["subdomains"].([]string); ok {
		for _, subdomain := range subdomains {
			sharedCtx.AddSubdomain(subdomain)
		}
	}

	if jsFiles, ok := result.Results["js_files"].([]string); ok {
		for _, jsFile := range jsFiles {
			sharedCtx.AddTechnology("JavaScript")
			break
		}
	}

	if riskAssessment, ok := result.Results["risk_assessment"].(map[string]interface{}); ok {
		if riskScore, ok := riskAssessment["risk_score"].(float64); ok && riskScore > 5.0 {
			sharedCtx.AddVulnerability("High-risk web application surface detected")
		}
	}
}

func (h *HakrawlerPlugin) Cleanup() error {
	return nil
}

func (h *HakrawlerPlugin) ValidateConfig() error {
	if h.config.Depth < 1 || h.config.Depth > 10 {
		return fmt.Errorf("depth must be between 1 and 10")
	}
	if h.config.Threads < 1 || h.config.Threads > 50 {
		return fmt.Errorf("threads must be between 1 and 50")
	}
	if h.config.Timeout < 1 || h.config.Timeout > 300 {
		return fmt.Errorf("timeout must be between 1 and 300 seconds")
	}
	return nil
}
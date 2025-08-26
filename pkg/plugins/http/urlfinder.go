package http

import (
	"bufio"
	"context"
	"encoding/json"
	"fmt"
	"net/url"
	"strings"
	"sync"
	"time"

	"github.com/f2u0a0d3/GoRecon/pkg/plugins/base"
	"github.com/f2u0a0d3/GoRecon/pkg/core"
	"github.com/f2u0a0d3/GoRecon/pkg/models"
)

type URLFinderPlugin struct {
	*base.BaseAdapter
	config *URLFinderConfig
}

type URLFinderConfig struct {
	Sources          []string `json:"sources"`
	ExcludeSources   []string `json:"exclude_sources"`
	UseAllSources    bool     `json:"use_all_sources"`
	URLScope         []string `json:"url_scope"`
	URLOutScope      []string `json:"url_out_scope"`
	FieldScope       string   `json:"field_scope"`
	NoScope          bool     `json:"no_scope"`
	DisplayOutScope  bool     `json:"display_out_scope"`
	Match            []string `json:"match"`
	Filter           []string `json:"filter"`
	RateLimit        int      `json:"rate_limit"`
	Timeout          int      `json:"timeout"`
	MaxTime          int      `json:"max_time"`
	OutputJSON       bool     `json:"output_json"`
	CollectSources   bool     `json:"collect_sources"`
	Silent           bool     `json:"silent"`
	Verbose          bool     `json:"verbose"`
	NoColor          bool     `json:"no_color"`
	ProxyURL         string   `json:"proxy_url"`
}

type URLFinderResult struct {
	URL           string    `json:"url"`
	Source        string    `json:"source,omitempty"`
	Timestamp     time.Time `json:"timestamp"`
	Domain        string    `json:"domain"`
	Path          string    `json:"path"`
	Parameters    []string  `json:"parameters,omitempty"`
	Extensions    []string  `json:"extensions,omitempty"`
	StatusCode    int       `json:"status_code,omitempty"`
	ContentLength int       `json:"content_length,omitempty"`
	Technology    []string  `json:"technology,omitempty"`
}

func NewURLFinderPlugin() *URLFinderPlugin {
	config := &URLFinderConfig{
		Sources:         []string{"waybackarchive", "commoncrawl", "alienvault"},
		ExcludeSources:  []string{},
		UseAllSources:   false,
		URLScope:        []string{},
		URLOutScope:     []string{},
		FieldScope:      "rdn",
		NoScope:         false,
		DisplayOutScope: false,
		Match:           []string{},
		Filter:          []string{},
		RateLimit:       100,
		Timeout:         30,
		MaxTime:         10,
		OutputJSON:      true,
		CollectSources:  true,
		Silent:          true,
		Verbose:         false,
		NoColor:         true,
	}

	return &URLFinderPlugin{
		BaseAdapter: base.NewBaseAdapter("urlfinder", "URL Discovery and Collection"),
		config:      config,
	}
}

func (u *URLFinderPlugin) GetMetadata() models.PluginMetadata {
	return models.PluginMetadata{
		Name:        "URLFinder",
		Version:     "0.0.3",
		Description: "High-speed tool for passively gathering URLs from multiple sources",
		Author:      "ProjectDiscovery",
		Tags:        []string{"url", "discovery", "passive", "reconnaissance", "wayback", "commoncrawl"},
		Category:    "http_analysis",
		Priority:    8,
		Timeout:     600,
		RateLimit:   100,
		Dependencies: []string{"urlfinder"},
		Capabilities: []string{
			"url_discovery",
			"passive_reconnaissance",
			"historical_data",
			"multi_source_aggregation",
			"scope_filtering",
			"parameter_extraction",
		},
	}
}

func (u *URLFinderPlugin) Configure(config map[string]interface{}) error {
	if sources, ok := config["sources"].([]interface{}); ok {
		u.config.Sources = make([]string, len(sources))
		for i, s := range sources {
			u.config.Sources[i] = fmt.Sprintf("%v", s)
		}
	}

	if excludeSources, ok := config["exclude_sources"].([]interface{}); ok {
		u.config.ExcludeSources = make([]string, len(excludeSources))
		for i, s := range excludeSources {
			u.config.ExcludeSources[i] = fmt.Sprintf("%v", s)
		}
	}

	if useAllSources, ok := config["use_all_sources"].(bool); ok {
		u.config.UseAllSources = useAllSources
	}

	if urlScope, ok := config["url_scope"].([]interface{}); ok {
		u.config.URLScope = make([]string, len(urlScope))
		for i, s := range urlScope {
			u.config.URLScope[i] = fmt.Sprintf("%v", s)
		}
	}

	if urlOutScope, ok := config["url_out_scope"].([]interface{}); ok {
		u.config.URLOutScope = make([]string, len(urlOutScope))
		for i, s := range urlOutScope {
			u.config.URLOutScope[i] = fmt.Sprintf("%v", s)
		}
	}

	if fieldScope, ok := config["field_scope"].(string); ok {
		u.config.FieldScope = fieldScope
	}

	if noScope, ok := config["no_scope"].(bool); ok {
		u.config.NoScope = noScope
	}

	if displayOutScope, ok := config["display_out_scope"].(bool); ok {
		u.config.DisplayOutScope = displayOutScope
	}

	if match, ok := config["match"].([]interface{}); ok {
		u.config.Match = make([]string, len(match))
		for i, m := range match {
			u.config.Match[i] = fmt.Sprintf("%v", m)
		}
	}

	if filter, ok := config["filter"].([]interface{}); ok {
		u.config.Filter = make([]string, len(filter))
		for i, f := range filter {
			u.config.Filter[i] = fmt.Sprintf("%v", f)
		}
	}

	if rateLimit, ok := config["rate_limit"].(int); ok {
		u.config.RateLimit = rateLimit
	}

	if timeout, ok := config["timeout"].(int); ok {
		u.config.Timeout = timeout
	}

	if maxTime, ok := config["max_time"].(int); ok {
		u.config.MaxTime = maxTime
	}

	if outputJSON, ok := config["output_json"].(bool); ok {
		u.config.OutputJSON = outputJSON
	}

	if collectSources, ok := config["collect_sources"].(bool); ok {
		u.config.CollectSources = collectSources
	}

	if silent, ok := config["silent"].(bool); ok {
		u.config.Silent = silent
	}

	if verbose, ok := config["verbose"].(bool); ok {
		u.config.Verbose = verbose
	}

	if noColor, ok := config["no_color"].(bool); ok {
		u.config.NoColor = noColor
	}

	if proxyURL, ok := config["proxy_url"].(string); ok {
		u.config.ProxyURL = proxyURL
	}

	return nil
}

func (u *URLFinderPlugin) Run(ctx context.Context, target *models.Target, results chan<- models.PluginResult, shared *core.SharedContext) error {
	u.SetStatus("running")
	defer u.SetStatus("completed")

	domains := u.getTargetDomains(target, shared)
	if len(domains) == 0 {
		domains = []string{target.GetDomain()}
	}

	// Process domains
	var wg sync.WaitGroup
	semaphore := make(chan struct{}, 5) // Limit concurrent scans

	for _, domain := range domains {
		wg.Add(1)
		go func(targetDomain string) {
			defer wg.Done()
			semaphore <- struct{}{}
			defer func() { <-semaphore }()

			if err := u.scanDomain(ctx, targetDomain, results, shared); err != nil {
				u.LogError("Failed to scan domain %s: %v", targetDomain, err)
			}
		}(domain)
	}

	wg.Wait()
	return nil
}

func (u *URLFinderPlugin) getTargetDomains(target *models.Target, shared *core.SharedContext) []string {
	var domains []string

	// Add primary target domain
	if target.GetDomain() != "" {
		domains = append(domains, target.GetDomain())
	}

	// Get domains from shared discoveries
	discoveries := shared.GetDiscoveriesByType("subdomain", "domain")
	for _, discovery := range discoveries {
		if discovery.Data != nil {
			if domain, ok := discovery.Data["domain"].(string); ok && domain != "" {
				domains = append(domains, domain)
			}
			if subdomain, ok := discovery.Data["subdomain"].(string); ok && subdomain != "" {
				domains = append(domains, subdomain)
			}
		}
	}

	// Remove duplicates
	domainSet := make(map[string]bool)
	uniqueDomains := []string{}
	for _, domain := range domains {
		if !domainSet[domain] {
			domainSet[domain] = true
			uniqueDomains = append(uniqueDomains, domain)
		}
	}

	return uniqueDomains
}

func (u *URLFinderPlugin) scanDomain(ctx context.Context, domain string, results chan<- models.PluginResult, shared *core.SharedContext) error {
	args := []string{
		"urlfinder",
		"-d", domain,
		"-timeout", fmt.Sprintf("%d", u.config.Timeout),
		"-max-time", fmt.Sprintf("%d", u.config.MaxTime),
		"-rl", fmt.Sprintf("%d", u.config.RateLimit),
		"-fs", u.config.FieldScope,
	}

	// Add sources
	if u.config.UseAllSources {
		args = append(args, "-all")
	} else if len(u.config.Sources) > 0 {
		args = append(args, "-s", strings.Join(u.config.Sources, ","))
	}

	// Add exclude sources
	if len(u.config.ExcludeSources) > 0 {
		args = append(args, "-es", strings.Join(u.config.ExcludeSources, ","))
	}

	// Add URL scope
	if len(u.config.URLScope) > 0 {
		for _, scope := range u.config.URLScope {
			args = append(args, "-us", scope)
		}
	}

	// Add URL out scope
	if len(u.config.URLOutScope) > 0 {
		for _, scope := range u.config.URLOutScope {
			args = append(args, "-uos", scope)
		}
	}

	// Add no scope
	if u.config.NoScope {
		args = append(args, "-ns")
	}

	// Add display out scope
	if u.config.DisplayOutScope {
		args = append(args, "-do")
	}

	// Add match patterns
	if len(u.config.Match) > 0 {
		for _, match := range u.config.Match {
			args = append(args, "-m", match)
		}
	}

	// Add filter patterns
	if len(u.config.Filter) > 0 {
		for _, filter := range u.config.Filter {
			args = append(args, "-f", filter)
		}
	}

	// Add JSON output
	if u.config.OutputJSON {
		args = append(args, "-j")
	}

	// Add collect sources
	if u.config.CollectSources {
		args = append(args, "-cs")
	}

	// Add silent mode
	if u.config.Silent {
		args = append(args, "-silent")
	}

	// Add verbose mode
	if u.config.Verbose {
		args = append(args, "-v")
	}

	// Add no color
	if u.config.NoColor {
		args = append(args, "-nc")
	}

	// Add proxy
	if u.config.ProxyURL != "" {
		args = append(args, "-proxy", u.config.ProxyURL)
	}

	execResult, err := u.ExecuteCommand(ctx, args)
	if err != nil {
		return fmt.Errorf("failed to execute urlfinder: %w", err)
	}

	return u.parseOutput(execResult.Stdout, domain, results, shared)
}

func (u *URLFinderPlugin) parseOutput(output, domain string, results chan<- models.PluginResult, shared *core.SharedContext) error {
	scanner := bufio.NewScanner(strings.NewReader(output))
	
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line == "" {
			continue
		}

		var urlResult URLFinderResult
		
		// Try to parse as JSON if configured
		if u.config.OutputJSON {
			if err := json.Unmarshal([]byte(line), &urlResult); err != nil {
				// Fall back to text parsing
				urlResult = u.parseTextLine(line, domain)
			}
		} else {
			urlResult = u.parseTextLine(line, domain)
		}

		if urlResult.URL == "" {
			continue
		}

		result := u.createPluginResult(urlResult, domain)
		
		select {
		case results <- result:
		case <-ctx.Done():
			return ctx.Err()
		}

		// Share URL discoveries
		u.shareURLDiscovery(shared, urlResult)
	}

	return scanner.Err()
}

func (u *URLFinderPlugin) parseTextLine(line, domain string) URLFinderResult {
	result := URLFinderResult{
		Timestamp:  time.Now(),
		Domain:     domain,
		Parameters: []string{},
		Extensions: []string{},
		Technology: []string{},
	}

	// Basic URL validation
	if !strings.HasPrefix(line, "http://") && !strings.HasPrefix(line, "https://") {
		return result
	}

	result.URL = line

	// Parse URL components
	if parsedURL, err := url.Parse(line); err == nil {
		result.Domain = parsedURL.Host
		result.Path = parsedURL.Path

		// Extract parameters
		if parsedURL.RawQuery != "" {
			params := strings.Split(parsedURL.RawQuery, "&")
			for _, param := range params {
				if paramName := strings.Split(param, "=")[0]; paramName != "" {
					result.Parameters = append(result.Parameters, paramName)
				}
			}
		}

		// Extract file extensions
		if result.Path != "" {
			pathParts := strings.Split(result.Path, "/")
			for _, part := range pathParts {
				if strings.Contains(part, ".") {
					ext := strings.ToLower(strings.Split(part, ".")[len(strings.Split(part, "."))-1])
					if ext != "" && len(ext) <= 10 { // Reasonable extension length
						result.Extensions = append(result.Extensions, ext)
					}
				}
			}
		}
	}

	return result
}

func (u *URLFinderPlugin) createPluginResult(result URLFinderResult, domain string) models.PluginResult {
	severity := u.calculateSeverity(result)
	
	data := map[string]interface{}{
		"url":            result.URL,
		"source":         result.Source,
		"domain":         result.Domain,
		"path":           result.Path,
		"parameters":     result.Parameters,
		"extensions":     result.Extensions,
		"status_code":    result.StatusCode,
		"content_length": result.ContentLength,
		"technology":     result.Technology,
	}

	title := fmt.Sprintf("URL Discovery: %s", result.URL)
	description := fmt.Sprintf("Found URL: %s", result.URL)
	
	if result.Source != "" {
		description += fmt.Sprintf(" (source: %s)", result.Source)
	}
	
	if len(result.Parameters) > 0 {
		description += fmt.Sprintf(" with parameters: %s", strings.Join(result.Parameters, ", "))
	}

	return models.PluginResult{
		Plugin:      u.GetName(),
		Target:      domain,
		Type:        "url_discovery",
		Severity:    severity,
		Title:       title,
		Description: description,
		Data:        data,
		Timestamp:   time.Now(),
		Confidence:  u.calculateConfidence(result),
		Risk:        u.calculateRisk(result),
	}
}

func (u *URLFinderPlugin) calculateSeverity(result URLFinderResult) models.Severity {
	// Check for sensitive parameters
	sensitiveParams := []string{"api", "key", "token", "password", "pass", "secret", "admin", "debug", "test"}
	for _, param := range result.Parameters {
		paramLower := strings.ToLower(param)
		for _, sensitive := range sensitiveParams {
			if strings.Contains(paramLower, sensitive) {
				return models.SeverityHigh
			}
		}
	}

	// Check for interesting extensions
	interestingExts := []string{"php", "asp", "aspx", "jsp", "sql", "bak", "old", "tmp", "log", "config", "xml", "json"}
	for _, ext := range result.Extensions {
		for _, interesting := range interestingExts {
			if ext == interesting {
				return models.SeverityMedium
			}
		}
	}

	// Check for admin/dev paths
	pathLower := strings.ToLower(result.Path)
	if strings.Contains(pathLower, "admin") || strings.Contains(pathLower, "dev") || 
	   strings.Contains(pathLower, "test") || strings.Contains(pathLower, "debug") {
		return models.SeverityMedium
	}

	// Check for parameters (might indicate dynamic content)
	if len(result.Parameters) > 0 {
		return models.SeverityLow
	}

	return models.SeverityInfo
}

func (u *URLFinderPlugin) calculateConfidence(result URLFinderResult) float64 {
	confidence := 0.8 // Base confidence for URL discovery

	// Higher confidence with source information
	if result.Source != "" {
		confidence += 0.1
	}

	// Higher confidence with parameters
	if len(result.Parameters) > 0 {
		confidence += 0.1
	}

	// Cap at 1.0
	if confidence > 1.0 {
		confidence = 1.0
	}

	return confidence
}

func (u *URLFinderPlugin) calculateRisk(result URLFinderResult) float64 {
	risk := 0.2 // Base risk

	// Higher risk for sensitive parameters
	sensitiveParams := []string{"api", "key", "token", "password", "pass", "secret", "admin"}
	for _, param := range result.Parameters {
		paramLower := strings.ToLower(param)
		for _, sensitive := range sensitiveParams {
			if strings.Contains(paramLower, sensitive) {
				risk += 0.4
				break
			}
		}
	}

	// Higher risk for sensitive extensions
	sensitiveExts := []string{"sql", "bak", "old", "config", "log"}
	for _, ext := range result.Extensions {
		for _, sensitive := range sensitiveExts {
			if ext == sensitive {
				risk += 0.3
				break
			}
		}
	}

	// Higher risk for admin paths
	pathLower := strings.ToLower(result.Path)
	if strings.Contains(pathLower, "admin") || strings.Contains(pathLower, "debug") {
		risk += 0.2
	}

	// Cap at 1.0
	if risk > 1.0 {
		risk = 1.0
	}

	return risk
}

func (u *URLFinderPlugin) shareURLDiscovery(shared *core.SharedContext, result URLFinderResult) {
	discoveryData := map[string]interface{}{
		"url":        result.URL,
		"source":     result.Source,
		"domain":     result.Domain,
		"path":       result.Path,
		"parameters": result.Parameters,
		"extensions": result.Extensions,
		"technology": result.Technology,
	}

	discovery := &models.Discovery{
		Type:       "url",
		Value:      result.URL,
		Source:     u.GetName(),
		Confidence: u.calculateConfidence(result),
		Timestamp:  time.Now(),
		Data:       discoveryData,
	}

	shared.AddDiscovery(discovery)

	// Also add endpoint discovery if path exists
	if result.Path != "" && result.Path != "/" {
		endpointDiscovery := &models.Discovery{
			Type:       "endpoint",
			Value:      result.Path,
			Source:     u.GetName(),
			Confidence: u.calculateConfidence(result),
			Timestamp:  time.Now(),
			Data:       discoveryData,
		}
		shared.AddDiscovery(endpointDiscovery)
	}

	// Add parameter discoveries
	for _, param := range result.Parameters {
		paramDiscovery := &models.Discovery{
			Type:       "parameter",
			Value:      param,
			Source:     u.GetName(),
			Confidence: 0.8,
			Timestamp:  time.Now(),
			Data:       discoveryData,
		}
		shared.AddDiscovery(paramDiscovery)
	}
}

func (u *URLFinderPlugin) GetIntelligencePatterns() []models.IntelligencePattern {
	return []models.IntelligencePattern{
		{
			Name:        "Sensitive Parameter Detection",
			Pattern:     `"parameters":\[.*"(api|key|token|password|pass|secret)".*\]`,
			Confidence:  0.9,
			Description: "Sensitive parameter detected in URL",
			Tags:        []string{"parameter", "sensitive", "credentials"},
		},
		{
			Name:        "Admin Path Detection",
			Pattern:     `"path":".*/(admin|administrator|manage|dashboard)"`,
			Confidence:  0.85,
			Description: "Administrative path detected",
			Tags:        []string{"admin", "path", "access"},
		},
		{
			Name:        "Backup File Detection",
			Pattern:     `"extensions":\[.*"(bak|old|tmp|backup)".*\]`,
			Confidence:  0.8,
			Description: "Backup file extension detected",
			Tags:        []string{"backup", "file", "exposure"},
		},
		{
			Name:        "Config File Detection",
			Pattern:     `"extensions":\[.*"(config|cfg|ini|xml|json)".*\]`,
			Confidence:  0.75,
			Description: "Configuration file detected",
			Tags:        []string{"config", "file", "information"},
		},
		{
			Name:        "Development Path Detection",
			Pattern:     `"path":".*/(dev|test|debug|staging)"`,
			Confidence:  0.7,
			Description: "Development or testing path detected",
			Tags:        []string{"development", "test", "staging"},
		},
		{
			Name:        "API Endpoint Detection",
			Pattern:     `"path":".*/(api|rest|graphql|v[0-9]+)"`,
			Confidence:  0.8,
			Description: "API endpoint detected",
			Tags:        []string{"api", "endpoint", "service"},
		},
	}
}
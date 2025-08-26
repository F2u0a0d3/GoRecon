package param

import (
	"context"
	"fmt"
	"net/url"
	"regexp"
	"strings"
	"time"

	"github.com/f2u0a0d3/GoRecon/pkg/core"
	"github.com/f2u0a0d3/GoRecon/pkg/models"
	"github.com/f2u0a0d3/GoRecon/pkg/plugins/base"
	"github.com/rs/zerolog/log"
)

type ParamDiscoveryPlugin struct {
	*base.BaseAdapter
}

type ParamResult struct {
	URL        string            `json:"url"`
	Parameters []Parameter       `json:"parameters"`
	Methods    []string          `json:"methods"`
	Headers    map[string]string `json:"headers"`
	Source     string            `json:"source"`
}

type Parameter struct {
	Name        string  `json:"name"`
	Type        string  `json:"type"` // query, form, json, header
	Value       string  `json:"value"`
	Source      string  `json:"source"`
	Confidence  float64 `json:"confidence"`
	Description string  `json:"description"`
	Sensitive   bool    `json:"sensitive"`
}

func NewParamDiscoveryPlugin() core.Plugin {
	return &ParamDiscoveryPlugin{
		BaseAdapter: base.NewBaseAdapter(base.PluginConfig{
			ID:          "param_discovery",
			Name:        "Parameter Discovery",
			Description: "Discover hidden parameters and endpoints through various techniques",
			Version:     "1.0.0",
			Author:      "GoRecon Team",
			Category:    "parameter-discovery",
		}),
	}
}

func (p *ParamDiscoveryPlugin) Execute(ctx context.Context, target models.Target, sharedCtx *core.SharedContext) (*models.PluginResult, error) {
	log.Info().
		Str("plugin", p.ID()).
		Str("target", target.String()).
		Msg("Starting parameter discovery")

	var allResults []ParamResult
	var allFindings []models.Finding

	// 1. Extract parameters from URLs found by other tools
	urlParams := p.extractParametersFromUrls(sharedCtx, target)
	allResults = append(allResults, urlParams...)

	// 2. Analyze JavaScript files for parameters
	jsParams := p.extractParametersFromJS(ctx, sharedCtx, target)
	allResults = append(allResults, jsParams...)

	// 3. Discover parameters through wordlist fuzzing
	fuzzedParams := p.discoverParametersByFuzzing(ctx, target)
	allResults = append(allResults, fuzzedParams...)

	// 4. Analyze forms and API schemas
	formParams := p.extractParametersFromForms(ctx, target)
	allResults = append(allResults, formParams...)

	// 5. Check for common parameter patterns
	commonParams := p.checkCommonParameters(ctx, target)
	allResults = append(allResults, commonParams...)

	// Convert results to findings
	for _, result := range allResults {
		findings := p.convertToFindings(result, target)
		allFindings = append(allFindings, findings...)
	}

	if len(allFindings) == 0 {
		return p.CreateResult(target, "No parameters discovered", "info", 0.5, map[string]interface{}{
			"techniques_used": []string{"url_analysis", "js_analysis", "fuzzing", "form_analysis"},
			"tool":           "param_discovery",
		}), nil
	}

	// Create summary result
	totalParams := p.countParameters(allResults)
	sensitiveParams := p.countSensitiveParameters(allResults)
	
	primaryResult := p.CreateResult(
		target,
		fmt.Sprintf("Discovered %d parameters (%d potentially sensitive)", totalParams, sensitiveParams),
		p.determineSeverity(allResults),
		p.calculateConfidence(allResults),
		map[string]interface{}{
			"total_parameters":     totalParams,
			"sensitive_parameters": sensitiveParams,
			"discovery_sources":    p.getDiscoverySources(allResults),
			"results":             allResults,
			"tool":                "param_discovery",
		},
	)

	// Add findings to shared context
	for _, finding := range allFindings {
		sharedCtx.AddFinding(finding)
	}

	return primaryResult, nil
}

func (p *ParamDiscoveryPlugin) extractParametersFromUrls(sharedCtx *core.SharedContext, target models.Target) []ParamResult {
	var results []ParamResult
	processedUrls := make(map[string]bool)

	findings := sharedCtx.GetFindings()
	for _, finding := range findings {
		// Look for URLs with parameters from other plugins
		if finding.Category == "url-discovery" || finding.Plugin == "gau" {
			urlStr := finding.Finding
			if processedUrls[urlStr] {
				continue
			}
			processedUrls[urlStr] = true

			params := p.parseUrlParameters(urlStr)
			if len(params) > 0 {
				result := ParamResult{
					URL:        urlStr,
					Parameters: params,
					Source:     finding.Plugin,
				}
				results = append(results, result)
			}
		}
	}

	return results
}

func (p *ParamDiscoveryPlugin) extractParametersFromJS(ctx context.Context, sharedCtx *core.SharedContext, target models.Target) []ParamResult {
	var results []ParamResult

	findings := sharedCtx.GetFindings()
	for _, finding := range findings {
		select {
		case <-ctx.Done():
			return results
		default:
		}

		// Look for JavaScript analysis results
		if finding.Plugin == "jsluice" || finding.Category == "js-analysis" {
			params := p.extractParamsFromJSFinding(finding)
			if len(params) > 0 {
				result := ParamResult{
					URL:        finding.Target.String(),
					Parameters: params,
					Source:     "javascript",
				}
				results = append(results, result)
			}
		}
	}

	return results
}

func (p *ParamDiscoveryPlugin) discoverParametersByFuzzing(ctx context.Context, target models.Target) []ParamResult {
	var results []ParamResult

	// Common parameter names to test
	commonParams := []string{
		"id", "user", "admin", "debug", "test", "key", "token", "api_key",
		"callback", "redirect", "url", "path", "file", "page", "action",
		"method", "format", "type", "category", "search", "query", "q",
		"limit", "offset", "start", "end", "count", "size", "max",
		"filter", "sort", "order", "by", "direction", "asc", "desc",
	}

	baseUrl := target.String()
	var discoveredParams []Parameter

	for _, paramName := range commonParams {
		select {
		case <-ctx.Done():
			return results
		default:
		}

		// Test parameter existence
		if p.testParameter(ctx, baseUrl, paramName) {
			param := Parameter{
				Name:       paramName,
				Type:       "query",
				Source:     "fuzzing",
				Confidence: 0.7,
				Sensitive:  p.isSensitiveParameter(paramName),
			}
			discoveredParams = append(discoveredParams, param)
		}
	}

	if len(discoveredParams) > 0 {
		result := ParamResult{
			URL:        baseUrl,
			Parameters: discoveredParams,
			Source:     "fuzzing",
		}
		results = append(results, result)
	}

	return results
}

func (p *ParamDiscoveryPlugin) extractParametersFromForms(ctx context.Context, target models.Target) []ParamResult {
	var results []ParamResult

	// Download and analyze HTML content
	content, err := p.downloadFile(ctx, target.String())
	if err != nil {
		return results
	}

	forms := p.extractForms(content)
	for _, form := range forms {
		if len(form.Parameters) > 0 {
			results = append(results, form)
		}
	}

	return results
}

func (p *ParamDiscoveryPlugin) checkCommonParameters(ctx context.Context, target models.Target) []ParamResult {
	var results []ParamResult

	// Check for common API parameter patterns
	commonEndpoints := []string{
		"/api/v1/users?id=1",
		"/search?q=test",
		"/admin?debug=true",
		"/callback?url=example.com",
		"/?redirect=http://example.com",
	}

	baseUrl := strings.TrimSuffix(target.String(), "/")
	var discoveredParams []Parameter

	for _, endpoint := range commonEndpoints {
		select {
		case <-ctx.Done():
			return results
		default:
		}

		fullUrl := baseUrl + endpoint
		if p.testUrl(ctx, fullUrl) {
			params := p.parseUrlParameters(fullUrl)
			discoveredParams = append(discoveredParams, params...)
		}
	}

	if len(discoveredParams) > 0 {
		result := ParamResult{
			URL:        target.String(),
			Parameters: discoveredParams,
			Source:     "common_patterns",
		}
		results = append(results, result)
	}

	return results
}

func (p *ParamDiscoveryPlugin) parseUrlParameters(urlStr string) []Parameter {
	var params []Parameter

	parsedUrl, err := url.Parse(urlStr)
	if err != nil {
		return params
	}

	query := parsedUrl.Query()
	for paramName, values := range query {
		for _, value := range values {
			param := Parameter{
				Name:       paramName,
				Type:       "query",
				Value:      value,
				Source:     "url",
				Confidence: 0.9,
				Sensitive:  p.isSensitiveParameter(paramName),
			}
			params = append(params, param)
		}
	}

	return params
}

func (p *ParamDiscoveryPlugin) extractParamsFromJSFinding(finding models.Finding) []Parameter {
	var params []Parameter

	// Look for parameter patterns in JavaScript findings
	patterns := []string{
		`(?i)(params?|arguments?)\[['"](\w+)['"]`,
		`(?i)\.(\w+)\s*=\s*['"]\$\{.*?\}['"]`,
		`(?i)fetch\([^)]*[?&](\w+)=`,
		`(?i)axios\.[^(]*\([^)]*[?&](\w+)=`,
	}

	content := finding.Finding + " " + finding.Description
	for _, pattern := range patterns {
		matches := p.findAllMatches(content, pattern)
		for _, match := range matches {
			if len(match) > 1 {
				param := Parameter{
					Name:       match[1],
					Type:       "javascript",
					Source:     "js_analysis",
					Confidence: 0.6,
					Sensitive:  p.isSensitiveParameter(match[1]),
				}
				params = append(params, param)
			}
		}
	}

	return params
}

func (p *ParamDiscoveryPlugin) extractForms(content string) []ParamResult {
	var results []ParamResult

	// Extract form elements and their inputs
	formPattern := `(?s)<form[^>]*>(.*?)</form>`
	inputPattern := `<input[^>]*name\s*=\s*['""]([^'""]+)['""][^>]*>`
	
	formMatches := p.findAllMatches(content, formPattern)
	for _, formMatch := range formMatches {
		if len(formMatch) > 1 {
			formContent := formMatch[1]
			inputMatches := p.findAllMatches(formContent, inputPattern)
			
			var params []Parameter
			for _, inputMatch := range inputMatches {
				if len(inputMatch) > 1 {
					paramName := inputMatch[1]
					param := Parameter{
						Name:       paramName,
						Type:       "form",
						Source:     "html_form",
						Confidence: 0.8,
						Sensitive:  p.isSensitiveParameter(paramName),
					}
					params = append(params, param)
				}
			}

			if len(params) > 0 {
				result := ParamResult{
					Parameters: params,
					Source:     "html_form",
				}
				results = append(results, result)
			}
		}
	}

	return results
}

func (p *ParamDiscoveryPlugin) convertToFindings(result ParamResult, target models.Target) []models.Finding {
	var findings []models.Finding

	sensitiveParams := make([]Parameter, 0)
	allParams := make([]string, 0)

	for _, param := range result.Parameters {
		allParams = append(allParams, param.Name)
		if param.Sensitive {
			sensitiveParams = append(sensitiveParams, param)
		}
	}

	// Create finding for all parameters
	if len(result.Parameters) > 0 {
		severity := "info"
		if len(sensitiveParams) > 0 {
			severity = "medium"
		}

		finding := models.Finding{
			ID:          p.generateFindingID(),
			Plugin:      p.ID(),
			Target:      target,
			Finding:     fmt.Sprintf("Discovered %d parameters", len(result.Parameters)),
			Description: fmt.Sprintf("Found parameters: %s (Source: %s)", strings.Join(allParams, ", "), result.Source),
			Severity:    severity,
			Confidence:  p.calculateResultConfidence(result),
			Timestamp:   time.Now(),
			Category:    "parameter-discovery",
			Metadata: map[string]interface{}{
				"parameter_count":     len(result.Parameters),
				"sensitive_count":     len(sensitiveParams),
				"parameters":          result.Parameters,
				"discovery_source":    result.Source,
				"url":                result.URL,
			},
		}

		findings = append(findings, finding)
	}

	// Create separate findings for sensitive parameters
	for _, param := range sensitiveParams {
		finding := models.Finding{
			ID:          p.generateFindingID(),
			Plugin:      p.ID(),
			Target:      target,
			Finding:     fmt.Sprintf("Sensitive parameter discovered: %s", param.Name),
			Description: fmt.Sprintf("Parameter '%s' may contain sensitive information (Type: %s, Source: %s)", param.Name, param.Type, param.Source),
			Severity:    p.getSensitiveParamSeverity(param.Name),
			Confidence:  param.Confidence,
			Timestamp:   time.Now(),
			Category:    "sensitive-parameter",
			Metadata: map[string]interface{}{
				"parameter_name": param.Name,
				"parameter_type": param.Type,
				"source":        param.Source,
				"value":         param.Value,
				"url":           result.URL,
			},
		}

		findings = append(findings, finding)
	}

	return findings
}

func (p *ParamDiscoveryPlugin) isSensitiveParameter(paramName string) bool {
	sensitiveKeywords := []string{
		"password", "passwd", "pwd", "pass",
		"token", "auth", "key", "secret", "api_key", "apikey",
		"admin", "root", "user", "username", "login",
		"session", "sess", "cookie", "jwt",
		"debug", "test", "dev", "development",
		"redirect", "url", "callback", "return_to",
		"file", "path", "dir", "directory",
		"sql", "query", "cmd", "command", "exec",
	}

	paramLower := strings.ToLower(paramName)
	for _, keyword := range sensitiveKeywords {
		if strings.Contains(paramLower, keyword) {
			return true
		}
	}

	return false
}

func (p *ParamDiscoveryPlugin) getSensitiveParamSeverity(paramName string) string {
	highRiskParams := []string{"password", "token", "key", "secret", "admin"}
	mediumRiskParams := []string{"debug", "redirect", "file", "sql", "cmd"}

	paramLower := strings.ToLower(paramName)
	
	for _, param := range highRiskParams {
		if strings.Contains(paramLower, param) {
			return "high"
		}
	}
	
	for _, param := range mediumRiskParams {
		if strings.Contains(paramLower, param) {
			return "medium"
		}
	}

	return "low"
}

func (p *ParamDiscoveryPlugin) determineSeverity(results []ParamResult) string {
	hasCritical := false
	hasHigh := false
	hasMedium := false

	for _, result := range results {
		for _, param := range result.Parameters {
			if param.Sensitive {
				severity := p.getSensitiveParamSeverity(param.Name)
				switch severity {
				case "critical":
					hasCritical = true
				case "high":
					hasHigh = true
				case "medium":
					hasMedium = true
				}
			}
		}
	}

	if hasCritical {
		return "critical"
	}
	if hasHigh {
		return "high"
	}
	if hasMedium {
		return "medium"
	}
	if p.countParameters(results) > 0 {
		return "low"
	}

	return "info"
}

func (p *ParamDiscoveryPlugin) calculateConfidence(results []ParamResult) float64 {
	if len(results) == 0 {
		return 0.5
	}

	totalConfidence := 0.0
	count := 0

	for _, result := range results {
		for _, param := range result.Parameters {
			totalConfidence += param.Confidence
			count++
		}
	}

	if count == 0 {
		return 0.5
	}

	return totalConfidence / float64(count)
}

func (p *ParamDiscoveryPlugin) calculateResultConfidence(result ParamResult) float64 {
	if len(result.Parameters) == 0 {
		return 0.5
	}

	total := 0.0
	for _, param := range result.Parameters {
		total += param.Confidence
	}

	return total / float64(len(result.Parameters))
}

func (p *ParamDiscoveryPlugin) countParameters(results []ParamResult) int {
	count := 0
	for _, result := range results {
		count += len(result.Parameters)
	}
	return count
}

func (p *ParamDiscoveryPlugin) countSensitiveParameters(results []ParamResult) int {
	count := 0
	for _, result := range results {
		for _, param := range result.Parameters {
			if param.Sensitive {
				count++
			}
		}
	}
	return count
}

func (p *ParamDiscoveryPlugin) getDiscoverySources(results []ParamResult) []string {
	sources := make(map[string]bool)
	for _, result := range results {
		sources[result.Source] = true
	}

	var sourceList []string
	for source := range sources {
		sourceList = append(sourceList, source)
	}

	return sourceList
}

func (p *ParamDiscoveryPlugin) testParameter(ctx context.Context, baseUrl, paramName string) bool {
	// Simple parameter existence test
	testUrl := baseUrl + "?" + paramName + "=test"
	return p.testUrl(ctx, testUrl)
}

func (p *ParamDiscoveryPlugin) testUrl(ctx context.Context, url string) bool {
	// Mock implementation - in real code would make HTTP request
	// and analyze response for differences
	return true // Simplified for demo
}

func (p *ParamDiscoveryPlugin) findAllMatches(content, pattern string) [][]string {
	re := regexp.MustCompile(pattern)
	return re.FindAllStringSubmatch(content, -1)
}

func (p *ParamDiscoveryPlugin) downloadFile(ctx context.Context, url string) (string, error) {
	// Mock implementation - would use HTTP client in real code
	return "<html><body></body></html>", nil
}

// Intelligence patterns
func (p *ParamDiscoveryPlugin) GetIntelligencePatterns() []core.IntelligencePattern {
	return []core.IntelligencePattern{
		{
			ID:          "sensitive-parameter-exposure",
			Name:        "Sensitive Parameter Exposure",
			Description: "Parameters that may expose sensitive functionality or data",
			Indicators:  []string{"password", "token", "key", "admin", "debug"},
			Severity:    "high",
			Confidence:  0.8,
		},
		{
			ID:          "parameter-pollution",
			Name:        "Parameter Pollution Potential",
			Description: "Multiple parameters with similar names that could enable pollution attacks",
			Indicators:  []string{"parameter", "multiple", "similar"},
			Severity:    "medium",
			Confidence:  0.7,
		},
	}
}
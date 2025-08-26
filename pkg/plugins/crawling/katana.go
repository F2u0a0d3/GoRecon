package crawling

import (
	"bufio"
	"context"
	"encoding/json"
	"fmt"
	"net/url"
	"strconv"
	"strings"
	"time"

	"github.com/f2u0a0d3/GoRecon/pkg/plugins/base"
	"github.com/f2u0a0d3/GoRecon/pkg/core"
	"github.com/f2u0a0d3/GoRecon/pkg/models"
)

type KatanaPlugin struct {
	base.BaseAdapter
	config *KatanaConfig
}

type KatanaConfig struct {
	URLs               []string
	Depth              int
	JSCrawl            bool
	JSLuice            bool
	Crawl              string
	Strategy           string
	Scope              []string
	OutOfScope         []string
	FieldScope         string
	NoScope            bool
	DisplayField       string
	StoreField         string
	JsonFields         string
	BodyRead           bool
	BodySizeLimit      int
	Headers            []string
	Resolvers          []string
	Proxy              string
	Concurrency        int
	Parallelism        int
	Delay              int
	RateLimit          int
	Timeout            int
	RetryTimeout       int
	MaxRetry           int
	OutputFormat       string
	StoreResponse      bool
	OmitRaw            bool
	OmitBody           bool
	JSON               bool
}

type KatanaResult struct {
	Timestamp    string                 `json:"timestamp"`
	Request      KatanaRequest          `json:"request"`
	Response     KatanaResponse         `json:"response"`
	Error        string                 `json:"error,omitempty"`
}

type KatanaRequest struct {
	Method string            `json:"method"`
	URL    string            `json:"url"`
	Headers map[string]string `json:"headers,omitempty"`
	Body   string            `json:"body,omitempty"`
}

type KatanaResponse struct {
	StatusCode int               `json:"status_code"`
	Headers    map[string]string `json:"headers,omitempty"`
	Body       string            `json:"body,omitempty"`
	Length     int               `json:"length"`
	Words      int               `json:"words"`
	Lines      int               `json:"lines"`
}

func NewKatanaPlugin() *KatanaPlugin {
	return &KatanaPlugin{
		BaseAdapter: base.BaseAdapter{
			PluginName:        "katana",
			PluginVersion:     "1.0.0",
			PluginDescription: "Next-generation crawling and spidering framework by ProjectDiscovery",
			PluginAuthor:     "GoRecon Team",
			SupportedTargets: []string{"domain", "url"},
		},
		config: &KatanaConfig{
			URLs:              make([]string, 0),
			Depth:             3,
			JSCrawl:           true,
			JSLuice:           false,
			Crawl:             "endpoint",
			Strategy:          "depth-first",
			Scope:             make([]string, 0),
			OutOfScope:        make([]string, 0),
			FieldScope:        "rdn",
			NoScope:           false,
			DisplayField:      "url",
			StoreField:        "url",
			JsonFields:        "url,status_code,length,lines,words",
			BodyRead:          false,
			BodySizeLimit:     1048576, // 1MB
			Headers:           make([]string, 0),
			Resolvers:         make([]string, 0),
			Concurrency:       10,
			Parallelism:       10,
			Delay:             0,
			RateLimit:         150,
			Timeout:           10,
			RetryTimeout:      0,
			MaxRetry:          1,
			OutputFormat:      "json",
			StoreResponse:     false,
			OmitRaw:           false,
			OmitBody:          true,
			JSON:              true,
		},
	}
}

func (k *KatanaPlugin) SetConfig(configMap map[string]interface{}) error {
	if urls, ok := configMap["urls"].([]interface{}); ok {
		k.config.URLs = make([]string, len(urls))
		for i, u := range urls {
			if str, ok := u.(string); ok {
				k.config.URLs[i] = str
			}
		}
	}
	if depth, ok := configMap["depth"].(int); ok && depth > 0 && depth <= 10 {
		k.config.Depth = depth
	}
	if jsCrawl, ok := configMap["js_crawl"].(bool); ok {
		k.config.JSCrawl = jsCrawl
	}
	if jsLuice, ok := configMap["js_luice"].(bool); ok {
		k.config.JSLuice = jsLuice
	}
	if crawl, ok := configMap["crawl"].(string); ok {
		validCrawl := map[string]bool{"endpoint": true, "robots": true, "sitemap": true}
		if validCrawl[crawl] {
			k.config.Crawl = crawl
		}
	}
	if strategy, ok := configMap["strategy"].(string); ok {
		validStrategy := map[string]bool{"depth-first": true, "breadth-first": true}
		if validStrategy[strategy] {
			k.config.Strategy = strategy
		}
	}
	if scope, ok := configMap["scope"].([]interface{}); ok {
		k.config.Scope = make([]string, len(scope))
		for i, s := range scope {
			if str, ok := s.(string); ok {
				k.config.Scope[i] = str
			}
		}
	}
	if outOfScope, ok := configMap["out_of_scope"].([]interface{}); ok {
		k.config.OutOfScope = make([]string, len(outOfScope))
		for i, s := range outOfScope {
			if str, ok := s.(string); ok {
				k.config.OutOfScope[i] = str
			}
		}
	}
	if fieldScope, ok := configMap["field_scope"].(string); ok {
		validFieldScope := map[string]bool{"rdn": true, "fqdn": true, "dn": true}
		if validFieldScope[fieldScope] {
			k.config.FieldScope = fieldScope
		}
	}
	if noScope, ok := configMap["no_scope"].(bool); ok {
		k.config.NoScope = noScope
	}
	if bodyRead, ok := configMap["body_read"].(bool); ok {
		k.config.BodyRead = bodyRead
	}
	if bodySizeLimit, ok := configMap["body_size_limit"].(int); ok && bodySizeLimit > 0 {
		k.config.BodySizeLimit = bodySizeLimit
	}
	if headers, ok := configMap["headers"].([]interface{}); ok {
		k.config.Headers = make([]string, len(headers))
		for i, h := range headers {
			if str, ok := h.(string); ok {
				k.config.Headers[i] = str
			}
		}
	}
	if proxy, ok := configMap["proxy"].(string); ok {
		k.config.Proxy = proxy
	}
	if concurrency, ok := configMap["concurrency"].(int); ok && concurrency > 0 && concurrency <= 100 {
		k.config.Concurrency = concurrency
	}
	if parallelism, ok := configMap["parallelism"].(int); ok && parallelism > 0 && parallelism <= 100 {
		k.config.Parallelism = parallelism
	}
	if delay, ok := configMap["delay"].(int); ok && delay >= 0 && delay <= 10000 {
		k.config.Delay = delay
	}
	if rateLimit, ok := configMap["rate_limit"].(int); ok && rateLimit > 0 && rateLimit <= 1000 {
		k.config.RateLimit = rateLimit
	}
	if timeout, ok := configMap["timeout"].(int); ok && timeout > 0 && timeout <= 300 {
		k.config.Timeout = timeout
	}
	if maxRetry, ok := configMap["max_retry"].(int); ok && maxRetry >= 0 && maxRetry <= 10 {
		k.config.MaxRetry = maxRetry
	}
	if storeResponse, ok := configMap["store_response"].(bool); ok {
		k.config.StoreResponse = storeResponse
	}
	return nil
}

func (k *KatanaPlugin) Execute(ctx context.Context, target models.Target, sharedCtx *core.SharedContext) (*models.PluginResult, error) {
	targetStr := k.getTargetString(target)
	if targetStr == "" {
		return nil, fmt.Errorf("invalid target for katana")
	}

	args := k.buildKatanaArgs(targetStr)
	
	output, err := k.ExecuteCommand(ctx, "katana", args, time.Duration(k.config.Timeout+60)*time.Second)
	if err != nil {
		return nil, fmt.Errorf("katana execution failed: %w", err)
	}

	result, err := k.parseKatanaOutput(output, target)
	if err != nil {
		return nil, fmt.Errorf("failed to parse katana output: %w", err)
	}

	k.populateSharedContext(result, sharedCtx)

	return result, nil
}

func (k *KatanaPlugin) getTargetString(target models.Target) string {
	switch target.GetType() {
	case "domain":
		return "https://" + target.GetDomain()
	case "url":
		return target.GetURL()
	default:
		return ""
	}
}

func (k *KatanaPlugin) buildKatanaArgs(target string) []string {
	args := []string{
		"-u", target,
		"-d", strconv.Itoa(k.config.Depth),
		"-c", strconv.Itoa(k.config.Concurrency),
		"-p", strconv.Itoa(k.config.Parallelism),
		"-rl", strconv.Itoa(k.config.RateLimit),
		"-timeout", strconv.Itoa(k.config.Timeout),
		"-retry", strconv.Itoa(k.config.MaxRetry),
		"-crawl-scope", k.config.FieldScope,
		"-field", k.config.DisplayField,
		"-store-field", k.config.StoreField,
	}

	if k.config.JSON {
		args = append(args, "-json")
		args = append(args, "-jc", k.config.JsonFields)
	}

	if k.config.JSCrawl {
		args = append(args, "-jc")
	}

	if k.config.JSLuice {
		args = append(args, "-jsluice")
	}

	if k.config.NoScope {
		args = append(args, "-no-scope")
	}

	if k.config.BodyRead {
		args = append(args, "-body")
		args = append(args, "-body-sz-limit", strconv.Itoa(k.config.BodySizeLimit))
	}

	if k.config.StoreResponse {
		args = append(args, "-sr")
	}

	if k.config.OmitRaw {
		args = append(args, "-omit-raw")
	}

	if k.config.OmitBody {
		args = append(args, "-omit-body")
	}

	if k.config.Delay > 0 {
		args = append(args, "-delay", strconv.Itoa(k.config.Delay))
	}

	if k.config.Proxy != "" {
		args = append(args, "-proxy", k.config.Proxy)
	}

	for _, scope := range k.config.Scope {
		args = append(args, "-cs", scope)
	}

	for _, outOfScope := range k.config.OutOfScope {
		args = append(args, "-cos", outOfScope)
	}

	for _, header := range k.config.Headers {
		args = append(args, "-H", header)
	}

	for _, resolver := range k.config.Resolvers {
		args = append(args, "-r", resolver)
	}

	return args
}

func (k *KatanaPlugin) parseKatanaOutput(output string, target models.Target) (*models.PluginResult, error) {
	result := &models.PluginResult{
		PluginName: k.PluginName,
		Target:     target,
		Status:     models.StatusSuccess,
		Timestamp:  time.Now(),
		Results:    make(map[string]interface{}),
		RawOutput:  output,
	}

	if strings.TrimSpace(output) == "" {
		result.Status = models.StatusError
		result.Error = "empty katana output"
		return result, nil
	}

	urls := make([]string, 0)
	endpoints := make([]string, 0)
	jsFiles := make([]string, 0)
	forms := make([]string, 0)
	subdomains := make([]string, 0)
	
	statusCodes := make(map[int]int)
	extensions := make(map[string]int)
	methods := make(map[string]int)
	crawlStats := make(map[string]interface{})

	scanner := bufio.NewScanner(strings.NewReader(output))
	seenURLs := make(map[string]bool)
	totalRequests := 0
	errorCount := 0

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

		if k.config.JSON && strings.HasPrefix(line, "{") {
			var katanaResult KatanaResult
			if err := json.Unmarshal([]byte(line), &katanaResult); err != nil {
				continue
			}

			k.processKatanaResult(&katanaResult, &urls, &endpoints, &jsFiles, &forms, &subdomains, &statusCodes, &extensions, &methods, seenURLs, target)
			totalRequests++
			
			if katanaResult.Error != "" {
				errorCount++
			}
		} else {
			k.processPlainTextLine(line, &urls, &endpoints, &jsFiles, &forms, &subdomains, &extensions, seenURLs, target)
			totalRequests++
		}
	}

	crawlStats["total_requests"] = totalRequests
	crawlStats["error_count"] = errorCount
	crawlStats["success_rate"] = float64(totalRequests-errorCount) / float64(totalRequests) * 100.0

	statistics := k.calculateStatistics(urls, statusCodes, extensions, methods, crawlStats)
	riskAssessment := k.assessRisk(urls, endpoints, jsFiles, forms)

	result.Results["urls"] = urls
	result.Results["endpoints"] = endpoints
	result.Results["js_files"] = jsFiles
	result.Results["forms"] = forms
	result.Results["subdomains"] = k.uniqueStrings(subdomains)
	result.Results["statistics"] = statistics
	result.Results["risk_assessment"] = riskAssessment

	return result, nil
}

func (k *KatanaPlugin) processKatanaResult(katanaResult *KatanaResult, urls, endpoints, jsFiles, forms, subdomains *[]string, statusCodes *map[int]int, extensions *map[string]int, methods *map[string]int, seenURLs map[string]bool, target models.Target) {
	urlStr := katanaResult.Request.URL
	if seenURLs[urlStr] {
		return
	}
	seenURLs[urlStr] = true

	*urls = append(*urls, urlStr)

	if katanaResult.Response.StatusCode > 0 {
		(*statusCodes)[katanaResult.Response.StatusCode]++
	}

	if katanaResult.Request.Method != "" {
		(*methods)[katanaResult.Request.Method]++
	}

	parsedURL, err := url.Parse(urlStr)
	if err == nil {
		ext := k.getFileExtension(parsedURL.Path)
		if ext != "" {
			(*extensions)[ext]++
		}

		if k.isSubdomain(parsedURL.Host, target) {
			*subdomains = append(*subdomains, parsedURL.Host)
		}

		if strings.Contains(urlStr, ".js") {
			*jsFiles = append(*jsFiles, urlStr)
		}

		if strings.Contains(strings.ToLower(urlStr), "form") || strings.Contains(strings.ToLower(katanaResult.Response.Body), "<form") {
			*forms = append(*forms, urlStr)
		}

		if parsedURL.Path != "" && parsedURL.Path != "/" {
			*endpoints = append(*endpoints, parsedURL.Path)
		}
	}
}

func (k *KatanaPlugin) processPlainTextLine(line string, urls, endpoints, jsFiles, forms, subdomains *[]string, extensions *map[string]int, seenURLs map[string]bool, target models.Target) {
	if seenURLs[line] {
		return
	}
	seenURLs[line] = true

	*urls = append(*urls, line)

	parsedURL, err := url.Parse(line)
	if err == nil {
		ext := k.getFileExtension(parsedURL.Path)
		if ext != "" {
			(*extensions)[ext]++
		}

		if k.isSubdomain(parsedURL.Host, target) {
			*subdomains = append(*subdomains, parsedURL.Host)
		}

		if strings.Contains(line, ".js") {
			*jsFiles = append(*jsFiles, line)
		}

		if strings.Contains(strings.ToLower(line), "form") {
			*forms = append(*forms, line)
		}

		if parsedURL.Path != "" && parsedURL.Path != "/" {
			*endpoints = append(*endpoints, parsedURL.Path)
		}
	}
}

func (k *KatanaPlugin) getFileExtension(path string) string {
	parts := strings.Split(path, ".")
	if len(parts) > 1 {
		ext := strings.ToLower(parts[len(parts)-1])
		if len(ext) <= 4 && ext != "" {
			return ext
		}
	}
	return ""
}

func (k *KatanaPlugin) isSubdomain(host string, target models.Target) bool {
	if target.GetType() == "domain" {
		domain := target.GetDomain()
		return strings.HasSuffix(host, "."+domain) || host == domain
	}
	return false
}

func (k *KatanaPlugin) uniqueStrings(slice []string) []string {
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

func (k *KatanaPlugin) calculateStatistics(urls []string, statusCodes map[int]int, extensions map[string]int, methods map[string]int, crawlStats map[string]interface{}) map[string]interface{} {
	stats := map[string]interface{}{
		"total_urls":          len(urls),
		"status_breakdown":    statusCodes,
		"extension_breakdown": extensions,
		"method_breakdown":    methods,
		"crawl_stats":         crawlStats,
	}

	successfulRequests := 0
	for statusCode, count := range statusCodes {
		if statusCode >= 200 && statusCode < 400 {
			successfulRequests += count
		}
	}

	stats["successful_requests"] = successfulRequests

	return stats
}

func (k *KatanaPlugin) assessRisk(urls, endpoints, jsFiles, forms []string) map[string]interface{} {
	riskScore := 0.0
	riskFactors := make([]string, 0)

	if len(jsFiles) > 30 {
		riskScore += 2.0
		riskFactors = append(riskFactors, "High number of JavaScript files")
	}

	if len(forms) > 5 {
		riskScore += 2.5
		riskFactors = append(riskFactors, "Multiple forms detected")
	}

	adminUrls := 0
	apiUrls := 0
	sensitiveUrls := 0

	for _, urlStr := range urls {
		urlLower := strings.ToLower(urlStr)
		if strings.Contains(urlLower, "admin") || strings.Contains(urlLower, "manage") || strings.Contains(urlLower, "dashboard") {
			adminUrls++
		}
		if strings.Contains(urlLower, "api") || strings.Contains(urlLower, "/v1/") || strings.Contains(urlLower, "/v2/") {
			apiUrls++
		}
		if strings.Contains(urlLower, "config") || strings.Contains(urlLower, "backup") || strings.Contains(urlLower, "debug") {
			sensitiveUrls++
		}
	}

	if adminUrls > 0 {
		riskScore += 3.0
		riskFactors = append(riskFactors, "Administrative interfaces detected")
	}

	if apiUrls > 15 {
		riskScore += 2.0
		riskFactors = append(riskFactors, "Multiple API endpoints detected")
	}

	if sensitiveUrls > 0 {
		riskScore += 2.5
		riskFactors = append(riskFactors, "Sensitive endpoints detected")
	}

	if len(endpoints) > 200 {
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
		"risk_score":      normalizedScore,
		"risk_level":      riskLevel,
		"risk_factors":    riskFactors,
		"admin_urls":      adminUrls,
		"api_urls":        apiUrls,
		"sensitive_urls":  sensitiveUrls,
	}
}

func (k *KatanaPlugin) populateSharedContext(result *models.PluginResult, sharedCtx *core.SharedContext) {
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

	if jsFiles, ok := result.Results["js_files"].([]string); ok && len(jsFiles) > 0 {
		sharedCtx.AddTechnology("JavaScript")
	}

	if forms, ok := result.Results["forms"].([]string); ok && len(forms) > 0 {
		sharedCtx.AddTechnology("HTML Forms")
	}

	if riskAssessment, ok := result.Results["risk_assessment"].(map[string]interface{}); ok {
		if riskScore, ok := riskAssessment["risk_score"].(float64); ok && riskScore > 6.0 {
			sharedCtx.AddVulnerability("High-risk web application detected via advanced crawling")
		}
	}
}

func (k *KatanaPlugin) Cleanup() error {
	return nil
}

func (k *KatanaPlugin) ValidateConfig() error {
	if k.config.Depth < 1 || k.config.Depth > 10 {
		return fmt.Errorf("depth must be between 1 and 10")
	}
	if k.config.Concurrency < 1 || k.config.Concurrency > 100 {
		return fmt.Errorf("concurrency must be between 1 and 100")
	}
	if k.config.Parallelism < 1 || k.config.Parallelism > 100 {
		return fmt.Errorf("parallelism must be between 1 and 100")
	}
	if k.config.Timeout < 1 || k.config.Timeout > 300 {
		return fmt.Errorf("timeout must be between 1 and 300 seconds")
	}
	if k.config.RateLimit < 1 || k.config.RateLimit > 1000 {
		return fmt.Errorf("rate_limit must be between 1 and 1000")
	}
	if k.config.Delay < 0 || k.config.Delay > 10000 {
		return fmt.Errorf("delay must be between 0 and 10000 milliseconds")
	}
	if k.config.MaxRetry < 0 || k.config.MaxRetry > 10 {
		return fmt.Errorf("max_retry must be between 0 and 10")
	}
	return nil
}
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

type GospiderPlugin struct {
	base.BaseAdapter
	config *GospiderConfig
}

type GospiderConfig struct {
	Sites          []string
	Cookie         string
	Header         map[string]string
	UserAgent      string
	Proxy          string
	Timeout        int
	Concurrent     int
	Depth          int
	Delay          int
	Random         bool
	Length         int
	Include        []string
	Exclude        []string
	OutputFormat   string
	Quiet          bool
	JSON           bool
}

type GospiderResult struct {
	Input       string `json:"input"`
	Source      string `json:"source"`
	OutputType  string `json:"output"`
	Output      string `json:"output_path"`
	StatusCode  int    `json:"status_code,omitempty"`
	Length      int    `json:"length,omitempty"`
	Words       int    `json:"words,omitempty"`
	Lines       int    `json:"lines,omitempty"`
}

func NewGospiderPlugin() *GospiderPlugin {
	return &GospiderPlugin{
		BaseAdapter: base.BaseAdapter{
			PluginName:        "gospider",
			PluginVersion:     "1.0.0",
			PluginDescription: "Fast web spider for comprehensive website crawling",
			PluginAuthor:     "GoRecon Team",
			SupportedTargets: []string{"domain", "url"},
		},
		config: &GospiderConfig{
			Sites:        make([]string, 0),
			Header:       make(map[string]string),
			UserAgent:    "GoRecon-Gospider/1.0",
			Timeout:      10,
			Concurrent:   20,
			Depth:        3,
			Delay:        0,
			Random:       false,
			Length:       0,
			Include:      make([]string, 0),
			Exclude:      make([]string, 0),
			OutputFormat: "json",
			Quiet:        false,
			JSON:         true,
		},
	}
}

func (g *GospiderPlugin) SetConfig(configMap map[string]interface{}) error {
	if sites, ok := configMap["sites"].([]interface{}); ok {
		g.config.Sites = make([]string, len(sites))
		for i, site := range sites {
			if str, ok := site.(string); ok {
				g.config.Sites[i] = str
			}
		}
	}
	if cookie, ok := configMap["cookie"].(string); ok {
		g.config.Cookie = cookie
	}
	if headers, ok := configMap["headers"].(map[string]interface{}); ok {
		g.config.Header = make(map[string]string)
		for key, value := range headers {
			if strValue, ok := value.(string); ok {
				g.config.Header[key] = strValue
			}
		}
	}
	if userAgent, ok := configMap["user_agent"].(string); ok && userAgent != "" {
		g.config.UserAgent = userAgent
	}
	if proxy, ok := configMap["proxy"].(string); ok {
		g.config.Proxy = proxy
	}
	if timeout, ok := configMap["timeout"].(int); ok && timeout > 0 && timeout <= 300 {
		g.config.Timeout = timeout
	}
	if concurrent, ok := configMap["concurrent"].(int); ok && concurrent > 0 && concurrent <= 100 {
		g.config.Concurrent = concurrent
	}
	if depth, ok := configMap["depth"].(int); ok && depth > 0 && depth <= 10 {
		g.config.Depth = depth
	}
	if delay, ok := configMap["delay"].(int); ok && delay >= 0 && delay <= 10000 {
		g.config.Delay = delay
	}
	if random, ok := configMap["random"].(bool); ok {
		g.config.Random = random
	}
	if length, ok := configMap["length"].(int); ok && length >= 0 {
		g.config.Length = length
	}
	if include, ok := configMap["include"].([]interface{}); ok {
		g.config.Include = make([]string, len(include))
		for i, inc := range include {
			if str, ok := inc.(string); ok {
				g.config.Include[i] = str
			}
		}
	}
	if exclude, ok := configMap["exclude"].([]interface{}); ok {
		g.config.Exclude = make([]string, len(exclude))
		for i, exc := range exclude {
			if str, ok := exc.(string); ok {
				g.config.Exclude[i] = str
			}
		}
	}
	if outputFormat, ok := configMap["output_format"].(string); ok {
		validFormats := map[string]bool{"json": true, "txt": true}
		if validFormats[outputFormat] {
			g.config.OutputFormat = outputFormat
		}
	}
	if quiet, ok := configMap["quiet"].(bool); ok {
		g.config.Quiet = quiet
	}
	return nil
}

func (g *GospiderPlugin) Execute(ctx context.Context, target models.Target, sharedCtx *core.SharedContext) (*models.PluginResult, error) {
	targetStr := g.getTargetString(target)
	if targetStr == "" {
		return nil, fmt.Errorf("invalid target for gospider")
	}

	args := g.buildGospiderArgs(targetStr)
	
	output, err := g.ExecuteCommand(ctx, "gospider", args, time.Duration(g.config.Timeout+60)*time.Second)
	if err != nil {
		return nil, fmt.Errorf("gospider execution failed: %w", err)
	}

	result, err := g.parseGospiderOutput(output, target)
	if err != nil {
		return nil, fmt.Errorf("failed to parse gospider output: %w", err)
	}

	g.populateSharedContext(result, sharedCtx)

	return result, nil
}

func (g *GospiderPlugin) getTargetString(target models.Target) string {
	switch target.GetType() {
	case "domain":
		return "https://" + target.GetDomain()
	case "url":
		return target.GetURL()
	default:
		return ""
	}
}

func (g *GospiderPlugin) buildGospiderArgs(target string) []string {
	args := []string{
		"-s", target,
		"-c", strconv.Itoa(g.config.Concurrent),
		"-d", strconv.Itoa(g.config.Depth),
		"-t", strconv.Itoa(g.config.Timeout),
	}

	if g.config.JSON {
		args = append(args, "--json")
	}

	if g.config.Quiet {
		args = append(args, "-q")
	}

	if g.config.Cookie != "" {
		args = append(args, "--cookie", g.config.Cookie)
	}

	if g.config.UserAgent != "" {
		args = append(args, "-u", g.config.UserAgent)
	}

	if g.config.Proxy != "" {
		args = append(args, "--proxy", g.config.Proxy)
	}

	if g.config.Delay > 0 {
		args = append(args, "--delay", strconv.Itoa(g.config.Delay))
	}

	if g.config.Random {
		args = append(args, "--random-delay")
	}

	if g.config.Length > 0 {
		args = append(args, "-l", strconv.Itoa(g.config.Length))
	}

	for key, value := range g.config.Header {
		args = append(args, "-H", fmt.Sprintf("%s: %s", key, value))
	}

	for _, include := range g.config.Include {
		args = append(args, "--include", include)
	}

	for _, exclude := range g.config.Exclude {
		args = append(args, "--exclude", exclude)
	}

	return args
}

func (g *GospiderPlugin) parseGospiderOutput(output string, target models.Target) (*models.PluginResult, error) {
	result := &models.PluginResult{
		PluginName: g.PluginName,
		Target:     target,
		Status:     models.StatusSuccess,
		Timestamp:  time.Now(),
		Results:    make(map[string]interface{}),
		RawOutput:  output,
	}

	if strings.TrimSpace(output) == "" {
		result.Status = models.StatusError
		result.Error = "empty gospider output"
		return result, nil
	}

	urls := make([]string, 0)
	forms := make([]string, 0)
	linkfinderResults := make([]string, 0)
	subdomains := make([]string, 0)
	jsFiles := make([]string, 0)
	
	crawlStats := make(map[string]int)
	statusCodes := make(map[int]int)
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

		if g.config.JSON && strings.HasPrefix(line, "{") {
			var gospiderResult GospiderResult
			if err := json.Unmarshal([]byte(line), &gospiderResult); err != nil {
				continue
			}

			g.processGospiderResult(&gospiderResult, &urls, &forms, &linkfinderResults, &subdomains, &jsFiles, &statusCodes, &extensions, &crawlStats, seenURLs, target)
		} else {
			g.processPlainTextLine(line, &urls, &forms, &linkfinderResults, &subdomains, &jsFiles, &statusCodes, &extensions, &crawlStats, seenURLs, target)
		}
	}

	statistics := g.calculateStatistics(urls, crawlStats, statusCodes, extensions)
	riskAssessment := g.assessRisk(urls, forms, jsFiles, linkfinderResults)

	result.Results["urls"] = urls
	result.Results["forms"] = forms
	result.Results["linkfinder_results"] = linkfinderResults
	result.Results["subdomains"] = g.uniqueStrings(subdomains)
	result.Results["js_files"] = jsFiles
	result.Results["statistics"] = statistics
	result.Results["risk_assessment"] = riskAssessment

	return result, nil
}

func (g *GospiderPlugin) processGospiderResult(gospiderResult *GospiderResult, urls, forms, linkfinderResults, subdomains, jsFiles *[]string, statusCodes *map[int]int, extensions *map[string]int, crawlStats *map[string]int, seenURLs map[string]bool, target models.Target) {
	if seenURLs[gospiderResult.Output] {
		return
	}
	seenURLs[gospiderResult.Output] = true

	*urls = append(*urls, gospiderResult.Output)

	if gospiderResult.StatusCode > 0 {
		(*statusCodes)[gospiderResult.StatusCode]++
	}

	(*crawlStats)[gospiderResult.OutputType]++

	parsedURL, err := url.Parse(gospiderResult.Output)
	if err == nil {
		ext := g.getFileExtension(parsedURL.Path)
		if ext != "" {
			(*extensions)[ext]++
		}

		if g.isSubdomain(parsedURL.Host, target) {
			*subdomains = append(*subdomains, parsedURL.Host)
		}

		if strings.Contains(gospiderResult.Output, ".js") {
			*jsFiles = append(*jsFiles, gospiderResult.Output)
		}

		if strings.Contains(strings.ToLower(gospiderResult.Output), "form") {
			*forms = append(*forms, gospiderResult.Output)
		}

		if gospiderResult.OutputType == "linkfinder" {
			*linkfinderResults = append(*linkfinderResults, gospiderResult.Output)
		}
	}
}

func (g *GospiderPlugin) processPlainTextLine(line string, urls, forms, linkfinderResults, subdomains, jsFiles *[]string, statusCodes *map[int]int, extensions *map[string]int, crawlStats *map[string]int, seenURLs map[string]bool, target models.Target) {
	if seenURLs[line] {
		return
	}
	seenURLs[line] = true

	*urls = append(*urls, line)

	parsedURL, err := url.Parse(line)
	if err == nil {
		ext := g.getFileExtension(parsedURL.Path)
		if ext != "" {
			(*extensions)[ext]++
		}

		if g.isSubdomain(parsedURL.Host, target) {
			*subdomains = append(*subdomains, parsedURL.Host)
		}

		if strings.Contains(line, ".js") {
			*jsFiles = append(*jsFiles, line)
		}

		if strings.Contains(strings.ToLower(line), "form") {
			*forms = append(*forms, line)
		}
	}

	(*crawlStats)["url"]++
}

func (g *GospiderPlugin) getFileExtension(path string) string {
	parts := strings.Split(path, ".")
	if len(parts) > 1 {
		ext := strings.ToLower(parts[len(parts)-1])
		if len(ext) <= 4 && ext != "" {
			return ext
		}
	}
	return ""
}

func (g *GospiderPlugin) isSubdomain(host string, target models.Target) bool {
	if target.GetType() == "domain" {
		domain := target.GetDomain()
		return strings.HasSuffix(host, "."+domain) || host == domain
	}
	return false
}

func (g *GospiderPlugin) uniqueStrings(slice []string) []string {
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

func (g *GospiderPlugin) calculateStatistics(urls []string, crawlStats map[string]int, statusCodes map[int]int, extensions map[string]int) map[string]interface{} {
	stats := map[string]interface{}{
		"total_urls":        len(urls),
		"crawl_breakdown":   crawlStats,
		"status_breakdown":  statusCodes,
		"extension_breakdown": extensions,
	}

	successfulRequests := 0
	for statusCode, count := range statusCodes {
		if statusCode >= 200 && statusCode < 300 {
			successfulRequests += count
		}
	}

	stats["successful_requests"] = successfulRequests
	if len(urls) > 0 {
		stats["success_rate"] = float64(successfulRequests) / float64(len(urls)) * 100.0
	}

	return stats
}

func (g *GospiderPlugin) assessRisk(urls, forms, jsFiles, linkfinderResults []string) map[string]interface{} {
	riskScore := 0.0
	riskFactors := make([]string, 0)

	if len(jsFiles) > 50 {
		riskScore += 2.0
		riskFactors = append(riskFactors, "High number of JavaScript files")
	}

	if len(forms) > 10 {
		riskScore += 2.5
		riskFactors = append(riskFactors, "Multiple forms detected")
	}

	if len(linkfinderResults) > 20 {
		riskScore += 1.5
		riskFactors = append(riskFactors, "High number of linkfinder results")
	}

	adminUrls := 0
	apiUrls := 0
	uploadUrls := 0

	for _, urlStr := range urls {
		urlLower := strings.ToLower(urlStr)
		if strings.Contains(urlLower, "admin") || strings.Contains(urlLower, "manage") {
			adminUrls++
		}
		if strings.Contains(urlLower, "api") || strings.Contains(urlLower, "/v1/") || strings.Contains(urlLower, "/v2/") {
			apiUrls++
		}
		if strings.Contains(urlLower, "upload") || strings.Contains(urlLower, "file") {
			uploadUrls++
		}
	}

	if adminUrls > 0 {
		riskScore += 3.0
		riskFactors = append(riskFactors, "Administrative URLs detected")
	}

	if apiUrls > 20 {
		riskScore += 2.0
		riskFactors = append(riskFactors, "Multiple API endpoints detected")
	}

	if uploadUrls > 0 {
		riskScore += 1.5
		riskFactors = append(riskFactors, "File upload functionality detected")
	}

	if len(urls) > 500 {
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
		"risk_score":     normalizedScore,
		"risk_level":     riskLevel,
		"risk_factors":   riskFactors,
		"admin_urls":     adminUrls,
		"api_urls":       apiUrls,
		"upload_urls":    uploadUrls,
	}
}

func (g *GospiderPlugin) populateSharedContext(result *models.PluginResult, sharedCtx *core.SharedContext) {
	if urls, ok := result.Results["urls"].([]string); ok {
		for _, urlStr := range urls {
			sharedCtx.AddURL(urlStr)
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

	if forms, ok := result.Results["forms"].([]string); ok && len(forms) > 0 {
		sharedCtx.AddTechnology("HTML Forms")
	}

	if riskAssessment, ok := result.Results["risk_assessment"].(map[string]interface{}); ok {
		if riskScore, ok := riskAssessment["risk_score"].(float64); ok && riskScore > 6.0 {
			sharedCtx.AddVulnerability("High-risk web application detected via crawling")
		}
	}
}

func (g *GospiderPlugin) Cleanup() error {
	return nil
}

func (g *GospiderPlugin) ValidateConfig() error {
	if g.config.Concurrent < 1 || g.config.Concurrent > 100 {
		return fmt.Errorf("concurrent must be between 1 and 100")
	}
	if g.config.Depth < 1 || g.config.Depth > 10 {
		return fmt.Errorf("depth must be between 1 and 10")
	}
	if g.config.Timeout < 1 || g.config.Timeout > 300 {
		return fmt.Errorf("timeout must be between 1 and 300 seconds")
	}
	if g.config.Delay < 0 || g.config.Delay > 10000 {
		return fmt.Errorf("delay must be between 0 and 10000 milliseconds")
	}
	return nil
}
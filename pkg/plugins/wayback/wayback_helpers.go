package wayback

import (
	"bufio"
	"encoding/json"
	"fmt"
	"io/ioutil"
	"net/url"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
	"time"

	"github.com/fatih/color"
	"github.com/f2u0a0d3/GoRecon/pkg/core"
	"github.com/f2u0a0d3/GoRecon/pkg/models"
)

// Helper methods for wayback plugin

// isValidURL checks if a URL is valid and should be included
func (w *WaybackPlugin) isValidURL(rawURL string) bool {
	if rawURL == "" {
		return false
	}
	
	// Parse URL
	parsedURL, err := url.Parse(rawURL)
	if err != nil {
		return false
	}
	
	// Must have valid scheme and host
	if parsedURL.Scheme == "" || parsedURL.Host == "" {
		return false
	}
	
	// Check for blocked extensions
	for _, ext := range w.config.GAUBlacklist {
		if strings.HasSuffix(strings.ToLower(parsedURL.Path), "."+ext) {
			return false
		}
	}
	
	return true
}

// normalizeURL normalizes a URL for deduplication
func (w *WaybackPlugin) normalizeURL(rawURL string) string {
	parsedURL, err := url.Parse(rawURL)
	if err != nil {
		return ""
	}
	
	// Normalize scheme to https
	if parsedURL.Scheme == "http" {
		parsedURL.Scheme = "https"
	}
	
	// Lowercase host
	parsedURL.Host = strings.ToLower(parsedURL.Host)
	
	// Remove fragment
	parsedURL.Fragment = ""
	
	// Keep query parameters for parameter analysis
	return parsedURL.String()
}

// analyzeURL analyzes a URL and extracts metadata
func (w *WaybackPlugin) analyzeURL(rawURL, source string) URLAnalysis {
	parsedURL, _ := url.Parse(rawURL)
	
	analysis := URLAnalysis{
		URL:        rawURL,
		Source:     source,
		Parameters: w.extractParameters(parsedURL),
		Extension:  w.getFileExtension(parsedURL.Path),
		Category:   w.categorizeURL(parsedURL),
		Metadata:   make(map[string]interface{}),
	}
	
	analysis.Interesting = w.isInterestingURL(parsedURL, analysis.Category)
	
	return analysis
}

// extractParameters extracts parameter names from URL
func (w *WaybackPlugin) extractParameters(parsedURL *url.URL) []string {
	var params []string
	
	if parsedURL.RawQuery != "" {
		values, err := url.ParseQuery(parsedURL.RawQuery)
		if err == nil {
			for param := range values {
				params = append(params, param)
			}
		}
	}
	
	// Also check for path parameters (e.g., /user/{id})
	pathParams := w.extractPathParameters(parsedURL.Path)
	params = append(params, pathParams...)
	
	return params
}

// extractPathParameters extracts parameters from URL path
func (w *WaybackPlugin) extractPathParameters(path string) []string {
	var params []string
	
	// Look for numeric IDs in path segments
	idRegex := regexp.MustCompile(`/\d+(/|$)`)
	if idRegex.MatchString(path) {
		params = append(params, "id")
	}
	
	// Look for UUID patterns
	uuidRegex := regexp.MustCompile(`/[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}(/|$)`)
	if uuidRegex.MatchString(path) {
		params = append(params, "uuid")
	}
	
	return params
}

// getFileExtension extracts file extension from path
func (w *WaybackPlugin) getFileExtension(path string) string {
	if path == "" || strings.HasSuffix(path, "/") {
		return "directory"
	}
	
	parts := strings.Split(filepath.Base(path), ".")
	if len(parts) < 2 {
		return "no_extension"
	}
	
	return strings.ToLower(parts[len(parts)-1])
}

// categorizeURL categorizes a URL based on patterns
func (w *WaybackPlugin) categorizeURL(parsedURL *url.URL) string {
	path := strings.ToLower(parsedURL.Path)
	host := strings.ToLower(parsedURL.Host)
	
	// Admin panels
	adminPatterns := []string{
		"/admin", "/administrator", "/wp-admin", "/panel", "/control",
		"/manage", "/dashboard", "/backend", "/console", "/system",
	}
	for _, pattern := range adminPatterns {
		if strings.Contains(path, pattern) {
			return "admin"
		}
	}
	
	// API endpoints
	apiPatterns := []string{
		"/api/", "/rest/", "/graphql", "/v1/", "/v2/", "/v3/",
		"api.", "rest.", "/json", "/xml", "/rpc",
	}
	for _, pattern := range apiPatterns {
		if strings.Contains(path, pattern) || strings.Contains(host, pattern) {
			return "api"
		}
	}
	
	// Backup files
	backupPatterns := []string{
		"backup", ".sql", ".bak", ".old", ".orig", ".tar", ".zip",
		".dump", "db_", "database", ".git/", ".env", "config.php",
	}
	for _, pattern := range backupPatterns {
		if strings.Contains(path, pattern) {
			return "backup"
		}
	}
	
	// Development/Debug
	devPatterns := []string{
		"/debug", "/test", "/dev", "/staging", "/phpinfo",
		"/info.php", "/.well-known", "/trace", "/status",
	}
	for _, pattern := range devPatterns {
		if strings.Contains(path, pattern) {
			return "development"
		}
	}
	
	// Authentication
	authPatterns := []string{
		"/login", "/signin", "/auth", "/oauth", "/sso",
		"/register", "/signup", "/forgot", "/reset",
	}
	for _, pattern := range authPatterns {
		if strings.Contains(path, pattern) {
			return "authentication"
		}
	}
	
	// File uploads
	uploadPatterns := []string{
		"/upload", "/file", "/media", "/assets", "/static",
		"/images", "/img", "/pictures", "/documents",
	}
	for _, pattern := range uploadPatterns {
		if strings.Contains(path, pattern) {
			return "upload"
		}
	}
	
	// Default category based on extension
	ext := w.getFileExtension(parsedURL.Path)
	switch ext {
	case "js", "javascript":
		return "javascript"
	case "css":
		return "stylesheet"
	case "php", "asp", "aspx", "jsp", "py", "rb":
		return "script"
	case "pdf", "doc", "docx", "xls", "xlsx", "ppt", "pptx":
		return "document"
	case "jpg", "jpeg", "png", "gif", "svg", "ico":
		return "image"
	case "mp4", "avi", "mov", "wmv", "flv":
		return "video"
	case "mp3", "wav", "ogg":
		return "audio"
	default:
		return "general"
	}
}

// isInterestingURL determines if a URL is potentially interesting for security testing
func (w *WaybackPlugin) isInterestingURL(parsedURL *url.URL, category string) bool {
	interestingCategories := map[string]bool{
		"admin":          true,
		"api":            true,
		"backup":         true,
		"development":    true,
		"authentication": true,
		"upload":         true,
	}
	
	if interestingCategories[category] {
		return true
	}
	
	// URLs with parameters are interesting for injection testing
	if len(parsedURL.RawQuery) > 0 {
		return true
	}
	
	// Check for interesting parameter names
	interestingParams := []string{
		"id", "user", "file", "path", "url", "redirect", "next",
		"callback", "jsonp", "search", "query", "q", "s",
	}
	
	if parsedURL.RawQuery != "" {
		values, err := url.ParseQuery(parsedURL.RawQuery)
		if err == nil {
			for param := range values {
				for _, interesting := range interestingParams {
					if strings.Contains(strings.ToLower(param), interesting) {
						return true
					}
				}
			}
		}
	}
	
	return false
}

// getTimeRange estimates the time range of URLs (simplified)
func (w *WaybackPlugin) getTimeRange(urls []string) string {
	// This is a simplified implementation
	// In a real implementation, you'd parse actual timestamps from Wayback URLs
	currentYear := time.Now().Year()
	return fmt.Sprintf("2010-%d", currentYear)
}

// saveURLsToFile saves URLs to a file
func (w *WaybackPlugin) saveURLsToFile(urls []string, filename string) error {
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

// readURLsFromFile reads URLs from a file
func (w *WaybackPlugin) readURLsFromFile(filename string) ([]string, error) {
	file, err := os.Open(filename)
	if err != nil {
		return nil, err
	}
	defer file.Close()
	
	var urls []string
	scanner := bufio.NewScanner(file)
	for scanner.Scan() {
		if url := strings.TrimSpace(scanner.Text()); url != "" {
			urls = append(urls, url)
		}
	}
	
	return urls, scanner.Err()
}

// saveProcessedResults saves processed results to files
func (w *WaybackPlugin) saveProcessedResults(allURLs []URLAnalysis, stats URLStats, processedDir, byExtDir, byCatDir string) error {
	// Save all URLs
	allURLsFile := filepath.Join(processedDir, "all_urls.txt")
	var urls []string
	for _, analysis := range allURLs {
		urls = append(urls, analysis.URL)
	}
	if err := w.saveURLsToFile(urls, allURLsFile); err != nil {
		return fmt.Errorf("failed to save all URLs: %w", err)
	}
	
	// Save parameters
	paramsFile := filepath.Join(processedDir, "parameters.txt")
	if err := w.saveParameters(stats.Parameters, paramsFile); err != nil {
		return fmt.Errorf("failed to save parameters: %w", err)
	}
	
	// Save interesting URLs
	interestingFile := filepath.Join(processedDir, "interesting.txt")
	var interesting []string
	for _, analysis := range allURLs {
		if analysis.Interesting {
			interesting = append(interesting, analysis.URL)
		}
	}
	if err := w.saveURLsToFile(interesting, interestingFile); err != nil {
		return fmt.Errorf("failed to save interesting URLs: %w", err)
	}
	
	// Save by extension
	if err := w.saveByExtension(allURLs, byExtDir); err != nil {
		return fmt.Errorf("failed to save by extension: %w", err)
	}
	
	// Save by category
	if err := w.saveByCategory(allURLs, byCatDir); err != nil {
		return fmt.Errorf("failed to save by category: %w", err)
	}
	
	// Save JSON analysis
	analysisFile := filepath.Join(processedDir, "analysis.json")
	if err := w.saveAnalysisJSON(allURLs, stats, analysisFile); err != nil {
		return fmt.Errorf("failed to save analysis JSON: %w", err)
	}
	
	return nil
}

// saveParameters saves parameter statistics to file
func (w *WaybackPlugin) saveParameters(params map[string]int, filename string) error {
	file, err := os.Create(filename)
	if err != nil {
		return err
	}
	defer file.Close()
	
	writer := bufio.NewWriter(file)
	defer writer.Flush()
	
	// Sort parameters by frequency
	type paramCount struct {
		name  string
		count int
	}
	
	var sorted []paramCount
	for name, count := range params {
		sorted = append(sorted, paramCount{name, count})
	}
	
	sort.Slice(sorted, func(i, j int) bool {
		return sorted[i].count > sorted[j].count
	})
	
	for _, pc := range sorted {
		line := fmt.Sprintf("%s=%d\n", pc.name, pc.count)
		if _, err := writer.WriteString(line); err != nil {
			return err
		}
	}
	
	return nil
}

// saveByExtension saves URLs categorized by file extension
func (w *WaybackPlugin) saveByExtension(allURLs []URLAnalysis, byExtDir string) error {
	extMap := make(map[string][]string)
	
	for _, analysis := range allURLs {
		extMap[analysis.Extension] = append(extMap[analysis.Extension], analysis.URL)
	}
	
	for ext, urls := range extMap {
		if len(urls) == 0 {
			continue
		}
		
		filename := filepath.Join(byExtDir, ext+".txt")
		if err := w.saveURLsToFile(urls, filename); err != nil {
			return err
		}
	}
	
	return nil
}

// saveByCategory saves URLs categorized by type
func (w *WaybackPlugin) saveByCategory(allURLs []URLAnalysis, byCatDir string) error {
	catMap := make(map[string][]string)
	
	for _, analysis := range allURLs {
		catMap[analysis.Category] = append(catMap[analysis.Category], analysis.URL)
	}
	
	for category, urls := range catMap {
		if len(urls) == 0 {
			continue
		}
		
		filename := filepath.Join(byCatDir, category+".txt")
		if err := w.saveURLsToFile(urls, filename); err != nil {
			return err
		}
	}
	
	return nil
}

// saveAnalysisJSON saves complete analysis as JSON
func (w *WaybackPlugin) saveAnalysisJSON(allURLs []URLAnalysis, stats URLStats, filename string) error {
	data := map[string]interface{}{
		"urls":       allURLs,
		"statistics": stats,
		"timestamp":  time.Now().Format(time.RFC3339),
	}
	
	jsonData, err := json.MarshalIndent(data, "", "  ")
	if err != nil {
		return err
	}
	
	return ioutil.WriteFile(filename, jsonData, 0644)
}

// displayResults displays the final results with GORECON branding
func (w *WaybackPlugin) displayResults(stats URLStats, duration time.Duration) {
	red := color.New(color.FgRed).SprintFunc()
	cyan := color.New(color.FgCyan).SprintFunc()
	white := color.New(color.FgWhite, color.Bold).SprintFunc()

	fmt.Println()

	// Display interesting findings
	if stats.InterestingURLs > 0 {
		fmt.Printf("%s\n", white("Interesting Findings:"))
		fmt.Printf("%s\n", strings.Repeat("-", 20))

		// Show top categories
		categories := []struct {
			name  string
			count int
		}{
			{"Admin panels", stats.ByCategory["admin"]},
			{"API endpoints", stats.ByCategory["api"]},
			{"Backup files", stats.ByCategory["backup"]},
			{"Development", stats.ByCategory["development"]},
		}

		for _, cat := range categories {
			if cat.count > 0 {
				fmt.Printf("[%s] %s: %d URLs\n", red("!"), cat.name, cat.count)
			}
		}

		fmt.Println()
	}

	// Display parameter statistics
	if len(stats.Parameters) > 0 {
		fmt.Printf("[%s] Parameters with potential injection points: %d\n", red("!"), len(stats.Parameters))

		// Show top parameters
		type paramCount struct {
			name  string
			count int
		}
		var sorted []paramCount
		for name, count := range stats.Parameters {
			sorted = append(sorted, paramCount{name, count})
		}
		sort.Slice(sorted, func(i, j int) bool {
			return sorted[i].count > sorted[j].count
		})

		// Show top 5 parameters
		for i, pc := range sorted {
			if i >= 5 {
				break
			}
			fmt.Printf("    ├─ %s= (%d occurrences)\n", pc.name, pc.count)
		}
		fmt.Println()
	}

	// Display file extensions
	fmt.Printf("%s\n", white("File Extensions Found:"))
	fmt.Printf("%s\n", strings.Repeat("-", 22))

	extCategories := map[string][]string{
		"Documents": {"pdf", "doc", "docx", "xls", "xlsx", "ppt", "pptx"},
		"Archives":  {"zip", "tar", "gz", "rar", "7z"},
		"Config":    {"xml", "json", "yml", "yaml", "ini", "conf"},
		"Scripts":   {"js", "php", "asp", "aspx", "jsp", "py", "rb"},
	}

	for category, extensions := range extCategories {
		var counts []string
		for _, ext := range extensions {
			if count := stats.ByExtension[ext]; count > 0 {
				counts = append(counts, fmt.Sprintf(".%s (%d)", ext, count))
			}
		}
		if len(counts) > 0 {
			fmt.Printf("%s: %s\n", category, strings.Join(counts, ", "))
		}
	}

	fmt.Println()
	fmt.Printf("[%s] Scan completed in %v\n", cyan("*"), duration.Round(100*time.Millisecond))
}

// generatePluginResults generates plugin results for the pipeline
func (w *WaybackPlugin) generatePluginResults(target *models.Target, allURLs []URLAnalysis, stats URLStats, results chan<- models.PluginResult) {
	// Generate summary result
	summaryData := map[string]interface{}{
		"total_urls":       stats.TotalURLs,
		"unique_urls":      stats.UniqueURLs,
		"interesting_urls": stats.InterestingURLs,
		"by_source":        stats.BySource,
		"by_category":      stats.ByCategory,
		"parameters":       len(stats.Parameters),
	}

	summaryResult := models.PluginResult{
		Plugin:      "wayback",
		Target:      target.URL,
		Severity:    models.SeverityInfo,
		Title:       "Historical URL Discovery Summary",
		Description: fmt.Sprintf("Discovered %d unique URLs from historical archives", stats.UniqueURLs),
		Data:        summaryData,
		Timestamp:   time.Now(),
	}

	results <- summaryResult

	// Generate results for interesting URLs
	for _, analysis := range allURLs {
		if !analysis.Interesting {
			continue
		}

		severity := models.SeverityLow
		if analysis.Category == "admin" || analysis.Category == "backup" {
			severity = models.SeverityMedium
		}
		if analysis.Category == "api" && len(analysis.Parameters) > 0 {
			severity = models.SeverityMedium
		}

		urlData := map[string]interface{}{
			"url":        analysis.URL,
			"source":     analysis.Source,
			"category":   analysis.Category,
			"extension":  analysis.Extension,
			"parameters": analysis.Parameters,
		}

		urlResult := models.PluginResult{
			Plugin:      "wayback",
			Target:      target.URL,
			Severity:    severity,
			Title:       fmt.Sprintf("Interesting URL: %s", analysis.Category),
			Description: fmt.Sprintf("Found %s URL: %s", analysis.Category, analysis.URL),
			Data:        urlData,
			Timestamp:   time.Now(),
		}

		results <- urlResult
	}
}

// addDiscoveries adds discoveries to the shared context
func (w *WaybackPlugin) addDiscoveries(shared *core.SharedContext, allURLs []URLAnalysis, stats URLStats) {
	// Add URL discoveries
	for _, analysis := range allURLs {
		shared.AddDiscovery(models.Discovery{
			Type:       "historical_url",
			Value:      analysis.URL,
			Source:     "wayback",
			Confidence: 0.9,
			Timestamp:  time.Now(),
			Metadata: map[string]interface{}{
				"category":    analysis.Category,
				"extension":   analysis.Extension,
				"parameters":  analysis.Parameters,
				"interesting": analysis.Interesting,
			},
		})

		// Add parameter discoveries
		for _, param := range analysis.Parameters {
			shared.AddDiscovery(models.Discovery{
				Type:       "url_parameter",
				Value:      param,
				Source:     "wayback",
				Confidence: 0.8,
				Timestamp:  time.Now(),
				Metadata: map[string]interface{}{
					"url":       analysis.URL,
					"frequency": stats.Parameters[param],
				},
			})
		}

		// Add interesting path discoveries
		if analysis.Interesting {
			shared.AddDiscovery(models.Discovery{
				Type:       "interesting_path",
				Value:      analysis.URL,
				Source:     "wayback",
				Confidence: 0.85,
				Timestamp:  time.Now(),
				Metadata: map[string]interface{}{
					"category": analysis.Category,
					"reason":   "historical_archive",
				},
			})
		}
	}
}
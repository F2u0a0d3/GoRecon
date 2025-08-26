package dirfuzz

import (
	"bufio"
	"context"
	"encoding/json"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/fatih/color"
	"github.com/f2u0a0d3/GoRecon/pkg/core"
	"github.com/f2u0a0d3/GoRecon/pkg/models"
	"github.com/f2u0a0d3/GoRecon/pkg/plugins/base"
)

// DirFuzzPlugin implements directory and file fuzzing
type DirFuzzPlugin struct {
	*base.BaseAdapter
	config *DirFuzzConfig
}

// DirFuzzConfig contains directory fuzzing configuration
type DirFuzzConfig struct {
	EnableFFUF       bool          `json:"enable_ffuf"`
	Threads          int           `json:"threads"`
	Timeout          time.Duration `json:"timeout"`
	WordlistDir      string        `json:"wordlist_dir"`
	WordlistFiles    []string      `json:"wordlist_files"`
	Extensions       []string      `json:"extensions"`
	FilterCodes      []int         `json:"filter_codes"`
	FilterSizes      []int         `json:"filter_sizes"`
	MatchCodes       []int         `json:"match_codes"`
	Delay            time.Duration `json:"delay"`
	UserAgent        string        `json:"user_agent"`
	FollowRedirects  bool          `json:"follow_redirects"`
	RecursiveDepth   int           `json:"recursive_depth"`
}

// FuzzResult represents a fuzzing result
type FuzzResult struct {
	URL            string            `json:"url"`
	StatusCode     int               `json:"status_code"`
	ContentLength  int               `json:"content_length"`
	ContentType    string            `json:"content_type"`
	Words          int               `json:"words"`
	Lines          int               `json:"lines"`
	RedirectURL    string            `json:"redirect_url"`
	ResponseTime   time.Duration     `json:"response_time"`
	Wordlist       string            `json:"wordlist"`
	FuzzedPath     string            `json:"fuzzed_path"`
	IsDirectory    bool              `json:"is_directory"`
	IsFile         bool              `json:"is_file"`
	Headers        map[string]string `json:"headers"`
	Metadata       map[string]string `json:"metadata"`
	Tool           string            `json:"tool"`
	Timestamp      time.Time         `json:"timestamp"`
	Confidence     float64           `json:"confidence"`
}

// FuzzStats contains directory fuzzing statistics
type FuzzStats struct {
	TotalURLs        int                    `json:"total_urls"`
	TotalRequests    int                    `json:"total_requests"`
	FoundPaths       int                    `json:"found_paths"`
	FoundDirectories int                    `json:"found_directories"`
	FoundFiles       int                    `json:"found_files"`
	ByStatusCode     map[int]int            `json:"by_status_code"`
	ByContentType    map[string]int         `json:"by_content_type"`
	ByWordlist       map[string]int         `json:"by_wordlist"`
	FuzzDuration     time.Duration          `json:"fuzz_duration"`
}

// NewDirFuzzPlugin creates a new directory fuzzing plugin
func NewDirFuzzPlugin() *DirFuzzPlugin {
	config := &DirFuzzConfig{
		EnableFFUF:      true,
		Threads:         40,
		Timeout:         10 * time.Second,
		WordlistDir:     "/usr/share/wordlists",
		WordlistFiles:   []string{"dirbuster/directory-list-2.3-medium.txt", "dirb/common.txt", "dirbuster/directory-list-2.3-small.txt"},
		Extensions:      []string{"php", "asp", "aspx", "jsp", "html", "js", "txt", "xml", "json", "bak", "old", "backup"},
		FilterCodes:     []int{404, 403},
		FilterSizes:     []int{},
		MatchCodes:      []int{200, 204, 301, 302, 307, 401, 403, 500},
		Delay:           100 * time.Millisecond,
		UserAgent:       "GORECON/2.0 Directory Fuzzer",
		FollowRedirects: false,
		RecursiveDepth:  1,
	}

	baseAdapter := base.NewBaseAdapter(base.BaseAdapterConfig{
		Name:        "dirfuzz",
		Category:    "dirfuzz",
		Description: "Directory and file fuzzing using ffuf",
		Version:     "1.0.0",
		Author:      "GoRecon Team",
		ToolName:    "ffuf",
		Passive:     false,
		Duration:    60 * time.Minute,
		Concurrency: 1,
		Priority:    10,
		Resources: core.Resources{
			CPUCores:      4,
			MemoryMB:      2048,
			NetworkAccess: true,
		},
		Provides: []string{"directories", "files", "hidden_paths"},
		Consumes: []string{"http_services", "web_pages"},
	})

	return &DirFuzzPlugin{
		BaseAdapter: baseAdapter,
		config:      config,
	}
}

// Run executes directory fuzzing
func (d *DirFuzzPlugin) Run(ctx context.Context, target *models.Target, results chan<- models.PluginResult, shared *core.SharedContext) error {
	logger := shared.GetLogger().WithField("plugin", "dirfuzz")
	
	cyan := color.New(color.FgCyan).SprintFunc()
	white := color.New(color.FgWhite, color.Bold).SprintFunc()

	domain := target.Domain
	if domain == "" {
		domain = d.ExtractDomain(target.URL)
	}

	fmt.Printf("\n%s\n", white("[GORECON] Directory Fuzzer v1.0"))
	fmt.Printf("%s\n", strings.Repeat("=", 32))
	fmt.Printf("[%s] Using ffuf for comprehensive directory and file discovery\n", cyan("*"))

	targetURLs := d.collectTargetURLs(shared, domain, target)
	fmt.Printf("[%s] Fuzzing %d target URLs from previous steps...\n\n", cyan("*"), len(targetURLs))

	workDir := filepath.Join("./work", domain, "dirfuzz")
	if err := os.MkdirAll(workDir, 0755); err != nil {
		return fmt.Errorf("failed to create workspace: %w", err)
	}
	
	rawDir := filepath.Join(workDir, "raw")
	if err := os.MkdirAll(rawDir, 0755); err != nil {
		return fmt.Errorf("failed to create directory: %w", err)
	}

	fuzzResults, stats, err := d.runDirectoryFuzzing(ctx, targetURLs, rawDir)
	if err != nil {
		logger.Error("Directory fuzzing failed", err)
		return err
	}

	d.displayResults(fuzzResults, stats)
	d.generatePluginResults(target, fuzzResults, results)
	d.addDiscoveries(shared, domain, fuzzResults)

	logger.Info("Directory fuzzing completed",
		"target", domain,
		"found_paths", stats.FoundPaths,
		"found_directories", stats.FoundDirectories,
		"found_files", stats.FoundFiles)

	return nil
}

func (d *DirFuzzPlugin) collectTargetURLs(shared *core.SharedContext, domain string, target *models.Target) []string {
	urlSet := make(map[string]bool)

	// Prioritize target URL if provided
	if target.URL != "" {
		// Extract base URL without path
		baseURL := d.extractBaseURL(target.URL)
		urlSet[baseURL] = true
	} else {
		// Only add domain URLs if no specific target URL provided
		urlSet[fmt.Sprintf("https://%s", domain)] = true
		// Don't add both HTTP and HTTPS by default to avoid duplicates
		// HTTP will be tried if HTTPS fails
	}

	// Only collect additional URLs from discoveries if we don't have a specific target
	if target.URL == "" {
		discoveries := shared.GetDiscoveries("")
		for _, discovery := range discoveries {
			value, ok := discovery.Value.(string)
			if !ok {
				continue
			}

			switch discovery.Type {
			case "http_service":
				if strings.Contains(value, domain) {
					baseURL := d.extractBaseURL(value)
					urlSet[baseURL] = true
				}
			case "web_page":
				if strings.Contains(value, domain) && (strings.HasPrefix(value, "http://") || strings.HasPrefix(value, "https://")) {
					baseURL := d.extractBaseURL(value)
					urlSet[baseURL] = true
				}
			}
		}
	}

	var urlList []string
	for url := range urlSet {
		// Ensure URLs end with / for directory fuzzing
		if !strings.HasSuffix(url, "/") {
			url += "/"
		}
		urlList = append(urlList, url)
	}
	sort.Strings(urlList)

	// Limit to avoid too many duplicate scans - prefer HTTPS over HTTP
	if len(urlList) > 1 {
		// Keep only one URL, preferring HTTPS
		var finalURL string
		for _, url := range urlList {
			if strings.HasPrefix(url, "https://") {
				finalURL = url
				break
			}
		}
		if finalURL == "" {
			finalURL = urlList[0]
		}
		urlList = []string{finalURL}
	}

	return urlList
}

func (d *DirFuzzPlugin) extractBaseURL(fullURL string) string {
	// Remove path and query parameters, keep only scheme://host:port
	if strings.HasPrefix(fullURL, "http://") || strings.HasPrefix(fullURL, "https://") {
		parts := strings.SplitN(fullURL, "/", 4)
		if len(parts) >= 3 {
			return strings.Join(parts[:3], "/")
		}
	}
	return fullURL
}

func (d *DirFuzzPlugin) runDirectoryFuzzing(ctx context.Context, targetURLs []string, rawDir string) ([]FuzzResult, FuzzStats, error) {
	white := color.New(color.FgWhite, color.Bold).SprintFunc()
	cyan := color.New(color.FgCyan).SprintFunc()
	red := color.New(color.FgRed).SprintFunc()

	fmt.Printf("%s\n", white("[GORECON::FFUF] Directory Discovery"))
	fmt.Printf("%s\n", strings.Repeat("=", 35))

	if _, err := exec.LookPath("ffuf"); err != nil {
		fmt.Printf("[%s] ffuf not found\n", red("!"))
		fmt.Printf("[%s] Install: go install github.com/ffuf/ffuf/v2@latest\n", cyan("*"))
		return nil, FuzzStats{}, fmt.Errorf("ffuf not installed")
	}

	startTime := time.Now()
	var allResults []FuzzResult

	// Find available wordlists
	wordlists := d.findAvailableWordlists()
	if len(wordlists) == 0 {
		fmt.Printf("[%s] No wordlists found. Using built-in common paths.\n", cyan("-"))
		wordlists = []string{d.createBuiltinWordlist(rawDir)}
	}

	fmt.Printf("[%s] Using %d wordlists for fuzzing\n", cyan("*"), len(wordlists))

	// Run fuzzing for each target URL and wordlist combination
	for _, targetURL := range targetURLs {
		for _, wordlist := range wordlists {
			fuzzResults, err := d.runFFUF(ctx, targetURL, wordlist, rawDir)
			if err != nil {
				fmt.Printf("[%s] FFUF failed for %s: %v\n", cyan("-"), targetURL, err)
				continue
			}

			allResults = append(allResults, fuzzResults...)
		}
	}

	// Remove duplicates
	allResults = d.deduplicateResults(allResults)

	// Generate statistics
	stats := FuzzStats{
		TotalURLs:        len(targetURLs),
		FoundPaths:       len(allResults),
		ByStatusCode:     make(map[int]int),
		ByContentType:    make(map[string]int),
		ByWordlist:       make(map[string]int),
		FuzzDuration:     time.Since(startTime),
	}

	for _, result := range allResults {
		stats.TotalRequests++
		stats.ByStatusCode[result.StatusCode]++
		if result.ContentType != "" {
			stats.ByContentType[result.ContentType]++
		}
		stats.ByWordlist[result.Wordlist]++
		
		if result.IsDirectory {
			stats.FoundDirectories++
		}
		if result.IsFile {
			stats.FoundFiles++
		}
	}

	return allResults, stats, nil
}

func (d *DirFuzzPlugin) runFFUF(ctx context.Context, targetURL, wordlist, rawDir string) ([]FuzzResult, error) {
	green := color.New(color.FgGreen).SprintFunc()
	red := color.New(color.FgRed).SprintFunc()
	yellow := color.New(color.FgYellow).SprintFunc()
	cyan := color.New(color.FgCyan).SprintFunc()
	
	// Build the exact ffuf command as specified by user
	fuzzURL := strings.TrimSuffix(targetURL, "/") + "/FUZZ"
	args := []string{
		"-w", wordlist,
		"-u", fuzzURL,
		"-H", "User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:138.0) Gecko/20100101 Firefox/138.0",
		"-mc", "all",
		"-fc", "404",
	}
	
	fmt.Printf("[%s] Running: ffuf %s\n", cyan("*"), strings.Join(args, " "))
	fmt.Printf("[%s] Target: %s\n", cyan("*"), fuzzURL)
	fmt.Printf("[%s] Wordlist: %s\n", cyan("*"), filepath.Base(wordlist))
	fmt.Println()
	
	cmd := exec.CommandContext(ctx, "ffuf", args...)
	
	// Create pipes for real-time output streaming
	stdout, err := cmd.StdoutPipe()
	if err != nil {
		return nil, fmt.Errorf("failed to create stdout pipe: %w", err)
	}
	
	stderr, err := cmd.StderrPipe()
	if err != nil {
		return nil, fmt.Errorf("failed to create stderr pipe: %w", err)
	}
	
	// Start the command
	if err := cmd.Start(); err != nil {
		return nil, fmt.Errorf("failed to start ffuf command: %w", err)
	}
	
	var allResults []FuzzResult
	var mu sync.Mutex
	var wg sync.WaitGroup
	
	wg.Add(2) // for stdout and stderr goroutines
	
	// Read stdout in real-time
	go func() {
		defer wg.Done()
		scanner := bufio.NewScanner(stdout)
		for scanner.Scan() {
			line := scanner.Text()
			
			// Parse and display line in real-time with styling
			result := d.parseFFUFLine(line, wordlist, targetURL)
			if result.URL != "" {
				mu.Lock()
				allResults = append(allResults, result)
				count := len(allResults)
				mu.Unlock()
				
				// Display result with counter
				d.displayFFUFResult(result, green, red, yellow, cyan, count)
			} else {
				d.displayFFUFInfo(line, green, red, yellow, cyan)
			}
		}
	}()
	
	// Read stderr in real-time
	go func() {
		defer wg.Done()
		scanner := bufio.NewScanner(stderr)
		for scanner.Scan() {
			// Skip stderr for cleaner output - errors will show in stdout parsing
		}
	}()
	
	// Wait for goroutines to finish reading
	wg.Wait()
	
	// Wait for command to complete
	err = cmd.Wait()
	if err != nil {
		// ffuf returns non-zero exit code when results are found, so don't treat as error
		if _, ok := err.(*exec.ExitError); !ok {
			return nil, fmt.Errorf("ffuf command failed: %w", err)
		}
	}
	
	return allResults, nil
}

func (d *DirFuzzPlugin) parseFFUFLine(line, wordlist, targetURL string) FuzzResult {
	line = strings.TrimSpace(line)
	if line == "" {
		return FuzzResult{}
	}
	
	// Check if this looks like a ffuf result line
	// Format: [2Kbackup                  [Status: 502, Size: 122, Words: 5, Lines: 7, Duration: 438ms][0m
	if !strings.Contains(line, "[Status:") {
		return FuzzResult{}
	}
	
	result := FuzzResult{
		Timestamp: time.Now(),
		Metadata:  make(map[string]string),
		Tool:      "ffuf",
		Wordlist:  filepath.Base(wordlist),
	}
	
	// Clean up the line and extract the path
	// Remove ANSI control characters
	cleanLine := regexp.MustCompile(`\x1b\[[0-9;]*[a-zA-Z]`).ReplaceAllString(line, "")
	cleanLine = regexp.MustCompile(`\[2K|\[0m`).ReplaceAllString(cleanLine, "")
	cleanLine = strings.TrimSpace(cleanLine)
	
	// Extract the fuzzed path (word before the first [Status: part)
	// Example: "backup                  [Status: 502, Size: 122..."
	statusIndex := strings.Index(cleanLine, "[Status:")
	if statusIndex > 0 {
		pathPart := strings.TrimSpace(cleanLine[:statusIndex])
		result.FuzzedPath = pathPart
		
		// Build full URL
		baseURL := strings.TrimSuffix(targetURL, "/")
		result.URL = baseURL + "/" + pathPart
	} else {
		return FuzzResult{}
	}
	
	// Extract status information from the line
	statusRegex := regexp.MustCompile(`Status:\s*(\d+)`)
	if statusMatch := statusRegex.FindStringSubmatch(line); len(statusMatch) > 1 {
		if code, err := strconv.Atoi(statusMatch[1]); err == nil {
			result.StatusCode = code
		}
	}
	
	sizeRegex := regexp.MustCompile(`Size:\s*(\d+)`)
	if sizeMatch := sizeRegex.FindStringSubmatch(line); len(sizeMatch) > 1 {
		if size, err := strconv.Atoi(sizeMatch[1]); err == nil {
			result.ContentLength = size
		}
	}
	
	wordsRegex := regexp.MustCompile(`Words:\s*(\d+)`)
	if wordsMatch := wordsRegex.FindStringSubmatch(line); len(wordsMatch) > 1 {
		if words, err := strconv.Atoi(wordsMatch[1]); err == nil {
			result.Words = words
		}
	}
	
	linesRegex := regexp.MustCompile(`Lines:\s*(\d+)`)
	if linesMatch := linesRegex.FindStringSubmatch(line); len(linesMatch) > 1 {
		if lines, err := strconv.Atoi(linesMatch[1]); err == nil {
			result.Lines = lines
		}
	}
	
	// Set default values if not found
	if result.StatusCode == 0 {
		result.StatusCode = 200 // Default
	}
	
	// Determine if directory or file
	result.IsDirectory = d.isLikelyDirectory(result.URL, result.StatusCode)
	result.IsFile = !result.IsDirectory
	result.Confidence = 0.9
	
	return result
}

func (d *DirFuzzPlugin) displayFFUFResult(result FuzzResult, green, red, yellow, cyan func(...interface{}) string, count int) {
	statusColor := green
	if result.StatusCode >= 500 {
		statusColor = red
	} else if result.StatusCode >= 400 {
		statusColor = red
	} else if result.StatusCode >= 300 {
		statusColor = yellow
	}
	
	typeIndicator := "F"
	if result.IsDirectory {
		typeIndicator = "D"
	}
	
	// Clean, professional output format
	fmt.Printf("[%s] %s", green("+"), result.URL)
	
	// Add status code with color
	fmt.Printf(" [%s]", statusColor(strconv.Itoa(result.StatusCode)))
	
	// Add type indicator
	fmt.Printf(" [%s]", typeIndicator)
	
	// Add size information if available
	if result.ContentLength > 0 {
		fmt.Printf(" %d bytes", result.ContentLength)
	}
	
	// Add word/line count if available (but keep it minimal)
	if result.Words > 0 && result.Lines > 0 {
		fmt.Printf(" (%dw %dl)", result.Words, result.Lines)
	}
	
	fmt.Println()
}

func (d *DirFuzzPlugin) displayFFUFInfo(line string, green, red, yellow, cyan func(...interface{}) string) {
	line = strings.TrimSpace(line)
	if line == "" {
		return
	}
	
	// Clean up and filter ffuf output
	// Remove ANSI escape sequences and control characters
	line = d.cleanFFUFLine(line)
	if line == "" {
		return
	}
	
	// Show only important configuration info at startup
	if strings.Contains(line, ":: Method") || strings.Contains(line, ":: URL") {
		fmt.Printf("[%s] %s\n", cyan("*"), line)
	} else if strings.Contains(line, ":: Wordlist") {
		// Clean up wordlist display
		parts := strings.Split(line, ":")
		if len(parts) >= 3 {
			wordlistPath := strings.TrimSpace(strings.Join(parts[2:], ":"))
			wordlistName := filepath.Base(wordlistPath)
			fmt.Printf("[%s] Wordlist: %s\n", cyan("*"), wordlistName)
		}
	} else if strings.Contains(line, ":: Header") || strings.Contains(line, ":: Matcher") || strings.Contains(line, ":: Filter") {
		fmt.Printf("[%s] %s\n", cyan("*"), line)
	} else if strings.Contains(line, "calibration") {
		fmt.Printf("[%s] %s\n", yellow("!"), line)
	} else if strings.Contains(line, "error") || strings.Contains(line, "Error") {
		fmt.Printf("[%s] %s\n", red("!"), line)
	}
	// Skip all progress lines and other noisy output
}

func (d *DirFuzzPlugin) cleanFFUFLine(line string) string {
	// Remove ANSI escape sequences like [2K and control characters
	line = regexp.MustCompile(`\x1b\[[0-9;]*[a-zA-Z]`).ReplaceAllString(line, "")
	line = regexp.MustCompile(`\[2K`).ReplaceAllString(line, "")
	
	// Skip progress lines entirely
	if strings.Contains(line, "Progress:") || strings.Contains(line, ":: Progress:") {
		return ""
	}
	
	// Skip lines with just "::" 
	if strings.TrimSpace(line) == "::" {
		return ""
	}
	
	return strings.TrimSpace(line)
}

func (d *DirFuzzPlugin) parseFFUFOutput(filename, wordlist string) ([]FuzzResult, error) {
	data, err := os.ReadFile(filename)
	if err != nil {
		return nil, err
	}

	var ffufOutput struct {
		Results []struct {
			URL            string            `json:"url"`
			StatusCode     int               `json:"status"`
			ContentLength  int               `json:"length"`
			ContentType    string            `json:"content-type"`
			Words          int               `json:"words"`
			Lines          int               `json:"lines"`
			RedirectURL    string            `json:"redirectlocation"`
			ResponseTime   int               `json:"duration"`
			Headers        map[string]string `json:"headers"`
		} `json:"results"`
	}

	if err := json.Unmarshal(data, &ffufOutput); err != nil {
		return nil, err
	}

	var results []FuzzResult
	for _, result := range ffufOutput.Results {
		fuzzResult := FuzzResult{
			URL:           result.URL,
			StatusCode:    result.StatusCode,
			ContentLength: result.ContentLength,
			ContentType:   result.ContentType,
			Words:         result.Words,
			Lines:         result.Lines,
			RedirectURL:   result.RedirectURL,
			ResponseTime:  time.Duration(result.ResponseTime) * time.Millisecond,
			Wordlist:      filepath.Base(wordlist),
			Headers:       result.Headers,
			Tool:          "ffuf",
			Timestamp:     time.Now(),
			Confidence:    0.9,
			Metadata:      make(map[string]string),
		}

		// Extract fuzzed path
		if strings.Contains(result.URL, "/") {
			parts := strings.Split(result.URL, "/")
			fuzzResult.FuzzedPath = parts[len(parts)-1]
		}

		// Determine if it's a directory or file
		fuzzResult.IsDirectory = d.isLikelyDirectory(result.URL, result.StatusCode)
		fuzzResult.IsFile = !fuzzResult.IsDirectory

		results = append(results, fuzzResult)
	}

	return results, nil
}

func (d *DirFuzzPlugin) findAvailableWordlists() []string {
	var wordlists []string

	for _, wordlistFile := range d.config.WordlistFiles {
		// Try absolute path first
		fullPath := filepath.Join(d.config.WordlistDir, wordlistFile)
		if _, err := os.Stat(fullPath); err == nil {
			wordlists = append(wordlists, fullPath)
			continue
		}

		// Try relative path
		if _, err := os.Stat(wordlistFile); err == nil {
			wordlists = append(wordlists, wordlistFile)
		}
	}

	return wordlists
}

func (d *DirFuzzPlugin) createBuiltinWordlist(rawDir string) string {
	// Enhanced wordlist with more comprehensive paths
	builtinPaths := []string{
		// Admin/Management
		"admin", "administrator", "login", "dashboard", "panel", "control", "manage", "manager",
		"admincp", "wp-admin", "cpanel", "console", "controlpanel", "admin.php",
		
		// API/Services
		"api", "rest", "graphql", "v1", "v2", "v3", "service", "services", "endpoint",
		"webhook", "callback", "rpc", "soap", "xml-rpc", "jsonrpc",
		
		// Development/Testing
		"dev", "development", "test", "testing", "stage", "staging", "debug", "demo",
		"beta", "alpha", "preview", "sandbox", "qa", "uat", "pre-prod",
		
		// Backup/Archive
		"backup", "backups", "archive", "archives", "old", "new", "bak", "backup.zip",
		"db_backup", "backup.sql", "backup.tar.gz", "dump", "export",
		
		// Config/Settings
		"config", "configuration", "settings", "setup", "install", "installation",
		"conf", "cfg", "ini", "env", ".env", "environment", "properties",
		
		// File/Upload areas
		"upload", "uploads", "files", "file", "documents", "docs", "download", "downloads",
		"media", "assets", "resources", "public", "static", "content",
		"images", "img", "pics", "pictures", "photos", "gallery",
		
		// Scripts/Code
		"js", "css", "javascript", "scripts", "script", "code", "src", "source",
		"lib", "libs", "library", "vendor", "node_modules", "bower_components",
		
		// Data/Database
		"data", "db", "database", "sql", "mysql", "postgres", "mongo", "redis",
		"cache", "storage", "store", "repository", "repo",
		
		// Logs/Monitoring
		"logs", "log", "logger", "logging", "audit", "monitor", "monitoring", "metrics",
		"stats", "statistics", "analytics", "track", "tracking",
		
		// Temporary/System
		"tmp", "temp", "temporary", "cache", "session", "sessions", "var", "run",
		"proc", "system", "sys", "bin", "sbin", "usr", "opt",
		
		// Common Files
		"robots.txt", "sitemap.xml", "sitemap", "favicon.ico", ".htaccess", "web.config",
		"crossdomain.xml", "clientaccesspolicy.xml", "humans.txt", "security.txt",
		"readme.txt", "README.md", "README", "changelog.txt", "CHANGELOG", "version.txt",
		"license.txt", "LICENSE", "todo.txt", "TODO", "manifest.json",
		
		// Web Technologies
		"index.html", "index.htm", "index.php", "index.asp", "index.aspx", "index.jsp",
		"default.html", "default.htm", "default.php", "home.html", "main.html",
		"phpinfo.php", "info.php", "test.php", "check.php", "health.php", "status.php",
		"wp-config.php", "config.php", "database.php", "db.php", "connect.php",
		
		// Security/Auth
		"auth", "authenticate", "authorization", "oauth", "sso", "ldap", "saml",
		"token", "tokens", "key", "keys", "secret", "secrets", "cert", "certificate",
		"security", "secure", "protected", "private", "internal",
		
		// User/Account
		"user", "users", "account", "accounts", "profile", "profiles", "member", "members",
		"customer", "customers", "client", "clients", "guest", "guests",
		
		// E-commerce
		"shop", "store", "cart", "checkout", "payment", "payments", "order", "orders",
		"product", "products", "catalog", "inventory", "warehouse",
		
		// CMS/Blog
		"blog", "news", "article", "articles", "post", "posts", "page", "pages",
		"category", "categories", "tag", "tags", "comment", "comments",
		"wp-content", "wp-includes", "wp-json", "xmlrpc.php",
		
		// Mobile/App
		"mobile", "app", "application", "android", "ios", "api-docs", "swagger",
		"openapi", "docs", "documentation", "help", "support", "faq",
	}

	wordlistFile := filepath.Join(rawDir, "builtin_wordlist.txt")
	file, err := os.Create(wordlistFile)
	if err != nil {
		return ""
	}
	defer file.Close()

	writer := bufio.NewWriter(file)
	defer writer.Flush()

	for _, path := range builtinPaths {
		writer.WriteString(path + "\n")
	}

	return wordlistFile
}

func (d *DirFuzzPlugin) deduplicateResults(results []FuzzResult) []FuzzResult {
	seen := make(map[string]bool)
	var unique []FuzzResult

	for _, result := range results {
		key := fmt.Sprintf("%s:%d", result.URL, result.StatusCode)
		if !seen[key] {
			seen[key] = true
			unique = append(unique, result)
		}
	}

	return unique
}

func (d *DirFuzzPlugin) isLikelyDirectory(url string, statusCode int) bool {
	// Directories typically:
	// - End with /
	// - Return 301/302 redirects
	// - Have specific status codes
	if strings.HasSuffix(url, "/") {
		return true
	}
	if statusCode == 301 || statusCode == 302 {
		return true
	}
	// File extensions suggest files
	if strings.Contains(filepath.Base(url), ".") {
		return false
	}
	return true
}

func (d *DirFuzzPlugin) displayResults(results []FuzzResult, stats FuzzStats) {
	green := color.New(color.FgGreen).SprintFunc()
	cyan := color.New(color.FgCyan).SprintFunc()
	
	// Results are now displayed in real-time, so just show summary
	fmt.Printf("\n[%s] Fuzzing completed: %d paths discovered\n", cyan("*"), len(results))
	if len(results) == 0 {
		fmt.Printf("[%s] No paths found\n", green("+"))
	}
}

func (d *DirFuzzPlugin) generatePluginResults(target *models.Target, results []FuzzResult, resultsChan chan<- models.PluginResult) {
	for _, result := range results {
		severity := models.SeverityLow
		if result.StatusCode == 200 {
			severity = models.SeverityMedium
		} else if result.StatusCode == 401 || result.StatusCode == 403 {
			severity = models.SeverityMedium
		} else if result.StatusCode >= 500 {
			severity = models.SeverityHigh
		}

		// Increase severity for sensitive paths
		if d.isSensitivePath(result.URL) {
			if severity < models.SeverityHigh {
				severity = models.SeverityHigh
			}
		}

		pluginResult := models.PluginResult{
			Plugin:      "dirfuzz",
			Target:      target.URL,
			Severity:    severity,
			Title:       fmt.Sprintf("Directory/File Found: %d %s", result.StatusCode, result.URL),
			Description: fmt.Sprintf("Found %s with status code %d", result.URL, result.StatusCode),
			Data: map[string]interface{}{
				"url":            result.URL,
				"status_code":    result.StatusCode,
				"content_length": result.ContentLength,
				"content_type":   result.ContentType,
				"response_time":  result.ResponseTime,
				"is_directory":   result.IsDirectory,
				"is_file":        result.IsFile,
				"fuzzed_path":    result.FuzzedPath,
				"wordlist":       result.Wordlist,
				"tool":           result.Tool,
			},
			Timestamp: time.Now(),
		}
		resultsChan <- pluginResult
	}
}

func (d *DirFuzzPlugin) addDiscoveries(shared *core.SharedContext, domain string, results []FuzzResult) {
	for _, result := range results {
		discoveryType := "file"
		if result.IsDirectory {
			discoveryType = "directory"
		}

		shared.AddDiscovery(models.Discovery{
			Type:       discoveryType,
			Value:      result.URL,
			Source:     "dirfuzz",
			Confidence: result.Confidence,
			Timestamp:  time.Now(),
			Metadata: map[string]interface{}{
				"status_code":    result.StatusCode,
				"content_length": result.ContentLength,
				"content_type":   result.ContentType,
				"response_time":  result.ResponseTime.Milliseconds(),
				"fuzzed_path":    result.FuzzedPath,
				"wordlist":       result.Wordlist,
				"tool":           result.Tool,
				"domain":         domain,
			},
		})

		// Add endpoint discovery for accessibility
		shared.AddDiscovery(models.Discovery{
			Type:       "endpoint",
			Value:      result.URL,
			Source:     "dirfuzz",
			Confidence: result.Confidence * 0.9,
			Timestamp:  time.Now(),
			Metadata: map[string]interface{}{
				"method":         "GET",
				"status_code":    result.StatusCode,
				"discovery_type": discoveryType,
				"tool":           result.Tool,
				"domain":         domain,
			},
		})
	}
}

func (d *DirFuzzPlugin) isSensitivePath(url string) bool {
	sensitivePaths := []string{
		"admin", "administrator", "login", "dashboard", "panel",
		"config", "configuration", "settings", "setup",
		"backup", "backups", "database", "db", "export",
		"phpinfo", "info.php", "test.php", ".env", ".git",
		"web.config", ".htaccess", "robots.txt",
	}

	lowerURL := strings.ToLower(url)
	for _, sensitive := range sensitivePaths {
		if strings.Contains(lowerURL, strings.ToLower(sensitive)) {
			return true
		}
	}
	return false
}
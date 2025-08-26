package httpcap

import (
	"bufio"
	"bytes"
	"compress/gzip"
	"context"
	"crypto/sha256"
	"crypto/tls"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/cookiejar"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"

	"github.com/f2u0a0d3/GoRecon/internal/utils"
	"github.com/f2u0a0d3/GoRecon/pkg/core"
	"github.com/rs/zerolog"
)

// CaptureClient provides HTTP request/response capture and storage capabilities
type CaptureClient struct {
	client      *http.Client
	workspace   *core.Workspace
	logger      zerolog.Logger
	robotsCache map[string]*RobotsData
	config      *CaptureConfig
	mutex       sync.RWMutex
	
	// Storage
	requestStorage  *RequestStorage
	responseStorage *ResponseStorage
	
	// Statistics
	stats *CaptureStats
}

// CaptureConfig defines configuration for the HTTP capture client
type CaptureConfig struct {
	Timeout             time.Duration `json:"timeout"`
	MaxRedirects        int           `json:"max_redirects"`
	UserAgent           string        `json:"user_agent"`
	MaxBodySize         int64         `json:"max_body_size"`
	StoreRawBodies      bool          `json:"store_raw_bodies"`
	CompressStorage     bool          `json:"compress_storage"`
	FollowRobots        bool          `json:"follow_robots"`
	EnableCookies       bool          `json:"enable_cookies"`
	InsecureSkipVerify  bool          `json:"insecure_skip_verify"`
	MaxIdleConns        int           `json:"max_idle_conns"`
	IdleConnTimeout     time.Duration `json:"idle_conn_timeout"`
}

// CapturedRequest represents a captured HTTP request
type CapturedRequest struct {
	ID          string            `json:"id"`
	Method      string            `json:"method"`
	URL         string            `json:"url"`
	Proto       string            `json:"proto"`
	Headers     map[string]string `json:"headers"`
	Body        string            `json:"body,omitempty"`
	BodyHash    string            `json:"body_hash"`
	BodySize    int64             `json:"body_size"`
	Timestamp   time.Time         `json:"timestamp"`
	RemoteAddr  string            `json:"remote_addr"`
	UserAgent   string            `json:"user_agent"`
	Referrer    string            `json:"referrer"`
	ContentType string            `json:"content_type"`
}

// CapturedResponse represents a captured HTTP response
type CapturedResponse struct {
	ID              string            `json:"id"`
	RequestID       string            `json:"request_id"`
	StatusCode      int               `json:"status_code"`
	Status          string            `json:"status"`
	Proto           string            `json:"proto"`
	Headers         map[string]string `json:"headers"`
	Body            string            `json:"body,omitempty"`
	BodyHash        string            `json:"body_hash"`
	BodySize        int64             `json:"body_size"`
	Timestamp       time.Time         `json:"timestamp"`
	Duration        time.Duration     `json:"duration"`
	Server          string            `json:"server"`
	ContentType     string            `json:"content_type"`
	ContentEncoding string            `json:"content_encoding"`
	Location        string            `json:"location,omitempty"`
	SetCookies      []string          `json:"set_cookies,omitempty"`
	Technologies    []string          `json:"technologies,omitempty"`
}

// RobotsData represents parsed robots.txt data
type RobotsData struct {
	UserAgent   string    `json:"user_agent"`
	Disallowed  []string  `json:"disallowed"`
	Allowed     []string  `json:"allowed"`
	CrawlDelay  int       `json:"crawl_delay"`
	Sitemap     []string  `json:"sitemap"`
	LastFetched time.Time `json:"last_fetched"`
}

// CaptureStats tracks capture statistics
type CaptureStats struct {
	TotalRequests    int64         `json:"total_requests"`
	TotalResponses   int64         `json:"total_responses"`
	TotalBytes       int64         `json:"total_bytes"`
	AverageLatency   time.Duration `json:"average_latency"`
	StatusCodes      map[int]int64 `json:"status_codes"`
	ContentTypes     map[string]int64 `json:"content_types"`
	ErrorCount       int64         `json:"error_count"`
	StartTime        time.Time     `json:"start_time"`
	LastActivity     time.Time     `json:"last_activity"`
	mutex            sync.RWMutex
}

// RequestStorage handles storage of captured requests
type RequestStorage struct {
	workspace *core.Workspace
	logger    zerolog.Logger
}

// ResponseStorage handles storage of captured responses
type ResponseStorage struct {
	workspace *core.Workspace
	logger    zerolog.Logger
}

// NewCaptureClient creates a new HTTP capture client
func NewCaptureClient(workspace *core.Workspace, config *CaptureConfig, logger zerolog.Logger) *CaptureClient {
	if config == nil {
		config = DefaultCaptureConfig()
	}
	
	// Create HTTP transport with custom settings
	transport := &http.Transport{
		MaxIdleConns:        config.MaxIdleConns,
		IdleConnTimeout:     config.IdleConnTimeout,
		TLSHandshakeTimeout: 10 * time.Second,
		TLSClientConfig: &tls.Config{
			InsecureSkipVerify: config.InsecureSkipVerify,
		},
		DialContext: (&net.Dialer{
			Timeout:   30 * time.Second,
			KeepAlive: 30 * time.Second,
		}).DialContext,
	}
	
	// Create HTTP client
	client := &http.Client{
		Transport: transport,
		Timeout:   config.Timeout,
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			if len(via) >= config.MaxRedirects {
				return fmt.Errorf("stopped after %d redirects", config.MaxRedirects)
			}
			return nil
		},
	}
	
	// Add cookie jar if enabled
	if config.EnableCookies {
		jar, _ := cookiejar.New(nil)
		client.Jar = jar
	}
	
	return &CaptureClient{
		client:          client,
		workspace:       workspace,
		logger:          logger.With().Str("component", "httpcap").Logger(),
		robotsCache:     make(map[string]*RobotsData),
		config:          config,
		requestStorage:  &RequestStorage{workspace: workspace, logger: logger},
		responseStorage: &ResponseStorage{workspace: workspace, logger: logger},
		stats: &CaptureStats{
			StatusCodes:  make(map[int]int64),
			ContentTypes: make(map[string]int64),
			StartTime:    time.Now(),
		},
	}
}

// DefaultCaptureConfig returns default capture configuration
func DefaultCaptureConfig() *CaptureConfig {
	return &CaptureConfig{
		Timeout:            30 * time.Second,
		MaxRedirects:       10,
		UserAgent:          "GoRecon/2.0 (Security Scanner)",
		MaxBodySize:        10 * 1024 * 1024, // 10MB
		StoreRawBodies:     true,
		CompressStorage:    true,
		FollowRobots:       true,
		EnableCookies:      true,
		InsecureSkipVerify: true,
		MaxIdleConns:       100,
		IdleConnTimeout:    90 * time.Second,
	}
}

// Do performs an HTTP request with full capture
func (c *CaptureClient) Do(ctx context.Context, req *http.Request) (*http.Response, *CapturedRequest, *CapturedResponse, error) {
	startTime := time.Now()
	
	// Check robots.txt if enabled
	if c.config.FollowRobots && !c.isAllowedByRobots(req.URL) {
		return nil, nil, nil, fmt.Errorf("disallowed by robots.txt")
	}
	
	// Capture request
	capturedReq := c.captureRequest(req)
	
	// Perform request
	resp, err := c.client.Do(req.WithContext(ctx))
	if err != nil {
		c.updateStats(0, "", time.Since(startTime), true)
		return nil, capturedReq, nil, fmt.Errorf("request failed: %w", err)
	}
	
	// Capture response
	capturedResp := c.captureResponse(resp, capturedReq.ID, time.Since(startTime))
	
	// Store captures
	if err := c.storeCaptures(capturedReq, capturedResp); err != nil {
		c.logger.Error().Err(err).Msg("Failed to store captures")
	}
	
	// Update statistics
	c.updateStats(resp.StatusCode, resp.Header.Get("Content-Type"), time.Since(startTime), false)
	
	return resp, capturedReq, capturedResp, nil
}

// Get performs a GET request with capture
func (c *CaptureClient) Get(ctx context.Context, url string) (*http.Response, *CapturedRequest, *CapturedResponse, error) {
	req, err := http.NewRequest("GET", url, nil)
	if err != nil {
		return nil, nil, nil, fmt.Errorf("failed to create request: %w", err)
	}
	
	// Set user agent
	req.Header.Set("User-Agent", c.config.UserAgent)
	
	return c.Do(ctx, req)
}

// Post performs a POST request with capture
func (c *CaptureClient) Post(ctx context.Context, url, contentType string, body io.Reader) (*http.Response, *CapturedRequest, *CapturedResponse, error) {
	req, err := http.NewRequest("POST", url, body)
	if err != nil {
		return nil, nil, nil, fmt.Errorf("failed to create request: %w", err)
	}
	
	req.Header.Set("Content-Type", contentType)
	req.Header.Set("User-Agent", c.config.UserAgent)
	
	return c.Do(ctx, req)
}

// captureRequest captures and processes an HTTP request
func (c *CaptureClient) captureRequest(req *http.Request) *CapturedRequest {
	requestID := c.generateID("req")
	
	// Read body if present
	var bodyContent []byte
	var bodySize int64
	if req.Body != nil {
		bodyContent, _ = io.ReadAll(req.Body)
		req.Body = io.NopCloser(bytes.NewReader(bodyContent))
		bodySize = int64(len(bodyContent))
	}
	
	// Convert headers to map
	headers := make(map[string]string)
	for key, values := range req.Header {
		headers[key] = strings.Join(values, "; ")
	}
	
	captured := &CapturedRequest{
		ID:          requestID,
		Method:      req.Method,
		URL:         req.URL.String(),
		Proto:       req.Proto,
		Headers:     headers,
		BodySize:    bodySize,
		Timestamp:   time.Now(),
		UserAgent:   req.Header.Get("User-Agent"),
		Referrer:    req.Header.Get("Referer"),
		ContentType: req.Header.Get("Content-Type"),
	}
	
	// Store body if within size limits
	if bodySize > 0 && bodySize <= c.config.MaxBodySize {
		if c.config.StoreRawBodies {
			captured.Body = string(bodyContent)
		}
		captured.BodyHash = utils.HashBytes(bodyContent)
	}
	
	return captured
}

// captureResponse captures and processes an HTTP response
func (c *CaptureClient) captureResponse(resp *http.Response, requestID string, duration time.Duration) *CapturedResponse {
	responseID := c.generateID("resp")
	
	// Read body
	var bodyContent []byte
	if resp.Body != nil {
		bodyContent, _ = io.ReadAll(resp.Body)
		resp.Body = io.NopCloser(bytes.NewReader(bodyContent))
	}
	
	// Convert headers to map
	headers := make(map[string]string)
	for key, values := range resp.Header {
		headers[key] = strings.Join(values, "; ")
	}
	
	// Extract set-cookies
	var setCookies []string
	if cookies := resp.Header["Set-Cookie"]; len(cookies) > 0 {
		setCookies = cookies
	}
	
	captured := &CapturedResponse{
		ID:              responseID,
		RequestID:       requestID,
		StatusCode:      resp.StatusCode,
		Status:          resp.Status,
		Proto:           resp.Proto,
		Headers:         headers,
		BodySize:        int64(len(bodyContent)),
		Timestamp:       time.Now(),
		Duration:        duration,
		Server:          resp.Header.Get("Server"),
		ContentType:     resp.Header.Get("Content-Type"),
		ContentEncoding: resp.Header.Get("Content-Encoding"),
		Location:        resp.Header.Get("Location"),
		SetCookies:      setCookies,
	}
	
	// Store body if within size limits
	if len(bodyContent) > 0 && int64(len(bodyContent)) <= c.config.MaxBodySize {
		if c.config.StoreRawBodies {
			captured.Body = string(bodyContent)
		}
		captured.BodyHash = utils.HashBytes(bodyContent)
	}
	
	// Detect technologies
	captured.Technologies = c.detectTechnologies(resp, bodyContent)
	
	return captured
}

// storeCaptures stores request and response to workspace
func (c *CaptureClient) storeCaptures(req *CapturedRequest, resp *CapturedResponse) error {
	// Store request
	if err := c.requestStorage.Store(req); err != nil {
		return fmt.Errorf("failed to store request: %w", err)
	}
	
	// Store response
	if err := c.responseStorage.Store(resp); err != nil {
		return fmt.Errorf("failed to store response: %w", err)
	}
	
	return nil
}

// isAllowedByRobots checks if URL is allowed by robots.txt
func (c *CaptureClient) isAllowedByRobots(u *url.URL) bool {
	if !c.config.FollowRobots {
		return true
	}
	
	robotsURL := fmt.Sprintf("%s://%s/robots.txt", u.Scheme, u.Host)
	
	c.mutex.RLock()
	robots, exists := c.robotsCache[robotsURL]
	c.mutex.RUnlock()
	
	if !exists || time.Since(robots.LastFetched) > 24*time.Hour {
		// Fetch robots.txt
		robots = c.fetchRobots(robotsURL)
		c.mutex.Lock()
		c.robotsCache[robotsURL] = robots
		c.mutex.Unlock()
	}
	
	if robots == nil {
		return true // No robots.txt or error fetching - allow
	}
	
	// Check if path is disallowed
	path := u.Path
	if path == "" {
		path = "/"
	}
	
	for _, disallowed := range robots.Disallowed {
		if strings.HasPrefix(path, disallowed) {
			return false
		}
	}
	
	return true
}

// fetchRobots fetches and parses robots.txt
func (c *CaptureClient) fetchRobots(robotsURL string) *RobotsData {
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	
	req, err := http.NewRequestWithContext(ctx, "GET", robotsURL, nil)
	if err != nil {
		return nil
	}
	
	resp, err := c.client.Do(req)
	if err != nil {
		return nil
	}
	defer resp.Body.Close()
	
	if resp.StatusCode != 200 {
		return nil
	}
	
	robots := &RobotsData{
		UserAgent:   "*",
		LastFetched: time.Now(),
	}
	
	scanner := bufio.NewScanner(resp.Body)
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		
		if strings.HasPrefix(strings.ToLower(line), "disallow:") {
			path := strings.TrimSpace(line[9:])
			if path != "" {
				robots.Disallowed = append(robots.Disallowed, path)
			}
		} else if strings.HasPrefix(strings.ToLower(line), "allow:") {
			path := strings.TrimSpace(line[6:])
			if path != "" {
				robots.Allowed = append(robots.Allowed, path)
			}
		} else if strings.HasPrefix(strings.ToLower(line), "sitemap:") {
			sitemap := strings.TrimSpace(line[8:])
			if sitemap != "" {
				robots.Sitemap = append(robots.Sitemap, sitemap)
			}
		}
	}
	
	return robots
}

// detectTechnologies detects web technologies from response
func (c *CaptureClient) detectTechnologies(resp *http.Response, body []byte) []string {
	var technologies []string
	
	// Server header detection
	server := resp.Header.Get("Server")
	if server != "" {
		technologies = append(technologies, c.parseServerHeader(server)...)
	}
	
	// X-Powered-By header
	if poweredBy := resp.Header.Get("X-Powered-By"); poweredBy != "" {
		technologies = append(technologies, poweredBy)
	}
	
	// Content analysis
	bodyStr := string(body)
	technologies = append(technologies, c.detectFromContent(bodyStr)...)
	
	return c.deduplicateStrings(technologies)
}

// parseServerHeader parses server header for technologies
func (c *CaptureClient) parseServerHeader(server string) []string {
	var techs []string
	
	serverLower := strings.ToLower(server)
	
	// Common web servers
	if strings.Contains(serverLower, "nginx") {
		techs = append(techs, "Nginx")
	}
	if strings.Contains(serverLower, "apache") {
		techs = append(techs, "Apache")
	}
	if strings.Contains(serverLower, "cloudflare") {
		techs = append(techs, "Cloudflare")
	}
	if strings.Contains(serverLower, "microsoft-iis") {
		techs = append(techs, "IIS")
	}
	
	return techs
}

// detectFromContent detects technologies from response content
func (c *CaptureClient) detectFromContent(content string) []string {
	var technologies []string
	contentLower := strings.ToLower(content)
	
	// JavaScript frameworks
	if strings.Contains(contentLower, "jquery") {
		technologies = append(technologies, "jQuery")
	}
	if strings.Contains(contentLower, "angular") {
		technologies = append(technologies, "Angular")
	}
	if strings.Contains(contentLower, "react") {
		technologies = append(technologies, "React")
	}
	if strings.Contains(contentLower, "vue.js") || strings.Contains(contentLower, "vuejs") {
		technologies = append(technologies, "Vue.js")
	}
	
	// CMS detection
	if strings.Contains(contentLower, "wp-content") || strings.Contains(contentLower, "wordpress") {
		technologies = append(technologies, "WordPress")
	}
	if strings.Contains(contentLower, "drupal") {
		technologies = append(technologies, "Drupal")
	}
	if strings.Contains(contentLower, "joomla") {
		technologies = append(technologies, "Joomla")
	}
	
	return technologies
}

// updateStats updates capture statistics
func (c *CaptureClient) updateStats(statusCode int, contentType string, duration time.Duration, isError bool) {
	c.stats.mutex.Lock()
	defer c.stats.mutex.Unlock()
	
	c.stats.TotalRequests++
	c.stats.LastActivity = time.Now()
	
	if isError {
		c.stats.ErrorCount++
		return
	}
	
	c.stats.TotalResponses++
	c.stats.StatusCodes[statusCode]++
	
	if contentType != "" {
		// Normalize content type
		ct := strings.Split(contentType, ";")[0]
		c.stats.ContentTypes[ct]++
	}
	
	// Update average latency
	totalDuration := c.stats.AverageLatency*time.Duration(c.stats.TotalResponses-1) + duration
	c.stats.AverageLatency = totalDuration / time.Duration(c.stats.TotalResponses)
}

// GetStats returns current capture statistics
func (c *CaptureClient) GetStats() CaptureStats {
	c.stats.mutex.RLock()
	defer c.stats.mutex.RUnlock()
	
	// Create a copy to avoid race conditions
	statsCopy := CaptureStats{
		TotalRequests:  c.stats.TotalRequests,
		TotalResponses: c.stats.TotalResponses,
		TotalBytes:     c.stats.TotalBytes,
		AverageLatency: c.stats.AverageLatency,
		ErrorCount:     c.stats.ErrorCount,
		StartTime:      c.stats.StartTime,
		LastActivity:   c.stats.LastActivity,
		StatusCodes:    make(map[int]int64),
		ContentTypes:   make(map[string]int64),
	}
	
	for k, v := range c.stats.StatusCodes {
		statsCopy.StatusCodes[k] = v
	}
	for k, v := range c.stats.ContentTypes {
		statsCopy.ContentTypes[k] = v
	}
	
	return statsCopy
}

// Implementation helpers

func (c *CaptureClient) generateID(prefix string) string {
	hash := sha256.Sum256([]byte(fmt.Sprintf("%s-%d-%d", prefix, time.Now().UnixNano(), c.stats.TotalRequests)))
	return fmt.Sprintf("%s_%x", prefix, hash[:8])
}

func (c *CaptureClient) deduplicateStrings(input []string) []string {
	seen := make(map[string]bool)
	var result []string
	
	for _, item := range input {
		if !seen[item] {
			seen[item] = true
			result = append(result, item)
		}
	}
	
	return result
}

// Storage implementations

// Store stores a captured request
func (rs *RequestStorage) Store(req *CapturedRequest) error {
	// Create request file
	filename := fmt.Sprintf("%s.json", req.ID)
	
	// Serialize to JSON
	data, err := json.MarshalIndent(req, "", "  ")
	if err != nil {
		return fmt.Errorf("failed to marshal request: %w", err)
	}
	
	// Store in workspace
	if err := rs.workspace.SaveFile("http_requests", filename, data); err != nil {
		return fmt.Errorf("failed to save request file: %w", err)
	}
	
	return nil
}

// Store stores a captured response
func (rs *ResponseStorage) Store(resp *CapturedResponse) error {
	// Create response file
	filename := fmt.Sprintf("%s.json", resp.ID)
	
	// Serialize to JSON
	data, err := json.MarshalIndent(resp, "", "  ")
	if err != nil {
		return fmt.Errorf("failed to marshal response: %w", err)
	}
	
	// Store in workspace
	if err := rs.workspace.SaveFile("http_responses", filename, data); err != nil {
		return fmt.Errorf("failed to save response file: %w", err)
	}
	
	return nil
}

// LoadRequest loads a captured request by ID
func (rs *RequestStorage) LoadRequest(requestID string) (*CapturedRequest, error) {
	filename := fmt.Sprintf("%s.json", requestID)
	
	data, err := rs.workspace.ReadFile("http_requests", filename)
	if err != nil {
		return nil, fmt.Errorf("failed to read request file: %w", err)
	}
	
	var req CapturedRequest
	if err := json.Unmarshal(data, &req); err != nil {
		return nil, fmt.Errorf("failed to unmarshal request: %w", err)
	}
	
	return &req, nil
}

// LoadResponse loads a captured response by ID
func (rs *ResponseStorage) LoadResponse(responseID string) (*CapturedResponse, error) {
	filename := fmt.Sprintf("%s.json", responseID)
	
	data, err := rs.workspace.ReadFile("http_responses", filename)
	if err != nil {
		return nil, fmt.Errorf("failed to read response file: %w", err)
	}
	
	var resp CapturedResponse
	if err := json.Unmarshal(data, &resp); err != nil {
		return nil, fmt.Errorf("failed to unmarshal response: %w", err)
	}
	
	return &resp, nil
}
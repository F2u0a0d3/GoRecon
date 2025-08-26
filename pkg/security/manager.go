package security

import (
	"context"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"encoding/hex"
	"fmt"
	"net/http"
	"os"
	"sync"
	"time"
)

// SecurityManager coordinates all security functionality
type SecurityManager struct {
	sandbox    *Sandbox
	rbac       *RBAC
	validator  *InputValidator
	config     SecurityConfig
	
	// Security monitoring
	threatDetector *ThreatDetector
	auditLogger    *AuditLogger
	
	// Rate limiting
	rateLimiters   map[string]*RateLimiter
	
	mutex sync.RWMutex
}

// SecurityConfig configures the security manager
type SecurityConfig struct {
	EnableSandbox        bool              `json:"enable_sandbox"`
	EnableRBAC          bool              `json:"enable_rbac"`
	EnableValidation    bool              `json:"enable_validation"`
	EnableThreatDetection bool            `json:"enable_threat_detection"`
	EnableAuditLogging  bool              `json:"enable_audit_logging"`
	EnableRateLimiting  bool              `json:"enable_rate_limiting"`
	
	SandboxConfig      SandboxConfig      `json:"sandbox_config"`
	RBACConfig         RBACConfig         `json:"rbac_config"`
	ValidationConfig   ValidationConfig   `json:"validation_config"`
	ThreatConfig       ThreatConfig       `json:"threat_config"`
	AuditConfig        AuditConfig        `json:"audit_config"`
	RateLimitConfig    RateLimitConfig    `json:"rate_limit_config"`
	
	// TLS Configuration
	TLSConfig          TLSSecurityConfig  `json:"tls_config"`
	
	// API Security
	APIKeys            map[string]string  `json:"api_keys"`
	RequireHTTPS       bool              `json:"require_https"`
	AllowedOrigins     []string          `json:"allowed_origins"`
	
	// Plugin Security
	PluginWhitelist    []string          `json:"plugin_whitelist"`
	PluginBlacklist    []string          `json:"plugin_blacklist"`
	RequireSignatures  bool              `json:"require_signatures"`
	
	// Monitoring
	SecurityEventWebhook string           `json:"security_event_webhook"`
	AlertThresholds      AlertThresholds  `json:"alert_thresholds"`
}

// TLS Security Configuration
type TLSSecurityConfig struct {
	MinVersion         uint16   `json:"min_version"`
	MaxVersion         uint16   `json:"max_version"`
	CipherSuites       []uint16 `json:"cipher_suites"`
	PreferServerCiphers bool    `json:"prefer_server_ciphers"`
	CertFile           string   `json:"cert_file"`
	KeyFile            string   `json:"key_file"`
	CAFile             string   `json:"ca_file"`
	ClientAuth         string   `json:"client_auth"` // none, request, require
}

// Alert Thresholds for security events
type AlertThresholds struct {
	FailedAuthPerMinute    int `json:"failed_auth_per_minute"`
	SuspiciousIPPerHour    int `json:"suspicious_ip_per_hour"`
	PluginErrorsPerMinute  int `json:"plugin_errors_per_minute"`
	ResourceUsagePercent   int `json:"resource_usage_percent"`
}

// ThreatDetector monitors for security threats
type ThreatDetector struct {
	config          ThreatConfig
	suspiciousIPs   map[string]*IPThreatInfo
	failedLogins    map[string]int
	pluginErrors    map[string]int
	mutex           sync.RWMutex
}

// ThreatConfig configures threat detection
type ThreatConfig struct {
	EnableIPBlocking      bool          `json:"enable_ip_blocking"`
	MaxFailedLogins       int           `json:"max_failed_logins"`
	BlockDuration         time.Duration `json:"block_duration"`
	SuspiciousPatterns    []string      `json:"suspicious_patterns"`
	MonitoringInterval    time.Duration `json:"monitoring_interval"`
}

// IPThreatInfo tracks threat information for IP addresses
type IPThreatInfo struct {
	IP              string    `json:"ip"`
	FailedLogins    int       `json:"failed_logins"`
	LastFailedLogin time.Time `json:"last_failed_login"`
	Blocked         bool      `json:"blocked"`
	BlockedUntil    time.Time `json:"blocked_until"`
	Reputation      string    `json:"reputation"` // good, suspicious, malicious
}

// AuditLogger handles security audit logging
type AuditLogger struct {
	config   AuditConfig
	events   chan *SecurityEvent
	logFile  string
}

// AuditConfig configures audit logging
type AuditConfig struct {
	LogFile          string        `json:"log_file"`
	LogLevel         string        `json:"log_level"`
	RetentionDays    int           `json:"retention_days"`
	MaxLogSize       int64         `json:"max_log_size"`
	CompressOldLogs  bool          `json:"compress_old_logs"`
	RemoteLogging    bool          `json:"remote_logging"`
	RemoteEndpoint   string        `json:"remote_endpoint"`
	BufferSize       int           `json:"buffer_size"`
	FlushInterval    time.Duration `json:"flush_interval"`
}

// SecurityEvent represents a security-related event
type SecurityEvent struct {
	ID          string                 `json:"id"`
	Type        string                 `json:"type"`
	Severity    string                 `json:"severity"` // low, medium, high, critical
	Source      string                 `json:"source"`
	Target      string                 `json:"target"`
	User        string                 `json:"user"`
	IPAddress   string                 `json:"ip_address"`
	Description string                 `json:"description"`
	Details     map[string]interface{} `json:"details"`
	Timestamp   time.Time              `json:"timestamp"`
}

// RateLimiter implements rate limiting for API endpoints
type RateLimiter struct {
	requests map[string]*RequestCounter
	limit    int
	window   time.Duration
	mutex    sync.RWMutex
}

// RequestCounter tracks requests for rate limiting
type RequestCounter struct {
	Count     int       `json:"count"`
	ResetTime time.Time `json:"reset_time"`
}

// RateLimitConfig configures rate limiting
type RateLimitConfig struct {
	DefaultLimit    int           `json:"default_limit"`
	DefaultWindow   time.Duration `json:"default_window"`
	EndpointLimits  map[string]int `json:"endpoint_limits"`
	UserLimits      map[string]int `json:"user_limits"`
	IPLimits        map[string]int `json:"ip_limits"`
}

// NewSecurityManager creates a new security manager
func NewSecurityManager(config SecurityConfig) (*SecurityManager, error) {
	sm := &SecurityManager{
		config:       config,
		rateLimiters: make(map[string]*RateLimiter),
	}

	var err error

	// Initialize sandbox if enabled
	if config.EnableSandbox {
		sm.sandbox, err = NewSandbox(config.SandboxConfig)
		if err != nil {
			return nil, fmt.Errorf("failed to initialize sandbox: %w", err)
		}
	}

	// Initialize RBAC if enabled
	if config.EnableRBAC {
		sm.rbac = NewRBAC(config.RBACConfig)
	}

	// Initialize input validator if enabled
	if config.EnableValidation {
		sm.validator = NewInputValidator(config.ValidationConfig)
	}

	// Initialize threat detector if enabled
	if config.EnableThreatDetection {
		sm.threatDetector = NewThreatDetector(config.ThreatConfig)
		go sm.threatDetector.Start()
	}

	// Initialize audit logger if enabled
	if config.EnableAuditLogging {
		sm.auditLogger, err = NewAuditLogger(config.AuditConfig)
		if err != nil {
			return nil, fmt.Errorf("failed to initialize audit logger: %w", err)
		}
		go sm.auditLogger.Start()
	}

	// Initialize rate limiters if enabled
	if config.EnableRateLimiting {
		sm.initializeRateLimiters()
	}

	return sm, nil
}

// ExecuteSecurely executes a command in the sandbox
func (sm *SecurityManager) ExecuteSecurely(ctx context.Context, sessionID string, execCtx ExecutionContext) (*ExecutionResult, error) {
	// Check authorization if RBAC is enabled
	if sm.config.EnableRBAC && sm.rbac != nil {
		if err := sm.rbac.Authorize(sessionID, "system", "execute"); err != nil {
			sm.logSecurityEvent("unauthorized_execution", "high", sessionID, "", map[string]interface{}{
				"command": execCtx.Command,
				"error":   err.Error(),
			})
			return nil, fmt.Errorf("authorization failed: %w", err)
		}
	}

	// Validate command if validation is enabled
	if sm.config.EnableValidation && sm.validator != nil {
		result := sm.validator.ValidateCommand(execCtx.Command)
		if !result.Valid {
			sm.logSecurityEvent("invalid_command", "medium", sessionID, "", map[string]interface{}{
				"command": execCtx.Command,
				"errors":  result.Errors,
			})
			return nil, fmt.Errorf("command validation failed: %v", result.Errors)
		}
		execCtx.Command = result.Sanitized
	}

	// Execute in sandbox if enabled
	if sm.config.EnableSandbox && sm.sandbox != nil {
		result, err := sm.sandbox.Execute(ctx, execCtx)
		if err != nil {
			sm.logSecurityEvent("sandbox_execution_failed", "medium", sessionID, "", map[string]interface{}{
				"command": execCtx.Command,
				"error":   err.Error(),
			})
			return nil, err
		}

		sm.logSecurityEvent("sandbox_execution", "low", sessionID, "", map[string]interface{}{
			"command":   execCtx.Command,
			"exit_code": result.ExitCode,
			"duration":  result.Duration.String(),
		})

		return result, nil
	}

	// If sandbox is disabled, return error for security
	return nil, fmt.Errorf("secure execution requires sandbox to be enabled")
}

// AuthenticateUser authenticates a user and creates a session
func (sm *SecurityManager) AuthenticateUser(username, password string, metadata map[string]string) (*Session, error) {
	if !sm.config.EnableRBAC || sm.rbac == nil {
		return nil, fmt.Errorf("RBAC is not enabled")
	}

	// Check rate limiting
	if sm.config.EnableRateLimiting {
		ipAddress := metadata["ip_address"]
		if err := sm.checkRateLimit("auth", ipAddress); err != nil {
			sm.logSecurityEvent("rate_limit_exceeded", "medium", "", ipAddress, map[string]interface{}{
				"endpoint": "auth",
				"username": username,
			})
			return nil, err
		}
	}

	// Check for IP blocking
	if sm.config.EnableThreatDetection && sm.threatDetector != nil {
		if sm.threatDetector.IsBlocked(metadata["ip_address"]) {
			sm.logSecurityEvent("blocked_ip_login_attempt", "high", "", metadata["ip_address"], map[string]interface{}{
				"username": username,
			})
			return nil, fmt.Errorf("IP address is temporarily blocked")
		}
	}

	// Attempt authentication
	session, err := sm.rbac.Authenticate(username, password, metadata)
	if err != nil {
		// Record failed login
		if sm.config.EnableThreatDetection && sm.threatDetector != nil {
			sm.threatDetector.RecordFailedLogin(metadata["ip_address"], username)
		}

		sm.logSecurityEvent("authentication_failed", "medium", "", metadata["ip_address"], map[string]interface{}{
			"username": username,
			"error":    err.Error(),
		})

		return nil, err
	}

	// Successful authentication
	sm.logSecurityEvent("authentication_success", "low", session.UserID, metadata["ip_address"], map[string]interface{}{
		"username":   username,
		"session_id": session.ID,
	})

	return session, nil
}

// ValidateInput validates user input
func (sm *SecurityManager) ValidateInput(input, inputType string) (*ValidationResult, error) {
	if !sm.config.EnableValidation || sm.validator == nil {
		// If validation is disabled, return as valid
		return &ValidationResult{
			Valid:     true,
			Sanitized: input,
			Errors:    []string{},
			Warnings:  []string{},
		}, nil
	}

	switch inputType {
	case "target":
		return sm.validator.ValidateTarget(input), nil
	case "command":
		return sm.validator.ValidateCommand(input), nil
	case "filename":
		return sm.validator.ValidateFilename(input), nil
	case "email":
		return sm.validator.ValidateEmail(input), nil
	case "user_input":
		return sm.validator.ValidateUserInput(input), nil
	case "json":
		return sm.validator.ValidateJSON(input), nil
	default:
		return sm.validator.ValidateUserInput(input), nil
	}
}

// CheckPermission checks if a user has permission to perform an action
func (sm *SecurityManager) CheckPermission(sessionID, resource, action string) error {
	if !sm.config.EnableRBAC || sm.rbac == nil {
		return nil // Permissions disabled
	}

	return sm.rbac.Authorize(sessionID, resource, action)
}

// CreateTLSConfig creates a secure TLS configuration
func (sm *SecurityManager) CreateTLSConfig() (*tls.Config, error) {
	config := &tls.Config{
		MinVersion:               sm.config.TLSConfig.MinVersion,
		MaxVersion:               sm.config.TLSConfig.MaxVersion,
		PreferServerCipherSuites: sm.config.TLSConfig.PreferServerCiphers,
	}

	// Set cipher suites if specified
	if len(sm.config.TLSConfig.CipherSuites) > 0 {
		config.CipherSuites = sm.config.TLSConfig.CipherSuites
	}

	// Load certificates
	if sm.config.TLSConfig.CertFile != "" && sm.config.TLSConfig.KeyFile != "" {
		cert, err := tls.LoadX509KeyPair(sm.config.TLSConfig.CertFile, sm.config.TLSConfig.KeyFile)
		if err != nil {
			return nil, fmt.Errorf("failed to load TLS certificate: %w", err)
		}
		config.Certificates = []tls.Certificate{cert}
	}

	// Load CA certificates for client authentication
	if sm.config.TLSConfig.CAFile != "" {
		caCert, err := os.ReadFile(sm.config.TLSConfig.CAFile)
		if err != nil {
			return nil, fmt.Errorf("failed to read CA certificate: %w", err)
		}

		caCertPool := x509.NewCertPool()
		if !caCertPool.AppendCertsFromPEM(caCert) {
			return nil, fmt.Errorf("failed to parse CA certificate")
		}
		config.ClientCAs = caCertPool

		// Set client authentication mode
		switch sm.config.TLSConfig.ClientAuth {
		case "require":
			config.ClientAuth = tls.RequireAndVerifyClientCert
		case "request":
			config.ClientAuth = tls.RequestClientCert
		default:
			config.ClientAuth = tls.NoClientCert
		}
	}

	return config, nil
}

// CreateSecureHTTPClient creates an HTTP client with security settings
func (sm *SecurityManager) CreateSecureHTTPClient() *http.Client {
	tlsConfig, _ := sm.CreateTLSConfig()
	
	transport := &http.Transport{
		TLSClientConfig: tlsConfig,
		// Additional security settings
		DisableKeepAlives:     false,
		DisableCompression:    false,
		MaxIdleConns:          10,
		IdleConnTimeout:       30 * time.Second,
		TLSHandshakeTimeout:   10 * time.Second,
		ExpectContinueTimeout: 1 * time.Second,
	}

	return &http.Client{
		Transport: transport,
		Timeout:   30 * time.Second,
	}
}

// IsPluginAllowed checks if a plugin is allowed to execute
func (sm *SecurityManager) IsPluginAllowed(pluginName string) bool {
	// Check blacklist first
	for _, blocked := range sm.config.PluginBlacklist {
		if pluginName == blocked {
			return false
		}
	}

	// Check whitelist if configured
	if len(sm.config.PluginWhitelist) > 0 {
		for _, allowed := range sm.config.PluginWhitelist {
			if pluginName == allowed {
				return true
			}
		}
		return false // Not in whitelist
	}

	return true // No restrictions
}

// GetSecurityMetrics returns security metrics
func (sm *SecurityManager) GetSecurityMetrics() SecurityMetrics {
	metrics := SecurityMetrics{
		EnabledModules: make([]string, 0),
	}

	if sm.config.EnableSandbox {
		metrics.EnabledModules = append(metrics.EnabledModules, "sandbox")
	}
	if sm.config.EnableRBAC {
		metrics.EnabledModules = append(metrics.EnabledModules, "rbac")
		if sm.rbac != nil {
			activeSessions := sm.rbac.GetActiveSessions()
			metrics.ActiveSessions = len(activeSessions)
		}
	}
	if sm.config.EnableValidation {
		metrics.EnabledModules = append(metrics.EnabledModules, "validation")
	}
	if sm.config.EnableThreatDetection {
		metrics.EnabledModules = append(metrics.EnabledModules, "threat_detection")
		if sm.threatDetector != nil {
			metrics.BlockedIPs = len(sm.threatDetector.GetBlockedIPs())
		}
	}
	if sm.config.EnableAuditLogging {
		metrics.EnabledModules = append(metrics.EnabledModules, "audit_logging")
	}
	if sm.config.EnableRateLimiting {
		metrics.EnabledModules = append(metrics.EnabledModules, "rate_limiting")
	}

	return metrics
}

// Helper methods

func (sm *SecurityManager) logSecurityEvent(eventType, severity, userID, ipAddress string, details map[string]interface{}) {
	if !sm.config.EnableAuditLogging || sm.auditLogger == nil {
		return
	}

	event := &SecurityEvent{
		ID:          generateID(),
		Type:        eventType,
		Severity:    severity,
		User:        userID,
		IPAddress:   ipAddress,
		Details:     details,
		Timestamp:   time.Now(),
	}

	select {
	case sm.auditLogger.events <- event:
		// Event queued successfully
	default:
		// Channel full, event dropped
	}
}

func (sm *SecurityManager) checkRateLimit(endpoint, identifier string) error {
	sm.mutex.Lock()
	defer sm.mutex.Unlock()

	rateLimiter, exists := sm.rateLimiters[endpoint]
	if !exists {
		// Create new rate limiter for this endpoint
		rateLimiter = &RateLimiter{
			requests: make(map[string]*RequestCounter),
			limit:    sm.config.RateLimitConfig.DefaultLimit,
			window:   sm.config.RateLimitConfig.DefaultWindow,
		}
		sm.rateLimiters[endpoint] = rateLimiter
	}

	return rateLimiter.CheckLimit(identifier)
}

func (sm *SecurityManager) initializeRateLimiters() {
	// Initialize rate limiters for common endpoints
	endpoints := []string{"auth", "scan", "api", "download"}
	
	for _, endpoint := range endpoints {
		limit := sm.config.RateLimitConfig.DefaultLimit
		if endpointLimit, exists := sm.config.RateLimitConfig.EndpointLimits[endpoint]; exists {
			limit = endpointLimit
		}

		sm.rateLimiters[endpoint] = &RateLimiter{
			requests: make(map[string]*RequestCounter),
			limit:    limit,
			window:   sm.config.RateLimitConfig.DefaultWindow,
		}
	}
}

// SecurityMetrics provides security-related metrics
type SecurityMetrics struct {
	EnabledModules  []string `json:"enabled_modules"`
	ActiveSessions  int      `json:"active_sessions"`
	BlockedIPs      int      `json:"blocked_ips"`
	TotalAuditEvents int64   `json:"total_audit_events"`
}

// CheckLimit checks if the rate limit has been exceeded
func (rl *RateLimiter) CheckLimit(identifier string) error {
	rl.mutex.Lock()
	defer rl.mutex.Unlock()

	now := time.Now()
	counter, exists := rl.requests[identifier]

	if !exists || now.After(counter.ResetTime) {
		// Create new counter or reset expired counter
		rl.requests[identifier] = &RequestCounter{
			Count:     1,
			ResetTime: now.Add(rl.window),
		}
		return nil
	}

	if counter.Count >= rl.limit {
		return fmt.Errorf("rate limit exceeded: %d requests per %v", rl.limit, rl.window)
	}

	counter.Count++
	return nil
}

// Close gracefully shuts down the security manager
func (sm *SecurityManager) Close() error {
	if sm.sandbox != nil {
		sm.sandbox.Close()
	}
	
	if sm.auditLogger != nil {
		close(sm.auditLogger.events)
	}

	return nil
}

// Helper functions for missing implementations

// NewThreatDetector creates a new threat detector
func NewThreatDetector(config ThreatConfig) *ThreatDetector {
	return &ThreatDetector{
		config:        config,
		suspiciousIPs: make(map[string]*IPThreatInfo),
		failedLogins:  make(map[string]int),
		pluginErrors:  make(map[string]int),
	}
}

// Start begins threat monitoring
func (td *ThreatDetector) Start() {
	ticker := time.NewTicker(td.config.MonitoringInterval)
	defer ticker.Stop()

	for range ticker.C {
		td.cleanupExpiredBlocks()
	}
}

// IsBlocked checks if an IP is currently blocked
func (td *ThreatDetector) IsBlocked(ip string) bool {
	td.mutex.RLock()
	defer td.mutex.RUnlock()

	if info, exists := td.suspiciousIPs[ip]; exists {
		if info.Blocked && time.Now().Before(info.BlockedUntil) {
			return true
		}
	}
	return false
}

// RecordFailedLogin records a failed login attempt
func (td *ThreatDetector) RecordFailedLogin(ip, username string) {
	td.mutex.Lock()
	defer td.mutex.Unlock()

	td.failedLogins[ip]++
	
	if td.failedLogins[ip] >= td.config.MaxFailedLogins {
		// Block the IP
		info := &IPThreatInfo{
			IP:              ip,
			FailedLogins:    td.failedLogins[ip],
			LastFailedLogin: time.Now(),
			Blocked:         true,
			BlockedUntil:    time.Now().Add(td.config.BlockDuration),
			Reputation:      "suspicious",
		}
		td.suspiciousIPs[ip] = info
	}
}

// GetBlockedIPs returns a list of currently blocked IPs
func (td *ThreatDetector) GetBlockedIPs() []string {
	td.mutex.RLock()
	defer td.mutex.RUnlock()

	var blocked []string
	for ip, info := range td.suspiciousIPs {
		if info.Blocked && time.Now().Before(info.BlockedUntil) {
			blocked = append(blocked, ip)
		}
	}
	return blocked
}

// cleanupExpiredBlocks removes expired IP blocks
func (td *ThreatDetector) cleanupExpiredBlocks() {
	td.mutex.Lock()
	defer td.mutex.Unlock()

	now := time.Now()
	for ip, info := range td.suspiciousIPs {
		if info.Blocked && now.After(info.BlockedUntil) {
			delete(td.suspiciousIPs, ip)
			delete(td.failedLogins, ip)
		}
	}
}

// NewAuditLogger creates a new audit logger
func NewAuditLogger(config AuditConfig) (*AuditLogger, error) {
	if config.BufferSize == 0 {
		config.BufferSize = 1000
	}
	if config.FlushInterval == 0 {
		config.FlushInterval = 30 * time.Second
	}

	return &AuditLogger{
		config:  config,
		events:  make(chan *SecurityEvent, config.BufferSize),
		logFile: config.LogFile,
	}, nil
}

// Start begins audit log processing
func (al *AuditLogger) Start() {
	ticker := time.NewTicker(al.config.FlushInterval)
	defer ticker.Stop()

	for {
		select {
		case event := <-al.events:
			al.writeEvent(event)
		case <-ticker.C:
			// Periodic flush if needed
		}
	}
}

// writeEvent writes a security event to the log
func (al *AuditLogger) writeEvent(event *SecurityEvent) {
	// In a production system, this would write to a proper log file
	// with rotation, compression, etc.
	fmt.Printf("SECURITY_EVENT: %+v\n", event)
}

// generateID generates a random ID
func generateID() string {
	bytes := make([]byte, 16)
	rand.Read(bytes)
	return hex.EncodeToString(bytes)
}
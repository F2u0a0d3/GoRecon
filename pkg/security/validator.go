package security

import (
	"encoding/json"
	"fmt"
	"net"
	"net/url"
	"regexp"
	"strings"
	"unicode"
)

// InputValidator provides comprehensive input validation and sanitization
type InputValidator struct {
	config ValidationConfig
}

// ValidationConfig configures validation rules
type ValidationConfig struct {
	MaxStringLength    int      `json:"max_string_length"`
	AllowedProtocols   []string `json:"allowed_protocols"`
	BlockedDomains     []string `json:"blocked_domains"`
	AllowPrivateIPs    bool     `json:"allow_private_ips"`
	AllowLocalhostIPs  bool     `json:"allow_localhost_ips"`
	MaxTargetsPerScan  int      `json:"max_targets_per_scan"`
	AllowedFileTypes   []string `json:"allowed_file_types"`
	MaxFileSize        int64    `json:"max_file_size"`
	StrictMode         bool     `json:"strict_mode"`
}

// ValidationResult contains validation results
type ValidationResult struct {
	Valid      bool     `json:"valid"`
	Sanitized  string   `json:"sanitized"`
	Errors     []string `json:"errors"`
	Warnings   []string `json:"warnings"`
}

// Common regex patterns
var (
	domainRegex    = regexp.MustCompile(`^[a-zA-Z0-9]([a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?(\.[a-zA-Z0-9]([a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?)*$`)
	emailRegex     = regexp.MustCompile(`^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$`)
	alphanumRegex  = regexp.MustCompile(`^[a-zA-Z0-9]+$`)
	filenameRegex  = regexp.MustCompile(`^[a-zA-Z0-9\-_.]+$`)
	commandRegex   = regexp.MustCompile(`^[a-zA-Z0-9\-_/]+$`)
	
	// Dangerous patterns to detect
	sqlInjectionPatterns = []*regexp.Regexp{
		regexp.MustCompile(`(?i)(union|select|insert|update|delete|drop|exec|execute)`),
		regexp.MustCompile(`['";\-\-]`),
	}
	
	xssPatterns = []*regexp.Regexp{
		regexp.MustCompile(`(?i)<script`),
		regexp.MustCompile(`(?i)javascript:`),
		regexp.MustCompile(`(?i)on\w+\s*=`),
		regexp.MustCompile(`(?i)expression\s*\(`),
	}
	
	commandInjectionPatterns = []*regexp.Regexp{
		regexp.MustCompile(`[;&|><\$\`\\]`),
		regexp.MustCompile(`\.\./`),
		regexp.MustCompile(`(?i)(rm|del|format|fdisk|mkfs)`),
	}
)

// NewInputValidator creates a new input validator
func NewInputValidator(config ValidationConfig) *InputValidator {
	// Set defaults
	if config.MaxStringLength == 0 {
		config.MaxStringLength = 1000
	}
	if len(config.AllowedProtocols) == 0 {
		config.AllowedProtocols = []string{"http", "https"}
	}
	if config.MaxTargetsPerScan == 0 {
		config.MaxTargetsPerScan = 1000
	}
	if len(config.AllowedFileTypes) == 0 {
		config.AllowedFileTypes = []string{".txt", ".json", ".csv", ".xml"}
	}
	if config.MaxFileSize == 0 {
		config.MaxFileSize = 10 * 1024 * 1024 // 10MB
	}

	return &InputValidator{config: config}
}

// ValidateTarget validates a target URL or domain
func (v *InputValidator) ValidateTarget(target string) *ValidationResult {
	result := &ValidationResult{
		Valid:     true,
		Sanitized: target,
		Errors:    []string{},
		Warnings:  []string{},
	}

	// Basic sanitization
	target = strings.TrimSpace(target)
	target = strings.ToLower(target)

	if target == "" {
		result.Valid = false
		result.Errors = append(result.Errors, "target cannot be empty")
		return result
	}

	// Check length
	if len(target) > v.config.MaxStringLength {
		result.Valid = false
		result.Errors = append(result.Errors, fmt.Sprintf("target exceeds maximum length of %d", v.config.MaxStringLength))
		return result
	}

	// Try to parse as URL first
	if strings.Contains(target, "://") {
		return v.validateURL(target, result)
	}

	// Try to parse as IP address
	if ip := net.ParseIP(target); ip != nil {
		return v.validateIP(target, ip, result)
	}

	// Assume it's a domain name
	return v.validateDomain(target, result)
}

// validateURL validates a complete URL
func (v *InputValidator) validateURL(target string, result *ValidationResult) *ValidationResult {
	parsedURL, err := url.Parse(target)
	if err != nil {
		result.Valid = false
		result.Errors = append(result.Errors, fmt.Sprintf("invalid URL format: %v", err))
		return result
	}

	// Check protocol
	if !v.isProtocolAllowed(parsedURL.Scheme) {
		result.Valid = false
		result.Errors = append(result.Errors, fmt.Sprintf("protocol '%s' not allowed", parsedURL.Scheme))
		return result
	}

	// Validate hostname
	if parsedURL.Hostname() != "" {
		hostResult := v.ValidateTarget(parsedURL.Hostname())
		if !hostResult.Valid {
			result.Valid = false
			result.Errors = append(result.Errors, hostResult.Errors...)
			return result
		}
		result.Warnings = append(result.Warnings, hostResult.Warnings...)
	}

	// Check for suspicious patterns
	if v.containsDangerousPatterns(target) {
		result.Valid = false
		result.Errors = append(result.Errors, "target contains potentially dangerous patterns")
		return result
	}

	result.Sanitized = parsedURL.String()
	return result
}

// validateIP validates an IP address
func (v *InputValidator) validateIP(target string, ip net.IP, result *ValidationResult) *ValidationResult {
	// Check if it's a private IP
	if v.isPrivateIP(ip) && !v.config.AllowPrivateIPs {
		result.Valid = false
		result.Errors = append(result.Errors, "private IP addresses are not allowed")
		return result
	}

	// Check if it's localhost
	if v.isLocalhostIP(ip) && !v.config.AllowLocalhostIPs {
		result.Valid = false
		result.Errors = append(result.Errors, "localhost addresses are not allowed")
		return result
	}

	// Check for reserved ranges
	if v.isReservedIP(ip) {
		result.Valid = false
		result.Errors = append(result.Errors, "reserved IP addresses are not allowed")
		return result
	}

	result.Sanitized = ip.String()
	return result
}

// validateDomain validates a domain name
func (v *InputValidator) validateDomain(target string, result *ValidationResult) *ValidationResult {
	// Check basic format
	if !domainRegex.MatchString(target) {
		result.Valid = false
		result.Errors = append(result.Errors, "invalid domain format")
		return result
	}

	// Check against blocked domains
	for _, blocked := range v.config.BlockedDomains {
		if strings.Contains(target, blocked) {
			result.Valid = false
			result.Errors = append(result.Errors, fmt.Sprintf("domain matches blocked pattern: %s", blocked))
			return result
		}
	}

	// Check for suspicious patterns
	if v.containsDangerousPatterns(target) {
		result.Valid = false
		result.Errors = append(result.Errors, "domain contains potentially dangerous patterns")
		return result
	}

	result.Sanitized = target
	return result
}

// ValidateCommand validates a command name for plugin execution
func (v *InputValidator) ValidateCommand(command string) *ValidationResult {
	result := &ValidationResult{
		Valid:     true,
		Sanitized: command,
		Errors:    []string{},
		Warnings:  []string{},
	}

	command = strings.TrimSpace(command)

	if command == "" {
		result.Valid = false
		result.Errors = append(result.Errors, "command cannot be empty")
		return result
	}

	// Check for command injection patterns
	for _, pattern := range commandInjectionPatterns {
		if pattern.MatchString(command) {
			result.Valid = false
			result.Errors = append(result.Errors, "command contains potentially dangerous characters")
			return result
		}
	}

	// Validate command format
	if !commandRegex.MatchString(command) {
		result.Valid = false
		result.Errors = append(result.Errors, "command contains invalid characters")
		return result
	}

	result.Sanitized = command
	return result
}

// ValidateFilename validates a filename
func (v *InputValidator) ValidateFilename(filename string) *ValidationResult {
	result := &ValidationResult{
		Valid:     true,
		Sanitized: filename,
		Errors:    []string{},
		Warnings:  []string{},
	}

	filename = strings.TrimSpace(filename)

	if filename == "" {
		result.Valid = false
		result.Errors = append(result.Errors, "filename cannot be empty")
		return result
	}

	// Check for path traversal
	if strings.Contains(filename, "..") {
		result.Valid = false
		result.Errors = append(result.Errors, "filename contains path traversal")
		return result
	}

	// Check for null bytes
	if strings.Contains(filename, "\x00") {
		result.Valid = false
		result.Errors = append(result.Errors, "filename contains null bytes")
		return result
	}

	// Validate filename format
	if !filenameRegex.MatchString(filename) {
		result.Valid = false
		result.Errors = append(result.Errors, "filename contains invalid characters")
		return result
	}

	// Check file extension if configured
	if len(v.config.AllowedFileTypes) > 0 {
		allowed := false
		for _, ext := range v.config.AllowedFileTypes {
			if strings.HasSuffix(filename, ext) {
				allowed = true
				break
			}
		}
		if !allowed {
			result.Valid = false
			result.Errors = append(result.Errors, "file type not allowed")
			return result
		}
	}

	result.Sanitized = filename
	return result
}

// ValidateEmail validates an email address
func (v *InputValidator) ValidateEmail(email string) *ValidationResult {
	result := &ValidationResult{
		Valid:     true,
		Sanitized: email,
		Errors:    []string{},
		Warnings:  []string{},
	}

	email = strings.TrimSpace(strings.ToLower(email))

	if email == "" {
		result.Valid = false
		result.Errors = append(result.Errors, "email cannot be empty")
		return result
	}

	if !emailRegex.MatchString(email) {
		result.Valid = false
		result.Errors = append(result.Errors, "invalid email format")
		return result
	}

	result.Sanitized = email
	return result
}

// ValidateUserInput validates general user input for XSS and injection attacks
func (v *InputValidator) ValidateUserInput(input string) *ValidationResult {
	result := &ValidationResult{
		Valid:     true,
		Sanitized: input,
		Errors:    []string{},
		Warnings:  []string{},
	}

	if len(input) > v.config.MaxStringLength {
		result.Valid = false
		result.Errors = append(result.Errors, fmt.Sprintf("input exceeds maximum length of %d", v.config.MaxStringLength))
		return result
	}

	// Check for SQL injection patterns
	for _, pattern := range sqlInjectionPatterns {
		if pattern.MatchString(input) {
			if v.config.StrictMode {
				result.Valid = false
				result.Errors = append(result.Errors, "input contains potential SQL injection patterns")
			} else {
				result.Warnings = append(result.Warnings, "input contains potential SQL injection patterns")
			}
		}
	}

	// Check for XSS patterns
	for _, pattern := range xssPatterns {
		if pattern.MatchString(input) {
			if v.config.StrictMode {
				result.Valid = false
				result.Errors = append(result.Errors, "input contains potential XSS patterns")
			} else {
				result.Warnings = append(result.Warnings, "input contains potential XSS patterns")
				result.Sanitized = v.sanitizeXSS(input)
			}
		}
	}

	// Check for control characters
	if v.containsControlCharacters(input) {
		result.Valid = false
		result.Errors = append(result.Errors, "input contains control characters")
		return result
	}

	return result
}

// ValidateTargetList validates a list of targets
func (v *InputValidator) ValidateTargetList(targets []string) *ValidationResult {
	result := &ValidationResult{
		Valid:     true,
		Sanitized: "",
		Errors:    []string{},
		Warnings:  []string{},
	}

	if len(targets) == 0 {
		result.Valid = false
		result.Errors = append(result.Errors, "target list cannot be empty")
		return result
	}

	if len(targets) > v.config.MaxTargetsPerScan {
		result.Valid = false
		result.Errors = append(result.Errors, fmt.Sprintf("too many targets: %d (max %d)", len(targets), v.config.MaxTargetsPerScan))
		return result
	}

	var sanitizedTargets []string
	for i, target := range targets {
		targetResult := v.ValidateTarget(target)
		if !targetResult.Valid {
			result.Valid = false
			for _, err := range targetResult.Errors {
				result.Errors = append(result.Errors, fmt.Sprintf("target %d: %s", i+1, err))
			}
		} else {
			sanitizedTargets = append(sanitizedTargets, targetResult.Sanitized)
		}
		result.Warnings = append(result.Warnings, targetResult.Warnings...)
	}

	result.Sanitized = strings.Join(sanitizedTargets, ",")
	return result
}

// Helper methods

func (v *InputValidator) isProtocolAllowed(protocol string) bool {
	for _, allowed := range v.config.AllowedProtocols {
		if protocol == allowed {
			return true
		}
	}
	return false
}

func (v *InputValidator) isPrivateIP(ip net.IP) bool {
	private := []string{
		"10.0.0.0/8",
		"172.16.0.0/12",
		"192.168.0.0/16",
	}

	for _, cidr := range private {
		_, ipnet, _ := net.ParseCIDR(cidr)
		if ipnet.Contains(ip) {
			return true
		}
	}
	return false
}

func (v *InputValidator) isLocalhostIP(ip net.IP) bool {
	return ip.IsLoopback()
}

func (v *InputValidator) isReservedIP(ip net.IP) bool {
	// Check for various reserved ranges
	reserved := []string{
		"0.0.0.0/8",       // Current network
		"127.0.0.0/8",     // Loopback
		"169.254.0.0/16",  // Link-local
		"224.0.0.0/4",     // Multicast
		"240.0.0.0/4",     // Reserved
	}

	for _, cidr := range reserved {
		_, ipnet, _ := net.ParseCIDR(cidr)
		if ipnet.Contains(ip) {
			return true
		}
	}
	return false
}

func (v *InputValidator) containsDangerousPatterns(input string) bool {
	// Check for various dangerous patterns
	dangerousPatterns := []string{
		"javascript:",
		"data:",
		"vbscript:",
		"<script",
		"</script>",
		"eval(",
		"expression(",
		"onload=",
		"onerror=",
	}

	inputLower := strings.ToLower(input)
	for _, pattern := range dangerousPatterns {
		if strings.Contains(inputLower, pattern) {
			return true
		}
	}

	return false
}

func (v *InputValidator) containsControlCharacters(input string) bool {
	for _, char := range input {
		if unicode.IsControl(char) && char != '\n' && char != '\r' && char != '\t' {
			return true
		}
	}
	return false
}

func (v *InputValidator) sanitizeXSS(input string) string {
	// Basic XSS sanitization
	sanitized := input
	
	// Remove script tags
	scriptRegex := regexp.MustCompile(`(?i)<script[^>]*>.*?</script>`)
	sanitized = scriptRegex.ReplaceAllString(sanitized, "")
	
	// Remove javascript: URLs
	jsRegex := regexp.MustCompile(`(?i)javascript:`)
	sanitized = jsRegex.ReplaceAllString(sanitized, "")
	
	// Remove event handlers
	eventRegex := regexp.MustCompile(`(?i)on\w+\s*=\s*['""][^'"]*['"]`)
	sanitized = eventRegex.ReplaceAllString(sanitized, "")
	
	return sanitized
}

// SanitizeForShell sanitizes input for safe shell execution
func (v *InputValidator) SanitizeForShell(input string) string {
	// Remove or escape dangerous shell characters
	dangerous := []string{";", "&", "|", ">", "<", "$", "`", "\\", "\"", "'"}
	
	sanitized := input
	for _, char := range dangerous {
		sanitized = strings.ReplaceAll(sanitized, char, "\\"+char)
	}
	
	return sanitized
}

// SanitizeForSQL sanitizes input for SQL queries (basic protection)
func (v *InputValidator) SanitizeForSQL(input string) string {
	// Basic SQL sanitization - escape single quotes
	return strings.ReplaceAll(input, "'", "''")
}

// ValidateJSON validates JSON input
func (v *InputValidator) ValidateJSON(jsonStr string) *ValidationResult {
	result := &ValidationResult{
		Valid:     true,
		Sanitized: jsonStr,
		Errors:    []string{},
		Warnings:  []string{},
	}

	if len(jsonStr) > v.config.MaxStringLength {
		result.Valid = false
		result.Errors = append(result.Errors, fmt.Sprintf("JSON exceeds maximum length of %d", v.config.MaxStringLength))
		return result
	}

	// Try to parse JSON to validate structure
	var obj interface{}
	if err := json.Unmarshal([]byte(jsonStr), &obj); err != nil {
		result.Valid = false
		result.Errors = append(result.Errors, fmt.Sprintf("invalid JSON: %v", err))
		return result
	}

	return result
}

// GetConfig returns the current validation configuration
func (v *InputValidator) GetConfig() ValidationConfig {
	return v.config
}

// UpdateConfig updates the validation configuration
func (v *InputValidator) UpdateConfig(config ValidationConfig) {
	v.config = config
}
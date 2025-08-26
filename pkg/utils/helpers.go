package utils

import (
	"crypto/md5"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"net/url"
	"os"
	"path/filepath"
	"reflect"
	"regexp"
	"strconv"
	"strings"
	"time"
	"unicode"

	"github.com/rs/zerolog/log"
)

// String utilities

func SafeString(s *string) string {
	if s == nil {
		return ""
	}
	return *s
}

func StringPtr(s string) *string {
	return &s
}

func IsEmpty(s string) bool {
	return strings.TrimSpace(s) == ""
}

func TruncateString(s string, maxLen int) string {
	if len(s) <= maxLen {
		return s
	}
	return s[:maxLen-3] + "..."
}

func SanitizeString(s string) string {
	// Remove non-printable characters
	return strings.Map(func(r rune) rune {
		if unicode.IsPrint(r) {
			return r
		}
		return -1
	}, s)
}

func SplitAndTrim(s, sep string) []string {
	if s == "" {
		return []string{}
	}
	
	parts := strings.Split(s, sep)
	result := make([]string, 0, len(parts))
	
	for _, part := range parts {
		if trimmed := strings.TrimSpace(part); trimmed != "" {
			result = append(result, trimmed)
		}
	}
	
	return result
}

func ContainsIgnoreCase(s, substr string) bool {
	return strings.Contains(strings.ToLower(s), strings.ToLower(substr))
}

func StartsWithAny(s string, prefixes []string) bool {
	for _, prefix := range prefixes {
		if strings.HasPrefix(s, prefix) {
			return true
		}
	}
	return false
}

// URL utilities

func IsValidURL(s string) bool {
	u, err := url.Parse(s)
	return err == nil && u.Scheme != "" && u.Host != ""
}

func NormalizeURL(rawURL string) (string, error) {
	u, err := url.Parse(rawURL)
	if err != nil {
		return "", err
	}
	
	// Ensure scheme
	if u.Scheme == "" {
		u.Scheme = "https"
	}
	
	// Remove default ports
	if (u.Scheme == "http" && u.Port() == "80") ||
	   (u.Scheme == "https" && u.Port() == "443") {
		u.Host = u.Hostname()
	}
	
	// Remove fragment
	u.Fragment = ""
	
	// Sort query parameters for consistency
	if u.RawQuery != "" {
		values := u.Query()
		u.RawQuery = values.Encode()
	}
	
	return u.String(), nil
}

func ExtractDomain(rawURL string) (string, error) {
	u, err := url.Parse(rawURL)
	if err != nil {
		return "", err
	}
	return u.Hostname(), nil
}

func IsSubdomain(subdomain, domain string) bool {
	if subdomain == domain {
		return false
	}
	return strings.HasSuffix(subdomain, "."+domain)
}

// File utilities

func FileExists(path string) bool {
	_, err := os.Stat(path)
	return !os.IsNotExist(err)
}

func DirExists(path string) bool {
	info, err := os.Stat(path)
	return !os.IsNotExist(err) && info.IsDir()
}

func EnsureDir(path string) error {
	return os.MkdirAll(path, 0755)
}

func WriteFileAtomic(filename string, data []byte, perm os.FileMode) error {
	dir := filepath.Dir(filename)
	if err := EnsureDir(dir); err != nil {
		return err
	}
	
	tmpFile := filename + ".tmp"
	if err := os.WriteFile(tmpFile, data, perm); err != nil {
		return err
	}
	
	return os.Rename(tmpFile, filename)
}

func ReadFileLines(path string) ([]string, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	
	content := string(data)
	lines := strings.Split(content, "\n")
	
	// Remove empty lines and trim whitespace
	result := make([]string, 0, len(lines))
	for _, line := range lines {
		if trimmed := strings.TrimSpace(line); trimmed != "" {
			result = append(result, trimmed)
		}
	}
	
	return result, nil
}

func GetFileSize(path string) (int64, error) {
	info, err := os.Stat(path)
	if err != nil {
		return 0, err
	}
	return info.Size(), nil
}

// Hash utilities

func MD5Hash(data string) string {
	hash := md5.Sum([]byte(data))
	return hex.EncodeToString(hash[:])
}

func SHA256Hash(data string) string {
	hash := sha256.Sum256([]byte(data))
	return hex.EncodeToString(hash[:])
}

func GenerateRandomID() string {
	bytes := make([]byte, 16)
	if _, err := rand.Read(bytes); err != nil {
		// Fallback to timestamp-based ID
		return fmt.Sprintf("%d", time.Now().UnixNano())
	}
	return hex.EncodeToString(bytes)
}

func GenerateShortID() string {
	bytes := make([]byte, 4)
	if _, err := rand.Read(bytes); err != nil {
		return fmt.Sprintf("%d", time.Now().Unix()%10000)
	}
	return hex.EncodeToString(bytes)
}

// JSON utilities

func ToJSONString(v interface{}) string {
	data, err := json.Marshal(v)
	if err != nil {
		return fmt.Sprintf("error: %v", err)
	}
	return string(data)
}

func ToJSONPretty(v interface{}) string {
	data, err := json.MarshalIndent(v, "", "  ")
	if err != nil {
		return fmt.Sprintf("error: %v", err)
	}
	return string(data)
}

func FromJSONString(s string, v interface{}) error {
	return json.Unmarshal([]byte(s), v)
}

// Slice utilities

func UniqueStrings(slice []string) []string {
	keys := make(map[string]bool)
	result := make([]string, 0, len(slice))
	
	for _, item := range slice {
		if !keys[item] {
			keys[item] = true
			result = append(result, item)
		}
	}
	
	return result
}

func StringSliceContains(slice []string, item string) bool {
	for _, s := range slice {
		if s == item {
			return true
		}
	}
	return false
}

func StringSliceContainsIgnoreCase(slice []string, item string) bool {
	lower := strings.ToLower(item)
	for _, s := range slice {
		if strings.ToLower(s) == lower {
			return true
		}
	}
	return false
}

func RemoveStringFromSlice(slice []string, item string) []string {
	result := make([]string, 0, len(slice))
	for _, s := range slice {
		if s != item {
			result = append(result, s)
		}
	}
	return result
}

func IntersectStrings(slice1, slice2 []string) []string {
	set := make(map[string]bool)
	for _, s := range slice1 {
		set[s] = true
	}
	
	result := make([]string, 0)
	for _, s := range slice2 {
		if set[s] {
			result = append(result, s)
		}
	}
	
	return result
}

// Map utilities

func MergeStringMaps(maps ...map[string]string) map[string]string {
	result := make(map[string]string)
	for _, m := range maps {
		for k, v := range m {
			result[k] = v
		}
	}
	return result
}

func MapKeys(m map[string]interface{}) []string {
	keys := make([]string, 0, len(m))
	for k := range m {
		keys = append(keys, k)
	}
	return keys
}

func MapStringKeys(m map[string]string) []string {
	keys := make([]string, 0, len(m))
	for k := range m {
		keys = append(keys, k)
	}
	return keys
}

// Type conversion utilities

func IntPtr(i int) *int {
	return &i
}

func Float64Ptr(f float64) *float64 {
	return &f
}

func BoolPtr(b bool) *bool {
	return &b
}

func SafeInt(s string, defaultValue int) int {
	if i, err := strconv.Atoi(s); err == nil {
		return i
	}
	return defaultValue
}

func SafeFloat64(s string, defaultValue float64) float64 {
	if f, err := strconv.ParseFloat(s, 64); err == nil {
		return f
	}
	return defaultValue
}

func SafeBool(s string, defaultValue bool) bool {
	if b, err := strconv.ParseBool(s); err == nil {
		return b
	}
	return defaultValue
}

func ToString(v interface{}) string {
	switch val := v.(type) {
	case string:
		return val
	case int, int8, int16, int32, int64:
		return fmt.Sprintf("%d", val)
	case uint, uint8, uint16, uint32, uint64:
		return fmt.Sprintf("%d", val)
	case float32, float64:
		return fmt.Sprintf("%g", val)
	case bool:
		return strconv.FormatBool(val)
	case nil:
		return ""
	default:
		return fmt.Sprintf("%v", val)
	}
}

// Validation utilities

func IsValidEmail(email string) bool {
	emailRegex := regexp.MustCompile(`^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$`)
	return emailRegex.MatchString(email)
}

func IsValidIPv4(ip string) bool {
	ipRegex := regexp.MustCompile(`^(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)$`)
	return ipRegex.MatchString(ip)
}

func IsValidDomain(domain string) bool {
	domainRegex := regexp.MustCompile(`^[a-zA-Z0-9]([a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?(\.[a-zA-Z0-9]([a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?)*$`)
	return len(domain) <= 253 && domainRegex.MatchString(domain)
}

// Time utilities

func FormatDuration(d time.Duration) string {
	if d < time.Minute {
		return fmt.Sprintf("%.1fs", d.Seconds())
	}
	if d < time.Hour {
		return fmt.Sprintf("%.1fm", d.Minutes())
	}
	if d < 24*time.Hour {
		return fmt.Sprintf("%.1fh", d.Hours())
	}
	days := d.Hours() / 24
	return fmt.Sprintf("%.1fd", days)
}

func ParseDurationFromString(s string) (time.Duration, error) {
	// Try standard format first
	if d, err := time.ParseDuration(s); err == nil {
		return d, nil
	}
	
	// Try custom formats
	if strings.HasSuffix(s, "d") {
		days, err := strconv.ParseFloat(strings.TrimSuffix(s, "d"), 64)
		if err != nil {
			return 0, err
		}
		return time.Duration(days * 24 * float64(time.Hour)), nil
	}
	
	return 0, fmt.Errorf("invalid duration format: %s", s)
}

func TimePtr(t time.Time) *time.Time {
	return &t
}

func SafeTime(t *time.Time) time.Time {
	if t == nil {
		return time.Time{}
	}
	return *t
}

// Security utilities

func SanitizeForLog(s string) string {
	// Remove potentially sensitive information from logs
	patterns := []struct {
		regex *regexp.Regexp
		replacement string
	}{
		{regexp.MustCompile(`(?i)(password|passwd|pwd|secret|token|key|auth)[\s]*[:=][\s]*[^\s]+`), "${1}=***"},
		{regexp.MustCompile(`[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}`), "***@***.***"},
		{regexp.MustCompile(`\b(?:\d{1,3}\.){3}\d{1,3}\b`), "***.***.***.***."},
	}
	
	result := s
	for _, pattern := range patterns {
		result = pattern.regex.ReplaceAllString(result, pattern.replacement)
	}
	
	return result
}

func MaskSensitiveData(data string, showChars int) string {
	if len(data) <= showChars*2 {
		return strings.Repeat("*", len(data))
	}
	
	visible := showChars
	return data[:visible] + strings.Repeat("*", len(data)-visible*2) + data[len(data)-visible:]
}

// Error utilities

func LogError(err error, context string) {
	if err != nil {
		log.Error().Err(err).Str("context", context).Msg("Error occurred")
	}
}

func LogErrorWithFields(err error, fields map[string]interface{}) {
	if err != nil {
		event := log.Error().Err(err)
		for k, v := range fields {
			event = event.Interface(k, v)
		}
		event.Msg("Error occurred")
	}
}

func WrapError(err error, message string) error {
	if err == nil {
		return nil
	}
	return fmt.Errorf("%s: %w", message, err)
}

// Reflection utilities

func IsNil(v interface{}) bool {
	if v == nil {
		return true
	}
	rv := reflect.ValueOf(v)
	switch rv.Kind() {
	case reflect.Chan, reflect.Func, reflect.Interface, reflect.Map, reflect.Ptr, reflect.Slice:
		return rv.IsNil()
	default:
		return false
	}
}

func IsZero(v interface{}) bool {
	if v == nil {
		return true
	}
	return reflect.DeepEqual(v, reflect.Zero(reflect.TypeOf(v)).Interface())
}

// Concurrent utilities

func CloseChannelSafely(ch chan struct{}) {
	defer func() {
		if r := recover(); r != nil {
			// Channel was already closed
		}
	}()
	close(ch)
}

// Math utilities

func MinInt(a, b int) int {
	if a < b {
		return a
	}
	return b
}

func MaxInt(a, b int) int {
	if a > b {
		return a
	}
	return b
}

func MinInt64(a, b int64) int64 {
	if a < b {
		return a
	}
	return b
}

func MaxInt64(a, b int64) int64 {
	if a > b {
		return a
	}
	return b
}

func ClampInt(value, min, max int) int {
	if value < min {
		return min
	}
	if value > max {
		return max
	}
	return value
}

func AbsInt(x int) int {
	if x < 0 {
		return -x
	}
	return x
}

// Rate limiting utilities

func CalculateBackoff(attempt int, baseDelay time.Duration, maxDelay time.Duration, multiplier float64) time.Duration {
	delay := baseDelay
	for i := 0; i < attempt; i++ {
		delay = time.Duration(float64(delay) * multiplier)
		if delay > maxDelay {
			return maxDelay
		}
	}
	return delay
}

// Resource cleanup utilities

func SafeClose(closer io.Closer) {
	if closer != nil {
		if err := closer.Close(); err != nil {
			log.Debug().Err(err).Msg("Error closing resource")
		}
	}
}
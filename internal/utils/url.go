package utils

import (
	"net/url"
	"strings"
)

// NormalizeURL normalizes a URL for consistent processing
func NormalizeURL(rawURL string) (string, error) {
	// Add scheme if missing
	if !strings.HasPrefix(rawURL, "http://") && !strings.HasPrefix(rawURL, "https://") {
		rawURL = "https://" + rawURL
	}
	
	parsedURL, err := url.Parse(rawURL)
	if err != nil {
		return "", err
	}
	
	// Normalize host to lowercase
	parsedURL.Host = strings.ToLower(parsedURL.Host)
	
	// Remove default ports
	if (parsedURL.Scheme == "http" && strings.HasSuffix(parsedURL.Host, ":80")) ||
		(parsedURL.Scheme == "https" && strings.HasSuffix(parsedURL.Host, ":443")) {
		parsedURL.Host = strings.TrimSuffix(parsedURL.Host, ":80")
		parsedURL.Host = strings.TrimSuffix(parsedURL.Host, ":443")
	}
	
	return parsedURL.String(), nil
}

// MakeAbsoluteURL converts a relative URL to absolute based on base URL
func MakeAbsoluteURL(baseURL, relativeURL string) string {
	base, err := url.Parse(baseURL)
	if err != nil {
		return relativeURL
	}
	
	rel, err := url.Parse(relativeURL)
	if err != nil {
		return relativeURL
	}
	
	return base.ResolveReference(rel).String()
}

// ExtractDomain extracts the domain from a URL
func ExtractDomain(rawURL string) string {
	parsedURL, err := url.Parse(rawURL)
	if err != nil {
		return ""
	}
	
	return parsedURL.Hostname()
}

// IsValidURL checks if a string is a valid URL
func IsValidURL(rawURL string) bool {
	_, err := url.Parse(rawURL)
	return err == nil
}
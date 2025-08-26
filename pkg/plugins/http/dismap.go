package http

import (
	"bufio"
	"context"
	"encoding/json"
	"fmt"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/f2u0a0d3/GoRecon/pkg/plugins/base"
	"github.com/f2u0a0d3/GoRecon/pkg/core"
	"github.com/f2u0a0d3/GoRecon/pkg/models"
)

type DismapPlugin struct {
	*base.BaseAdapter
	config *DismapConfig
}

type DismapConfig struct {
	Threads     int      `json:"threads"`
	Timeout     int      `json:"timeout"`
	Mode        string   `json:"mode"`
	Ports       []string `json:"ports"`
	LogLevel    int      `json:"log_level"`
	OutputJSON  bool     `json:"output_json"`
	NoColor     bool     `json:"no_color"`
	NoPing      bool     `json:"no_ping"`
	ProxyURL    string   `json:"proxy_url"`
	CustomPorts string   `json:"custom_ports"`
	PortType    string   `json:"port_type"`
}

type DismapResult struct {
	URL           string            `json:"url"`
	IP            string            `json:"ip"`
	Port          string            `json:"port"`
	Protocol      string            `json:"protocol"`
	Service       string            `json:"service"`
	Title         string            `json:"title"`
	StatusCode    int               `json:"status_code"`
	Server        string            `json:"server"`
	Banner        string            `json:"banner"`
	Fingerprint   string            `json:"fingerprint"`
	Technology    []string          `json:"technology"`
	Version       string            `json:"version"`
	OS            string            `json:"os"`
	Vulnerability []string          `json:"vulnerability"`
	Timestamp     time.Time         `json:"timestamp"`
	Headers       map[string]string `json:"headers"`
	Body          string            `json:"body"`
}

func NewDismapPlugin() *DismapPlugin {
	config := &DismapConfig{
		Threads:    500,
		Timeout:    5,
		Mode:       "http",
		Ports:      []string{"80", "443", "8080", "8443"},
		LogLevel:   3,
		OutputJSON: true,
		NoColor:    true,
		NoPing:     false,
		PortType:   "tcp",
	}

	return &DismapPlugin{
		BaseAdapter: base.NewBaseAdapter("dismap", "Asset Discovery and Service Identification"),
		config:      config,
	}
}

func (d *DismapPlugin) GetMetadata() models.PluginMetadata {
	return models.PluginMetadata{
		Name:        "Dismap",
		Version:     "0.6.1",
		Description: "Asset discovery tool for identifying services and protocols on network hosts",
		Author:      "zhzyker",
		Tags:        []string{"discovery", "fingerprinting", "service", "asset", "reconnaissance"},
		Category:    "http_analysis",
		Priority:    7,
		Timeout:     120,
		RateLimit:   100,
		Dependencies: []string{"dismap"},
		Capabilities: []string{
			"service_identification",
			"protocol_detection",
			"asset_discovery",
			"fingerprinting",
			"banner_grabbing",
			"technology_detection",
		},
	}
}

func (d *DismapPlugin) Configure(config map[string]interface{}) error {
	if threads, ok := config["threads"].(int); ok {
		d.config.Threads = threads
	}

	if timeout, ok := config["timeout"].(int); ok {
		d.config.Timeout = timeout
	}

	if mode, ok := config["mode"].(string); ok {
		d.config.Mode = mode
	}

	if ports, ok := config["ports"].([]interface{}); ok {
		d.config.Ports = make([]string, len(ports))
		for i, p := range ports {
			d.config.Ports[i] = fmt.Sprintf("%v", p)
		}
	}

	if logLevel, ok := config["log_level"].(int); ok {
		d.config.LogLevel = logLevel
	}

	if outputJSON, ok := config["output_json"].(bool); ok {
		d.config.OutputJSON = outputJSON
	}

	if noColor, ok := config["no_color"].(bool); ok {
		d.config.NoColor = noColor
	}

	if noPing, ok := config["no_ping"].(bool); ok {
		d.config.NoPing = noPing
	}

	if proxyURL, ok := config["proxy_url"].(string); ok {
		d.config.ProxyURL = proxyURL
	}

	if customPorts, ok := config["custom_ports"].(string); ok {
		d.config.CustomPorts = customPorts
	}

	if portType, ok := config["port_type"].(string); ok {
		d.config.PortType = portType
	}

	return nil
}

func (d *DismapPlugin) Run(ctx context.Context, target *models.Target, results chan<- models.PluginResult, shared *core.SharedContext) error {
	d.SetStatus("running")
	defer d.SetStatus("completed")

	targetHosts := d.getTargetHosts(target, shared)
	if len(targetHosts) == 0 {
		targetHosts = []string{target.GetHost()}
	}

	// Process targets
	var wg sync.WaitGroup
	semaphore := make(chan struct{}, 10) // Limit concurrent scans

	for _, host := range targetHosts {
		wg.Add(1)
		go func(targetHost string) {
			defer wg.Done()
			semaphore <- struct{}{}
			defer func() { <-semaphore }()

			if err := d.scanTarget(ctx, targetHost, results, shared); err != nil {
				d.LogError("Failed to scan target %s: %v", targetHost, err)
			}
		}(host)
	}

	wg.Wait()
	return nil
}

func (d *DismapPlugin) getTargetHosts(target *models.Target, shared *core.SharedContext) []string {
	var hosts []string

	// Get hosts from shared discoveries
	discoveries := shared.GetDiscoveriesByType("subdomain", "ip", "host")
	for _, discovery := range discoveries {
		if discovery.Data != nil {
			if host, ok := discovery.Data["host"].(string); ok && host != "" {
				hosts = append(hosts, host)
			}
			if ip, ok := discovery.Data["ip"].(string); ok && ip != "" {
				hosts = append(hosts, ip)
			}
			if subdomain, ok := discovery.Data["subdomain"].(string); ok && subdomain != "" {
				hosts = append(hosts, subdomain)
			}
		}
	}

	// Remove duplicates
	hostSet := make(map[string]bool)
	uniqueHosts := []string{}
	for _, host := range hosts {
		if !hostSet[host] {
			hostSet[host] = true
			uniqueHosts = append(uniqueHosts, host)
		}
	}

	return uniqueHosts
}

func (d *DismapPlugin) scanTarget(ctx context.Context, targetHost string, results chan<- models.PluginResult, shared *core.SharedContext) error {
	args := []string{
		"dismap",
		"-u", targetHost,
		"-l", strconv.Itoa(d.config.LogLevel),
		"-t", strconv.Itoa(d.config.Threads),
		"--timeout", strconv.Itoa(d.config.Timeout),
		"--type", d.config.PortType,
	}

	// Add mode
	if d.config.Mode != "" {
		args = append(args, "-m", d.config.Mode)
	}

	// Add custom ports
	if d.config.CustomPorts != "" {
		args = append(args, "-p", d.config.CustomPorts)
	} else if len(d.config.Ports) > 0 {
		args = append(args, "-p", strings.Join(d.config.Ports, ","))
	}

	// Add JSON output
	if d.config.OutputJSON {
		args = append(args, "-j", "/tmp/dismap_"+targetHost+".json")
	}

	// Add no color
	if d.config.NoColor {
		args = append(args, "--nc")
	}

	// Add no ping
	if d.config.NoPing {
		args = append(args, "--np")
	}

	// Add proxy
	if d.config.ProxyURL != "" {
		args = append(args, "--proxy", d.config.ProxyURL)
	}

	execResult, err := d.ExecuteCommand(ctx, args)
	if err != nil {
		return fmt.Errorf("failed to execute dismap: %w", err)
	}

	// Parse JSON output if available
	if d.config.OutputJSON {
		jsonFile := "/tmp/dismap_" + targetHost + ".json"
		if err := d.parseJSONOutput(jsonFile, targetHost, results, shared); err != nil {
			d.LogError("Failed to parse JSON output: %v", err)
			// Fall back to text parsing
			return d.parseTextOutput(execResult.Stdout, targetHost, results, shared)
		}
		return nil
	}

	return d.parseTextOutput(execResult.Stdout, targetHost, results, shared)
}

func (d *DismapPlugin) parseJSONOutput(jsonFile, targetHost string, results chan<- models.PluginResult, shared *core.SharedContext) error {
	// Read JSON file (implementation would depend on actual dismap JSON format)
	// For now, we'll implement text parsing as the primary method
	return fmt.Errorf("JSON parsing not implemented")
}

func (d *DismapPlugin) parseTextOutput(output, targetHost string, results chan<- models.PluginResult, shared *core.SharedContext) error {
	scanner := bufio.NewScanner(strings.NewReader(output))
	
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line == "" || strings.HasPrefix(line, "[") {
			continue
		}

		// Parse dismap output format
		result := d.parseOutputLine(line, targetHost)
		if result != nil {
			pluginResult := d.createPluginResult(*result, targetHost)
			
			select {
			case results <- pluginResult:
			case <-ctx.Done():
				return ctx.Err()
			}

			// Share service discoveries
			d.shareServiceDiscovery(shared, *result)
		}
	}

	return scanner.Err()
}

func (d *DismapPlugin) parseOutputLine(line, targetHost string) *DismapResult {
	// Parse dismap output format
	// Example: "http://example.com:80 [200] [nginx/1.18.0] [Example Title]"
	
	if !strings.Contains(line, "http") && !strings.Contains(line, "https") {
		return nil
	}

	result := &DismapResult{
		Timestamp:   time.Now(),
		IP:          targetHost,
		Technology:  []string{},
		Headers:     make(map[string]string),
	}

	// Extract URL
	parts := strings.Fields(line)
	if len(parts) > 0 {
		result.URL = parts[0]
		
		// Extract protocol and port from URL
		if strings.HasPrefix(result.URL, "https://") {
			result.Protocol = "https"
			result.Port = "443"
		} else if strings.HasPrefix(result.URL, "http://") {
			result.Protocol = "http"
			result.Port = "80"
		}

		// Override port if specified in URL
		if strings.Contains(result.URL, ":") && strings.Count(result.URL, ":") > 1 {
			urlParts := strings.Split(result.URL, ":")
			if len(urlParts) >= 3 {
				portPart := strings.Split(urlParts[2], "/")[0]
				result.Port = portPart
			}
		}
	}

	// Extract status code
	if statusMatch := strings.Index(line, "["); statusMatch != -1 {
		statusEnd := strings.Index(line[statusMatch+1:], "]")
		if statusEnd != -1 {
			statusStr := line[statusMatch+1 : statusMatch+1+statusEnd]
			if statusCode, err := strconv.Atoi(statusStr); err == nil {
				result.StatusCode = statusCode
			}
		}
	}

	// Extract server/service info
	serverStart := strings.Index(line, "] [")
	if serverStart != -1 {
		serverStart += 3
		serverEnd := strings.Index(line[serverStart:], "]")
		if serverEnd != -1 {
			result.Server = line[serverStart : serverStart+serverEnd]
			result.Service = result.Server
		}
	}

	// Extract title
	titleStart := strings.LastIndex(line, "[")
	if titleStart != -1 && titleStart > serverStart {
		titleEnd := strings.LastIndex(line, "]")
		if titleEnd != -1 && titleEnd > titleStart {
			result.Title = line[titleStart+1 : titleEnd]
		}
	}

	return result
}

func (d *DismapPlugin) createPluginResult(result DismapResult, targetHost string) models.PluginResult {
	severity := d.calculateSeverity(result)
	
	data := map[string]interface{}{
		"url":           result.URL,
		"ip":            result.IP,
		"port":          result.Port,
		"protocol":      result.Protocol,
		"service":       result.Service,
		"title":         result.Title,
		"status_code":   result.StatusCode,
		"server":        result.Server,
		"banner":        result.Banner,
		"fingerprint":   result.Fingerprint,
		"technology":    result.Technology,
		"version":       result.Version,
		"os":            result.OS,
		"vulnerability": result.Vulnerability,
		"headers":       result.Headers,
		"body":          result.Body,
	}

	title := fmt.Sprintf("Service Discovery: %s", result.Service)
	if result.Title != "" {
		title = fmt.Sprintf("Service Discovery: %s (%s)", result.Service, result.Title)
	}

	description := fmt.Sprintf("Discovered service %s on %s:%s", result.Service, result.IP, result.Port)
	if result.StatusCode > 0 {
		description += fmt.Sprintf(" with status %d", result.StatusCode)
	}

	return models.PluginResult{
		Plugin:      d.GetName(),
		Target:      targetHost,
		Type:        "service_discovery",
		Severity:    severity,
		Title:       title,
		Description: description,
		Data:        data,
		Timestamp:   time.Now(),
		Confidence:  d.calculateConfidence(result),
		Risk:        d.calculateRisk(result),
	}
}

func (d *DismapPlugin) calculateSeverity(result DismapResult) models.Severity {
	// Check for potential vulnerabilities
	if len(result.Vulnerability) > 0 {
		return models.SeverityHigh
	}

	// Check for interesting services
	serviceMap := map[string]models.Severity{
		"ssh":        models.SeverityMedium,
		"ftp":        models.SeverityMedium,
		"telnet":     models.SeverityHigh,
		"mysql":      models.SeverityMedium,
		"postgres":   models.SeverityMedium,
		"mongodb":    models.SeverityMedium,
		"redis":      models.SeverityMedium,
		"memcached":  models.SeverityMedium,
		"vnc":        models.SeverityHigh,
		"rdp":        models.SeverityMedium,
		"smb":        models.SeverityMedium,
	}

	serviceLower := strings.ToLower(result.Service)
	for service, severity := range serviceMap {
		if strings.Contains(serviceLower, service) {
			return severity
		}
	}

	// Check status codes
	if result.StatusCode >= 400 && result.StatusCode < 500 {
		return models.SeverityLow
	}
	if result.StatusCode >= 500 {
		return models.SeverityMedium
	}

	return models.SeverityInfo
}

func (d *DismapPlugin) calculateConfidence(result DismapResult) float64 {
	confidence := 0.7 // Base confidence

	// Higher confidence for HTTP services with status codes
	if result.StatusCode > 0 {
		confidence += 0.2
	}

	// Higher confidence for detailed service information
	if result.Server != "" {
		confidence += 0.1
	}

	// Higher confidence for titles
	if result.Title != "" {
		confidence += 0.1
	}

	// Cap at 1.0
	if confidence > 1.0 {
		confidence = 1.0
	}

	return confidence
}

func (d *DismapPlugin) calculateRisk(result DismapResult) float64 {
	risk := 0.3 // Base risk

	// Higher risk for vulnerable services
	if len(result.Vulnerability) > 0 {
		risk = 0.8
	}

	// Risk based on service type
	serviceLower := strings.ToLower(result.Service)
	highRiskServices := []string{"telnet", "vnc", "ftp", "ssh"}
	mediumRiskServices := []string{"mysql", "postgres", "mongodb", "redis", "smb"}
	
	for _, service := range highRiskServices {
		if strings.Contains(serviceLower, service) {
			risk += 0.3
			break
		}
	}
	
	for _, service := range mediumRiskServices {
		if strings.Contains(serviceLower, service) {
			risk += 0.2
			break
		}
	}

	// Risk based on status codes
	if result.StatusCode >= 500 {
		risk += 0.1
	}

	// Cap at 1.0
	if risk > 1.0 {
		risk = 1.0
	}

	return risk
}

func (d *DismapPlugin) shareServiceDiscovery(shared *core.SharedContext, result DismapResult) {
	discoveryData := map[string]interface{}{
		"url":         result.URL,
		"ip":          result.IP,
		"port":        result.Port,
		"protocol":    result.Protocol,
		"service":     result.Service,
		"title":       result.Title,
		"status_code": result.StatusCode,
		"server":      result.Server,
		"technology":  result.Technology,
		"version":     result.Version,
	}

	discovery := &models.Discovery{
		Type:       "service",
		Value:      result.Service,
		Source:     d.GetName(),
		Confidence: d.calculateConfidence(result),
		Timestamp:  time.Now(),
		Data:       discoveryData,
	}

	shared.AddDiscovery(discovery)

	// Also add URL discovery if available
	if result.URL != "" {
		urlDiscovery := &models.Discovery{
			Type:       "url",
			Value:      result.URL,
			Source:     d.GetName(),
			Confidence: d.calculateConfidence(result),
			Timestamp:  time.Now(),
			Data:       discoveryData,
		}
		shared.AddDiscovery(urlDiscovery)
	}
}

func (d *DismapPlugin) GetIntelligencePatterns() []models.IntelligencePattern {
	return []models.IntelligencePattern{
		{
			Name:        "High-Risk Service Detection",
			Pattern:     `"service":"(telnet|vnc|ftp)"`,
			Confidence:  0.9,
			Description: "High-risk service detected (telnet/vnc/ftp)",
			Tags:        []string{"service", "high-risk", "insecure"},
		},
		{
			Name:        "Database Service Detection",
			Pattern:     `"service":"(mysql|postgres|mongodb|redis)"`,
			Confidence:  0.85,
			Description: "Database service detected",
			Tags:        []string{"service", "database", "data"},
		},
		{
			Name:        "Admin Interface Detection",
			Pattern:     `"title":".*([Aa]dmin|[Ll]ogin|[Dd]ashboard)"`,
			Confidence:  0.8,
			Description: "Administrative interface detected",
			Tags:        []string{"admin", "interface", "login"},
		},
		{
			Name:        "Error Page Detection",
			Pattern:     `"status_code":(500|502|503)`,
			Confidence:  0.7,
			Description: "Server error detected",
			Tags:        []string{"error", "server", "misconfiguration"},
		},
		{
			Name:        "Development Service Detection",
			Pattern:     `"service":".*([Dd]ev|[Tt]est|[Ss]taging)"`,
			Confidence:  0.75,
			Description: "Development or staging service detected",
			Tags:        []string{"development", "staging", "test"},
		},
	}
}
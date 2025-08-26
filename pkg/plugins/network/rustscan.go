package network

import (
	"bufio"
	"context"
	"encoding/json"
	"fmt"
	"net"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/f2u0a0d3/GoRecon/pkg/plugins/base"
	"github.com/f2u0a0d3/GoRecon/pkg/core"
	"github.com/f2u0a0d3/GoRecon/pkg/models"
)

type RustScanPlugin struct {
	*base.BaseAdapter
	config *RustScanConfig
}

type RustScanConfig struct {
	Ports           []string `json:"ports"`
	Range           string   `json:"range"`
	TopPorts        int      `json:"top_ports"`
	UlimitValue     int      `json:"ulimit_value"`
	BatchSize       int      `json:"batch_size"`
	Timeout         int      `json:"timeout"`
	Tries           int      `json:"tries"`
	Accessible      bool     `json:"accessible"`
	Greppable       bool     `json:"greppable"`
	NoConfig        bool     `json:"no_config"`
	Scripts         []string `json:"scripts"`
	Command         string   `json:"command"`
	ConfigPath      string   `json:"config_path"`
	OutputJSON      bool     `json:"output_json"`
}

type RustScanResult struct {
	IP       string    `json:"ip"`
	Hostname string    `json:"hostname,omitempty"`
	Ports    []PortInfo `json:"ports"`
}

type PortInfo struct {
	Port     int    `json:"port"`
	Protocol string `json:"protocol"`
	State    string `json:"state"`
	Service  string `json:"service,omitempty"`
	Version  string `json:"version,omitempty"`
}

func NewRustScanPlugin() *RustScanPlugin {
	config := &RustScanConfig{
		Ports:       []string{},
		Range:       "1-65535",
		TopPorts:    1000,
		UlimitValue: 5000,
		BatchSize:   4500,
		Timeout:     1500,
		Tries:       1,
		Accessible:  false,
		Greppable:   true,
		NoConfig:    true,
		Scripts:     []string{},
		Command:     "",
		ConfigPath:  "",
		OutputJSON:  false, // RustScan doesn't have JSON output, we'll parse text
	}

	return &RustScanPlugin{
		BaseAdapter: base.NewBaseAdapter("rustscan", "Fast Port Scanner"),
		config:      config,
	}
}

func (r *RustScanPlugin) GetMetadata() models.PluginMetadata {
	return models.PluginMetadata{
		Name:        "RustScan",
		Version:     "2.4.1",
		Description: "The Modern Port Scanner - fast, accurate, and easy to use",
		Author:      "RustScan Team",
		Tags:        []string{"port", "scanner", "network", "reconnaissance", "tcp", "discovery"},
		Category:    "network_scanning",
		Priority:    9,
		Timeout:     300,
		RateLimit:   50,
		Dependencies: []string{"rustscan"},
		Capabilities: []string{
			"tcp_port_scanning",
			"fast_scanning",
			"custom_port_ranges",
			"host_discovery",
			"service_detection",
			"batch_processing",
		},
	}
}

func (r *RustScanPlugin) Configure(config map[string]interface{}) error {
	if ports, ok := config["ports"].([]interface{}); ok {
		r.config.Ports = make([]string, len(ports))
		for i, p := range ports {
			r.config.Ports[i] = fmt.Sprintf("%v", p)
		}
	}

	if portRange, ok := config["range"].(string); ok {
		r.config.Range = portRange
	}

	if topPorts, ok := config["top_ports"].(int); ok {
		r.config.TopPorts = topPorts
	}

	if ulimitValue, ok := config["ulimit_value"].(int); ok {
		if ulimitValue <= 0 {
			r.config.UlimitValue = 5000 // Default value
		} else if ulimitValue > 65535 {
			r.config.UlimitValue = 65535 // Cap at max
		} else {
			r.config.UlimitValue = ulimitValue
		}
	}

	if batchSize, ok := config["batch_size"].(int); ok {
		if batchSize <= 0 {
			r.config.BatchSize = 4500 // Default value
		} else if batchSize > 65535 {
			r.config.BatchSize = 65535 // Cap at max ports
		} else {
			r.config.BatchSize = batchSize
		}
	}

	if timeout, ok := config["timeout"].(int); ok {
		if timeout <= 0 {
			r.config.Timeout = 1500 // Default value
		} else if timeout > 30000 {
			r.config.Timeout = 30000 // Cap at 30 seconds
		} else {
			r.config.Timeout = timeout
		}
	}

	if tries, ok := config["tries"].(int); ok {
		if tries <= 0 {
			r.config.Tries = 1 // Minimum 1 try
		} else if tries > 10 {
			r.config.Tries = 10 // Cap at 10 tries
		} else {
			r.config.Tries = tries
		}
	}

	if accessible, ok := config["accessible"].(bool); ok {
		r.config.Accessible = accessible
	}

	if greppable, ok := config["greppable"].(bool); ok {
		r.config.Greppable = greppable
	}

	if noConfig, ok := config["no_config"].(bool); ok {
		r.config.NoConfig = noConfig
	}

	if scripts, ok := config["scripts"].([]interface{}); ok {
		r.config.Scripts = make([]string, len(scripts))
		for i, s := range scripts {
			r.config.Scripts[i] = fmt.Sprintf("%v", s)
		}
	}

	if command, ok := config["command"].(string); ok {
		r.config.Command = command
	}

	if configPath, ok := config["config_path"].(string); ok {
		r.config.ConfigPath = configPath
	}

	return nil
}

func (r *RustScanPlugin) Run(ctx context.Context, target *models.Target, results chan<- models.PluginResult, shared *core.SharedContext) error {
	r.SetStatus("running")
	defer r.SetStatus("completed")

	targetHosts := r.getTargetHosts(target, shared)
	if len(targetHosts) == 0 {
		targetHosts = []string{target.GetHost()}
	}

	// Process hosts
	var wg sync.WaitGroup
	semaphore := make(chan struct{}, 5) // Limit concurrent scans

	for _, host := range targetHosts {
		wg.Add(1)
		go func(targetHost string) {
			defer wg.Done()
			semaphore <- struct{}{}
			defer func() { <-semaphore }()

			if err := r.scanHost(ctx, targetHost, results, shared); err != nil {
				r.LogError("Failed to scan host %s: %v", targetHost, err)
			}
		}(host)
	}

	wg.Wait()
	return nil
}

func (r *RustScanPlugin) getTargetHosts(target *models.Target, shared *core.SharedContext) []string {
	var hosts []string

	// Get hosts from shared discoveries
	discoveries := shared.GetDiscoveriesByType("subdomain", "ip", "host", "service")
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

	// Add target host/IP
	if target.GetHost() != "" {
		hosts = append(hosts, target.GetHost())
	}
	if target.GetIP() != "" {
		hosts = append(hosts, target.GetIP())
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

func (r *RustScanPlugin) scanHost(ctx context.Context, host string, results chan<- models.PluginResult, shared *core.SharedContext) error {
	args := []string{
		"rustscan",
		"-a", host,
		"--ulimit", strconv.Itoa(r.config.UlimitValue),
		"--batch-size", strconv.Itoa(r.config.BatchSize),
		"-t", strconv.Itoa(r.config.Timeout),
		"--tries", strconv.Itoa(r.config.Tries),
	}

	// Add port range or specific ports
	if len(r.config.Ports) > 0 {
		args = append(args, "-p", strings.Join(r.config.Ports, ","))
	} else if r.config.TopPorts > 0 {
		args = append(args, "--top")
	} else {
		args = append(args, "-r", r.config.Range)
	}

	// Add flags
	if r.config.Accessible {
		args = append(args, "--accessible")
	}

	if r.config.Greppable {
		args = append(args, "-g")
	}

	if r.config.NoConfig {
		args = append(args, "--no-config")
	}

	// Add scripts
	if len(r.config.Scripts) > 0 {
		args = append(args, "--scripts", strings.Join(r.config.Scripts, ","))
	}

	// Add custom command
	if r.config.Command != "" {
		args = append(args, "--", r.config.Command)
	}

	// Add config path
	if r.config.ConfigPath != "" {
		args = append(args, "-C", r.config.ConfigPath)
	}

	execResult, err := r.ExecuteCommand(ctx, args)
	if err != nil {
		return fmt.Errorf("failed to execute rustscan: %w", err)
	}

	return r.parseOutput(execResult.Stdout, host, results, shared)
}

func (r *RustScanPlugin) parseOutput(output, host string, results chan<- models.PluginResult, shared *core.SharedContext) error {
	scanner := bufio.NewScanner(strings.NewReader(output))
	
	rustScanResult := RustScanResult{
		IP:    host,
		Ports: []PortInfo{},
	}

	// Resolve hostname if it's an IP
	if ip := net.ParseIP(host); ip != nil {
		if names, err := net.LookupAddr(host); err == nil && len(names) > 0 {
			rustScanResult.Hostname = names[0]
		}
	} else {
		rustScanResult.Hostname = host
		// Try to resolve IP
		if ips, err := net.LookupIP(host); err == nil && len(ips) > 0 {
			rustScanResult.IP = ips[0].String()
		}
	}

	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line == "" {
			continue
		}

		// Parse different RustScan output formats
		ports := r.parseOutputLine(line)
		for _, port := range ports {
			rustScanResult.Ports = append(rustScanResult.Ports, port)
		}
	}

	// Create plugin results for each port
	for _, portInfo := range rustScanResult.Ports {
		result := r.createPluginResult(rustScanResult, portInfo, host)
		
		select {
		case results <- result:
		case <-ctx.Done():
			return ctx.Err()
		}

		// Share port discoveries
		r.sharePortDiscovery(shared, rustScanResult, portInfo)
	}

	return scanner.Err()
}

func (r *RustScanPlugin) parseOutputLine(line string) []PortInfo {
	var ports []PortInfo

	// Parse RustScan output formats:
	// Format 1: "Open 10.0.0.1:80"
	// Format 2: "80/tcp open"
	// Format 3: "Discovered open port 80/tcp on 10.0.0.1"

	if strings.Contains(line, "Open ") && strings.Contains(line, ":") {
		// Format: "Open 10.0.0.1:80"
		parts := strings.Split(line, ":")
		if len(parts) >= 2 {
			portStr := strings.TrimSpace(parts[len(parts)-1])
			if port, err := strconv.Atoi(portStr); err == nil && port > 0 && port <= 65535 {
				ports = append(ports, PortInfo{
					Port:     port,
					Protocol: "tcp",
					State:    "open",
				})
			}
		}
	} else if strings.Contains(line, "/tcp") && strings.Contains(line, "open") {
		// Format: "80/tcp open" or "Discovered open port 80/tcp"
		parts := strings.Fields(line)
		for _, part := range parts {
			if strings.Contains(part, "/tcp") {
				portParts := strings.Split(part, "/")
				if len(portParts) > 0 {
					portStr := portParts[0]
					if port, err := strconv.Atoi(portStr); err == nil && port > 0 && port <= 65535 {
						ports = append(ports, PortInfo{
							Port:     port,
							Protocol: "tcp",
							State:    "open",
						})
					}
				}
			}
		}
	} else if strings.Contains(line, "PORT") || strings.Contains(line, "STATE") {
		// Skip header lines
		return ports
	}

	return ports
}

func (r *RustScanPlugin) createPluginResult(rustScanResult RustScanResult, portInfo PortInfo, host string) models.PluginResult {
	severity := r.calculateSeverity(portInfo)
	
	data := map[string]interface{}{
		"ip":       rustScanResult.IP,
		"hostname": rustScanResult.Hostname,
		"port":     portInfo.Port,
		"protocol": portInfo.Protocol,
		"state":    portInfo.State,
		"service":  portInfo.Service,
		"version":  portInfo.Version,
	}

	title := fmt.Sprintf("Open Port: %s:%d/%s", host, portInfo.Port, portInfo.Protocol)
	description := fmt.Sprintf("Found open port %d/%s on %s", portInfo.Port, portInfo.Protocol, host)
	
	if portInfo.Service != "" {
		description += fmt.Sprintf(" (service: %s)", portInfo.Service)
	}
	
	if portInfo.Version != "" {
		description += fmt.Sprintf(" (version: %s)", portInfo.Version)
	}

	return models.PluginResult{
		Plugin:      r.GetName(),
		Target:      host,
		Type:        "port_discovery",
		Severity:    severity,
		Title:       title,
		Description: description,
		Data:        data,
		Timestamp:   time.Now(),
		Confidence:  r.calculateConfidence(portInfo),
		Risk:        r.calculateRisk(portInfo),
	}
}

func (r *RustScanPlugin) calculateSeverity(portInfo PortInfo) models.Severity {
	// Check for high-risk ports
	highRiskPorts := map[int]string{
		21:   "ftp",
		22:   "ssh",
		23:   "telnet",
		25:   "smtp",
		53:   "dns",
		135:  "rpc",
		139:  "netbios",
		445:  "smb",
		1433: "mssql",
		1521: "oracle",
		3306: "mysql",
		3389: "rdp",
		5432: "postgresql",
		5985: "winrm",
		5986: "winrm-ssl",
		6379: "redis",
		27017: "mongodb",
	}

	if _, exists := highRiskPorts[portInfo.Port]; exists {
		return models.SeverityHigh
	}

	// Medium risk ports
	mediumRiskPorts := map[int]string{
		80:   "http",
		443:  "https",
		8080: "http-proxy",
		8443: "https-alt",
		9200: "elasticsearch",
		5672: "rabbitmq",
		6379: "redis",
	}

	if _, exists := mediumRiskPorts[portInfo.Port]; exists {
		return models.SeverityMedium
	}

	// Check for uncommon high ports
	if portInfo.Port > 10000 {
		return models.SeverityLow
	}

	return models.SeverityInfo
}

func (r *RustScanPlugin) calculateConfidence(portInfo PortInfo) float64 {
	confidence := 0.9 // Base confidence for port scanning

	// Higher confidence if service is identified
	if portInfo.Service != "" {
		confidence += 0.05
	}

	// Higher confidence if version is identified
	if portInfo.Version != "" {
		confidence += 0.05
	}

	// Cap at 1.0
	if confidence > 1.0 {
		confidence = 1.0
	}

	return confidence
}

func (r *RustScanPlugin) calculateRisk(portInfo PortInfo) float64 {
	risk := 0.3 // Base risk

	// High risk services
	highRiskServices := map[int]float64{
		21:   0.7, // FTP
		23:   0.9, // Telnet
		135:  0.6, // RPC
		139:  0.5, // NetBIOS
		445:  0.6, // SMB
		1433: 0.7, // MSSQL
		3306: 0.6, // MySQL
		3389: 0.8, // RDP
		5432: 0.6, // PostgreSQL
		6379: 0.5, // Redis
	}

	if riskValue, exists := highRiskServices[portInfo.Port]; exists {
		risk = riskValue
	}

	// SSH is special case - medium risk but important
	if portInfo.Port == 22 {
		risk = 0.5
	}

	// HTTP services
	if portInfo.Port == 80 || portInfo.Port == 443 || portInfo.Port == 8080 || portInfo.Port == 8443 {
		risk = 0.4
	}

	// Cap at 1.0
	if risk > 1.0 {
		risk = 1.0
	}

	return risk
}

func (r *RustScanPlugin) sharePortDiscovery(shared *core.SharedContext, rustScanResult RustScanResult, portInfo PortInfo) {
	discoveryData := map[string]interface{}{
		"ip":       rustScanResult.IP,
		"hostname": rustScanResult.Hostname,
		"port":     portInfo.Port,
		"protocol": portInfo.Protocol,
		"state":    portInfo.State,
		"service":  portInfo.Service,
		"version":  portInfo.Version,
	}

	discovery := &models.Discovery{
		Type:       "port",
		Value:      fmt.Sprintf("%d/%s", portInfo.Port, portInfo.Protocol),
		Source:     r.GetName(),
		Confidence: r.calculateConfidence(portInfo),
		Timestamp:  time.Now(),
		Data:       discoveryData,
	}

	shared.AddDiscovery(discovery)

	// Also add service discovery if service is identified
	if portInfo.Service != "" {
		serviceDiscovery := &models.Discovery{
			Type:       "service",
			Value:      portInfo.Service,
			Source:     r.GetName(),
			Confidence: r.calculateConfidence(portInfo),
			Timestamp:  time.Now(),
			Data:       discoveryData,
		}
		shared.AddDiscovery(serviceDiscovery)
	}

	// Add host discovery
	hostDiscovery := &models.Discovery{
		Type:       "host",
		Value:      rustScanResult.IP,
		Source:     r.GetName(),
		Confidence: 0.9,
		Timestamp:  time.Now(),
		Data:       discoveryData,
	}
	shared.AddDiscovery(hostDiscovery)
}

func (r *RustScanPlugin) GetIntelligencePatterns() []models.IntelligencePattern {
	return []models.IntelligencePattern{
		{
			Name:        "SSH Service Detection",
			Pattern:     `"port":22.*"protocol":"tcp"`,
			Confidence:  0.9,
			Description: "SSH service detected on port 22",
			Tags:        []string{"ssh", "remote-access", "administration"},
		},
		{
			Name:        "Web Service Detection",
			Pattern:     `"port":(80|443|8080|8443).*"protocol":"tcp"`,
			Confidence:  0.85,
			Description: "Web service detected",
			Tags:        []string{"web", "http", "https"},
		},
		{
			Name:        "Database Service Detection",
			Pattern:     `"port":(1433|3306|5432|1521|27017).*"protocol":"tcp"`,
			Confidence:  0.9,
			Description: "Database service detected",
			Tags:        []string{"database", "data", "sql"},
		},
		{
			Name:        "Remote Desktop Detection",
			Pattern:     `"port":3389.*"protocol":"tcp"`,
			Confidence:  0.95,
			Description: "Remote Desktop Protocol (RDP) detected",
			Tags:        []string{"rdp", "remote-desktop", "windows"},
		},
		{
			Name:        "SMB Service Detection",
			Pattern:     `"port":(139|445).*"protocol":"tcp"`,
			Confidence:  0.9,
			Description: "SMB/NetBIOS service detected",
			Tags:        []string{"smb", "netbios", "file-sharing"},
		},
		{
			Name:        "Telnet Service Detection",
			Pattern:     `"port":23.*"protocol":"tcp"`,
			Confidence:  0.95,
			Description: "Telnet service detected (insecure)",
			Tags:        []string{"telnet", "insecure", "remote-access"},
		},
	]
}
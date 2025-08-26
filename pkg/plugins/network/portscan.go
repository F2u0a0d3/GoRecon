package network

import (
	"context"
	"fmt"
	"net"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/f2u0a0d3/GoRecon/pkg/plugins/base"
	"github.com/f2u0a0d3/GoRecon/pkg/core"
	"github.com/f2u0a0d3/GoRecon/pkg/models"
)

type PortScanPlugin struct {
	*base.BaseAdapter
	config *PortScanConfig
}

type PortScanConfig struct {
	Ports        []int `json:"ports"`
	PortRanges   []string `json:"port_ranges"`
	TopPorts     int   `json:"top_ports"`
	Threads      int   `json:"threads"`
	Timeout      int   `json:"timeout"` // in milliseconds
	ConnectScan  bool  `json:"connect_scan"`
	UDPScan      bool  `json:"udp_scan"`
	TCPScan      bool  `json:"tcp_scan"`
	ServiceScan  bool  `json:"service_scan"`
}

type PortScanResult struct {
	Host       string      `json:"host"`
	IP         string      `json:"ip"`
	Ports      []OpenPort  `json:"ports"`
	ScanTime   time.Time   `json:"scan_time"`
	Duration   time.Duration `json:"duration"`
}

type OpenPort struct {
	Port     int    `json:"port"`
	Protocol string `json:"protocol"`
	State    string `json:"state"`
	Service  string `json:"service,omitempty"`
	Banner   string `json:"banner,omitempty"`
}

// Common port definitions
var CommonPorts = []int{
	21, 22, 23, 25, 53, 80, 110, 111, 135, 139, 143, 443, 993, 995,
	1723, 3306, 3389, 5900, 25565,
}

var TopPorts = []int{
	21, 22, 23, 25, 53, 80, 110, 111, 135, 139, 143, 443, 993, 995,
	1723, 3306, 3389, 5900, 25565, 143, 993, 995, 587, 465, 110, 995,
	143, 993, 21, 990, 115, 194, 6667, 6697, 1194, 1723, 1701, 500,
	4500, 631, 515, 9100, 5353, 548, 427, 5298, 88, 749, 464, 543,
	544, 5060, 5061, 1720, 1719, 554, 322, 1755, 5004, 5005, 1900,
	49152, 49153, 49154, 49155, 49156, 49157,
}

// Port to service mapping
var PortServices = map[int]string{
	21:    "ftp",
	22:    "ssh",
	23:    "telnet",
	25:    "smtp",
	53:    "dns",
	80:    "http",
	110:   "pop3",
	111:   "rpcbind",
	135:   "msrpc",
	139:   "netbios-ssn",
	143:   "imap",
	443:   "https",
	993:   "imaps",
	995:   "pop3s",
	1723:  "pptp",
	3306:  "mysql",
	3389:  "ms-wbt-server",
	5900:  "vnc",
	25565: "minecraft",
	587:   "smtp",
	465:   "smtps",
	990:   "ftps",
	115:   "sftp",
	194:   "irc",
	6667:  "ircd",
	6697:  "ircd-ssl",
	1194:  "openvpn",
	1701:  "l2tp",
	500:   "isakmp",
	4500:  "ipsec-nat-t",
	631:   "ipp",
	515:   "printer",
	9100:  "jetdirect",
	5353:  "mdns",
	548:   "afp",
	427:   "svrloc",
	5298:  "presence",
	88:    "kerberos",
	749:   "kerberos-adm",
	464:   "kpasswd",
	543:   "klogin",
	544:   "kshell",
	5060:  "sip",
	5061:  "sips",
	1720:  "h323q931",
	1719:  "h323gatestat",
	554:   "rtsp",
	322:   "rtsps",
	1755:  "wms",
	5004:  "rtp-data",
	5005:  "rtp-data",
	1900:  "upnp",
	1433:  "mssql",
	1521:  "oracle",
	5432:  "postgresql",
	6379:  "redis",
	27017: "mongodb",
	8080:  "http-proxy",
	8443:  "https-alt",
	9200:  "elasticsearch",
	5672:  "rabbitmq",
}

func NewPortScanPlugin() *PortScanPlugin {
	config := &PortScanConfig{
		Ports:       []int{},
		PortRanges:  []string{"1-1000"},
		TopPorts:    100,
		Threads:     100,
		Timeout:     1000, // 1 second
		ConnectScan: true,
		UDPScan:     false,
		TCPScan:     true,
		ServiceScan: true,
	}

	return &PortScanPlugin{
		BaseAdapter: base.NewBaseAdapter("portscan", "Internal Port Scanner"),
		config:      config,
	}
}

func (p *PortScanPlugin) GetMetadata() models.PluginMetadata {
	return models.PluginMetadata{
		Name:        "PortScan",
		Version:     "1.0.0",
		Description: "Internal TCP/UDP port scanner implemented in Go",
		Author:      "GoRecon",
		Tags:        []string{"port", "scanner", "network", "tcp", "udp", "internal"},
		Category:    "network_scanning",
		Priority:    7,
		Timeout:     180,
		RateLimit:   100,
		Dependencies: []string{}, // No external dependencies
		Capabilities: []string{
			"tcp_port_scanning",
			"udp_port_scanning",
			"service_detection",
			"banner_grabbing",
			"connect_scanning",
			"internal_implementation",
		},
	}
}

func (p *PortScanPlugin) Configure(config map[string]interface{}) error {
	if ports, ok := config["ports"].([]interface{}); ok {
		p.config.Ports = make([]int, len(ports))
		for i, port := range ports {
			if portInt, ok := port.(int); ok {
				p.config.Ports[i] = portInt
			} else if portStr, ok := port.(string); ok {
				if portInt, err := strconv.Atoi(portStr); err == nil {
					p.config.Ports[i] = portInt
				}
			}
		}
	}

	if portRanges, ok := config["port_ranges"].([]interface{}); ok {
		p.config.PortRanges = make([]string, len(portRanges))
		for i, r := range portRanges {
			p.config.PortRanges[i] = fmt.Sprintf("%v", r)
		}
	}

	if topPorts, ok := config["top_ports"].(int); ok {
		p.config.TopPorts = topPorts
	}

	if threads, ok := config["threads"].(int); ok {
		if threads <= 0 {
			p.config.Threads = 1
		} else if threads > 1000 {
			p.config.Threads = 1000 // Cap at reasonable limit
		} else {
			p.config.Threads = threads
		}
	}

	if timeout, ok := config["timeout"].(int); ok {
		if timeout <= 0 {
			p.config.Timeout = 1000 // Default 1 second
		} else if timeout > 30000 {
			p.config.Timeout = 30000 // Cap at 30 seconds
		} else {
			p.config.Timeout = timeout
		}
	}

	if connectScan, ok := config["connect_scan"].(bool); ok {
		p.config.ConnectScan = connectScan
	}

	if udpScan, ok := config["udp_scan"].(bool); ok {
		p.config.UDPScan = udpScan
	}

	if tcpScan, ok := config["tcp_scan"].(bool); ok {
		p.config.TCPScan = tcpScan
	}

	if serviceScan, ok := config["service_scan"].(bool); ok {
		p.config.ServiceScan = serviceScan
	}

	return nil
}

func (p *PortScanPlugin) Run(ctx context.Context, target *models.Target, results chan<- models.PluginResult, shared *core.SharedContext) error {
	p.SetStatus("running")
	defer p.SetStatus("completed")

	targetHosts := p.getTargetHosts(target, shared)
	if len(targetHosts) == 0 {
		targetHosts = []string{target.GetHost()}
	}

	// Process hosts
	var wg sync.WaitGroup
	semaphore := make(chan struct{}, 3) // Limit concurrent host scans

	for _, host := range targetHosts {
		wg.Add(1)
		go func(targetHost string) {
			defer wg.Done()
			semaphore <- struct{}{}
			defer func() { <-semaphore }()

			if err := p.scanHost(ctx, targetHost, results, shared); err != nil {
				p.LogError("Failed to scan host %s: %v", targetHost, err)
			}
		}(host)
	}

	wg.Wait()
	return nil
}

func (p *PortScanPlugin) getTargetHosts(target *models.Target, shared *core.SharedContext) []string {
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

func (p *PortScanPlugin) scanHost(ctx context.Context, host string, results chan<- models.PluginResult, shared *core.SharedContext) error {
	startTime := time.Now()
	
	// Determine which ports to scan
	ports := p.getPortsToScan()
	
	// Resolve host to IP if needed
	ip := host
	if net.ParseIP(host) == nil {
		if ips, err := net.LookupIP(host); err == nil && len(ips) > 0 {
			ip = ips[0].String()
		}
	}

	scanResult := PortScanResult{
		Host:     host,
		IP:       ip,
		Ports:    []OpenPort{},
		ScanTime: startTime,
	}

	// Scan ports concurrently
	var wg sync.WaitGroup
	portChan := make(chan OpenPort, len(ports))
	semaphore := make(chan struct{}, p.config.Threads)

	for _, port := range ports {
		wg.Add(1)
		go func(portNum int) {
			defer wg.Done()
			semaphore <- struct{}{}
			defer func() { <-semaphore }()

			select {
			case <-ctx.Done():
				return
			default:
				if openPort := p.scanPort(ctx, ip, portNum); openPort != nil {
					portChan <- *openPort
				}
			}
		}(port)
	}

	// Close channel when all scans are done
	go func() {
		wg.Wait()
		close(portChan)
	}()

	// Collect results
	for openPort := range portChan {
		select {
		case <-ctx.Done():
			return ctx.Err()
		default:
			scanResult.Ports = append(scanResult.Ports, openPort)
		}
	}

	scanResult.Duration = time.Since(startTime)

	// Sort ports
	sort.Slice(scanResult.Ports, func(i, j int) bool {
		return scanResult.Ports[i].Port < scanResult.Ports[j].Port
	})

	// Create plugin results for each open port
	for _, openPort := range scanResult.Ports {
		result := p.createPluginResult(scanResult, openPort, host)
		
		select {
		case results <- result:
		case <-ctx.Done():
			return ctx.Err()
		}

		// Share port discoveries
		p.sharePortDiscovery(shared, scanResult, openPort)
	}

	return nil
}

func (p *PortScanPlugin) getPortsToScan() []int {
	var ports []int

	// Use specified ports if provided
	if len(p.config.Ports) > 0 {
		ports = append(ports, p.config.Ports...)
	}

	// Parse port ranges
	for _, portRange := range p.config.PortRanges {
		rangePorts := p.parsePortRange(portRange)
		ports = append(ports, rangePorts...)
	}

	// Use top ports if no specific ports/ranges specified
	if len(ports) == 0 {
		if p.config.TopPorts > 0 && p.config.TopPorts <= len(TopPorts) {
			ports = TopPorts[:p.config.TopPorts]
		} else {
			ports = CommonPorts
		}
	}

	// Remove duplicates and sort
	portSet := make(map[int]bool)
	uniquePorts := []int{}
	for _, port := range ports {
		if !portSet[port] && port > 0 && port <= 65535 {
			portSet[port] = true
			uniquePorts = append(uniquePorts, port)
		}
	}

	sort.Ints(uniquePorts)
	return uniquePorts
}

func (p *PortScanPlugin) parsePortRange(portRange string) []int {
	var ports []int

	if strings.Contains(portRange, "-") {
		parts := strings.Split(portRange, "-")
		if len(parts) == 2 {
			start, err1 := strconv.Atoi(strings.TrimSpace(parts[0]))
			end, err2 := strconv.Atoi(strings.TrimSpace(parts[1]))
			
			if err1 == nil && err2 == nil && start <= end && start > 0 && end <= 65535 {
				for i := start; i <= end; i++ {
					ports = append(ports, i)
				}
			}
		}
	} else {
		if port, err := strconv.Atoi(strings.TrimSpace(portRange)); err == nil && port > 0 && port <= 65535 {
			ports = append(ports, port)
		}
	}

	return ports
}

func (p *PortScanPlugin) scanPort(ctx context.Context, ip string, port int) *OpenPort {
	timeout := time.Duration(p.config.Timeout) * time.Millisecond
	
	if p.config.TCPScan {
		// TCP Connect scan
		address := fmt.Sprintf("%s:%d", ip, port)
		conn, err := net.DialTimeout("tcp", address, timeout)
		if err != nil {
			return nil
		}
		defer conn.Close()

		openPort := &OpenPort{
			Port:     port,
			Protocol: "tcp",
			State:    "open",
		}

		// Add service name if known
		if service, exists := PortServices[port]; exists {
			openPort.Service = service
		}

		// Try to grab banner if service scan is enabled
		if p.config.ServiceScan {
			openPort.Banner = p.grabBanner(conn, port)
		}

		return openPort
	}

	// TODO: Implement UDP scanning if needed
	// UDP scanning is more complex and requires different techniques

	return nil
}

func (p *PortScanPlugin) grabBanner(conn net.Conn, port int) string {
	// Set a short timeout for banner grabbing
	if err := conn.SetReadDeadline(time.Now().Add(2 * time.Second)); err != nil {
		return ""
	}
	defer func() {
		// Reset deadline, ignore error as connection might be closed
		conn.SetReadDeadline(time.Time{})
	}()

	// Send appropriate probe based on port
	var probe []byte
	switch port {
	case 21: // FTP
		probe = []byte("HELP\r\n")
	case 22: // SSH
		// SSH sends banner immediately, no probe needed
	case 25: // SMTP
		probe = []byte("EHLO test\r\n")
	case 80, 8080: // HTTP
		probe = []byte("GET / HTTP/1.1\r\nHost: test\r\n\r\n")
	case 443, 8443: // HTTPS - don't probe, it's encrypted
		return ""
	case 110: // POP3
		probe = []byte("USER test\r\n")
	case 143: // IMAP
		probe = []byte("A001 CAPABILITY\r\n")
	default:
		probe = []byte("\r\n")
	}

	// Send probe if we have one
	if len(probe) > 0 {
		if _, err := conn.Write(probe); err != nil {
			return "" // Failed to send probe
		}
	}

	// Read response
	buffer := make([]byte, 1024)
	n, err := conn.Read(buffer)
	if err != nil {
		return ""
	}

	banner := strings.TrimSpace(string(buffer[:n]))
	// Clean up banner - remove control characters and limit length
	if len(banner) > 200 {
		banner = banner[:200]
	}
	
	return banner
}

func (p *PortScanPlugin) createPluginResult(scanResult PortScanResult, openPort OpenPort, host string) models.PluginResult {
	severity := p.calculateSeverity(openPort)
	
	data := map[string]interface{}{
		"host":     scanResult.Host,
		"ip":       scanResult.IP,
		"port":     openPort.Port,
		"protocol": openPort.Protocol,
		"state":    openPort.State,
		"service":  openPort.Service,
		"banner":   openPort.Banner,
		"scan_time": scanResult.ScanTime,
		"duration": scanResult.Duration.String(),
	}

	title := fmt.Sprintf("Open Port: %s:%d/%s", host, openPort.Port, openPort.Protocol)
	description := fmt.Sprintf("Found open port %d/%s on %s", openPort.Port, openPort.Protocol, host)
	
	if openPort.Service != "" {
		description += fmt.Sprintf(" (service: %s)", openPort.Service)
	}
	
	if openPort.Banner != "" {
		description += fmt.Sprintf(" (banner: %.50s...)", openPort.Banner)
	}

	return models.PluginResult{
		Plugin:      p.GetName(),
		Target:      host,
		Type:        "port_discovery",
		Severity:    severity,
		Title:       title,
		Description: description,
		Data:        data,
		Timestamp:   time.Now(),
		Confidence:  p.calculateConfidence(openPort),
		Risk:        p.calculateRisk(openPort),
	}
}

func (p *PortScanPlugin) calculateSeverity(openPort OpenPort) models.Severity {
	// Check for high-risk ports
	highRiskPorts := map[int]models.Severity{
		23:    models.SeverityCritical, // Telnet - unencrypted
		21:    models.SeverityHigh,     // FTP
		135:   models.SeverityHigh,     // RPC
		139:   models.SeverityHigh,     // NetBIOS
		445:   models.SeverityHigh,     // SMB
		1433:  models.SeverityHigh,     // MSSQL
		1521:  models.SeverityHigh,     // Oracle
		3306:  models.SeverityHigh,     // MySQL
		3389:  models.SeverityHigh,     // RDP
		5432:  models.SeverityHigh,     // PostgreSQL
		6379:  models.SeverityMedium,   // Redis
		27017: models.SeverityMedium,   // MongoDB
	}

	if severity, exists := highRiskPorts[openPort.Port]; exists {
		return severity
	}

	// SSH is special - medium risk
	if openPort.Port == 22 {
		return models.SeverityMedium
	}

	// Web services
	if openPort.Port == 80 || openPort.Port == 443 || openPort.Port == 8080 || openPort.Port == 8443 {
		return models.SeverityMedium
	}

	// Standard services
	standardPorts := []int{25, 53, 110, 143, 993, 995, 587, 465}
	for _, port := range standardPorts {
		if openPort.Port == port {
			return models.SeverityLow
		}
	}

	// High ports or uncommon services
	if openPort.Port > 10000 {
		return models.SeverityLow
	}

	return models.SeverityInfo
}

func (p *PortScanPlugin) calculateConfidence(openPort OpenPort) float64 {
	confidence := 0.95 // High confidence for connect scans

	// Higher confidence if service is identified
	if openPort.Service != "" {
		confidence += 0.03
	}

	// Higher confidence if banner is grabbed
	if openPort.Banner != "" {
		confidence += 0.02
	}

	// Cap at 1.0
	if confidence > 1.0 {
		confidence = 1.0
	}

	return confidence
}

func (p *PortScanPlugin) calculateRisk(openPort OpenPort) float64 {
	risk := 0.3 // Base risk

	// Critical risk services
	if openPort.Port == 23 { // Telnet
		risk = 0.9
	}

	// High risk services
	highRiskPorts := map[int]float64{
		21:    0.7, // FTP
		135:   0.6, // RPC
		139:   0.5, // NetBIOS
		445:   0.6, // SMB
		1433:  0.7, // MSSQL
		1521:  0.7, // Oracle
		3306:  0.6, // MySQL
		3389:  0.8, // RDP
		5432:  0.6, // PostgreSQL
		6379:  0.5, // Redis
		27017: 0.5, // MongoDB
	}

	if riskValue, exists := highRiskPorts[openPort.Port]; exists {
		risk = riskValue
	}

	// SSH - medium risk
	if openPort.Port == 22 {
		risk = 0.5
	}

	// Web services - moderate risk
	if openPort.Port == 80 || openPort.Port == 443 || openPort.Port == 8080 || openPort.Port == 8443 {
		risk = 0.4
	}

	// Increase risk if suspicious banner detected
	if openPort.Banner != "" {
		bannerLower := strings.ToLower(openPort.Banner)
		if strings.Contains(bannerLower, "default") ||
		   strings.Contains(bannerLower, "admin") ||
		   strings.Contains(bannerLower, "password") {
			risk += 0.1
		}
	}

	// Cap at 1.0
	if risk > 1.0 {
		risk = 1.0
	}

	return risk
}

func (p *PortScanPlugin) sharePortDiscovery(shared *core.SharedContext, scanResult PortScanResult, openPort OpenPort) {
	discoveryData := map[string]interface{}{
		"host":     scanResult.Host,
		"ip":       scanResult.IP,
		"port":     openPort.Port,
		"protocol": openPort.Protocol,
		"state":    openPort.State,
		"service":  openPort.Service,
		"banner":   openPort.Banner,
	}

	discovery := &models.Discovery{
		Type:       "port",
		Value:      fmt.Sprintf("%d/%s", openPort.Port, openPort.Protocol),
		Source:     p.GetName(),
		Confidence: p.calculateConfidence(openPort),
		Timestamp:  time.Now(),
		Data:       discoveryData,
	}

	shared.AddDiscovery(discovery)

	// Also add service discovery if service is identified
	if openPort.Service != "" {
		serviceDiscovery := &models.Discovery{
			Type:       "service",
			Value:      openPort.Service,
			Source:     p.GetName(),
			Confidence: p.calculateConfidence(openPort),
			Timestamp:  time.Now(),
			Data:       discoveryData,
		}
		shared.AddDiscovery(serviceDiscovery)
	}

	// Add host discovery
	hostDiscovery := &models.Discovery{
		Type:       "host",
		Value:      scanResult.IP,
		Source:     p.GetName(),
		Confidence: 0.9,
		Timestamp:  time.Now(),
		Data:       discoveryData,
	}
	shared.AddDiscovery(hostDiscovery)
}

func (p *PortScanPlugin) GetIntelligencePatterns() []models.IntelligencePattern {
	return []models.IntelligencePattern{
		{
			Name:        "Critical Telnet Service",
			Pattern:     `"port":23.*"protocol":"tcp".*"state":"open"`,
			Confidence:  0.95,
			Description: "Telnet service detected - unencrypted remote access",
			Tags:        []string{"telnet", "unencrypted", "critical"},
		},
		{
			Name:        "Database Services Exposed",
			Pattern:     `"port":(1433|3306|5432|1521|27017).*"state":"open"`,
			Confidence:  0.9,
			Description: "Database service exposed to network",
			Tags:        []string{"database", "exposed", "data"},
		},
		{
			Name:        "Remote Access Services",
			Pattern:     `"port":(22|3389|5900).*"state":"open"`,
			Confidence:  0.85,
			Description: "Remote access service detected",
			Tags:        []string{"remote-access", "administration"},
		},
		{
			Name:        "File Sharing Services",
			Pattern:     `"port":(21|139|445).*"state":"open"`,
			Confidence:  0.8,
			Description: "File sharing service detected",
			Tags:        []string{"file-sharing", "ftp", "smb"},
		},
		{
			Name:        "Web Services",
			Pattern:     `"port":(80|443|8080|8443).*"state":"open"`,
			Confidence:  0.8,
			Description: "Web service detected",
			Tags:        []string{"web", "http", "https"},
		},
		{
			Name:        "Default Credentials Banner",
			Pattern:     `"banner":".*([Dd]efault|[Aa]dmin|[Pp]assword).*"`,
			Confidence:  0.85,
			Description: "Service banner suggests default credentials",
			Tags:        []string{"default-credentials", "weak-auth", "banner"},
		},
	]
}
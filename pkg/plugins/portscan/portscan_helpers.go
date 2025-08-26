package portscan

import (
	"bufio"
	"encoding/json"
	"fmt"
	"io/ioutil"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/fatih/color"
	"github.com/f2u0a0d3/GoRecon/pkg/core"
	"github.com/f2u0a0d3/GoRecon/pkg/models"
)

// Helper methods for port scanning plugin

// parseSmapOutput parses smap output format
func (p *PortScanPlugin) parseSmapOutput(output string) []PortResult {
	var ports []PortResult
	
	lines := strings.Split(output, "\n")
	for _, line := range lines {
		line = strings.TrimSpace(line)
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		
		// smap format: port/proto service [additional info]
		parts := strings.Fields(line)
		if len(parts) < 2 {
			continue
		}
		
		portProto := strings.Split(parts[0], "/")
		if len(portProto) != 2 {
			continue
		}
		
		port, err := strconv.Atoi(portProto[0])
		if err != nil {
			continue
		}
		
		protocol := portProto[1]
		service := parts[1]
		
		var version string
		if len(parts) > 2 {
			version = strings.Join(parts[2:], " ")
		}
		
		ports = append(ports, PortResult{
			Port:       port,
			Protocol:   protocol,
			State:      "open",
			Service:    service,
			Version:    version,
			Source:     "smap",
			Confidence: 0.7, // Passive scan, lower confidence
			Timestamp:  time.Now(),
			Metadata: map[string]interface{}{
				"scan_type": "passive",
				"shodan_based": true,
			},
		})
	}
	
	return ports
}

// parseMasscanOutput parses masscan output format
func (p *PortScanPlugin) parseMasscanOutput(filename string) ([]PortResult, error) {
	file, err := os.Open(filename)
	if err != nil {
		return nil, err
	}
	defer file.Close()
	
	var ports []PortResult
	scanner := bufio.NewScanner(file)
	
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		
		// masscan format: open tcp 80 1.2.3.4
		parts := strings.Fields(line)
		if len(parts) < 4 {
			continue
		}
		
		state := parts[0]
		protocol := parts[1]
		portStr := parts[2]
		
		port, err := strconv.Atoi(portStr)
		if err != nil {
			continue
		}
		
		service := p.getServiceByPort(port, protocol)
		
		ports = append(ports, PortResult{
			Port:       port,
			Protocol:   protocol,
			State:      state,
			Service:    service,
			Source:     "masscan",
			Confidence: 0.95, // Active scan, high confidence
			Timestamp:  time.Now(),
			Metadata: map[string]interface{}{
				"scan_type": "active",
				"syn_scan": true,
			},
		})
	}
	
	return ports, scanner.Err()
}

// parseNaabuOutput parses naabu output format
func (p *PortScanPlugin) parseNaabuOutput(filename string) ([]PortResult, error) {
	file, err := os.Open(filename)
	if err != nil {
		return nil, err
	}
	defer file.Close()
	
	var ports []PortResult
	scanner := bufio.NewScanner(file)
	
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line == "" {
			continue
		}
		
		// naabu format: 1.2.3.4:80 or just 80
		var port int
		var err error
		
		if strings.Contains(line, ":") {
			parts := strings.Split(line, ":")
			if len(parts) >= 2 {
				port, err = strconv.Atoi(parts[len(parts)-1])
			}
		} else {
			port, err = strconv.Atoi(line)
		}
		
		if err != nil {
			continue
		}
		
		service := p.getServiceByPort(port, "tcp")
		
		ports = append(ports, PortResult{
			Port:       port,
			Protocol:   "tcp",
			State:      "open",
			Service:    service,
			Source:     "naabu",
			Confidence: 0.9, // Validation scan, high confidence
			Timestamp:  time.Now(),
			Metadata: map[string]interface{}{
				"scan_type": "validation",
				"verified": true,
			},
		})
	}
	
	return ports, scanner.Err()
}

// getServiceByPort returns common service name for port number
func (p *PortScanPlugin) getServiceByPort(port int, protocol string) string {
	services := map[string]map[int]string{
		"tcp": {
			21:   "ftp",
			22:   "ssh",
			23:   "telnet",
			25:   "smtp",
			53:   "domain",
			80:   "http",
			110:  "pop3",
			143:  "imap",
			443:  "https",
			993:  "imaps",
			995:  "pop3s",
			1433: "mssql",
			3306: "mysql",
			3389: "rdp",
			5432: "postgresql",
			5984: "couchdb",
			6379: "redis",
			8080: "http-proxy",
			8443: "https-alt",
			9200: "elasticsearch",
			27017: "mongodb",
		},
		"udp": {
			53:   "domain",
			67:   "dhcp",
			68:   "dhcp",
			69:   "tftp",
			123:  "ntp",
			161:  "snmp",
			162:  "snmptrap",
			514:  "syslog",
		},
	}
	
	if service, exists := services[protocol][port]; exists {
		return service
	}
	
	return "unknown"
}

// processResults processes and merges results from all scanning tools
func (p *PortScanPlugin) processResults(toolResults []ToolScanResult, targetIP, processedDir string) ([]PortResult, PortScanStats, error) {
	white := color.New(color.FgWhite, color.Bold).SprintFunc()
	cyan := color.New(color.FgCyan).SprintFunc()
	green := color.New(color.FgGreen).SprintFunc()

	fmt.Printf("%s\n", white("[GORECON::ANALYSIS] Port Analysis"))
	fmt.Printf("%s\n", strings.Repeat("=", 34))
	fmt.Printf("[%s] Consolidating results from %d tools...\n", cyan("*"), len(toolResults))

	// Merge and deduplicate ports
	portMap := make(map[int]*PortResult)
	stats := PortScanStats{
		ByService: make(map[string]int),
		BySource:  make(map[string]int),
		TargetIP:  targetIP,
	}

	for _, result := range toolResults {
		if result.Error != "" {
			continue
		}
		
		stats.BySource[result.Tool] = result.Count
		
		for _, port := range result.Ports {
			existing, exists := portMap[port.Port]
			if exists {
				// Port found by multiple tools - increase confidence
				existing.Confidence = (existing.Confidence + port.Confidence) / 2
				if existing.Confidence > 1.0 {
					existing.Confidence = 1.0
				}
				
				// Merge source information
				if !strings.Contains(existing.Source, port.Source) {
					existing.Source += "," + port.Source
				}
				
				// Keep best version/banner information
				if port.Version != "" && existing.Version == "" {
					existing.Version = port.Version
				}
				if port.Banner != "" && existing.Banner == "" {
					existing.Banner = port.Banner
				}
			} else {
				// New port
				portCopy := port
				portMap[port.Port] = &portCopy
			}
		}
	}

	// Convert to slice and sort
	var allPorts []PortResult
	for _, port := range portMap {
		allPorts = append(allPorts, *port)
		
		// Update stats
		if port.State == "open" {
			stats.OpenPorts++
		} else if port.State == "filtered" {
			stats.FilteredPorts++
		} else {
			stats.ClosedPorts++
		}
		
		stats.ByService[port.Service]++
	}
	
	// Sort by port number
	sort.Slice(allPorts, func(i, j int) bool {
		return allPorts[i].Port < allPorts[j].Port
	})
	
	stats.TotalPorts = len(allPorts)

	fmt.Printf("[%s] Consolidated %d unique open ports\n", green("+"), stats.OpenPorts)

	// Save processed results
	if err := p.saveProcessedResults(allPorts, stats, processedDir); err != nil {
		return allPorts, stats, err
	}

	return allPorts, stats, nil
}

// savePortsToFile saves port results to a file
func (p *PortScanPlugin) savePortsToFile(ports []PortResult, filename, source string) error {
	file, err := os.Create(filename)
	if err != nil {
		return err
	}
	defer file.Close()
	
	writer := bufio.NewWriter(file)
	defer writer.Flush()
	
	// Write header
	header := fmt.Sprintf("# Port scan results from %s\n", source)
	header += fmt.Sprintf("# Timestamp: %s\n", time.Now().Format(time.RFC3339))
	header += "# Format: port/protocol state service [version]\n"
	if _, err := writer.WriteString(header); err != nil {
		return err
	}
	
	for _, port := range ports {
		line := fmt.Sprintf("%d/%s %s %s", port.Port, port.Protocol, port.State, port.Service)
		if port.Version != "" {
			line += " " + port.Version
		}
		line += "\n"
		
		if _, err := writer.WriteString(line); err != nil {
			return err
		}
	}
	
	return nil
}

// saveProcessedResults saves processed and analyzed results
func (p *PortScanPlugin) saveProcessedResults(allPorts []PortResult, stats PortScanStats, processedDir string) error {
	// Save all ports in various formats
	allPortsFile := filepath.Join(processedDir, "all_ports.txt")
	if err := p.savePortsToFile(allPorts, allPortsFile, "consolidated"); err != nil {
		return fmt.Errorf("failed to save all ports: %w", err)
	}
	
	// Save only open ports
	var openPorts []PortResult
	for _, port := range allPorts {
		if port.State == "open" {
			openPorts = append(openPorts, port)
		}
	}
	
	openPortsFile := filepath.Join(processedDir, "open_ports.txt")
	if err := p.savePortsToFile(openPorts, openPortsFile, "open-only"); err != nil {
		return fmt.Errorf("failed to save open ports: %w", err)
	}
	
	// Save services list
	servicesFile := filepath.Join(processedDir, "services.txt")
	if err := p.saveServices(allPorts, servicesFile); err != nil {
		return fmt.Errorf("failed to save services: %w", err)
	}
	
	// Save JSON analysis
	analysisFile := filepath.Join(processedDir, "analysis.json")
	if err := p.saveAnalysisJSON(allPorts, stats, analysisFile); err != nil {
		return fmt.Errorf("failed to save analysis JSON: %w", err)
	}
	
	return nil
}

// saveServices saves discovered services to file
func (p *PortScanPlugin) saveServices(ports []PortResult, filename string) error {
	file, err := os.Create(filename)
	if err != nil {
		return err
	}
	defer file.Close()
	
	writer := bufio.NewWriter(file)
	defer writer.Flush()
	
	// Group by service
	serviceMap := make(map[string][]PortResult)
	for _, port := range ports {
		if port.State == "open" {
			serviceMap[port.Service] = append(serviceMap[port.Service], port)
		}
	}
	
	// Sort services by name
	var services []string
	for service := range serviceMap {
		services = append(services, service)
	}
	sort.Strings(services)
	
	for _, service := range services {
		ports := serviceMap[service]
		fmt.Fprintf(writer, "%s:\n", service)
		for _, port := range ports {
			fmt.Fprintf(writer, "  %d/%s", port.Port, port.Protocol)
			if port.Version != "" {
				fmt.Fprintf(writer, " (%s)", port.Version)
			}
			fmt.Fprintf(writer, "\n")
		}
		fmt.Fprintf(writer, "\n")
	}
	
	return nil
}

// saveAnalysisJSON saves complete analysis as JSON
func (p *PortScanPlugin) saveAnalysisJSON(ports []PortResult, stats PortScanStats, filename string) error {
	data := map[string]interface{}{
		"ports":      ports,
		"statistics": stats,
		"timestamp":  time.Now().Format(time.RFC3339),
		"scan_info": map[string]interface{}{
			"total_tools": len(stats.BySource),
			"scan_types": []string{"passive", "active", "validation"},
		},
	}
	
	jsonData, err := json.MarshalIndent(data, "", "  ")
	if err != nil {
		return err
	}
	
	return ioutil.WriteFile(filename, jsonData, 0644)
}

// displayResults displays the final port scanning results
func (p *PortScanPlugin) displayResults(allPorts []PortResult, stats PortScanStats, duration time.Duration) {
	green := color.New(color.FgGreen).SprintFunc()
	yellow := color.New(color.FgYellow).SprintFunc()
	red := color.New(color.FgRed).SprintFunc()
	cyan := color.New(color.FgCyan).SprintFunc()
	white := color.New(color.FgWhite, color.Bold).SprintFunc()

	fmt.Println()

	if stats.OpenPorts > 0 {
		fmt.Printf("%s\n", white("Open Ports:"))
		fmt.Printf("%s\n", strings.Repeat("-", 11))

		// Display open ports with service information
		for _, port := range allPorts {
			if port.State != "open" {
				continue
			}

			stateColor := green
			if port.State == "filtered" {
				stateColor = yellow
			} else if port.State == "closed" {
				stateColor = red
			}

			fmt.Printf("%d/%s\t%s\t%s", 
				port.Port, 
				port.Protocol, 
				stateColor(port.State), 
				port.Service)

			if port.Version != "" {
				fmt.Printf("\t%s", port.Version)
			}

			// Show confidence and source
			fmt.Printf("\t[%.0f%% - %s]", port.Confidence*100, port.Source)
			fmt.Println()
		}

		fmt.Println()
	}

	// Display service summary
	if len(stats.ByService) > 0 {
		fmt.Printf("%s\n", white("Services Found:"))
		fmt.Printf("%s\n", strings.Repeat("-", 15))

		// Sort services by count
		type serviceCount struct {
			name  string
			count int
		}
		var services []serviceCount
		for name, count := range stats.ByService {
			if name != "unknown" { // Skip unknown services
				services = append(services, serviceCount{name, count})
			}
		}
		sort.Slice(services, func(i, j int) bool {
			return services[i].count > services[j].count
		})

		for _, sc := range services {
			fmt.Printf("%s: %d port(s)\n", sc.name, sc.count)
		}
		fmt.Println()
	}

	// Display scan summary
	fmt.Printf("[%s] Scan completed in %v\n", cyan("*"), duration.Round(100*time.Millisecond))
	fmt.Printf("[%s] Total ports found: %d (%d open, %d filtered, %d closed)\n", 
		cyan("*"), stats.TotalPorts, stats.OpenPorts, stats.FilteredPorts, stats.ClosedPorts)

	// Display tool effectiveness
	if len(stats.BySource) > 1 {
		fmt.Printf("[%s] Tool results: ", cyan("*"))
		var toolStats []string
		for tool, count := range stats.BySource {
			toolStats = append(toolStats, fmt.Sprintf("%s (%d)", tool, count))
		}
		fmt.Printf("%s\n", strings.Join(toolStats, ", "))
	}
}

// generatePluginResults generates plugin results for the pipeline
func (p *PortScanPlugin) generatePluginResults(target *models.Target, allPorts []PortResult, stats PortScanStats, results chan<- models.PluginResult) {
	// Generate summary result
	summaryData := map[string]interface{}{
		"total_ports":    stats.TotalPorts,
		"open_ports":     stats.OpenPorts,
		"filtered_ports": stats.FilteredPorts,
		"closed_ports":   stats.ClosedPorts,
		"by_service":     stats.ByService,
		"by_source":      stats.BySource,
		"target_ip":      stats.TargetIP,
		"scan_duration":  stats.ScanDuration,
	}

	summaryResult := models.PluginResult{
		Plugin:      "portscan",
		Target:      target.URL,
		Severity:    models.SeverityInfo,
		Title:       "Port Scanning Summary",
		Description: fmt.Sprintf("Discovered %d open ports on %s", stats.OpenPorts, stats.TargetIP),
		Data:        summaryData,
		Timestamp:   time.Now(),
	}

	results <- summaryResult

	// Generate results for individual open ports
	for _, port := range allPorts {
		if port.State != "open" {
			continue
		}

		severity := models.SeverityLow
		
		// Classify severity based on service
		switch port.Service {
		case "ssh", "rdp", "ftp", "telnet":
			severity = models.SeverityMedium
		case "mysql", "postgresql", "mssql", "mongodb", "redis":
			severity = models.SeverityHigh
		case "http", "https", "http-proxy":
			severity = models.SeverityLow
		}

		portData := map[string]interface{}{
			"port":       port.Port,
			"protocol":   port.Protocol,
			"state":      port.State,
			"service":    port.Service,
			"version":    port.Version,
			"banner":     port.Banner,
			"source":     port.Source,
			"confidence": port.Confidence,
		}

		portResult := models.PluginResult{
			Plugin:      "portscan",
			Target:      target.URL,
			Severity:    severity,
			Title:       fmt.Sprintf("Open Port: %d/%s (%s)", port.Port, port.Protocol, port.Service),
			Description: fmt.Sprintf("Found open %s service on port %d", port.Service, port.Port),
			Data:        portData,
			Timestamp:   time.Now(),
		}

		results <- portResult
	}
}

// addDiscoveries adds port discoveries to the shared context
func (p *PortScanPlugin) addDiscoveries(shared *core.SharedContext, domain string, allPorts []PortResult, stats PortScanStats) {
	// Add port discoveries
	for _, port := range allPorts {
		if port.State != "open" {
			continue
		}

		shared.AddDiscovery(models.Discovery{
			Type:       "open_port",
			Value:      fmt.Sprintf("%s:%d", stats.TargetIP, port.Port),
			Source:     "portscan",
			Confidence: port.Confidence,
			Timestamp:  time.Now(),
			Metadata: map[string]interface{}{
				"port":       port.Port,
				"protocol":   port.Protocol,
				"service":    port.Service,
				"version":    port.Version,
				"scan_tool":  port.Source,
				"target_ip":  stats.TargetIP,
				"domain":     domain,
			},
		})

		// Add service discoveries
		if port.Service != "unknown" {
			shared.AddDiscovery(models.Discovery{
				Type:       "service",
				Value:      port.Service,
				Source:     "portscan",
				Confidence: port.Confidence * 0.9,
				Timestamp:  time.Now(),
				Metadata: map[string]interface{}{
					"port":      port.Port,
					"protocol":  port.Protocol,
					"version":   port.Version,
					"target_ip": stats.TargetIP,
					"domain":    domain,
				},
			})
		}

		// Add HTTP service discoveries for web probing
		if port.Service == "http" || port.Service == "https" || port.Service == "http-proxy" {
			protocol := "http"
			if port.Service == "https" || port.Port == 443 {
				protocol = "https"
			}

			url := fmt.Sprintf("%s://%s:%d", protocol, domain, port.Port)
			shared.AddDiscovery(models.Discovery{
				Type:       "http_service",
				Value:      url,
				Source:     "portscan",
				Confidence: port.Confidence,
				Timestamp:  time.Now(),
				Metadata: map[string]interface{}{
					"port":      port.Port,
					"protocol":  protocol,
					"service":   port.Service,
					"target_ip": stats.TargetIP,
					"domain":    domain,
				},
			})
		}
	}
}
package portscan

import (
	"context"
	"fmt"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/fatih/color"
	"github.com/f2u0a0d3/GoRecon/pkg/core"
	"github.com/f2u0a0d3/GoRecon/pkg/models"
	"github.com/f2u0a0d3/GoRecon/pkg/plugins/base"
)

// PortScanPlugin implements comprehensive port scanning
type PortScanPlugin struct {
	*base.BaseAdapter
	config *PortScanConfig
}

// PortScanConfig contains configuration for port scanning
type PortScanConfig struct {
	EnableSmap    bool          `json:"enable_smap"`
	EnableMasscan bool          `json:"enable_masscan"`
	EnableNaabu   bool          `json:"enable_naabu"`
	TopPorts      int           `json:"top_ports"`
	CustomPorts   []string      `json:"custom_ports"`
	Timeout       time.Duration `json:"timeout"`
	Rate          int           `json:"rate"`
	RequireSudo   bool          `json:"require_sudo"`
	ConnectScan   bool          `json:"connect_scan"`
}

// PortResult represents a discovered port
type PortResult struct {
	Port        int               `json:"port"`
	Protocol    string            `json:"protocol"`
	State       string            `json:"state"`
	Service     string            `json:"service"`
	Version     string            `json:"version,omitempty"`
	Banner      string            `json:"banner,omitempty"`
	Source      string            `json:"source"`
	Confidence  float64           `json:"confidence"`
	Timestamp   time.Time         `json:"timestamp"`
	Metadata    map[string]interface{} `json:"metadata"`
}

// PortScanStats contains statistics about the scan
type PortScanStats struct {
	TotalPorts    int                    `json:"total_ports"`
	OpenPorts     int                    `json:"open_ports"`
	FilteredPorts int                    `json:"filtered_ports"`
	ClosedPorts   int                    `json:"closed_ports"`
	ByService     map[string]int         `json:"by_service"`
	BySource      map[string]int         `json:"by_source"`
	ScanDuration  time.Duration          `json:"scan_duration"`
	TargetIP      string                 `json:"target_ip"`
}

// ToolScanResult represents results from individual scanning tools
type ToolScanResult struct {
	Tool     string       `json:"tool"`
	Ports    []PortResult `json:"ports"`
	Count    int          `json:"count"`
	Duration time.Duration `json:"duration"`
	Error    string       `json:"error,omitempty"`
	Warning  string       `json:"warning,omitempty"`
}

// NewPortScanPlugin creates a new port scanning plugin
func NewPortScanPlugin() *PortScanPlugin {
	config := &PortScanConfig{
		EnableSmap:    true,
		EnableMasscan: true,
		EnableNaabu:   true,
		TopPorts:      1000,
		Timeout:       30 * time.Minute,
		Rate:          1000,
		ConnectScan:   false,
	}

	baseAdapter := base.NewBaseAdapter(base.BaseAdapterConfig{
		Name:        "portscan",
		Category:    "portscan",
		Description: "Comprehensive port scanning using multiple tools",
		Version:     "1.0.0",
		Author:      "GoRecon Team",
		ToolName:    "smap",
		Passive:     false,
		Duration:    config.Timeout,
		Concurrency: 3,
		Priority:    6,
		Resources: core.Resources{
			CPUCores:      4,
			MemoryMB:      2048,
			NetworkAccess: true,
		},
		Provides: []string{"open_ports", "services", "banners"},
		Consumes: []string{"domain", "ip_address"},
	})

	return &PortScanPlugin{
		BaseAdapter: baseAdapter,
		config:      config,
	}
}

// Run executes the port scanning workflow
func (p *PortScanPlugin) Run(ctx context.Context, target *models.Target, results chan<- models.PluginResult, shared *core.SharedContext) error {
	logger := shared.GetLogger().WithField("plugin", "portscan")
	
	// Create color functions
	cyan := color.New(color.FgCyan).SprintFunc()
	green := color.New(color.FgGreen).SprintFunc()
	white := color.New(color.FgWhite, color.Bold).SprintFunc()

	// Extract domain and resolve IP
	domain := target.Domain
	if domain == "" {
		domain = p.ExtractDomain(target.URL)
	}

	// Resolve target IP
	targetIP, err := p.resolveIP(domain)
	if err != nil {
		logger.Error("Failed to resolve target IP", err)
		return fmt.Errorf("failed to resolve %s: %w", domain, err)
	}

	// Display header
	fmt.Printf("\n%s\n", white("[GORECON] Port Scanner v1.0"))
	fmt.Printf("%s\n", strings.Repeat("=", 27))
	fmt.Printf("[%s] Target: %s (%s)\n", green("*"), domain, targetIP)

	// Check sudo availability
	hasSudo := p.checkSudoAvailable()
	tools := p.selectTools(hasSudo)
	
	fmt.Printf("[%s] Using: %s\n\n", cyan("*"), strings.Join(tools, ", "))

	// Create workspace
	workDir := filepath.Join("./work", domain, "portscan")
	if err := os.MkdirAll(workDir, 0755); err != nil {
		return fmt.Errorf("failed to create workspace: %w", err)
	}
	
	rawDir := filepath.Join(workDir, "raw")
	processedDir := filepath.Join(workDir, "processed")
	for _, dir := range []string{rawDir, processedDir} {
		if err := os.MkdirAll(dir, 0755); err != nil {
			return fmt.Errorf("failed to create directory %s: %w", dir, err)
		}
	}

	startTime := time.Now()
	var toolResults []ToolScanResult
	var wg sync.WaitGroup
	var mu sync.Mutex

	// Run scanning tools in parallel
	scanTools := []struct {
		name    string
		enabled bool
		fn      func() ToolScanResult
	}{
		{"smap", p.config.EnableSmap, func() ToolScanResult { return p.runSmap(ctx, domain, targetIP, rawDir) }},
		{"masscan", p.config.EnableMasscan && hasSudo, func() ToolScanResult { return p.runMasscan(ctx, targetIP, rawDir) }},
		{"naabu", p.config.EnableNaabu, func() ToolScanResult { return p.runNaabu(ctx, targetIP, rawDir, hasSudo) }},
	}

	for _, tool := range scanTools {
		if !tool.enabled {
			continue
		}
		
		wg.Add(1)
		go func(t struct {
			name    string
			enabled bool
			fn      func() ToolScanResult
		}) {
			defer wg.Done()
			result := t.fn()
			mu.Lock()
			toolResults = append(toolResults, result)
			mu.Unlock()
		}(tool)
	}

	wg.Wait()

	// Process and analyze results
	allPorts, stats, err := p.processResults(toolResults, targetIP, processedDir)
	if err != nil {
		logger.Error("Failed to process results", err)
		return err
	}

	// Display results
	p.displayResults(allPorts, stats, time.Since(startTime))

	// Generate plugin results
	p.generatePluginResults(target, allPorts, stats, results)

	// Add discoveries
	p.addDiscoveries(shared, domain, allPorts, stats)

	logger.Info("Port scanning completed",
		"target", domain,
		"target_ip", targetIP,
		"open_ports", stats.OpenPorts,
		"total_ports", stats.TotalPorts,
		"duration", time.Since(startTime))

	return nil
}

// checkSudoAvailable checks if running with sudo privileges
func (p *PortScanPlugin) checkSudoAvailable() bool {
	return os.Geteuid() == 0
}

// selectTools determines which tools to use based on sudo availability
func (p *PortScanPlugin) selectTools(hasSudo bool) []string {
	var tools []string
	
	if p.config.EnableSmap {
		tools = append(tools, "smap (passive)")
	}
	
	if p.config.EnableMasscan {
		if hasSudo {
			tools = append(tools, "masscan (active)")
		} else {
			tools = append(tools, "masscan (requires sudo - skipped)")
		}
	}
	
	if p.config.EnableNaabu {
		if hasSudo {
			tools = append(tools, "naabu (SYN scan)")
		} else {
			tools = append(tools, "naabu (connect scan)")
		}
	}
	
	return tools
}

// resolveIP resolves domain to IP address
func (p *PortScanPlugin) resolveIP(domain string) (string, error) {
	// Remove protocol if present
	domain = strings.TrimPrefix(domain, "https://")
	domain = strings.TrimPrefix(domain, "http://")
	
	// Remove port if present
	if colonIndex := strings.LastIndex(domain, ":"); colonIndex != -1 {
		if portPart := domain[colonIndex+1:]; strings.Contains(portPart, "/") {
			// This is a URL path, not a port
		} else if _, err := strconv.Atoi(portPart); err == nil {
			// This is a port number
			domain = domain[:colonIndex]
		}
	}
	
	// Remove path if present
	if slashIndex := strings.Index(domain, "/"); slashIndex != -1 {
		domain = domain[:slashIndex]
	}
	
	// Check if it's already an IP address
	if net.ParseIP(domain) != nil {
		return domain, nil
	}
	
	// Resolve domain to IP
	ips, err := net.LookupIP(domain)
	if err != nil {
		return "", err
	}
	
	for _, ip := range ips {
		if ip.To4() != nil {
			return ip.String(), nil
		}
	}
	
	return "", fmt.Errorf("no IPv4 address found for %s", domain)
}

// runSmap executes smap for passive port discovery
func (p *PortScanPlugin) runSmap(ctx context.Context, domain, targetIP, rawDir string) ToolScanResult {
	cyan := color.New(color.FgCyan).SprintFunc()
	green := color.New(color.FgGreen).SprintFunc()
	red := color.New(color.FgRed).SprintFunc()
	white := color.New(color.FgWhite, color.Bold).SprintFunc()

	fmt.Printf("%s\n", white("[GORECON::PORTSCAN] Passive Discovery (smap)"))
	fmt.Printf("%s\n", strings.Repeat("=", 45))

	startTime := time.Now()
	outputFile := filepath.Join(rawDir, "smap.txt")

	// Check if smap is installed
	if _, err := exec.LookPath("smap"); err != nil {
		fmt.Printf("[%s] smap not found\n", red("-"))
		fmt.Printf("[%s] Install: go install github.com/s0md3v/smap@latest\n", cyan("*"))
		return ToolScanResult{
			Tool:    "smap",
			Error:   "tool not installed",
			Warning: "Install with: go install github.com/s0md3v/smap@latest",
		}
	}

	fmt.Printf("[%s] Querying Shodan for historical port data...\n", cyan("*"))

	// Execute smap
	cmd := exec.CommandContext(ctx, "smap", "-H", targetIP)
	output, err := cmd.Output()
	if err != nil {
		fmt.Printf("[%s] smap failed: %v\n", red("-"), err)
		return ToolScanResult{
			Tool:     "smap",
			Error:    err.Error(),
			Duration: time.Since(startTime),
		}
	}

	// Parse smap output
	ports := p.parseSmapOutput(string(output))

	// Save results
	if err := p.savePortsToFile(ports, outputFile, "smap"); err != nil {
		fmt.Printf("[%s] Failed to save smap results: %v\n", red("-"), err)
	}

	duration := time.Since(startTime)
	fmt.Printf("[%s] Found %d previously open ports\n", green("+"), len(ports))
	fmt.Println()

	return ToolScanResult{
		Tool:     "smap",
		Ports:    ports,
		Count:    len(ports),
		Duration: duration,
	}
}

// runMasscan executes masscan for fast active scanning
func (p *PortScanPlugin) runMasscan(ctx context.Context, targetIP, rawDir string) ToolScanResult {
	cyan := color.New(color.FgCyan).SprintFunc()
	green := color.New(color.FgGreen).SprintFunc()
	red := color.New(color.FgRed).SprintFunc()
	white := color.New(color.FgWhite, color.Bold).SprintFunc()

	fmt.Printf("%s\n", white("[GORECON::PORTSCAN] Active Scanning"))
	fmt.Printf("%s\n", strings.Repeat("=", 36))

	startTime := time.Now()
	outputFile := filepath.Join(rawDir, "masscan.txt")

	// Check if masscan is installed
	if _, err := exec.LookPath("masscan"); err != nil {
		fmt.Printf("[%s] masscan not found\n", red("-"))
		fmt.Printf("[%s] Install: sudo apt-get install masscan\n", cyan("*"))
		return ToolScanResult{
			Tool:    "masscan",
			Error:   "tool not installed",
			Warning: "Install with: sudo apt-get install masscan",
		}
	}

	fmt.Printf("[%s] Scanning top %d ports...\n", cyan("*"), p.config.TopPorts)

	// Execute masscan
	cmd := exec.CommandContext(ctx, "masscan",
		targetIP,
		"--top-ports", strconv.Itoa(p.config.TopPorts),
		"--rate", strconv.Itoa(p.config.Rate),
		"--banners",
		"--output-format", "list",
		"--output-filename", outputFile)

	if err := cmd.Run(); err != nil {
		fmt.Printf("[%s] masscan failed: %v\n", red("-"), err)
		return ToolScanResult{
			Tool:     "masscan",
			Error:    err.Error(),
			Duration: time.Since(startTime),
		}
	}

	// Parse masscan output
	ports, err := p.parseMasscanOutput(outputFile)
	if err != nil {
		fmt.Printf("[%s] Failed to parse masscan output: %v\n", red("-"), err)
		return ToolScanResult{
			Tool:     "masscan",
			Error:    err.Error(),
			Duration: time.Since(startTime),
		}
	}

	duration := time.Since(startTime)
	fmt.Printf("[%s] Found %d open ports\n", green("+"), len(ports))
	fmt.Println()

	return ToolScanResult{
		Tool:     "masscan",
		Ports:    ports,
		Count:    len(ports),
		Duration: duration,
	}
}

// runNaabu executes naabu for port validation
func (p *PortScanPlugin) runNaabu(ctx context.Context, targetIP, rawDir string, hasSudo bool) ToolScanResult {
	cyan := color.New(color.FgCyan).SprintFunc()
	green := color.New(color.FgGreen).SprintFunc()
	red := color.New(color.FgRed).SprintFunc()
	yellow := color.New(color.FgYellow).SprintFunc()
	white := color.New(color.FgWhite, color.Bold).SprintFunc()

	fmt.Printf("%s\n", white("[GORECON::PORTSCAN] Port Validation (naabu)"))
	fmt.Printf("%s\n", strings.Repeat("=", 43))

	startTime := time.Now()
	outputFile := filepath.Join(rawDir, "naabu.txt")

	// Check if naabu is installed
	if _, err := exec.LookPath("naabu"); err != nil {
		fmt.Printf("[%s] naabu not found\n", red("-"))
		fmt.Printf("[%s] Install: go install github.com/projectdiscovery/naabu/v2/cmd/naabu@latest\n", cyan("*"))
		return ToolScanResult{
			Tool:    "naabu",
			Error:   "tool not installed",
			Warning: "Install with: go install github.com/projectdiscovery/naabu/v2/cmd/naabu@latest",
		}
	}

	// Build naabu command
	args := []string{
		"-host", targetIP,
		"-top-ports", strconv.Itoa(p.config.TopPorts),
		"-o", outputFile,
		"-silent",
	}

	if !hasSudo {
		fmt.Printf("[%s] naabu requires sudo for SYN scan - using connect scan (slower)\n", yellow("!"))
		args = append(args, "-Pn") // Skip ping and use connect scan
	}

	fmt.Printf("[%s] Scanning with %s mode...\n", cyan("*"), 
		map[bool]string{true: "SYN", false: "connect"}[hasSudo])

	// Execute naabu
	cmd := exec.CommandContext(ctx, "naabu", args...)
	if err := cmd.Run(); err != nil {
		fmt.Printf("[%s] naabu failed: %v\n", red("-"), err)
		return ToolScanResult{
			Tool:     "naabu",
			Error:    err.Error(),
			Duration: time.Since(startTime),
		}
	}

	// Parse naabu output
	ports, err := p.parseNaabuOutput(outputFile)
	if err != nil {
		fmt.Printf("[%s] Failed to parse naabu output: %v\n", red("-"), err)
		return ToolScanResult{
			Tool:     "naabu",
			Error:    err.Error(),
			Duration: time.Since(startTime),
		}
	}

	duration := time.Since(startTime)
	fmt.Printf("[%s] Validated %d open ports\n", green("+"), len(ports))
	fmt.Println()

	return ToolScanResult{
		Tool:     "naabu",
		Ports:    ports,
		Count:    len(ports),
		Duration: duration,
	}
}
package network

import (
	"bufio"
	"context"
	"encoding/xml"
	"fmt"
	"strconv"
	"strings"
	"time"

	"github.com/f2u0a0d3/GoRecon/pkg/plugins/base"
	"github.com/f2u0a0d3/GoRecon/pkg/core"
	"github.com/f2u0a0d3/GoRecon/pkg/models"
)

type NmapPlugin struct {
	base.BaseAdapter
	config *NmapConfig
}

type NmapConfig struct {
	Threads        int
	Timeout        int
	Ports          string
	ScanType       string
	ServiceDetection bool
	OSDetection    bool
	ScriptScan     bool
	OutputFormat   string
	Timing         int
	MaxRetries     int
}

type NmapResult struct {
	XMLName xml.Name `xml:"nmaprun"`
	Hosts   []Host   `xml:"host"`
}

type Host struct {
	Address   []Address `xml:"address"`
	Hostnames []Hostname `xml:"hostnames>hostname"`
	Ports     []Port    `xml:"ports>port"`
	OS        OS        `xml:"os"`
	Status    Status    `xml:"status"`
}

type Address struct {
	Addr     string `xml:"addr,attr"`
	AddrType string `xml:"addrtype,attr"`
}

type Hostname struct {
	Name string `xml:"name,attr"`
	Type string `xml:"type,attr"`
}

type Port struct {
	Protocol string  `xml:"protocol,attr"`
	PortID   int     `xml:"portid,attr"`
	State    State   `xml:"state"`
	Service  Service `xml:"service"`
}

type State struct {
	State  string `xml:"state,attr"`
	Reason string `xml:"reason,attr"`
}

type Service struct {
	Name    string `xml:"name,attr"`
	Product string `xml:"product,attr"`
	Version string `xml:"version,attr"`
}

type OS struct {
	Matches []OSMatch `xml:"osmatch"`
}

type OSMatch struct {
	Name     string `xml:"name,attr"`
	Accuracy int    `xml:"accuracy,attr"`
}

type Status struct {
	State  string `xml:"state,attr"`
	Reason string `xml:"reason,attr"`
}

func NewNmapPlugin() *NmapPlugin {
	return &NmapPlugin{
		BaseAdapter: base.BaseAdapter{
			PluginName:        "nmap",
			PluginVersion:     "1.0.0",
			PluginDescription: "Advanced network port scanner using Nmap",
			PluginAuthor:     "GoRecon Team",
			SupportedTargets: []string{"domain", "ip", "cidr"},
		},
		config: &NmapConfig{
			Threads:          10,
			Timeout:          300,
			Ports:            "1-65535",
			ScanType:         "syn",
			ServiceDetection: true,
			OSDetection:      false,
			ScriptScan:       false,
			OutputFormat:     "xml",
			Timing:           3,
			MaxRetries:       2,
		},
	}
}

func (n *NmapPlugin) SetConfig(configMap map[string]interface{}) error {
	if threads, ok := configMap["threads"].(int); ok && threads > 0 && threads <= 1000 {
		n.config.Threads = threads
	}
	if timeout, ok := configMap["timeout"].(int); ok && timeout > 0 && timeout <= 3600 {
		n.config.Timeout = timeout
	}
	if ports, ok := configMap["ports"].(string); ok && ports != "" {
		n.config.Ports = ports
	}
	if scanType, ok := configMap["scan_type"].(string); ok && scanType != "" {
		validTypes := map[string]bool{"syn": true, "tcp": true, "udp": true, "ack": true, "fin": true}
		if validTypes[scanType] {
			n.config.ScanType = scanType
		}
	}
	if serviceDetection, ok := configMap["service_detection"].(bool); ok {
		n.config.ServiceDetection = serviceDetection
	}
	if osDetection, ok := configMap["os_detection"].(bool); ok {
		n.config.OSDetection = osDetection
	}
	if scriptScan, ok := configMap["script_scan"].(bool); ok {
		n.config.ScriptScan = scriptScan
	}
	if timing, ok := configMap["timing"].(int); ok && timing >= 0 && timing <= 5 {
		n.config.Timing = timing
	}
	if maxRetries, ok := configMap["max_retries"].(int); ok && maxRetries >= 0 && maxRetries <= 10 {
		n.config.MaxRetries = maxRetries
	}
	return nil
}

func (n *NmapPlugin) Execute(ctx context.Context, target models.Target, sharedCtx *core.SharedContext) (*models.PluginResult, error) {
	if target.GetType() != "domain" && target.GetType() != "ip" && target.GetType() != "cidr" {
		return nil, fmt.Errorf("unsupported target type: %s", target.GetType())
	}

	targetStr := n.getTargetString(target)
	if targetStr == "" {
		return nil, fmt.Errorf("invalid target for nmap scan")
	}

	args := n.buildNmapArgs(targetStr)
	
	output, err := n.ExecuteCommand(ctx, "nmap", args, time.Duration(n.config.Timeout)*time.Second)
	if err != nil {
		return nil, fmt.Errorf("nmap execution failed: %w", err)
	}

	result, err := n.parseNmapOutput(output, target)
	if err != nil {
		return nil, fmt.Errorf("failed to parse nmap output: %w", err)
	}

	n.populateSharedContext(result, sharedCtx)

	return result, nil
}

func (n *NmapPlugin) getTargetString(target models.Target) string {
	switch target.GetType() {
	case "domain":
		return target.GetDomain()
	case "ip":
		return target.GetIP()
	case "cidr":
		return target.GetCIDR()
	default:
		return ""
	}
}

func (n *NmapPlugin) buildNmapArgs(target string) []string {
	args := []string{
		"-T" + strconv.Itoa(n.config.Timing),
		"--max-retries", strconv.Itoa(n.config.MaxRetries),
		"-p", n.config.Ports,
	}

	switch n.config.ScanType {
	case "syn":
		args = append(args, "-sS")
	case "tcp":
		args = append(args, "-sT")
	case "udp":
		args = append(args, "-sU")
	case "ack":
		args = append(args, "-sA")
	case "fin":
		args = append(args, "-sF")
	}

	if n.config.ServiceDetection {
		args = append(args, "-sV")
	}

	if n.config.OSDetection {
		args = append(args, "-O")
	}

	if n.config.ScriptScan {
		args = append(args, "-sC")
	}

	args = append(args, "-oX", "-")
	args = append(args, target)

	return args
}

func (n *NmapPlugin) parseNmapOutput(output string, target models.Target) (*models.PluginResult, error) {
	result := &models.PluginResult{
		PluginName: n.PluginName,
		Target:     target,
		Status:     models.StatusSuccess,
		Timestamp:  time.Now(),
		Results:    make(map[string]interface{}),
		RawOutput:  output,
	}

	if strings.TrimSpace(output) == "" {
		result.Status = models.StatusError
		result.Error = "empty nmap output"
		return result, nil
	}

	var nmapResult NmapResult
	if err := xml.Unmarshal([]byte(output), &nmapResult); err != nil {
		lines := strings.Split(output, "\n")
		for _, line := range lines {
			line = strings.TrimSpace(line)
			if line == "" {
				continue
			}
			
			select {
			case <-ctx.Done():
				return result, ctx.Err()
			default:
			}

			if strings.Contains(line, "/tcp") || strings.Contains(line, "/udp") {
				if portInfo := n.parsePortLine(line); portInfo != nil {
					if result.Results["ports"] == nil {
						result.Results["ports"] = make([]map[string]interface{}, 0)
					}
					ports := result.Results["ports"].([]map[string]interface{})
					result.Results["ports"] = append(ports, portInfo)
				}
			}
		}
		return result, nil
	}

	ports := make([]map[string]interface{}, 0)
	hostInfo := make(map[string]interface{})

	for _, host := range nmapResult.Hosts {
		if len(host.Address) > 0 {
			hostInfo["ip"] = host.Address[0].Addr
		}

		if len(host.Hostnames) > 0 {
			hostnames := make([]string, len(host.Hostnames))
			for i, hostname := range host.Hostnames {
				hostnames[i] = hostname.Name
			}
			hostInfo["hostnames"] = hostnames
		}

		hostInfo["status"] = host.Status.State
		hostInfo["reason"] = host.Status.Reason

		if len(host.OS.Matches) > 0 {
			osInfo := make([]map[string]interface{}, len(host.OS.Matches))
			for i, osMatch := range host.OS.Matches {
				osInfo[i] = map[string]interface{}{
					"name":     osMatch.Name,
					"accuracy": osMatch.Accuracy,
				}
			}
			hostInfo["os_detection"] = osInfo
		}

		for _, port := range host.Ports {
			if port.State.State == "open" || port.State.State == "filtered" {
				portInfo := map[string]interface{}{
					"port":     port.PortID,
					"protocol": port.Protocol,
					"state":    port.State.State,
					"reason":   port.State.Reason,
				}

				if port.Service.Name != "" {
					serviceInfo := map[string]interface{}{
						"name": port.Service.Name,
					}
					if port.Service.Product != "" {
						serviceInfo["product"] = port.Service.Product
					}
					if port.Service.Version != "" {
						serviceInfo["version"] = port.Service.Version
					}
					portInfo["service"] = serviceInfo
				}

				ports = append(ports, portInfo)
			}
		}
	}

	result.Results["host_info"] = hostInfo
	result.Results["ports"] = ports
	result.Results["total_ports"] = len(ports)

	riskScore := n.calculateRiskScore(ports)
	result.Results["risk_score"] = riskScore

	return result, nil
}

func (n *NmapPlugin) parsePortLine(line string) map[string]interface{} {
	parts := strings.Fields(line)
	if len(parts) < 3 {
		return nil
	}

	portProto := parts[0]
	state := parts[1]
	service := ""
	if len(parts) > 2 {
		service = parts[2]
	}

	portProtoParts := strings.Split(portProto, "/")
	if len(portProtoParts) != 2 {
		return nil
	}

	port, err := strconv.Atoi(portProtoParts[0])
	if err != nil {
		return nil
	}

	protocol := portProtoParts[1]

	return map[string]interface{}{
		"port":     port,
		"protocol": protocol,
		"state":    state,
		"service":  service,
	}
}

func (n *NmapPlugin) calculateRiskScore(ports []map[string]interface{}) float64 {
	if len(ports) == 0 {
		return 0.0
	}

	score := 0.0
	highRiskPorts := map[int]bool{
		21: true, 22: true, 23: true, 25: true, 53: true,
		80: true, 110: true, 135: true, 139: true, 143: true,
		443: true, 445: true, 993: true, 995: true, 1433: true,
		1521: true, 3306: true, 3389: true, 5432: true, 5900: true,
	}

	for _, portData := range ports {
		if port, ok := portData["port"].(int); ok {
			if state, ok := portData["state"].(string); ok && state == "open" {
				if highRiskPorts[port] {
					score += 2.0
				} else {
					score += 1.0
				}
			}
		}
	}

	maxScore := float64(len(ports)) * 2.0
	if maxScore > 0 {
		return (score / maxScore) * 10.0
	}
	return 0.0
}

func (n *NmapPlugin) populateSharedContext(result *models.PluginResult, sharedCtx *core.SharedContext) {
	if ports, ok := result.Results["ports"].([]map[string]interface{}); ok {
		for _, portData := range ports {
			if port, ok := portData["port"].(int); ok {
				if state, ok := portData["state"].(string); ok && state == "open" {
					sharedCtx.AddPort(port)
					
					if service, ok := portData["service"].(map[string]interface{}); ok {
						if serviceName, ok := service["name"].(string); ok {
							sharedCtx.AddService(serviceName)
						}
					}
				}
			}
		}
	}

	if hostInfo, ok := result.Results["host_info"].(map[string]interface{}); ok {
		if hostnames, ok := hostInfo["hostnames"].([]string); ok {
			for _, hostname := range hostnames {
				sharedCtx.AddSubdomain(hostname)
			}
		}
	}
}

func (n *NmapPlugin) Cleanup() error {
	return nil
}

func (n *NmapPlugin) ValidateConfig() error {
	if n.config.Threads < 1 || n.config.Threads > 1000 {
		return fmt.Errorf("threads must be between 1 and 1000")
	}
	if n.config.Timeout < 1 || n.config.Timeout > 3600 {
		return fmt.Errorf("timeout must be between 1 and 3600 seconds")
	}
	if n.config.Timing < 0 || n.config.Timing > 5 {
		return fmt.Errorf("timing must be between 0 and 5")
	}
	if n.config.MaxRetries < 0 || n.config.MaxRetries > 10 {
		return fmt.Errorf("max_retries must be between 0 and 10")
	}
	return nil
}
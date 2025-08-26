package network

import (
	"bufio"
	"context"
	"fmt"
	"strconv"
	"strings"
	"time"

	"github.com/f2u0a0d3/GoRecon/pkg/plugins/base"
	"github.com/f2u0a0d3/GoRecon/pkg/core"
	"github.com/f2u0a0d3/GoRecon/pkg/models"
)

type MasscanPlugin struct {
	base.BaseAdapter
	config *MasscanConfig
}

type MasscanConfig struct {
	Rate       int
	Ports      string
	Timeout    int
	MaxRetries int
	Banners    bool
	OutputFormat string
}

func NewMasscanPlugin() *MasscanPlugin {
	return &MasscanPlugin{
		BaseAdapter: base.BaseAdapter{
			PluginName:        "masscan",
			PluginVersion:     "1.0.0",
			PluginDescription: "Ultra-fast port scanner using Masscan for large-scale network reconnaissance",
			PluginAuthor:     "GoRecon Team",
			SupportedTargets: []string{"ip", "cidr"},
		},
		config: &MasscanConfig{
			Rate:         1000,
			Ports:        "1-65535",
			Timeout:      10,
			MaxRetries:   3,
			Banners:      false,
			OutputFormat: "list",
		},
	}
}

func (m *MasscanPlugin) SetConfig(configMap map[string]interface{}) error {
	if rate, ok := configMap["rate"].(int); ok && rate > 0 && rate <= 100000 {
		m.config.Rate = rate
	}
	if ports, ok := configMap["ports"].(string); ok && ports != "" {
		m.config.Ports = ports
	}
	if timeout, ok := configMap["timeout"].(int); ok && timeout > 0 && timeout <= 300 {
		m.config.Timeout = timeout
	}
	if maxRetries, ok := configMap["max_retries"].(int); ok && maxRetries >= 0 && maxRetries <= 10 {
		m.config.MaxRetries = maxRetries
	}
	if banners, ok := configMap["banners"].(bool); ok {
		m.config.Banners = banners
	}
	if outputFormat, ok := configMap["output_format"].(string); ok {
		validFormats := map[string]bool{"list": true, "json": true, "xml": true}
		if validFormats[outputFormat] {
			m.config.OutputFormat = outputFormat
		}
	}
	return nil
}

func (m *MasscanPlugin) Execute(ctx context.Context, target models.Target, sharedCtx *core.SharedContext) (*models.PluginResult, error) {
	if target.GetType() != "ip" && target.GetType() != "cidr" {
		return nil, fmt.Errorf("unsupported target type: %s", target.GetType())
	}

	targetStr := m.getTargetString(target)
	if targetStr == "" {
		return nil, fmt.Errorf("invalid target for masscan")
	}

	args := m.buildMasscanArgs(targetStr)
	
	output, err := m.ExecuteCommand(ctx, "masscan", args, time.Duration(m.config.Timeout)*time.Second)
	if err != nil {
		return nil, fmt.Errorf("masscan execution failed: %w", err)
	}

	result, err := m.parseMasscanOutput(output, target)
	if err != nil {
		return nil, fmt.Errorf("failed to parse masscan output: %w", err)
	}

	m.populateSharedContext(result, sharedCtx)

	return result, nil
}

func (m *MasscanPlugin) getTargetString(target models.Target) string {
	switch target.GetType() {
	case "ip":
		return target.GetIP()
	case "cidr":
		return target.GetCIDR()
	default:
		return ""
	}
}

func (m *MasscanPlugin) buildMasscanArgs(target string) []string {
	args := []string{
		"-p", m.config.Ports,
		"--rate", strconv.Itoa(m.config.Rate),
		"--max-retries", strconv.Itoa(m.config.MaxRetries),
		"--open-only",
	}

	if m.config.Banners {
		args = append(args, "--banners")
	}

	switch m.config.OutputFormat {
	case "json":
		args = append(args, "--output-format", "json")
	case "xml":
		args = append(args, "--output-format", "xml")
	default:
		args = append(args, "--output-format", "list")
	}

	args = append(args, target)

	return args
}

func (m *MasscanPlugin) parseMasscanOutput(output string, target models.Target) (*models.PluginResult, error) {
	result := &models.PluginResult{
		PluginName: m.PluginName,
		Target:     target,
		Status:     models.StatusSuccess,
		Timestamp:  time.Now(),
		Results:    make(map[string]interface{}),
		RawOutput:  output,
	}

	if strings.TrimSpace(output) == "" {
		result.Status = models.StatusError
		result.Error = "empty masscan output"
		return result, nil
	}

	ports := make([]map[string]interface{}, 0)
	hostInfo := make(map[string]interface{})
	bannersFound := make(map[string]interface{})

	scanner := bufio.NewScanner(strings.NewReader(output))
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}

		select {
		case <-ctx.Done():
			return result, ctx.Err()
		default:
		}

		if strings.Contains(line, "Discovered open port") {
			portInfo := m.parseOpenPortLine(line)
			if portInfo != nil {
				ports = append(ports, portInfo)
			}
		} else if strings.Contains(line, "Banner on port") {
			bannerInfo := m.parseBannerLine(line)
			if bannerInfo != nil {
				port := fmt.Sprintf("%d", bannerInfo["port"])
				bannersFound[port] = bannerInfo["banner"]
			}
		} else if strings.Contains(line, "Starting masscan") {
			hostInfo["scan_info"] = line
		}
	}

	for _, portData := range ports {
		if port, ok := portData["port"].(int); ok {
			portStr := fmt.Sprintf("%d", port)
			if banner, exists := bannersFound[portStr]; exists {
				portData["banner"] = banner
			}
		}
	}

	result.Results["host_info"] = hostInfo
	result.Results["ports"] = ports
	result.Results["total_ports"] = len(ports)
	
	if len(bannersFound) > 0 {
		result.Results["banners"] = bannersFound
	}

	scanStats := m.calculateScanStats(ports)
	result.Results["scan_stats"] = scanStats

	riskScore := m.calculateRiskScore(ports)
	result.Results["risk_score"] = riskScore

	return result, nil
}

func (m *MasscanPlugin) parseOpenPortLine(line string) map[string]interface{} {
	parts := strings.Fields(line)
	if len(parts) < 6 {
		return nil
	}

	for i, part := range parts {
		if part == "port" && i+1 < len(parts) {
			portProtocol := parts[i+1]
			portProtocolParts := strings.Split(portProtocol, "/")
			if len(portProtocolParts) != 2 {
				continue
			}

			port, err := strconv.Atoi(portProtocolParts[0])
			if err != nil {
				continue
			}

			protocol := portProtocolParts[1]

			for j, p := range parts {
				if p == "on" && j+1 < len(parts) {
					ip := parts[j+1]
					return map[string]interface{}{
						"port":     port,
						"protocol": protocol,
						"state":    "open",
						"ip":       ip,
					}
				}
			}

			return map[string]interface{}{
				"port":     port,
				"protocol": protocol,
				"state":    "open",
			}
		}
	}

	return nil
}

func (m *MasscanPlugin) parseBannerLine(line string) map[string]interface{} {
	parts := strings.Fields(line)
	if len(parts) < 4 {
		return nil
	}

	for i, part := range parts {
		if part == "port" && i+1 < len(parts) {
			portStr := parts[i+1]
			port, err := strconv.Atoi(portStr)
			if err != nil {
				continue
			}

			bannerStartIdx := strings.Index(line, "banner:")
			if bannerStartIdx == -1 {
				return nil
			}

			banner := strings.TrimSpace(line[bannerStartIdx+7:])
			
			return map[string]interface{}{
				"port":   port,
				"banner": banner,
			}
		}
	}

	return nil
}

func (m *MasscanPlugin) calculateScanStats(ports []map[string]interface{}) map[string]interface{} {
	stats := map[string]interface{}{
		"total_open_ports": len(ports),
		"protocols":        make(map[string]int),
		"port_ranges":      make(map[string]int),
	}

	protocolCounts := make(map[string]int)
	rangeCounts := map[string]int{
		"1-1023":      0,
		"1024-49151":  0,
		"49152-65535": 0,
	}

	for _, portData := range ports {
		if protocol, ok := portData["protocol"].(string); ok {
			protocolCounts[protocol]++
		}

		if port, ok := portData["port"].(int); ok {
			if port <= 1023 {
				rangeCounts["1-1023"]++
			} else if port <= 49151 {
				rangeCounts["1024-49151"]++
			} else {
				rangeCounts["49152-65535"]++
			}
		}
	}

	stats["protocols"] = protocolCounts
	stats["port_ranges"] = rangeCounts

	return stats
}

func (m *MasscanPlugin) calculateRiskScore(ports []map[string]interface{}) float64 {
	if len(ports) == 0 {
		return 0.0
	}

	score := 0.0
	criticalPorts := map[int]float64{
		21:   3.0, // FTP
		22:   2.0, // SSH
		23:   4.0, // Telnet
		25:   2.5, // SMTP
		53:   2.0, // DNS
		80:   1.5, // HTTP
		110:  2.5, // POP3
		135:  3.5, // RPC
		139:  3.5, // NetBIOS
		143:  2.5, // IMAP
		443:  1.0, // HTTPS
		445:  4.0, // SMB
		993:  1.5, // IMAPS
		995:  1.5, // POP3S
		1433: 4.0, // MSSQL
		1521: 4.0, // Oracle
		3306: 4.0, // MySQL
		3389: 3.5, // RDP
		5432: 4.0, // PostgreSQL
		5900: 3.5, // VNC
		6379: 3.5, // Redis
		27017: 4.0, // MongoDB
	}

	for _, portData := range ports {
		if port, ok := portData["port"].(int); ok {
			if riskValue, exists := criticalPorts[port]; exists {
				score += riskValue
			} else {
				score += 1.0
			}

			if banner, ok := portData["banner"].(string); ok && banner != "" {
				score += 0.5
			}
		}
	}

	maxPossibleScore := float64(len(ports)) * 4.0
	if maxPossibleScore > 0 {
		normalizedScore := (score / maxPossibleScore) * 10.0
		if normalizedScore > 10.0 {
			return 10.0
		}
		return normalizedScore
	}

	return 0.0
}

func (m *MasscanPlugin) populateSharedContext(result *models.PluginResult, sharedCtx *core.SharedContext) {
	if ports, ok := result.Results["ports"].([]map[string]interface{}); ok {
		for _, portData := range ports {
			if port, ok := portData["port"].(int); ok {
				sharedCtx.AddPort(port)
			}

			if ip, ok := portData["ip"].(string); ok && ip != "" {
				sharedCtx.AddIP(ip)
			}
		}
	}
}

func (m *MasscanPlugin) Cleanup() error {
	return nil
}

func (m *MasscanPlugin) ValidateConfig() error {
	if m.config.Rate < 1 || m.config.Rate > 100000 {
		return fmt.Errorf("rate must be between 1 and 100000")
	}
	if m.config.Timeout < 1 || m.config.Timeout > 300 {
		return fmt.Errorf("timeout must be between 1 and 300 seconds")
	}
	if m.config.MaxRetries < 0 || m.config.MaxRetries > 10 {
		return fmt.Errorf("max_retries must be between 0 and 10")
	}
	return nil
}
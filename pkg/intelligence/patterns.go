package intelligence

import (
	"fmt"
	"time"
	
	"github.com/f2u0a0d3/GoRecon/pkg/models"
)

// DefaultCorrelationRules returns a set of default correlation rules
func DefaultCorrelationRules() []CorrelationRule {
	return []CorrelationRule{
		{
			ID:          "domain-infrastructure-correlation",
			Name:        "Domain Infrastructure Correlation",
			Description: "Correlates findings related to the same domain infrastructure",
			Conditions: []CorrelationCondition{
				{
					Field:    "target",
					Operator: "contains",
					Value:    nil, // Will be dynamically populated
					Weight:   0.8,
					Required: true,
				},
			},
			Actions:     []string{"group", "analyze"},
			Severity:    "medium",
			Confidence:  0.8,
			TTL:         24 * time.Hour,
			Enabled:     true,
			Priority:    8,
		},
		{
			ID:          "vulnerability-cluster",
			Name:        "Vulnerability Cluster",
			Description: "Groups multiple vulnerabilities on the same target",
			Conditions: []CorrelationCondition{
				{
					Field:    "category",
					Operator: "equals",
					Value:    "vulnerability",
					Weight:   0.9,
					Required: true,
				},
				{
					Field:    "severity",
					Operator: "range",
					Value:    []string{"high", "critical"},
					Weight:   0.7,
					Required: false,
				},
			},
			Actions:     []string{"group", "alert", "prioritize"},
			Severity:    "high",
			Confidence:  0.9,
			TTL:         48 * time.Hour,
			Enabled:     true,
			Priority:    10,
		},
		{
			ID:          "service-enumeration-pattern",
			Name:        "Service Enumeration Pattern",
			Description: "Detects systematic service enumeration activities",
			Conditions: []CorrelationCondition{
				{
					Field:    "plugin",
					Operator: "contains",
					Value:    "port",
					Weight:   0.6,
					Required: false,
				},
				{
					Field:    "plugin",
					Operator: "contains",
					Value:    "service",
					Weight:   0.6,
					Required: false,
				},
			},
			Actions:     []string{"group", "timeline_analysis"},
			Severity:    "medium",
			Confidence:  0.7,
			TTL:         12 * time.Hour,
			Enabled:     true,
			Priority:    6,
		},
		{
			ID:          "credential-exposure-correlation",
			Name:        "Credential Exposure Correlation",
			Description: "Correlates findings that may indicate credential exposure",
			Conditions: []CorrelationCondition{
				{
					Field:    "finding",
					Operator: "contains",
					Value:    "credential",
					Weight:   0.9,
					Required: false,
				},
				{
					Field:    "finding",
					Operator: "contains",
					Value:    "password",
					Weight:   0.9,
					Required: false,
				},
				{
					Field:    "finding",
					Operator: "contains",
					Value:    "token",
					Weight:   0.8,
					Required: false,
				},
				{
					Field:    "finding",
					Operator: "contains",
					Value:    "api_key",
					Weight:   0.8,
					Required: false,
				},
			},
			Actions:     []string{"group", "alert", "urgent"},
			Severity:    "critical",
			Confidence:  0.95,
			TTL:         72 * time.Hour,
			Enabled:     true,
			Priority:    10,
		},
		{
			ID:          "cloud-misconfiguration-pattern",
			Name:        "Cloud Misconfiguration Pattern",
			Description: "Groups cloud security misconfigurations",
			Conditions: []CorrelationCondition{
				{
					Field:    "plugin",
					Operator: "equals",
					Value:    "cloud_enum",
					Weight:   0.8,
					Required: true,
				},
				{
					Field:    "severity",
					Operator: "range",
					Value:    []string{"medium", "high", "critical"},
					Weight:   0.6,
					Required: false,
				},
			},
			Actions:     []string{"group", "cloud_analysis"},
			Severity:    "high",
			Confidence:  0.85,
			TTL:         36 * time.Hour,
			Enabled:     true,
			Priority:    9,
		},
		{
			ID:          "web-application-vulnerability-chain",
			Name:        "Web Application Vulnerability Chain",
			Description: "Detects chained web application vulnerabilities",
			Conditions: []CorrelationCondition{
				{
					Field:    "category",
					Operator: "equals",
					Value:    "web-application",
					Weight:   0.8,
					Required: true,
				},
				{
					Field:    "finding",
					Operator: "regex",
					Value:    "(xss|sqli|rce|lfi|rfi)",
					Weight:   0.9,
					Required: false,
				},
			},
			Actions:     []string{"group", "attack_path_analysis"},
			Severity:    "high",
			Confidence:  0.8,
			TTL:         24 * time.Hour,
			Enabled:     true,
			Priority:    8,
		},
		{
			ID:          "information-disclosure-cluster",
			Name:        "Information Disclosure Cluster",
			Description: "Groups information disclosure findings",
			Conditions: []CorrelationCondition{
				{
					Field:    "finding",
					Operator: "contains",
					Value:    "disclosure",
					Weight:   0.7,
					Required: false,
				},
				{
					Field:    "finding",
					Operator: "contains",
					Value:    "exposure",
					Weight:   0.7,
					Required: false,
				},
				{
					Field:    "finding",
					Operator: "contains",
					Value:    "leak",
					Weight:   0.8,
					Required: false,
				},
			},
			Actions:     []string{"group", "data_analysis"},
			Severity:    "medium",
			Confidence:  0.75,
			TTL:         24 * time.Hour,
			Enabled:     true,
			Priority:    7,
		},
	}
}

// DefaultThreatPatterns returns a set of default threat patterns
func DefaultThreatPatterns() []ThreatPattern {
	return []ThreatPattern{
		{
			ID:          "apt-reconnaissance-pattern",
			Name:        "APT Reconnaissance Pattern",
			Description: "Pattern indicating advanced persistent threat reconnaissance activities",
			MitreTechniques: []string{"T1595", "T1590", "T1589", "T1596"},
			Indicators: []string{
				"systematic enumeration",
				"multiple discovery tools",
				"infrastructure mapping",
				"technology fingerprinting",
			},
			Signatures: []string{
				"port scanning + service enumeration + technology detection",
				"dns enumeration + subdomain discovery + certificate analysis",
			},
			Severity: "high",
			TTP: TacticsTreePattern{
				Tactics:    []string{"reconnaissance"},
				Techniques: []string{"T1595.001", "T1590.001", "T1589.002"},
				Procedures: []string{"active_scanning", "subdomain_enumeration", "certificate_harvesting"},
			},
			LastUpdated: time.Now(),
		},
		{
			ID:          "credential-harvesting-pattern",
			Name:        "Credential Harvesting Pattern",
			Description: "Pattern indicating credential harvesting attempts",
			MitreTechniques: []string{"T1552", "T1555", "T1528"},
			Indicators: []string{
				"credential files",
				"configuration exposure",
				"password databases",
				"api key exposure",
				"token leakage",
			},
			Signatures: []string{
				"github + credential exposure",
				"cloud misconfiguration + credential access",
				"web application + information disclosure + credentials",
			},
			Severity: "critical",
			TTP: TacticsTreePattern{
				Tactics:    []string{"credential-access"},
				Techniques: []string{"T1552.001", "T1555.003", "T1528"},
				Procedures: []string{"unsecured_credentials", "web_credentials", "cloud_credentials"},
			},
			LastUpdated: time.Now(),
		},
		{
			ID:          "initial-access-web-pattern",
			Name:        "Initial Access Web Pattern",
			Description: "Pattern indicating potential initial access through web vulnerabilities",
			MitreTechniques: []string{"T1190", "T1566.002", "T1195.002"},
			Indicators: []string{
				"web vulnerability",
				"sql injection",
				"remote code execution",
				"file upload",
				"path traversal",
			},
			Signatures: []string{
				"web application + high severity vulnerability",
				"rce + web server",
				"sql injection + database access",
			},
			Severity: "high",
			TTP: TacticsTreePattern{
				Tactics:    []string{"initial-access"},
				Techniques: []string{"T1190"},
				Procedures: []string{"exploit_public_application", "web_shell", "sql_injection"},
			},
			LastUpdated: time.Now(),
		},
		{
			ID:          "cloud-compromise-pattern",
			Name:        "Cloud Infrastructure Compromise Pattern",
			Description: "Pattern indicating potential cloud infrastructure compromise",
			MitreTechniques: []string{"T1078.004", "T1580", "T1552.005"},
			Indicators: []string{
				"cloud misconfiguration",
				"excessive permissions",
				"public storage",
				"weak authentication",
				"unencrypted data",
			},
			Signatures: []string{
				"cloud_enum + critical findings",
				"s3 bucket + public access + sensitive data",
				"iam misconfiguration + privilege escalation",
			},
			Severity: "high",
			TTP: TacticsTreePattern{
				Tactics:    []string{"initial-access", "persistence", "privilege-escalation"},
				Techniques: []string{"T1078.004", "T1580", "T1552.005"},
				Procedures: []string{"cloud_accounts", "cloud_infrastructure_discovery", "cloud_credentials"},
			},
			LastUpdated: time.Now(),
		},
		{
			ID:          "data-exfiltration-preparation",
			Name:        "Data Exfiltration Preparation Pattern",
			Description: "Pattern indicating preparation for data exfiltration",
			MitreTechniques: []string{"T1083", "T1005", "T1039", "T1025"},
			Indicators: []string{
				"file discovery",
				"database enumeration",
				"sensitive data identification",
				"backup file access",
				"archive discovery",
			},
			Signatures: []string{
				"file enumeration + sensitive data patterns",
				"database access + data discovery",
				"backup files + credential exposure",
			},
			Severity: "medium",
			TTP: TacticsTreePattern{
				Tactics:    []string{"collection", "discovery"},
				Techniques: []string{"T1083", "T1005", "T1039"},
				Procedures: []string{"file_directory_discovery", "data_from_local_system", "data_from_network_share"},
			},
			LastUpdated: time.Now(),
		},
		{
			ID:          "privilege-escalation-chain",
			Name:        "Privilege Escalation Chain Pattern",
			Description: "Pattern indicating potential privilege escalation opportunities",
			MitreTechniques: []string{"T1068", "T1055", "T1134", "T1548"},
			Indicators: []string{
				"privilege escalation vulnerability",
				"process injection opportunity",
				"token manipulation potential",
				"sudo misconfiguration",
				"suid binary exploitation",
			},
			Signatures: []string{
				"vulnerability + privilege escalation + system access",
				"process injection + elevated privileges",
				"configuration error + admin access",
			},
			Severity: "high",
			TTP: TacticsTreePattern{
				Tactics:    []string{"privilege-escalation"},
				Techniques: []string{"T1068", "T1055", "T1134"},
				Procedures: []string{"exploitation_for_privilege_escalation", "process_injection", "access_token_manipulation"},
			},
			LastUpdated: time.Now(),
		},
		{
			ID:          "lateral-movement-preparation",
			Name:        "Lateral Movement Preparation Pattern",
			Description: "Pattern indicating preparation for lateral movement",
			MitreTechniques: []string{"T1021", "T1570", "T1563", "T1080"},
			Indicators: []string{
				"network service enumeration",
				"shared resource discovery",
				"remote access capability",
				"trust relationship abuse",
				"credential reuse potential",
			},
			Signatures: []string{
				"network enumeration + service discovery + credential access",
				"remote desktop + network access + shared resources",
			},
			Severity: "medium",
			TTP: TacticsTreePattern{
				Tactics:    []string{"lateral-movement"},
				Techniques: []string{"T1021", "T1570"},
				Procedures: []string{"remote_services", "lateral_tool_transfer"},
			},
			LastUpdated: time.Now(),
		},
		{
			ID:          "persistence-establishment",
			Name:        "Persistence Establishment Pattern",
			Description: "Pattern indicating potential persistence mechanisms",
			MitreTechniques: []string{"T1053", "T1543", "T1136", "T1546"},
			Indicators: []string{
				"scheduled task creation",
				"service installation",
				"user account creation",
				"startup persistence",
				"registry modification",
			},
			Signatures: []string{
				"system access + persistence capability",
				"administrative privileges + startup modification",
				"service creation + system persistence",
			},
			Severity: "high",
			TTP: TacticsTreePattern{
				Tactics:    []string{"persistence"},
				Techniques: []string{"T1053", "T1543", "T1136"},
				Procedures: []string{"scheduled_task", "system_services", "create_account"},
			},
			LastUpdated: time.Now(),
		},
	}
}

// Helper functions for correlation analysis

func generateCorrelationID(correlationType string, findingIDs []string) string {
	return fmt.Sprintf("%s_%x_%d", correlationType, findingIDs, time.Now().Unix())
}

func generateAttackPathID(findings []*models.PluginResult) string {
	return fmt.Sprintf("attack_path_%d", time.Now().UnixNano())
}

func generateStepDescription(finding *models.PluginResult) string {
	return fmt.Sprintf("Exploit %s vulnerability in %s", finding.Category, finding.Target.String())
}

func extractTechnique(finding *models.PluginResult) string {
	if len(finding.MITRETechniques) > 0 {
		return finding.MITRETechniques[0]
	}
	
	// Infer technique based on category and content
	switch finding.Category {
	case "vulnerability":
		return "T1190" // Exploit Public-Facing Application
	case "service-discovery":
		return "T1046" // Network Service Scanning
	case "web-application":
		return "T1190" // Exploit Public-Facing Application
	case "credential":
		return "T1552" // Unsecured Credentials
	case "misconfiguration":
		return "T1580" // Cloud Infrastructure Discovery
	default:
		return "T1595" // Active Scanning
	}
}

func extractTactic(finding *models.PluginResult) string {
	technique := extractTechnique(finding)
	
	// Map techniques to tactics
	tacticMap := map[string]string{
		"T1190": "initial-access",
		"T1046": "discovery",
		"T1552": "credential-access",
		"T1580": "discovery",
		"T1595": "reconnaissance",
	}
	
	if tactic, exists := tacticMap[technique]; exists {
		return tactic
	}
	
	return "discovery"
}

func extractPrerequisites(finding *models.PluginResult) []string {
	var prerequisites []string
	
	switch finding.Category {
	case "vulnerability":
		prerequisites = append(prerequisites, "network access", "target reachability")
	case "web-application":
		prerequisites = append(prerequisites, "web access", "application availability")
	case "credential":
		prerequisites = append(prerequisites, "credential discovery", "access to storage")
	case "misconfiguration":
		prerequisites = append(prerequisites, "configuration access", "enumeration capability")
	default:
		prerequisites = append(prerequisites, "network access")
	}
	
	return prerequisites
}

func calculateDifficulty(findings []*models.PluginResult) string {
	avgSeverity := 0.0
	severityWeights := map[string]float64{
		"critical": 5.0,
		"high":     4.0,
		"medium":   3.0,
		"low":      2.0,
		"info":     1.0,
	}
	
	for _, finding := range findings {
		if weight, exists := severityWeights[finding.Severity]; exists {
			avgSeverity += weight
		}
	}
	
	if len(findings) > 0 {
		avgSeverity /= float64(len(findings))
	}
	
	if avgSeverity >= 4.0 {
		return "low"
	} else if avgSeverity >= 3.0 {
		return "medium"
	}
	
	return "high"
}

func calculateImpact(findings []*models.PluginResult) string {
	hasHighImpact := false
	hasCriticalImpact := false
	
	for _, finding := range findings {
		if finding.Severity == "high" {
			hasHighImpact = true
		}
		if finding.Severity == "critical" {
			hasCriticalImpact = true
		}
	}
	
	if hasCriticalImpact {
		return "critical"
	} else if hasHighImpact {
		return "high"
	}
	
	return "medium"
}

func calculateProbability(findings []*models.PluginResult) float64 {
	totalConfidence := 0.0
	exploitableCount := 0
	
	for _, finding := range findings {
		totalConfidence += finding.Confidence
		if finding.ExploitAvailable {
			exploitableCount++
		}
	}
	
	if len(findings) == 0 {
		return 0.0
	}
	
	avgConfidence := totalConfidence / float64(len(findings))
	exploitabilityRatio := float64(exploitableCount) / float64(len(findings))
	
	probability := (avgConfidence + exploitabilityRatio) / 2.0
	return probability
}

func getSeverityWeight(severity string) float64 {
	weights := map[string]float64{
		"critical": 5.0,
		"high":     4.0,
		"medium":   3.0,
		"low":      2.0,
		"info":     1.0,
	}
	
	if weight, exists := weights[severity]; exists {
		return weight
	}
	
	return 1.0
}

func extractDomain(finding *models.PluginResult) string {
	if finding.Target.Domain != "" {
		return finding.Target.Domain
	}
	return ""
}

func extractIP(finding *models.PluginResult) string {
	if finding.Target.IP != "" {
		return finding.Target.IP
	}
	return ""
}

func extractPort(finding *models.PluginResult) string {
	if finding.Target.Port != "" {
		return finding.Target.Port
	}
	return ""
}

func extractService(finding *models.PluginResult) string {
	if finding.Target.Service != "" {
		return finding.Target.Service
	}
	return ""
}

func extractTechnology(finding *models.PluginResult) string {
	// Extract technology information from finding content
	// This would be implemented based on specific plugin outputs
	return ""
}

func extractVulnerability(finding *models.PluginResult) string {
	if finding.Category == "vulnerability" {
		return finding.Finding
	}
	return ""
}

func extractIDs(findings []*models.PluginResult) []string {
	var ids []string
	for _, finding := range findings {
		ids = append(ids, finding.ID)
	}
	return ids
}
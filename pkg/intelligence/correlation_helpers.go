package intelligence

import (
	"fmt"
	"strings"
	"time"

	"github.com/f2u0a0d3/GoRecon/pkg/models"
)

// Helper functions for the intelligence correlation system

// ThreatIntelligence provides external threat intelligence integration
type ThreatIntelligence struct {
	apis     []string
	cache    map[string]*ThreatInfo
	lastSync time.Time
}

type ThreatInfo struct {
	IOCs         []string  `json:"iocs"`
	ThreatActors []string  `json:"threat_actors"`
	Campaigns    []string  `json:"campaigns"`
	TTPs         []string  `json:"ttps"`
	LastUpdated  time.Time `json:"last_updated"`
}

func NewThreatIntelligence(apis []string) (*ThreatIntelligence, error) {
	return &ThreatIntelligence{
		apis:  apis,
		cache: make(map[string]*ThreatInfo),
	}, nil
}

func (ti *ThreatIntelligence) EnrichFindings(findings []models.PluginResult) error {
	// Simplified threat intelligence enrichment
	// In a real implementation, this would query external APIs
	return nil
}

// MLEngine stub for missing functions
func (ic *IntelligenceCorrelator) incorporateMLResults(result *CorrelationResult, mlResults *MLResults) {
	if mlResults == nil {
		return
	}

	// Add ML classifications to correlation metadata
	for _, classification := range mlResults.Classifications {
		if classification.Confidence >= ic.config.MinConfidence {
			result.Recommendations = append(result.Recommendations, 
				fmt.Sprintf("ML Classification: %s (confidence: %.2f)", classification.Category, classification.Confidence))
		}
	}

	// Add ML insights
	for _, insight := range mlResults.Insights {
		if insight.Confidence >= ic.config.MinConfidence {
			result.Recommendations = append(result.Recommendations, 
				fmt.Sprintf("ML Insight: %s", insight.Description))
		}
	}

	// Adjust risk score based on ML anomalies
	if len(mlResults.Anomalies) > 0 {
		anomalyBoost := float64(len(mlResults.Anomalies)) * 0.5
		result.RiskScore += anomalyBoost
	}
}

func (ic *IntelligenceCorrelator) enrichWithThreatIntel(groups []CorrelatedFindingGroup) []ThreatActor {
	// Simplified threat actor identification
	var actors []ThreatActor
	
	for _, group := range groups {
		// Analyze group patterns to identify potential threat actors
		if len(group.Findings) >= 5 {
			actor := ThreatActor{
				ID:          fmt.Sprintf("actor_%d", time.Now().Unix()),
				Name:        "Unknown Actor",
				Description: "Potential threat actor identified through correlation analysis",
				TTPs:        []string{"T1595", "T1590"},
				Confidence:  0.6,
			}
			actors = append(actors, actor)
		}
	}
	
	return actors
}

func (ic *IntelligenceCorrelator) findRelatedCVEs(findings []models.PluginResult) []CVE {
	var cves []CVE
	
	for _, finding := range findings {
		if finding.Category == "vulnerability" {
			// Extract CVE information from finding
			if strings.Contains(finding.Finding, "CVE-") {
				cve := CVE{
					ID:          extractCVEID(finding.Finding),
					Description: finding.Description,
					CVSS:        finding.CVSSScore,
					Severity:    finding.Severity,
					Published:   finding.Timestamp,
				}
				cves = append(cves, cve)
			}
		}
	}
	
	return cves
}

func extractCVEID(text string) string {
	// Simple CVE extraction - in practice would use regex
	if idx := strings.Index(text, "CVE-"); idx != -1 {
		end := idx + 13 // CVE-YYYY-NNNN format
		if end <= len(text) {
			return text[idx:end]
		}
	}
	return "CVE-UNKNOWN"
}

func (ic *IntelligenceCorrelator) filterFalsePositives(findings []models.PluginResult) []models.PluginResult {
	var filtered []models.PluginResult
	
	for _, finding := range findings {
		if !ic.isFalsePositive(finding) {
			filtered = append(filtered, finding)
		}
	}
	
	return filtered
}

func (ic *IntelligenceCorrelator) isFalsePositive(finding models.PluginResult) bool {
	// Simple false positive detection
	// In practice, this would use ML models and reputation data
	
	// Filter out common false positives
	findingLower := strings.ToLower(finding.Finding)
	
	falsePositivePatterns := []string{
		"test page",
		"default page", 
		"placeholder",
		"example.com",
		"localhost",
		"127.0.0.1",
	}
	
	for _, pattern := range falsePositivePatterns {
		if strings.Contains(findingLower, pattern) {
			return true
		}
	}
	
	// Low confidence findings from unreliable plugins
	if finding.Confidence < 0.3 && finding.Plugin == "wayback" {
		return true
	}
	
	return false
}

func (ic *IntelligenceCorrelator) extractEvidence(findings []models.PluginResult, rule CorrelationRule) []string {
	var evidence []string
	
	for _, finding := range findings {
		evidence = append(evidence, fmt.Sprintf("Finding from %s: %s", finding.Plugin, finding.Finding))
	}
	
	return evidence
}

func (ic *IntelligenceCorrelator) calculateCorrelationStrength(findings []models.PluginResult, rule CorrelationRule) float64 {
	if len(findings) == 0 {
		return 0.0
	}
	
	// Base strength from number of findings
	baseStrength := float64(len(findings)) / 10.0
	if baseStrength > 1.0 {
		baseStrength = 1.0
	}
	
	// Boost for high confidence findings
	totalConfidence := 0.0
	for _, finding := range findings {
		totalConfidence += finding.Confidence
	}
	avgConfidence := totalConfidence / float64(len(findings))
	
	return (baseStrength + avgConfidence) / 2.0
}

func (ic *IntelligenceCorrelator) calculatePriority(severity string, strength float64) string {
	severityWeight := map[string]float64{
		"critical": 1.0,
		"high":     0.8,
		"medium":   0.6,
		"low":      0.4,
		"info":     0.2,
	}
	
	weight := severityWeight[severity]
	score := weight * strength
	
	if score >= 0.8 {
		return "critical"
	} else if score >= 0.6 {
		return "high"
	} else if score >= 0.4 {
		return "medium"
	}
	return "low"
}

func (ic *IntelligenceCorrelator) mergeOverlappingGroups(groups []CorrelatedFindingGroup) []CorrelatedFindingGroup {
	if len(groups) <= 1 {
		return groups
	}
	
	var merged []CorrelatedFindingGroup
	used := make(map[int]bool)
	
	for i, group := range groups {
		if used[i] {
			continue
		}
		
		currentGroup := group
		used[i] = true
		
		// Check for overlapping groups
		for j := i + 1; j < len(groups); j++ {
			if used[j] {
				continue
			}
			
			if ic.hasOverlap(currentGroup, groups[j]) {
				currentGroup = ic.mergeGroups(currentGroup, groups[j])
				used[j] = true
			}
		}
		
		merged = append(merged, currentGroup)
	}
	
	return merged
}

func (ic *IntelligenceCorrelator) hasOverlap(group1, group2 CorrelatedFindingGroup) bool {
	findings1 := make(map[string]bool)
	for _, finding := range group1.Findings {
		findings1[finding.ID] = true
	}
	
	for _, finding := range group2.Findings {
		if findings1[finding.ID] {
			return true
		}
	}
	
	return false
}

func (ic *IntelligenceCorrelator) mergeGroups(group1, group2 CorrelatedFindingGroup) CorrelatedFindingGroup {
	merged := group1
	merged.ID = fmt.Sprintf("merged_%s_%s", group1.ID, group2.ID)
	merged.Name = fmt.Sprintf("Merged: %s + %s", group1.Name, group2.Name)
	
	// Merge findings (avoid duplicates)
	findingMap := make(map[string]models.PluginResult)
	for _, finding := range group1.Findings {
		findingMap[finding.ID] = finding
	}
	for _, finding := range group2.Findings {
		findingMap[finding.ID] = finding
	}
	
	merged.Findings = make([]models.PluginResult, 0, len(findingMap))
	for _, finding := range findingMap {
		merged.Findings = append(merged.Findings, finding)
	}
	
	// Average correlation metrics
	merged.Correlation.Strength = (group1.Correlation.Strength + group2.Correlation.Strength) / 2.0
	merged.Correlation.Confidence = (group1.Correlation.Confidence + group2.Correlation.Confidence) / 2.0
	
	return merged
}

func (ic *IntelligenceCorrelator) createTimeWindows(findings []models.PluginResult) [][]models.PluginResult {
	var windows [][]models.PluginResult
	
	if len(findings) == 0 {
		return windows
	}
	
	// Sort findings by timestamp
	sortedFindings := make([]models.PluginResult, len(findings))
	copy(sortedFindings, findings)
	
	// Group into time windows (simplified implementation)
	windowSize := time.Hour
	var currentWindow []models.PluginResult
	var windowStart time.Time
	
	for i, finding := range sortedFindings {
		if i == 0 {
			windowStart = finding.Timestamp
			currentWindow = []models.PluginResult{finding}
			continue
		}
		
		if finding.Timestamp.Sub(windowStart) <= windowSize {
			currentWindow = append(currentWindow, finding)
		} else {
			if len(currentWindow) > 0 {
				windows = append(windows, currentWindow)
			}
			currentWindow = []models.PluginResult{finding}
			windowStart = finding.Timestamp
		}
	}
	
	if len(currentWindow) > 0 {
		windows = append(windows, currentWindow)
	}
	
	return windows
}

func (ic *IntelligenceCorrelator) calculateTemporalConfidence(findings []models.PluginResult) float64 {
	if len(findings) <= 1 {
		return 0.5
	}
	
	// Calculate confidence based on temporal proximity
	var totalSpread time.Duration
	for i := 1; i < len(findings); i++ {
		spread := findings[i].Timestamp.Sub(findings[i-1].Timestamp)
		if spread < 0 {
			spread = -spread
		}
		totalSpread += spread
	}
	
	avgSpread := totalSpread / time.Duration(len(findings)-1)
	
	// Shorter spreads = higher confidence
	if avgSpread <= time.Hour {
		return 0.9
	} else if avgSpread <= 6*time.Hour {
		return 0.8
	} else if avgSpread <= 24*time.Hour {
		return 0.7
	}
	
	return 0.6
}

func (ic *IntelligenceCorrelator) calculateTemporalStrength(findings []models.PluginResult) float64 {
	if len(findings) <= 1 {
		return 0.0
	}
	
	// Strength based on number of findings in close proximity
	return float64(len(findings)) / 10.0
}

func (ic *IntelligenceCorrelator) calculateSpatialConfidence(findings []models.PluginResult) float64 {
	if len(findings) <= 1 {
		return 0.5
	}
	
	// All findings are from the same target, so confidence is high
	return 0.85
}

func (ic *IntelligenceCorrelator) calculateSpatialStrength(findings []models.PluginResult) float64 {
	if len(findings) <= 1 {
		return 0.0
	}
	
	// Strength based on diversity of findings on same target
	pluginTypes := make(map[string]bool)
	categories := make(map[string]bool)
	
	for _, finding := range findings {
		pluginTypes[finding.Plugin] = true
		categories[finding.Category] = true
	}
	
	diversity := (float64(len(pluginTypes)) + float64(len(categories))) / 2.0
	return diversity / 10.0
}

func (ic *IntelligenceCorrelator) inferMitreTechniques(group CorrelatedFindingGroup) []MitreTechnique {
	var techniques []MitreTechnique
	
	// Analyze group patterns to infer additional MITRE techniques
	hasVulns := false
	hasServices := false
	hasWebApp := false
	
	for _, finding := range group.Findings {
		switch finding.Category {
		case "vulnerability":
			hasVulns = true
		case "service-discovery":
			hasServices = true
		case "web-application":
			hasWebApp = true
		}
	}
	
	// Infer techniques based on patterns
	if hasVulns && hasServices {
		techniques = append(techniques, MitreTechnique{
			ID:          "T1046",
			Name:        "Network Service Scanning",
			Description: "Inferred from service discovery + vulnerability findings",
			Confidence:  0.7,
		})
	}
	
	if hasWebApp && hasVulns {
		techniques = append(techniques, MitreTechnique{
			ID:          "T1190",
			Name:        "Exploit Public-Facing Application",
			Description: "Inferred from web application vulnerabilities",
			Confidence:  0.8,
		})
	}
	
	return techniques
}

func (ic *IntelligenceCorrelator) buildAttackChains(techniques []MitreTechnique, groups []CorrelatedFindingGroup) [][]AttackStep {
	var chains [][]AttackStep
	
	// Simple attack chain building
	if len(techniques) >= 2 {
		var steps []AttackStep
		
		for i, technique := range techniques {
			step := AttackStep{
				StepNumber:     i + 1,
				Technique:      technique.Name,
				Description:    technique.Description,
				MitreTechnique: technique.ID,
				Difficulty:     "medium",
			}
			
			// Add evidence from related groups
			for _, group := range groups {
				if len(group.Findings) > 0 {
					step.Evidence = append(step.Evidence, group.Findings[0])
				}
			}
			
			steps = append(steps, step)
		}
		
		chains = append(chains, steps)
	}
	
	return chains
}

func (ic *IntelligenceCorrelator) generatePathDescription(steps []AttackStep) string {
	if len(steps) == 0 {
		return "Unknown attack path"
	}
	
	return fmt.Sprintf("Attack path with %d steps starting from %s", len(steps), steps[0].Technique)
}

func (ic *IntelligenceCorrelator) calculatePathLikelihood(steps []AttackStep) float64 {
	if len(steps) == 0 {
		return 0.0
	}
	
	// Simplified likelihood calculation
	baseScore := 0.8
	for range steps {
		baseScore *= 0.9 // Each step reduces likelihood
	}
	
	return baseScore
}

func (ic *IntelligenceCorrelator) calculatePathImpact(steps []AttackStep) float64 {
	if len(steps) == 0 {
		return 0.0
	}
	
	// Impact increases with more steps
	return float64(len(steps)) * 2.0
}

func (ic *IntelligenceCorrelator) generateMitigations(steps []AttackStep) []string {
	var mitigations []string
	
	for _, step := range steps {
		switch step.MitreTechnique {
		case "T1190":
			mitigations = append(mitigations, "Patch public-facing applications")
			mitigations = append(mitigations, "Implement web application firewall")
		case "T1046":
			mitigations = append(mitigations, "Implement network segmentation")
			mitigations = append(mitigations, "Deploy network monitoring")
		default:
			mitigations = append(mitigations, "Implement general security controls")
		}
	}
	
	return mitigations
}
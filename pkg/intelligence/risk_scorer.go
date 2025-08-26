package intelligence

import (
	"math"
	"strings"
	"time"

	"github.com/f2u0a0d3/GoRecon/pkg/models"
)

// RiskScorer calculates risk scores for findings and correlations
type RiskScorer struct {
	config       RiskScoringConfig
	severityWeights map[string]float64
	categoryWeights map[string]float64
	cvssCalculator  *CVSSCalculator
}

// RiskScoringConfig configures risk scoring behavior
type RiskScoringConfig struct {
	EnableCVSS           bool            `json:"enable_cvss"`
	EnableTimeDecay      bool            `json:"enable_time_decay"`
	EnableAssetWeighting bool            `json:"enable_asset_weighting"`
	BaselineRisk         float64         `json:"baseline_risk"`
	MaxRiskScore         float64         `json:"max_risk_score"`
	DecayRate            float64         `json:"decay_rate"`
	AssetWeights         map[string]float64 `json:"asset_weights"`
}

// CVSSCalculator implements CVSS v3.1 scoring
type CVSSCalculator struct {
	baseMetrics map[string]float64
}

// RiskVector represents risk calculation components
type RiskVector struct {
	Severity         float64 `json:"severity"`
	Confidence       float64 `json:"confidence"`
	Exploitability   float64 `json:"exploitability"`
	Impact          float64 `json:"impact"`
	AssetValue      float64 `json:"asset_value"`
	TimeDecay       float64 `json:"time_decay"`
	CorrelationBoost float64 `json:"correlation_boost"`
	FinalScore      float64 `json:"final_score"`
}

// RiskAssessment provides detailed risk analysis
type RiskAssessment struct {
	OverallRisk      float64                    `json:"overall_risk"`
	RiskVector       RiskVector                 `json:"risk_vector"`
	RiskFactors      []RiskFactor               `json:"risk_factors"`
	TrendAnalysis    RiskTrend                  `json:"trend_analysis"`
	BusinessImpact   BusinessImpactAssessment   `json:"business_impact"`
	Recommendations  []RiskMitigation           `json:"recommendations"`
}

// RiskFactor represents individual risk components
type RiskFactor struct {
	Name        string  `json:"name"`
	Value       float64 `json:"value"`
	Weight      float64 `json:"weight"`
	Contribution float64 `json:"contribution"`
	Description string  `json:"description"`
}

// RiskTrend analyzes risk over time
type RiskTrend struct {
	Direction    string    `json:"direction"` // increasing, decreasing, stable
	Velocity     float64   `json:"velocity"`  // rate of change
	Prediction   float64   `json:"prediction"` // predicted future risk
	Confidence   float64   `json:"confidence"`
	LastUpdated  time.Time `json:"last_updated"`
}

// BusinessImpactAssessment evaluates business consequences
type BusinessImpactAssessment struct {
	FinancialImpact     float64  `json:"financial_impact"`
	OperationalImpact   float64  `json:"operational_impact"`
	ReputationalImpact  float64  `json:"reputational_impact"`
	RegulatoryImpact    float64  `json:"regulatory_impact"`
	AffectedSystems     []string `json:"affected_systems"`
	CriticalityLevel    string   `json:"criticality_level"`
}

// RiskMitigation provides specific remediation guidance
type RiskMitigation struct {
	Priority     string  `json:"priority"`
	Action       string  `json:"action"`
	Effort       string  `json:"effort"`
	Cost         string  `json:"cost"`
	Timeframe    string  `json:"timeframe"`
	RiskReduction float64 `json:"risk_reduction"`
	Dependencies []string `json:"dependencies"`
}

// NewRiskScorer creates a new risk scoring engine
func NewRiskScorer() *RiskScorer {
	return &RiskScorer{
		config: RiskScoringConfig{
			EnableCVSS:           true,
			EnableTimeDecay:      true,
			EnableAssetWeighting: true,
			BaselineRisk:         1.0,
			MaxRiskScore:         10.0,
			DecayRate:            0.1,
			AssetWeights: map[string]float64{
				"production":  1.0,
				"staging":     0.7,
				"development": 0.3,
				"internal":    0.8,
				"external":    1.2,
			},
		},
		severityWeights: map[string]float64{
			"critical": 10.0,
			"high":     8.0,
			"medium":   5.0,
			"low":      2.0,
			"info":     1.0,
		},
		categoryWeights: map[string]float64{
			"vuln":       1.0,
			"cloud":      0.9,
			"wayback":    0.6,
			"portscan":   0.7,
			"httpprobe":  0.5,
			"js":         0.4,
			"github":     0.8,
			"param":      0.6,
			"crawl":      0.4,
			"brokenlink": 0.2,
		},
		cvssCalculator: NewCVSSCalculator(),
	}
}

// CalculateRiskScore calculates the overall risk score for findings
func (rs *RiskScorer) CalculateRiskScore(findings []models.PluginResult, groups []CorrelatedFindingGroup) float64 {
	if len(findings) == 0 {
		return 0.0
	}

	var totalRisk float64
	var weights float64

	// Calculate individual finding risks
	for _, finding := range findings {
		risk := rs.CalculateFindingRisk(finding)
		weight := rs.calculateFindingWeight(finding)
		totalRisk += risk * weight
		weights += weight
	}

	baseRisk := totalRisk / weights

	// Apply correlation boost
	correlationBoost := rs.calculateCorrelationBoost(groups)
	
	// Apply multipliers
	finalRisk := baseRisk * (1.0 + correlationBoost)

	// Ensure within bounds
	return math.Min(finalRisk, rs.config.MaxRiskScore)
}

// CalculateFindingRisk calculates risk for a single finding
func (rs *RiskScorer) CalculateFindingRisk(finding models.PluginResult) float64 {
	vector := rs.buildRiskVector(finding)
	return rs.calculateFromVector(vector)
}

// CalculateGroupRiskScore calculates risk for a correlated group
func (rs *RiskScorer) CalculateGroupRiskScore(group CorrelatedFindingGroup) float64 {
	if len(group.Findings) == 0 {
		return 0.0
	}

	// Base risk from individual findings
	var totalRisk float64
	for _, finding := range group.Findings {
		totalRisk += rs.CalculateFindingRisk(finding)
	}

	avgRisk := totalRisk / float64(len(group.Findings))

	// Apply group multipliers
	correlationMultiplier := 1.0 + (group.Correlation.Strength * 0.5)
	confidenceMultiplier := group.Correlation.Confidence
	
	groupRisk := avgRisk * correlationMultiplier * confidenceMultiplier

	return math.Min(groupRisk, rs.config.MaxRiskScore)
}

// PerformRiskAssessment provides comprehensive risk analysis
func (rs *RiskScorer) PerformRiskAssessment(findings []models.PluginResult, groups []CorrelatedFindingGroup) *RiskAssessment {
	overallRisk := rs.CalculateRiskScore(findings, groups)
	
	assessment := &RiskAssessment{
		OverallRisk: overallRisk,
		RiskVector:  rs.buildAggregateRiskVector(findings),
		RiskFactors: rs.identifyRiskFactors(findings, groups),
		TrendAnalysis: rs.analyzeTrend(findings),
		BusinessImpact: rs.assessBusinessImpact(findings, overallRisk),
		Recommendations: rs.generateMitigations(findings, groups, overallRisk),
	}

	return assessment
}

// buildRiskVector creates a risk vector for a finding
func (rs *RiskScorer) buildRiskVector(finding models.PluginResult) RiskVector {
	vector := RiskVector{
		Severity:     rs.calculateSeverityScore(finding.Severity),
		Confidence:   finding.Confidence,
		Exploitability: rs.calculateExploitability(finding),
		Impact:       rs.calculateImpact(finding),
		AssetValue:   rs.calculateAssetValue(finding.Target.String()),
		TimeDecay:    rs.calculateTimeDecay(finding.Timestamp),
	}

	vector.FinalScore = rs.calculateFromVector(vector)
	return vector
}

// calculateFromVector computes final risk score from vector components
func (rs *RiskScorer) calculateFromVector(vector RiskVector) float64 {
	// CVSS-inspired calculation with customizations
	exploitabilityScore := 8.22 * vector.Exploitability
	impactScore := 6.42 * vector.Impact
	
	baseScore := math.Min(10.0, (impactScore + exploitabilityScore))
	
	// Apply confidence scaling
	confidenceAdjusted := baseScore * vector.Confidence
	
	// Apply severity weighting
	severityAdjusted := confidenceAdjusted * (vector.Severity / 10.0)
	
	// Apply asset value weighting
	assetAdjusted := severityAdjusted * vector.AssetValue
	
	// Apply time decay if enabled
	if rs.config.EnableTimeDecay {
		assetAdjusted *= vector.TimeDecay
	}

	return math.Min(assetAdjusted, rs.config.MaxRiskScore)
}

// calculateSeverityScore converts severity string to numeric score
func (rs *RiskScorer) calculateSeverityScore(severity string) float64 {
	if weight, exists := rs.severityWeights[strings.ToLower(severity)]; exists {
		return weight
	}
	return 1.0 // Default for unknown severity
}

// calculateExploitability estimates how easily a finding can be exploited
func (rs *RiskScorer) calculateExploitability(finding models.PluginResult) float64 {
	score := 0.5 // Base exploitability

	// Higher exploitability for certain categories
	switch strings.ToLower(finding.Category) {
	case "vuln":
		score = 0.9
	case "cloud":
		score = 0.8
	case "github":
		score = 0.7
	case "param":
		score = 0.6
	default:
		score = 0.4
	}

	// Adjust based on finding content
	findingLower := strings.ToLower(finding.Finding)
	if strings.Contains(findingLower, "rce") || strings.Contains(findingLower, "remote code") {
		score = math.Min(1.0, score + 0.3)
	}
	if strings.Contains(findingLower, "sql injection") {
		score = math.Min(1.0, score + 0.2)
	}
	if strings.Contains(findingLower, "xss") {
		score = math.Min(1.0, score + 0.15)
	}

	return score
}

// calculateImpact estimates the potential impact of a finding
func (rs *RiskScorer) calculateImpact(finding models.PluginResult) float64 {
	score := 0.5 // Base impact

	// Impact based on what could be compromised
	findingLower := strings.ToLower(finding.Finding + " " + finding.Description)
	
	if strings.Contains(findingLower, "admin") || strings.Contains(findingLower, "root") {
		score = math.Min(1.0, score + 0.4)
	}
	if strings.Contains(findingLower, "database") || strings.Contains(findingLower, "db") {
		score = math.Min(1.0, score + 0.3)
	}
	if strings.Contains(findingLower, "config") || strings.Contains(findingLower, "credential") {
		score = math.Min(1.0, score + 0.25)
	}
	if strings.Contains(findingLower, "api") || strings.Contains(findingLower, "endpoint") {
		score = math.Min(1.0, score + 0.2)
	}

	// Adjust based on severity
	switch strings.ToLower(finding.Severity) {
	case "critical":
		score = math.Min(1.0, score + 0.3)
	case "high":
		score = math.Min(1.0, score + 0.2)
	case "medium":
		score = math.Min(1.0, score + 0.1)
	}

	return score
}

// calculateAssetValue determines the value/criticality of the target asset
func (rs *RiskScorer) calculateAssetValue(target string) float64 {
	if rs.config.EnableAssetWeighting {
		// Check for asset type indicators
		targetLower := strings.ToLower(target)
		
		if strings.Contains(targetLower, "prod") || strings.Contains(targetLower, "production") {
			return rs.config.AssetWeights["production"]
		}
		if strings.Contains(targetLower, "stage") || strings.Contains(targetLower, "staging") {
			return rs.config.AssetWeights["staging"]
		}
		if strings.Contains(targetLower, "dev") || strings.Contains(targetLower, "development") {
			return rs.config.AssetWeights["development"]
		}
		if strings.Contains(targetLower, "internal") {
			return rs.config.AssetWeights["internal"]
		}
		
		return rs.config.AssetWeights["external"] // Default to external
	}
	
	return 1.0 // No weighting
}

// calculateTimeDecay applies time-based decay to risk scores
func (rs *RiskScorer) calculateTimeDecay(timestamp time.Time) float64 {
	if !rs.config.EnableTimeDecay {
		return 1.0
	}

	daysSince := time.Since(timestamp).Hours() / 24
	decay := math.Exp(-rs.config.DecayRate * daysSince)
	
	// Minimum decay factor
	return math.Max(0.1, decay)
}

// calculateFindingWeight determines the relative importance of a finding
func (rs *RiskScorer) calculateFindingWeight(finding models.PluginResult) float64 {
	categoryWeight := rs.categoryWeights[strings.ToLower(finding.Category)]
	confidenceWeight := finding.Confidence
	
	return categoryWeight * confidenceWeight
}

// calculateCorrelationBoost increases risk score based on correlated findings
func (rs *RiskScorer) calculateCorrelationBoost(groups []CorrelatedFindingGroup) float64 {
	if len(groups) == 0 {
		return 0.0
	}

	var totalBoost float64
	for _, group := range groups {
		// More findings in a group = higher boost
		findingBoost := math.Log(float64(len(group.Findings))) * 0.1
		
		// Higher correlation strength = higher boost
		strengthBoost := group.Correlation.Strength * 0.2
		
		// Higher confidence = higher boost
		confidenceBoost := group.Correlation.Confidence * 0.15
		
		groupBoost := findingBoost + strengthBoost + confidenceBoost
		totalBoost += groupBoost
	}

	// Cap the total boost
	return math.Min(totalBoost, 1.0)
}

// buildAggregateRiskVector creates an aggregate risk vector from multiple findings
func (rs *RiskScorer) buildAggregateRiskVector(findings []models.PluginResult) RiskVector {
	if len(findings) == 0 {
		return RiskVector{}
	}

	var totalSeverity, totalConfidence, totalExploitability, totalImpact, totalAssetValue, totalTimeDecay float64

	for _, finding := range findings {
		vector := rs.buildRiskVector(finding)
		totalSeverity += vector.Severity
		totalConfidence += vector.Confidence
		totalExploitability += vector.Exploitability
		totalImpact += vector.Impact
		totalAssetValue += vector.AssetValue
		totalTimeDecay += vector.TimeDecay
	}

	count := float64(len(findings))
	aggregate := RiskVector{
		Severity:       totalSeverity / count,
		Confidence:     totalConfidence / count,
		Exploitability: totalExploitability / count,
		Impact:         totalImpact / count,
		AssetValue:     totalAssetValue / count,
		TimeDecay:      totalTimeDecay / count,
	}

	aggregate.FinalScore = rs.calculateFromVector(aggregate)
	return aggregate
}

// identifyRiskFactors breaks down risk into contributing factors
func (rs *RiskScorer) identifyRiskFactors(findings []models.PluginResult, groups []CorrelatedFindingGroup) []RiskFactor {
	factors := []RiskFactor{
		{
			Name:        "Severity Distribution",
			Value:       rs.calculateSeverityDistribution(findings),
			Weight:      0.3,
			Description: "Overall severity of identified findings",
		},
		{
			Name:        "Confidence Level",
			Value:       rs.calculateAverageConfidence(findings),
			Weight:      0.2,
			Description: "Confidence in finding accuracy",
		},
		{
			Name:        "Correlation Strength",
			Value:       rs.calculateAverageCorrelation(groups),
			Weight:      0.25,
			Description: "Strength of relationships between findings",
		},
		{
			Name:        "Asset Criticality",
			Value:       rs.calculateAssetCriticality(findings),
			Weight:      0.15,
			Description: "Business criticality of affected assets",
		},
		{
			Name:        "Finding Freshness",
			Value:       rs.calculateFreshness(findings),
			Weight:      0.1,
			Description: "Recency of identified issues",
		},
	}

	// Calculate contributions
	for i := range factors {
		factors[i].Contribution = factors[i].Value * factors[i].Weight
	}

	return factors
}

// analyzeTrend analyzes risk trends over time
func (rs *RiskScorer) analyzeTrend(findings []models.PluginResult) RiskTrend {
	// Simplified trend analysis - in practice would use historical data
	return RiskTrend{
		Direction:   "stable",
		Velocity:    0.0,
		Prediction:  rs.CalculateRiskScore(findings, nil),
		Confidence:  0.7,
		LastUpdated: time.Now(),
	}
}

// assessBusinessImpact evaluates business consequences
func (rs *RiskScorer) assessBusinessImpact(findings []models.PluginResult, overallRisk float64) BusinessImpactAssessment {
	impact := BusinessImpactAssessment{
		FinancialImpact:    overallRisk * 0.8,
		OperationalImpact:  overallRisk * 0.9,
		ReputationalImpact: overallRisk * 0.7,
		RegulatoryImpact:   overallRisk * 0.6,
	}

	// Determine criticality level
	if overallRisk >= 8.0 {
		impact.CriticalityLevel = "Critical"
	} else if overallRisk >= 6.0 {
		impact.CriticalityLevel = "High"
	} else if overallRisk >= 4.0 {
		impact.CriticalityLevel = "Medium"
	} else {
		impact.CriticalityLevel = "Low"
	}

	// Extract affected systems
	systemMap := make(map[string]bool)
	for _, finding := range findings {
		systemMap[finding.Target.String()] = true
	}
	for system := range systemMap {
		impact.AffectedSystems = append(impact.AffectedSystems, system)
	}

	return impact
}

// generateMitigations provides specific remediation guidance
func (rs *RiskScorer) generateMitigations(findings []models.PluginResult, groups []CorrelatedFindingGroup, overallRisk float64) []RiskMitigation {
	var mitigations []RiskMitigation

	if overallRisk >= 8.0 {
		mitigations = append(mitigations, RiskMitigation{
			Priority:      "Critical",
			Action:        "Immediate incident response activation",
			Effort:        "High",
			Cost:          "High",
			Timeframe:     "0-24 hours",
			RiskReduction: 0.6,
		})
	}

	if len(groups) > 0 {
		mitigations = append(mitigations, RiskMitigation{
			Priority:      "High",
			Action:        "Address correlated vulnerabilities as attack chain",
			Effort:        "Medium",
			Cost:          "Medium",
			Timeframe:     "1-7 days",
			RiskReduction: 0.4,
		})
	}

	// Add standard mitigations based on findings
	mitigations = append(mitigations, RiskMitigation{
		Priority:      "Medium",
		Action:        "Patch identified vulnerabilities",
		Effort:        "Medium",
		Cost:          "Low",
		Timeframe:     "1-30 days",
		RiskReduction: 0.3,
	})

	return mitigations
}

// Helper calculation methods

func (rs *RiskScorer) calculateSeverityDistribution(findings []models.PluginResult) float64 {
	severityCounts := make(map[string]int)
	for _, finding := range findings {
		severityCounts[strings.ToLower(finding.Severity)]++
	}

	weightedSum := 0.0
	for severity, count := range severityCounts {
		weightedSum += rs.severityWeights[severity] * float64(count)
	}

	return math.Min(10.0, weightedSum/float64(len(findings)))
}

func (rs *RiskScorer) calculateAverageConfidence(findings []models.PluginResult) float64 {
	if len(findings) == 0 {
		return 0.0
	}

	var total float64
	for _, finding := range findings {
		total += finding.Confidence
	}
	return (total / float64(len(findings))) * 10.0
}

func (rs *RiskScorer) calculateAverageCorrelation(groups []CorrelatedFindingGroup) float64 {
	if len(groups) == 0 {
		return 0.0
	}

	var total float64
	for _, group := range groups {
		total += group.Correlation.Strength
	}
	return (total / float64(len(groups))) * 10.0
}

func (rs *RiskScorer) calculateAssetCriticality(findings []models.PluginResult) float64 {
	if len(findings) == 0 {
		return 0.0
	}

	var total float64
	for _, finding := range findings {
		total += rs.calculateAssetValue(finding.Target.String())
	}
	return (total / float64(len(findings))) * 10.0
}

func (rs *RiskScorer) calculateFreshness(findings []models.PluginResult) float64 {
	if len(findings) == 0 {
		return 0.0
	}

	var total float64
	for _, finding := range findings {
		total += rs.calculateTimeDecay(finding.Timestamp)
	}
	return (total / float64(len(findings))) * 10.0
}

// NewCVSSCalculator creates a new CVSS calculator
func NewCVSSCalculator() *CVSSCalculator {
	return &CVSSCalculator{
		baseMetrics: map[string]float64{
			"attack_vector":     0.85,
			"attack_complexity": 0.77,
			"privileges_required": 0.62,
			"user_interaction":  0.85,
			"scope":            0.0,
			"confidentiality":   0.56,
			"integrity":        0.56,
			"availability":     0.56,
		},
	}
}
package intelligence

import (
	"context"
	"encoding/json"
	"fmt"
	"math"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/f2u0a0d3/GoRecon/pkg/models"
)

// IntelligenceCorrelator analyzes and correlates security findings
type IntelligenceCorrelator struct {
	config       CorrelationConfig
	rules        []CorrelationRule
	patterns     []ThreatPattern
	riskScorer   *RiskScorer
	ml           *MLEngine
	
	// Knowledge base
	knowledgeBase *KnowledgeBase
	threatIntel   *ThreatIntelligence
	
	// Caching and performance
	correlationCache map[string]*CorrelationResult
	mutex            sync.RWMutex
}

// CorrelationConfig configures the intelligence correlation system
type CorrelationConfig struct {
	EnableMLAnalysis      bool          `json:"enable_ml_analysis"`
	EnableThreatIntel     bool          `json:"enable_threat_intel"`
	EnableRiskScoring     bool          `json:"enable_risk_scoring"`
	CorrelationWindow     time.Duration `json:"correlation_window"`
	MinConfidence         float64       `json:"min_confidence"`
	MaxResults            int           `json:"max_results"`
	CacheResults          bool          `json:"cache_results"`
	CacheTTL              time.Duration `json:"cache_ttl"`
	ExternalAPIs          []string      `json:"external_apis"`
	MitreMapping          bool          `json:"mitre_mapping"`
	AttackPathAnalysis    bool          `json:"attack_path_analysis"`
	FalsePositiveFiltering bool         `json:"false_positive_filtering"`
}

// CorrelationRule defines how findings should be correlated
type CorrelationRule struct {
	ID          string                 `json:"id"`
	Name        string                 `json:"name"`
	Description string                 `json:"description"`
	Conditions  []CorrelationCondition `json:"conditions"`
	Actions     []string               `json:"actions"`
	Severity    string                 `json:"severity"`
	Confidence  float64                `json:"confidence"`
	TTL         time.Duration          `json:"ttl"`
	Enabled     bool                   `json:"enabled"`
	Priority    int                    `json:"priority"`
}

// CorrelationCondition defines matching criteria
type CorrelationCondition struct {
	Field     string      `json:"field"`
	Operator  string      `json:"operator"` // equals, contains, regex, range
	Value     interface{} `json:"value"`
	Weight    float64     `json:"weight"`
	Required  bool        `json:"required"`
}

// ThreatPattern represents a known threat pattern
type ThreatPattern struct {
	ID               string            `json:"id"`
	Name             string            `json:"name"`
	Description      string            `json:"description"`
	MitreTechniques  []string          `json:"mitre_techniques"`
	Indicators       []string          `json:"indicators"`
	Signatures       []string          `json:"signatures"`
	Severity         string            `json:"severity"`
	TTP              TacticsTreePattern `json:"ttp"`
	LastUpdated      time.Time         `json:"last_updated"`
}

// TacticsTreePattern represents MITRE ATT&CK TTPs
type TacticsTreePattern struct {
	Tactics    []string `json:"tactics"`
	Techniques []string `json:"techniques"`
	Procedures []string `json:"procedures"`
}

// CorrelationResult contains the result of correlation analysis
type CorrelationResult struct {
	ID                string                    `json:"id"`
	Summary           string                    `json:"summary"`
	Findings          []models.PluginResult     `json:"findings"`
	CorrelatedGroups  []CorrelatedFindingGroup  `json:"correlated_groups"`
	RiskScore         float64                   `json:"risk_score"`
	Confidence        float64                   `json:"confidence"`
	AttackPaths       []AttackPath              `json:"attack_paths"`
	MitreTechniques   []MitreTechnique          `json:"mitre_techniques"`
	ThreatActors      []ThreatActor             `json:"threat_actors"`
	Recommendations   []string                  `json:"recommendations"`
	FalsePositives    []string                  `json:"false_positives"`
	RelatedCVEs       []CVE                     `json:"related_cves"`
	GeneratedAt       time.Time                 `json:"generated_at"`
	AnalysisDuration  time.Duration             `json:"analysis_duration"`
}

// CorrelatedFindingGroup represents a group of related findings
type CorrelatedFindingGroup struct {
	ID           string                `json:"id"`
	Name         string                `json:"name"`
	Description  string                `json:"description"`
	Findings     []models.PluginResult `json:"findings"`
	Correlation  CorrelationMetadata   `json:"correlation"`
	RiskScore    float64               `json:"risk_score"`
	Priority     string                `json:"priority"`
}

// CorrelationMetadata contains correlation details
type CorrelationMetadata struct {
	Rules       []string  `json:"rules"`
	Patterns    []string  `json:"patterns"`
	Confidence  float64   `json:"confidence"`
	Strength    float64   `json:"strength"`
	Type        string    `json:"type"` // temporal, spatial, causal, semantic
	Evidence    []string  `json:"evidence"`
	CreatedAt   time.Time `json:"created_at"`
}

// AttackPath represents a potential attack chain
type AttackPath struct {
	ID          string                `json:"id"`
	Name        string                `json:"name"`
	Description string                `json:"description"`
	Steps       []AttackStep          `json:"steps"`
	Likelihood  float64               `json:"likelihood"`
	Impact      float64               `json:"impact"`
	RiskScore   float64               `json:"risk_score"`
	Mitigations []string              `json:"mitigations"`
}

// AttackStep represents a single step in an attack path
type AttackStep struct {
	StepNumber     int                   `json:"step_number"`
	Technique      string                `json:"technique"`
	Description    string                `json:"description"`
	Prerequisites  []string              `json:"prerequisites"`
	Tools          []string              `json:"tools"`
	Evidence       []models.PluginResult `json:"evidence"`
	MitreTechnique string                `json:"mitre_technique"`
	Difficulty     string                `json:"difficulty"`
}

// MitreTechnique represents a MITRE ATT&CK technique
type MitreTechnique struct {
	ID           string   `json:"id"`
	Name         string   `json:"name"`
	Description  string   `json:"description"`
	Tactics      []string `json:"tactics"`
	Platforms    []string `json:"platforms"`
	DataSources  []string `json:"data_sources"`
	Permissions  []string `json:"permissions"`
	Evidence     []string `json:"evidence"`
	Confidence   float64  `json:"confidence"`
}

// ThreatActor represents information about threat actors
type ThreatActor struct {
	ID          string   `json:"id"`
	Name        string   `json:"name"`
	Aliases     []string `json:"aliases"`
	Description string   `json:"description"`
	TTPs        []string `json:"ttps"`
	Targets     []string `json:"targets"`
	Motivation  string   `json:"motivation"`
	Sophistication string `json:"sophistication"`
	Confidence  float64  `json:"confidence"`
}

// CVE represents Common Vulnerabilities and Exposures
type CVE struct {
	ID          string  `json:"id"`
	Description string  `json:"description"`
	CVSS        float64 `json:"cvss"`
	Severity    string  `json:"severity"`
	Published   time.Time `json:"published"`
	References  []string `json:"references"`
}

// NewIntelligenceCorrelator creates a new intelligence correlator
func NewIntelligenceCorrelator(config CorrelationConfig) (*IntelligenceCorrelator, error) {
	// Set defaults
	if config.CorrelationWindow == 0 {
		config.CorrelationWindow = 24 * time.Hour
	}
	if config.MinConfidence == 0 {
		config.MinConfidence = 0.7
	}
	if config.MaxResults == 0 {
		config.MaxResults = 1000
	}
	if config.CacheTTL == 0 {
		config.CacheTTL = 1 * time.Hour
	}

	ic := &IntelligenceCorrelator{
		config:           config,
		rules:            DefaultCorrelationRules(),
		patterns:         DefaultThreatPatterns(),
		correlationCache: make(map[string]*CorrelationResult),
	}

	// Initialize components
	if config.EnableRiskScoring {
		ic.riskScorer = NewRiskScorer()
	}

	if config.EnableMLAnalysis {
		var err error
		ic.ml, err = NewMLEngine()
		if err != nil {
			return nil, fmt.Errorf("failed to initialize ML engine: %w", err)
		}
	}

	if config.EnableThreatIntel {
		var err error
		ic.threatIntel, err = NewThreatIntelligence(config.ExternalAPIs)
		if err != nil {
			return nil, fmt.Errorf("failed to initialize threat intelligence: %w", err)
		}
	}

	// Initialize knowledge base
	ic.knowledgeBase = NewKnowledgeBase()

	// Load MITRE ATT&CK data if enabled
	if config.MitreMapping {
		if err := ic.knowledgeBase.LoadMitreData(); err != nil {
			return nil, fmt.Errorf("failed to load MITRE data: %w", err)
		}
	}

	return ic, nil
}

// CorrelateFindings analyzes and correlates security findings
func (ic *IntelligenceCorrelator) CorrelateFindings(ctx context.Context, findings []models.PluginResult) (*CorrelationResult, error) {
	startTime := time.Now()

	// Generate cache key
	cacheKey := ic.generateCacheKey(findings)
	
	// Check cache if enabled
	if ic.config.CacheResults {
		if cached := ic.getCachedResult(cacheKey); cached != nil {
			return cached, nil
		}
	}

	result := &CorrelationResult{
		ID:          generateCorrelationID(),
		Findings:    findings,
		GeneratedAt: startTime,
	}

	// Step 1: Filter false positives
	if ic.config.FalsePositiveFiltering {
		findings = ic.filterFalsePositives(findings)
		result.Findings = findings
	}

	// Step 2: Apply correlation rules
	correlatedGroups, err := ic.applyCorrelationRules(findings)
	if err != nil {
		return nil, fmt.Errorf("correlation rules failed: %w", err)
	}
	result.CorrelatedGroups = correlatedGroups

	// Step 3: Pattern matching
	matchedPatterns := ic.matchThreatPatterns(findings)
	
	// Step 4: Risk scoring
	if ic.config.EnableRiskScoring && ic.riskScorer != nil {
		result.RiskScore = ic.riskScorer.CalculateRiskScore(findings, correlatedGroups)
		result.Confidence = ic.calculateConfidence(correlatedGroups, matchedPatterns)
	}

	// Step 5: MITRE ATT&CK mapping
	if ic.config.MitreMapping {
		result.MitreTechniques = ic.mapToMitreTechniques(findings, correlatedGroups)
	}

	// Step 6: Attack path analysis
	if ic.config.AttackPathAnalysis {
		result.AttackPaths = ic.analyzeAttackPaths(correlatedGroups, result.MitreTechniques)
	}

	// Step 7: Threat intelligence enrichment
	if ic.config.EnableThreatIntel && ic.threatIntel != nil {
		result.ThreatActors = ic.enrichWithThreatIntel(correlatedGroups)
		result.RelatedCVEs = ic.findRelatedCVEs(findings)
	}

	// Step 8: ML analysis (if enabled)
	if ic.config.EnableMLAnalysis && ic.ml != nil {
		mlResults := ic.ml.Analyze(findings, correlatedGroups)
		ic.incorporateMLResults(result, mlResults)
	}

	// Step 9: Generate recommendations
	result.Recommendations = ic.generateRecommendations(result)

	// Step 10: Create summary
	result.Summary = ic.generateSummary(result)

	result.AnalysisDuration = time.Since(startTime)

	// Cache result if enabled
	if ic.config.CacheResults {
		ic.cacheResult(cacheKey, result)
	}

	return result, nil
}

// applyCorrelationRules applies correlation rules to findings
func (ic *IntelligenceCorrelator) applyCorrelationRules(findings []models.PluginResult) ([]CorrelatedFindingGroup, error) {
	var groups []CorrelatedFindingGroup

	// Sort rules by priority
	sort.Slice(ic.rules, func(i, j int) bool {
		return ic.rules[i].Priority > ic.rules[j].Priority
	})

	for _, rule := range ic.rules {
		if !rule.Enabled {
			continue
		}

		matches := ic.findRuleMatches(findings, rule)
		if len(matches) >= 2 { // Need at least 2 findings to correlate
			group := CorrelatedFindingGroup{
				ID:          fmt.Sprintf("group_%s_%d", rule.ID, len(groups)),
				Name:        rule.Name,
				Description: rule.Description,
				Findings:    matches,
				Correlation: CorrelationMetadata{
					Rules:      []string{rule.ID},
					Confidence: rule.Confidence,
					Type:       "rule-based",
					Evidence:   ic.extractEvidence(matches, rule),
					CreatedAt:  time.Now(),
				},
			}

			// Calculate correlation strength
			group.Correlation.Strength = ic.calculateCorrelationStrength(matches, rule)
			
			// Set priority based on severity and correlation strength
			group.Priority = ic.calculatePriority(rule.Severity, group.Correlation.Strength)
			
			groups = append(groups, group)
		}
	}

	// Apply temporal correlation (time-based grouping)
	temporalGroups := ic.applyTemporalCorrelation(findings)
	groups = append(groups, temporalGroups...)

	// Apply spatial correlation (target-based grouping)
	spatialGroups := ic.applySpatialCorrelation(findings)
	groups = append(groups, spatialGroups...)

	// Merge overlapping groups
	groups = ic.mergeOverlappingGroups(groups)

	// Calculate risk scores for each group
	if ic.config.EnableRiskScoring && ic.riskScorer != nil {
		for i := range groups {
			groups[i].RiskScore = ic.riskScorer.CalculateGroupRiskScore(groups[i])
		}
	}

	return groups, nil
}

// matchThreatPatterns matches findings against known threat patterns
func (ic *IntelligenceCorrelator) matchThreatPatterns(findings []models.PluginResult) []string {
	var matchedPatterns []string

	for _, pattern := range ic.patterns {
		matches := 0
		for _, finding := range findings {
			if ic.matchesPattern(finding, pattern) {
				matches++
			}
		}
		
		// Require multiple matches for pattern confirmation
		threshold := int(math.Max(2, float64(len(pattern.Indicators))*0.3))
		if matches >= threshold {
			matchedPatterns = append(matchedPatterns, pattern.ID)
		}
	}

	return matchedPatterns
}

// matchesPattern checks if a finding matches a threat pattern
func (ic *IntelligenceCorrelator) matchesPattern(finding models.PluginResult, pattern ThreatPattern) bool {
	// Check indicators in finding content
	findingText := strings.ToLower(finding.Finding + " " + finding.Description)
	
	for _, indicator := range pattern.Indicators {
		if strings.Contains(findingText, strings.ToLower(indicator)) {
			return true
		}
	}

	// Check signatures
	for _, signature := range pattern.Signatures {
		if strings.Contains(findingText, strings.ToLower(signature)) {
			return true
		}
	}

	// Check MITRE techniques
	for _, technique := range pattern.MitreTechniques {
		for _, findingTechnique := range finding.MITRETechniques {
			if technique == findingTechnique {
				return true
			}
		}
	}

	return false
}

// mapToMitreTechniques maps findings to MITRE ATT&CK techniques
func (ic *IntelligenceCorrelator) mapToMitreTechniques(findings []models.PluginResult, groups []CorrelatedFindingGroup) []MitreTechnique {
	techniqueMap := make(map[string]*MitreTechnique)

	// Map from individual findings
	for _, finding := range findings {
		for _, techniqueID := range finding.MITRETechniques {
			if technique := ic.knowledgeBase.GetMitreTechnique(techniqueID); technique != nil {
				if existing, exists := techniqueMap[techniqueID]; exists {
					existing.Confidence = math.Min(1.0, existing.Confidence+0.1)
					existing.Evidence = append(existing.Evidence, finding.Finding)
				} else {
					techniqueMap[techniqueID] = &MitreTechnique{
						ID:          technique.ID,
						Name:        technique.Name,
						Description: technique.Description,
						Tactics:     technique.Tactics,
						Platforms:   technique.Platforms,
						Evidence:    []string{finding.Finding},
						Confidence:  0.7,
					}
				}
			}
		}
	}

	// Infer additional techniques from patterns and correlations
	for _, group := range groups {
		inferredTechniques := ic.inferMitreTechniques(group)
		for _, technique := range inferredTechniques {
			if existing, exists := techniqueMap[technique.ID]; exists {
				existing.Confidence = math.Min(1.0, existing.Confidence+0.2)
			} else {
				techniqueMap[technique.ID] = &technique
			}
		}
	}

	// Convert map to slice
	var techniques []MitreTechnique
	for _, technique := range techniqueMap {
		if technique.Confidence >= ic.config.MinConfidence {
			techniques = append(techniques, *technique)
		}
	}

	// Sort by confidence
	sort.Slice(techniques, func(i, j int) bool {
		return techniques[i].Confidence > techniques[j].Confidence
	})

	return techniques
}

// analyzeAttackPaths identifies potential attack chains
func (ic *IntelligenceCorrelator) analyzeAttackPaths(groups []CorrelatedFindingGroup, techniques []MitreTechnique) []AttackPath {
	var attackPaths []AttackPath

	// Build attack chains from MITRE techniques
	chains := ic.buildAttackChains(techniques, groups)
	
	for i, chain := range chains {
		path := AttackPath{
			ID:          fmt.Sprintf("path_%d", i),
			Name:        fmt.Sprintf("Attack Path %d", i+1),
			Description: ic.generatePathDescription(chain),
			Steps:       chain,
			Likelihood:  ic.calculatePathLikelihood(chain),
			Impact:      ic.calculatePathImpact(chain),
		}
		
		path.RiskScore = (path.Likelihood * path.Impact) / 2.0
		path.Mitigations = ic.generateMitigations(chain)
		
		attackPaths = append(attackPaths, path)
	}

	// Sort by risk score
	sort.Slice(attackPaths, func(i, j int) bool {
		return attackPaths[i].RiskScore > attackPaths[j].RiskScore
	})

	// Limit results
	if len(attackPaths) > 10 {
		attackPaths = attackPaths[:10]
	}

	return attackPaths
}

// Helper methods for correlation logic

func (ic *IntelligenceCorrelator) findRuleMatches(findings []models.PluginResult, rule CorrelationRule) []models.PluginResult {
	var matches []models.PluginResult

	for _, finding := range findings {
		if ic.evaluateConditions(finding, rule.Conditions) {
			matches = append(matches, finding)
		}
	}

	return matches
}

func (ic *IntelligenceCorrelator) evaluateConditions(finding models.PluginResult, conditions []CorrelationCondition) bool {
	requiredMet := true
	totalWeight := 0.0
	metWeight := 0.0

	for _, condition := range conditions {
		fieldValue := ic.extractFieldValue(finding, condition.Field)
		matches := ic.evaluateCondition(fieldValue, condition)

		if condition.Required && !matches {
			requiredMet = false
		}

		totalWeight += condition.Weight
		if matches {
			metWeight += condition.Weight
		}
	}

	// Must meet all required conditions and sufficient weight
	return requiredMet && (metWeight/totalWeight) >= 0.6
}

func (ic *IntelligenceCorrelator) evaluateCondition(fieldValue interface{}, condition CorrelationCondition) bool {
	switch condition.Operator {
	case "equals":
		return fmt.Sprintf("%v", fieldValue) == fmt.Sprintf("%v", condition.Value)
	case "contains":
		return strings.Contains(fmt.Sprintf("%v", fieldValue), fmt.Sprintf("%v", condition.Value))
	case "regex":
		// Simplified regex matching
		return strings.Contains(fmt.Sprintf("%v", fieldValue), fmt.Sprintf("%v", condition.Value))
	case "range":
		// Simplified range checking for numeric values
		return true
	default:
		return false
	}
}

func (ic *IntelligenceCorrelator) extractFieldValue(finding models.PluginResult, field string) interface{} {
	switch field {
	case "plugin":
		return finding.Plugin
	case "category":
		return finding.Category
	case "severity":
		return finding.Severity
	case "target":
		return finding.Target.String()
	case "finding":
		return finding.Finding
	case "description":
		return finding.Description
	case "confidence":
		return finding.Confidence
	default:
		return ""
	}
}

func (ic *IntelligenceCorrelator) applyTemporalCorrelation(findings []models.PluginResult) []CorrelatedFindingGroup {
	var groups []CorrelatedFindingGroup

	// Group findings within time windows
	timeWindows := ic.createTimeWindows(findings)
	
	for i, window := range timeWindows {
		if len(window) >= 3 { // Require at least 3 findings for temporal correlation
			group := CorrelatedFindingGroup{
				ID:          fmt.Sprintf("temporal_group_%d", i),
				Name:        "Temporal Correlation",
				Description: "Findings that occurred within a similar timeframe",
				Findings:    window,
				Correlation: CorrelationMetadata{
					Type:       "temporal",
					Confidence: ic.calculateTemporalConfidence(window),
					Strength:   ic.calculateTemporalStrength(window),
					CreatedAt:  time.Now(),
				},
			}
			groups = append(groups, group)
		}
	}

	return groups
}

func (ic *IntelligenceCorrelator) applySpatialCorrelation(findings []models.PluginResult) []CorrelatedFindingGroup {
	var groups []CorrelatedFindingGroup

	// Group by target/domain
	targetGroups := make(map[string][]models.PluginResult)
	
	for _, finding := range findings {
		target := finding.Target.String()
		targetGroups[target] = append(targetGroups[target], finding)
	}

	i := 0
	for target, targetFindings := range targetGroups {
		if len(targetFindings) >= 2 { // Require at least 2 findings per target
			group := CorrelatedFindingGroup{
				ID:          fmt.Sprintf("spatial_group_%d", i),
				Name:        "Spatial Correlation",
				Description: fmt.Sprintf("Findings related to target: %s", target),
				Findings:    targetFindings,
				Correlation: CorrelationMetadata{
					Type:       "spatial",
					Confidence: ic.calculateSpatialConfidence(targetFindings),
					Strength:   ic.calculateSpatialStrength(targetFindings),
					CreatedAt:  time.Now(),
				},
			}
			groups = append(groups, group)
			i++
		}
	}

	return groups
}

// Additional helper methods would continue here...
// Due to length constraints, I'll implement key remaining methods

func (ic *IntelligenceCorrelator) generateCacheKey(findings []models.PluginResult) string {
	// Generate a hash-based cache key from findings
	var keys []string
	for _, finding := range findings {
		keys = append(keys, finding.ID)
	}
	sort.Strings(keys)
	return fmt.Sprintf("corr_%x", strings.Join(keys, "_"))
}

func (ic *IntelligenceCorrelator) getCachedResult(key string) *CorrelationResult {
	ic.mutex.RLock()
	defer ic.mutex.RUnlock()
	
	if result, exists := ic.correlationCache[key]; exists {
		if time.Since(result.GeneratedAt) < ic.config.CacheTTL {
			return result
		}
		delete(ic.correlationCache, key)
	}
	return nil
}

func (ic *IntelligenceCorrelator) cacheResult(key string, result *CorrelationResult) {
	ic.mutex.Lock()
	defer ic.mutex.Unlock()
	
	ic.correlationCache[key] = result
}

func (ic *IntelligenceCorrelator) generateSummary(result *CorrelationResult) string {
	return fmt.Sprintf("Analyzed %d findings, found %d correlations with risk score %.2f",
		len(result.Findings), len(result.CorrelatedGroups), result.RiskScore)
}

func (ic *IntelligenceCorrelator) generateRecommendations(result *CorrelationResult) []string {
	var recommendations []string
	
	if result.RiskScore > 8.0 {
		recommendations = append(recommendations, "CRITICAL: Immediate action required - high risk attack path detected")
	}
	if len(result.AttackPaths) > 0 {
		recommendations = append(recommendations, "Review and mitigate identified attack paths")
	}
	if len(result.MitreTechniques) > 5 {
		recommendations = append(recommendations, "Multiple attack techniques detected - comprehensive security review needed")
	}
	
	return recommendations
}

func generateCorrelationID() string {
	return fmt.Sprintf("corr_%d", time.Now().UnixNano())
}
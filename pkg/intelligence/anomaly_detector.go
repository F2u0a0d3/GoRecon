package intelligence

import (
	"context"
	"fmt"
	"math"
	"sort"
	"strings"
	"time"

	"github.com/f2u0a0d3/GoRecon/pkg/models"
	"github.com/rs/zerolog/log"
)

type AnomalyDetector struct {
	config           AnomalyDetectionConfig
	baselineProfiles map[string]*BaselineProfile
	thresholds       AnomalyThresholds
	historicalData   []HistoricalDataPoint
}

type AnomalyDetectionConfig struct {
	EnableStatisticalAnalysis bool    `json:"enable_statistical_analysis"`
	EnableTimeSeriesAnalysis  bool    `json:"enable_time_series_analysis"`
	EnableBehavioralAnalysis  bool    `json:"enable_behavioral_analysis"`
	SensitivityLevel         string  `json:"sensitivity_level"` // low, medium, high
	MinDataPoints            int     `json:"min_data_points"`
	MaxHistory               int     `json:"max_history"`
	ConfidenceThreshold      float64 `json:"confidence_threshold"`
}

type BaselineProfile struct {
	Target           string                 `json:"target"`
	NormalPatterns   map[string]PatternData `json:"normal_patterns"`
	StatisticalData  StatisticalMetrics     `json:"statistical_data"`
	LastUpdated      time.Time              `json:"last_updated"`
	DataPoints       int                    `json:"data_points"`
}

type PatternData struct {
	Frequency    float64   `json:"frequency"`
	Timing       []float64 `json:"timing"`
	Severity     []string  `json:"severity"`
	Categories   []string  `json:"categories"`
	Plugins      []string  `json:"plugins"`
}

type StatisticalMetrics struct {
	Mean         float64 `json:"mean"`
	StdDev       float64 `json:"std_dev"`
	Variance     float64 `json:"variance"`
	Median       float64 `json:"median"`
	Mode         float64 `json:"mode"`
	Percentiles  map[int]float64 `json:"percentiles"`
}

type AnomalyThresholds struct {
	FrequencyThreshold    float64 `json:"frequency_threshold"`
	SeverityThreshold     float64 `json:"severity_threshold"`
	VolumeThreshold       float64 `json:"volume_threshold"`
	TemporalThreshold     float64 `json:"temporal_threshold"`
	BehavioralThreshold   float64 `json:"behavioral_threshold"`
	StatisticalThreshold  float64 `json:"statistical_threshold"`
}

type HistoricalDataPoint struct {
	Timestamp time.Time            `json:"timestamp"`
	Target    string               `json:"target"`
	Metrics   map[string]float64   `json:"metrics"`
	Context   map[string]string    `json:"context"`
}

type AnomalyResult struct {
	ID            string                 `json:"id"`
	Type          AnomalyType            `json:"type"`
	Severity      string                 `json:"severity"`
	Confidence    float64                `json:"confidence"`
	Description   string                 `json:"description"`
	Evidence      []AnomalyEvidence      `json:"evidence"`
	Baseline      *BaselineComparison    `json:"baseline"`
	Impact        string                 `json:"impact"`
	Recommendations []string            `json:"recommendations"`
	Metadata      map[string]interface{} `json:"metadata"`
	DetectedAt    time.Time              `json:"detected_at"`
}

type AnomalyType string

const (
	AnomalyTypeFrequency   AnomalyType = "frequency"
	AnomalyTypeVolume      AnomalyType = "volume"
	AnomalyTypeTemporal    AnomalyType = "temporal"
	AnomalyTypeSeverity    AnomalyType = "severity"
	AnomalyTypeBehavioral  AnomalyType = "behavioral"
	AnomalyTypeStatistical AnomalyType = "statistical"
	AnomalyTypePattern     AnomalyType = "pattern"
)

type AnomalyEvidence struct {
	Type        string      `json:"type"`
	Value       interface{} `json:"value"`
	Expected    interface{} `json:"expected"`
	Deviation   float64     `json:"deviation"`
	Description string      `json:"description"`
}

type BaselineComparison struct {
	CurrentValue   float64 `json:"current_value"`
	BaselineValue  float64 `json:"baseline_value"`
	Deviation      float64 `json:"deviation"`
	StandardScore  float64 `json:"standard_score"`
	Percentile     float64 `json:"percentile"`
}

func NewAnomalyDetector() *AnomalyDetector {
	return &AnomalyDetector{
		config: AnomalyDetectionConfig{
			EnableStatisticalAnalysis: true,
			EnableTimeSeriesAnalysis:  true,
			EnableBehavioralAnalysis:  true,
			SensitivityLevel:         "medium",
			MinDataPoints:            10,
			MaxHistory:               1000,
			ConfidenceThreshold:      0.8,
		},
		baselineProfiles: make(map[string]*BaselineProfile),
		thresholds: AnomalyThresholds{
			FrequencyThreshold:    2.0,  // 2 std deviations
			SeverityThreshold:     1.5,  // 1.5 std deviations
			VolumeThreshold:       2.5,  // 2.5 std deviations
			TemporalThreshold:     2.0,  // 2 std deviations
			BehavioralThreshold:   1.8,  // 1.8 std deviations
			StatisticalThreshold:  2.0,  // 2 std deviations
		},
		historicalData: make([]HistoricalDataPoint, 0),
	}
}

func (ad *AnomalyDetector) DetectAnomalies(ctx context.Context, newFinding *models.PluginResult, allFindings map[string]*models.PluginResult) ([]*Correlation, error) {
	var anomalies []*Correlation

	target := newFinding.Target.String()
	
	// Update baseline profile
	ad.updateBaselineProfile(target, newFinding, allFindings)
	
	// Detect different types of anomalies
	if ad.config.EnableStatisticalAnalysis {
		statAnomalies := ad.detectStatisticalAnomalies(newFinding, allFindings)
		anomalies = append(anomalies, statAnomalies...)
	}

	if ad.config.EnableTimeSeriesAnalysis {
		tempAnomalies := ad.detectTemporalAnomalies(newFinding, allFindings)
		anomalies = append(anomalies, tempAnomalies...)
	}

	if ad.config.EnableBehavioralAnalysis {
		behavAnomalies := ad.detectBehavioralAnomalies(newFinding, allFindings)
		anomalies = append(anomalies, behavAnomalies...)
	}

	// Convert anomaly results to correlations
	correlations := ad.convertAnomaliesToCorrelations(anomalies)
	
	return correlations, nil
}

func (ad *AnomalyDetector) detectStatisticalAnomalies(newFinding *models.PluginResult, allFindings map[string]*models.PluginResult) []*AnomalyResult {
	var anomalies []*AnomalyResult
	
	target := newFinding.Target.String()
	profile := ad.baselineProfiles[target]
	
	if profile == nil || profile.DataPoints < ad.config.MinDataPoints {
		return anomalies
	}

	// Analyze finding frequency
	currentFrequency := ad.calculateCurrentFrequency(newFinding, allFindings)
	if ad.isFrequencyAnomaly(currentFrequency, profile) {
		anomaly := &AnomalyResult{
			ID:          fmt.Sprintf("freq_anomaly_%d", time.Now().UnixNano()),
			Type:        AnomalyTypeFrequency,
			Severity:    ad.calculateAnomalySeverity(currentFrequency, profile.StatisticalData.Mean),
			Confidence:  ad.calculateConfidence(currentFrequency, profile.StatisticalData),
			Description: "Unusual frequency of findings detected",
			Evidence: []AnomalyEvidence{{
				Type:        "frequency",
				Value:       currentFrequency,
				Expected:    profile.StatisticalData.Mean,
				Deviation:   math.Abs(currentFrequency - profile.StatisticalData.Mean),
				Description: "Current finding frequency deviates significantly from baseline",
			}},
			DetectedAt: time.Now(),
		}
		anomalies = append(anomalies, anomaly)
	}

	// Analyze severity distribution
	if ad.isSeverityAnomaly(newFinding, profile) {
		anomaly := &AnomalyResult{
			ID:          fmt.Sprintf("sev_anomaly_%d", time.Now().UnixNano()),
			Type:        AnomalyTypeSeverity,
			Severity:    "high",
			Confidence:  0.85,
			Description: "Unusual severity pattern detected",
			Evidence: []AnomalyEvidence{{
				Type:        "severity",
				Value:       newFinding.Severity,
				Expected:    "normal distribution",
				Deviation:   1.0,
				Description: "Severity pattern deviates from established baseline",
			}},
			DetectedAt: time.Now(),
		}
		anomalies = append(anomalies, anomaly)
	}

	return anomalies
}

func (ad *AnomalyDetector) detectTemporalAnomalies(newFinding *models.PluginResult, allFindings map[string]*models.PluginResult) []*AnomalyResult {
	var anomalies []*AnomalyResult
	
	// Analyze temporal patterns
	recentFindings := ad.getRecentFindings(allFindings, 24*time.Hour)
	
	if len(recentFindings) > ad.getExpectedRecentCount(allFindings) * 3 {
		anomaly := &AnomalyResult{
			ID:          fmt.Sprintf("temp_anomaly_%d", time.Now().UnixNano()),
			Type:        AnomalyTypeTemporal,
			Severity:    "medium",
			Confidence:  0.8,
			Description: "Unusual temporal clustering of findings",
			Evidence: []AnomalyEvidence{{
				Type:        "temporal",
				Value:       len(recentFindings),
				Expected:    ad.getExpectedRecentCount(allFindings),
				Deviation:   float64(len(recentFindings)) / float64(ad.getExpectedRecentCount(allFindings)),
				Description: "Recent finding count significantly exceeds normal patterns",
			}},
			DetectedAt: time.Now(),
		}
		anomalies = append(anomalies, anomaly)
	}

	// Check for unusual timing patterns
	if ad.isUnusualTiming(newFinding, recentFindings) {
		anomaly := &AnomalyResult{
			ID:          fmt.Sprintf("timing_anomaly_%d", time.Now().UnixNano()),
			Type:        AnomalyTypeTemporal,
			Severity:    "low",
			Confidence:  0.7,
			Description: "Unusual timing pattern detected",
			Evidence: []AnomalyEvidence{{
				Type:        "timing",
				Value:       newFinding.Timestamp.Hour(),
				Expected:    "normal business hours",
				Deviation:   1.0,
				Description: "Finding detected outside normal operational hours",
			}},
			DetectedAt: time.Now(),
		}
		anomalies = append(anomalies, anomaly)
	}

	return anomalies
}

func (ad *AnomalyDetector) detectBehavioralAnomalies(newFinding *models.PluginResult, allFindings map[string]*models.PluginResult) []*AnomalyResult {
	var anomalies []*AnomalyResult
	
	// Analyze plugin usage patterns
	pluginCounts := ad.getPluginUsageStats(allFindings)
	
	if ad.isUnusualPluginUsage(newFinding.Plugin, pluginCounts) {
		anomaly := &AnomalyResult{
			ID:          fmt.Sprintf("plugin_anomaly_%d", time.Now().UnixNano()),
			Type:        AnomalyTypeBehavioral,
			Severity:    "low",
			Confidence:  0.75,
			Description: "Unusual plugin usage pattern",
			Evidence: []AnomalyEvidence{{
				Type:        "plugin_usage",
				Value:       newFinding.Plugin,
				Expected:    "normal plugin distribution",
				Deviation:   1.0,
				Description: "Plugin usage deviates from normal patterns",
			}},
			DetectedAt: time.Now(),
		}
		anomalies = append(anomalies, anomaly)
	}

	// Analyze target patterns
	targetCounts := ad.getTargetUsageStats(allFindings)
	
	if ad.isUnusualTargetPattern(newFinding.Target.String(), targetCounts) {
		anomaly := &AnomalyResult{
			ID:          fmt.Sprintf("target_anomaly_%d", time.Now().UnixNano()),
			Type:        AnomalyTypeBehavioral,
			Severity:    "medium",
			Confidence:  0.8,
			Description: "Unusual target access pattern",
			Evidence: []AnomalyEvidence{{
				Type:        "target_pattern",
				Value:       newFinding.Target.String(),
				Expected:    "normal target distribution",
				Deviation:   1.0,
				Description: "Target access pattern is unusual",
			}},
			DetectedAt: time.Now(),
		}
		anomalies = append(anomalies, anomaly)
	}

	return anomalies
}

func (ad *AnomalyDetector) updateBaselineProfile(target string, newFinding *models.PluginResult, allFindings map[string]*models.PluginResult) {
	if ad.baselineProfiles[target] == nil {
		ad.baselineProfiles[target] = &BaselineProfile{
			Target:         target,
			NormalPatterns: make(map[string]PatternData),
			LastUpdated:    time.Now(),
			DataPoints:     0,
		}
	}

	profile := ad.baselineProfiles[target]
	
	// Update statistical metrics
	targetFindings := ad.getTargetFindings(target, allFindings)
	profile.StatisticalData = ad.calculateStatisticalMetrics(targetFindings)
	profile.DataPoints = len(targetFindings)
	profile.LastUpdated = time.Now()

	// Update pattern data
	ad.updatePatternData(profile, targetFindings)
}

func (ad *AnomalyDetector) calculateStatisticalMetrics(findings []*models.PluginResult) StatisticalMetrics {
	if len(findings) == 0 {
		return StatisticalMetrics{}
	}

	// Extract numeric values for analysis (using confidence scores)
	values := make([]float64, len(findings))
	for i, finding := range findings {
		values[i] = finding.Confidence
	}

	sort.Float64s(values)

	metrics := StatisticalMetrics{
		Mean:        ad.calculateMean(values),
		StdDev:      ad.calculateStdDev(values),
		Variance:    ad.calculateVariance(values),
		Median:      ad.calculateMedian(values),
		Mode:        ad.calculateMode(values),
		Percentiles: ad.calculatePercentiles(values),
	}

	return metrics
}

func (ad *AnomalyDetector) calculateMean(values []float64) float64 {
	if len(values) == 0 {
		return 0.0
	}

	sum := 0.0
	for _, v := range values {
		sum += v
	}
	return sum / float64(len(values))
}

func (ad *AnomalyDetector) calculateStdDev(values []float64) float64 {
	if len(values) <= 1 {
		return 0.0
	}

	mean := ad.calculateMean(values)
	sumSquares := 0.0
	for _, v := range values {
		diff := v - mean
		sumSquares += diff * diff
	}
	variance := sumSquares / float64(len(values)-1)
	return math.Sqrt(variance)
}

func (ad *AnomalyDetector) calculateVariance(values []float64) float64 {
	stdDev := ad.calculateStdDev(values)
	return stdDev * stdDev
}

func (ad *AnomalyDetector) calculateMedian(values []float64) float64 {
	if len(values) == 0 {
		return 0.0
	}

	n := len(values)
	if n%2 == 0 {
		return (values[n/2-1] + values[n/2]) / 2.0
	}
	return values[n/2]
}

func (ad *AnomalyDetector) calculateMode(values []float64) float64 {
	if len(values) == 0 {
		return 0.0
	}

	counts := make(map[float64]int)
	for _, v := range values {
		counts[v]++
	}

	maxCount := 0
	mode := values[0]
	for v, count := range counts {
		if count > maxCount {
			maxCount = count
			mode = v
		}
	}

	return mode
}

func (ad *AnomalyDetector) calculatePercentiles(values []float64) map[int]float64 {
	percentiles := make(map[int]float64)
	if len(values) == 0 {
		return percentiles
	}

	for _, p := range []int{25, 50, 75, 90, 95, 99} {
		index := int(float64(len(values)-1) * float64(p) / 100.0)
		percentiles[p] = values[index]
	}

	return percentiles
}

func (ad *AnomalyDetector) isFrequencyAnomaly(currentFreq float64, profile *BaselineProfile) bool {
	if profile.StatisticalData.StdDev == 0 {
		return false
	}

	zScore := math.Abs(currentFreq-profile.StatisticalData.Mean) / profile.StatisticalData.StdDev
	return zScore > ad.thresholds.FrequencyThreshold
}

func (ad *AnomalyDetector) isSeverityAnomaly(finding *models.PluginResult, profile *BaselineProfile) bool {
	// Simplified severity anomaly detection
	// In practice, this would analyze the distribution of severities
	return finding.Severity == "critical" && profile.DataPoints > 10
}

func (ad *AnomalyDetector) calculateCurrentFrequency(finding *models.PluginResult, allFindings map[string]*models.PluginResult) float64 {
	count := 0
	window := 24 * time.Hour
	cutoff := time.Now().Add(-window)

	for _, f := range allFindings {
		if f.Target.String() == finding.Target.String() && f.Timestamp.After(cutoff) {
			count++
		}
	}

	return float64(count)
}

func (ad *AnomalyDetector) calculateAnomalySeverity(current, baseline float64) string {
	ratio := current / baseline
	if ratio > 5.0 {
		return "critical"
	} else if ratio > 3.0 {
		return "high"
	} else if ratio > 2.0 {
		return "medium"
	}
	return "low"
}

func (ad *AnomalyDetector) calculateConfidence(current float64, stats StatisticalMetrics) float64 {
	if stats.StdDev == 0 {
		return 0.5
	}

	zScore := math.Abs(current-stats.Mean) / stats.StdDev
	confidence := math.Min(zScore/3.0, 1.0) // Normalize to 0-1 range
	return confidence
}

func (ad *AnomalyDetector) getRecentFindings(allFindings map[string]*models.PluginResult, window time.Duration) []*models.PluginResult {
	var recent []*models.PluginResult
	cutoff := time.Now().Add(-window)

	for _, finding := range allFindings {
		if finding.Timestamp.After(cutoff) {
			recent = append(recent, finding)
		}
	}

	return recent
}

func (ad *AnomalyDetector) getExpectedRecentCount(allFindings map[string]*models.PluginResult) int {
	// Simplified calculation - in practice would use historical averages
	return len(allFindings) / 24 // Expected hourly rate
}

func (ad *AnomalyDetector) isUnusualTiming(finding *models.PluginResult, recentFindings []*models.PluginResult) bool {
	hour := finding.Timestamp.Hour()
	
	// Business hours are typically 9-17
	if hour < 9 || hour > 17 {
		// Check if this is unusual compared to recent patterns
		offHoursCount := 0
		for _, f := range recentFindings {
			fHour := f.Timestamp.Hour()
			if fHour < 9 || fHour > 17 {
				offHoursCount++
			}
		}
		
		offHoursRatio := float64(offHoursCount) / float64(len(recentFindings))
		return offHoursRatio < 0.1 // Less than 10% of recent findings were off-hours
	}
	
	return false
}

func (ad *AnomalyDetector) getPluginUsageStats(allFindings map[string]*models.PluginResult) map[string]int {
	counts := make(map[string]int)
	for _, finding := range allFindings {
		counts[finding.Plugin]++
	}
	return counts
}

func (ad *AnomalyDetector) isUnusualPluginUsage(plugin string, counts map[string]int) bool {
	// Calculate if this plugin usage is unusual
	total := 0
	for _, count := range counts {
		total += count
	}

	if total == 0 {
		return false
	}

	currentCount := counts[plugin]
	avgCount := total / len(counts)
	
	return currentCount > avgCount*3 // More than 3x average usage
}

func (ad *AnomalyDetector) getTargetUsageStats(allFindings map[string]*models.PluginResult) map[string]int {
	counts := make(map[string]int)
	for _, finding := range allFindings {
		counts[finding.Target.String()]++
	}
	return counts
}

func (ad *AnomalyDetector) isUnusualTargetPattern(target string, counts map[string]int) bool {
	// Similar logic to plugin usage
	total := 0
	for _, count := range counts {
		total += count
	}

	if total == 0 {
		return false
	}

	currentCount := counts[target]
	avgCount := total / len(counts)
	
	return currentCount > avgCount*2 // More than 2x average usage
}

func (ad *AnomalyDetector) getTargetFindings(target string, allFindings map[string]*models.PluginResult) []*models.PluginResult {
	var targetFindings []*models.PluginResult
	for _, finding := range allFindings {
		if finding.Target.String() == target {
			targetFindings = append(targetFindings, finding)
		}
	}
	return targetFindings
}

func (ad *AnomalyDetector) updatePatternData(profile *BaselineProfile, findings []*models.PluginResult) {
	// Update normal patterns based on current findings
	pluginPattern := PatternData{
		Plugins: make([]string, 0),
	}

	for _, finding := range findings {
		pluginPattern.Plugins = append(pluginPattern.Plugins, finding.Plugin)
	}

	profile.NormalPatterns["plugins"] = pluginPattern
}

func (ad *AnomalyDetector) convertAnomaliesToCorrelations(anomalies []*AnomalyResult) []*Correlation {
	var correlations []*Correlation

	for _, anomaly := range anomalies {
		correlation := &Correlation{
			ID:          anomaly.ID,
			Type:        CorrelationTypeAnomaly,
			Score:       anomaly.Confidence * 10.0, // Scale to 0-10
			Description: anomaly.Description,
			Metadata: map[string]interface{}{
				"anomaly_type":     string(anomaly.Type),
				"anomaly_severity": anomaly.Severity,
				"evidence_count":   len(anomaly.Evidence),
			},
			CreatedAt: anomaly.DetectedAt,
		}

		correlations = append(correlations, correlation)
	}

	return correlations
}
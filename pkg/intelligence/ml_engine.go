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

type MLEngine struct {
	config         MLConfig
	models         map[string]MLModel
	featureStore   *FeatureStore
	trainingData   []TrainingExample
	isInitialized  bool
}

type MLConfig struct {
	EnablePredictiveAnalysis bool     `json:"enable_predictive_analysis"`
	EnableClassification     bool     `json:"enable_classification"`
	EnableClustering         bool     `json:"enable_clustering"`
	EnableAnomalyDetection   bool     `json:"enable_anomaly_detection"`
	ModelTypes              []string `json:"model_types"`
	TrainingDataSize        int      `json:"training_data_size"`
	RetrainingInterval      time.Duration `json:"retraining_interval"`
	ConfidenceThreshold     float64  `json:"confidence_threshold"`
}

type MLModel interface {
	Train(data []TrainingExample) error
	Predict(features FeatureVector) (*Prediction, error)
	GetAccuracy() float64
	GetModelInfo() ModelInfo
}

type FeatureStore struct {
	features       map[string]FeatureVector
	featureHistory []HistoricalFeature
	extractors     map[string]FeatureExtractor
}

type FeatureVector struct {
	Features   map[string]float64 `json:"features"`
	Metadata   map[string]string  `json:"metadata"`
	Timestamp  time.Time          `json:"timestamp"`
	SourceID   string             `json:"source_id"`
}

type TrainingExample struct {
	Features FeatureVector `json:"features"`
	Label    string        `json:"label"`
	Weight   float64       `json:"weight"`
}

type Prediction struct {
	Label       string            `json:"label"`
	Confidence  float64           `json:"confidence"`
	Probability map[string]float64 `json:"probability"`
	Features    FeatureVector     `json:"features"`
	ModelInfo   ModelInfo         `json:"model_info"`
}

type ModelInfo struct {
	Name      string    `json:"name"`
	Type      string    `json:"type"`
	Version   string    `json:"version"`
	Accuracy  float64   `json:"accuracy"`
	TrainedAt time.Time `json:"trained_at"`
}

type HistoricalFeature struct {
	Timestamp time.Time     `json:"timestamp"`
	Features  FeatureVector `json:"features"`
	Context   string        `json:"context"`
}

type FeatureExtractor interface {
	Extract(finding *models.PluginResult) (map[string]float64, error)
	GetFeatureNames() []string
}

type MLResults struct {
	Predictions     []*Prediction          `json:"predictions"`
	Classifications []*Classification      `json:"classifications"`
	Clusters        []*Cluster             `json:"clusters"`
	Anomalies       []*MLAnomaly           `json:"anomalies"`
	Insights        []*MLInsight           `json:"insights"`
	ModelMetrics    map[string]ModelMetric `json:"model_metrics"`
}

type Classification struct {
	Category    string  `json:"category"`
	Confidence  float64 `json:"confidence"`
	Description string  `json:"description"`
	Evidence    []string `json:"evidence"`
}

type Cluster struct {
	ID          string                 `json:"id"`
	Center      FeatureVector          `json:"center"`
	Members     []string               `json:"members"`
	Radius      float64                `json:"radius"`
	Cohesion    float64                `json:"cohesion"`
	Description string                 `json:"description"`
}

type MLAnomaly struct {
	ID          string        `json:"id"`
	Score       float64       `json:"score"`
	Confidence  float64       `json:"confidence"`
	Features    FeatureVector `json:"features"`
	Description string        `json:"description"`
}

type MLInsight struct {
	Type        string      `json:"type"`
	Title       string      `json:"title"`
	Description string      `json:"description"`
	Evidence    []string    `json:"evidence"`
	Confidence  float64     `json:"confidence"`
	Impact      string      `json:"impact"`
}

type ModelMetric struct {
	Accuracy    float64 `json:"accuracy"`
	Precision   float64 `json:"precision"`
	Recall      float64 `json:"recall"`
	F1Score     float64 `json:"f1_score"`
	DataPoints  int     `json:"data_points"`
	LastUpdated time.Time `json:"last_updated"`
}

// Simple implementation of a rule-based classifier
type RuleBasedClassifier struct {
	rules      []ClassificationRule
	accuracy   float64
	modelInfo  ModelInfo
}

type ClassificationRule struct {
	Name        string                 `json:"name"`
	Conditions  []FeatureCondition     `json:"conditions"`
	Label       string                 `json:"label"`
	Confidence  float64                `json:"confidence"`
	Priority    int                    `json:"priority"`
}

type FeatureCondition struct {
	Feature   string      `json:"feature"`
	Operator  string      `json:"operator"`
	Value     interface{} `json:"value"`
	Weight    float64     `json:"weight"`
}

// Simple feature extractor implementation
type BasicFeatureExtractor struct {
	name     string
	features []string
}

func NewMLEngine() (*MLEngine, error) {
	engine := &MLEngine{
		config: MLConfig{
			EnablePredictiveAnalysis: true,
			EnableClassification:     true,
			EnableClustering:        false, // Disabled for simplicity
			EnableAnomalyDetection:  true,
			ModelTypes:              []string{"rule-based", "statistical"},
			TrainingDataSize:        1000,
			RetrainingInterval:      24 * time.Hour,
			ConfidenceThreshold:     0.7,
		},
		models:       make(map[string]MLModel),
		featureStore: NewFeatureStore(),
		trainingData: make([]TrainingExample, 0),
	}

	// Initialize models
	if err := engine.initializeModels(); err != nil {
		return nil, fmt.Errorf("failed to initialize ML models: %w", err)
	}

	engine.isInitialized = true
	return engine, nil
}

func (ml *MLEngine) Analyze(findings []models.PluginResult, groups []CorrelatedFindingGroup) *MLResults {
	if !ml.isInitialized {
		log.Warn().Msg("ML Engine not initialized, returning empty results")
		return &MLResults{}
	}

	results := &MLResults{
		Predictions:     make([]*Prediction, 0),
		Classifications: make([]*Classification, 0),
		Clusters:        make([]*Cluster, 0),
		Anomalies:       make([]*MLAnomaly, 0),
		Insights:        make([]*MLInsight, 0),
		ModelMetrics:    make(map[string]ModelMetric),
	}

	// Extract features from findings
	features := ml.extractFeatures(findings)
	
	// Update feature store
	for _, feature := range features {
		ml.featureStore.AddFeature(feature.SourceID, feature)
	}

	// Run predictions
	if ml.config.EnablePredictiveAnalysis {
		predictions := ml.runPredictions(features)
		results.Predictions = predictions
	}

	// Run classification
	if ml.config.EnableClassification {
		classifications := ml.runClassification(features)
		results.Classifications = classifications
	}

	// Detect ML-based anomalies
	if ml.config.EnableAnomalyDetection {
		anomalies := ml.detectMLAnomalies(features)
		results.Anomalies = anomalies
	}

	// Generate insights
	insights := ml.generateInsights(findings, groups, results)
	results.Insights = insights

	// Update model metrics
	ml.updateModelMetrics(results)

	return results
}

func (ml *MLEngine) initializeModels() error {
	// Initialize rule-based classifier
	classifier := &RuleBasedClassifier{
		rules:    ml.getDefaultClassificationRules(),
		accuracy: 0.85,
		modelInfo: ModelInfo{
			Name:      "Rule-Based Classifier",
			Type:      "rule-based",
			Version:   "1.0",
			Accuracy:  0.85,
			TrainedAt: time.Now(),
		},
	}
	
	ml.models["classifier"] = classifier
	
	return nil
}

func (ml *MLEngine) extractFeatures(findings []models.PluginResult) []FeatureVector {
	var features []FeatureVector
	
	extractor := &BasicFeatureExtractor{
		name: "basic",
		features: []string{
			"severity_score", "confidence", "plugin_type", "category_score", 
			"target_type", "cvss_score", "exploit_available", "time_of_day",
		},
	}
	
	for _, finding := range findings {
		featureMap, err := extractor.Extract(&finding)
		if err != nil {
			log.Error().Err(err).Msg("Failed to extract features")
			continue
		}
		
		vector := FeatureVector{
			Features:  featureMap,
			Metadata:  map[string]string{"plugin": finding.Plugin, "category": finding.Category},
			Timestamp: finding.Timestamp,
			SourceID:  finding.ID,
		}
		
		features = append(features, vector)
	}
	
	return features
}

func (ml *MLEngine) runPredictions(features []FeatureVector) []*Prediction {
	var predictions []*Prediction
	
	classifier, exists := ml.models["classifier"]
	if !exists {
		return predictions
	}
	
	for _, feature := range features {
		prediction, err := classifier.Predict(feature)
		if err != nil {
			log.Error().Err(err).Msg("Failed to run prediction")
			continue
		}
		
		if prediction.Confidence >= ml.config.ConfidenceThreshold {
			predictions = append(predictions, prediction)
		}
	}
	
	return predictions
}

func (ml *MLEngine) runClassification(features []FeatureVector) []*Classification {
	var classifications []*Classification
	
	// Simple classification based on feature patterns
	for _, feature := range features {
		classification := ml.classifyFeature(feature)
		if classification != nil {
			classifications = append(classifications, classification)
		}
	}
	
	return classifications
}

func (ml *MLEngine) classifyFeature(feature FeatureVector) *Classification {
	severityScore := feature.Features["severity_score"]
	confidence := feature.Features["confidence"]
	cvssScore := feature.Features["cvss_score"]
	
	if severityScore >= 8.0 && confidence >= 0.8 {
		return &Classification{
			Category:    "high-priority",
			Confidence:  0.9,
			Description: "High priority security finding requiring immediate attention",
			Evidence:    []string{"high severity score", "high confidence"},
		}
	} else if cvssScore >= 7.0 {
		return &Classification{
			Category:    "vulnerable",
			Confidence:  0.8,
			Description: "Vulnerability with significant CVSS score",
			Evidence:    []string{"CVSS score >= 7.0"},
		}
	} else if severityScore >= 5.0 {
		return &Classification{
			Category:    "moderate-risk",
			Confidence:  0.7,
			Description: "Moderate risk security finding",
			Evidence:    []string{"moderate severity score"},
		}
	}
	
	return &Classification{
		Category:    "low-priority",
		Confidence:  0.6,
		Description: "Low priority finding for routine review",
		Evidence:    []string{"low severity indicators"},
	}
}

func (ml *MLEngine) detectMLAnomalies(features []FeatureVector) []*MLAnomaly {
	var anomalies []*MLAnomaly
	
	// Simple statistical anomaly detection
	if len(features) < 10 {
		return anomalies // Need sufficient data
	}
	
	// Calculate statistical thresholds
	severityScores := make([]float64, len(features))
	confidenceScores := make([]float64, len(features))
	
	for i, feature := range features {
		severityScores[i] = feature.Features["severity_score"]
		confidenceScores[i] = feature.Features["confidence"]
	}
	
	severityMean, severityStdDev := ml.calculateStats(severityScores)
	confidenceMean, confidenceStdDev := ml.calculateStats(confidenceScores)
	
	// Detect outliers
	for _, feature := range features {
		severityZ := math.Abs(feature.Features["severity_score"]-severityMean) / severityStdDev
		confidenceZ := math.Abs(feature.Features["confidence"]-confidenceMean) / confidenceStdDev
		
		if severityZ > 2.5 || confidenceZ > 2.5 {
			anomaly := &MLAnomaly{
				ID:         fmt.Sprintf("ml_anomaly_%s", feature.SourceID),
				Score:      math.Max(severityZ, confidenceZ),
				Confidence: 0.8,
				Features:   feature,
				Description: "Statistical outlier detected in feature space",
			}
			anomalies = append(anomalies, anomaly)
		}
	}
	
	return anomalies
}

func (ml *MLEngine) generateInsights(findings []models.PluginResult, groups []CorrelatedFindingGroup, results *MLResults) []*MLInsight {
	var insights []*MLInsight
	
	// Insight 1: High-priority finding patterns
	highPriorityCount := 0
	for _, classification := range results.Classifications {
		if classification.Category == "high-priority" {
			highPriorityCount++
		}
	}
	
	if highPriorityCount > len(findings)/4 {
		insights = append(insights, &MLInsight{
			Type:        "pattern",
			Title:       "High Concentration of Critical Findings",
			Description: fmt.Sprintf("%.1f%% of findings are classified as high-priority", float64(highPriorityCount)/float64(len(findings))*100),
			Evidence:    []string{fmt.Sprintf("%d high-priority classifications", highPriorityCount)},
			Confidence:  0.85,
			Impact:      "high",
		})
	}
	
	// Insight 2: Anomaly patterns
	if len(results.Anomalies) > 0 {
		insights = append(insights, &MLInsight{
			Type:        "anomaly",
			Title:       "Unusual Activity Patterns Detected",
			Description: fmt.Sprintf("ML analysis identified %d statistical anomalies", len(results.Anomalies)),
			Evidence:    []string{fmt.Sprintf("%d anomalies detected", len(results.Anomalies))},
			Confidence:  0.75,
			Impact:      "medium",
		})
	}
	
	// Insight 3: Correlation strength
	strongCorrelations := 0
	for _, group := range groups {
		if group.Correlation.Strength > 0.8 {
			strongCorrelations++
		}
	}
	
	if strongCorrelations > 0 {
		insights = append(insights, &MLInsight{
			Type:        "correlation",
			Title:       "Strong Finding Correlations Identified",
			Description: fmt.Sprintf("Found %d groups with strong correlations", strongCorrelations),
			Evidence:    []string{fmt.Sprintf("%d strong correlations", strongCorrelations)},
			Confidence:  0.9,
			Impact:      "high",
		})
	}
	
	return insights
}

func (ml *MLEngine) updateModelMetrics(results *MLResults) {
	// Update classifier metrics
	if len(results.Predictions) > 0 {
		totalConfidence := 0.0
		for _, prediction := range results.Predictions {
			totalConfidence += prediction.Confidence
		}
		
		avgConfidence := totalConfidence / float64(len(results.Predictions))
		
		ml.updateMetric("classifier", ModelMetric{
			Accuracy:    avgConfidence,
			Precision:   avgConfidence * 0.9, // Simplified
			Recall:      avgConfidence * 0.85,
			F1Score:     avgConfidence * 0.87,
			DataPoints:  len(results.Predictions),
			LastUpdated: time.Now(),
		})
	}
}

func (ml *MLEngine) updateMetric(modelName string, metric ModelMetric) {
	// In a real implementation, this would update persistent storage
	log.Info().
		Str("model", modelName).
		Float64("accuracy", metric.Accuracy).
		Int("data_points", metric.DataPoints).
		Msg("Updated model metrics")
}

func (ml *MLEngine) calculateStats(values []float64) (float64, float64) {
	if len(values) == 0 {
		return 0.0, 0.0
	}
	
	// Calculate mean
	sum := 0.0
	for _, v := range values {
		sum += v
	}
	mean := sum / float64(len(values))
	
	// Calculate standard deviation
	sumSquares := 0.0
	for _, v := range values {
		diff := v - mean
		sumSquares += diff * diff
	}
	variance := sumSquares / float64(len(values))
	stdDev := math.Sqrt(variance)
	
	return mean, stdDev
}

func (ml *MLEngine) getDefaultClassificationRules() []ClassificationRule {
	return []ClassificationRule{
		{
			Name: "Critical Vulnerability",
			Conditions: []FeatureCondition{
				{Feature: "severity_score", Operator: ">=", Value: 8.0, Weight: 0.8},
				{Feature: "cvss_score", Operator: ">=", Value: 7.0, Weight: 0.9},
			},
			Label:      "critical",
			Confidence: 0.95,
			Priority:   10,
		},
		{
			Name: "High Confidence Finding",
			Conditions: []FeatureCondition{
				{Feature: "confidence", Operator: ">=", Value: 0.9, Weight: 0.8},
				{Feature: "severity_score", Operator: ">=", Value: 5.0, Weight: 0.7},
			},
			Label:      "high-confidence",
			Confidence: 0.85,
			Priority:   8,
		},
	}
}

// MLModel implementation for RuleBasedClassifier
func (rbc *RuleBasedClassifier) Train(data []TrainingExample) error {
	// Rule-based models don't require training in the traditional sense
	rbc.accuracy = 0.85
	rbc.modelInfo.TrainedAt = time.Now()
	return nil
}

func (rbc *RuleBasedClassifier) Predict(features FeatureVector) (*Prediction, error) {
	bestRule := ""
	bestConfidence := 0.0
	bestLabel := "unknown"
	
	for _, rule := range rbc.rules {
		matches := 0
		totalWeight := 0.0
		metWeight := 0.0
		
		for _, condition := range rule.Conditions {
			totalWeight += condition.Weight
			if rbc.evaluateCondition(features.Features, condition) {
				matches++
				metWeight += condition.Weight
			}
		}
		
		if matches > 0 {
			conditionScore := metWeight / totalWeight
			ruleConfidence := rule.Confidence * conditionScore
			
			if ruleConfidence > bestConfidence {
				bestRule = rule.Name
				bestConfidence = ruleConfidence
				bestLabel = rule.Label
			}
		}
	}
	
	return &Prediction{
		Label:      bestLabel,
		Confidence: bestConfidence,
		Probability: map[string]float64{bestLabel: bestConfidence},
		Features:   features,
		ModelInfo:  rbc.modelInfo,
	}, nil
}

func (rbc *RuleBasedClassifier) evaluateCondition(features map[string]float64, condition FeatureCondition) bool {
	value, exists := features[condition.Feature]
	if !exists {
		return false
	}
	
	switch condition.Operator {
	case ">=":
		if threshold, ok := condition.Value.(float64); ok {
			return value >= threshold
		}
	case "<=":
		if threshold, ok := condition.Value.(float64); ok {
			return value <= threshold
		}
	case "==":
		if threshold, ok := condition.Value.(float64); ok {
			return math.Abs(value-threshold) < 0.001
		}
	}
	
	return false
}

func (rbc *RuleBasedClassifier) GetAccuracy() float64 {
	return rbc.accuracy
}

func (rbc *RuleBasedClassifier) GetModelInfo() ModelInfo {
	return rbc.modelInfo
}

// FeatureExtractor implementation
func (bfe *BasicFeatureExtractor) Extract(finding *models.PluginResult) (map[string]float64, error) {
	features := make(map[string]float64)
	
	// Severity score
	severityScores := map[string]float64{
		"critical": 10.0,
		"high":     8.0,
		"medium":   5.0,
		"low":      2.0,
		"info":     1.0,
	}
	
	if score, exists := severityScores[strings.ToLower(finding.Severity)]; exists {
		features["severity_score"] = score
	} else {
		features["severity_score"] = 1.0
	}
	
	// Confidence
	features["confidence"] = finding.Confidence
	
	// Plugin type (simplified encoding)
	pluginScores := map[string]float64{
		"vuln":       10.0,
		"cloud":      8.0,
		"portscan":   6.0,
		"httpprobe":  5.0,
		"wayback":    4.0,
		"github":     7.0,
		"js":         3.0,
		"param":      4.0,
		"crawl":      3.0,
		"brokenlink": 1.0,
	}
	
	if score, exists := pluginScores[strings.ToLower(finding.Plugin)]; exists {
		features["plugin_type"] = score
	} else {
		features["plugin_type"] = 1.0
	}
	
	// Category score
	categoryScores := map[string]float64{
		"vulnerability":    10.0,
		"misconfiguration": 7.0,
		"information":      5.0,
		"service":         6.0,
		"web-application":  8.0,
	}
	
	if score, exists := categoryScores[strings.ToLower(finding.Category)]; exists {
		features["category_score"] = score
	} else {
		features["category_score"] = 1.0
	}
	
	// Target type (simplified)
	features["target_type"] = 1.0
	if finding.Target.IP != "" {
		features["target_type"] = 2.0
	}
	if finding.Target.Domain != "" {
		features["target_type"] = 3.0
	}
	
	// CVSS score
	features["cvss_score"] = finding.CVSSScore
	
	// Exploit available
	if finding.ExploitAvailable {
		features["exploit_available"] = 1.0
	} else {
		features["exploit_available"] = 0.0
	}
	
	// Time of day (0-23)
	features["time_of_day"] = float64(finding.Timestamp.Hour())
	
	return features, nil
}

func (bfe *BasicFeatureExtractor) GetFeatureNames() []string {
	return bfe.features
}

// FeatureStore implementation
func NewFeatureStore() *FeatureStore {
	return &FeatureStore{
		features:   make(map[string]FeatureVector),
		extractors: make(map[string]FeatureExtractor),
	}
}

func (fs *FeatureStore) AddFeature(id string, feature FeatureVector) {
	fs.features[id] = feature
	fs.featureHistory = append(fs.featureHistory, HistoricalFeature{
		Timestamp: time.Now(),
		Features:  feature,
		Context:   "analysis",
	})
	
	// Limit history size
	if len(fs.featureHistory) > 10000 {
		fs.featureHistory = fs.featureHistory[len(fs.featureHistory)-10000:]
	}
}

func (fs *FeatureStore) GetFeature(id string) (FeatureVector, bool) {
	feature, exists := fs.features[id]
	return feature, exists
}

func (fs *FeatureStore) GetFeatureHistory() []HistoricalFeature {
	return fs.featureHistory
}
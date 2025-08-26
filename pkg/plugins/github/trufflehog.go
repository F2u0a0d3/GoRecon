package github

import (
	"bufio"
	"context"
	"encoding/json"
	"fmt"
	"path/filepath"
	"strings"
	"time"

	"github.com/f2u0a0d3/GoRecon/pkg/plugins/base"
	"github.com/f2u0a0d3/GoRecon/pkg/core"
	"github.com/f2u0a0d3/GoRecon/pkg/models"
)

type TrufflehogPlugin struct {
	base.BaseAdapter
	config *TrufflehogConfig
}

type TrufflehogConfig struct {
	MaxDepth      int
	IncludeFiles  string
	ExcludeFiles  string
	Entropy       bool
	Regex         bool
	OutputFormat  string
	Rules         string
	Timeout       int
}

type TrufflehogSecret struct {
	SourceMetadata struct {
		Data struct {
			Git struct {
				Commit     string `json:"commit"`
				File       string `json:"file"`
				Email      string `json:"email"`
				Repository string `json:"repository"`
				Timestamp  string `json:"timestamp"`
				Line       int    `json:"line"`
			} `json:"git"`
		} `json:"data"`
	} `json:"SourceMetadata"`
	SourceID   int    `json:"SourceID"`
	SourceType int    `json:"SourceType"`
	SourceName string `json:"SourceName"`
	DetectorType int `json:"DetectorType"`
	DetectorName string `json:"DetectorName"`
	DecoderName string `json:"DecoderName"`
	Verified    bool   `json:"Verified"`
	Raw         string `json:"Raw"`
	Redacted    string `json:"Redacted"`
	ExtraData   map[string]interface{} `json:"ExtraData"`
}

func NewTrufflehogPlugin() *TrufflehogPlugin {
	return &TrufflehogPlugin{
		BaseAdapter: base.BaseAdapter{
			PluginName:        "trufflehog",
			PluginVersion:     "1.0.0",
			PluginDescription: "Secret detection in Git repositories and filesystems using TruffleHog",
			PluginAuthor:     "GoRecon Team",
			SupportedTargets: []string{"url", "path"},
		},
		config: &TrufflehogConfig{
			MaxDepth:     100,
			IncludeFiles: "",
			ExcludeFiles: "",
			Entropy:      true,
			Regex:        true,
			OutputFormat: "json",
			Rules:        "",
			Timeout:      300,
		},
	}
}

func (t *TrufflehogPlugin) SetConfig(configMap map[string]interface{}) error {
	if maxDepth, ok := configMap["max_depth"].(int); ok && maxDepth > 0 && maxDepth <= 10000 {
		t.config.MaxDepth = maxDepth
	}
	if includeFiles, ok := configMap["include_files"].(string); ok {
		t.config.IncludeFiles = includeFiles
	}
	if excludeFiles, ok := configMap["exclude_files"].(string); ok {
		t.config.ExcludeFiles = excludeFiles
	}
	if entropy, ok := configMap["entropy"].(bool); ok {
		t.config.Entropy = entropy
	}
	if regex, ok := configMap["regex"].(bool); ok {
		t.config.Regex = regex
	}
	if outputFormat, ok := configMap["output_format"].(string); ok {
		validFormats := map[string]bool{"json": true, "yaml": true}
		if validFormats[outputFormat] {
			t.config.OutputFormat = outputFormat
		}
	}
	if rules, ok := configMap["rules"].(string); ok {
		t.config.Rules = rules
	}
	if timeout, ok := configMap["timeout"].(int); ok && timeout > 0 && timeout <= 3600 {
		t.config.Timeout = timeout
	}
	return nil
}

func (t *TrufflehogPlugin) Execute(ctx context.Context, target models.Target, sharedCtx *core.SharedContext) (*models.PluginResult, error) {
	targetStr := t.getTargetString(target)
	if targetStr == "" {
		return nil, fmt.Errorf("invalid target for trufflehog scan")
	}

	var args []string
	var binaryPath string

	if t.isGitRepository(targetStr) {
		binaryPath = "/usr/local/bin/trufflehog"
		args = t.buildTrufflehogV3Args(targetStr)
	} else {
		binaryPath = filepath.Join("/home/f2u0a0d3/.local/bin", "trufflehog")
		args = t.buildTrufflehogPythonArgs(targetStr)
	}

	output, err := t.ExecuteCommand(ctx, binaryPath, args, time.Duration(t.config.Timeout)*time.Second)
	if err != nil {
		return nil, fmt.Errorf("trufflehog execution failed: %w", err)
	}

	result, err := t.parseTrufflehogOutput(output, target)
	if err != nil {
		return nil, fmt.Errorf("failed to parse trufflehog output: %w", err)
	}

	t.populateSharedContext(result, sharedCtx)

	return result, nil
}

func (t *TrufflehogPlugin) getTargetString(target models.Target) string {
	switch target.GetType() {
	case "url":
		return target.GetURL()
	case "path":
		return target.GetPath()
	default:
		return ""
	}
}

func (t *TrufflehogPlugin) isGitRepository(target string) bool {
	return strings.Contains(target, ".git") || strings.HasPrefix(target, "https://github.com") || strings.HasPrefix(target, "git@")
}

func (t *TrufflehogPlugin) buildTrufflehogV3Args(target string) []string {
	args := []string{
		"git",
		target,
		"--json",
	}

	if t.config.MaxDepth > 0 {
		args = append(args, "--max-depth", fmt.Sprintf("%d", t.config.MaxDepth))
	}

	if t.config.IncludeFiles != "" {
		args = append(args, "--include-paths", t.config.IncludeFiles)
	}

	if t.config.ExcludeFiles != "" {
		args = append(args, "--exclude-paths", t.config.ExcludeFiles)
	}

	return args
}

func (t *TrufflehogPlugin) buildTrufflehogPythonArgs(target string) []string {
	args := []string{
		"--repo", target,
		"--json",
	}

	if t.config.MaxDepth > 0 {
		args = append(args, "--max_depth", fmt.Sprintf("%d", t.config.MaxDepth))
	}

	if t.config.IncludeFiles != "" {
		args = append(args, "--include_paths", t.config.IncludeFiles)
	}

	if t.config.ExcludeFiles != "" {
		args = append(args, "--exclude_paths", t.config.ExcludeFiles)
	}

	if !t.config.Entropy {
		args = append(args, "--entropy", "False")
	}

	if !t.config.Regex {
		args = append(args, "--regex")
	}

	if t.config.Rules != "" {
		args = append(args, "--rules", t.config.Rules)
	}

	return args
}

func (t *TrufflehogPlugin) parseTrufflehogOutput(output string, target models.Target) (*models.PluginResult, error) {
	result := &models.PluginResult{
		PluginName: t.PluginName,
		Target:     target,
		Status:     models.StatusSuccess,
		Timestamp:  time.Now(),
		Results:    make(map[string]interface{}),
		RawOutput:  output,
	}

	if strings.TrimSpace(output) == "" {
		result.Status = models.StatusError
		result.Error = "empty trufflehog output"
		return result, nil
	}

	secrets := make([]map[string]interface{}, 0)
	secretStats := make(map[string]interface{})
	riskMetrics := make(map[string]interface{})

	scanner := bufio.NewScanner(strings.NewReader(output))
	detectorCounts := make(map[string]int)
	verifiedCount := 0
	totalSecrets := 0

	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line == "" || !strings.HasPrefix(line, "{") {
			continue
		}

		select {
		case <-ctx.Done():
			return result, ctx.Err()
		default:
		}

		var secret TrufflehogSecret
		if err := json.Unmarshal([]byte(line), &secret); err != nil {
			secretInfo := t.parsePlainTextSecret(line)
			if secretInfo != nil {
				secrets = append(secrets, secretInfo)
				totalSecrets++
			}
			continue
		}

		secretInfo := map[string]interface{}{
			"detector_name": secret.DetectorName,
			"verified":      secret.Verified,
			"raw":           secret.Raw,
			"redacted":      secret.Redacted,
			"source_type":   secret.SourceName,
		}

		if secret.SourceMetadata.Data.Git.File != "" {
			secretInfo["file"] = secret.SourceMetadata.Data.Git.File
			secretInfo["commit"] = secret.SourceMetadata.Data.Git.Commit
			secretInfo["line"] = secret.SourceMetadata.Data.Git.Line
			secretInfo["repository"] = secret.SourceMetadata.Data.Git.Repository
		}

		if len(secret.ExtraData) > 0 {
			secretInfo["extra_data"] = secret.ExtraData
		}

		secrets = append(secrets, secretInfo)
		detectorCounts[secret.DetectorName]++
		
		if secret.Verified {
			verifiedCount++
		}
		totalSecrets++
	}

	secretStats["total_secrets"] = totalSecrets
	secretStats["verified_secrets"] = verifiedCount
	secretStats["unverified_secrets"] = totalSecrets - verifiedCount
	secretStats["detector_breakdown"] = detectorCounts
	secretStats["unique_detectors"] = len(detectorCounts)

	riskScore := t.calculateRiskScore(secrets, totalSecrets, verifiedCount)
	riskMetrics["risk_score"] = riskScore
	riskMetrics["risk_level"] = t.getRiskLevel(riskScore)
	riskMetrics["critical_secrets"] = t.countCriticalSecrets(secrets)

	result.Results["secrets"] = secrets
	result.Results["secret_stats"] = secretStats
	result.Results["risk_metrics"] = riskMetrics

	return result, nil
}

func (t *TrufflehogPlugin) parsePlainTextSecret(line string) map[string]interface{} {
	if strings.Contains(line, "Reason:") && strings.Contains(line, "Date:") {
		parts := strings.Split(line, "~")
		if len(parts) >= 3 {
			return map[string]interface{}{
				"detector_name": "entropy_based",
				"verified":      false,
				"content":       strings.TrimSpace(parts[0]),
				"reason":        strings.TrimSpace(parts[1]),
				"date":          strings.TrimSpace(parts[2]),
			}
		}
	}
	return nil
}

func (t *TrufflehogPlugin) calculateRiskScore(secrets []map[string]interface{}, total, verified int) float64 {
	if total == 0 {
		return 0.0
	}

	baseScore := float64(total) * 2.0
	verifiedBonus := float64(verified) * 3.0
	criticalBonus := float64(t.countCriticalSecrets(secrets)) * 2.0

	totalScore := baseScore + verifiedBonus + criticalBonus
	maxPossibleScore := float64(total) * 7.0

	if maxPossibleScore > 0 {
		normalizedScore := (totalScore / maxPossibleScore) * 10.0
		if normalizedScore > 10.0 {
			return 10.0
		}
		return normalizedScore
	}

	return 0.0
}

func (t *TrufflehogPlugin) getRiskLevel(score float64) string {
	if score >= 8.0 {
		return "CRITICAL"
	} else if score >= 6.0 {
		return "HIGH"
	} else if score >= 4.0 {
		return "MEDIUM"
	} else if score >= 2.0 {
		return "LOW"
	}
	return "INFO"
}

func (t *TrufflehogPlugin) countCriticalSecrets(secrets []map[string]interface{}) int {
	criticalDetectors := map[string]bool{
		"AWS":                 true,
		"AWSSecret":          true,
		"Github":             true,
		"Slack":              true,
		"Stripe":             true,
		"JWT":                true,
		"PrivateKey":         true,
		"GoogleAPI":          true,
		"SendGrid":           true,
		"Mailgun":            true,
		"Twilio":             true,
		"Square":             true,
		"PayPal":             true,
	}

	count := 0
	for _, secret := range secrets {
		if detectorName, ok := secret["detector_name"].(string); ok {
			if criticalDetectors[detectorName] {
				count++
			}
		}
	}

	return count
}

func (t *TrufflehogPlugin) populateSharedContext(result *models.PluginResult, sharedCtx *core.SharedContext) {
	if secrets, ok := result.Results["secrets"].([]map[string]interface{}); ok {
		for _, secret := range secrets {
			if detectorName, ok := secret["detector_name"].(string); ok {
				sharedCtx.AddTechnology(detectorName)
			}

			if file, ok := secret["file"].(string); ok && file != "" {
				sharedCtx.AddPath(file)
			}
		}
	}

	if riskMetrics, ok := result.Results["risk_metrics"].(map[string]interface{}); ok {
		if riskScore, ok := riskMetrics["risk_score"].(float64); ok && riskScore > 5.0 {
			sharedCtx.AddVulnerability("High-risk secrets detected")
		}
	}
}

func (t *TrufflehogPlugin) Cleanup() error {
	return nil
}

func (t *TrufflehogPlugin) ValidateConfig() error {
	if t.config.MaxDepth < 1 || t.config.MaxDepth > 10000 {
		return fmt.Errorf("max_depth must be between 1 and 10000")
	}
	if t.config.Timeout < 1 || t.config.Timeout > 3600 {
		return fmt.Errorf("timeout must be between 1 and 3600 seconds")
	}
	return nil
}
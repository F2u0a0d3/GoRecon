package github

import (
	"bufio"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"regexp"
	"strings"
	"time"

	"github.com/f2u0a0d3/GoRecon/pkg/plugins/base"
	"github.com/f2u0a0d3/GoRecon/pkg/core"
	"github.com/f2u0a0d3/GoRecon/pkg/models"
)

type GitHoundPlugin struct {
	base.BaseAdapter
	config *GitHoundConfig
}

type GitHoundConfig struct {
	Keywords      []string
	Organization  string
	User          string
	Repositories  []string
	MaxPages      int
	Timeout       int
	IncludeForked bool
	FileTypes     []string
	ExcludeTests  bool
}

type GitHubSearchResult struct {
	TotalCount        int                    `json:"total_count"`
	IncompleteResults bool                   `json:"incomplete_results"`
	Items             []GitHubCodeSearchItem `json:"items"`
}

type GitHubCodeSearchItem struct {
	Name        string              `json:"name"`
	Path        string              `json:"path"`
	SHA         string              `json:"sha"`
	URL         string              `json:"url"`
	GitURL      string              `json:"git_url"`
	HTMLURL     string              `json:"html_url"`
	Repository  GitHubRepository    `json:"repository"`
	Score       float64             `json:"score"`
	FileContent string              `json:"-"`
}

type GitHubRepository struct {
	ID       int    `json:"id"`
	Name     string `json:"name"`
	FullName string `json:"full_name"`
	Owner    GitHubOwner `json:"owner"`
	Private  bool   `json:"private"`
	HTMLURL  string `json:"html_url"`
	GitURL   string `json:"git_url"`
	CloneURL string `json:"clone_url"`
	Language string `json:"language"`
}

type GitHubOwner struct {
	Login   string `json:"login"`
	ID      int    `json:"id"`
	HTMLURL string `json:"html_url"`
	Type    string `json:"type"`
}

func NewGitHoundPlugin() *GitHoundPlugin {
	return &GitHoundPlugin{
		BaseAdapter: base.BaseAdapter{
			PluginName:        "git-hound",
			PluginVersion:     "1.0.0",
			PluginDescription: "GitHub reconnaissance and code search for sensitive information",
			PluginAuthor:     "GoRecon Team",
			SupportedTargets: []string{"organization", "user", "repository"},
		},
		config: &GitHoundConfig{
			Keywords: []string{
				"password", "passwd", "pwd", "secret", "token", "api_key", "apikey",
				"private_key", "ssh_key", "access_token", "auth_token", "oauth",
				"credential", "key", "login", "database_url", "db_url", "connection_string",
				"aws_access_key", "aws_secret", "s3_bucket", "stripe_key", "github_token",
			},
			MaxPages:      5,
			Timeout:       300,
			IncludeForked: false,
			FileTypes:     []string{"js", "json", "yaml", "yml", "xml", "config", "env", "ini", "properties", "conf"},
			ExcludeTests:  true,
		},
	}
}

func (g *GitHoundPlugin) SetConfig(configMap map[string]interface{}) error {
	if keywords, ok := configMap["keywords"].([]interface{}); ok {
		stringKeywords := make([]string, len(keywords))
		for i, keyword := range keywords {
			if str, ok := keyword.(string); ok {
				stringKeywords[i] = str
			}
		}
		g.config.Keywords = stringKeywords
	}
	if organization, ok := configMap["organization"].(string); ok {
		g.config.Organization = organization
	}
	if user, ok := configMap["user"].(string); ok {
		g.config.User = user
	}
	if repositories, ok := configMap["repositories"].([]interface{}); ok {
		stringRepos := make([]string, len(repositories))
		for i, repo := range repositories {
			if str, ok := repo.(string); ok {
				stringRepos[i] = str
			}
		}
		g.config.Repositories = stringRepos
	}
	if maxPages, ok := configMap["max_pages"].(int); ok && maxPages > 0 && maxPages <= 100 {
		g.config.MaxPages = maxPages
	}
	if timeout, ok := configMap["timeout"].(int); ok && timeout > 0 && timeout <= 3600 {
		g.config.Timeout = timeout
	}
	if includeForked, ok := configMap["include_forked"].(bool); ok {
		g.config.IncludeForked = includeForked
	}
	if fileTypes, ok := configMap["file_types"].([]interface{}); ok {
		stringFileTypes := make([]string, len(fileTypes))
		for i, fileType := range fileTypes {
			if str, ok := fileType.(string); ok {
				stringFileTypes[i] = str
			}
		}
		g.config.FileTypes = stringFileTypes
	}
	if excludeTests, ok := configMap["exclude_tests"].(bool); ok {
		g.config.ExcludeTests = excludeTests
	}
	return nil
}

func (g *GitHoundPlugin) Execute(ctx context.Context, target models.Target, sharedCtx *core.SharedContext) (*models.PluginResult, error) {
	targetStr := g.getTargetString(target)
	if targetStr == "" {
		return nil, fmt.Errorf("invalid target for git-hound scan")
	}

	client := &http.Client{
		Timeout: time.Duration(g.config.Timeout) * time.Second,
	}

	results := make([]GitHubCodeSearchItem, 0)
	
	for _, keyword := range g.config.Keywords {
		select {
		case <-ctx.Done():
			return nil, ctx.Err()
		default:
		}

		searchResults, err := g.searchGitHubCode(ctx, client, targetStr, keyword)
		if err != nil {
			continue
		}
		results = append(results, searchResults...)

		time.Sleep(time.Second)
	}

	result, err := g.parseGitHoundResults(results, target)
	if err != nil {
		return nil, fmt.Errorf("failed to parse git-hound results: %w", err)
	}

	g.populateSharedContext(result, sharedCtx)

	return result, nil
}

func (g *GitHoundPlugin) getTargetString(target models.Target) string {
	switch target.GetType() {
	case "organization":
		return target.GetOrganization()
	case "user":
		return target.GetUser()
	case "repository":
		return target.GetRepository()
	default:
		return ""
	}
}

func (g *GitHoundPlugin) searchGitHubCode(ctx context.Context, client *http.Client, target, keyword string) ([]GitHubCodeSearchItem, error) {
	results := make([]GitHubCodeSearchItem, 0)
	
	for page := 1; page <= g.config.MaxPages; page++ {
		select {
		case <-ctx.Done():
			return results, ctx.Err()
		default:
		}

		query := g.buildSearchQuery(target, keyword)
		url := fmt.Sprintf("https://api.github.com/search/code?q=%s&page=%d&per_page=30", query, page)

		req, err := http.NewRequestWithContext(ctx, "GET", url, nil)
		if err != nil {
			continue
		}

		req.Header.Set("Accept", "application/vnd.github.v3+json")
		req.Header.Set("User-Agent", "GoRecon-GitHound/1.0")

		resp, err := client.Do(req)
		if err != nil {
			continue
		}

		if resp.StatusCode != http.StatusOK {
			resp.Body.Close()
			if resp.StatusCode == 429 {
				time.Sleep(time.Minute)
				page--
				continue
			}
			break
		}

		body, err := io.ReadAll(resp.Body)
		resp.Body.Close()
		if err != nil {
			continue
		}

		var searchResult GitHubSearchResult
		if err := json.Unmarshal(body, &searchResult); err != nil {
			continue
		}

		for _, item := range searchResult.Items {
			if g.shouldIncludeResult(item) {
				results = append(results, item)
			}
		}

		if len(searchResult.Items) < 30 {
			break
		}

		time.Sleep(2 * time.Second)
	}

	return results, nil
}

func (g *GitHoundPlugin) buildSearchQuery(target, keyword string) string {
	query := fmt.Sprintf("%s in:file", keyword)
	
	if g.config.Organization != "" {
		query += fmt.Sprintf(" org:%s", g.config.Organization)
	} else if g.config.User != "" {
		query += fmt.Sprintf(" user:%s", g.config.User)
	} else {
		query += fmt.Sprintf(" user:%s", target)
	}

	if !g.config.IncludeForked {
		query += " fork:false"
	}

	if len(g.config.FileTypes) > 0 {
		extensions := strings.Join(g.config.FileTypes, " extension:")
		query += " extension:" + extensions
	}

	if g.config.ExcludeTests {
		query += " -path:test -path:tests -path:spec -path:__tests__"
	}

	return query
}

func (g *GitHoundPlugin) shouldIncludeResult(item GitHubCodeSearchItem) bool {
	if g.config.ExcludeTests {
		testPatterns := []string{
			"test", "tests", "spec", "__tests__", "_test", ".test",
			"mock", "mocks", "fixture", "fixtures", "stub", "stubs",
		}
		
		for _, pattern := range testPatterns {
			if strings.Contains(strings.ToLower(item.Path), pattern) {
				return false
			}
		}
	}

	if len(g.config.Repositories) > 0 {
		found := false
		for _, repo := range g.config.Repositories {
			if item.Repository.FullName == repo {
				found = true
				break
			}
		}
		if !found {
			return false
		}
	}

	return true
}

func (g *GitHoundPlugin) parseGitHoundResults(items []GitHubCodeSearchItem, target models.Target) (*models.PluginResult, error) {
	result := &models.PluginResult{
		PluginName: g.PluginName,
		Target:     target,
		Status:     models.StatusSuccess,
		Timestamp:  time.Now(),
		Results:    make(map[string]interface{}),
	}

	findings := make([]map[string]interface{}, 0)
	repoStats := make(map[string]int)
	ownerStats := make(map[string]int)
	languageStats := make(map[string]int)
	fileTypeStats := make(map[string]int)
	sensitivePatterns := make(map[string]int)

	for _, item := range items {
		finding := map[string]interface{}{
			"file_name":       item.Name,
			"file_path":       item.Path,
			"repository":      item.Repository.FullName,
			"owner":           item.Repository.Owner.Login,
			"repo_url":        item.Repository.HTMLURL,
			"file_url":        item.HTMLURL,
			"language":        item.Repository.Language,
			"score":           item.Score,
			"sha":             item.SHA,
		}

		patterns := g.detectSensitivePatterns(item.Name + " " + item.Path)
		if len(patterns) > 0 {
			finding["detected_patterns"] = patterns
			for _, pattern := range patterns {
				sensitivePatterns[pattern]++
			}
		}

		findings = append(findings, finding)

		repoStats[item.Repository.FullName]++
		ownerStats[item.Repository.Owner.Login]++
		
		if item.Repository.Language != "" {
			languageStats[item.Repository.Language]++
		}

		fileExt := g.getFileExtension(item.Name)
		if fileExt != "" {
			fileTypeStats[fileExt]++
		}
	}

	statistics := map[string]interface{}{
		"total_findings":       len(findings),
		"unique_repositories":  len(repoStats),
		"unique_owners":        len(ownerStats),
		"repository_breakdown": repoStats,
		"owner_breakdown":      ownerStats,
		"language_breakdown":   languageStats,
		"file_type_breakdown":  fileTypeStats,
		"pattern_breakdown":    sensitivePatterns,
	}

	riskScore := g.calculateRiskScore(findings, sensitivePatterns)
	riskAssessment := map[string]interface{}{
		"risk_score":        riskScore,
		"risk_level":        g.getRiskLevel(riskScore),
		"high_risk_repos":   g.getHighRiskRepos(repoStats),
		"critical_patterns": g.getCriticalPatterns(sensitivePatterns),
	}

	result.Results["findings"] = findings
	result.Results["statistics"] = statistics
	result.Results["risk_assessment"] = riskAssessment

	return result, nil
}

func (g *GitHoundPlugin) detectSensitivePatterns(content string) []string {
	patterns := []string{}
	content = strings.ToLower(content)

	sensitiveRegexes := map[string]*regexp.Regexp{
		"password":      regexp.MustCompile(`(password|passwd|pwd)`),
		"secret":        regexp.MustCompile(`(secret|secretkey)`),
		"token":         regexp.MustCompile(`(token|auth_?token|access_?token)`),
		"api_key":       regexp.MustCompile(`(api_?key|apikey)`),
		"private_key":   regexp.MustCompile(`(private_?key|privatekey)`),
		"database_url":  regexp.MustCompile(`(database_?url|db_?url|connection_?string)`),
		"aws_key":       regexp.MustCompile(`(aws_?access_?key|aws_?secret)`),
		"oauth":         regexp.MustCompile(`(oauth|client_?secret|client_?id)`),
		"ssh_key":       regexp.MustCompile(`(ssh_?key|id_rsa|id_dsa)`),
		"config":        regexp.MustCompile(`(\.env|config|settings|credentials)`),
	}

	for patternName, regex := range sensitiveRegexes {
		if regex.MatchString(content) {
			patterns = append(patterns, patternName)
		}
	}

	return patterns
}

func (g *GitHoundPlugin) getFileExtension(filename string) string {
	parts := strings.Split(filename, ".")
	if len(parts) > 1 {
		return strings.ToLower(parts[len(parts)-1])
	}
	return ""
}

func (g *GitHoundPlugin) calculateRiskScore(findings []map[string]interface{}, patterns map[string]int) float64 {
	if len(findings) == 0 {
		return 0.0
	}

	baseScore := float64(len(findings)) * 1.0

	criticalPatterns := map[string]float64{
		"password":     3.0,
		"secret":       3.0,
		"private_key":  4.0,
		"aws_key":      4.0,
		"database_url": 3.5,
		"token":        2.5,
		"api_key":      2.5,
		"oauth":        2.0,
		"ssh_key":      3.5,
	}

	patternScore := 0.0
	for pattern, count := range patterns {
		if weight, exists := criticalPatterns[pattern]; exists {
			patternScore += weight * float64(count)
		} else {
			patternScore += 1.0 * float64(count)
		}
	}

	totalScore := baseScore + patternScore
	maxPossibleScore := float64(len(findings)) * 5.0

	if maxPossibleScore > 0 {
		normalizedScore := (totalScore / maxPossibleScore) * 10.0
		if normalizedScore > 10.0 {
			return 10.0
		}
		return normalizedScore
	}

	return 0.0
}

func (g *GitHoundPlugin) getRiskLevel(score float64) string {
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

func (g *GitHoundPlugin) getHighRiskRepos(repoStats map[string]int) []string {
	highRiskRepos := make([]string, 0)
	for repo, count := range repoStats {
		if count >= 5 {
			highRiskRepos = append(highRiskRepos, repo)
		}
	}
	return highRiskRepos
}

func (g *GitHoundPlugin) getCriticalPatterns(patterns map[string]int) []string {
	criticalPatterns := []string{"password", "secret", "private_key", "aws_key", "database_url"}
	found := make([]string, 0)
	
	for _, pattern := range criticalPatterns {
		if count, exists := patterns[pattern]; exists && count > 0 {
			found = append(found, pattern)
		}
	}
	
	return found
}

func (g *GitHoundPlugin) populateSharedContext(result *models.PluginResult, sharedCtx *core.SharedContext) {
	if findings, ok := result.Results["findings"].([]map[string]interface{}); ok {
		for _, finding := range findings {
			if repo, ok := finding["repository"].(string); ok {
				sharedCtx.AddRepository(repo)
			}

			if owner, ok := finding["owner"].(string); ok {
				sharedCtx.AddUser(owner)
			}

			if language, ok := finding["language"].(string); ok && language != "" {
				sharedCtx.AddTechnology(language)
			}

			if patterns, ok := finding["detected_patterns"].([]string); ok {
				for _, pattern := range patterns {
					sharedCtx.AddVulnerability("Sensitive pattern detected: " + pattern)
				}
			}
		}
	}

	if riskAssessment, ok := result.Results["risk_assessment"].(map[string]interface{}); ok {
		if riskScore, ok := riskAssessment["risk_score"].(float64); ok && riskScore > 6.0 {
			sharedCtx.AddVulnerability("High-risk GitHub secrets detected")
		}
	}
}

func (g *GitHoundPlugin) Cleanup() error {
	return nil
}

func (g *GitHoundPlugin) ValidateConfig() error {
	if g.config.MaxPages < 1 || g.config.MaxPages > 100 {
		return fmt.Errorf("max_pages must be between 1 and 100")
	}
	if g.config.Timeout < 1 || g.config.Timeout > 3600 {
		return fmt.Errorf("timeout must be between 1 and 3600 seconds")
	}
	if len(g.config.Keywords) == 0 {
		return fmt.Errorf("at least one keyword must be specified")
	}
	return nil
}
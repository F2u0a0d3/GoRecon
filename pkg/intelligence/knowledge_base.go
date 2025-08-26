package intelligence

import (
	"encoding/json"
	"fmt"
	"strings"
	"sync"
	"time"
)

// KnowledgeBase stores threat intelligence and security knowledge
type KnowledgeBase struct {
	mitreTechniques map[string]*MitreATTACKTechnique
	vulnerabilities map[string]*VulnerabilityInfo
	threatActors    map[string]*ThreatActorProfile
	iocs           map[string]*IOC
	rules          map[string]*DetectionRule
	
	// Metadata
	lastUpdated map[string]time.Time
	version     string
	
	mutex sync.RWMutex
}

// MitreATTACKTechnique represents a MITRE ATT&CK technique
type MitreATTACKTechnique struct {
	ID                string            `json:"id"`
	Name              string            `json:"name"`
	Description       string            `json:"description"`
	Tactics           []string          `json:"tactics"`
	Platforms         []string          `json:"platforms"`
	DataSources       []string          `json:"data_sources"`
	Permissions       []string          `json:"permissions"`
	DefenseBypassed   []string          `json:"defense_bypassed"`
	SubTechniques     []string          `json:"sub_techniques"`
	Mitigations       []string          `json:"mitigations"`
	Detection         string            `json:"detection"`
	References        []Reference       `json:"references"`
	Version           string            `json:"version"`
	CreatedDate       time.Time         `json:"created"`
	ModifiedDate      time.Time         `json:"modified"`
	Metadata          map[string]string `json:"metadata"`
}

// VulnerabilityInfo contains detailed vulnerability information
type VulnerabilityInfo struct {
	CVE           string            `json:"cve"`
	Title         string            `json:"title"`
	Description   string            `json:"description"`
	CVSS          CVSSVector        `json:"cvss"`
	Severity      string            `json:"severity"`
	CWE           []string          `json:"cwe"`
	CPE           []string          `json:"cpe"`
	References    []Reference       `json:"references"`
	ExploitAvailable bool           `json:"exploit_available"`
	ExploitCode   string            `json:"exploit_code"`
	Patches       []Patch           `json:"patches"`
	Workarounds   []string          `json:"workarounds"`
	PublishedDate time.Time         `json:"published"`
	ModifiedDate  time.Time         `json:"modified"`
	Metadata      map[string]string `json:"metadata"`
}

// ThreatActorProfile contains threat actor information
type ThreatActorProfile struct {
	ID            string            `json:"id"`
	Name          string            `json:"name"`
	Aliases       []string          `json:"aliases"`
	Description   string            `json:"description"`
	Attribution   string            `json:"attribution"`
	Motivation    []string          `json:"motivation"`
	Sophistication string           `json:"sophistication"`
	TTPs          []string          `json:"ttps"`
	Targets       []string          `json:"targets"`
	Geography     []string          `json:"geography"`
	KnownCampaigns []Campaign       `json:"known_campaigns"`
	IOCs          []string          `json:"iocs"`
	FirstSeen     time.Time         `json:"first_seen"`
	LastSeen      time.Time         `json:"last_seen"`
	Confidence    float64           `json:"confidence"`
	Metadata      map[string]string `json:"metadata"`
}

// IOC (Indicator of Compromise) represents threat indicators
type IOC struct {
	ID           string            `json:"id"`
	Type         string            `json:"type"` // ip, domain, hash, url, email
	Value        string            `json:"value"`
	Description  string            `json:"description"`
	Confidence   float64           `json:"confidence"`
	Severity     string            `json:"severity"`
	Tags         []string          `json:"tags"`
	ThreatTypes  []string          `json:"threat_types"`
	Sources      []string          `json:"sources"`
	FirstSeen    time.Time         `json:"first_seen"`
	LastSeen     time.Time         `json:"last_seen"`
	Active       bool              `json:"active"`
	FalsePositive bool             `json:"false_positive"`
	Context      map[string]string `json:"context"`
}

// DetectionRule represents a security detection rule
type DetectionRule struct {
	ID          string            `json:"id"`
	Name        string            `json:"name"`
	Description string            `json:"description"`
	Rule        string            `json:"rule"`
	Language    string            `json:"language"` // sigma, yara, snort, etc.
	Category    string            `json:"category"`
	Severity    string            `json:"severity"`
	TTPs        []string          `json:"ttps"`
	Tags        []string          `json:"tags"`
	References  []Reference       `json:"references"`
	Author      string            `json:"author"`
	CreatedDate time.Time         `json:"created"`
	ModifiedDate time.Time        `json:"modified"`
	Enabled     bool              `json:"enabled"`
	Metadata    map[string]string `json:"metadata"`
}

// Reference represents a reference link or citation
type Reference struct {
	URL         string `json:"url"`
	Description string `json:"description"`
	Source      string `json:"source"`
}

// CVSSVector contains CVSS scoring information
type CVSSVector struct {
	Version    string  `json:"version"`
	Vector     string  `json:"vector"`
	BaseScore  float64 `json:"base_score"`
	Severity   string  `json:"severity"`
	Exploitability float64 `json:"exploitability"`
	Impact     float64 `json:"impact"`
}

// Patch represents a security patch
type Patch struct {
	ID          string    `json:"id"`
	Vendor      string    `json:"vendor"`
	Product     string    `json:"product"`
	Version     string    `json:"version"`
	URL         string    `json:"url"`
	ReleaseDate time.Time `json:"release_date"`
}

// Campaign represents a threat campaign
type Campaign struct {
	Name        string    `json:"name"`
	Description string    `json:"description"`
	StartDate   time.Time `json:"start_date"`
	EndDate     time.Time `json:"end_date"`
	Targets     []string  `json:"targets"`
	TTPs        []string  `json:"ttps"`
}

// NewKnowledgeBase creates a new knowledge base
func NewKnowledgeBase() *KnowledgeBase {
	return &KnowledgeBase{
		mitreTechniques: make(map[string]*MitreATTACKTechnique),
		vulnerabilities: make(map[string]*VulnerabilityInfo),
		threatActors:    make(map[string]*ThreatActorProfile),
		iocs:           make(map[string]*IOC),
		rules:          make(map[string]*DetectionRule),
		lastUpdated:    make(map[string]time.Time),
		version:        "1.0.0",
	}
}

// LoadMitreData loads MITRE ATT&CK framework data
func (kb *KnowledgeBase) LoadMitreData() error {
	kb.mutex.Lock()
	defer kb.mutex.Unlock()

	// Load default MITRE ATT&CK techniques
	defaultTechniques := kb.getDefaultMitreTechniques()
	
	for _, technique := range defaultTechniques {
		kb.mitreTechniques[technique.ID] = technique
	}

	kb.lastUpdated["mitre"] = time.Now()
	return nil
}

// GetMitreTechnique retrieves a MITRE technique by ID
func (kb *KnowledgeBase) GetMitreTechnique(techniqueID string) *MitreATTACKTechnique {
	kb.mutex.RLock()
	defer kb.mutex.RUnlock()

	return kb.mitreTechniques[techniqueID]
}

// SearchMitreTechniques searches for MITRE techniques
func (kb *KnowledgeBase) SearchMitreTechniques(query string) []*MitreATTACKTechnique {
	kb.mutex.RLock()
	defer kb.mutex.RUnlock()

	var results []*MitreATTACKTechnique
	queryLower := strings.ToLower(query)

	for _, technique := range kb.mitreTechniques {
		if strings.Contains(strings.ToLower(technique.Name), queryLower) ||
			strings.Contains(strings.ToLower(technique.Description), queryLower) ||
			strings.Contains(strings.ToLower(technique.ID), queryLower) {
			results = append(results, technique)
		}
	}

	return results
}

// GetVulnerability retrieves vulnerability information by CVE
func (kb *KnowledgeBase) GetVulnerability(cve string) *VulnerabilityInfo {
	kb.mutex.RLock()
	defer kb.mutex.RUnlock()

	return kb.vulnerabilities[cve]
}

// AddVulnerability adds vulnerability information to the knowledge base
func (kb *KnowledgeBase) AddVulnerability(vuln *VulnerabilityInfo) {
	kb.mutex.Lock()
	defer kb.mutex.Unlock()

	kb.vulnerabilities[vuln.CVE] = vuln
	kb.lastUpdated["vulnerabilities"] = time.Now()
}

// GetThreatActor retrieves threat actor information
func (kb *KnowledgeBase) GetThreatActor(actorID string) *ThreatActorProfile {
	kb.mutex.RLock()
	defer kb.mutex.RUnlock()

	return kb.threatActors[actorID]
}

// SearchThreatActors searches for threat actors
func (kb *KnowledgeBase) SearchThreatActors(query string) []*ThreatActorProfile {
	kb.mutex.RLock()
	defer kb.mutex.RUnlock()

	var results []*ThreatActorProfile
	queryLower := strings.ToLower(query)

	for _, actor := range kb.threatActors {
		if strings.Contains(strings.ToLower(actor.Name), queryLower) ||
			strings.Contains(strings.ToLower(actor.Description), queryLower) {
			results = append(results, actor)
		}

		// Check aliases
		for _, alias := range actor.Aliases {
			if strings.Contains(strings.ToLower(alias), queryLower) {
				results = append(results, actor)
				break
			}
		}
	}

	return results
}

// CheckIOC checks if a value is a known indicator of compromise
func (kb *KnowledgeBase) CheckIOC(value string) *IOC {
	kb.mutex.RLock()
	defer kb.mutex.RUnlock()

	for _, ioc := range kb.iocs {
		if ioc.Value == value && ioc.Active && !ioc.FalsePositive {
			return ioc
		}
	}

	return nil
}

// AddIOC adds an indicator of compromise
func (kb *KnowledgeBase) AddIOC(ioc *IOC) {
	kb.mutex.Lock()
	defer kb.mutex.Unlock()

	kb.iocs[ioc.ID] = ioc
	kb.lastUpdated["iocs"] = time.Now()
}

// GetDetectionRule retrieves a detection rule by ID
func (kb *KnowledgeBase) GetDetectionRule(ruleID string) *DetectionRule {
	kb.mutex.RLock()
	defer kb.mutex.RUnlock()

	return kb.rules[ruleID]
}

// SearchDetectionRules searches for detection rules
func (kb *KnowledgeBase) SearchDetectionRules(category, language string) []*DetectionRule {
	kb.mutex.RLock()
	defer kb.mutex.RUnlock()

	var results []*DetectionRule

	for _, rule := range kb.rules {
		if !rule.Enabled {
			continue
		}

		match := true
		if category != "" && rule.Category != category {
			match = false
		}
		if language != "" && rule.Language != language {
			match = false
		}

		if match {
			results = append(results, rule)
		}
	}

	return results
}

// GetRelatedTechniques finds MITRE techniques related to findings
func (kb *KnowledgeBase) GetRelatedTechniques(indicators []string) []*MitreATTACKTechnique {
	kb.mutex.RLock()
	defer kb.mutex.RUnlock()

	var techniques []*MitreATTACKTechnique
	techniqueMap := make(map[string]bool)

	for _, indicator := range indicators {
		indicatorLower := strings.ToLower(indicator)

		for _, technique := range kb.mitreTechniques {
			// Check if indicator matches technique name, description, or detection
			if strings.Contains(strings.ToLower(technique.Name), indicatorLower) ||
				strings.Contains(strings.ToLower(technique.Description), indicatorLower) ||
				strings.Contains(strings.ToLower(technique.Detection), indicatorLower) {
				
				if !techniqueMap[technique.ID] {
					techniques = append(techniques, technique)
					techniqueMap[technique.ID] = true
				}
			}
		}
	}

	return techniques
}

// GetMitigations retrieves mitigations for specific techniques
func (kb *KnowledgeBase) GetMitigations(techniqueIDs []string) []string {
	kb.mutex.RLock()
	defer kb.mutex.RUnlock()

	mitigationSet := make(map[string]bool)
	var mitigations []string

	for _, techniqueID := range techniqueIDs {
		if technique, exists := kb.mitreTechniques[techniqueID]; exists {
			for _, mitigation := range technique.Mitigations {
				if !mitigationSet[mitigation] {
					mitigations = append(mitigations, mitigation)
					mitigationSet[mitigation] = true
				}
			}
		}
	}

	return mitigations
}

// UpdateFromExternalSource updates knowledge base from external threat feeds
func (kb *KnowledgeBase) UpdateFromExternalSource(sourceType, data string) error {
	kb.mutex.Lock()
	defer kb.mutex.Unlock()

	switch sourceType {
	case "mitre":
		return kb.updateMitreData(data)
	case "cve":
		return kb.updateCVEData(data)
	case "ioc":
		return kb.updateIOCData(data)
	case "threat_actor":
		return kb.updateThreatActorData(data)
	default:
		return fmt.Errorf("unknown source type: %s", sourceType)
	}
}

// Export serializes knowledge base data
func (kb *KnowledgeBase) Export() ([]byte, error) {
	kb.mutex.RLock()
	defer kb.mutex.RUnlock()

	exportData := map[string]interface{}{
		"mitre_techniques": kb.mitreTechniques,
		"vulnerabilities":  kb.vulnerabilities,
		"threat_actors":    kb.threatActors,
		"iocs":            kb.iocs,
		"rules":           kb.rules,
		"version":         kb.version,
		"last_updated":    kb.lastUpdated,
		"exported_at":     time.Now(),
	}

	return json.Marshal(exportData)
}

// Import loads knowledge base data from serialized format
func (kb *KnowledgeBase) Import(data []byte) error {
	kb.mutex.Lock()
	defer kb.mutex.Unlock()

	var importData map[string]interface{}
	if err := json.Unmarshal(data, &importData); err != nil {
		return err
	}

	// Import each data type
	if mitreData, ok := importData["mitre_techniques"]; ok {
		mitreBytes, _ := json.Marshal(mitreData)
		var techniques map[string]*MitreATTACKTechnique
		if err := json.Unmarshal(mitreBytes, &techniques); err == nil {
			for id, technique := range techniques {
				kb.mitreTechniques[id] = technique
			}
		}
	}

	if vulnData, ok := importData["vulnerabilities"]; ok {
		vulnBytes, _ := json.Marshal(vulnData)
		var vulnerabilities map[string]*VulnerabilityInfo
		if err := json.Unmarshal(vulnBytes, &vulnerabilities); err == nil {
			for cve, vuln := range vulnerabilities {
				kb.vulnerabilities[cve] = vuln
			}
		}
	}

	kb.lastUpdated["import"] = time.Now()
	return nil
}

// GetStats returns knowledge base statistics
func (kb *KnowledgeBase) GetStats() map[string]interface{} {
	kb.mutex.RLock()
	defer kb.mutex.RUnlock()

	return map[string]interface{}{
		"mitre_techniques": len(kb.mitreTechniques),
		"vulnerabilities":  len(kb.vulnerabilities),
		"threat_actors":    len(kb.threatActors),
		"iocs":            len(kb.iocs),
		"detection_rules":  len(kb.rules),
		"version":         kb.version,
		"last_updated":    kb.lastUpdated,
	}
}

// Private helper methods

func (kb *KnowledgeBase) getDefaultMitreTechniques() []*MitreATTACKTechnique {
	return []*MitreATTACKTechnique{
		{
			ID:          "T1059",
			Name:        "Command and Scripting Interpreter",
			Description: "Adversaries may abuse command and script interpreters to execute commands, scripts, or binaries.",
			Tactics:     []string{"execution"},
			Platforms:   []string{"Linux", "macOS", "Windows"},
			DataSources: []string{"Process", "Command"},
			Permissions: []string{"User", "Administrator"},
			Detection:   "Monitor process execution for unusual command patterns",
			CreatedDate: time.Now(),
			ModifiedDate: time.Now(),
		},
		{
			ID:          "T1055",
			Name:        "Process Injection",
			Description: "Adversaries may inject code into processes in order to evade process-based defenses.",
			Tactics:     []string{"defense-evasion", "privilege-escalation"},
			Platforms:   []string{"Linux", "macOS", "Windows"},
			DataSources: []string{"Process", "API Monitoring"},
			Permissions: []string{"User", "Administrator"},
			Detection:   "Monitor for process access and modification activities",
			CreatedDate: time.Now(),
			ModifiedDate: time.Now(),
		},
		{
			ID:          "T1071",
			Name:        "Application Layer Protocol",
			Description: "Adversaries may communicate using application layer protocols to avoid detection.",
			Tactics:     []string{"command-and-control"},
			Platforms:   []string{"Linux", "macOS", "Windows"},
			DataSources: []string{"Network Traffic", "Process"},
			Permissions: []string{"User"},
			Detection:   "Monitor network traffic for unusual patterns",
			CreatedDate: time.Now(),
			ModifiedDate: time.Now(),
		},
		{
			ID:          "T1190",
			Name:        "Exploit Public-Facing Application",
			Description: "Adversaries may attempt to exploit a weakness in an Internet-facing host or system.",
			Tactics:     []string{"initial-access"},
			Platforms:   []string{"Linux", "Windows", "macOS"},
			DataSources: []string{"Application Log", "Web Proxy"},
			Permissions: []string{"User"},
			Detection:   "Monitor application logs for exploitation attempts",
			CreatedDate: time.Now(),
			ModifiedDate: time.Now(),
		},
		{
			ID:          "T1566",
			Name:        "Phishing",
			Description: "Adversaries may send phishing messages to gain access to victim systems.",
			Tactics:     []string{"initial-access"},
			Platforms:   []string{"Linux", "macOS", "Windows"},
			DataSources: []string{"Email Gateway", "File Monitoring"},
			Permissions: []string{"User"},
			Detection:   "Monitor for suspicious email attachments and links",
			CreatedDate: time.Now(),
			ModifiedDate: time.Now(),
		},
	}
}

func (kb *KnowledgeBase) updateMitreData(data string) error {
	var techniques map[string]*MitreATTACKTechnique
	if err := json.Unmarshal([]byte(data), &techniques); err != nil {
		return err
	}

	for id, technique := range techniques {
		kb.mitreTechniques[id] = technique
	}

	kb.lastUpdated["mitre"] = time.Now()
	return nil
}

func (kb *KnowledgeBase) updateCVEData(data string) error {
	var vulnerabilities map[string]*VulnerabilityInfo
	if err := json.Unmarshal([]byte(data), &vulnerabilities); err != nil {
		return err
	}

	for cve, vuln := range vulnerabilities {
		kb.vulnerabilities[cve] = vuln
	}

	kb.lastUpdated["cve"] = time.Now()
	return nil
}

func (kb *KnowledgeBase) updateIOCData(data string) error {
	var iocs map[string]*IOC
	if err := json.Unmarshal([]byte(data), &iocs); err != nil {
		return err
	}

	for id, ioc := range iocs {
		kb.iocs[id] = ioc
	}

	kb.lastUpdated["ioc"] = time.Now()
	return nil
}

func (kb *KnowledgeBase) updateThreatActorData(data string) error {
	var actors map[string]*ThreatActorProfile
	if err := json.Unmarshal([]byte(data), &actors); err != nil {
		return err
	}

	for id, actor := range actors {
		kb.threatActors[id] = actor
	}

	kb.lastUpdated["threat_actor"] = time.Now()
	return nil
}
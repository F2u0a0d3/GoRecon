package cloud

import (
	"bufio"
	"context"
	"crypto/tls"
	"fmt"
	"net"
	"os"
	"strings"
	"time"

	"github.com/google/uuid"
	"github.com/f2u0a0d3/GoRecon/internal/utils"
	"github.com/f2u0a0d3/GoRecon/pkg/config"
	"github.com/f2u0a0d3/GoRecon/pkg/core"
	"github.com/f2u0a0d3/GoRecon/pkg/models"
	"github.com/rs/zerolog"
)

// SNIScannerPlugin implements cloud asset discovery via SNI scanning
type SNIScannerPlugin struct {
	core.BasePlugin
	logger   zerolog.Logger
	config   *config.Config
	ipMap    map[string][]string // IP -> hostnames mapping
	sniHosts []string            // Hosts to test via SNI
}

// NewSNIScannerPlugin creates a new SNI scanner plugin
func NewSNIScannerPlugin() *SNIScannerPlugin {
	logger := zerolog.New(nil).With().Str("plugin", "sni_scanner").Logger()
	
	return &SNIScannerPlugin{
		BasePlugin: core.NewBasePlugin("sni_scanner", "cloud", []string{"openssl", "dig"}),
		logger:     logger,
		ipMap:      make(map[string][]string),
		sniHosts:   make([]string, 0),
	}
}

// Metadata methods
func (s *SNIScannerPlugin) Name() string { return "sni_scanner" }
func (s *SNIScannerPlugin) Category() string { return "cloud" }
func (s *SNIScannerPlugin) Description() string {
	return "Discovers cloud assets and services using SNI (Server Name Indication) scanning"
}
func (s *SNIScannerPlugin) Version() string { return "1.0.0" }
func (s *SNIScannerPlugin) Author() string { return "GoRecon Team" }

// Dependency methods
func (s *SNIScannerPlugin) RequiredBinaries() []string {
	return []string{"dig"} // openssl is optional for advanced cert analysis
}

func (s *SNIScannerPlugin) RequiredEnvVars() []string {
	return []string{}
}

func (s *SNIScannerPlugin) SupportedTargetTypes() []string {
	return []string{"web", "subdomain", "cloud", "ip"}
}

func (s *SNIScannerPlugin) Dependencies() []core.PluginDependency {
	return []core.PluginDependency{
		{
			Plugin:   "subfinder",
			Required: false,
			Reason:   "Provides subdomains for SNI scanning",
		},
	}
}

func (s *SNIScannerPlugin) Provides() []string {
	return []string{"cloud_assets", "ssl_certificates", "virtual_hosts"}
}

func (s *SNIScannerPlugin) Consumes() []string {
	return []string{"subdomains", "ip_addresses", "ssl_endpoints"}
}

// Capability methods
func (s *SNIScannerPlugin) IsPassive() bool { return false } // SNI probing is semi-active
func (s *SNIScannerPlugin) RequiresConfirmation() bool { return false }
func (s *SNIScannerPlugin) EstimatedDuration() time.Duration { return 10 * time.Minute }
func (s *SNIScannerPlugin) MaxConcurrency() int { return 5 }
func (s *SNIScannerPlugin) Priority() int { return 7 } // High priority for cloud discovery
func (s *SNIScannerPlugin) ResourceRequirements() core.Resources {
	return core.Resources{
		CPUCores:         2,
		MemoryMB:         512,
		DiskMB:           100,
		NetworkBandwidth: "5Mbps",
		MaxFileHandles:   200,
		MaxProcesses:     10,
		RequiresRoot:     false,
		NetworkAccess:    true,
	}
}

// Intelligence methods
func (s *SNIScannerPlugin) ProcessDiscovery(ctx context.Context, discovery models.Discovery) error {
	switch discovery.Type {
	case models.DiscoveryTypeSubdomain:
		if hostname, ok := discovery.Value.(string); ok {
			s.sniHosts = append(s.sniHosts, hostname)
		}
	case "ip_address":
		if ip, ok := discovery.Value.(string); ok {
			// Add to IP mapping for reverse SNI lookup
			s.ipMap[ip] = append(s.ipMap[ip], "")
		}
	}
	return nil
}

func (s *SNIScannerPlugin) GetIntelligencePatterns() []core.Pattern {
	return []core.Pattern{
		{
			Name:        "cloud_service_sni",
			Type:        "service",
			Keywords:    []string{"amazonaws.com", "cloudfront.net", "azurewebsites.net", "googleapis.com", "herokuapp.com"},
			Confidence:  0.9,
			Description: "Cloud service indicators in SNI certificates",
		},
		{
			Name:        "wildcard_certificate",
			Type:        "certificate",
			Keywords:    []string{"*.", "wildcard"},
			Confidence:  0.8,
			Description: "Wildcard certificates that may expose additional subdomains",
		},
		{
			Name:        "cdn_detection",
			Type:        "infrastructure",
			Keywords:    []string{"cloudflare", "fastly", "akamai", "maxcdn", "keycdn"},
			Confidence:  0.9,
			Description: "CDN infrastructure detection via certificates",
		},
	}
}

// Lifecycle methods
func (s *SNIScannerPlugin) Validate(ctx context.Context, cfg *config.Config) error {
	s.config = cfg
	
	// Check if dig is available for DNS resolution
	exec := utils.NewExecWrapper(s.logger)
	if err := exec.CheckBinary("dig"); err != nil {
		s.logger.Warn().Err(err).Msg("dig not found, will use basic DNS resolution")
	}
	
	return nil
}

func (s *SNIScannerPlugin) Prepare(ctx context.Context, target *models.Target, cfg *config.Config, shared *core.SharedContext) error {
	s.config = cfg
	s.logger = s.logger.With().Str("target", target.Domain).Logger()
	
	s.logger.Info().
		Str("target", target.URL).
		Msg("Preparing SNI scanner for cloud asset discovery")
	
	// Load SNI map if provided in config (currently not supported in config structure)
	// TODO: Add SNI map file support to config structure
	
	// Add target domain to SNI hosts
	s.sniHosts = append(s.sniHosts, target.Domain)
	
	// Get additional hostnames from shared context
	if shared != nil {
		discoveries := shared.GetDiscoveries(models.DiscoveryTypeSubdomain)
		for _, discovery := range discoveries {
			if hostname, ok := discovery.Value.(string); ok {
				s.sniHosts = append(s.sniHosts, hostname)
			}
		}
	}
	
	return nil
}

func (s *SNIScannerPlugin) Run(ctx context.Context, target *models.Target, results chan<- models.PluginResult, shared *core.SharedContext) error {
	s.logger.Info().
		Int("sni_hosts", len(s.sniHosts)).
		Int("ip_mappings", len(s.ipMap)).
		Msg("Starting SNI scanning for cloud asset discovery")
	
	// Scan hosts via SNI
	for _, hostname := range s.sniHosts {
		if err := s.scanHostSNI(ctx, hostname, target, results); err != nil {
			s.logger.Error().Err(err).
				Str("hostname", hostname).
				Msg("Failed to scan hostname via SNI")
		}
	}
	
	// Perform reverse SNI scanning on known IPs
	for ip, hostnames := range s.ipMap {
		if err := s.reverseSNIScan(ctx, ip, hostnames, target, results); err != nil {
			s.logger.Error().Err(err).
				Str("ip", ip).
				Msg("Failed to perform reverse SNI scan")
		}
	}
	
	s.logger.Info().
		Msg("SNI scanning completed")
	
	return nil
}

func (s *SNIScannerPlugin) Teardown(ctx context.Context) error {
	s.logger.Debug().Msg("Tearing down SNI scanner plugin")
	return nil
}

// Implementation methods

func (s *SNIScannerPlugin) loadSNIMap(filepath string) error {
	file, err := os.Open(filepath)
	if err != nil {
		return fmt.Errorf("failed to open SNI map file: %w", err)
	}
	defer file.Close()
	
	scanner := bufio.NewScanner(file)
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		
		// Support multiple formats: "IP hostname" or "IP,hostname" or "IP:hostname"
		var ip, hostname string
		if strings.Contains(line, ",") {
			parts := strings.Split(line, ",")
			if len(parts) >= 2 {
				ip = strings.TrimSpace(parts[0])
				hostname = strings.TrimSpace(parts[1])
			}
		} else if strings.Contains(line, ":") && !strings.Contains(line, "::") {
			parts := strings.Split(line, ":")
			if len(parts) >= 2 {
				ip = strings.TrimSpace(parts[0])
				hostname = strings.TrimSpace(parts[1])
			}
		} else {
			parts := strings.Fields(line)
			if len(parts) >= 2 {
				ip = parts[0]
				hostname = parts[1]
			}
		}
		
		if ip != "" && hostname != "" {
			s.ipMap[ip] = append(s.ipMap[ip], hostname)
		}
	}
	
	s.logger.Info().
		Int("ip_mappings", len(s.ipMap)).
		Msg("Loaded SNI map file")
	
	return scanner.Err()
}

func (s *SNIScannerPlugin) scanHostSNI(ctx context.Context, hostname string, target *models.Target, results chan<- models.PluginResult) error {
	s.logger.Debug().
		Str("hostname", hostname).
		Msg("Scanning hostname via SNI")
	
	// Resolve hostname to IP
	ips, err := net.LookupIP(hostname)
	if err != nil {
		s.logger.Debug().Err(err).
			Str("hostname", hostname).
			Msg("Failed to resolve hostname")
		return nil // Don't fail the whole scan for one hostname
	}
	
	// Test SNI on each IP
	for _, ip := range ips {
		certInfo, err := s.probeSNI(ctx, ip.String(), hostname)
		if err != nil {
			s.logger.Debug().Err(err).
				Str("hostname", hostname).
				Str("ip", ip.String()).
				Msg("SNI probe failed")
			continue
		}
		
		if certInfo != nil {
			result := s.createSNIResult(certInfo, hostname, ip.String(), target)
			results <- result
			
			// Extract additional hostnames from certificate
			s.extractCertificateHosts(certInfo, results, target)
		}
	}
	
	return nil
}

func (s *SNIScannerPlugin) reverseSNIScan(ctx context.Context, ip string, knownHosts []string, target *models.Target, results chan<- models.PluginResult) error {
	s.logger.Debug().
		Str("ip", ip).
		Strs("known_hosts", knownHosts).
		Msg("Performing reverse SNI scan")
	
	// Test each known hostname against the IP
	for _, hostname := range knownHosts {
		if hostname == "" {
			continue
		}
		
		certInfo, err := s.probeSNI(ctx, ip, hostname)
		if err != nil {
			continue
		}
		
		if certInfo != nil {
			result := s.createSNIResult(certInfo, hostname, ip, target)
			results <- result
		}
	}
	
	return nil
}

func (s *SNIScannerPlugin) probeSNI(ctx context.Context, ip, hostname string) (*CertificateInfo, error) {
	// Create timeout context
	probeCtx, cancel := context.WithTimeout(ctx, 10*time.Second)
	defer cancel()
	
	// Set up TLS connection with SNI
	dialer := &net.Dialer{
		Timeout: 5 * time.Second,
	}
	
	conn, err := dialer.DialContext(probeCtx, "tcp", fmt.Sprintf("%s:443", ip))
	if err != nil {
		return nil, fmt.Errorf("failed to connect to %s:443: %w", ip, err)
	}
	defer conn.Close()
	
	// Perform TLS handshake with SNI
	tlsConn := tls.Client(conn, &tls.Config{
		ServerName:         hostname,
		InsecureSkipVerify: true,
	})
	
	if err := tlsConn.Handshake(); err != nil {
		return nil, fmt.Errorf("TLS handshake failed: %w", err)
	}
	defer tlsConn.Close()
	
	// Extract certificate information
	state := tlsConn.ConnectionState()
	if len(state.PeerCertificates) == 0 {
		return nil, fmt.Errorf("no certificates received")
	}
	
	cert := state.PeerCertificates[0]
	
	certInfo := &CertificateInfo{
		Subject:      cert.Subject.CommonName,
		Issuer:       cert.Issuer.CommonName,
		SerialNumber: cert.SerialNumber.String(),
		NotBefore:    cert.NotBefore,
		NotAfter:     cert.NotAfter,
		DNSNames:     cert.DNSNames,
		IPAddresses:  make([]string, len(cert.IPAddresses)),
		KeyUsage:     int(cert.KeyUsage),
		IsCA:         cert.IsCA,
		Fingerprint:  utils.HashBytes(cert.Raw),
	}
	
	for i, ip := range cert.IPAddresses {
		certInfo.IPAddresses[i] = ip.String()
	}
	
	return certInfo, nil
}

func (s *SNIScannerPlugin) createSNIResult(certInfo *CertificateInfo, hostname, ip string, target *models.Target) models.PluginResult {
	// Determine severity based on findings
	severity := models.SeverityInfo
	title := fmt.Sprintf("Cloud Asset: %s", hostname)
	description := fmt.Sprintf("Discovered cloud asset %s on IP %s via SNI scanning", hostname, ip)
	
	// Check for cloud services
	cloudService := s.detectCloudService(certInfo)
	if cloudService != "" {
		severity = models.SeverityLow
		title = fmt.Sprintf("Cloud Service: %s (%s)", hostname, cloudService)
		description = fmt.Sprintf("Detected %s cloud service at %s (IP: %s)", cloudService, hostname, ip)
	}
	
	// Check for wildcard certificates
	if s.isWildcardCert(certInfo) {
		severity = models.SeverityMedium
		title = fmt.Sprintf("Wildcard Certificate: %s", hostname)
		description = fmt.Sprintf("Wildcard certificate found for %s - may expose additional subdomains", hostname)
	}
	
	// Check for certificate issues
	if time.Now().After(certInfo.NotAfter) {
		severity = models.SeverityHigh
		title = fmt.Sprintf("Expired Certificate: %s", hostname)
		description = fmt.Sprintf("Expired SSL certificate found for %s (expired: %s)", hostname, certInfo.NotAfter.Format("2006-01-02"))
	}
	
	result := models.PluginResult{
		ID:        uuid.New().String(),
		Plugin:    s.Name(),
		Tool:      "sni_scanner",
		Category:  "cloud",
		Target:    target.URL,
		Timestamp: time.Now(),
		Severity:  severity,
		Title:     title,
		Description: description,
		Evidence: models.Evidence{
			Type:    "certificate",
			Content: fmt.Sprintf("SNI probe of %s on %s", hostname, ip),
			URL:     fmt.Sprintf("https://%s", hostname),
		},
		Data: map[string]interface{}{
			"hostname":       hostname,
			"ip_address":     ip,
			"cloud_service":  cloudService,
			"certificate": map[string]interface{}{
				"subject":       certInfo.Subject,
				"issuer":        certInfo.Issuer,
				"serial_number": certInfo.SerialNumber,
				"not_before":    certInfo.NotBefore,
				"not_after":     certInfo.NotAfter,
				"dns_names":     certInfo.DNSNames,
				"ip_addresses":  certInfo.IPAddresses,
				"fingerprint":   certInfo.Fingerprint,
				"is_wildcard":   s.isWildcardCert(certInfo),
				"is_expired":    time.Now().After(certInfo.NotAfter),
			},
		},
		Confidence: 0.8,
		Tags:       []string{"cloud", "sni", "certificate", cloudService},
	}
	
	return result
}

func (s *SNIScannerPlugin) extractCertificateHosts(certInfo *CertificateInfo, results chan<- models.PluginResult, target *models.Target) {
	// Extract additional hostnames from certificate DNS names
	for _, dnsName := range certInfo.DNSNames {
		if dnsName != certInfo.Subject && !strings.HasPrefix(dnsName, "*.") {
			// Create discovery result for new hostname
			result := models.PluginResult{
				ID:        uuid.New().String(),
				Plugin:    s.Name(),
				Tool:      "sni_scanner",
				Category:  "cloud",
				Target:    target.URL,
				Timestamp: time.Now(),
				Severity:  models.SeverityInfo,
				Title:     fmt.Sprintf("Certificate Hostname: %s", dnsName),
				Description: fmt.Sprintf("Additional hostname %s found in SSL certificate", dnsName),
				Evidence: models.Evidence{
					Type:    "certificate",
					Content: fmt.Sprintf("DNS name in certificate: %s", dnsName),
				},
				Data: map[string]interface{}{
					"hostname":        dnsName,
					"discovery_type":  "certificate_san",
					"certificate_subject": certInfo.Subject,
					"source_certificate": certInfo.Fingerprint,
				},
				Confidence: 0.9,
				Tags:       []string{"hostname", "certificate", "san"},
			}
			
			results <- result
		}
	}
}

func (s *SNIScannerPlugin) detectCloudService(certInfo *CertificateInfo) string {
	cloudServices := map[string]string{
		"amazonaws.com":       "AWS",
		"cloudfront.net":      "AWS CloudFront",
		"azurewebsites.net":   "Azure",
		"azure.com":           "Azure",
		"googleapis.com":      "Google Cloud",
		"googlesyndication.com": "Google",
		"herokuapp.com":       "Heroku",
		"netlify.com":         "Netlify",
		"vercel.com":          "Vercel",
		"cloudflare.com":      "Cloudflare",
		"fastly.com":          "Fastly",
		"akamai.com":          "Akamai",
		"maxcdn.com":          "MaxCDN",
	}
	
	// Check issuer
	issuer := strings.ToLower(certInfo.Issuer)
	for service, name := range cloudServices {
		if strings.Contains(issuer, service) {
			return name
		}
	}
	
	// Check subject
	subject := strings.ToLower(certInfo.Subject)
	for service, name := range cloudServices {
		if strings.Contains(subject, service) {
			return name
		}
	}
	
	// Check DNS names
	for _, dnsName := range certInfo.DNSNames {
		dnsName = strings.ToLower(dnsName)
		for service, name := range cloudServices {
			if strings.Contains(dnsName, service) {
				return name
			}
		}
	}
	
	return ""
}

func (s *SNIScannerPlugin) isWildcardCert(certInfo *CertificateInfo) bool {
	if strings.HasPrefix(certInfo.Subject, "*.") {
		return true
	}
	
	for _, dnsName := range certInfo.DNSNames {
		if strings.HasPrefix(dnsName, "*.") {
			return true
		}
	}
	
	return false
}

// CertificateInfo represents extracted certificate information
type CertificateInfo struct {
	Subject      string    `json:"subject"`
	Issuer       string    `json:"issuer"`
	SerialNumber string    `json:"serial_number"`
	NotBefore    time.Time `json:"not_before"`
	NotAfter     time.Time `json:"not_after"`
	DNSNames     []string  `json:"dns_names"`
	IPAddresses  []string  `json:"ip_addresses"`
	KeyUsage     int       `json:"key_usage"`
	IsCA         bool      `json:"is_ca"`
	Fingerprint  string    `json:"fingerprint"`
}
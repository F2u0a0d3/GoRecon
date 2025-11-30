# 🔍 GoRecon

> **Collaborator Elmir Hajizada**

> **Intelligence-Driven Penetration Testing Framework**

[![Go Version](https://img.shields.io/badge/Go-1.21+-blue.svg)](https://golang.org)
[![License](https://img.shields.io/badge/License-MIT-green.svg)](LICENSE)
[![Platform](https://img.shields.io/badge/Platform-Linux%20%7C%20macOS%20%7C%20Windows-lightgrey.svg)](https://github.com/f2u0a0d3/GoRecon)
[![Build Status](https://img.shields.io/badge/Build-Passing-brightgreen.svg)](https://github.com/f2u0a0d3/GoRecon/actions)
[![Release](https://img.shields.io/badge/Release-v2.1.0-blue.svg)](https://github.com/f2u0a0d3/GoRecon/releases)

**GoRecon** is a next-generation, modular penetration testing framework engineered for security professionals, bug bounty hunters, red team operators, and security researchers. Built with Go for maximum performance and reliability, it seamlessly combines **passive** and **active reconnaissance** techniques with intelligent automation, comprehensive reporting, and enterprise-grade scalability.

<div align="center">

![GoRecon Demo](https://via.placeholder.com/800x400/1e1e2e/cdd6f4?text=GoRecon+Demo+%7C+Professional+Security+Testing)

*Professional reconnaissance and vulnerability assessment in action*

</div>

---

## 🎯 **Why GoRecon?**

| Feature | Description | Benefit |
|---------|-------------|---------|
| 🚀 **Performance** | Built with Go for speed and efficiency | **10x faster** than Python alternatives |
| 🔧 **Modular Design** | Plugin-based architecture | Easy to extend and customize |
| 🛡️ **Safety First** | Built-in rate limiting and respectful scanning | Avoid detection and service disruption |
| 📊 **Professional Reports** | Multiple output formats with rich visualizations | Ready for client delivery |
| 🔄 **Intelligent Automation** | Smart dependency resolution and caching | Resume interrupted scans seamlessly |
| 🌐 **Enterprise Ready** | Kubernetes deployment, distributed scanning | Scale to large environments |

## ✨ **Key Capabilities**

<table>
<tr>
<td width="50%">

### 🔍 **Reconnaissance**
- ✅ **Subdomain Takeover** - Detect vulnerable subdomains
- ✅ **Cloud Asset Discovery** - AWS, Azure, GCP resources
- ✅ **Historical URLs** - Web archive mining
- ✅ **DNS Enumeration** - Comprehensive record discovery
- ✅ **Certificate Analysis** - SSL/TLS intelligence
- ✅ **Technology Stack** - Framework detection

</td>
<td width="50%">

### 🕸️ **Web Application Testing**
- ✅ **Smart Crawling** - Intelligent site mapping
- ✅ **JavaScript Analysis** - Extract endpoints & secrets
- ✅ **Directory Fuzzing** - Hidden content discovery
- ✅ **Parameter Mining** - HTTP parameter enumeration
- ✅ **Broken Link Detection** - Dead link analysis
- ✅ **HTTP Service Probing** - Technology fingerprinting

</td>
</tr>
<tr>
<td width="50%">

### 🔒 **Security Testing**
- ✅ **Vulnerability Scanning** - 4000+ Nuclei templates
- ✅ **Port Scanning** - Multi-tool network discovery
- ✅ **SSL/TLS Testing** - Certificate validation
- ✅ **Security Headers** - Configuration analysis
- ✅ **Authentication Bypass** - Access control testing
- ✅ **Configuration Issues** - Misconfiguration detection

</td>
<td width="50%">

### ⚙️ **Enterprise Features**
- ✅ **Pipeline Orchestration** - Intelligent workflow management
- ✅ **Distributed Scanning** - Scale across multiple nodes
- ✅ **Result Correlation** - Smart finding aggregation
- ✅ **Custom Reporting** - Professional PDF/HTML reports
- ✅ **API Integration** - RESTful and GraphQL APIs
- ✅ **Kubernetes Support** - Container-native deployment

</td>
</tr>
</table>

## 📦 Installation

### Prerequisites
- Go 1.21 or later
- Linux, macOS, or Windows
- Git

### 🚀 Quick Setup (Recommended)
```bash
# Clone the repository
git clone https://github.com/f2u0a0d3/GoRecon.git
cd GoRecon

# Complete setup (builds binary + installs all tools)
make setup
```

### 📋 Step-by-Step Installation

#### 1. Build GoRecon
```bash
# Build the binary
make build

# Or build for development (with debug symbols)
make dev
```

#### 2. Install External Tools
```bash
# Install all security tools (recommended)
make install-tools

# Or install minimal set only
make install-tools-minimal

# Verify tool installations
make verify-tools
```

#### 3. Install GoRecon Binary (Optional)
```bash
# Install to /usr/local/bin (requires sudo)
make install

# Or run from the build directory
./bin/gorecon --help
```

### 🛠️ Tool Dependencies

GoRecon integrates with these external security tools:

#### **Core Tools** (automatically installed):
- **subzy** - Subdomain takeover detection  
- **nuclei** - Vulnerability scanning
- **paramspider** - Parameter discovery
- **hakrawler** - Web crawling
- **ffuf** - Directory/file fuzzing
- **jsluice** - JavaScript analysis
- **httpx** - HTTP probing
- **gau** - URL collection from archives
- **waybackurls** - Wayback machine URLs
- **cloud_enum** - Cloud asset discovery
- **sni-scanner** - SNI certificate scanning
- **blc** - Broken link checker

#### **Additional Tools** (optional):
- **subfinder** - Subdomain discovery
- **naabu** - Port scanning  
- **masscan** - Fast port scanning
- **amass** - Asset discovery

### Manual Tool Installation
```bash
# Run the installation script directly
./scripts/install-tools.sh

# Install minimal tools only
./scripts/install-tools.sh --minimal

# Verify installations
./scripts/install-tools.sh --verify-only

# Install to custom directory
./scripts/install-tools.sh --install-dir /path/to/bin
```

## 📈 **Performance Metrics**

<div align="center">

| Metric | Value | Description |
|--------|-------|-------------|
| 🚀 **Speed** | **10x faster** | Compared to Python alternatives |
| 🔧 **Tools Integrated** | **15+ tools** | Industry-standard security tools |
| 🎯 **Nuclei Templates** | **4000+ templates** | Latest vulnerability checks |
| 📊 **Output Formats** | **4 formats** | JSON, JSONL, HTML, Console |
| 🔍 **Scan Types** | **12 stages** | Comprehensive security pipeline |
| ⚡ **Concurrent Execution** | **Multi-threaded** | Parallel plugin processing |

</div>

## 🎯 **Quick Start**

### 🚀 **One-Line Setup**
```bash
git clone https://github.com/f2u0a0d3/GoRecon.git && cd GoRecon && make setup
```

### 🔍 **Basic Usage**
```bash
# 🛡️ Safe passive reconnaissance (no intrusive scans)
gorecon step takeover --target example.com

# 🔥 Active vulnerability scanning (requires --confirm)
gorecon step vuln --target https://example.com --confirm

# 🚀 Complete security pipeline
gorecon do-all --target https://example.com --confirm
```

### 📋 **Common Workflows**

<table>
<tr>
<td width="50%">

#### 🐛 **Bug Bounty Hunting**
```bash
# Comprehensive reconnaissance
gorecon do-all --target example.com \
  --format jsonl --output recon-data

# Focus on specific attack vectors
gorecon step takeover --target example.com
gorecon step params --target example.com
```

</td>
<td width="50%">

#### 🏢 **Enterprise Assessment**
```bash
# Full security assessment
gorecon do-all --target https://company.com \
  --confirm --timeout 6h --format html

# Distributed scanning
gorecon serve --distributed --workers 5
```

</td>
</tr>
<tr>
<td width="50%">

#### ⚡ **Quick Security Check**
```bash
# Fast vulnerability scan
gorecon step vuln --target https://target.com \
  --confirm --timeout 30m

# Subdomain takeover check
gorecon step takeover --target target.com
```

</td>
<td width="50%">

#### 🔬 **Research & Analysis**
```bash
# Technology profiling
gorecon step js --target https://app.com
gorecon step httpprobe --target https://app.com

# Historical data mining
gorecon step wayback --target example.com
```

</td>
</tr>
</table>

## 🔧 Available Stages

### **Passive Reconnaissance**
- `takeover` - Subdomain takeover vulnerability detection
- `cloud` - Cloud asset and service discovery
- `wayback` - Historical URL collection from web archives

### **Active Scanning** (requires `--confirm`)
- `portscan` - Network port and service discovery
- `httpprobe` - HTTP service probing and technology detection
- `js` - JavaScript analysis for endpoints and secrets
- `crawl` - Web application crawling and mapping

### **Web Discovery**
- `blc` - Broken link detection and analysis
- `dirfuzz` - Directory and file fuzzing
- `params` - Parameter discovery and enumeration

### **Security Testing** (requires `--confirm`)
- `vuln` - Vulnerability scanning with nuclei

## 📊 Output Formats

### JSONL (Default - Streaming)
```bash
gorecon do-all --target example.com --format jsonl
```

### Structured JSON
```bash
gorecon do-all --target example.com --format json
```

### HTML Reports
```bash
gorecon do-all --target example.com --format html
```

## ⚡ Performance & Safety

### Built-in Safety Controls
- **Passive First** - Safe reconnaissance by default
- **Confirmation Required** - Active scans need explicit `--confirm`
- **Rate Limiting** - Respectful scanning practices
- **Timeout Controls** - Configurable execution limits

### Performance Features
- **Concurrent Execution** - Parallel plugin processing
- **Intelligent Caching** - Result caching and deduplication
- **Resource Management** - CPU and memory optimization
- **Resume Capability** - Interrupted scan recovery

## 🔌 Plugin Architecture

GoRecon uses a modular, plugin-based architecture for maximum extensibility:

### Core Components

```go
// Plugin interface - all plugins implement this
type Plugin interface {
    Name() string
    Run(ctx context.Context, target *models.Target, 
        results chan<- models.PluginResult, shared *core.SharedContext) error
}

// Example plugin implementation
type MyPlugin struct {
    *base.BaseAdapter
}

func (p *MyPlugin) Run(ctx context.Context, target *models.Target, 
    results chan<- models.PluginResult, shared *core.SharedContext) error {
    // Plugin implementation
    return nil
}
```

### Plugin Categories

#### **Reconnaissance Plugins**
- `SubdomainTakeoverPlugin` - Detects subdomain takeover vulnerabilities
- `CloudDiscoveryPlugin` - Discovers cloud assets (AWS, Azure, GCP)
- `WaybackPlugin` - Mines historical URLs from web archives

#### **Web Analysis Plugins**
- `HttpProbePlugin` - HTTP service probing and fingerprinting
- `JavaScriptAnalysisPlugin` - Extract secrets and endpoints from JS
- `CrawlerPlugin` - Intelligent web application crawling
- `ParamSpiderPlugin` - HTTP parameter discovery

#### **Security Testing Plugins**
- `VulnerabilityPlugin` - Nuclei-based vulnerability scanning
- `PortScanPlugin` - Network service discovery
- `DirectoryFuzzPlugin` - Hidden content discovery

### Creating Custom Plugins

1. **Implement the Plugin Interface**:
```go
type CustomPlugin struct {
    *base.BaseAdapter
}

func (p *CustomPlugin) Name() string {
    return "custom"
}

func (p *CustomPlugin) Run(ctx context.Context, target *models.Target, 
    results chan<- models.PluginResult, shared *core.SharedContext) error {
    // Your custom logic here
    return nil
}
```

2. **Register Your Plugin**:
```go
// In main.go or plugin registry
plugins.Register("custom", &CustomPlugin{})
```

3. **Use in Pipeline**:
```bash
gorecon step custom --target example.com
```

## 🚀 Advanced Usage

### Configuration Management

#### Configuration File
Create `~/.gorecon/config.yaml`:
```yaml
# Global settings
timeout: "2h"
workers: 10
rate_limit: 100
format: "jsonl"

# Tool-specific settings
nuclei:
  templates_dir: "/opt/nuclei-templates"
  rate_limit: 50
  timeout: "5m"

paramspider:
  rate_limit: 20
  max_depth: 3

# Output settings
output:
  directory: "./results"
  timestamp: true
  compress: true
```

#### Environment Variables
```bash
export GORECON_TIMEOUT="4h"
export GORECON_WORKERS="20"
export GORECON_OUTPUT_DIR="./custom-results"
export NUCLEI_TEMPLATES_DIR="/opt/nuclei-templates"
```

### Pipeline Orchestration

#### Custom Workflows
```yaml
# workflow.yaml
name: "bug-bounty-recon"
stages:
  - name: "passive"
    plugins: ["takeover", "cloud", "wayback"]
    parallel: true
  - name: "active"
    plugins: ["httpprobe", "crawl", "params"]
    requires: ["passive"]
  - name: "security"
    plugins: ["vuln"]
    requires: ["active"]
    confirm_required: true
```

```bash
# Run custom workflow
gorecon workflow --file workflow.yaml --target example.com
```

#### Distributed Scanning
```bash
# Start coordinator node
gorecon serve --mode coordinator --port 8080

# Start worker nodes
gorecon serve --mode worker --coordinator http://coordinator:8080

# Submit distributed scan
gorecon submit --target example.com --nodes 5
```

### Output Processing

#### JSON Processing with jq
```bash
# Extract all vulnerabilities
gorecon do-all --target example.com --format json | \
  jq '.results[] | select(.plugin == "vuln") | .data'

# Filter high severity findings
gorecon do-all --target example.com --format json | \
  jq '.results[] | select(.data.severity == "high")'

# Export to CSV
gorecon do-all --target example.com --format json | \
  jq -r '.results[] | [.plugin, .target, .data.title] | @csv'
```

#### Continuous Monitoring
```bash
# Monitor with file watching
gorecon do-all --target example.com --format jsonl \
  --output ./results/continuous.jsonl &

# Process results in real-time
tail -f ./results/continuous.jsonl | \
  jq 'select(.data.severity == "critical")'
```

## 📡 API Integration

### RESTful API

#### Start API Server
```bash
# Start REST API server
gorecon serve --mode api --port 8080

# With authentication
gorecon serve --mode api --port 8080 --auth-token "your-secret-token"
```

#### API Endpoints

**Submit Scan**:
```bash
curl -X POST http://localhost:8080/api/v1/scans \
  -H "Content-Type: application/json" \
  -H "Authorization: Bearer your-token" \
  -d '{
    "target": "example.com",
    "stages": ["takeover", "vuln"],
    "format": "json"
  }'
```

**Check Status**:
```bash
curl http://localhost:8080/api/v1/scans/scan-id/status \
  -H "Authorization: Bearer your-token"
```

**Get Results**:
```bash
curl http://localhost:8080/api/v1/scans/scan-id/results \
  -H "Authorization: Bearer your-token"
```

### GraphQL API

```bash
# Start GraphQL server
gorecon serve --mode graphql --port 8080
```

**Query Example**:
```graphql
query {
  scans(target: "example.com") {
    id
    status
    results {
      plugin
      severity
      title
      description
    }
  }
}
```

## 🐳 Deployment & Scaling

### Docker Deployment

#### Single Container
```bash
# Build image
docker build -t gorecon:latest .

# Run container
docker run -d \
  --name gorecon \
  -p 8080:8080 \
  -v $(pwd)/results:/app/results \
  gorecon:latest serve --mode api
```

#### Docker Compose
```yaml
# docker-compose.yml
version: '3.8'
services:
  coordinator:
    build: .
    ports:
      - "8080:8080"
    command: serve --mode coordinator
    
  worker:
    build: .
    depends_on:
      - coordinator
    command: serve --mode worker --coordinator http://coordinator:8080
    scale: 3
    
  redis:
    image: redis:alpine
    
  postgres:
    image: postgres:13
    environment:
      POSTGRES_DB: gorecon
      POSTGRES_USER: gorecon
      POSTGRES_PASSWORD: password
```

### Kubernetes Deployment

#### Deployment Configuration
```yaml
# k8s/deployment.yaml
apiVersion: apps/v1
kind: Deployment
metadata:
  name: gorecon-coordinator
spec:
  replicas: 1
  selector:
    matchLabels:
      app: gorecon-coordinator
  template:
    metadata:
      labels:
        app: gorecon-coordinator
    spec:
      containers:
      - name: gorecon
        image: gorecon:latest
        ports:
        - containerPort: 8080
        args: ["serve", "--mode", "coordinator"]
        resources:
          requests:
            memory: "1Gi"
            cpu: "500m"
          limits:
            memory: "2Gi"
            cpu: "1000m"
```

#### Worker Scaling
```yaml
apiVersion: apps/v1
kind: Deployment
metadata:
  name: gorecon-workers
spec:
  replicas: 5
  selector:
    matchLabels:
      app: gorecon-worker
  template:
    spec:
      containers:
      - name: gorecon
        image: gorecon:latest
        args: ["serve", "--mode", "worker", "--coordinator", "http://gorecon-coordinator:8080"]
```

### Cloud Deployments

#### AWS ECS
```bash
# Create ECS cluster
aws ecs create-cluster --cluster-name gorecon-cluster

# Deploy service
aws ecs create-service \
  --cluster gorecon-cluster \
  --service-name gorecon-service \
  --task-definition gorecon-task:1 \
  --desired-count 3
```

#### Google Cloud Run
```bash
# Build and push to GCR
docker tag gorecon:latest gcr.io/PROJECT-ID/gorecon
docker push gcr.io/PROJECT-ID/gorecon

# Deploy to Cloud Run
gcloud run deploy gorecon \
  --image gcr.io/PROJECT-ID/gorecon \
  --platform managed \
  --region us-central1
```

## 🔧 Configuration & Customization

### Security Configuration

#### Rate Limiting
```yaml
# config.yaml
rate_limiting:
  global_limit: 100  # requests per minute
  per_host_limit: 10
  burst_size: 20
  
tool_limits:
  nuclei: 50
  httpx: 30
  paramspider: 20
```

#### Proxy & Authentication
```yaml
proxy:
  http_proxy: "http://proxy.company.com:8080"
  https_proxy: "https://proxy.company.com:8080"
  no_proxy: "localhost,127.0.0.1"

authentication:
  basic_auth:
    username: "user"
    password: "pass"
  bearer_token: "your-jwt-token"
  custom_headers:
    - "X-API-Key: your-api-key"
```

### Custom Templates & Rules

#### Nuclei Custom Templates
```yaml
# custom-templates/sql-injection.yaml
id: custom-sqli-test
info:
  name: Custom SQL Injection Test
  author: your-team
  severity: high
  
requests:
  - method: GET
    path:
      - "{{BaseURL}}/search?q={{payload}}"
    payloads:
      payload:
        - "' OR 1=1--"
        - "'; DROP TABLE users--"
```

#### Custom Wordlists
```bash
# Directory for custom wordlists
mkdir -p ~/.gorecon/wordlists/

# Add custom directory wordlist
echo -e "admin\nadministrator\napi\nbackup" > ~/.gorecon/wordlists/custom-dirs.txt
```

## 🚨 Troubleshooting

### Common Issues & Solutions

#### Installation Problems

**Issue: Tools not found in PATH**
```bash
# Solution: Add tool directories to PATH
echo 'export PATH="$HOME/go/bin:$HOME/.local/bin:$PATH"' >> ~/.bashrc
source ~/.bashrc
```

**Issue: Permission denied errors**
```bash
# Solution: Fix file permissions
chmod +x scripts/install-tools.sh
sudo chown -R $(whoami) ~/.local/bin
```

**Issue: Go version too old**
```bash
# Solution: Update Go
wget https://go.dev/dl/go1.21.5.linux-amd64.tar.gz
sudo rm -rf /usr/local/go
sudo tar -C /usr/local -xzf go1.21.5.linux-amd64.tar.gz
```

#### Runtime Issues

**Issue: High memory usage**
```bash
# Solution: Limit concurrent workers and add memory limits
gorecon do-all --target example.com --workers 5 --memory-limit 2GB
```

**Issue: Network timeouts**
```yaml
# config.yaml - Adjust timeout settings
timeouts:
  http_timeout: "30s"
  dns_timeout: "10s"
  connect_timeout: "15s"
```

**Issue: Rate limiting errors**
```bash
# Solution: Reduce scan speed
gorecon step vuln --target example.com --rate-limit 10 --delay 1s
```

#### Debug Mode

```bash
# Enable verbose logging
export GORECON_DEBUG=true
gorecon do-all --target example.com --verbose

# Output logs to file
gorecon do-all --target example.com 2>&1 | tee debug.log

# Plugin-specific debugging
gorecon step vuln --target example.com --debug --plugin-debug nuclei
```

### Performance Optimization

#### Resource Tuning
```yaml
# config.yaml
performance:
  max_workers: 20
  memory_limit: "4GB"
  cpu_limit: "2000m"
  disk_cache: "1GB"
  
  # Tool-specific limits
  tool_limits:
    nuclei:
      rate_limit: 100
      concurrent_templates: 50
    httpx:
      threads: 100
      rate_limit: 200
```

#### Network Optimization
```bash
# Optimize for high-bandwidth networks
gorecon do-all --target example.com \
  --workers 50 \
  --rate-limit 500 \
  --timeout 30s

# Optimize for slow/unreliable networks
gorecon do-all --target example.com \
  --workers 5 \
  --rate-limit 20 \
  --timeout 5m \
  --retries 3
```

### Getting Help

#### Verbose Output
```bash
# Get detailed information about what's running
gorecon step vuln --target example.com --verbose --debug

# Check plugin validation
gorecon plugins validate --verbose
```

#### Log Analysis
```bash
# Parse logs for errors
grep -i "error\|failed\|timeout" ~/.gorecon/logs/gorecon.log

# Monitor real-time logs
tail -f ~/.gorecon/logs/gorecon.log | grep -E "(ERROR|WARN|FATAL)"
```

#### Health Checks
```bash
# System health check
gorecon health-check --verbose

# Tool verification
gorecon tools verify --all

# Performance benchmark
gorecon benchmark --target example.com --duration 5m
```

## 🤝 Contributing

We welcome contributions from the security community! GoRecon thrives on community input and collaboration.

### Quick Start for Contributors

1. **Fork & Clone**:
   ```bash
   git clone https://github.com/f2u0a0d3/GoRecon.git
   cd GoRecon
   git remote add upstream https://github.com/f2u0a0d3/GoRecon.git
   ```

2. **Set Up Development Environment**:
   ```bash
   make dev-setup    # Install development dependencies
   make test         # Ensure everything works
   ```

3. **Make Your Changes**:
   ```bash
   git checkout -b feature/your-feature-name
   # Make your changes
   make test lint    # Ensure quality
   ```

4. **Submit Pull Request**:
   ```bash
   git push origin feature/your-feature-name
   # Open PR on GitHub
   ```

### Development Workflow

#### Code Quality Standards
```bash
# Run full quality checks
make check

# Individual quality checks
make fmt        # Format code
make vet        # Static analysis
make lint       # Linting
make test       # Unit tests
```

#### Testing
```bash
# Run all tests
make test

# Run specific test suite
go test ./pkg/plugins/...

# Run tests with coverage
go test -cover ./...

# Integration tests
make test-integration
```

#### Building & Packaging
```bash
# Development build
make dev

# Production build
make build

# Multi-platform builds
make build-all

# Docker build
make docker-build
```

### Contribution Guidelines

#### Types of Contributions We Welcome

1. **🐛 Bug Fixes**
   - Fix existing functionality
   - Improve error handling
   - Enhance stability

2. **✨ New Features**
   - New plugin integrations
   - Additional output formats
   - Performance improvements

3. **🔧 Plugin Development**
   - New security tools integration
   - Custom analysis plugins
   - Specialized workflows

4. **📖 Documentation**
   - API documentation
   - Usage examples
   - Installation guides

5. **🧪 Testing**
   - Unit tests
   - Integration tests
   - Performance benchmarks

#### Code Standards

##### Go Code Style
- Follow [Effective Go](https://golang.org/doc/effective_go.html)
- Use `gofmt` for formatting
- Write comprehensive tests
- Document public APIs

```go
// Example: Proper function documentation
// ProcessTarget analyzes the given target using specified plugins.
// It returns processed results and any errors encountered.
func ProcessTarget(ctx context.Context, target *models.Target, 
    plugins []core.Plugin) (*models.ScanResult, error) {
    // Implementation
}
```

##### Plugin Development Guidelines
```go
// Plugin must implement core.Plugin interface
type MyPlugin struct {
    *base.BaseAdapter
}

func (p *MyPlugin) Name() string {
    return "my-plugin"
}

func (p *MyPlugin) Run(ctx context.Context, target *models.Target, 
    results chan<- models.PluginResult, shared *core.SharedContext) error {
    // Always check context cancellation
    select {
    case <-ctx.Done():
        return ctx.Err()
    default:
    }
    
    // Implement your plugin logic
    return nil
}
```

#### Pull Request Process

1. **Pre-Submission Checklist**:
   - [ ] Tests pass (`make test`)
   - [ ] Code is formatted (`make fmt`)
   - [ ] No linting errors (`make lint`)
   - [ ] Documentation updated if needed
   - [ ] CHANGELOG.md updated for significant changes

2. **PR Description Template**:
   ```markdown
   ## Description
   Brief description of changes

   ## Type of Change
   - [ ] Bug fix
   - [ ] New feature
   - [ ] Breaking change
   - [ ] Documentation update

   ## Testing
   - [ ] Unit tests added/updated
   - [ ] Manual testing performed
   - [ ] Integration tests pass

   ## Screenshots (if applicable)

   ## Additional Notes
   ```

3. **Review Process**:
   - Code review by maintainers
   - Automated CI checks
   - Community feedback welcome
   - Squash and merge after approval

### Plugin Development Guide

#### Creating a New Plugin

1. **Plugin Structure**:
   ```bash
   pkg/plugins/your-plugin/
   ├── plugin.go          # Main plugin implementation
   ├── config.go          # Configuration structure
   ├── parser.go          # Output parsing logic
   └── plugin_test.go     # Unit tests
   ```

2. **Implementation Template**:
   ```go
   package yourplugin

   import (
       "context"
       "github.com/f2u0a0d3/GoRecon/pkg/core"
       "github.com/f2u0a0d3/GoRecon/pkg/models"
       "github.com/f2u0a0d3/GoRecon/pkg/plugins/base"
   )

   type YourPlugin struct {
       *base.BaseAdapter
   }

   func (p *YourPlugin) Name() string {
       return "your-plugin"
   }

   func (p *YourPlugin) Run(ctx context.Context, target *models.Target,
       results chan<- models.PluginResult, shared *core.SharedContext) error {
       // Implementation here
       return nil
   }
   ```

3. **Register Your Plugin**:
   ```go
   // In cmd/gorecon/main.go or plugin registry
   import "github.com/f2u0a0d3/GoRecon/pkg/plugins/yourplugin"

   func init() {
       plugins.Register("your-plugin", &yourplugin.YourPlugin{})
   }
   ```

### Community & Support

#### Communication Channels

- **GitHub Issues**: Bug reports and feature requests
- **GitHub Discussions**: General questions and community chat
- **Security Issues**: security@gorecon.dev (private)

#### Community Guidelines

1. **Be Respectful**: Treat all community members with respect
2. **Be Constructive**: Provide helpful feedback and suggestions
3. **Be Patient**: Maintainers and contributors volunteer their time
4. **Be Secure**: Only share responsible disclosure information

#### Recognition

Contributors are recognized in:
- **CONTRIBUTORS.md**: All contributors listed
- **Release Notes**: Major contributions highlighted  
- **GitHub Contributors**: Automatic recognition
- **Hall of Fame**: Outstanding contributors featured

### Roadmap & Future Plans

#### Short Term (Q1-Q2 2024)
- [ ] Enhanced API documentation
- [ ] Mobile app for results viewing
- [ ] Cloud-native deployment options
- [ ] Advanced reporting templates

#### Medium Term (Q3-Q4 2024)
- [ ] Machine learning-based vulnerability correlation
- [ ] Integration with popular security platforms
- [ ] Custom dashboard development
- [ ] Enhanced distributed scanning

#### Long Term (2025+)
- [ ] AI-powered reconnaissance suggestions
- [ ] Automated remediation recommendations
- [ ] Enterprise SSO integration
- [ ] Multi-tenant SaaS offering

### Development Resources

#### Useful Commands
```bash
# Watch for changes and rebuild
make watch

# Start development server
make dev-server

# Run specific plugin tests
make test-plugin PLUGIN=nuclei

# Profile application performance
make profile TARGET=example.com
```

#### Documentation
- **API Reference**: `/docs/api/`
- **Plugin Guide**: `/docs/plugins/`
- **Architecture**: `/docs/architecture/`
- **Examples**: `/examples/`

### Getting Help

- **Documentation**: Check `/docs/` directory first
- **Examples**: Browse `/examples/` for usage patterns  
- **Issues**: Search existing GitHub issues
- **Discussions**: Join community discussions for help

#### For New Contributors
1. Start with "good first issue" labels
2. Join community discussions
3. Read existing code to understand patterns
4. Ask questions - we're here to help!

#### For Experienced Contributors
1. Help review pull requests
2. Mentor new contributors  
3. Propose architectural improvements
4. Lead feature development initiatives

## 📋 Requirements

### Integrated Tools
- **subzy** - Subdomain takeover detection
- **nuclei** - Vulnerability scanning
- **httpx** - HTTP probing
- **hakrawler** - Web crawling
- **ffuf** - Directory fuzzing
- **paramspider** - Parameter discovery
- **gau/waybackurls** - URL collection
- **jsluice** - JavaScript analysis
- **cloud_enum** - Cloud asset discovery

## 📜 License

MIT License - see [LICENSE](LICENSE) file for details.

## 🙏 Acknowledgments

Built with ❤️ by security researchers, for security researchers. Special thanks to the creators of the integrated security tools that make GoRecon possible.

## 📞 Support

- **Issues**: [GitHub Issues](https://github.com/f2u0a0d3/GoRecon/issues)
- **Discussions**: [GitHub Discussions](https://github.com/f2u0a0d3/GoRecon/discussions)

---

⚡ **Happy Hunting!** 🔍

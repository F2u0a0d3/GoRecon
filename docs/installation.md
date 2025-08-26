# GoRecon Installation Guide

Complete guide for installing GoRecon and all required security tools.

## 🚀 Quick Start

The fastest way to get GoRecon running:

```bash
git clone https://github.com/f2u0a0d3/GoRecon.git
cd GoRecon
make setup
```

This single command will:
1. Build the GoRecon binary
2. Install all external security tools
3. Verify installations

## 📋 Requirements

### System Requirements
- **Operating System**: Linux, macOS, or Windows with WSL
- **Go**: Version 1.21 or later
- **Git**: For cloning repositories
- **Python**: 3.6+ (for paramspider and cloud_enum)
- **Node.js**: For broken-link-checker (blc)

### Storage Space
- GoRecon binary: ~50MB
- External tools: ~500MB
- Nuclei templates: ~100MB
- Total: ~650MB

## 🔧 Installation Methods

### Method 1: Automated Setup (Recommended)

```bash
# Clone and setup everything
git clone https://github.com/f2u0a0d3/GoRecon.git
cd GoRecon
make setup

# Test installation
./bin/gorecon version
./bin/gorecon plugins validate
```

### Method 2: Step-by-Step

```bash
# 1. Clone repository
git clone https://github.com/f2u0a0d3/GoRecon.git
cd GoRecon

# 2. Build GoRecon
make build

# 3. Install external tools
make install-tools

# 4. Verify everything works
make verify-tools
```

### Method 3: Manual Installation

```bash
# Build GoRecon manually
go mod tidy
go build -o gorecon ./cmd/gorecon

# Install tools manually
chmod +x scripts/install-tools.sh
./scripts/install-tools.sh
```

## 🛠️ Tool Installation Details

### Core Tools (Required)

These tools are essential for GoRecon functionality:

| Tool | Purpose | Installation |
|------|---------|--------------|
| **subzy** | Subdomain takeover detection | `go install github.com/LukaSikic/subzy@latest` |
| **nuclei** | Vulnerability scanning | `go install github.com/projectdiscovery/nuclei/v3/cmd/nuclei@latest` |
| **paramspider** | Parameter discovery | `pip install paramspider` |
| **hakrawler** | Web crawling | `go install github.com/hakluke/hakrawler@latest` |
| **ffuf** | Directory fuzzing | `go install github.com/ffuf/ffuf/v2@latest` |
| **jsluice** | JavaScript analysis | `go install github.com/BishopFox/jsluice/cmd/jsluice@latest` |
| **httpx** | HTTP probing | `go install github.com/projectdiscovery/httpx/cmd/httpx@latest` |
| **gau** | URL collection | `go install github.com/lc/gau/v2/cmd/gau@latest` |
| **waybackurls** | Wayback URLs | `go install github.com/tomnomnom/waybackurls@latest` |
| **cloud_enum** | Cloud discovery | `git clone + pip install` |
| **sni-scanner** | SNI scanning | `git clone + go build` |
| **blc** | Broken link checker | `npm install -g broken-link-checker` |

### Additional Tools (Optional)

These tools enhance GoRecon capabilities:

| Tool | Purpose | Installation |
|------|---------|--------------|
| **subfinder** | Subdomain discovery | `go install github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest` |
| **naabu** | Port scanning | `go install github.com/projectdiscovery/naabu/v2/cmd/naabu@latest` |
| **masscan** | Fast port scanning | `sudo apt-get install masscan` |
| **amass** | Asset discovery | `go install github.com/OWASP/Amass/v3/...@master` |

## 🎯 Installation Options

### Minimal Installation

For basic functionality with core tools only:

```bash
make install-tools-minimal
```

### Custom Installation Directory

Install tools to a custom directory:

```bash
./scripts/install-tools.sh --install-dir /path/to/custom/bin
```

### User vs System Installation

#### User Installation (Recommended)
- Tools installed to `~/.local/bin`
- No sudo required
- Add `~/.local/bin` to your PATH

```bash
echo 'export PATH="$HOME/.local/bin:$PATH"' >> ~/.bashrc
source ~/.bashrc
```

#### System Installation
- Tools installed to `/usr/local/bin`
- Requires sudo for some tools
- Available for all users

## 🔍 Verification

### Verify Core Tools

```bash
# Using make
make verify-tools

# Using script directly
./scripts/install-tools.sh --verify-only

# Manual verification
which subzy nuclei paramspider hakrawler ffuf jsluice httpx gau waybackurls
```

### Test GoRecon

```bash
# Check version
./bin/gorecon version

# Validate plugins
./bin/gorecon plugins validate

# Test with a simple scan
./bin/gorecon step takeover --target example.com
```

## 🚨 Troubleshooting

### Common Issues

#### Go Not Found
```bash
# Install Go
wget https://go.dev/dl/go1.21.5.linux-amd64.tar.gz
sudo tar -C /usr/local -xzf go1.21.5.linux-amd64.tar.gz
echo 'export PATH=/usr/local/go/bin:$PATH' >> ~/.bashrc
```

#### Tools Not in PATH
```bash
# Add Go bin to PATH
echo 'export PATH="$HOME/go/bin:$PATH"' >> ~/.bashrc
echo 'export PATH="$HOME/.local/bin:$PATH"' >> ~/.bashrc
source ~/.bashrc
```

#### Permission Denied
```bash
# Make scripts executable
chmod +x scripts/*.sh

# Fix Go module permissions
go clean -modcache
```

#### Python/pip Issues
```bash
# Ubuntu/Debian
sudo apt-get install python3 python3-pip

# macOS
brew install python3

# Verify
python3 --version
pip3 --version
```

#### Node.js/npm Issues
```bash
# Ubuntu/Debian
curl -fsSL https://deb.nodesource.com/setup_lts.x | sudo -E bash -
sudo apt-get install -y nodejs

# macOS
brew install node

# Verify
node --version
npm --version
```

### Getting Help

#### Validation Command
```bash
# Check what's missing
./scripts/install-tools.sh --verify-only
```

#### Individual Tool Testing
```bash
# Test each tool
subzy --help
nuclei --help
paramspider --help
# ... etc
```

#### Debug Mode
```bash
# Run with verbose output
./scripts/install-tools.sh --minimal 2>&1 | tee install.log
```

## 📈 Next Steps

After successful installation:

1. **Test Basic Functionality**:
   ```bash
   ./bin/gorecon step takeover --target example.com
   ```

2. **Explore Available Stages**:
   ```bash
   ./bin/gorecon step
   ```

3. **Run Complete Pipeline**:
   ```bash
   ./bin/gorecon do-all --target example.com
   ```

4. **Read Documentation**:
   - Check `./bin/gorecon --help`
   - Explore stage-specific help: `./bin/gorecon step takeover --help`

## 🔄 Updates

### Update GoRecon
```bash
git pull origin main
make build
```

### Update Tools
```bash
# Re-run tool installation
make install-tools

# Or update specific tools manually
go install github.com/projectdiscovery/nuclei/v3/cmd/nuclei@latest
pip install --upgrade paramspider
```

### Update Nuclei Templates
```bash
nuclei -update-templates
```
#!/bin/bash
set -e

# GoRecon External Tool Installation Script
# This script installs the external security tools used by GoRecon plugins

INSTALL_DIR="/usr/local/bin"
TEMP_DIR="/tmp/gorecon-install"

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

# Logging functions
log_info() {
    echo -e "${BLUE}[INFO]${NC} $1"
}

log_success() {
    echo -e "${GREEN}[SUCCESS]${NC} $1"
}

log_warning() {
    echo -e "${YELLOW}[WARNING]${NC} $1"
}

log_error() {
    echo -e "${RED}[ERROR]${NC} $1"
}

# Check if running as root
check_permissions() {
    if [[ $EUID -eq 0 ]]; then
        log_warning "Running as root. Tools will be installed system-wide."
    else
        log_info "Running as user. Some installations may require sudo."
        INSTALL_DIR="$HOME/.local/bin"
        mkdir -p "$INSTALL_DIR"
        export PATH="$INSTALL_DIR:$PATH"
    fi
}

# Create temporary directory
setup_temp_dir() {
    log_info "Setting up temporary directory: $TEMP_DIR"
    mkdir -p "$TEMP_DIR"
    cd "$TEMP_DIR"
}

# Cleanup function
cleanup() {
    log_info "Cleaning up temporary files"
    rm -rf "$TEMP_DIR"
}

# Check if tool is already installed
is_installed() {
    command -v "$1" >/dev/null 2>&1
}

# Install Go if not present
install_go() {
    if is_installed go; then
        log_success "Go is already installed: $(go version)"
        return
    fi
    
    log_info "Installing Go..."
    
    # Detect architecture
    ARCH=$(uname -m)
    case $ARCH in
        x86_64) ARCH="amd64" ;;
        aarch64) ARCH="arm64" ;;
        armv7l) ARCH="armv6l" ;;
        *) log_error "Unsupported architecture: $ARCH"; exit 1 ;;
    esac
    
    # Detect OS
    OS=$(uname -s | tr '[:upper:]' '[:lower:]')
    
    GO_VERSION="1.22.0"
    GO_ARCHIVE="go${GO_VERSION}.${OS}-${ARCH}.tar.gz"
    GO_URL="https://golang.org/dl/${GO_ARCHIVE}"
    
    log_info "Downloading Go ${GO_VERSION} for ${OS}/${ARCH}"
    curl -sSL "$GO_URL" -o "$GO_ARCHIVE"
    
    # Install Go
    if [[ $EUID -eq 0 ]]; then
        tar -C /usr/local -xzf "$GO_ARCHIVE"
        echo 'export PATH=$PATH:/usr/local/go/bin' >> /etc/profile
    else
        mkdir -p "$HOME/go"
        tar -C "$HOME" -xzf "$GO_ARCHIVE"
        echo 'export PATH=$PATH:$HOME/go/bin' >> "$HOME/.bashrc"
        export PATH="$PATH:$HOME/go/bin"
    fi
    
    log_success "Go installed successfully"
}

# Install gau (GetAllURLs)
install_gau() {
    if is_installed gau; then
        log_success "gau is already installed"
        return
    fi
    
    log_info "Installing gau..."
    go install github.com/lc/gau/v2/cmd/gau@latest
    
    if is_installed gau; then
        log_success "gau installed successfully"
    else
        log_error "Failed to install gau"
        return 1
    fi
}

# Install cloud_enum
install_cloud_enum() {
    if is_installed cloud_enum; then
        log_success "cloud_enum is already installed"
        return
    fi
    
    log_info "Installing cloud_enum..."
    
    # Clone repository
    git clone https://github.com/initstring/cloud_enum.git
    cd cloud_enum
    
    # Install Python dependencies
    if command -v pip3 >/dev/null; then
        pip3 install -r requirements.txt
    elif command -v pip >/dev/null; then
        pip install -r requirements.txt
    else
        log_error "pip not found. Please install Python pip first."
        return 1
    fi
    
    # Make executable and move to bin
    chmod +x cloud_enum.py
    cp cloud_enum.py "$INSTALL_DIR/cloud_enum"
    cp -r enum_tools "$INSTALL_DIR/"
    
    cd ..
    
    if is_installed cloud_enum; then
        log_success "cloud_enum installed successfully"
    else
        log_error "Failed to install cloud_enum"
        return 1
    fi
}

# Install meg
install_meg() {
    if is_installed meg; then
        log_success "meg is already installed"
        return
    fi
    
    log_info "Installing meg..."
    go install github.com/tomnomnom/meg@latest
    
    if is_installed meg; then
        log_success "meg installed successfully"
    else
        log_error "Failed to install meg"
        return 1
    fi
}

# Install jsluice
install_jsluice() {
    if is_installed jsluice; then
        log_success "jsluice is already installed"
        return
    fi
    
    log_info "Installing jsluice..."
    go install github.com/BishopFox/jsluice/cmd/jsluice@latest
    
    if is_installed jsluice; then
        log_success "jsluice installed successfully"
    else
        log_error "Failed to install jsluice"
        return 1
    fi
}

# Install waybackurls (alternative to gau)
install_waybackurls() {
    if is_installed waybackurls; then
        log_success "waybackurls is already installed"
        return
    fi
    
    log_info "Installing waybackurls..."
    go install github.com/tomnomnom/waybackurls@latest
    
    if is_installed waybackurls; then
        log_success "waybackurls installed successfully"
    else
        log_error "Failed to install waybackurls"
        return 1
    fi
}

# Install subjack
install_subjack() {
    if is_installed subjack; then
        log_success "subjack is already installed"
        return
    fi
    
    log_info "Installing subjack..."
    go install github.com/haccer/subjack@latest
    
    if is_installed subjack; then
        log_success "subjack installed successfully"
    else
        log_error "Failed to install subjack"
        return 1
    fi
}

# Install httprobe
install_httprobe() {
    if is_installed httprobe; then
        log_success "httprobe is already installed"
        return
    fi
    
    log_info "Installing httprobe..."
    go install github.com/tomnomnom/httprobe@latest
    
    if is_installed httprobe; then
        log_success "httprobe installed successfully"
    else
        log_error "Failed to install httprobe"
        return 1
    fi
}

# Install paramspider
install_paramspider() {
    if is_installed paramspider; then
        log_success "paramspider is already installed"
        return
    fi
    
    log_info "Installing paramspider..."
    
    # Install via pip
    if command -v pip3 >/dev/null; then
        pip3 install paramspider
    elif command -v pip >/dev/null; then
        pip install paramspider
    else
        log_error "pip not found. Please install Python pip first."
        return 1
    fi
    
    if is_installed paramspider; then
        log_success "paramspider installed successfully"
    else
        log_error "Failed to install paramspider"
        return 1
    fi
}

# Install subzy
install_subzy() {
    if is_installed subzy; then
        log_success "subzy is already installed"
        return
    fi
    
    log_info "Installing subzy..."
    go install github.com/LukaSikic/subzy@latest
    
    if is_installed subzy; then
        log_success "subzy installed successfully"
    else
        log_error "Failed to install subzy"
        return 1
    fi
}

# Install hakrawler
install_hakrawler() {
    if is_installed hakrawler; then
        log_success "hakrawler is already installed"
        return
    fi
    
    log_info "Installing hakrawler..."
    go install github.com/hakluke/hakrawler@latest
    
    if is_installed hakrawler; then
        log_success "hakrawler installed successfully"
    else
        log_error "Failed to install hakrawler"
        return 1
    fi
}

# Install hakcheckurl
install_hakcheckurl() {
    if is_installed hakcheckurl; then
        log_success "hakcheckurl is already installed"
        return
    fi
    
    log_info "Installing hakcheckurl..."
    go install github.com/hakluke/hakcheckurl@latest
    
    if is_installed hakcheckurl; then
        log_success "hakcheckurl installed successfully"
    else
        log_error "Failed to install hakcheckurl"
        return 1
    fi
}

# Install ffuf
install_ffuf() {
    if is_installed ffuf; then
        log_success "ffuf is already installed"
        return
    fi
    
    log_info "Installing ffuf..."
    go install github.com/ffuf/ffuf/v2@latest
    
    if is_installed ffuf; then
        log_success "ffuf installed successfully"
    else
        log_error "Failed to install ffuf"
        return 1
    fi
}

# Install broken-link-checker (blc)
install_blc() {
    if is_installed blc; then
        log_success "broken-link-checker (blc) is already installed"
        return
    fi
    
    log_info "Installing broken-link-checker (blc)..."
    
    # Install via npm
    if command -v npm >/dev/null; then
        npm install -g broken-link-checker
    else
        log_error "npm not found. Please install Node.js and npm first."
        return 1
    fi
    
    if is_installed blc; then
        log_success "broken-link-checker (blc) installed successfully"
    else
        log_error "Failed to install broken-link-checker (blc)"
        return 1
    fi
}

# Install sni-scanner
install_sni_scanner() {
    if is_installed sni-scanner; then
        log_success "sni-scanner is already installed"
        return
    fi
    
    log_info "Installing sni-scanner..."
    
    # Clone and build sni-scanner
    git clone https://github.com/mhmdiaa/sni-scanner.git
    cd sni-scanner
    go build -o sni-scanner .
    cp sni-scanner "$INSTALL_DIR/"
    cd ..
    
    if is_installed sni-scanner; then
        log_success "sni-scanner installed successfully"
    else
        log_error "Failed to install sni-scanner"
        return 1
    fi
}

# Install additional tools
install_additional_tools() {
    log_info "Installing additional tools..."
    
    # Install common tools that are often available via package managers
    if command -v apt-get >/dev/null; then
        # Debian/Ubuntu
        sudo apt-get update
        sudo apt-get install -y curl wget git python3 python3-pip jq
    elif command -v yum >/dev/null; then
        # RHEL/CentOS
        sudo yum install -y curl wget git python3 python3-pip jq
    elif command -v brew >/dev/null; then
        # macOS
        brew install curl wget git python3 jq
    fi
    
    # Install additional Go tools
    log_info "Installing additional Go-based tools..."
    
    # assetfinder
    if ! is_installed assetfinder; then
        log_info "Installing assetfinder..."
        go install github.com/tomnomnom/assetfinder@latest
    fi
    
    # amass
    if ! is_installed amass; then
        log_info "Installing amass..."
        go install github.com/OWASP/Amass/v3/...@master
    fi
    
    # subfinder
    if ! is_installed subfinder; then
        log_info "Installing subfinder..."
        go install github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest
    fi
    
    # httpx
    if ! is_installed httpx; then
        log_info "Installing httpx..."
        go install github.com/projectdiscovery/httpx/cmd/httpx@latest
    fi
    
    # nuclei
    if ! is_installed nuclei; then
        log_info "Installing nuclei..."
        go install github.com/projectdiscovery/nuclei/v3/cmd/nuclei@latest
    fi
    
    # naabu (port scanner)
    if ! is_installed naabu; then
        log_info "Installing naabu..."
        go install github.com/projectdiscovery/naabu/v2/cmd/naabu@latest
    fi
    
    # masscan (if available on system)
    if ! is_installed masscan && command -v apt-get >/dev/null; then
        log_info "Installing masscan via apt..."
        sudo apt-get install -y masscan
    fi
}

# Verify installations
verify_installations() {
    log_info "Verifying tool installations..."
    
    # Core tools required by GoRecon
    core_tools=(
        "subzy"           # Subdomain takeover detection
        "nuclei"          # Vulnerability scanning
        "paramspider"     # Parameter discovery
        "hakrawler"       # Web crawling
        "ffuf"           # Directory fuzzing
        "jsluice"        # JavaScript analysis
        "hakcheckurl"    # HTTP URL checking
        "httpx"          # HTTP probing
        "gau"            # URL collection
        "waybackurls"    # Wayback machine URLs
        "cloud_enum"     # Cloud asset discovery
        "sni-scanner"    # SNI scanning
        "blc"            # Broken link checker
    )
    
    # Additional tools (optional)
    additional_tools=(
        "subfinder"      # Subdomain discovery
        "naabu"         # Port scanning
        "masscan"       # Fast port scanning
        "amass"         # Asset discovery
    )
    
    # Check core tools
    log_info "=== Core Tools (Required) ==="
    core_installed=0
    core_total=${#core_tools[@]}
    
    for tool in "${core_tools[@]}"; do
        tool_name=$(echo "$tool" | awk '{print $1}')  # Extract tool name without comment
        if is_installed "$tool_name"; then
            version_info=$(command -v "$tool_name" 2>/dev/null || echo "installed")
            log_success "$tool_name: $version_info"
            ((core_installed++))
        else
            log_error "$tool_name: not found"
        fi
    done
    
    # Check additional tools
    log_info "=== Additional Tools (Optional) ==="
    additional_installed=0
    additional_total=${#additional_tools[@]}
    
    for tool in "${additional_tools[@]}"; do
        tool_name=$(echo "$tool" | awk '{print $1}')  # Extract tool name without comment
        if is_installed "$tool_name"; then
            version_info=$(command -v "$tool_name" 2>/dev/null || echo "installed")
            log_success "$tool_name: $version_info"
            ((additional_installed++))
        else
            log_warning "$tool_name: not found (optional)"
        fi
    done
    
    total_installed=$((core_installed + additional_installed))
    total_tools=$((core_total + additional_total))
    
    log_info "Installation summary:"
    log_info "  Core tools: $core_installed/$core_total installed"
    log_info "  Additional tools: $additional_installed/$additional_total installed"
    log_info "  Total: $total_installed/$total_tools tools available"
    
    if [ $core_installed -eq $core_total ]; then
        log_success "All core tools installed successfully!"
        log_success "GoRecon is ready to use!"
        return 0
    else
        log_error "Some core tools are missing. GoRecon may not work properly."
        log_info "Run this script again or install missing tools manually."
        return 1
    fi
}

# Print usage information
print_usage() {
    echo "GoRecon Tool Installation Script"
    echo ""
    echo "Usage: $0 [OPTIONS]"
    echo ""
    echo "Options:"
    echo "  --help, -h          Show this help message"
    echo "  --install-dir DIR   Set installation directory (default: /usr/local/bin or ~/.local/bin)"
    echo "  --minimal          Install only core tools (gau, cloud_enum, meg, jsluice)"
    echo "  --verify-only      Only verify existing installations"
    echo ""
    echo "Environment Variables:"
    echo "  INSTALL_DIR        Override installation directory"
    echo ""
}

# Main installation function
main() {
    local minimal=false
    local verify_only=false
    
    # Parse arguments
    while [[ $# -gt 0 ]]; do
        case $1 in
            --help|-h)
                print_usage
                exit 0
                ;;
            --install-dir)
                INSTALL_DIR="$2"
                shift 2
                ;;
            --minimal)
                minimal=true
                shift
                ;;
            --verify-only)
                verify_only=true
                shift
                ;;
            *)
                log_error "Unknown option: $1"
                print_usage
                exit 1
                ;;
        esac
    done
    
    # Override with environment variable if set
    if [[ -n "$INSTALL_DIR_ENV" ]]; then
        INSTALL_DIR="$INSTALL_DIR_ENV"
    fi
    
    log_info "Starting GoRecon tool installation"
    log_info "Installation directory: $INSTALL_DIR"
    
    if [ "$verify_only" = true ]; then
        verify_installations
        exit $?
    fi
    
    # Trap cleanup function
    trap cleanup EXIT
    
    # Setup
    check_permissions
    setup_temp_dir
    
    # Install Go if needed
    install_go
    
    # Install core tools required by GoRecon
    log_info "Installing core tools..."
    install_subzy
    install_paramspider
    install_hakrawler
    install_hakcheckurl
    install_ffuf
    install_jsluice
    install_gau
    install_waybackurls
    install_cloud_enum
    install_sni_scanner
    install_blc
    
    # Install additional tools unless minimal mode
    if [ "$minimal" = false ]; then
        log_info "Installing additional tools..."
        install_additional_tools
    fi
    
    # Verify installations
    verify_installations
    
    # Final message
    echo ""
    log_success "Tool installation completed!"
    log_info "Make sure $INSTALL_DIR is in your PATH"
    
    if [[ $EUID -ne 0 ]]; then
        log_info "You may need to restart your shell or run: source ~/.bashrc"
    fi
    
    log_info "Test the installation with: gorecon plugins validate"
}

# Run main function
main "$@"
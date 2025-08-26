#!/bin/bash

# GoRecon Installation Script
# This script installs GoRecon and its dependencies

set -euo pipefail

# Configuration
PROJECT_NAME="gorecon"
REPO_URL="https://github.com/f2u0a0d3/GoRecon"
INSTALL_DIR="${INSTALL_DIR:-/usr/local/bin}"
CONFIG_DIR="${CONFIG_DIR:-$HOME/.gorecon}"
VERSION="${VERSION:-latest}"

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

print_usage() {
    cat << EOF
Usage: $0 [OPTIONS]

Install GoRecon security assessment framework.

OPTIONS:
    -h, --help          Show this help message
    -v, --version       Install specific version (default: latest)
    -d, --install-dir   Installation directory (default: ${INSTALL_DIR})
    -c, --config-dir    Configuration directory (default: ${CONFIG_DIR})
    --dev               Install development version
    --update            Update existing installation
    --uninstall         Uninstall GoRecon
    --deps-only         Install only dependencies

EXAMPLES:
    $0                          # Install latest version
    $0 -v v1.0.0               # Install specific version
    $0 --dev                   # Install development version
    $0 --update                # Update existing installation

EOF
}

detect_os() {
    case "$(uname -s)" in
        Linux*)
            if command -v apt-get >/dev/null 2>&1; then
                OS="ubuntu"
                PACKAGE_MANAGER="apt"
            elif command -v yum >/dev/null 2>&1; then
                OS="centos"
                PACKAGE_MANAGER="yum"
            elif command -v dnf >/dev/null 2>&1; then
                OS="fedora"
                PACKAGE_MANAGER="dnf"
            elif command -v pacman >/dev/null 2>&1; then
                OS="arch"
                PACKAGE_MANAGER="pacman"
            else
                OS="linux"
                PACKAGE_MANAGER="unknown"
            fi
            ;;
        Darwin*)
            OS="darwin"
            if command -v brew >/dev/null 2>&1; then
                PACKAGE_MANAGER="brew"
            else
                PACKAGE_MANAGER="unknown"
            fi
            ;;
        *)
            OS="unknown"
            PACKAGE_MANAGER="unknown"
            ;;
    esac
    
    case "$(uname -m)" in
        x86_64|amd64)
            ARCH="amd64"
            ;;
        aarch64|arm64)
            ARCH="arm64"
            ;;
        armv7l)
            ARCH="armv7"
            ;;
        *)
            ARCH="unknown"
            ;;
    esac
    
    log_info "Detected OS: ${OS} (${ARCH})"
}

check_permissions() {
    if [[ ! -w "${INSTALL_DIR}" ]]; then
        if [[ $EUID -ne 0 ]]; then
            log_error "Installation requires write access to ${INSTALL_DIR}"
            log_info "Please run with sudo or specify a different install directory with -d"
            exit 1
        fi
    fi
}

install_dependencies() {
    log_info "Installing system dependencies..."
    
    case "${PACKAGE_MANAGER}" in
        apt)
            apt-get update
            apt-get install -y curl wget git unzip ca-certificates python3 python3-pip
            ;;
        yum)
            yum update -y
            yum install -y curl wget git unzip ca-certificates python3 python3-pip
            ;;
        dnf)
            dnf update -y
            dnf install -y curl wget git unzip ca-certificates python3 python3-pip
            ;;
        brew)
            brew install curl wget git
            ;;
        pacman)
            pacman -Sy --noconfirm curl wget git unzip ca-certificates
            ;;
        *)
            log_warning "Unknown package manager. Please install curl, wget, git, and unzip manually."
            ;;
    esac
}

install_external_tools() {
    log_info "Installing external security tools..."
    
    local tools_dir="${CONFIG_DIR}/tools"
    mkdir -p "${tools_dir}"
    
    # Install gau
    log_info "Installing gau..."
    local gau_url="https://github.com/lc/gau/releases/latest/download/gau-${OS}-${ARCH}"
    if [[ "${OS}" == "darwin" ]]; then
        gau_url="https://github.com/lc/gau/releases/latest/download/gau-darwin-${ARCH}"
    elif [[ "${OS}" == "linux" ]]; then
        gau_url="https://github.com/lc/gau/releases/latest/download/gau-linux-${ARCH}"
    fi
    
    curl -sSL "${gau_url}" -o "${tools_dir}/gau" && chmod +x "${tools_dir}/gau" || log_warning "Failed to install gau"
    
    # Install meg
    log_info "Installing meg..."
    local meg_url="https://github.com/tomnomnom/meg/releases/latest/download/meg-${OS}-${ARCH}"
    if [[ "${OS}" == "darwin" ]]; then
        meg_url="https://github.com/tomnomnom/meg/releases/latest/download/meg-darwin-${ARCH}"
    elif [[ "${OS}" == "linux" ]]; then
        meg_url="https://github.com/tomnomnom/meg/releases/latest/download/meg-linux-${ARCH}"
    fi
    
    curl -sSL "${meg_url}" -o "${tools_dir}/meg" && chmod +x "${tools_dir}/meg" || log_warning "Failed to install meg"
    
    # Install jsluice
    log_info "Installing jsluice..."
    local jsluice_url="https://github.com/BishopFox/jsluice/releases/latest/download/jsluice-${OS}-${ARCH}"
    if [[ "${OS}" == "darwin" ]]; then
        jsluice_url="https://github.com/BishopFox/jsluice/releases/latest/download/jsluice-darwin-${ARCH}"
    elif [[ "${OS}" == "linux" ]]; then
        jsluice_url="https://github.com/BishopFox/jsluice/releases/latest/download/jsluice-linux-${ARCH}"
    fi
    
    curl -sSL "${jsluice_url}" -o "${tools_dir}/jsluice" && chmod +x "${tools_dir}/jsluice" || log_warning "Failed to install jsluice"
    
    # Install smap
    log_info "Installing smap..."
    if command -v go >/dev/null 2>&1; then
        go install github.com/s0md3v/smap/cmd/smap@latest || log_warning "Failed to install smap via go install"
    else
        log_warning "Go not found, skipping smap installation"
    fi
    
    # Install cloud_enum
    log_info "Installing cloud_enum..."
    local temp_dir=$(mktemp -d)
    curl -sSL "https://github.com/initstring/cloud_enum/archive/main.zip" -o "${temp_dir}/cloud_enum.zip"
    unzip -q "${temp_dir}/cloud_enum.zip" -d "${temp_dir}"
    sudo mkdir -p "/opt/cloud_enum"
    sudo cp -r "${temp_dir}/cloud_enum-main"/* "/opt/cloud_enum/"
    sudo chmod +x "/opt/cloud_enum/cloud_enum.py"
    rm -rf "${temp_dir}"
    
    log_success "External tools installed to ${tools_dir}"
}

download_gorecon() {
    log_info "Downloading GoRecon ${VERSION}..."
    
    local download_url
    local binary_name="${PROJECT_NAME}"
    local archive_name
    
    if [[ "${VERSION}" == "latest" ]]; then
        download_url="https://api.github.com/repos/f2u0a0d3/GoRecon/releases/latest"
        local latest_version
        latest_version=$(curl -sSL "${download_url}" | grep '"tag_name":' | cut -d'"' -f4)
        VERSION="${latest_version}"
    fi
    
    case "${OS}" in
        linux)
            archive_name="${PROJECT_NAME}-${VERSION}-linux-${ARCH}.tar.gz"
            ;;
        darwin)
            archive_name="${PROJECT_NAME}-${VERSION}-darwin-${ARCH}.tar.gz"
            ;;
        *)
            log_error "Unsupported operating system: ${OS}"
            exit 1
            ;;
    esac
    
    download_url="https://github.com/f2u0a0d3/GoRecon/releases/download/${VERSION}/${archive_name}"
    
    local temp_dir
    temp_dir=$(mktemp -d)
    
    log_info "Downloading from ${download_url}"
    if ! curl -sSL "${download_url}" -o "${temp_dir}/${archive_name}"; then
        log_error "Failed to download GoRecon. Please check the version and try again."
        log_info "Available releases: https://github.com/f2u0a0d3/GoRecon/releases"
        rm -rf "${temp_dir}"
        exit 1
    fi
    
    # Extract archive
    tar -xzf "${temp_dir}/${archive_name}" -C "${temp_dir}"
    
    # Install binary
    install -m 755 "${temp_dir}/${binary_name}" "${INSTALL_DIR}/${binary_name}"
    
    # Cleanup
    rm -rf "${temp_dir}"
    
    log_success "GoRecon ${VERSION} installed to ${INSTALL_DIR}/${binary_name}"
}

create_config() {
    log_info "Creating configuration directory..."
    
    mkdir -p "${CONFIG_DIR}"
    mkdir -p "${CONFIG_DIR}/profiles"
    mkdir -p "${CONFIG_DIR}/data"
    mkdir -p "${CONFIG_DIR}/cache"
    mkdir -p "${CONFIG_DIR}/reports"
    mkdir -p "${CONFIG_DIR}/logs"
    
    # Create default config
    if [[ ! -f "${CONFIG_DIR}/config.yaml" ]]; then
        cat > "${CONFIG_DIR}/config.yaml" << EOF
# GoRecon Configuration
data_dir: ${CONFIG_DIR}/data
log_level: info
log_file: ${CONFIG_DIR}/logs/gorecon.log

# Plugin configuration
plugins:
  enabled: true
  timeout: 300s
  
# Cache configuration
cache:
  enabled: true
  directory: ${CONFIG_DIR}/cache
  ttl: 24h
  
# Output configuration
output:
  directory: ${CONFIG_DIR}/reports
  format: ["json", "html"]
  
# Rate limiting
rate_limit:
  enabled: true
  requests_per_second: 10.0
  
# External tools
tools:
  directory: ${CONFIG_DIR}/tools
  
# API configuration (optional)
api:
  enabled: false
  host: localhost
  port: 8080
EOF
        
        log_info "Created default configuration at ${CONFIG_DIR}/config.yaml"
    fi
    
    # Create default profile
    if [[ ! -f "${CONFIG_DIR}/profiles/default.yaml" ]]; then
        cat > "${CONFIG_DIR}/profiles/default.yaml" << EOF
# Default Scan Profile
name: default
description: Default security assessment profile

plugins:
  - gau
  - cloud_enum
  - meg
  - jsluice
  - param_discovery

rate_limit:
  requests_per_second: 5.0
  human_mode: false

output:
  formats: ["json", "html"]
  include_metadata: true

intelligence:
  correlation: true
  risk_scoring: true
EOF
        
        log_info "Created default profile at ${CONFIG_DIR}/profiles/default.yaml"
    fi
}

setup_shell_completion() {
    log_info "Setting up shell completion..."
    
    local shell_name
    shell_name=$(basename "$SHELL")
    
    case "${shell_name}" in
        bash)
            if command -v "${PROJECT_NAME}" >/dev/null 2>&1; then
                "${PROJECT_NAME}" completion bash > "${CONFIG_DIR}/completion.bash"
                echo "# GoRecon completion" >> ~/.bashrc
                echo "source ${CONFIG_DIR}/completion.bash" >> ~/.bashrc
                log_info "Bash completion configured. Restart your shell or run 'source ~/.bashrc'"
            fi
            ;;
        zsh)
            if command -v "${PROJECT_NAME}" >/dev/null 2>&1; then
                "${PROJECT_NAME}" completion zsh > "${CONFIG_DIR}/completion.zsh"
                echo "# GoRecon completion" >> ~/.zshrc
                echo "source ${CONFIG_DIR}/completion.zsh" >> ~/.zshrc
                log_info "Zsh completion configured. Restart your shell or run 'source ~/.zshrc'"
            fi
            ;;
        fish)
            if command -v "${PROJECT_NAME}" >/dev/null 2>&1; then
                mkdir -p ~/.config/fish/completions
                "${PROJECT_NAME}" completion fish > ~/.config/fish/completions/${PROJECT_NAME}.fish
                log_info "Fish completion configured"
            fi
            ;;
        *)
            log_warning "Shell completion not configured for ${shell_name}"
            ;;
    esac
}

verify_installation() {
    log_info "Verifying installation..."
    
    if command -v "${PROJECT_NAME}" >/dev/null 2>&1; then
        local installed_version
        installed_version=$("${PROJECT_NAME}" version --short 2>/dev/null || echo "unknown")
        log_success "GoRecon installed successfully (version: ${installed_version})"
        
        # Test basic functionality
        if "${PROJECT_NAME}" --help >/dev/null 2>&1; then
            log_success "Basic functionality test passed"
        else
            log_warning "Basic functionality test failed"
        fi
    else
        log_error "GoRecon not found in PATH. Installation may have failed."
        log_info "Manually add ${INSTALL_DIR} to your PATH or use the full path: ${INSTALL_DIR}/${PROJECT_NAME}"
    fi
}

uninstall() {
    log_info "Uninstalling GoRecon..."
    
    # Remove binary
    if [[ -f "${INSTALL_DIR}/${PROJECT_NAME}" ]]; then
        rm -f "${INSTALL_DIR}/${PROJECT_NAME}"
        log_info "Removed binary from ${INSTALL_DIR}/${PROJECT_NAME}"
    fi
    
    # Ask before removing config
    echo -n "Remove configuration directory ${CONFIG_DIR}? [y/N]: "
    read -r response
    case "$response" in
        [yY][eE][sS]|[yY])
            rm -rf "${CONFIG_DIR}"
            log_info "Removed configuration directory"
            ;;
        *)
            log_info "Keeping configuration directory"
            ;;
    esac
    
    log_success "GoRecon uninstalled"
}

update_installation() {
    log_info "Updating GoRecon installation..."
    
    # Get current version
    local current_version="unknown"
    if command -v "${PROJECT_NAME}" >/dev/null 2>&1; then
        current_version=$("${PROJECT_NAME}" version --short 2>/dev/null || echo "unknown")
    fi
    
    # Download and install latest version
    download_gorecon
    
    log_success "Updated from ${current_version} to ${VERSION}"
}

main() {
    local install_deps=true
    local install_tools=true
    local setup_completion=true
    local uninstall_flag=false
    local update_flag=false
    local deps_only=false
    
    # Parse command line arguments
    while [[ $# -gt 0 ]]; do
        case $1 in
            -h|--help)
                print_usage
                exit 0
                ;;
            -v|--version)
                VERSION="$2"
                shift 2
                ;;
            -d|--install-dir)
                INSTALL_DIR="$2"
                shift 2
                ;;
            -c|--config-dir)
                CONFIG_DIR="$2"
                shift 2
                ;;
            --dev)
                VERSION="main"
                shift
                ;;
            --update)
                update_flag=true
                shift
                ;;
            --uninstall)
                uninstall_flag=true
                shift
                ;;
            --deps-only)
                deps_only=true
                shift
                ;;
            --no-deps)
                install_deps=false
                shift
                ;;
            --no-tools)
                install_tools=false
                shift
                ;;
            --no-completion)
                setup_completion=false
                shift
                ;;
            *)
                log_error "Unknown option: $1"
                print_usage
                exit 1
                ;;
        esac
    done
    
    log_info "GoRecon Installation Script"
    echo
    
    # Handle uninstall
    if [[ "${uninstall_flag}" == "true" ]]; then
        uninstall
        exit 0
    fi
    
    # Detect system
    detect_os
    
    # Check permissions
    check_permissions
    
    # Install dependencies
    if [[ "${install_deps}" == "true" ]]; then
        install_dependencies
    fi
    
    # Install external tools
    if [[ "${install_tools}" == "true" ]]; then
        install_external_tools
    fi
    
    # Exit if deps only
    if [[ "${deps_only}" == "true" ]]; then
        log_success "Dependencies installed successfully"
        exit 0
    fi
    
    # Handle update
    if [[ "${update_flag}" == "true" ]]; then
        update_installation
    else
        # Fresh installation
        download_gorecon
        create_config
    fi
    
    # Setup shell completion
    if [[ "${setup_completion}" == "true" ]]; then
        setup_shell_completion
    fi
    
    # Verify installation
    verify_installation
    
    echo
    log_success "GoRecon installation completed!"
    log_info "Configuration directory: ${CONFIG_DIR}"
    log_info "Run 'gorecon --help' to get started"
    log_info "Documentation: https://github.com/f2u0a0d3/GoRecon"
}

# Run main function
main "$@"
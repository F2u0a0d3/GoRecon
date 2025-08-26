#!/bin/bash
set -e

# GoRecon Development Environment Bootstrap Script
# This script sets up a complete development environment for GoRecon

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

# Check if command exists
command_exists() {
    command -v "$1" >/dev/null 2>&1
}

# Install system dependencies
install_system_dependencies() {
    log_info "Installing system dependencies..."
    
    if [[ "$OSTYPE" == "linux-gnu"* ]]; then
        # Linux
        if command_exists apt-get; then
            # Debian/Ubuntu
            sudo apt-get update
            sudo apt-get install -y \
                build-essential \
                git \
                curl \
                wget \
                python3 \
                python3-pip \
                nodejs \
                npm \
                jq \
                unzip \
                ca-certificates \
                gnupg \
                lsb-release
        elif command_exists yum; then
            # RHEL/CentOS
            sudo yum groupinstall -y "Development Tools"
            sudo yum install -y \
                git \
                curl \
                wget \
                python3 \
                python3-pip \
                nodejs \
                npm \
                jq \
                unzip
        elif command_exists pacman; then
            # Arch Linux
            sudo pacman -S --noconfirm \
                base-devel \
                git \
                curl \
                wget \
                python \
                python-pip \
                nodejs \
                npm \
                jq \
                unzip
        fi
    elif [[ "$OSTYPE" == "darwin"* ]]; then
        # macOS
        if ! command_exists brew; then
            log_info "Installing Homebrew..."
            /bin/bash -c "$(curl -fsSL https://raw.githubusercontent.com/Homebrew/install/HEAD/install.sh)"
        fi
        
        brew install \
            git \
            curl \
            wget \
            python3 \
            node \
            jq \
            unzip
    fi
    
    log_success "System dependencies installed"
}

# Install Go
install_go() {
    if command_exists go; then
        GO_VERSION=$(go version | cut -d' ' -f3 | sed 's/go//')
        log_success "Go is already installed: $GO_VERSION"
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
    
    # Download and install
    curl -sSL "$GO_URL" -o "/tmp/$GO_ARCHIVE"
    
    if [[ $EUID -eq 0 ]]; then
        tar -C /usr/local -xzf "/tmp/$GO_ARCHIVE"
        echo 'export PATH=$PATH:/usr/local/go/bin' >> /etc/profile
        export PATH=$PATH:/usr/local/go/bin
    else
        mkdir -p "$HOME/go-install"
        tar -C "$HOME/go-install" -xzf "/tmp/$GO_ARCHIVE"
        echo 'export PATH=$PATH:$HOME/go-install/go/bin' >> "$HOME/.bashrc"
        export PATH="$PATH:$HOME/go-install/go/bin"
    fi
    
    rm "/tmp/$GO_ARCHIVE"
    
    log_success "Go $GO_VERSION installed successfully"
}

# Setup Go environment
setup_go_environment() {
    log_info "Setting up Go environment..."
    
    # Set GOPATH if not set
    if [[ -z "$GOPATH" ]]; then
        export GOPATH="$HOME/go"
        echo 'export GOPATH=$HOME/go' >> "$HOME/.bashrc"
        echo 'export PATH=$PATH:$GOPATH/bin' >> "$HOME/.bashrc"
    fi
    
    # Create Go workspace directories
    mkdir -p "$GOPATH/src" "$GOPATH/bin" "$GOPATH/pkg"
    
    # Install common Go tools
    log_info "Installing Go development tools..."
    go install golang.org/x/tools/cmd/goimports@latest
    go install github.com/golangci/golangci-lint/cmd/golangci-lint@latest
    go install github.com/securecodewarrior/gosec/cmd/gosec@latest
    go install github.com/go-delve/delve/cmd/dlv@latest
    
    log_success "Go environment configured"
}

# Install Docker
install_docker() {
    if command_exists docker; then
        log_success "Docker is already installed"
        return
    fi
    
    log_info "Installing Docker..."
    
    if [[ "$OSTYPE" == "linux-gnu"* ]]; then
        # Linux
        curl -fsSL https://get.docker.com | sh
        
        # Add current user to docker group
        if [[ $EUID -ne 0 ]]; then
            sudo usermod -aG docker "$USER"
            log_warning "Please log out and back in to use Docker without sudo"
        fi
    elif [[ "$OSTYPE" == "darwin"* ]]; then
        # macOS
        log_info "Please install Docker Desktop for macOS from: https://docs.docker.com/desktop/mac/install/"
        return
    fi
    
    log_success "Docker installed"
}

# Install development tools
install_dev_tools() {
    log_info "Installing development tools..."
    
    # Install pre-commit
    if command_exists pip3; then
        pip3 install --user pre-commit
    elif command_exists pip; then
        pip install --user pre-commit
    fi
    
    # Install Node.js tools for documentation
    if command_exists npm; then
        npm install -g markdownlint-cli
    fi
    
    log_success "Development tools installed"
}

# Setup project environment
setup_project_environment() {
    log_info "Setting up project environment..."
    
    # Create necessary directories
    mkdir -p "$HOME/.gorecon"
    mkdir -p "$HOME/.gorecon/work"
    mkdir -p "$HOME/.gorecon/reports"
    mkdir -p "$HOME/.gorecon/cache"
    mkdir -p "$HOME/.gorecon/models"
    
    # Copy default configuration if it doesn't exist
    if [[ ! -f "$HOME/.gorecon/config.yaml" ]]; then
        if [[ -f "configs/default.yaml" ]]; then
            cp configs/default.yaml "$HOME/.gorecon/config.yaml"
            log_success "Default configuration copied to ~/.gorecon/config.yaml"
        fi
    fi
    
    # Create scope file template
    if [[ ! -f "$HOME/.gorecon/scope.txt" ]]; then
        cat > "$HOME/.gorecon/scope.txt" << EOF
# GoRecon Scope Configuration
# Lines starting with # are comments
# Use + for included domains/IPs
# Use - for excluded domains/IPs
# If no prefix is specified, + is assumed

# Example:
# +example.com
# +*.example.com
# -internal.example.com
# +192.168.1.0/24
# -192.168.1.1

# Add your targets here:
EOF
        log_success "Scope template created at ~/.gorecon/scope.txt"
    fi
    
    log_success "Project environment configured"
}

# Download dependencies
download_dependencies() {
    log_info "Downloading Go dependencies..."
    
    if [[ -f "go.mod" ]]; then
        go mod tidy
        go mod download
        log_success "Go dependencies downloaded"
    else
        log_warning "go.mod not found, skipping dependency download"
    fi
}

# Build project
build_project() {
    log_info "Building GoRecon..."
    
    if [[ -f "Makefile" ]]; then
        make build
    else
        go build -o build/gorecon ./cmd/gorecon
    fi
    
    if [[ -f "build/gorecon" ]]; then
        log_success "GoRecon built successfully"
    else
        log_error "Failed to build GoRecon"
        exit 1
    fi
}

# Setup git hooks
setup_git_hooks() {
    if [[ -d ".git" ]]; then
        log_info "Setting up Git hooks..."
        
        if command_exists pre-commit; then
            pre-commit install
            log_success "Pre-commit hooks installed"
        else
            log_warning "pre-commit not found, skipping hook installation"
        fi
    else
        log_warning "Not a Git repository, skipping hook setup"
    fi
}

# Install external tools
install_external_tools() {
    log_info "Installing external security tools..."
    
    if [[ -f "scripts/install-tools.sh" ]]; then
        chmod +x scripts/install-tools.sh
        ./scripts/install-tools.sh --minimal
    else
        log_warning "Tool installation script not found"
    fi
}

# Verify installation
verify_installation() {
    log_info "Verifying installation..."
    
    # Check Go
    if command_exists go; then
        log_success "Go: $(go version)"
    else
        log_error "Go not found"
    fi
    
    # Check Docker
    if command_exists docker; then
        log_success "Docker: $(docker --version)"
    else
        log_warning "Docker not found"
    fi
    
    # Check GoRecon binary
    if [[ -f "build/gorecon" ]]; then
        log_success "GoRecon binary: build/gorecon"
    else
        log_error "GoRecon binary not found"
    fi
    
    # Test GoRecon
    if [[ -f "build/gorecon" ]]; then
        if ./build/gorecon version >/dev/null 2>&1; then
            log_success "GoRecon is working correctly"
        else
            log_error "GoRecon is not working properly"
        fi
    fi
}

# Print next steps
print_next_steps() {
    echo ""
    log_success "Bootstrap completed successfully!"
    echo ""
    echo "Next steps:"
    echo "1. Restart your shell or run: source ~/.bashrc"
    echo "2. Edit ~/.gorecon/config.yaml to configure your settings"
    echo "3. Edit ~/.gorecon/scope.txt to define your scan scope"
    echo "4. Run: ./build/gorecon plugins validate"
    echo "5. Run: ./build/gorecon scan --target example.com --dry-run"
    echo ""
    echo "Development commands:"
    echo "• make build          - Build the project"
    echo "• make test           - Run tests"
    echo "• make lint           - Run linter"
    echo "• make install        - Install binary"
    echo ""
    echo "Documentation:"
    echo "• README.md           - Main documentation"
    echo "• docs/               - Additional documentation"
    echo ""
}

# Main function
main() {
    echo "🚀 GoRecon Development Environment Bootstrap"
    echo "============================================"
    echo ""
    
    # Check if we're in the right directory
    if [[ ! -f "go.mod" ]] || [[ ! -d "cmd/gorecon" ]]; then
        log_error "Please run this script from the GoRecon project root directory"
        exit 1
    fi
    
    # Install system dependencies
    install_system_dependencies
    
    # Install Go
    install_go
    
    # Setup Go environment
    setup_go_environment
    
    # Install Docker
    install_docker
    
    # Install development tools
    install_dev_tools
    
    # Setup project environment
    setup_project_environment
    
    # Download dependencies
    download_dependencies
    
    # Build project
    build_project
    
    # Setup git hooks
    setup_git_hooks
    
    # Install external tools
    install_external_tools
    
    # Verify installation
    verify_installation
    
    # Print next steps
    print_next_steps
}

# Run main function
main "$@"
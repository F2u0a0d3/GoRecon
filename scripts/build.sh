#!/bin/bash

# GoRecon Build Script
# This script builds the GoRecon binary for multiple platforms

set -euo pipefail

# Configuration
PROJECT_NAME="gorecon"
CMD_PATH="./cmd/gorecon"
BUILD_DIR="./bin"
VERSION="${VERSION:-$(git describe --tags --always --dirty 2>/dev/null || echo 'dev')}"
COMMIT="${COMMIT:-$(git rev-parse --short HEAD 2>/dev/null || echo 'unknown')}"
BUILD_DATE="${BUILD_DATE:-$(date -u +%Y-%m-%dT%H:%M:%SZ)}"

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

# Build flags
LDFLAGS=(
    "-s" "-w"
    "-X main.Version=${VERSION}"
    "-X main.Commit=${COMMIT}"
    "-X main.BuildDate=${BUILD_DATE}"
    "-X github.com/f2u0a0d3/GoRecon/pkg/version.Version=${VERSION}"
    "-X github.com/f2u0a0d3/GoRecon/pkg/version.Commit=${COMMIT}"
    "-X github.com/f2u0a0d3/GoRecon/pkg/version.BuildDate=${BUILD_DATE}"
)

# Target platforms
PLATFORMS=(
    "linux/amd64"
    "linux/arm64"
    "darwin/amd64"
    "darwin/arm64"
    "windows/amd64"
)

# Functions
print_usage() {
    cat << EOF
Usage: $0 [OPTIONS]

Build GoRecon for multiple platforms.

OPTIONS:
    -h, --help      Show this help message
    -v, --verbose   Enable verbose output
    -p, --platform  Build for specific platform (e.g., linux/amd64)
    -o, --output    Output directory (default: ${BUILD_DIR})
    --version       Set version string
    --dev           Development build (disable optimizations)
    --race          Enable race detection
    --clean         Clean build directory before building

EXAMPLES:
    $0                          # Build for all platforms
    $0 -p linux/amd64          # Build only for Linux AMD64
    $0 --dev                   # Development build
    $0 --clean -v              # Clean build with verbose output

EOF
}

clean_build_dir() {
    if [[ -d "${BUILD_DIR}" ]]; then
        log_info "Cleaning build directory: ${BUILD_DIR}"
        rm -rf "${BUILD_DIR}"
    fi
    mkdir -p "${BUILD_DIR}"
}

check_dependencies() {
    log_info "Checking dependencies..."
    
    if ! command -v go >/dev/null 2>&1; then
        log_error "Go is not installed or not in PATH"
        exit 1
    fi
    
    local go_version
    go_version=$(go version | awk '{print $3}' | sed 's/go//')
    log_info "Go version: ${go_version}"
    
    if ! command -v git >/dev/null 2>&1; then
        log_warning "Git is not available, version info may be incomplete"
    fi
}

download_dependencies() {
    log_info "Downloading Go modules..."
    go mod download
    go mod verify
}

run_tests() {
    log_info "Running tests..."
    go test -v ./...
    if [[ $? -eq 0 ]]; then
        log_success "All tests passed"
    else
        log_error "Tests failed"
        exit 1
    fi
}

build_for_platform() {
    local platform=$1
    local goos=${platform%/*}
    local goarch=${platform#*/}
    
    local binary_name="${PROJECT_NAME}"
    if [[ "${goos}" == "windows" ]]; then
        binary_name="${binary_name}.exe"
    fi
    
    local output_path="${BUILD_DIR}/${goos}-${goarch}/${binary_name}"
    
    log_info "Building for ${goos}/${goarch}..."
    
    env GOOS=${goos} GOARCH=${goarch} CGO_ENABLED=0 go build \
        -ldflags="${LDFLAGS[*]}" \
        ${BUILD_FLAGS:-} \
        -o "${output_path}" \
        "${CMD_PATH}"
    
    if [[ $? -eq 0 ]]; then
        local file_size
        file_size=$(du -h "${output_path}" | cut -f1)
        log_success "Built ${goos}/${goarch} (${file_size}): ${output_path}"
        
        # Create checksum
        if command -v sha256sum >/dev/null 2>&1; then
            (cd "$(dirname "${output_path}")" && sha256sum "$(basename "${output_path}")" > "${binary_name}.sha256")
        fi
    else
        log_error "Failed to build for ${goos}/${goarch}"
        return 1
    fi
}

create_archives() {
    log_info "Creating release archives..."
    
    for platform_dir in "${BUILD_DIR}"/*; do
        if [[ -d "${platform_dir}" ]]; then
            local platform_name=$(basename "${platform_dir}")
            local archive_name="${PROJECT_NAME}-${VERSION}-${platform_name}"
            
            cd "${platform_dir}"
            
            if [[ "${platform_name}" == *"windows"* ]]; then
                zip -q "../${archive_name}.zip" ./*
                log_info "Created ${archive_name}.zip"
            else
                tar -czf "../${archive_name}.tar.gz" ./*
                log_info "Created ${archive_name}.tar.gz"
            fi
            
            cd - >/dev/null
        fi
    done
}

generate_build_info() {
    local build_info_file="${BUILD_DIR}/build-info.json"
    
    cat > "${build_info_file}" << EOF
{
  "project": "${PROJECT_NAME}",
  "version": "${VERSION}",
  "commit": "${COMMIT}",
  "build_date": "${BUILD_DATE}",
  "go_version": "$(go version | awk '{print $3}' | sed 's/go//')",
  "platforms": [
EOF

    local first=true
    for platform in "${PLATFORMS[@]}"; do
        if [[ "${first}" == "true" ]]; then
            first=false
        else
            echo "," >> "${build_info_file}"
        fi
        echo -n "    \"${platform}\"" >> "${build_info_file}"
    done

    cat >> "${build_info_file}" << EOF

  ]
}
EOF

    log_info "Generated build info: ${build_info_file}"
}

main() {
    local verbose=false
    local clean=false
    local dev_build=false
    local race_detection=false
    local run_tests_flag=false
    local specific_platform=""
    
    # Parse command line arguments
    while [[ $# -gt 0 ]]; do
        case $1 in
            -h|--help)
                print_usage
                exit 0
                ;;
            -v|--verbose)
                verbose=true
                shift
                ;;
            -p|--platform)
                specific_platform="$2"
                shift 2
                ;;
            -o|--output)
                BUILD_DIR="$2"
                shift 2
                ;;
            --version)
                VERSION="$2"
                shift 2
                ;;
            --dev)
                dev_build=true
                shift
                ;;
            --race)
                race_detection=true
                shift
                ;;
            --clean)
                clean=true
                shift
                ;;
            --test)
                run_tests_flag=true
                shift
                ;;
            *)
                log_error "Unknown option: $1"
                print_usage
                exit 1
                ;;
        esac
    done
    
    # Set verbose output
    if [[ "${verbose}" == "true" ]]; then
        set -x
    fi
    
    # Set build flags based on options
    if [[ "${dev_build}" == "true" ]]; then
        BUILD_FLAGS="-race -gcflags=all=-N -l"
        log_warning "Development build enabled (race detection and no optimizations)"
    elif [[ "${race_detection}" == "true" ]]; then
        BUILD_FLAGS="-race"
        log_info "Race detection enabled"
    fi
    
    log_info "Starting GoRecon build process..."
    log_info "Version: ${VERSION}"
    log_info "Commit: ${COMMIT}"
    log_info "Build Date: ${BUILD_DATE}"
    
    # Clean if requested
    if [[ "${clean}" == "true" ]]; then
        clean_build_dir
    fi
    
    # Ensure build directory exists
    mkdir -p "${BUILD_DIR}"
    
    # Check dependencies
    check_dependencies
    
    # Download dependencies
    download_dependencies
    
    # Run tests if requested
    if [[ "${run_tests_flag}" == "true" ]]; then
        run_tests
    fi
    
    # Build for platforms
    local build_failed=false
    
    if [[ -n "${specific_platform}" ]]; then
        # Build for specific platform
        if ! build_for_platform "${specific_platform}"; then
            build_failed=true
        fi
    else
        # Build for all platforms
        for platform in "${PLATFORMS[@]}"; do
            if ! build_for_platform "${platform}"; then
                build_failed=true
            fi
        done
        
        # Create archives and build info for multi-platform builds
        if [[ "${build_failed}" == "false" ]]; then
            create_archives
            generate_build_info
        fi
    fi
    
    if [[ "${build_failed}" == "true" ]]; then
        log_error "Build failed for one or more platforms"
        exit 1
    fi
    
    log_success "Build completed successfully!"
    log_info "Artifacts created in: ${BUILD_DIR}"
    
    # Show build summary
    echo
    log_info "Build Summary:"
    find "${BUILD_DIR}" -name "${PROJECT_NAME}*" -type f | sort | while read -r file; do
        local size
        size=$(du -h "${file}" | cut -f1)
        echo "  - $(basename "${file}") (${size})"
    done
}

# Run main function
main "$@"
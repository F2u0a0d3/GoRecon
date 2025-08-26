# GoRecon Makefile
# Comprehensive build and deployment automation

# Project configuration
PROJECT_NAME := gorecon
BINARY_NAME := gorecon
PACKAGE := github.com/f2u0a0d3/GoRecon
CMD_PATH := ./cmd/gorecon

# Version information
VERSION ?= $(shell git describe --tags --always --dirty 2>/dev/null || echo "dev")
COMMIT ?= $(shell git rev-parse --short HEAD 2>/dev/null || echo "unknown")
BUILD_DATE ?= $(shell date -u +"%Y-%m-%dT%H:%M:%SZ")

# Build configuration
BUILD_DIR := ./bin
DIST_DIR := ./dist
DOCKER_IMAGE := $(PROJECT_NAME)
DOCKER_TAG ?= latest

# Go configuration
GO := go
GOFMT := gofmt
GOLINT := golangci-lint
GOTEST := $(GO) test
GOBUILD := $(GO) build
GOCLEAN := $(GO) clean
GOMOD := $(GO) mod

# Build flags
LDFLAGS := -s -w \
	-X main.Version=$(VERSION) \
	-X main.Commit=$(COMMIT) \
	-X main.BuildDate=$(BUILD_DATE) \
	-X $(PACKAGE)/pkg/version.Version=$(VERSION) \
	-X $(PACKAGE)/pkg/version.Commit=$(COMMIT) \
	-X $(PACKAGE)/pkg/version.BuildDate=$(BUILD_DATE)

BUILD_FLAGS := -ldflags "$(LDFLAGS)"
DEV_BUILD_FLAGS := -race -gcflags="all=-N -l"

# Colors for output
RED := \033[0;31m
GREEN := \033[0;32m
YELLOW := \033[1;33m
BLUE := \033[0;34m
NC := \033[0m # No Color

# Default target
.PHONY: all
all: clean deps test build

# Help target
.PHONY: help
help: ## Show this help message
	@echo "$(BLUE)GoRecon Build System$(NC)"
	@echo ""
	@echo "$(YELLOW)Available targets:$(NC)"
	@awk 'BEGIN {FS = ":.*?## "} /^[a-zA-Z_-]+:.*?## / {printf "  $(GREEN)%-20s$(NC) %s\n", $$1, $$2}' $(MAKEFILE_LIST)

# Development targets
.PHONY: dev
dev: ## Build for development with debug symbols
	@echo "$(BLUE)Building for development...$(NC)"
	$(GOBUILD) $(DEV_BUILD_FLAGS) -o $(BUILD_DIR)/$(BINARY_NAME) $(CMD_PATH)
	@echo "$(GREEN)Development build complete: $(BUILD_DIR)/$(BINARY_NAME)$(NC)"

.PHONY: run
run: dev ## Build and run the application
	@echo "$(BLUE)Running $(BINARY_NAME)...$(NC)"
	$(BUILD_DIR)/$(BINARY_NAME) --help

# Build targets
.PHONY: build
build: ## Build the binary for current platform
	@echo "$(BLUE)Building $(BINARY_NAME)...$(NC)"
	@mkdir -p $(BUILD_DIR)
	CGO_ENABLED=0 $(GOBUILD) $(BUILD_FLAGS) -o $(BUILD_DIR)/$(BINARY_NAME) $(CMD_PATH)
	@echo "$(GREEN)Build complete: $(BUILD_DIR)/$(BINARY_NAME)$(NC)"

.PHONY: build-all
build-all: clean ## Build for all platforms
	@echo "$(BLUE)Building for all platforms...$(NC)"
	@./scripts/build.sh --clean --verbose
	@echo "$(GREEN)Multi-platform build complete$(NC)"

# Dependencies
.PHONY: deps
deps: ## Download and verify dependencies
	@echo "$(BLUE)Downloading dependencies...$(NC)"
	$(GOMOD) download
	$(GOMOD) verify
	@echo "$(GREEN)Dependencies updated$(NC)"

# Testing
.PHONY: test
test: ## Run tests
	@echo "$(BLUE)Running tests...$(NC)"
	$(GOTEST) -v -race -coverprofile=coverage.out ./...
	@echo "$(GREEN)Tests complete$(NC)"

# Code quality
.PHONY: fmt
fmt: ## Format Go code
	@echo "$(BLUE)Formatting code...$(NC)"
	$(GOFMT) -s -w .
	@echo "$(GREEN)Code formatted$(NC)"

.PHONY: lint
lint: ## Run linter
	@echo "$(BLUE)Running linter...$(NC)"
	@command -v $(GOLINT) >/dev/null 2>&1 || (echo "$(YELLOW)Installing golangci-lint...$(NC)" && curl -sSfL https://raw.githubusercontent.com/golangci/golangci-lint/master/install.sh | sh -s -- -b $$(go env GOPATH)/bin)
	$(GOLINT) run ./...
	@echo "$(GREEN)Linting complete$(NC)"

.PHONY: vet
vet: ## Run go vet
	@echo "$(BLUE)Running go vet...$(NC)"
	$(GO) vet ./...
	@echo "$(GREEN)Vet complete$(NC)"

.PHONY: check
check: fmt vet lint test ## Run all code quality checks

# Docker targets
.PHONY: docker-build
docker-build: ## Build Docker image
	@echo "$(BLUE)Building Docker image...$(NC)"
	docker build -f deployments/docker/Dockerfile -t $(DOCKER_IMAGE):$(DOCKER_TAG) .
	@echo "$(GREEN)Docker image built: $(DOCKER_IMAGE):$(DOCKER_TAG)$(NC)"

.PHONY: docker-compose-up
docker-compose-up: ## Start services with docker-compose
	@echo "$(BLUE)Starting services with docker-compose...$(NC)"
	cd deployments/docker && docker-compose up -d
	@echo "$(GREEN)Services started$(NC)"

.PHONY: docker-compose-down
docker-compose-down: ## Stop services with docker-compose
	@echo "$(BLUE)Stopping services with docker-compose...$(NC)"
	cd deployments/docker && docker-compose down
	@echo "$(GREEN)Services stopped$(NC)"

# Kubernetes targets
.PHONY: k8s-deploy
k8s-deploy: ## Deploy to Kubernetes
	@echo "$(BLUE)Deploying to Kubernetes...$(NC)"
	kubectl apply -f deployments/kubernetes/
	@echo "$(GREEN)Kubernetes deployment complete$(NC)"

.PHONY: k8s-delete
k8s-delete: ## Delete Kubernetes resources
	@echo "$(BLUE)Deleting Kubernetes resources...$(NC)"
	kubectl delete -f deployments/kubernetes/ --ignore-not-found=true
	@echo "$(GREEN)Kubernetes resources deleted$(NC)"

# Installation targets
.PHONY: install
install: build ## Install binary to system
	@echo "$(BLUE)Installing $(BINARY_NAME)...$(NC)"
	@sudo cp $(BUILD_DIR)/$(BINARY_NAME) /usr/local/bin/
	@echo "$(GREEN)$(BINARY_NAME) installed to /usr/local/bin/$(NC)"

.PHONY: install-tools
install-tools: ## Install external security tools
	@echo "$(BLUE)Installing external security tools...$(NC)"
	@chmod +x scripts/install-tools.sh
	@./scripts/install-tools.sh
	@echo "$(GREEN)Tools installation complete$(NC)"

.PHONY: install-tools-minimal
install-tools-minimal: ## Install minimal set of tools
	@echo "$(BLUE)Installing minimal set of tools...$(NC)"
	@chmod +x scripts/install-tools.sh
	@./scripts/install-tools.sh --minimal
	@echo "$(GREEN)Minimal tools installation complete$(NC)"

.PHONY: verify-tools
verify-tools: ## Verify tool installations
	@echo "$(BLUE)Verifying tool installations...$(NC)"
	@chmod +x scripts/install-tools.sh
	@./scripts/install-tools.sh --verify-only

.PHONY: setup
setup: build install-tools ## Complete setup (build + install tools)
	@echo "$(GREEN)GoRecon setup complete!$(NC)"
	@echo "$(YELLOW)Run 'gorecon --help' to get started$(NC)"

# Cleanup targets
.PHONY: clean
clean: ## Clean build artifacts
	@echo "$(BLUE)Cleaning build artifacts...$(NC)"
	@rm -rf $(BUILD_DIR) $(DIST_DIR)
	@$(GOCLEAN)
	@rm -f coverage.out coverage.html
	@echo "$(GREEN)Clean complete$(NC)"

# Utility targets
.PHONY: version
version: ## Show version information
	@echo "Project: $(PROJECT_NAME)"
	@echo "Version: $(VERSION)"
	@echo "Commit: $(COMMIT)"
	@echo "Build Date: $(BUILD_DATE)"

# CI/CD helpers
.PHONY: ci
ci: deps check test build ## Run CI pipeline
	@echo "$(GREEN)CI pipeline complete$(NC)"

# Show available make targets
.DEFAULT_GOAL := help
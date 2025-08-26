# GoRecon Dockerfile
# Multi-stage build for optimal image size and security

# Build stage
FROM golang:1.22-alpine AS builder

# Install build dependencies
RUN apk add --no-cache \
    git \
    ca-certificates \
    tzdata \
    make \
    gcc \
    musl-dev

# Set working directory
WORKDIR /build

# Copy go mod and sum files
COPY go.mod go.sum ./

# Download dependencies
RUN go mod download
RUN go mod verify

# Copy source code
COPY . .

# Build arguments
ARG VERSION=dev
ARG COMMIT=unknown
ARG BUILD_TIME=unknown

# Build the binary
RUN CGO_ENABLED=0 GOOS=linux GOARCH=amd64 go build \
    -ldflags "-X main.version=${VERSION} -X main.commit=${COMMIT} -X main.buildTime=${BUILD_TIME} -s -w" \
    -o gorecon \
    ./cmd/gorecon

# Runtime stage
FROM alpine:3.18

# Install runtime dependencies and security tools
RUN apk add --no-cache \
    ca-certificates \
    tzdata \
    curl \
    wget \
    nmap \
    nmap-scripts \
    git \
    python3 \
    py3-pip \
    nodejs \
    npm \
    bash \
    jq \
    && rm -rf /var/cache/apk/*

# Install common security tools
RUN pip3 install --no-cache-dir \
    requests \
    beautifulsoup4 \
    colorama

# Create non-root user
RUN addgroup -g 1001 -S gorecon && \
    adduser -u 1001 -S gorecon -G gorecon

# Create necessary directories
RUN mkdir -p /app /etc/gorecon /var/lib/gorecon /var/log/gorecon /workspace && \
    chown -R gorecon:gorecon /app /etc/gorecon /var/lib/gorecon /var/log/gorecon /workspace

# Copy binary from builder stage
COPY --from=builder /build/gorecon /app/gorecon

# Copy configuration files
COPY configs/default.yaml /etc/gorecon/config.yaml
COPY configs/profiles/ /etc/gorecon/profiles/
COPY scripts/install-tools.sh /app/install-tools.sh

# Make scripts executable
RUN chmod +x /app/gorecon /app/install-tools.sh

# Switch to non-root user
USER gorecon

# Set working directory
WORKDIR /app

# Install additional tools (as non-root user)
RUN ./install-tools.sh || true

# Expose ports
EXPOSE 8080 8081 9090

# Health check
HEALTHCHECK --interval=30s --timeout=10s --start-period=40s --retries=3 \
    CMD ./gorecon health || exit 1

# Default command
CMD ["./gorecon", "server", "--config", "/etc/gorecon/config.yaml"]

# Labels for better maintainability
LABEL \
    org.opencontainers.image.title="GoRecon" \
    org.opencontainers.image.description="Intelligence-driven penetration testing orchestrator" \
    org.opencontainers.image.version="${VERSION}" \
    org.opencontainers.image.revision="${COMMIT}" \
    org.opencontainers.image.created="${BUILD_TIME}" \
    org.opencontainers.image.source="https://github.com/gorecon/gorecon" \
    org.opencontainers.image.documentation="https://docs.gorecon.io" \
    org.opencontainers.image.vendor="GoRecon Team" \
    org.opencontainers.image.licenses="MIT"
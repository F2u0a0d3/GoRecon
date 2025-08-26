# Multi-stage build for GoRecon
# Stage 1: Build the application
FROM golang:1.22-alpine AS builder

# Install build dependencies
RUN apk add --no-cache git ca-certificates tzdata gcc musl-dev

# Set working directory
WORKDIR /app

# Copy go mod files
COPY go.mod go.sum ./

# Download dependencies
RUN go mod download

# Copy source code
COPY . .

# Build the application
RUN CGO_ENABLED=0 GOOS=linux go build -a -installsuffix cgo -o gorecon ./cmd/gorecon

# Stage 2: Create the runtime image
FROM alpine:3.18

# Install runtime dependencies and security tools
RUN apk add --no-cache \
    ca-certificates \
    curl \
    wget \
    git \
    unzip \
    bash \
    jq \
    python3 \
    py3-pip \
    nmap \
    nmap-scripts \
    masscan \
    bind-tools \
    whois \
    && rm -rf /var/cache/apk/*

# Install external security tools
RUN wget -O /usr/local/bin/gau https://github.com/lc/gau/releases/latest/download/gau-linux-amd64 \
    && chmod +x /usr/local/bin/gau

RUN wget -O /tmp/cloud_enum.zip https://github.com/initstring/cloud_enum/archive/main.zip \
    && unzip /tmp/cloud_enum.zip -d /opt/ \
    && mv /opt/cloud_enum-main /opt/cloud_enum \
    && chmod +x /opt/cloud_enum/cloud_enum.py \
    && rm /tmp/cloud_enum.zip

RUN wget -O /usr/local/bin/meg https://github.com/tomnomnom/meg/releases/latest/download/meg-linux-amd64 \
    && chmod +x /usr/local/bin/meg

RUN wget -O /usr/local/bin/jsluice https://github.com/BishopFox/jsluice/releases/latest/download/jsluice-linux-amd64 \
    && chmod +x /usr/local/bin/jsluice

# Create non-root user
RUN addgroup -g 1000 gorecon && \
    adduser -D -s /bin/bash -u 1000 -G gorecon gorecon

# Create application directories
RUN mkdir -p /app/data /app/config /app/logs /app/cache /app/reports \
    && chown -R gorecon:gorecon /app

# Copy binary from builder stage
COPY --from=builder /app/gorecon /usr/local/bin/gorecon
RUN chmod +x /usr/local/bin/gorecon

# Copy configuration files
COPY configs/ /app/config/
COPY profiles/ /app/profiles/

# Set ownership
RUN chown -R gorecon:gorecon /app

# Switch to non-root user
USER gorecon

# Set working directory
WORKDIR /app

# Create default config if it doesn't exist
RUN if [ ! -f /app/config/config.yaml ]; then \
        echo "# GoRecon Configuration" > /app/config/config.yaml; \
        echo "data_dir: /app/data" >> /app/config/config.yaml; \
        echo "log_level: info" >> /app/config/config.yaml; \
        echo "cache:" >> /app/config/config.yaml; \
        echo "  directory: /app/cache" >> /app/config/config.yaml; \
        echo "output:" >> /app/config/config.yaml; \
        echo "  directory: /app/reports" >> /app/config/config.yaml; \
    fi

# Health check
HEALTHCHECK --interval=30s --timeout=10s --start-period=5s --retries=3 \
    CMD gorecon health || exit 1

# Expose ports
EXPOSE 8080 8081 8082

# Default command
CMD ["gorecon", "--config", "/app/config/config.yaml"]
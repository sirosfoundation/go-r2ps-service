# Build stage
FROM golang:1.26-alpine AS builder
WORKDIR /app
RUN apk add --no-cache git ca-certificates gcc musl-dev
COPY go.mod go.sum ./
RUN go mod download
COPY . .
RUN CGO_ENABLED=1 GOOS=linux go build \
    -ldflags="-s -w" \
    -o r2ps-server ./cmd/server

# Runtime stage
FROM alpine:3.24
WORKDIR /app

# Security: upgrade all packages, install minimal deps, create non-root user
RUN apk add --no-cache --upgrade ca-certificates softhsm curl && \
    adduser -D -u 1000 -h /app -s /sbin/nologin appuser && \
    rm -rf /var/cache/apk/*

COPY --from=builder --chown=appuser:appuser --chmod=0555 /app/r2ps-server /app/r2ps-server

# Install siros-integrity-guard (static musl binary from GitHub Releases)
ARG INTEGRITY_GUARD_VERSION=latest
ADD --chmod=0555 https://github.com/sirosfoundation/siros-integrity-guard/releases/${INTEGRITY_GUARD_VERSION}/download/siros-integrity-guard /usr/bin/siros-integrity-guard

# Generate integrity manifest: hash all protected files
RUN DIGEST=$(sha256sum /app/r2ps-server | awk '{print $1}') && \
    printf '{"version":1,"files":[{"path":"/app/r2ps-server","digest":"%s"}],"signature":"unsigned-placeholder"}' "$DIGEST" \
    > /app/manifest.json && \
    chown appuser:appuser /app/manifest.json && chmod 0444 /app/manifest.json

# SoftHSM2 token directory
RUN mkdir -p /var/lib/softhsm/tokens && chown appuser:appuser /var/lib/softhsm/tokens

# Drop all capabilities
ENV R2PS_LOG_LEVEL=WARN \
    R2PS_LOG_FORMAT=json \
    PKCS11_MODULE=/usr/lib/softhsm/libsofthsm2.so \
    PKCS11_SLOT=0 \
    INTEGRITY_KEY_LABEL=integrity-guard

USER appuser
EXPOSE 8443
HEALTHCHECK --interval=30s --timeout=5s --start-period=5s --retries=3 \
    CMD curl -sf http://localhost:8443/healthz || exit 1
ENTRYPOINT ["/usr/bin/siros-integrity-guard", \
    "--manifest", "/app/manifest.json", \
    "--exec", "/app/r2ps-server"]

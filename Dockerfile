# Build stage
FROM golang:1.26-alpine AS builder
WORKDIR /app
RUN apk add --no-cache git ca-certificates gcc musl-dev pkcs11-helper-dev softhsm
COPY go.mod go.sum ./
RUN go mod download
COPY . .
RUN CGO_ENABLED=1 GOOS=linux go build \
    -ldflags="-s -w" \
    -o r2ps-server ./cmd/server

# Runtime stage
FROM alpine:3.23
WORKDIR /app
RUN apk add --no-cache --upgrade ca-certificates softhsm curl && \
    adduser -D -u 1000 appuser

COPY --from=builder /app/r2ps-server /app/r2ps-server

# SoftHSM2 token directory
RUN mkdir -p /var/lib/softhsm/tokens && chown appuser:appuser /var/lib/softhsm/tokens

ENV R2PS_LOG_LEVEL=WARN \
    R2PS_LOG_FORMAT=json

USER appuser
EXPOSE 8443
HEALTHCHECK --interval=30s --timeout=5s --start-period=5s --retries=3 \
    CMD curl -sf http://localhost:8443/healthz || exit 1
ENTRYPOINT ["/app/r2ps-server"]

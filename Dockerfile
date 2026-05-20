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
RUN apk add --no-cache ca-certificates softhsm wget
COPY --from=builder /app/r2ps-server /app/r2ps-server
RUN adduser -D -u 1000 appuser

# SoftHSM2 token directory
RUN mkdir -p /var/lib/softhsm/tokens && chown appuser:appuser /var/lib/softhsm/tokens

USER appuser
EXPOSE 8443
HEALTHCHECK --interval=30s --timeout=5s --start-period=5s --retries=3 \
    CMD wget --no-verbose --tries=1 --spider http://localhost:8443/health || exit 1
ENTRYPOINT ["/app/r2ps-server"]

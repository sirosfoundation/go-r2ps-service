# go-r2ps-service

R2PS (Remote PAKE-Protected Services) server implementation in Go.

Implements the [DIGG R2PS specification](https://github.com/diggsweden/wallet-r2ps-specification)
for secure remote HSM key operations with OPAQUE (RFC 9807) authentication and
end-to-end JWE encryption. All cryptographic key operations are performed via
PKCS#11 (SoftHSM2 for development, hardware HSM for production).

## Package Structure

```
cmd/server/          HTTP server entry point
internal/
  crypto/            JWS signing/verification, JWE encryption, ECDH
  hsm/               PKCS#11 backend (key generation, ECDSA, ECDH)
  pake/              OPAQUE server (registration, authentication, sessions)
  service/           Request dispatcher, HSM service handlers
pkg/
  client/            R2PS client library (register, authenticate, call service)
  r2ps/              Protocol types and constants
test/integration/    End-to-end tests (SoftHSM2)
```

## Dependencies

| Package | Purpose |
|---------|---------|
| `bytemare/opaque` v0.18.0 | OPAQUE RFC 9807 (P256Sha256) |
| `go-jose/go-jose/v4` | JWS/JWE compact serialization |
| `miekg/pkcs11` v1.1.2 | PKCS#11 CGo bindings |

## Quick Start

```bash
make build
make test
```

### Docker

```bash
cd deployments
docker compose up
```

### Environment Variables

| Variable | Default | Description |
|----------|---------|-------------|
| `R2PS_HSM_MODULE` | `/usr/lib/softhsm/libsofthsm2.so` | PKCS#11 module path |
| `R2PS_HSM_TOKEN_LABEL` | `r2ps` | HSM token label |
| `R2PS_HSM_PIN` | (required) | HSM user PIN |
| `R2PS_HSM_SLOT` | (auto) | Slot number (optional, finds by label) |

## Architecture

See [security/go-r2ps-service-plan.md](../security/go-r2ps-service-plan.md) and
[security/remote-wscd-architecture.md](../security/remote-wscd-architecture.md).

## Development

```bash
make setup    # Configure git hooks, download deps, verify build
make check    # Format, vet, test
make coverage # Generate coverage report
```

## License

BSD 2-Clause. See [LICENSE](LICENSE).

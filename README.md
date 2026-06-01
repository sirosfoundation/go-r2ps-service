# go-r2ps-service

<div align="center">

[![CI](https://github.com/sirosfoundation/go-r2ps-service/actions/workflows/ci.yml/badge.svg)](https://github.com/sirosfoundation/go-r2ps-service/actions/workflows/ci.yml)
[![Go Reference](https://pkg.go.dev/badge/github.com/sirosfoundation/go-r2ps-service.svg)](https://pkg.go.dev/github.com/sirosfoundation/go-r2ps-service)
[![Go Report Card](https://goreportcard.com/badge/github.com/sirosfoundation/go-r2ps-service)](https://goreportcard.com/report/github.com/sirosfoundation/go-r2ps-service)
[![Coverage](https://raw.githubusercontent.com/sirosfoundation/go-r2ps-service/badges/.badges/main/coverage.svg)](https://github.com/sirosfoundation/go-r2ps-service/actions/workflows/ci.yml)
[![Go Version](https://img.shields.io/github/go-mod/go-version/sirosfoundation/go-r2ps-service)](https://go.dev/)
[![GHCR](https://img.shields.io/badge/ghcr.io-sirosfoundation%2Fgo--r2ps--service-blue)](https://ghcr.io/sirosfoundation/go-r2ps-service)
[![License](https://img.shields.io/badge/License-BSD_2--Clause-orange.svg)](LICENSE)

</div>

R2PS (Remote PAKE-Protected Services) server implementation in Go.

Implements the R2PS protocol for secure remote HSM key operations with OPAQUE
(RFC 9807) authentication and end-to-end JWE encryption. All cryptographic key
operations are performed via PKCS#11 (SoftHSM2 for development, hardware HSM
for production).

## Specification

The authoritative R2PS protocol specifications are maintained in
[docs/specs/](docs/specs/):

| Document | Description |
|----------|-------------|
| [r2ps.md](docs/specs/r2ps.md) | Base protocol — E2EE transport, 1FA/2FA modes, JWE/JWS structure |
| [r2ps-service-types.md](docs/specs/r2ps-service-types.md) | Service types, message structure, 2FA mechanisms |
| [r2ps-service-types-register.md](docs/specs/r2ps-service-types-register.md) | Registry of all service types |
| [r2ps-service-types-eudiw.md](docs/specs/r2ps-service-types-eudiw.md) | EUDIW profile (eudiw_wka_etsi, eudiw_wia_etsi) |
| [r2ps-appendix-a.md](docs/specs/r2ps-appendix-a.md) | Service type creation framework/template |

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

See [docs/adr/](docs/adr/) for architecture decision records and
[docs/specs/](docs/specs/) for the authoritative protocol specifications.

## Development

```bash
make setup    # Configure git hooks, download deps, verify build
make check    # Format, vet, test
make coverage # Generate coverage report
```

## License

BSD 2-Clause. See [LICENSE](LICENSE).

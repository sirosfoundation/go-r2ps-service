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

Implements the R2PS protocol for secure remote cryptographic operations with
OPAQUE (RFC 9807) authentication and JWS-signed request/response envelopes.
All cryptographic key operations are performed via PKCS#11 (SoftHSM2 for
development, hardware HSM for production).

The server acts as both a **WSCD backend** (remote key generation, ECDSA
signing, ECDH agreement via PKCS#11) and a **WSCA** (Wallet Key Attestation
and Wallet Instance Attestation issuance per ETSI TS 119 476-3 / CS-04).

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
  audit/             Structured audit event logging
  crypto/            JWS signing/verification, ECDH
  hsm/               PKCS#11 backend (key generation, ECDSA, ECDH)
  pake/              OPAQUE server (registration, authentication, sessions)
  service/           Request dispatcher, HSM + EUDIW service handlers
  statuslist/        Token Status List publisher (RFC 9701)
  store/             Lifecycle state persistence (in-memory, MongoDB)
pkg/
  client/            R2PS client library (register, authenticate, call service)
  r2ps/              Protocol types and constants
test/integration/    End-to-end tests (SoftHSM2)
```

## Implemented Service Types

| Identifier | Purpose | Mode | WSCD/WSCA role |
|---|---|---|---|
| `2fa_registration` | Establish OPAQUE credential | 1FA | — |
| `2fa_authenticate` | Verify OPAQUE and open session | 1FA | — |
| `2fa_change` | Replace OPAQUE credential | 2FA | — |
| `p256_generate` | Generate P-256 key in HSM | 1FA | WSCD |
| `sign_ecdsa` | ECDSA sign with HSM key | 2FA | WSCD |
| `agree_ecdh` | ECDH agreement with HSM key | 2FA | WSCD |
| `hsm_list_keys` | List keys in HSM | 2FA | WSCD |
| `eudiw_wka_etsi` | Issue Wallet Key Attestation | 1FA | WSCA |
| `eudiw_wia_etsi` | Issue Wallet Instance Attestation | 1FA | WSCA |
| `eudiw_wi_revoke` | Revoke wallet instance attestations | 1FA | WSCA |
| `eudiw_wi_suspend` | Suspend wallet instance attestations | 1FA | WSCA |

See the [service type registry](docs/specs/r2ps-service-types-register.md) for
the full list including planned types.

## Dependencies

| Package | Purpose |
|---------|---------|
| `bytemare/opaque` v0.18.0 | OPAQUE RFC 9807 (P256Sha256) |
| `go-jose/go-jose/v4` | JWS/JWE compact serialization |
| `miekg/pkcs11` v1.1.2 | PKCS#11 CGo bindings |
| `mongo-driver` v1.17.9 | MongoDB persistence (optional) |

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

#### HSM / PKCS#11

| Variable | Default | Description |
|----------|---------|-------------|
| `R2PS_HSM_MODULE` | `/usr/lib/softhsm/libsofthsm2.so` | PKCS#11 module path |
| `R2PS_HSM_TOKEN_LABEL` | `r2ps` | HSM token label |
| `R2PS_HSM_PIN` | (required) | HSM user PIN |
| `R2PS_HSM_SLOT` | (auto) | Slot number (optional, finds by label) |

#### Wallet Provider (WSCA)

| Variable | Default | Description |
|----------|---------|-------------|
| `R2PS_WP_WALLET_NAME` | `SIROS EUDI Wallet` | `wallet_name` in WIA |
| `R2PS_WP_WALLET_VERSION` | `1.0.0` | `wallet_version` in WIA |
| `R2PS_WP_WALLET_LINK` | (empty) | `wallet_link` in WIA/WKA |
| `R2PS_WP_STATUS_LIST_BASE` | `https://wp.example.com/statuslists` | Base URI for status lists |
| `R2PS_WP_WKA_TTL` | `24h` | WKA time-to-live |
| `R2PS_WP_WIA_TTL` | `12h` | WIA time-to-live (MUST < 24h per CS-04) |
| `R2PS_WP_STATUS_MAINT` | `744h` (31d) | Status maintenance period |
| `R2PS_WP_X5C_PATH` | (empty) | PEM file with x5c certificate chain |

#### Lifecycle Store (MongoDB)

| Variable | Default | Description |
|----------|---------|-------------|
| `R2PS_STORE_URI` | (empty) | MongoDB connection URI; if unset, in-memory store is used |
| `R2PS_STORE_DATABASE` | `r2ps` | MongoDB database name |
| `R2PS_STORE_TIMEOUT` | `10` | MongoDB connect timeout (seconds) |

#### Server

| Variable | Default | Description |
|----------|---------|-------------|
| `R2PS_MAX_ATTEMPTS` | `5` | Max failed auth attempts before lockout |
| `R2PS_LOCKOUT_DURATION` | `15m` | Lockout duration after max attempts |
| `R2PS_SESSION_TTL` | `5m` | 2FA session time-to-live |

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

# ADR-001: Cryptographic Libraries

## Status

Accepted

## Context

The R2PS service handles sensitive cryptographic operations: PAKE authentication, JWS/JWE message envelopes, ECDSA signing, ECDH key agreement, and EC key generation via hardware security modules.

## Decision

No custom cryptographic primitives. All operations use established, maintained libraries:

- **PAKE (OPAQUE)**: `github.com/bytemare/opaque` — implements RFC 9497
- **JWS/JWE**: `github.com/go-jose/go-jose/v4` — JOSE standard implementation
- **PKCS#11 (HSM)**: `github.com/miekg/pkcs11` — CGO bindings to PKCS#11 C API
- **Standard library**: `crypto/ecdsa`, `crypto/elliptic`, `crypto/sha256` for non-HSM operations

## Rationale

Cryptography is hard to get right. A mistake in a primitive has cascading security implications for the entire R2PS protocol — which protects PID issuance and presentation flows.

## Consequences

- Dependencies tracked by Dependabot (weekly), CI runs `govulncheck`
- Library upgrades are security-critical and must be prioritized
- Custom crypto code is prohibited without explicit security review
- PKCS#11 bindings require CGO — impacts cross-compilation and static analysis

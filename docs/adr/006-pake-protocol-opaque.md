# ADR-006: PAKE Protocol Selection (OPAQUE)

## Status

Accepted

## Context

R2PS requires PIN-based authentication between the wallet and the remote WSCD. The protocol must resist offline dictionary attacks — a passive or active attacker who intercepts the authentication exchange must not be able to brute-force the PIN offline.

## Decision

Use OPAQUE (RFC 9497) via `github.com/bytemare/opaque` with the P256Sha256 configuration.

The authentication flow is:
1. **Registration**: Client sends OPAQUE registration request → server returns response → client sends record → server stores it
2. **Authentication**: Client sends KE1 → server returns KE2 + PAKE session ID → client sends KE3 → server verifies MAC and marks session as verified
3. **Service**: Authenticated session key encrypts subsequent HSM operation requests

## Rationale

- OPAQUE is an asymmetric PAKE — the server never sees the PIN in any form
- Resistant to offline dictionary attacks even if the server's credential file is compromised
- Standardized in RFC 9497 with security proofs
- `bytemare/opaque` is the most complete Go implementation with active maintenance
- The P256Sha256 suite aligns with the ECDSA/ECDH operations already in the HSM backend

## Consequences

- OPAQUE credential records must be persisted (currently in-memory — production needs durable storage)
- The `bytemare/opaque` API is pre-1.0 — breaking changes may occur on upgrade
- Session keys are ephemeral and must not be logged at any level
- Lockout policy (max attempts + duration) is enforced server-side to limit online brute-force

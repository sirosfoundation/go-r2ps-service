# ADR-009: Input Validation at Service Boundary

## Status

Accepted

## Context

R2PS accepts JWS-wrapped requests over HTTP POST. After JWS verification and JSON parsing, handler-specific fields (kid, hash, curve, peer public key) are passed to the HSM backend. Invalid inputs that reach PKCS#11 can cause panics, undefined behavior, or cryptic HSM errors.

## Decision

Validate all inputs at the handler layer before calling the HSM backend:

| Field | Rule |
|---|---|
| `kid` | `^[a-zA-Z0-9_-]{1,128}$` — alphanumeric, dash, underscore |
| `hash` | Decoded length must be 32, 48, or 64 bytes (SHA-256/384/512) |
| `curve` | Must be `P-256`, `P-384`, or `P-521` (enforced by `curveOID()`) |
| `peer_pub_key` | Decoded length must match compressed (33/49/67) or uncompressed (65/97/133) EC point sizes |
| HTTP body | Limited to 1 MB via `io.LimitReader` |

## Rationale

- PKCS#11 modules vary in how they handle malformed inputs — some panic, some return opaque errors
- Kid format validation prevents injection into HSM attribute lookups
- Hash length validation catches truncation/padding bugs before they reach the HSM
- Body size limits prevent denial-of-service via large payloads

## Consequences

- New handler types must define and enforce input constraints
- Validation errors return generic messages (per ADR-007) — no internal details leaked
- Overly strict validation may reject edge-case inputs — monitor error rates after deployment

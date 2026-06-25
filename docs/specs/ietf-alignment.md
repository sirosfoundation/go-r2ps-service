# IETF Internet-Draft Alignment

This document maps the go-r2ps-service implementation to the IETF
Internet-Draft
[draft-santesson-r2ps-00](https://datatracker.ietf.org/doc/draft-santesson-r2ps/)
(15 June 2026), identifies discrepancies, and tracks planned changes.

The Internet-Draft defines the **base protocol** — JWE/JWS envelopes,
1FA/2FA protection modes, and three service types for second-factor
establishment. This implementation extends the base protocol with
WSCD and WSCA service types (PKCS#11 operations, EUDIW attestations)
that are out of scope for the I-D.

## Service Type Naming

| I-D name (§4.3.4) | Implementation | Status |
|--------------------|----------------|--------|
| `create_session` | `2fa_authenticate` | **Divergent** — predates I-D |
| `2fa_registration` | `2fa_registration` | Aligned |
| `2fa_update` | `2fa_change` | **Divergent** — predates I-D |

The implementation names were chosen before the I-D was published.
The I-D names are more descriptive (`create_session` makes it clear
that the output is a session; `2fa_update` is more natural than
`2fa_change`). Backward-compatible aliases exist in `pkg/r2ps/types.go`.

**Plan**: Add I-D names as primary identifiers; keep current names as
aliases for backward compatibility.

## JWS Payload Fields

### Common fields (I-D §4.2)

| I-D field | Implementation field | Status |
|-----------|---------------------|--------|
| `ver` | `ver` | Aligned — both use `"1.0"` |
| `nonce` | `nonce` | Aligned |
| `iat` | `iat` | Aligned |
| `data` | `data` | Aligned |
| `type` | `type` | Aligned (request only) |
| `jwe_hash` | *(not implemented)* | **Missing** — see below |

### Request-only fields

| I-D field | Implementation field | Status |
|-----------|---------------------|--------|
| `jwe_hash` | *(not present)* | **Missing** |
| `client_id` | `client_id` | Present in impl, not in I-D base payload |
| `context` | `context` | Present in impl, not in I-D base payload |
| `2fa_session_id` | `2fa_session_id` | Present in impl, carried via JWE `kid` in I-D |

**`jwe_hash`**: The I-D requires a SHA-256 digest of the JWE protected
header to bind the inner JWS to the outer JWE and prevent surreptitious
forwarding. The implementation does not currently compute or verify
`jwe_hash`.

**Plan**: Implement `jwe_hash` computation in JWE encryption and
verification in JWS decryption.

**`client_id` / `context`**: The I-D carries these in the JWE header
(`apu`/`apv`) rather than in the JWS payload. The implementation
includes them in the JWS payload for simplicity since the dispatcher
needs them before JWE decryption. Both approaches achieve the same
binding; the I-D approach is cleaner cryptographically.

## 2FA Data Fields

| I-D field (§4.3.1) | Implementation field | Status |
|---------------------|---------------------|--------|
| `protocol` | `2fa_mode` | **Divergent** — same semantics |
| `state` | `state` | Aligned |
| `p_data` | `request` / `response` | **Divergent** — I-D uses single `p_data` for both directions |
| `authorization` | `authorization` | Aligned |
| `authorization_type` | *(not implemented)* | **Missing** — we accept OTP implicitly |
| `task` | *(partially)* | SAD task binding exists but uses different format |
| `session_duration` | *(not implemented)* | **Missing** — we use fixed `R2PS_SESSION_TTL` |
| `session_id` | `2fa_session_id` | Aligned semantics, different name |
| `session_expiration_time` | `session_expiration_time` | Aligned |
| `success` | *(implicit)* | **Missing** — we return error responses instead |

**`protocol` vs `2fa_mode`**: The I-D names this field `protocol`; our
implementation calls it `2fa_mode`. Both identify the authentication
mechanism (`opaque`, `fido2`).

**`p_data` vs `request`/`response`**: The I-D uses a single `p_data`
field for protocol-specific data in both directions. Our implementation
uses separate `request` (in requests) and `response` (in responses)
fields. The I-D approach is simpler.

**`success`**: The I-D requires a boolean `success` field in every
response. Our implementation signals failure via HTTP error codes and
`ErrorResponse` JSON outside the JWE/JWS envelope. The I-D approach is
better for in-band error reporting within the encrypted channel.

## JWE Structure

### 1FA Mode (I-D §4.1.1)

| I-D requirement | Implementation | Status |
|-----------------|----------------|--------|
| `typ: r2ps-1fa` | *(not set)* | **Missing** |
| `alg: ECDH-ES` | `ECDH-ES` | Aligned |
| `enc: A256GCM` | `A256GCM` | Aligned |
| `epk` | Ephemeral key | Aligned |
| `kid` | Recipient key ID | Aligned |
| `apu: client_id` (req) / `context` (resp) | Set | Aligned |
| `apv: context` (req) / `client_id` (resp) | Set | Aligned |
| `cty: JWT` | Set | Aligned |

### 2FA Mode (I-D §4.1.2)

| I-D requirement | Implementation | Status |
|-----------------|----------------|--------|
| `typ: r2ps-2fa` | *(not set)* | **Missing** |
| `alg: dir` | `A256KW` | **Divergent** |
| `enc: A256GCM` | `A256GCM` | Aligned |
| `kid: session_id` | `session_id` | Aligned |
| `cty: JWT` | Set | Aligned |

**2FA key wrapping**: The I-D specifies `alg: dir` (session key used
directly as CEK). Our implementation uses `alg: A256KW` with an
HKDF-derived KEK from the session key, which provides directional
key separation (c2s vs s2c). This is a deliberate design choice that
is arguably more secure but diverges from the I-D.

**JWE `typ`**: The I-D uses `typ` to distinguish 1FA from 2FA mode.
Our implementation infers the mode from the presence of
`2fa_session_id` in the request payload. Adding `typ` is straightforward.

## Nonce Entropy

The I-D requires "at least 16 bytes of entropy" for the nonce. Our
implementation validates ≥8 bytes after base64 decoding.

**Plan**: Increase minimum to 16 bytes to align with I-D.

## Base64 Encoding

The I-D specifies standard base64 (RFC 4648 §4, with padding) for
binary values in the JWS payload. Our implementation uses base64url
(RFC 4648 §5, no padding), which is the standard for JWS/JWT contexts
per RFC 7515.

**Assessment**: Our choice is consistent with JWS conventions and is
what implementors expect. The I-D may be updated to clarify this.

## Authentication Protocols

### OPAQUE (I-D §4.3.5.1)

| I-D requirement | Implementation | Status |
|-----------------|----------------|--------|
| Protocol ID: `opaque` | `opaque` (via `2fa_mode`) | Aligned |
| States: `evaluate`, `finalize` | `evaluate`, `finalize` | Aligned |
| OPAQUE config: P256Sha256 | P256Sha256 | Aligned |
| AKE messages as base64 strings | base64url strings | See base64 note above |
| Registration + authentication flows | Both implemented | Aligned |

### FIDO2 (I-D §4.3.5.2)

| I-D requirement | Implementation | Status |
|-----------------|----------------|--------|
| Protocol ID: `fido2` | `fido2` (via `2fa_mode`) | Aligned |
| States: `challenge`, `finalize` | `challenge`, `finalize` | Aligned (registration uses `register`) |
| Challenge response: `challenge`, `token`, `user_verification` | All present | Aligned |
| Finalize request: `token`, `assertion{...}` | Assertion fields present | Aligned |
| Finalize response: `server_epub` | `server_epub` | Aligned |
| Session key: HKDF with DST `r2ps-2fa_authentication-fido2` | Implemented | Aligned |
| Transcript hash: SHA256(mode \|\| client_epub \|\| server_epub \|\| task \|\| sig) | Implemented | Aligned |
| Registration attestation verification (7 steps) | WebAuthn library | Aligned |

## Error Codes (I-D §4.2.2.2)

| I-D code | Implementation constant | HTTP | Status |
|----------|------------------------|------|--------|
| `ILLEGAL_REQUEST_DATA` | `ErrIllegalRequestData` | 400 | Aligned |
| `UNAUTHORIZED` | `ErrUnauthorized` | 401 | Aligned |
| `ACCESS_DENIED` | `ErrAccessDenied` | 403 | Aligned |
| `ILLEGAL_STATE` | `ErrIllegalState` | 409 | Aligned |
| `UNSUPPORTED_REQUEST_TYPE` | `ErrUnsupportedType` | 415 | Aligned |
| `SERVER_ERROR` | `ErrServerError` | 500 | Aligned |
| `TRY_LATER` | `ErrTryLater` | 503 | Aligned |

The I-D recommends RFC 9457 (Problem Details for HTTP APIs) for error
responses. Our implementation uses a simpler `{"error_code", "error_message"}`
JSON structure.

## Features Beyond I-D Scope

The following are implemented but not covered by draft-santesson-r2ps:

- **WSCD service types**: `p256_generate`, `sign_ecdsa`, `agree_ecdh`, `hsm_list_keys`
- **EUDIW attestation service types**: `eudiw_wka_etsi`, `eudiw_wia_etsi`, `eudiw_wi_revoke`, `eudiw_wi_suspend`
- **Token Status List** (RFC 9701) for WKA/WIA revocation/suspension
- **Signature Activation Data (SAD)** task binding for signing sessions
- **PKCS#11 session pooling** for concurrent HSM access
- **MongoDB lifecycle persistence**
- **Prometheus metrics**
- **Admin API** for status list management

The I-D §6 ("Definition of service types") is marked TBD and will
provide guidance on defining new service types. Our service type
definitions in [r2ps-service-types-register.md](r2ps-service-types-register.md)
follow the template in [r2ps-appendix-a.md](r2ps-appendix-a.md).

## Priority of Alignment Work

1. **High**: Add `jwe_hash` computation and verification
2. **High**: Add I-D service type names as primary identifiers (`create_session`, `2fa_update`)
3. **Medium**: Add `success` field to all 2FA responses
4. **Medium**: Add JWE `typ` headers (`r2ps-1fa`, `r2ps-2fa`)
5. **Medium**: Rename `2fa_mode` → `protocol`, `request`/`response` → `p_data`
6. **Low**: Increase nonce minimum to 16 bytes
7. **Low**: Add `session_duration` support
8. **Low**: Add `authorization_type` field
9. **Deferred**: Evaluate `alg: dir` vs `A256KW` for 2FA mode (security trade-off)

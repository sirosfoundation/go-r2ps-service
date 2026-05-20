# R2PS Protocol Specification

**Version:** 1.0  
**Status:** Implementation Draft  
**Date:** 2026-05-20

## 1. Introduction

R2PS (Remote PAKE-Protected Services) is a protocol for secure remote access
to Hardware Security Module (HSM) key operations.  It provides:

- **PIN-based authentication** using the OPAQUE augmented PAKE protocol
  (RFC 9497), so that the server never learns the user's PIN.
- **End-to-end encryption** of all service data using JWE (RFC 7516).
- **JWS integrity** (RFC 7515) on every request and response.
- **Session management** with configurable TTL, lockout, and cleanup.

The protocol is designed for use by EUDI Wallet instances that delegate
cryptographic key operations (ECDSA signing, ECDH key agreement, key
generation) to a remote WSCD (Wallet Secure Cryptographic Device).

### 1.1 Terminology

| Term | Definition |
|------|-----------|
| **Client** | The wallet application initiating requests. |
| **Server** | The R2PS service managing HSM key operations. |
| **HSM** | Hardware Security Module accessed via PKCS#11. |
| **kid** | Key identifier — a 32-character hex string derived from `SHA-256(compressed_public_key)[:16]`. |
| **context** | A namespace for grouping keys and sessions (e.g. `"signing"`). |
| **client_id** | A stable identifier for the wallet instance (e.g. a URI). |
| **PAKE session** | A session established by OPAQUE authentication, carrying a shared session key. |

### 1.2 Conventions

- All binary values in JSON are encoded as base64url (RFC 4648 §5) **with padding**.
- All timestamps (`iat`, `session_expiration_time`) are Unix epoch seconds.
- JWS uses compact serialization with content type `JOSE`.
- JWE uses compact serialization with content type `application/octet-stream`.

## 2. Transport

### 2.1 HTTP Binding

All protocol messages are exchanged over a single HTTP endpoint:

```
POST /r2ps
Content-Type: application/jose
```

The request body is a JWS compact serialization.  The response body is either:

- **Success:** JWS compact serialization (`Content-Type: application/jose`,
  HTTP 200).
- **Error:** JSON error object (`Content-Type: application/json`,
  HTTP 4xx/5xx).

The server enforces a maximum request body size of 1 MB.

### 2.2 TLS

The server supports direct TLS termination (configured via `R2PS_TLS_CERT`
and `R2PS_TLS_KEY`) or may run behind a TLS-terminating reverse proxy.
TLS 1.2 is the minimum supported version.

### 2.3 Observability Endpoints

| Path | Method | Purpose |
|------|--------|---------|
| `/healthz` | GET | Liveness probe — always returns `{"status":"ok"}` |
| `/readyz` | GET | Readiness probe — probes HSM connectivity |
| `/metrics` | GET | Prometheus metrics |

## 3. Message Format

### 3.1 Envelope Structure

Every R2PS exchange follows the same envelope pattern:

1. The sender constructs a **service request/response** JSON object.
2. The JSON is signed as a **JWS** (ES256/ES384/ES512) in compact serialization.
3. The JWS is sent as the HTTP body.

The JWS payload contains an inner `data` field that carries the
operation-specific data as an encrypted JWE compact serialization string.

#### 3.1.1 Cryptographic Algorithms

| Purpose | Algorithm | Notes |
|---------|-----------|-------|
| JWS signing | ES256, ES384, ES512 | Selected by key curve |
| JWE key agreement (device mode) | ECDH-ES+A256KW | Ephemeral-static ECDH |
| JWE content encryption | A256GCM | |
| JWE symmetric (user mode) | dir + A256GCM | Key from OPAQUE session |

#### 3.1.2 Service Request

```json
{
  "ver": "1.0",
  "nonce": "<base64url random>",
  "iat": 1700000000,
  "enc": "device" | "user",
  "data": "<JWE compact serialization>",
  "client_id": "https://example.com/wallet/1",
  "kid": "a1b2c3d4e5f6...",
  "context": "signing",
  "type": "<service type>",
  "pake_session_id": "<session ID, if authenticated>"
}
```

| Field | Type | Required | Description |
|-------|------|----------|-------------|
| `ver` | string | Yes | Protocol version. Must be `"1.0"`. |
| `nonce` | string | Yes | Client-generated random nonce (base64url). Echoed in the response. |
| `iat` | integer | Yes | Issued-at timestamp (Unix seconds). |
| `enc` | string | Yes | Encryption mode for `data`. See §3.1.4. |
| `data` | string | Yes | JWE compact serialization of the operation payload. |
| `client_id` | string | Yes | Stable client identifier. |
| `kid` | string | Yes | Key identifier for the target key. |
| `context` | string | Yes | Namespace for the operation. |
| `type` | string | Yes | Service type identifier. See §4 and §5. |
| `pake_session_id` | string | Conditional | Required for `enc=user` requests and authentication finalize. |

#### 3.1.3 Service Response

```json
{
  "ver": "1.0",
  "nonce": "<echoed from request>",
  "iat": 1700000000,
  "enc": "device" | "user",
  "data": "<JWE compact serialization>"
}
```

| Field | Type | Description |
|-------|------|-------------|
| `ver` | string | Protocol version. |
| `nonce` | string | Echoed from the request. |
| `iat` | integer | Server-issued timestamp. |
| `enc` | string | Encryption mode matching the response context. |
| `data` | string | JWE compact serialization of the response payload. |

#### 3.1.4 Encryption Modes

| Mode | Value | Key Source | Used For |
|------|-------|-----------|----------|
| **Device** | `"device"` | ECDH-ES+A256KW with server's static public key | PAKE registration and authentication |
| **User** | `"user"` | Direct keying with OPAQUE session key (first 32 bytes) | Authenticated service requests |

In **device** mode, the client encrypts the `data` field to the server's
static EC public key using ECDH-ES+A256KW (with an ephemeral client key).
The server decrypts using its corresponding private key.

In **user** mode, both client and server use the shared session key
derived from the OPAQUE AKE exchange.  The key is used as a direct
symmetric key with A256GCM content encryption.

### 3.2 Error Response

On failure, the server returns a JSON error instead of a JWS:

```json
{
  "error_code": "UNAUTHORIZED",
  "error_message": "session not found or expired"
}
```

| Error Code | HTTP Status | Meaning |
|------------|-------------|---------|
| `ILLEGAL_REQUEST_DATA` | 400 | Malformed request, bad JWS, decryption failure |
| `ILLEGAL_STATE` | 400 | Invalid type/state combination |
| `UNSUPPORTED_REQUEST_TYPE` | 400 | Unknown service type |
| `UNAUTHORIZED` | 401 | Authentication failed or session invalid |
| `ACCESS_DENIED` | 403 | Account locked due to failed attempts |
| `SERVER_ERROR` | 500 | Internal server error |
| `TRY_LATER` | 503 | Service temporarily unavailable |

Error messages are intentionally generic and never expose HSM internals,
key identifiers, or PKCS#11 error codes.

## 4. PAKE Authentication

All service requests (§5) require an authenticated session.  Sessions are
established using the OPAQUE protocol (RFC 9497) with the P256Sha256
cipher suite.

### 4.1 PAKE Data Structures

#### 4.1.1 PAKE Request (inner `data` payload)

```json
{
  "protocol": "opaque",
  "state": "evaluate" | "finalize",
  "authorization": "<optional>",
  "task": "<optional task identifier>",
  "session_duration": 300,
  "req": "<base64url-encoded OPAQUE message>"
}
```

| Field | Type | Required | Description |
|-------|------|----------|-------------|
| `protocol` | string | Yes | Must be `"opaque"`. |
| `state` | string | Yes | Phase of the PAKE exchange. |
| `authorization` | string | No | Optional authorization token. |
| `task` | string | No | Task binding for the session. |
| `session_duration` | integer | No | Requested session duration in seconds. |
| `req` | string | Yes | Base64url-encoded OPAQUE protocol message. |

#### 4.1.2 PAKE Response (inner `data` payload)

```json
{
  "pake_session_id": "<session identifier>",
  "resp": "<base64url-encoded OPAQUE message>",
  "msg": "<human-readable status>",
  "task": "<echoed task>",
  "session_expiration_time": 1700000300
}
```

| Field | Type | Presence | Description |
|-------|------|----------|-------------|
| `pake_session_id` | string | Conditional | Session ID, returned in auth-evaluate. |
| `resp` | string | Conditional | Base64url-encoded OPAQUE response message. |
| `msg` | string | Conditional | Status message (e.g. `"registration complete"`, `"authenticated"`). |
| `task` | string | Conditional | Echoed task identifier. |
| `session_expiration_time` | integer | Conditional | Unix timestamp when the session expires. |

### 4.2 PIN Registration

PIN registration stores the user's OPAQUE credential on the server without
the server ever learning the PIN.  It is a two-phase exchange.

The credential identifier is `client_id + "|" + kid`.

#### Phase 1: Evaluate

```
Client                                    Server
  |                                         |
  |  type=pin_registration, state=evaluate  |
  |  req = RegistrationRequest.Serialize()  |
  |---------------------------------------->|
  |                                         |  RegistrationResponse(req, credID)
  |  resp = RegistrationResponse            |
  |<----------------------------------------|
```

#### Phase 2: Finalize

```
Client                                    Server
  |                                         |
  |  type=pin_registration, state=finalize  |
  |  req = RegistrationRecord.Serialize()   |
  |---------------------------------------->|
  |                                         |  PutRecord(clientID, kid, record)
  |  msg = "registration complete"          |
  |<----------------------------------------|
```

### 4.3 Authentication

Authentication establishes a shared session key using the OPAQUE AKE
(Authenticated Key Exchange).  It is a two-phase exchange.

#### Phase 1: Evaluate (KE1 → KE2)

```
Client                                    Server
  |                                         |
  |  type=authenticate, state=evaluate      |
  |  req = KE1.Serialize()                  |
  |  task = "<optional task>"               |
  |---------------------------------------->|
  |                                         |  Check lockout
  |                                         |  GetRecord(clientID, kid)
  |                                         |  GenerateKE2(ke1, record)
  |                                         |  Create session (unverified)
  |  pake_session_id = "<session ID>"       |
  |  resp = KE2                             |
  |  session_expiration_time = <unix>       |
  |<----------------------------------------|
```

#### Phase 2: Finalize (KE3 → verified)

```
Client                                    Server
  |                                         |
  |  type=authenticate, state=finalize      |
  |  pake_session_id = "<from phase 1>"     |
  |  req = KE3.Serialize()                  |
  |---------------------------------------->|
  |                                         |  Verify KE3 MAC
  |                                         |  On failure: increment counter, delete session
  |                                         |  On success: mark session verified, reset counter
  |  pake_session_id = "<confirmed>"        |
  |  msg = "authenticated"                  |
  |  session_expiration_time = <unix>       |
  |<----------------------------------------|
```

After successful authentication, both client and server hold the same
session key (the OPAQUE session secret).  The first 32 bytes of this key
are used as the A256GCM symmetric key for `enc=user` requests.

### 4.4 Lockout Policy

The server tracks failed authentication attempts per `(client_id, kid,
context)` tuple.  After a configurable number of failures (default: 5),
the account is locked for a configurable duration (default: 15 minutes).
Successful authentication resets the failure counter.

### 4.5 Session Lifecycle

- Sessions have a configurable TTL (default: 5 minutes).
- A background goroutine runs at a configurable interval (default: 1
  minute) to clean up expired sessions.
- Sessions are created in an **unverified** state during auth-evaluate and
  marked **verified** after successful auth-finalize.
- Only verified sessions can be used for service requests.
- Failed auth-finalize immediately deletes the session.

## 5. Service Types

Once authenticated, the client sends service requests with `enc=user`.
The `data` field contains a JWE encrypted with the session key.  The
decrypted payload is a JSON object specific to the service type.

All service requests require a verified PAKE session (`pake_session_id`
must reference an active, verified session).

### 5.1 EC Key Generation (`hsm_ec_keygen`)

Generates a new EC key pair in the HSM.

**Request:**

```json
{
  "curve": "P-256"
}
```

| Field | Type | Description |
|-------|------|-------------|
| `curve` | string | EC curve name: `"P-256"`, `"P-384"`, or `"P-521"`. |

**Response:**

```json
{
  "kid": "a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4",
  "pub_key": "<base64url compressed public key>"
}
```

| Field | Type | Description |
|-------|------|-------------|
| `kid` | string | Key identifier (32-char hex, derived from SHA-256 of the public key). |
| `pub_key` | string | Base64url-encoded compressed EC public key (SEC 1, §2.3.3). |

The `kid` is computed as `hex(SHA-256(compressed_public_key)[:16])` and
stored as the PKCS#11 `CKA_ID` attribute on both the public and private
key objects.

### 5.2 ECDSA Signing (`hsm_ecdsa`)

Signs a pre-computed hash using a key in the HSM.

**Request:**

```json
{
  "kid": "a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4",
  "hash": "<base64url hash>"
}
```

| Field | Type | Description |
|-------|------|-------------|
| `kid` | string | Key identifier (must match `^[a-zA-Z0-9_-]{1,128}$`). |
| `hash` | string | Base64url-encoded hash. Must be 32 (SHA-256), 48 (SHA-384), or 64 (SHA-512) bytes. |

**Response:**

```json
{
  "signature": "<base64url ASN.1 DER signature>"
}
```

| Field | Type | Description |
|-------|------|-------------|
| `signature` | string | Base64url-encoded ECDSA signature in ASN.1 DER format. |

The server performs `CKM_ECDSA` signing via PKCS#11.  If the HSM returns
a raw R||S signature, it is converted to ASN.1 DER.  If the HSM returns
ASN.1 DER directly, it is passed through unchanged.

### 5.3 ECDH Key Agreement (`hsm_ecdh`)

Performs ECDH key agreement between an HSM-resident key and a peer public key.

**Request:**

```json
{
  "kid": "a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4",
  "peer_pub_key": "<base64url peer public key>"
}
```

| Field | Type | Description |
|-------|------|-------------|
| `kid` | string | Key identifier. |
| `peer_pub_key` | string | Base64url-encoded peer EC public key (compressed or uncompressed). |

Valid peer key sizes (bytes):

| Curve | Compressed | Uncompressed |
|-------|-----------|--------------|
| P-256 | 33 | 65 |
| P-384 | 49 | 97 |
| P-521 | 67 | 133 |

**Response:**

```json
{
  "shared_secret": "<base64url shared secret>"
}
```

| Field | Type | Description |
|-------|------|-------------|
| `shared_secret` | string | Base64url-encoded raw ECDH shared secret (x-coordinate). Length equals the curve's field size. |

The server uses `CKM_ECDH1_DERIVE` with `CKD_NULL`.  If the peer key is
in compressed form, the server decompresses it before passing it to the
HSM.  The derived secret key object is extracted and immediately destroyed.

### 5.4 List Keys (`hsm_list_keys`)

Lists EC keys available in the HSM.

**Request:**

```json
{
  "curves": ["P-256", "P-384"]
}
```

| Field | Type | Description |
|-------|------|-------------|
| `curves` | string[] | Optional filter by curve name.  If omitted or empty, all EC keys are returned. |

**Response:**

```json
{
  "keys": [
    {
      "kid": "a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4",
      "curve": "P-256",
      "pub_key": "<base64url compressed public key>"
    }
  ]
}
```

| Field | Type | Description |
|-------|------|-------------|
| `keys` | array | List of key info objects. |
| `keys[].kid` | string | Key identifier (CKA_ID). |
| `keys[].curve` | string | Curve name (derived from CKA_EC_PARAMS OID). |
| `keys[].pub_key` | string | Compressed public key bytes (not base64url — raw bytes in JSON). |

## 6. Protocol Flow Summary

A complete interaction from registration through service use:

```
Client                                         Server
  |                                              |
  |  === PIN Registration (one-time setup) ===   |
  |                                              |
  |  POST /r2ps  [JWS]                          |
  |  type=pin_registration, state=evaluate       |
  |  enc=device, data=JWE(RegistrationRequest)   |
  |--------------------------------------------->|
  |                                              |
  |  [JWS]                                      |
  |  enc=device, data=JWE(RegistrationResponse)  |
  |<---------------------------------------------|
  |                                              |
  |  POST /r2ps  [JWS]                          |
  |  type=pin_registration, state=finalize       |
  |  enc=device, data=JWE(RegistrationRecord)    |
  |--------------------------------------------->|
  |                                              |  Store record
  |  [JWS]                                      |
  |  msg="registration complete"                 |
  |<---------------------------------------------|
  |                                              |
  |  === Authentication ===                      |
  |                                              |
  |  POST /r2ps  [JWS]                          |
  |  type=authenticate, state=evaluate           |
  |  enc=device, data=JWE(KE1)                   |
  |--------------------------------------------->|
  |                                              |
  |  [JWS]                                      |
  |  pake_session_id, resp=KE2                   |
  |<---------------------------------------------|
  |                                              |
  |  POST /r2ps  [JWS]                          |
  |  type=authenticate, state=finalize           |
  |  enc=device, pake_session_id, data=JWE(KE3)  |
  |--------------------------------------------->|
  |                                              |  Verify MAC
  |  [JWS]                                      |  Mark session verified
  |  msg="authenticated"                         |
  |<---------------------------------------------|
  |                                              |
  |  === Service Request (e.g. ECDSA sign) ===   |
  |                                              |
  |  POST /r2ps  [JWS]                          |
  |  type=hsm_ecdsa, enc=user                    |
  |  pake_session_id                              |
  |  data=JWE_symmetric({"kid":"...","hash":"."}) |
  |--------------------------------------------->|
  |                                              |  Verify session
  |                                              |  Decrypt with session key
  |                                              |  HSM sign operation
  |  [JWS]                                      |
  |  enc=user, data=JWE_symmetric({"signature"})  |
  |<---------------------------------------------|
```

## 7. Security Considerations

### 7.1 PIN Protection

The OPAQUE protocol ensures the server never learns the user's PIN.  The
server stores only an OPAQUE registration record (containing a masked
credential and public key envelope) from which the PIN cannot be recovered.

### 7.2 Session Key Derivation

The session key is the OPAQUE session secret, derived during the
Authenticated Key Exchange.  Both parties compute it independently and
verify consistency via KE3 MAC verification.  Only the first 32 bytes
are used for A256GCM encryption.

### 7.3 Error Sanitization

All error messages returned to clients are generic.  Internal details
(PKCS#11 error codes, key identifiers, HSM module paths) are logged at
DEBUG level and never included in protocol responses.

### 7.4 Brute-Force Protection

The server implements per-`(client_id, kid, context)` lockout after a
configurable number of failed authentication attempts (default: 5 failures,
15-minute lockout).  Successful authentication resets the counter.

### 7.5 Request Size Limits

The server limits request bodies to 1 MB to prevent resource exhaustion.

### 7.6 HSM Timeout

All HSM operations are subject to a configurable timeout (default: 5
seconds) enforced via Go context cancellation.

### 7.7 Panic Recovery

The server recovers from panics in request handlers and returns a generic
error.  However, panics originating in infrastructure code (HSM session
pool, PAKE session store) cause the process to exit so the orchestration
layer can restart a clean instance.

## 8. OPAQUE Configuration

The implementation uses the following OPAQUE cipher suite:

| Parameter | Value |
|-----------|-------|
| OPRF | P256Sha256 |
| AKE | P256Sha256 |
| KDF | SHA-256 |
| MAC | SHA-256 (HMAC) |
| Hash | SHA-256 |

This corresponds to the `bytemare/opaque` library configuration with
`opaque.P256Sha256` for both OPRF and AKE groups.

## 9. Configuration Reference

| Variable | Default | Description |
|----------|---------|-------------|
| `R2PS_LISTEN` | `:8443` | Listen address |
| `R2PS_HSM_MODULE` | *(required)* | PKCS#11 shared library path |
| `R2PS_HSM_PIN` | *(required)* | HSM user PIN |
| `R2PS_HSM_TOKEN_LABEL` | | Find HSM slot by token label |
| `R2PS_HSM_SLOT` | *(auto)* | HSM slot number |
| `R2PS_HSM_POOL_SIZE` | `4` | Number of concurrent PKCS#11 sessions |
| `R2PS_HSM_TIMEOUT` | `5s` | Timeout for HSM operations |
| `R2PS_TLS_CERT` | | TLS certificate file |
| `R2PS_TLS_KEY` | | TLS private key file |
| `R2PS_MAX_ATTEMPTS` | `5` | Failed auth attempts before lockout |
| `R2PS_LOCKOUT_DURATION` | `15m` | Lockout duration after max failures |
| `R2PS_SESSION_TTL` | `5m` | PAKE session time-to-live |
| `R2PS_LOG_LEVEL` | `WARN` | Log level: DEBUG, INFO, WARN, ERROR |
| `R2PS_LOG_FORMAT` | `text` | Log format: `text` or `json` |

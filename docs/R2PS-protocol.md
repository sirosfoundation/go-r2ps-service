# Remote PAKE-Protected Services Protocol (R2PS)

**Version:** 1.0
**Status:** Implementation Draft
**Date:** 2026-05-21
**Normative Reference:** `security/rp2s-peter.md`

## 1. Introduction

The R2PS protocol lets constrained clients offload critical service operations
to a secure server environment. The protocol is generic and can support any
client application, but its primary target is remote-WSCD solutions.

The same remote-server architecture also supports:

- Multi-device access to a single wallet instance
- Private storage of client data
- Audit logging

### 1.1 Encryption Modes

R2PS defines two modes for encrypting service data:

**Device-authenticated encryption** uses ephemeral-static ECDH as defined for
JWE in RFC 7518. The client encrypts to the server's static public key; the
server encrypts to the client's public context key. This mode applies to
services that must operate before a user-authenticated key has been
established (notably PAKE exchanges). It proves the possession factor.

**User-authenticated encryption** uses a key negotiated through a PAKE
exchange that binds the key to the user's PIN. The RECOMMENDED configuration
is OPAQUE combined with Device-Enhanced PIN hardening (§3.3.2 of the normative
reference).

## 2. Transport

### 2.1 HTTP Binding

All protocol messages are exchanged over a single HTTP endpoint:

```
POST /r2ps
Content-Type: application/jose
```

- A successful response SHALL be returned with HTTP 200 and `Content-Type: application/jose`.
- On failure, the server SHALL return an error response (§3.2) with the
  appropriate HTTP status code and `Content-Type: application/json`.
- The server enforces a maximum request body size of 1 MB.

### 2.2 TLS

TLS 1.2 is the minimum supported version. The server supports direct TLS
termination (configured via `R2PS_TLS_CERT` and `R2PS_TLS_KEY`) or may run
behind a TLS-terminating reverse proxy.

### 2.3 Observability Endpoints

| Path | Method | Purpose |
|------|--------|---------|
| `/healthz` | GET | Liveness probe — always returns `{"status":"ok"}` |
| `/readyz` | GET | Readiness probe — probes HSM connectivity |
| `/metrics` | GET | Prometheus metrics |

## 3. Protocol

### 3.1 Service Request and Response

Service requests and responses take the form of a JWS [RFC 7515] in compact
serialization. The JWS payload is a JSON object whose parameters are defined
below.

#### 3.1.1 Common Request/Response Parameters

The following parameters MUST be present in both service requests and
service responses:

| Parameter | Type | Description |
|-----------|------|-------------|
| `ver` | string | Protocol version. SHALL be `"1.0"`. |
| `nonce` | byte array | Random value included in request and echoed in response. |
| `iat` | integer | Unix timestamp at time of creation. |
| `enc` | string | Encryption mode: `"user"` or `"device"`. |
| `data` | byte array | JWE-encrypted service data in compact serialization. |

#### 3.1.2 Service Request

Additional parameters MUST be present in service requests:

| Parameter | Type | Description |
|-----------|------|-------------|
| `client_id` | string | Identifies the client entity. |
| `kid` | string | Key identifier for the context key used by this client on the current device. |
| `context` | string | Security context under which the request is made. |
| `type` | string | Service type identifier. |
| `pake_session_id` | string | Identifies the PAKE-authenticated session. |

These parameters give the server the information needed to:

- `context` → route to the backend resource for this security context.
- `client_id` → retrieve all records associated with the client account.
- `kid` → identify the client public key used to establish a PAKE session;
  also used by default to validate the JWS signature.
- `pake_session_id` → locate the session holding the decryption key.
- `type` → identify the expected structure of the decrypted service data.

A service request MUST include the `typ` header parameter with value
`"r2ps-request+json"`.

#### 3.1.3 Service Response

A service response is bound to its request by echoing the `nonce` value.
The server MUST ensure the request `nonce` provides at least 64 bits of
entropy.

A service response MUST include all common parameters defined in §3.1.1.

A service response MUST NOT include the additional request parameters
(`client_id`, `kid`, `context`, `type`, `pake_session_id`).

A service response MUST include the `typ` header parameter with value
`"r2ps-response+json"`.

### 3.2 Error Response

If the server fails to process a service request, it MUST respond with an
appropriate HTTP error code and a structured error response:

```json
{
  "error_code": "ACCESS_DENIED",
  "error_message": "The service type 'hsm_ecdsa' under context 'test' is not supported"
}
```

| Response Code | HTTP Status |
|---------------|-------------|
| `ILLEGAL_REQUEST_DATA` | 400 |
| `UNAUTHORIZED` | 401 |
| `ACCESS_DENIED` | 403 |
| `ILLEGAL_STATE` | 409 |
| `UNSUPPORTED_REQUEST_TYPE` | 415 |
| `SERVER_ERROR` | 500 |
| `TRY_LATER` | 503 |

> **Note**: The server MUST NOT return an error when receiving an unknown
> `client_id`. Instead, the server completes the response using a fake client
> record with a randomly generated public key and masking key.

Error messages are intentionally generic and never expose HSM internals,
key identifiers, or PKCS#11 error codes.

### 3.3 PAKE Exchanges

PAKE processing is handled through the following service types:

| Service Type | Encryption Mode | Purpose |
|--------------|----------------|---------|
| `pin_registration` | `device` | Register a new PIN for a security context |
| `pin_change` | `user` | Replace an existing PIN with a new one |
| `authenticate` | `device` | Establish a PAKE session |

The `device` mode ensures PIN-based operations proceed only after the
possession factor has been established.

The `user` mode ensures PIN changes proceed only after the knowledge
factor has been established.

#### 3.3.1 PAKE Data Structures

##### 3.3.1.1 PAKE Request Data Structure

| Parameter | Type | Description |
|-----------|------|-------------|
| `protocol` | string | Identifier of the PAKE protocol in use. |
| `state` | string | Current state of the PAKE protocol exchange. |
| `authorization` | byte array | Authorization data for new PIN registrations. |
| `task` | string | Requested session task. |
| `session_duration` | integer | Requested maximum session duration in seconds. |
| `req` | byte array | PAKE request data. |

The `authorization` parameter asserts that the client is authorized to set
a PIN. The mechanism is outside the scope of this specification.

##### 3.3.1.2 PAKE Response Data Structure

| Parameter | Type | Description |
|-----------|------|-------------|
| `pake_session_id` | string | Session identifier. |
| `resp` | byte array | PAKE response data. |
| `msg` | string | Human-readable message. |
| `task` | string | Confirms the session task. |
| `session_expiration_time` | integer | Session expiry as Unix timestamp. |

#### 3.3.2 Device-Enhanced PIN

Implementations SHOULD use Device-Enhanced PIN (DE-PIN) to strengthen the
PAKE protocol. The RECOMMENDED algorithm:

```
DE-PIN = HKDF(ECDH(prv, hash2Curve(PIN)))
```

where `prv` is the device-protected private key for the intended `context`
and `hash2Curve()` is defined in [RFC 9380].

#### 3.3.3 OPAQUE as PAKE Protocol

When OPAQUE [RFC 9807] is used, it is identified by the protocol identifier
`"opaque"`.

OPAQUE uses the following states:

| State | Description |
|-------|-------------|
| `evaluate` | Server evaluates blinded OPRF data (registration) or generates KE2 (auth). |
| `finalize` | Client sends RegistrationRecord (registration) or KE3 (auth). |

##### 3.3.3.1 OPAQUE PIN Registration

**Evaluate request:** `protocol: "opaque"`, `state: "evaluate"`, `req: <RegistrationRequest>`

**Evaluate response:** `resp: <RegistrationResponse>`

**Finalize request:** `protocol: "opaque"`, `state: "finalize"`, `authorization: <auth data>`, `req: <RegistrationRecord>`

**Finalize response:** `msg: "OK"`

The registration is stateless. The `authorization` parameter MUST be
included in the `finalize` state on initial PIN registration.

##### 3.3.3.2 OPAQUE Authentication

**Evaluate request:** `protocol: "opaque"`, `state: "evaluate"`, `req: <KE1>`

**Evaluate response:** `pake_session_id: <id>`, `resp: <KE2>`

**Finalize request:** `protocol: "opaque"`, `state: "finalize"`, `task: <task>`, `session_duration: <seconds>`, `req: <KE3>`

**Finalize response:** `pake_session_id: <id>`, `task: <echoed>`, `session_expiration_time: <unix>`, `msg: "OK"`

> **Note 1**: `session_duration` is the maximum permitted lifetime. The server
> sets `session_expiration_time` to no later than `session_duration` seconds
> from the current time, but MAY set it shorter.

> **Note 2**: The `task` identifier allows the server to enforce controls such
> as rejecting requests inconsistent with the declared task or closing sessions
> after task completion.

> **Note 3**: Before generating the finalize response, the server MUST verify
> the client authentication material.

The server SHOULD only echo `task` if it recognizes the identifier.

##### 3.3.3.3 OPAQUE PIN Change

PIN change proceeds as:

1. Establish a new PAKE session under the existing PIN (`authenticate`)
2. Perform a `pin_change` registration exchange encrypted under that session key

Once complete, the old session SHOULD be invalidated.

## 4. Service Types (HSM Profile)

Once authenticated, the client sends service requests with `enc=user`.
All service requests require a verified PAKE session.

### 4.1 EC Key Generation (`hsm_ec_keygen`)

**Request:**
```json
{ "curve": "P-256" }
```

**Response:**
```json
{ "kid": "<hex>", "pub_key": "<base64url compressed>" }
```

The `kid` is computed as `hex(SHA-256(compressed_public_key)[:16])`.

### 4.2 ECDSA Signing (`hsm_ecdsa`)

**Request:**
```json
{ "kid": "<key id>", "hash": "<base64url hash>" }
```

Hash must be 32 (SHA-256), 48 (SHA-384), or 64 (SHA-512) bytes.

**Response:**
```json
{ "signature": "<base64url ASN.1 DER signature>" }
```

### 4.3 ECDH Key Agreement (`hsm_ecdh`)

**Request:**
```json
{ "kid": "<key id>", "peer_pub_key": "<base64url peer key>" }
```

Peer key may be compressed or uncompressed.

**Response:**
```json
{ "shared_secret": "<base64url shared secret>" }
```

### 4.4 List Keys (`hsm_list_keys`)

**Request:**
```json
{ "curves": ["P-256", "P-384"] }
```

**Response:**
```json
{ "keys": [{"kid": "...", "curve": "P-256", "pub_key": "..."}] }
```

## 5. Security Considerations

### 5.1 PIN Protection

The OPAQUE protocol ensures the server never learns the user's PIN.

### 5.2 Unknown Client Handling

The server MUST NOT return an error for unknown `client_id`. It completes
the response using a fake record to prevent client enumeration.

### 5.3 Error Sanitization

Internal details (PKCS#11 error codes, key identifiers, HSM module paths)
are logged at DEBUG level and never included in protocol responses.

### 5.4 Brute-Force Protection

Per-`(client_id, kid, context)` lockout after configurable failed attempts
(default: 5 failures, 15-minute lockout).

### 5.5 Panic Recovery

Infrastructure panics (HSM pool, PAKE store) cause process exit.
Request-scoped panics are recovered and return a generic error.

## 6. OPAQUE Configuration

| Parameter | Value |
|-----------|-------|
| OPRF | P256Sha256 |
| AKE | P256Sha256 |
| KDF | SHA-256 |
| MAC | SHA-256 (HMAC) |
| Hash | SHA-256 |

## 7. Configuration Reference

| Variable | Default | Description |
|----------|---------|-------------|
| `R2PS_LISTEN` | `:8443` | Listen address |
| `R2PS_HSM_MODULE` | *(required)* | PKCS#11 shared library path |
| `R2PS_HSM_PIN` | *(required)* | HSM user PIN |
| `R2PS_HSM_TOKEN_LABEL` | | Find HSM slot by token label |
| `R2PS_HSM_SLOT` | *(auto)* | HSM slot number |
| `R2PS_HSM_POOL_SIZE` | `4` | Concurrent PKCS#11 sessions |
| `R2PS_HSM_TIMEOUT` | `5s` | Timeout for HSM operations |
| `R2PS_TLS_CERT` | | TLS certificate file |
| `R2PS_TLS_KEY` | | TLS private key file |
| `R2PS_MAX_ATTEMPTS` | `5` | Failed auth attempts before lockout |
| `R2PS_LOCKOUT_DURATION` | `15m` | Lockout duration |
| `R2PS_SESSION_TTL` | `5m` | PAKE session time-to-live |
| `R2PS_LOG_LEVEL` | `WARN` | Log level |
| `R2PS_LOG_FORMAT` | `text` | Log format: `text` or `json` |

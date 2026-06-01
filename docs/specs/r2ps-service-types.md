R2PS - Service Types
===

*version 1.0*

# 0. Abstract

The Remote Two-factor Protected Services (R2PS) protocol specification defines the end-to-end encrypted (E2EE) transport between a client and a server, alongside one-factor authenticated (`1FA`) and two-factor authenticated (`2FA`) exchange modes. This specification defines the *service types* carried over that transport.

This specification defines three core service types: 

* `2fa_registration`: Registers a second authentication factor.
* `2fa_change`: Replaces an existing second factor.
* `2fa_authenticate`: Establishes a two-factor authenticated session to enable application-level E2EE service exchanges.

Additionally, this document specifies a mechanism for defining new service types.

# 1. Introduction

## 1.1. Relationship to R2PS

This document depends on the base R2PS specification and reuses its terminology without redefinition. 

R2PS defines two service-exchange modes:

* `1FA` mode verifies a single possession factor and applies to service types that do not operate on a remote hardware-protected private key.
* `2FA` mode requires an additional second factor and applies to service types operating on a remote hardware-protected private key.

To maintain architectural simplicity and flexibility, establishing a second-factor proof is a service type executed within `1FA` mode. Successful execution yields a `2FA`-authenticated session; the base specification consumes this session key to derive the content encryption key (CEK) for any subsequent `2FA` exchanges.

The three core service types defined in this document govern the lifecycle of the second factor:

* `2fa_registration`: Establishes a new second factor within a security context.
* `2fa_authenticate`: Verifies the second factor and establishes the parameters required for the `2FA` session.
* `2fa_change`: Replaces an existing second factor.

R2PS service types are designed for ease of implementation while remaining fully extensible to accommodate any future service-level requirements. To achieve this, [Appendix A] defines the extensibility model, template requirements, and namespace conventions used to profile new or existing service types.

## 1.2. Terminology and Conventions

The key words "MUST", "MUST NOT", "REQUIRED", "SHOULD", "SHOULD NOT", "RECOMMENDED", "MAY", and "OPTIONAL" in this document are to be interpreted as described in [RFC2119] and [RFC8174].

Additional terms used in this document:

* **Second-factor mechanism**: The concrete method used to establish the second authentication factor, as defined in [Section 4](#2fa-mechanism)
* **Client Signing Key (CSK)**: The key used by the client to sign the JWS in service requests. Each security context maintains a unique CSK.
* **Server Signing Key (SSK)**: The key used by the server to sign the JWS in service responses.
* **`2FA` session**: The logical scope of an authenticated session produced by a successful `2fa_authenticate` exchange. It encompasses the set of E2EE service exchanges protected under the session key, identified by `2fa_session_id`, and bounded by `task` and `session_expiration_time`. 
* **Service data**: The payload elements exchanged within messages to execute the service provided by the server.

All JSON examples are illustrative. Nonces and other long byte arrays are abbreviated (e.g., `"b8b...615"`). Angle brackets (`"<...>"`) denote a placeholder value whose encoding is defined by the referenced specification.

# 2. Common Message Structure

The R2PS JWE payload is a JWS [RFC7515] in compact serialization. The JWS is signed by the client's CSK on requests and by the server's SSK on responses. The JWS payload carries the service data. 

This single structure is shared across all service types and second-factor mechanisms. Variant content specific to a service type or mechanism resides entirely within the `data` member of the payload object.

## 2.1. JWS Header

The JWS header identifies the signature algorithm and the signing key. In this version of the specification:

* `alg`: MUST be `ES256`.
* `kid`: Identifies the signing key. In requests, it MUST identify the client's CSK for the security context; implementations SHOULD use the JWK Thumbprint [RFC7638] of the CSK public key. In responses, it MUST identify the server's SSK.
* `typ`: MUST be `r2ps-request+jwt` for service requests, and MUST be `r2ps-response+jwt` for service responses.

All service exchanges MUST include the JWS header parameters required by [RFC7515].

The mechanism by which the CSK produces the `ES256` signature depends on the environment. A software or platform key (e.g., on a smartphone) signs the JWS directly. A roaming FIDO2 authenticator produces the signature over the JWS signing input via the WebAuthn `sign` extension as detailed in [WebAuthn-sign-extension](https://github.com/w3c/webauthn/pull/2078).

## 2.2. JWS Payload

The JWS payload consists of common parameters present in all exchanges, request parameters present only in requests, and a session-binding parameter required when the exchange is carried over a `2FA` session.

### 2.2.1. Common Parameters

These parameters MUST be present in both requests and responses:

* `ver` (**string**): Identifies the protocol version (`"1.0"` for this document).
* `nonce` (**byte array**): A random byte array containing a minimum of 8 bytes of entropy. It is generated by the client for each request and echoed unchanged in the corresponding response.
* `iat` (**integer**): A Unix timestamp indicating message creation time.
* `data` (**determined by service type**): Contains the service-specific payload. Its structure is determined by the request `type` and, within a second-factor exchange, by the mechanism ([Section 4]). The specific contents are defined per service type in [Section 5].

### 2.2.2. Request Parameters

These parameters MUST be present in requests and MUST NOT be present in responses:

* `type` (**string**): The service type identifier ([Section 3]). It determines the structure of the `data` parameter, the protocol operations executed, and the required service-exchange mode (`1FA` or `2FA`).
* `client_id` (**string**): Identifies the client entity.
* `context` (**string**): Identifies the security context, which determines the target server for the request.

### 2.2.3. Session-binding Parameter

When the exchange is carried over a `2FA` session, the following parameter MUST be present in the JWS payload:

* `2fa_session_id` (**string**): MUST equal the JWE `kid` value of the enclosing `2FA`-mode JWE. Its presence in the signed payload binds the client's signature to the `2FA` session.

# 3. [Second-factor Mechanisms](#2fa-mechanism)

A second-factor mechanism defines how the second factor is established at registration and proved at authentication. This profile defines three mechanisms, each mapping to one of the models described in the base specification.

* `password`: The password mechanism sends a plaintext password to the server. When a new `2FA` session is established, the client additionally sends information required to decrypt each subsequent JWE of the `2FA` session.

The mechanisms differ along two dimensions:

1. The binding between the second factor and the `2FA` session. In OPAQUE, the parties only get the shared secret (i.e., the OPAQUE `session_key`) if and only if the password was right. In OPAQUE, the binding is the session key derivation. In contrast, a password check or a FIDO2 UV assertion does not produce a shared secret. So for `password` and `fido2` the session key is established separately and bolted onto the authenticated check. Here, the binding is policy-gated; the server can open the session without having actually validated the factor.
2. What the server learns about the second factor. OPAQUE and fido2 transfers no knowledge about second factor. Password mode transfers it in plaintext.

The mechanism in use is signalled by the `2fa_mode` field inside `data`. The `password` mode covers both the hashed-salted and the KDF-based salted password verifiers of the base specification; the choice between a plain cryptographic hash and a slow KDF, as well as the use of a server-held pepper, is a server-side storage decision that is not visible in the service data.

Where Device-Enhanced Password (DE-PWD) hardening is used (base spec §2.2.1.1), the client computes the DE-PWD value and places that value in the `request` field for the `password` and `opaque` mechanisms. The wire format is otherwise unchanged.

[THE SESSION KEY FOR PASSWORD SHOULD SOURCE RANDOM FROM BOTH SIDES.]

## 4.1. Common second-factor `data` fields

The second-factor exchanges `2fa_registration` and `2fa_authenticate` place the following fields inside `data`. Which fields are present depends on the service type and mechanism, as specified in §5.

Request fields:

* `2fa_mode` (**string**): The second-factor mechanism in use (`password`, `opaque`, or `fido2`).
* `state` (**string**): The protocol state, for multi-round mechanisms. Single round mechanisms MUST NOT use `state`.
* `request` (**byte array** or **string**): The mechanism-specific request payload for the current state.
* `authorization` (**string**, OPTIONAL): Asserts that the client is authorized to establish a second factor for a given `1FA` identity and security context. Present only during registration of a new second factor (§4.5). The means by which authorization data is established is out of scope; a typical deployment issues a sender-constrained access token during initial `1FA` enrolment (for example, after a first passkey login) and binds it to the `1FA` channel.

Response fields:

* `response` (**byte array** or **string**): the mechanism-specific response payload for the current state.
* `message` (**string**): a cleartext status or user-facing message (for example, `"success"`).

## 4.2. Password mechanism (`password`)

The server stores a verification key `vk` derived from the user's password and a per-user random salt. Per the base specification the server stores either a cryptographically secure hash, `vk = H(password + salt)`, or a slow KDF, `vk = KDF(password + salt)`; either way it stores `{salt, vk}`. For the KDF case, the server additionally stores the parameters needed to reproduce the derivation. The `salt` value MUST be drawn from a cryptographically secure random source and MUST be unique per `vk`.

## 4.3. FIDO2 Authenticator Mechanism (`fido2`)

In the device-attested model the second factor is established and verified locally by the user's FIDO2 authenticator.

The mechanism relies on two complementary signatures: the JWS signature, which demonstrates possession, and a WebAuthn assertion carried inside data, which demonstrates user verification.

Every exchange is is signed as an `ES256` JWS by the CSK §2.1. In a platform or smartphone deployment the CSK is the platform's registered signing key and signs the JWS directly. In a roaming FIDO2 deployment the CSK is held by the FIDO2 authenticator, and the JWS signature is produced over the JWS signing input using the WebAuthn sign extension [WebAuthn-sign] (a raw signature over the supplied input). Either way the result is an ordinary ES256 JWS.

The second factor is demonstrated by a regular WebAuthn assertion whose authenticator data has the user-verification (UV) flat set. The client requests UV; the authenticator prompts for a PIN or biometric and sets the UV flag in the assertion. The assertion is carried inside `data` as the `request` value of a `fido2` exchange.

To complete the second-factor check the server MUST:

1. verify the assertion signature under the CSK registered for the context
2. verify that the UV flag is set

There is no server-side password-verification object for this mechanism; registration enrols the credential itself (see §5.1.3).

## 4.4. PAKE Mechanism

A PAKE mechanism authenticates the knowledge factor without the server ever learning it. PAKE mechanisms share the common fields of §4.2; the content of request and response, and the set of valid state values, are determined by the underlying PAKE protocol.

### 4.4.1. OPAQUE (`opaque`)

This profile uses OPAQUE [RFC9807] as its aPAKE. When OPAQUE is used the `2fa_mode`  MUST be `opaque`.

OPAQUE defines two states in this profile:

1. `evaluate`: the first round, in which the server evaluates the client's blinded OPRF input.
2. `finalize`: the final round, in which registration or authentication is completed.

The mapping of OPAQUE messages onto these states differs between registration and authentication and is given in §5.1.2 and §5.2.2.

# 5. Core Service Types

## 5.1. `2FA` Registration

The client registers a new second factor for a security context. Because no second factor yet exists, the exchange is carried in `1FA` mode and is optionally authorized by the `authorization` field (§4.2).

* Service type identifier: `2fa_registration`
* Message-exchange mode: `1FA`

### 5.1.1. Password

The password based flow uses two rounds. In the `evaluate` round, the client and the server establish a symmetric secret used to encrypt the password. In the `finalize` round, the client sends over the JWE containing the password (or DE-PWD value) and the registration authorization; the server stores `{salt, vk}` and acknowledges.

| State      | Request data                                                                                 | Response data                             |
|------------|----------------------------------------------------------------------------------------------|-------------------------------------------|
| `evaluate` | `2fa_mode` is `password`, `state` is `evaluate`, `request` is client ephmemeral public key   | `response` is server ephemeral public key |
| `finalize` | `2fa_mode` is `password`, `state` is `finalize`, request is `JWE(password)`, `authorization` | `message` is `success`                    |

#### 5.1.1.1. The `password` evaluate round (`evalute`)

`evaluate` request header

```json
{
  "alg": "ES256",
  "kid": "<jwk thumbprint of CSK>",
  "typ": "r2ps-request+jwt"
}
```

`evaluate` request payload

```json
{
  "ver": "1.0",
  "nonce": "538...111",
  "iat": <Unix timestamp>,
  "data": {
    "2fa_mode": "password",
    "state": "evaluate",
    "request": "<client JWE ephemeral public key>"
  },
  "client_id": "https://example.com/wallet/1",
  "context": "hsm",
  "type": "2fa_registration"
}
```

`evaluate` response header

```json
{
  "alg": "ES256",
  "kid": "<jwk thumbprint of SSK>",
  "typ": "r2ps-response+jwt"
}
```

`evaluate` response payload

```json
{
  "ver": "1.0",
  "nonce": "538...111",
  "iat": <Unix timestamp>,
  "data": {
    "response": "<server JWE ephemeral public key>"
  }
}
```

Both parties can now establish the content encryption key as:

1. Compute `ikm = ECDH(client ephemeral key, server ephemeral key)`
2. Derive `CEK = HKDF(ikm, salt, info, L)` where salt is empty, info is DST + transcript hash (SHA256 of the `evaluate` round nonce, both ephemeral public keys, `client_id`, `context`), and `L` is 32 bytes. The DST MUST be `r2ps-2fa_registration-password-cek`.

The inner `<JWE(password)>` is a `dir` / `A256GCM` JWE with the derived `CEK`.

#### 5.1.1.2. The `password` finalize round (`finalize`)

`finalize` request header

```json
{
  "alg": "ES256",
  "kid": "<jwk thumbprint of CSK>",
  "typ": "r2ps-request+jwt"
}
```

`finalize` request payload

```json
{
  "ver": "1.0",
  "nonce": "138...115",
  "iat": <Unix timestamp>,
  "data": {
    "2fa_mode": "password",
    "state": "finalize",
    "request": "<JWE(password)>",
    "authorization": "<authorization data>"
  },
  "client_id": "https://example.com/wallet/1",
  "context": "hsm",
  "type": "2fa_registration"
}
```

`finalize` response header

```json
{
  "alg": "ES256",
  "kid": "<SSK>",
  "typ": "r2ps-response+jwt"
}
```

`finalize` response payload

```json
{
  "ver": "1.0",
  "nonce": "138...115",
  "iat": <Unix timestamp>,
  "data": {
    "message": "success"
  }
}
```

### 5.1.2. FIDO2 Authenticator (`fido2`)

There is no server-side verification object to register for the `fido2` mechanism. Registration instead enrols the WebAuthn UV-capable credential and binds it to the `client_id` for that security context. The request carries the result of the WebAuthn credential-creation ceremony (the attestation object and client data); the server validates it according to [WebAuthn] and stores the credential public key. The `authorization` field (§4.2) authorizes the enrolment, as for the other mechanisms.

The flow is double-round. The client first requests a challenge. It then runs the WebAuthn credential-creation ceremony using the challenge it received in round 1.

#### 5.1.2.1. Challenge Request

request header

```json
{
  "alg": "ES256",
  "kid": "<jwk thumbprint of CSK>",
  "typ": "r2ps-request+jwt"
}
```

request payload

```json
{
  "ver": "1.0",
  "nonce": "a90...774",
  "iat": <Unix timestamp>,
  "data": {
    "2fa_mode": "fido2",
    "state": "challenge",
    "request": "<client capabilities or preferences>"
  },
  "client_id": "https://example.com/wallet/1",
  "context": "hsm",
  "type": "2fa_registration"
}
```

response header

```json
{
  "alg": "ES256",
  "kid": "<SSK>",
  "typ": "r2ps-response+jwt"
}
```

response payload

```json
{
  "ver": "1.0",
  "nonce": "a90...774",
  "iat": <Unix timestamp>,
  "data": {
    "challenge": "S2E...9zQ"
  }
}
```

#### 5.1.2.2. Registration Ceremony

The client runs the WebAuthn credential-creation ceremony using the server-provided challenge as the WebAuthn challenge, requesting user verification (e.g., using a biometric or PIN). It then forwards the resulting attestation to the server.

Request

```json
{
  "ver": "1.0",
  "nonce": "21E...91Q", 
  "iat": <Unix timestamp>,
  "data": {
    "2fa_mode": "fido2",
    "state": "register",
    "request": {
      "credential_id": "<base64url credential identifier>",
      "attestation_object": "<base64url encoded attestationObject>",
      "client_data": "<base64url clientDataJSON>"
    },
    "authorization": "<authorization data>"
  },
  "client_id": "https://example.com/wallet/1",
  "context": "hsm",
  "type": "2fa_registration"
}
```

Response

```json
{
  "ver": "1.0",
  "nonce": "21E...91Q",
  "iat": <Unix timestamp>,
  "data": {
    "message": "success"
  }
}
```

On receiving the registration request, the server MUST validate the attestation according to the WebAuthn standard. Specifically, the server MUST:

1. Parse `client_data` and verify that the `type` field is exactly `"webauthn.create"`.
2. Verify that the `challenge` field in `client_data` exactly matches the server-generated `challenge` in the Challenge Request.
3. Verify that the `origin` in `client_data` matches the Relying Party's expected origin.
4. Decode the `attestation_object` and verify that the `rpIdHash` in the authenticator data is the SHA-256 hash of the Relying Party ID.
5. Verify that the User Present (UP) bit of the flags in the authenticator data is set to 1.
6. Verify that the User Verified (UV) bit of the flags in the authenticator data is set to 1, confirming the user successfully provided second factor during this setup.
7. Verify the attestation statement's cryptographic signature using the appropriate verification procedure for the attestation format.

On success, the server extracts the `credentialId` and `credentialPublicKey` from the attested credential data. It stores the `credential_id` and the public key bound to the `client_id` and security context. This credential (discovered via `credential_id` in the `allowCredentials` list) is the one from which UV assertions will be required during future `2fa_authenticate` flows.


### 5.1.3. OPAQUE (`opaque`)

OPAQUE registration runs over two states. The `evaluate` state exchanges the `RegistrationRequest` and `RegistrationResponse`; the `finalize` state delivers the `RegistrationRecord` (per [RFC9807] §3.2).

| State    | Request data                                                                    | Response data                 |
|----------|---------------------------------------------------------------------------------|-------------------------------|
| evaluate | 2fa_mode="opaque", state="evaluate", request=RegistrationRequest, authorization | response=RegistrationResponse |
| finalize | 2fa_mode="opaque", state="finalize", request=RegistrationRecord, authorization  | message="success"             |

`authorization` MAY be sent in the `evaluate` state of an OPAQUE registration if required to prevent a costly HSM operation on behalf of an unauthorized caller. The second `authorization` authorizes the actual creation of the registration record.

#### 5.1.3.1. The `opaque` evaluate round (`evalute`)

`evaluate` request header

```json
{
  "alg": "ES256",
  "kid": "<jwk thumbprint of CSK>",
  "typ": "r2ps-request+jwt"
}
```

`evaluate` request payload

```json
{
  "ver": "1.0",
  "nonce": "538...111",
  "iat": <Unix timestamp>,
  "data": {
    "2fa_mode": "opaque",
    "state": "evaluate",
    "request": "<RegistrationRequest>",
    "authorization": "<authorization data>"
  },
  "client_id": "https://example.com/wallet/1",
  "context": "hsm",
  "type": "2fa_registration"
}
```
`evaluate` response header

```json
{
  "alg": "ES256",
  "kid": "<jwk thumbprint of SSK>",
  "typ": "r2ps-response+jwt"
}
```

`evaluate` response payload

```json
{
  "ver": "1.0",
  "nonce": "538...111",
  "iat": <Unix timestamp>,
  "data": {
    "response": "<RegistrationResponse>"
  }
}
```

#### 5.1.3.2. The `opaque` finalize round (`finalize`)

`finalize` request header

```json
{
  "alg": "ES256",
  "kid": "<jwk thumbprint of CSK>",
  "typ": "r2ps-request+jwt"
}
```

`finalize` request payload

```json
{
  "ver": "1.0",
  "nonce": "138...115",
  "iat": <Unix timestamp>,
  "data": {
    "2fa_mode": "opaque",
    "state": "finalize",
    "request": "<RegistrationRecord>",
    "authorization": "<authorization data>"
  },
  "client_id": "https://example.com/wallet/1",
  "context": "hsm",
  "type": "2fa_registration"
}
```

`finalize` response header

```json
{
  "alg": "ES256",
  "kid": "<jwk thumbprint of SSK>",
  "typ": "r2ps-response+jwt"
}
```

`finalize` response payload

```json
{
  "ver": "1.0",
  "nonce": "138...115",
  "iat": <Unix timestamp>,
  "data": {
    "message": "success"
  }
}
```

## 5.2. `2FA` Authentication

TODO FOR PASSWORD FIDO2 AND OPAQUE. 

OPAQUE IS EASY. 

PASSWORD IS A BIT TRICKY SINCE IT DEPENDS ON WHETHER OR NOT WE WANT FORWARD SECRECY FOR PASSWORD DATA. IF WE DO, WE MUST ADD A LOT OF COMPLEXITY (SEE PASTEBIN TEXT BELOW) AND WE MAY AS WELL JUST USE OPAQUE OR FIDO2.

FIDO2 IS STRAIGHT FORWARD.

## 5.3. `2FA` Change

TODO. THIS IS ESSENTIALLY `2FA` AUTHENTICATION FOLLOWED BY `1FA` REGISTRATION WHERE THE AUTHORIZATION IS THE EXISTING `2FA` SESSION KEY.

---

# PASTEBIN

TODO: MUST ADD SESSION EXPIRATION AND TASK INFO

## Password-based `2FA` authentication

**PASS 1**

Request: The `data` object contains the following:

* `2fa_mode` MUST be `password`.
* `request` MUST be empty.

The server recieves the request and generates an ephemeral keypair (`server_eprv_jwe`,`server_epub_jwe`). The server then uses an encryption key only known to it to create:

```
encrypted_eprv_jwe = A256GCM-JWE( key = server_token_key,
                                  plaintext = { server_eprv_jwe, iat, client_id, context } )
```

> Note: The encryption key needs to be frequently rotated. Because the server's private encryption key encrypts the ephemeral private key in transit, that encryption key's lifespan dictates the forward secrecy window.

Response: The `data` object contains the following:

* `reponse`: A JSON object with the following two values:
  * The public key `server_epub_jwe`
  * The timestamped private key `encrypted_eprv_jwe` in encrypted form.

The client now generates two distinct ephemeral keys sets. The first for the intended `2FA` session (`client_eprv_2fa`, `client_epub_2fa`). The second used for the JWE encryption (`client_eprv_jwe`, `client_epub_jwe`); using which it creates a JWE containing a JSON with the parameter values `password` and `client_epub_2fa`. 

**PASS 2**

Request: The `data` object contains the following:

* the client's ephemeral public key used for the JWE (`client_epub_jwe`)
* The JWE containing
  * the client's password
  * the client's ephemeral public key used for the `2FA` (`client_epub_2fa`)
* The server's encrypted timestamped private key `encrypted_eprv_jwe`

The server can now decrypt `encrypted_eprv_jwe` and check the tag validity, iat freshness, and that the `client_id`/`context` match. Upon success, the server derives the JWE CEK, decrypt the JWE to get the client's password and the client's `2FA` ephemeral public key. Upon successful password validation, the server generates ephemeral key pair for the intended `2FA` session (`server_eprv_2fa` `server_epub_2fa`). The server can now establish the `2FA` session and gives it a session id `2fa_session_id`.

> Note: It is not strictly necessary to encrypt the client's ephemeral public `2FA` key. Encrypting it ensures that the server cannot establish the `2FA` session without at least decrypting the password.

Response: The `data` object contains the following:

  * `2fa_session_id`: the server assigned session id for the `2FA` session.
  * `reponse`: the server ephemeral public key for the `2FA` session `server_epub_2fa`.

**A simplification exists when only session forward secrecy is required**:

If a deployment accepts not having forward secrecy for the password, and sending it encrypted only using `1FA`, then the exchange collapses to a single round:

  * Request `data` must at least contain: `2fa_mode = "password"`, the password, and `client_epub_2fa`
  * The server validates the password and, only on success, generates `server_eprv_2fa`. It then sends the response `data`: `2fa_session_id`, and `server_epub_2fa`.
  * Both sides derive the session key from the `2fa` ephemeral ECDH.

The session keeps full forward secrecy; the password does not.


## FIDO2-based `2FA` Authentication

**PASS 1**

Request:

* `2fa_mode` MUST be `fido2`
* request MUST be empty

The server generates a secure random `server_nonce` and computes a random 16 byte `challenge`. The server then uses an encryption key only known to it to create a stateless token:

```
token = A256GCM( key = server_token_key,
                 plaintext = { iat, client_id, context, challenge } )
```

Response:

* `challenge`
* `token`
* UV flag requirement

The client runs the `authenticatorGetAssertion` ceremony using `challenge`, explicitly requiring UV.

**PASS 2**:

Request:

* `client_epub_2fa`
* `token`
* `assertion` the WebAuthn assertion data (`credential_id`, `authenticatorData`, `clientDataJSON`, and `signature`).

The server, after verifying the outer JWS and the credential client_id binding, can now decrypt `token` and check the tag validity, `iat` freshness, and that the `client_id`/`context` match. Upon success, the server extracts `server_nonce` and `challenge`. The server then validates the WebAuthn assertion:

1. Confirms the type in clientDataJSON is exactly "webauthn.get"
2. Confirms the `challenge` in `clientDataJSON` exactly matches `challenge` extracted from the decrypted token
3. Confirms the origin in clientDataJSON exactly matches the Relying Party's expected origin
4. Verifies the rpIdHash within authenticatorData matches the expected SHA256 hash of the Relying Party ID
5. Verifies both the User Present (UP) and User Verified (UV) flags in authenticatorData are set to 1
6. Computes the SHA-256 hash of clientDataJSON and verifies the cryptographic signature against the registered credential's public key over the binary concatenation of authenticatorData and the clientDataJSON hash

Upon successful validation, the server generates an ephemeral key pair for the intended 2FA session `(server_eprv_2fa, server_epub_2fa)`, derives the session key via `KDF(ECDH(client_epub_2fa, server_eprv_2fa))` and gives it a session id `2fa_session_id`.

Response: 

* `2fa_session_id`: the server assigned session id for the 2FA session.
* `server_epub_2fa`: the server ephemeral public key for the 2FA session.


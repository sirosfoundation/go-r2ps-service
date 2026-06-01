Remote Two-Factor Protected Services (R2PS)
===

# 0. Abstract

This specification defines R2PS, a protocol for exchanging data between a client and a backend services infrastructure, allowing the client to offload critical operations to secure services. Its primary motivation is enabling remote access to resources that protect cryptographic keys, such as a remote WSCD for the EU Digital Identity Wallet (EUDIW).

The protocol provides end-to-end encryption (E2EE) from the client to the backend providing the service and enforces security-context isolation between backend services. Each service type declares whether it requires one or two authentication factors and all service types share a common request/response structure.

# 1. Introduction

User devices often cannot satisfy security requirements for sensitive cryptographic operations either because the capability is absent (e.g., in the case of many smartphones), or because it exists but is not yet certified for the intended use (e.g., a FIDO2 Authenticator as a WSCD for the EUDIW).

R2PS distinguishes service types that require only a possession factor from those that additionally require a knowledge factor. Operations not using a private key held in a remote WSCD (e.g., key generation) require only a possession proof; operations using such a key (e.g., signing) additionally require a second factor proof. R2PS accommodates many methods of establishing the second-factor proof.

The E2EE is designed to meet the following security requirements:

- Two-factor protected service data is encrypted under a key that provides forward secrecy.
- Keys used to encrypt service data in different security contexts are cryptographically separated.

Key concepts are defined next.

## 1.1. Definitions

* **Service data**: The application-level payload of a service request or response. It excludes transport- and protocol-level information.
* **Security context**: A named scope under which a defined set of service types is offered with a common security and key-management policy. Each context has its own context key set (signing key and agreement key) and its own mechanism to establish the second factor where applicable.

# 2. Service Exchanges

R2PS defines two modes for service exchanges. `1FA` mode requires only a possession factor; `2FA` mode additionally requires a second factor, such as a knowledge factor.

## 2.1. `1FA` mode

`1FA` applies to service types that do not use a private key protected by the remote WSCD. 

Deployments choose how to carry out the possession-factor proof. The RECOMMENDED method is to register a client context agreement key (CAK) and context signing key (CSK), used for E2EE and signing respectively. When this method is used, the client MUST generate a distinct CAK and CSK per security context. A CAK MUST NOT be used for any purpose other than ECDH key agreement, and a CSK MUST NOT be used for any purpose other than signing.

All `1FA` exchanges MUST be E2EE and SHOULD use JWE with `alg` set to `ECDH-ES` and `enc` to `A256GCM` as defined in [RFC7518](https://datatracker.ietf.org/doc/html/rfc7518#section-4.6), applied independently in each direction. Deployments MAY agree on alternatives out-of-band.

## 2.2. `2FA` mode

`2FA` mode proves the user's second factor. It applies to service types that use a private key protected by the remote WSCD.

Establishing the second-factor proof is itself a service type, carried in `1FA` mode, that on success establishes a `2FA`-authenticated session. Deployments choose how the proof is completed; the available approaches fall into two models:

1. **Device-attested**: a key attestation asserts that the hardware-protected private key requires local user authentication (password or biometrics) before use. The second factor is established locally.
2. **Server-verified**: the server checks the second factor (normally a password) against a registered object (e.g., a PIN entered on a smartphone).

For the server-verified model with a knowledge-based second factor, the RECOMMENDED mechanism is an augmented Password-Authenticated Key Exchange (aPAKE), which never exposes the knowledge factor to the server and ensures a cryptographic binding to the knowledge factor. When using an aPAKE verifier, deployments MAY add secret entropy to the password object.

If an aPAKE is unavailable, deployments SHOULD use a KDF-based salted password verifier. When using a KDF-based salted password verifier, deployments SHOULD add secret entropy to the password object.

Deployments MAY use a salted password hash. If a salted password hash is used, deployments MUST add secret entropy to the password object.

The mechanisms differ across two further dimensions:

* **Server second factor knowledge**: In the device-attested model and the aPAKE flow, the server learns nothing about the second factor beyond that it was established. The KDF-based and salted-hash password methods reveal the plaintext password to the server.
* **Binding and enforcement**: With an aPAKE session, the server is structurally unable to process the service data without validating the second factor. The device-attested (FIDO2) method binds the second factor to the session cryptographically via a signature, but the server can establish the session without validating that signature—the binding exists, but its enforcement is policy-based. The password methods are policy-based without a cryptographic binding between a second factor and the session.

Mechanisms to add secret entropy are discussed next.

### 2.2.1. Adding Secret Entropy

Too add additional secret entropy into the derivation of the verification key `vk`, deployments SHOULD use one of two different mechanisms:

1. **Device-Enhanced Password (DE-PWD) hardening**: Sources entropy from the user device and MUST be used where resistance to offline guessing under server compromise is required.
2. **Post-hash pepper**: Sources entropy from the server and MUST NOT be relied upon as the sole secret entropy where server-compromise resistance is required.

The two mechanisms source that secret from two different places and therefore resist different threats.

#### 2.2.1.1. Device-Enhanced Password

DE-PWD sources secret entropy from the user's device by binding the password to a client held secret. Deployments are RECOMMENDED to use the client's private CAK as the secret.

The DE-PWD value replaces the raw password as input to the verifier method (aPAKE, KDF, or hash). Any DE-PWD generation algorithm MAY be used without affecting interoperability, provided that it is: 1) deterministic, 2) influenced by a suitable secret such as the private CAK, and 3) identical at registration and at authentication.

The following derivation algorithm is RECOMMENDED:

1. Compute `point = hash2curve(password)`
2. Compute `ikm = ECDH(CAK_private, point)` 
3. Compute `de_pwd = HKDF(ikm)`

producing a 32 byte value, where `CAK_private` is the client's registered private context agreement key, `hash2curve()` is defined in [RFC9380](https://datatracker.ietf.org/doc/rfc9380/), and `password` is the knowledge factor. The specific parameters and inputs must be fixed.

#### 2.2.1.2. Post-hash Pepper

A post-hash pepper sources secret entropy from the server. The stored verifier is processed with a keyed HMAC under a server-held secret (the pepper) before storage:

`vk_stored = HMAC(pepper, vk)`

The pepper is the HMAC key and MUST be generated and sized per the requirements of the chosen HMAC (e.g., HMAC-SHA256). It MUST be stored separately from the verifier database (for example, in an HSM or a distinct secret store).

A pepper protects the verifier database against disclosure when the pepper is not also disclosed. Consistent with §1.2.2, it MUST NOT be the sole secret entropy where server-compromise resistance is required.

### 2.2.2. Server-verified Knowledge Factor

The mechanisms below establish a knowledge-factor and MUST be completed once `1FA` is established.

**Using a Hashed Salted Password**

In this method the server stores a verification key `vk` derived from the user's password and a per-user random salt:

`vk = H(password + salt)`

where `H` is a secure cryptographic hash function such as SHA-256. The server stores the pair `{salt, vk}` associated with the user's account and security context.

The salt MUST be generated from a cryptographically secure random source and MUST be unique per verifier. The specific salt generation and storage scheme is otherwise deployment-defined.

To authenticate, the client transmits the password in an E2EE service request, and the server recomputes the `vk` and compares it to the stored verifier. A successful match completes the knowledge-factor proof.

**Using a KDF-based Salted Password**

In this method the server stores a verification key `vk` derived from the user's password and a per-user random salt using a password-hashing key derivation function

`vk = KDF(password + salt)`

where `KDF` is a hard slow hashing algorithm like Argon2id, bcrypt, or PBKDF2. The server stores the pair `{salt, vk}` associated with the user's account and security context, together with the KDF parameters needed to reproduce the derivation. 

The salt MUST be generated from a cryptographically secure random source and MUST be unique per verifier. The specific salt generation, parameter selection, and storage scheme is otherwise deployment-defined (for parameter selection, see [OWASP Password Storage Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/Password_Storage_Cheat_Sheet.html)).

**Using an aPAKE**

In this method, the user's knowledge factor is authenticated without the server ever learning it. In `2FA` mode, completion of the aPAKE exchange constitutes the knowledge-factor proof; with DE-PWD additionally relies on a device-provided secret entropy.

This version of R2PS uses OPAQUE as the aPAKE.

#### 2.2.3 Device-Attested Second Factor

In this method the second factor is established and verified locally by the user's FIDO2 authenticator, rather than by server-side password verification. 

The same credential serves as both factors: possession is demonstrated by a valid assertion under the registered credential key, and the knowledge or inherence factor is demonstrated by the authenticator performing user verification (UV).

The authenticator holds the context signing key (CSK) as a FIDO2 credential registered, with user verification capability, to the user's account and security context. Every assertion carries user presence (UP); `2FA` service types additionally require user verification (UV), according to what the requested service type demands.

For `2FA` service types the client requests UV, and the authenticator prompts the user for a PIN or biometric and sets the UV flag in the signed assertion; for 1FA service types user presence alone suffices. The server MUST verify the UV flag is set in the signed assertion to complete the second-factor check.

# 3. The JWE

Every service request and response is end-to-end encrypted between the client and the backend server, and takes the form of a JWE [RFC7516](https://datatracker.ietf.org/doc/rfc7516/) in compact serialization carrying the signed service exchange. The backend server determines the encryption mode from the JWE header. How the JWE is routed to the correct backend server is out of scope for this specification.

## 3.1. The JWE in `1FA` mode

In `1FA` mode, the JWE CEK is derived via ECDH-ES. The header has these parameters:

* `alg` MUST be `ECDH-ES`
* `enc` MUST be `A256GCM`
* `epk` contains the sender's ephemeral public key.
* `kid` identifies the recipient's static key agreement key (server's static ECDH key for requests; client's CAK for responses).
* `apu` (base64url-encoded string) MUST be `client_id` for requests and `context` for responses.
* `apv` (base64url-encoded string) MUST be `context` for requests and `client_id` for responses.
* `cty` MUST be `JWT`

where `context` is the security context and `client_id` is the client identifier for that context. How the client obtains the server's static ECDH public key and its `kid` is deployment-defined and out of scope.

The resulting JWE in compact serialization will be structured as `<encoded-header>..<encoded-iv>.<encoded-ciphertext>.<encoded-tag>`.

## 3.2. The JWE in `2FA` mode

In `2FA` mode, a fresh random CEK MUST be generated for each message and protected using the negotiated `2FA` session key. 

The RECOMMENDED encryption operation is key wrapping, where each CEK is wrapped using a key derived from the session key as the key-encryption key (KEK). When key wrapping is used, the JWE header has these parameters:

* `alg` MUST be `A256KW`
* `enc` MUST be `A256GCM`
* `kid` MUST be the session key identifier.
* `cty` MUST be `JWT`

The KEK is derived from the `2FA` session key using HKDF [RFC5869](https://datatracker.ietf.org/doc/rfc5869/) as follows:

* Hash function: SHA-256.
* Input keying material `ikm`: the `2FA` session key.
* Salt: empty.
* Output length `L`: 32 bytes.
* `info`: the concatenation of the fields below, each prefixed by its length as a 4-byte big-endian unsigned integer:
  * `dst`: domain separation tag, the ASCII bytes of `"R2PS-2FA-KEK-1.0"`.
  * `direction`: the 3-byte ASCII string `"c2s"` for client-to-server messages, `"s2c"` for server-to-client messages.
  * `session_id`: the `2FA` session identifier.

The resulting JWE in compact serialization will be structured as `<encoded-header>.<encoded-encryptedkey>.<encoded-iv>.<encoded-ciphertext>.<encoded-tag>`. The IV MUST be a freshly generated 96-bit random nonce for each message.

This profile uses key wrap; other profiles MAY define alternatives.

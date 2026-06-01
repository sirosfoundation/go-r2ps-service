Service Type Profile: EU Digital Identity Wallet
===

# 1. ETSI Wallet Attestations

This service type profile defines two service types: 

1. ETSI Wallet Key Attestation
2. ETSI Wallet Instance Attestation

## 1.1. Wallet Key Attestation

**Service type name**: ETSI Wallet Key Attestation

* **Identifier**: `eudiw_wka_etsi`
* **Mode**: `1FA`
* **Session Prerequisites**: A hardware-protected private key associated with the client's possession factor. Note that key generation is a `1FA` service exchange.
* **State Values**: Single-round.

Purpose: Requests a Wallet Key Attestation (WKA) as defined in ETSI TS 119 476-3 V0.0.8.

Request `data` Schema:

* `keys_to_attest` (**array of strings**, required): A non-empty array of key identifiers for the keys to be attested.
* `ver` (**string**, required): The ETSI TS 119 476-3 version identifier specifying the layout format (e.g., `"draft-008"`).

Response `data` Schema:

* `wka` (**string**): The generated WKA formatted as a JSON Web Token (JWT) matching the requested ETSI version.

**Worked Example**:

Request payload:

```json
{
  "ver": "1.0",
  "nonce": "b8b...615",
  "iat": 1774892400,
  "data": {
    "keys_to_attest": ["key-0"],
    "ver": "draft-008"
  },
  "client_id": "https://example.com/wallet/1",
  "context": "wua",
  "type": "eudiw_wka_etsi"
}
```

Response payload:

```json
{
  "ver": "1.0",
  "nonce": "b8b...615",
  "iat": 1774892410,
  "data": {
    "wka": "eyJ0eXAiOiJrZXktYXR0ZXN0YXRpb24ranNvb..."
  }
}
```

Decoded `wka`:

```json
{
  "typ": "key-attestation+jwt",
  "alg": "ES256",
  "x5c": ["MIIDQjCCA..."]
}
.
{
  "iat": "<Unix timestamp>",
  "exp": "<Unix timestamp>",
  "wallet_link": "https://wp.example.com/eudiw-info",
  "key_storage_status": {
    "status": {
      "status_list": {
        "idx": "<index>",
        "uri": "https://wp.example.com/statuslists/wka/1"
      }
    }
  },
  "attested_keys": [
    {
      "kty": "EC",
      "crv": "P-256",
      "x": "<x-coordinate>",
      "y": "<y-coordinate>"
    }
  ],
  "key_storage": ["iso_18045_high"],
  "user_authentication": ["iso_18045_high"],
  "certification": "https://certbody.example.org/cert/1/"
}
```

**Additional info**:

* Special reject conditions:
  * The server MUST NOT include any invalid keys within the `keys_to_attest` array in the WKA.
  * ETSI TS 119 476-3 Version Number MUST be `draft-008` for the ETSI TS 119 476-3 V0.0.8 draft.
 
## 1.2. Wallet Instance Attestation

**Service type name**: ETSI Wallet Instance Attestation

* **Identifier**: `eudiw_wia_etsi`
* **Mode**: `1FA`
* **Session Prerequisites**: A WKA.
* **State Values**: Single-round.

Purpose: Requests a Wallet Instance Attestation (WIA) as defined in ETSI TS 119 476-3 V0.0.8.

Request `data` Schema:

* `keys_to_attest` (**array of strings**, required): A non-empty array of key identifiers associated with the wallet instance.
* `ver` (**string**, required): The ETSI TS 119 476-3 version identifier specifying the layout format (e.g., `"draft-008"`).

Response `data` Schema:

* `wia` (**string**): The generated WIA formatted as a JSON Web Token (JWT) matching the requested ETSI version.

**Worked Example**:

Request payload:

```json
{
  "ver": "1.0",
  "nonce": "13b...615",
  "iat": 1774892500,
  "data": {
    "keys_to_attest": ["key-0"],
    "ver": "draft-008"
  },
  "client_id": "https://example.com/wallet/1",
  "context": "wua",
  "type": "eudiw_wia_etsi"
}
```

Response payload:

```json
{
  "ver": "1.0",
  "nonce": "13b...615",
  "iat": 1774892510,
  "data": {
    "wia": "eyJYXR0ZXN0eXAYXRpranb24NvbiOiJrZXkt0..."
  }
}
```

Decoded `wia`:

```json
{
  "typ": "oauth-client-attestation+jwt",
  "alg": "ES256",
  "x5c": ["MIIDDTCCA..."]
}
.
{
  "iat": "<Unix timestamp>",
  "exp": "<Unix timestamp>",
  "sub": "https://example.com/wallet/1",
  "wallet_link": "https://wp.example.com/eudiw-info",
  "client_status": {
    "status": {
      "status_list": {
        "idx": "<index>",
        "uri": "https://wp.example.com/statuslists/wia/1"
      }
    },
    "exp": "<Unix timestamp>"
  },
  "cnf": {
    "jwk": {
      "kty": "EC",
      "use": "sig",
      "crv": "P-256",
      "x": "<x-coordinate>",
      "y": "<y-coordinate>"
    }
  }
}
```

**Additional info**:

* Special reject conditions:
  * The server MUST NOT include any invalid keys within the `keys_to_attest` array in the WIA.
  * ETSI TS 119 476-3 Version Number MUST be `draft-008` for the ETSI TS 119 476-3 V0.0.8 draft.

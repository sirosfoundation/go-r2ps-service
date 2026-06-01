| Identifier         | Purpose                                         | Mode   | Status    |
|--------------------|-------------------------------------------------|--------|-----------|
| `2fa_registration` | Establishes a new second factor                 | `1FA`  | Completed |
| `2fa_authenticate` | Verifies the second factor and opens a session  | `1FA`  | Completed |
| `2fa_change`       | Replaces an existing second factor              | `2FA`  | Completed |
| `eudiw_wka_etsi`   | Issuance of an ETSI Wallet Key Attestation      | `1FA`  | Completed |
| `eudiw_wia_etsi`   | Issuance of an ETSI Wallet Instance Attestation | `1FA`  | Completed |
| `eudiw_wi_revoke`  | Client triggered revocation of wallet instance  | `1FA`  | TODO      |
| `eudiw_wi_suspend` | Client triggered suspension of EUDIW instance   | `1FA`  | TODO      |
| `eudiw_wi_add`     | Client adds new EUDIW instance to their account | `1FA`  | TODO      |
| `p256_generate`    | Generates a P-256 key at security context `hsm` | `1FA`  | TODO      |
| `sign_ecdsa`       | Creates a raw ECDSA at security context `hsm`   | `2FA`  | TODO      |
| `agree_ecdh`       | Performs ECDH at security context `hsm`         | `2FA`  | TODO      |

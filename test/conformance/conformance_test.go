package conformance

import (
	"encoding/hex"
	"encoding/json"
	"os"
	"path/filepath"
	"testing"

	icrypto "github.com/sirosfoundation/go-r2ps-service/internal/crypto"
	"github.com/sirosfoundation/go-r2ps-service/pkg/r2ps"
)

// vectorFiles returns the list of vector files to validate.
// Always includes vectors_go.json; includes vectors_rust.json if present.
func vectorFiles(t *testing.T) []string {
	t.Helper()
	base := filepath.Join("..", "..", "testdata")
	var files []string
	goPath := filepath.Join(base, "vectors_go.json")
	if _, err := os.Stat(goPath); err == nil {
		files = append(files, goPath)
	} else {
		t.Fatalf("vectors_go.json not found — run TestGenerateGoVectors first")
	}
	rustPath := filepath.Join(base, "vectors_rust.json")
	if _, err := os.Stat(rustPath); err == nil {
		files = append(files, rustPath)
	} else {
		t.Logf("vectors_rust.json not found — skipping Rust cross-validation")
	}
	return files
}

// ============================================================
// Layer 1: JWS / JWE crypto interop
// ============================================================

func TestJWSVerify(t *testing.T) {
	for _, path := range vectorFiles(t) {
		v := loadVectors(t, path)
		t.Run(v.Generator+"/jws_verify", func(t *testing.T) {
			pub := parseECPublicKey(t, v.Keys.ECPublicSPKIPEM)
			payload, err := icrypto.VerifyJWS(v.JWS.Compact, pub)
			if err != nil {
				t.Fatalf("VerifyJWS: %v", err)
			}
			expected, _ := hex.DecodeString(v.JWS.PayloadHex)
			if string(payload) != string(expected) {
				t.Fatalf("payload mismatch: got %q, want %q", payload, expected)
			}
		})
	}
}

func TestJWSHeaders(t *testing.T) {
	for _, path := range vectorFiles(t) {
		v := loadVectors(t, path)
		t.Run(v.Generator+"/jws_headers", func(t *testing.T) {
			hdrs, err := icrypto.PeekJWSHeaders(v.JWS.Compact)
			if err != nil {
				t.Fatalf("PeekJWSHeaders: %v", err)
			}
			if kid, ok := hdrs["kid"].(string); !ok || kid != v.JWS.Kid {
				t.Errorf("kid: got %v, want %s", hdrs["kid"], v.JWS.Kid)
			}
			if typ, ok := hdrs["typ"].(string); !ok || typ != v.JWS.Typ {
				t.Errorf("typ: got %v, want %s", hdrs["typ"], v.JWS.Typ)
			}
		})
	}
}

func TestJWEDecryptECDH(t *testing.T) {
	for _, path := range vectorFiles(t) {
		v := loadVectors(t, path)
		t.Run(v.Generator+"/jwe_ecdh_decrypt", func(t *testing.T) {
			priv := parseECPrivateKey(t, v.Keys.ECPrivatePKCS8PEM)
			plaintext, err := icrypto.DecryptJWE(v.JWEEcdh.Compact, priv)
			if err != nil {
				t.Fatalf("DecryptJWE: %v", err)
			}
			expected, _ := hex.DecodeString(v.JWEEcdh.PlaintextHex)
			if string(plaintext) != string(expected) {
				t.Fatalf("plaintext mismatch: got %q, want %q", plaintext, expected)
			}
		})
	}
}

func TestJWEDecryptSymmetric(t *testing.T) {
	for _, path := range vectorFiles(t) {
		v := loadVectors(t, path)
		t.Run(v.Generator+"/jwe_symmetric_decrypt", func(t *testing.T) {
			key, _ := hex.DecodeString(v.Keys.SymmetricKeyHex)
			plaintext, err := icrypto.DecryptJWESymmetric(v.JWESym.Compact, key)
			if err != nil {
				t.Fatalf("DecryptJWESymmetric: %v", err)
			}
			expected, _ := hex.DecodeString(v.JWESym.PlaintextHex)
			if string(plaintext) != string(expected) {
				t.Fatalf("plaintext mismatch: got %q, want %q", plaintext, expected)
			}
		})
	}
}

// ============================================================
// Layer 2: Protocol type conformance (R2PS spec §3)
// ============================================================

func TestProtocolServiceRequest(t *testing.T) {
	for _, path := range vectorFiles(t) {
		v := loadVectors(t, path)
		t.Run(v.Generator+"/service_request", func(t *testing.T) {
			var req r2ps.ServiceRequest
			if err := json.Unmarshal([]byte(v.Protocol.ServiceRequestJSON), &req); err != nil {
				t.Fatalf("unmarshal: %v", err)
			}
			// Verify required fields per spec §3.1.1 and §3.1.2
			assertNonEmpty(t, "ver", req.Ver)
			assertNonEmpty(t, "nonce", req.Nonce)
			if req.Iat == 0 {
				t.Error("iat must not be zero")
			}
			assertNonEmpty(t, "enc", req.Enc)
			assertNonEmpty(t, "data", req.Data)
			assertNonEmpty(t, "client_id", req.ClientID)
			assertNonEmpty(t, "kid", req.Kid)
			assertNonEmpty(t, "context", req.Context)
			assertNonEmpty(t, "type", req.Type)

			// Verify enc is valid
			if req.Enc != r2ps.EncDevice && req.Enc != r2ps.EncUser {
				t.Errorf("enc must be %q or %q, got %q", r2ps.EncDevice, r2ps.EncUser, req.Enc)
			}

			// Verify version
			if req.Ver != r2ps.ProtocolVersion {
				t.Errorf("ver: got %q, want %q", req.Ver, r2ps.ProtocolVersion)
			}

			// Verify JSON field names match spec
			raw := make(map[string]json.RawMessage)
			json.Unmarshal([]byte(v.Protocol.ServiceRequestJSON), &raw)
			requiredFields := []string{"ver", "nonce", "iat", "enc", "data", "client_id", "kid", "context", "type"}
			for _, f := range requiredFields {
				if _, ok := raw[f]; !ok {
					t.Errorf("missing required field %q in JSON", f)
				}
			}
		})
	}
}

func TestProtocolServiceResponse(t *testing.T) {
	for _, path := range vectorFiles(t) {
		v := loadVectors(t, path)
		t.Run(v.Generator+"/service_response", func(t *testing.T) {
			var resp r2ps.ServiceResponse
			if err := json.Unmarshal([]byte(v.Protocol.ServiceResponseJSON), &resp); err != nil {
				t.Fatalf("unmarshal: %v", err)
			}
			assertNonEmpty(t, "ver", resp.Ver)
			assertNonEmpty(t, "nonce", resp.Nonce)
			if resp.Iat == 0 {
				t.Error("iat must not be zero")
			}
			assertNonEmpty(t, "enc", resp.Enc)
			assertNonEmpty(t, "data", resp.Data)

			// Response MUST NOT contain request-only fields (spec §3.1.3)
			raw := make(map[string]json.RawMessage)
			json.Unmarshal([]byte(v.Protocol.ServiceResponseJSON), &raw)
			forbidden := []string{"client_id", "kid", "context", "type", "pake_session_id"}
			for _, f := range forbidden {
				if _, ok := raw[f]; ok {
					t.Errorf("response MUST NOT contain request field %q (spec §3.1.3)", f)
				}
			}
		})
	}
}

func TestProtocolPAKERequest(t *testing.T) {
	for _, path := range vectorFiles(t) {
		v := loadVectors(t, path)
		t.Run(v.Generator+"/pake_request", func(t *testing.T) {
			var req r2ps.PAKERequest
			if err := json.Unmarshal([]byte(v.Protocol.PAKERequestJSON), &req); err != nil {
				t.Fatalf("unmarshal: %v", err)
			}
			assertNonEmpty(t, "protocol", req.Protocol)
			assertNonEmpty(t, "state", req.State)
			assertNonEmpty(t, "req", req.Req)

			// Verify protocol identifier
			if req.Protocol != r2ps.PAKEProtocolOPAQUE {
				t.Logf("non-OPAQUE protocol: %q", req.Protocol)
			}

			// Verify state is valid
			if req.State != r2ps.PAKEStateEvaluate && req.State != r2ps.PAKEStateFinalize {
				t.Errorf("state must be %q or %q, got %q",
					r2ps.PAKEStateEvaluate, r2ps.PAKEStateFinalize, req.State)
			}

			// Verify spec field names
			raw := make(map[string]json.RawMessage)
			json.Unmarshal([]byte(v.Protocol.PAKERequestJSON), &raw)
			for _, f := range []string{"protocol", "state", "req"} {
				if _, ok := raw[f]; !ok {
					t.Errorf("missing required field %q in JSON", f)
				}
			}
		})
	}
}

func TestProtocolPAKEResponse(t *testing.T) {
	for _, path := range vectorFiles(t) {
		v := loadVectors(t, path)
		t.Run(v.Generator+"/pake_response", func(t *testing.T) {
			var resp r2ps.PAKEResponse
			if err := json.Unmarshal([]byte(v.Protocol.PAKEResponseJSON), &resp); err != nil {
				t.Fatalf("unmarshal: %v", err)
			}
			// At least one of pake_session_id or resp must be present
			if resp.PakeSessionID == "" && resp.Resp == "" {
				t.Error("pake_response: at least pake_session_id or resp must be present")
			}

			// Verify spec field names
			raw := make(map[string]json.RawMessage)
			json.Unmarshal([]byte(v.Protocol.PAKEResponseJSON), &raw)
			for key := range raw {
				switch key {
				case "pake_session_id", "resp", "msg", "task", "session_expiration_time":
					// valid
				default:
					t.Errorf("unexpected field %q in PAKE response (not in spec §3.3.1.2)", key)
				}
			}
		})
	}
}

func TestProtocolErrorResponse(t *testing.T) {
	for _, path := range vectorFiles(t) {
		v := loadVectors(t, path)
		t.Run(v.Generator+"/error_response", func(t *testing.T) {
			var resp r2ps.ErrorResponse
			if err := json.Unmarshal([]byte(v.Protocol.ErrorResponseJSON), &resp); err != nil {
				t.Fatalf("unmarshal: %v", err)
			}
			assertNonEmpty(t, "error_code", resp.ErrorCode)
			assertNonEmpty(t, "error_message", resp.ErrorMessage)

			// Verify error_code is one of the defined codes (spec §3.2)
			validCodes := map[string]bool{
				r2ps.ErrIllegalRequestData: true,
				r2ps.ErrUnauthorized:       true,
				r2ps.ErrAccessDenied:       true,
				r2ps.ErrIllegalState:       true,
				r2ps.ErrUnsupportedType:    true,
				r2ps.ErrServerError:        true,
				r2ps.ErrTryLater:           true,
			}
			if !validCodes[resp.ErrorCode] {
				t.Errorf("unknown error_code %q — not in spec §3.2", resp.ErrorCode)
			}
		})
	}
}

// ============================================================
// Layer 3: HSM service type conformance
// (spec: security/remote-hsm-apake-service-types.md)
// ============================================================

func TestHSMKeygenRequest(t *testing.T) {
	for _, path := range vectorFiles(t) {
		v := loadVectors(t, path)
		t.Run(v.Generator+"/hsm_keygen_request", func(t *testing.T) {
			var req SpecECKeygenRequest
			if err := json.Unmarshal([]byte(v.HSM.ECKeygenRequestJSON), &req); err != nil {
				t.Fatalf("unmarshal: %v", err)
			}
			assertNonEmpty(t, "curve", req.Curve)

			// Verify only spec fields are present
			raw := make(map[string]json.RawMessage)
			json.Unmarshal([]byte(v.HSM.ECKeygenRequestJSON), &raw)
			for key := range raw {
				if key != "curve" {
					t.Errorf("unexpected field %q — spec §1.2 defines only 'curve'", key)
				}
			}
		})
	}
}

func TestHSMKeygenResponse(t *testing.T) {
	for _, path := range vectorFiles(t) {
		v := loadVectors(t, path)
		t.Run(v.Generator+"/hsm_keygen_response", func(t *testing.T) {
			var resp SpecECKeygenResponse
			if err := json.Unmarshal([]byte(v.HSM.ECKeygenResponseJSON), &resp); err != nil {
				t.Fatalf("unmarshal: %v", err)
			}
			assertNonEmpty(t, "created_key", resp.CreatedKey)

			// Verify only spec fields: 'created_key' (spec §1.2)
			raw := make(map[string]json.RawMessage)
			json.Unmarshal([]byte(v.HSM.ECKeygenResponseJSON), &raw)
			if _, ok := raw["created_key"]; !ok {
				t.Error("missing spec-required field 'created_key' (spec §1.2)")
			}
			// Non-spec fields that Go service currently uses
			for _, bad := range []string{"kid", "pub_key"} {
				if _, ok := raw[bad]; ok {
					t.Errorf("non-spec field %q present — spec §1.2 defines only 'created_key'", bad)
				}
			}
		})
	}
}

func TestHSMECDSARequest(t *testing.T) {
	for _, path := range vectorFiles(t) {
		v := loadVectors(t, path)
		t.Run(v.Generator+"/hsm_ecdsa_request", func(t *testing.T) {
			var req SpecECDSARequest
			if err := json.Unmarshal([]byte(v.HSM.ECDSARequestJSON), &req); err != nil {
				t.Fatalf("unmarshal: %v", err)
			}
			assertNonEmpty(t, "kid", req.Kid)
			assertNonEmpty(t, "tbs_hash", req.TbsHash)

			// Verify spec field names (spec §3.2)
			raw := make(map[string]json.RawMessage)
			json.Unmarshal([]byte(v.HSM.ECDSARequestJSON), &raw)
			if _, ok := raw["tbs_hash"]; !ok {
				t.Error("missing spec-required field 'tbs_hash' (spec §3.2)")
			}
			// The Go service currently uses 'hash' instead of 'tbs_hash'
			if _, ok := raw["hash"]; ok {
				t.Error("non-spec field 'hash' — spec §3.2 requires 'tbs_hash'")
			}
		})
	}
}

func TestHSMECDSAResponse(t *testing.T) {
	for _, path := range vectorFiles(t) {
		v := loadVectors(t, path)
		t.Run(v.Generator+"/hsm_ecdsa_response", func(t *testing.T) {
			// Spec §3.2: response is raw DER signature bytes, not JSON
			sigBytes, err := hex.DecodeString(v.HSM.ECDSAResponseHex)
			if err != nil {
				t.Fatalf("decode hex: %v", err)
			}
			if len(sigBytes) == 0 {
				t.Fatal("empty ECDSA response")
			}
			// Verify it looks like ASN.1 DER: starts with 0x30 (SEQUENCE)
			if sigBytes[0] != 0x30 {
				t.Errorf("ECDSA response does not start with ASN.1 SEQUENCE tag 0x30, got 0x%02x", sigBytes[0])
			}
		})
	}
}

func TestHSMECDHRequest(t *testing.T) {
	for _, path := range vectorFiles(t) {
		v := loadVectors(t, path)
		t.Run(v.Generator+"/hsm_ecdh_request", func(t *testing.T) {
			var req SpecECDHRequest
			if err := json.Unmarshal([]byte(v.HSM.ECDHRequestJSON), &req); err != nil {
				t.Fatalf("unmarshal: %v", err)
			}
			assertNonEmpty(t, "kid", req.Kid)
			assertNonEmpty(t, "public_key", req.PublicKey)

			// Verify spec field names (spec §4.2)
			raw := make(map[string]json.RawMessage)
			json.Unmarshal([]byte(v.HSM.ECDHRequestJSON), &raw)
			if _, ok := raw["public_key"]; !ok {
				t.Error("missing spec-required field 'public_key' (spec §4.2)")
			}
			// The Go service currently uses 'peer_pub_key' instead of 'public_key'
			if _, ok := raw["peer_pub_key"]; ok {
				t.Error("non-spec field 'peer_pub_key' — spec §4.2 requires 'public_key'")
			}
		})
	}
}

func TestHSMECDHResponse(t *testing.T) {
	for _, path := range vectorFiles(t) {
		v := loadVectors(t, path)
		t.Run(v.Generator+"/hsm_ecdh_response", func(t *testing.T) {
			// Spec §4.2: response is raw shared secret bytes, not JSON
			secret, err := hex.DecodeString(v.HSM.ECDHResponseHex)
			if err != nil {
				t.Fatalf("decode hex: %v", err)
			}
			if len(secret) == 0 {
				t.Fatal("empty ECDH shared secret")
			}
			// For P-256, shared secret should be 32 bytes
			if len(secret) != 32 {
				t.Logf("shared secret is %d bytes (expected 32 for P-256)", len(secret))
			}
		})
	}
}

func TestHSMListKeysRequest(t *testing.T) {
	for _, path := range vectorFiles(t) {
		v := loadVectors(t, path)
		t.Run(v.Generator+"/hsm_list_keys_request", func(t *testing.T) {
			var req SpecListKeysRequest
			if err := json.Unmarshal([]byte(v.HSM.ListKeysRequestJSON), &req); err != nil {
				t.Fatalf("unmarshal: %v", err)
			}

			// Verify spec field name (spec §2.2): 'curve' (not 'curves')
			raw := make(map[string]json.RawMessage)
			json.Unmarshal([]byte(v.HSM.ListKeysRequestJSON), &raw)
			if _, ok := raw["curve"]; !ok {
				t.Error("missing spec-required field 'curve' (spec §2.2)")
			}
			if _, ok := raw["curves"]; ok {
				t.Error("non-spec field 'curves' — spec §2.2 requires 'curve' (singular)")
			}
		})
	}
}

func TestHSMListKeysResponse(t *testing.T) {
	for _, path := range vectorFiles(t) {
		v := loadVectors(t, path)
		t.Run(v.Generator+"/hsm_list_keys_response", func(t *testing.T) {
			var resp SpecListKeysResponse
			if err := json.Unmarshal([]byte(v.HSM.ListKeysResponseJSON), &resp); err != nil {
				t.Fatalf("unmarshal: %v", err)
			}

			// Verify top-level uses 'key_info' not 'keys' (spec §2.2)
			raw := make(map[string]json.RawMessage)
			json.Unmarshal([]byte(v.HSM.ListKeysResponseJSON), &raw)
			if _, ok := raw["key_info"]; !ok {
				t.Error("missing spec-required field 'key_info' (spec §2.2)")
			}
			if _, ok := raw["keys"]; ok {
				t.Error("non-spec field 'keys' — spec §2.2 requires 'key_info'")
			}

			// Validate each key_info entry has spec-required fields
			for i, ki := range resp.KeyInfo {
				assertNonEmpty(t, "key_info[].kid", ki.Kid)
				assertNonEmpty(t, "key_info[].curve_name", ki.CurveName)
				if ki.CreationTime == 0 {
					t.Errorf("key_info[%d].creation_time must not be zero", i)
				}
				assertNonEmpty(t, "key_info[].public_key", ki.PublicKey)
			}

			// Verify key_info entries don't use Go service's non-spec names
			var rawEntries []map[string]json.RawMessage
			if kiRaw, ok := raw["key_info"]; ok {
				json.Unmarshal(kiRaw, &rawEntries)
				for i, entry := range rawEntries {
					for _, bad := range []string{"curve", "pub_key"} {
						if _, ok := entry[bad]; ok {
							t.Errorf("key_info[%d]: non-spec field %q — spec §2.2 requires 'curve_name' and 'public_key'",
								i, bad)
						}
					}
				}
			}
		})
	}
}

// ============================================================
// Helpers
// ============================================================

func assertNonEmpty(t *testing.T, field, value string) {
	t.Helper()
	if value == "" {
		t.Errorf("%s must not be empty", field)
	}
}

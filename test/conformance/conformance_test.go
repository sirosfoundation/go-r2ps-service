package conformance

import (
	"encoding/hex"
	"encoding/json"
	"testing"

	icrypto "github.com/sirosfoundation/go-r2ps-service/internal/crypto"
	"github.com/sirosfoundation/go-r2ps-service/pkg/r2ps"
)

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
// Layer 2: Protocol type conformance
// ============================================================

func TestProtocolServiceRequest(t *testing.T) {
	for _, path := range vectorFiles(t) {
		v := loadVectors(t, path)
		t.Run(v.Generator+"/service_request", func(t *testing.T) {
			var req r2ps.ServiceRequest
			if err := json.Unmarshal([]byte(v.Protocol.ServiceRequestJSON), &req); err != nil {
				t.Fatalf("unmarshal: %v", err)
			}
			assertNonEmpty(t, "ver", req.Ver)
			assertNonEmpty(t, "nonce", req.Nonce)
			if req.Iat == 0 {
				t.Error("iat must not be zero")
			}
			if len(req.Data) == 0 {
				t.Error("data must not be empty")
			}
			assertNonEmpty(t, "client_id", req.ClientID)
			assertNonEmpty(t, "context", req.Context)
			assertNonEmpty(t, "type", req.Type)

			if req.Ver != r2ps.ProtocolVersion {
				t.Errorf("ver: got %q, want %q", req.Ver, r2ps.ProtocolVersion)
			}

			// Verify JSON field names match spec
			raw := make(map[string]json.RawMessage)
			json.Unmarshal([]byte(v.Protocol.ServiceRequestJSON), &raw)
			requiredFields := []string{"ver", "nonce", "iat", "data", "client_id", "context", "type"}
			for _, f := range requiredFields {
				if _, ok := raw[f]; !ok {
					t.Errorf("missing required field %q in JSON", f)
				}
			}
			// Fields removed in new spec
			for _, f := range []string{"enc", "kid"} {
				if _, ok := raw[f]; ok {
					t.Errorf("field %q should not be in JWS payload (removed in spec update)", f)
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
			if len(resp.Data) == 0 {
				t.Error("data must not be empty")
			}

			// Response MUST NOT contain request-only fields
			raw := make(map[string]json.RawMessage)
			json.Unmarshal([]byte(v.Protocol.ServiceResponseJSON), &raw)
			forbidden := []string{"client_id", "context", "type", "2fa_session_id"}
			for _, f := range forbidden {
				if _, ok := raw[f]; ok {
					t.Errorf("response MUST NOT contain request field %q", f)
				}
			}
		})
	}
}

func TestProtocolTFARequest(t *testing.T) {
	for _, path := range vectorFiles(t) {
		v := loadVectors(t, path)
		t.Run(v.Generator+"/tfa_request", func(t *testing.T) {
			var req r2ps.TFARequestData
			if err := json.Unmarshal([]byte(v.Protocol.TFARequestJSON), &req); err != nil {
				t.Fatalf("unmarshal: %v", err)
			}
			// Accept both I-D ("protocol"/"p_data") and legacy ("2fa_mode"/"request") field names
			protocol := req.GetProtocol()
			pData := req.GetPData()
			assertNonEmpty(t, "protocol/2fa_mode", protocol)
			assertNonEmpty(t, "p_data/request", pData)

			validModes := map[string]bool{
				r2ps.TFAModeOPAQUE:   true,
				r2ps.TFAModePassword: true,
				r2ps.TFAModeFIDO2:    true,
			}
			if !validModes[protocol] {
				t.Errorf("invalid protocol/2fa_mode: %q", protocol)
			}

			raw := make(map[string]json.RawMessage)
			json.Unmarshal([]byte(v.Protocol.TFARequestJSON), &raw)
			// Accept either I-D or legacy field names
			hasProtocol := false
			for _, f := range []string{"protocol", "2fa_mode"} {
				if _, ok := raw[f]; ok {
					hasProtocol = true
				}
			}
			if !hasProtocol {
				t.Error("missing required field 'protocol' or '2fa_mode' in JSON")
			}
			hasPData := false
			for _, f := range []string{"p_data", "request"} {
				if _, ok := raw[f]; ok {
					hasPData = true
				}
			}
			if !hasPData {
				t.Error("missing required field 'p_data' or 'request' in JSON")
			}
		})
	}
}

func TestProtocolTFAResponse(t *testing.T) {
	for _, path := range vectorFiles(t) {
		v := loadVectors(t, path)
		t.Run(v.Generator+"/tfa_response", func(t *testing.T) {
			var resp r2ps.TFAResponseData
			if err := json.Unmarshal([]byte(v.Protocol.TFAResponseJSON), &resp); err != nil {
				t.Fatalf("unmarshal: %v", err)
			}
			if resp.GetPData() == "" && resp.Message == "" {
				t.Error("at least p_data/response or message must be present")
			}

			raw := make(map[string]json.RawMessage)
			json.Unmarshal([]byte(v.Protocol.TFAResponseJSON), &raw)
			for key := range raw {
				switch key {
				case "p_data", "response", "message":
				default:
					t.Errorf("unexpected field %q in TFA response data", key)
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
				t.Errorf("unknown error_code %q", resp.ErrorCode)
			}
		})
	}
}

// ============================================================
// Layer 3: Service type conformance
// ============================================================

func TestHSMKeygenRequest(t *testing.T) {
	for _, path := range vectorFiles(t) {
		v := loadVectors(t, path)
		t.Run(v.Generator+"/keygen_request", func(t *testing.T) {
			var req SpecECKeygenRequest
			if err := json.Unmarshal([]byte(v.HSM.ECKeygenRequestJSON), &req); err != nil {
				t.Fatalf("unmarshal: %v", err)
			}
			assertNonEmpty(t, "curve", req.Curve)
		})
	}
}

func TestHSMECDSARequest(t *testing.T) {
	for _, path := range vectorFiles(t) {
		v := loadVectors(t, path)
		t.Run(v.Generator+"/ecdsa_request", func(t *testing.T) {
			var req SpecECDSARequest
			if err := json.Unmarshal([]byte(v.HSM.ECDSARequestJSON), &req); err != nil {
				t.Fatalf("unmarshal: %v", err)
			}
			assertNonEmpty(t, "kid", req.Kid)
			assertNonEmpty(t, "tbs_hash", req.TbsHash)
		})
	}
}

func TestHSMECDSAResponse(t *testing.T) {
	for _, path := range vectorFiles(t) {
		v := loadVectors(t, path)
		t.Run(v.Generator+"/ecdsa_response", func(t *testing.T) {
			sigBytes, err := hex.DecodeString(v.HSM.ECDSAResponseHex)
			if err != nil {
				t.Fatalf("decode hex: %v", err)
			}
			if len(sigBytes) == 0 {
				t.Fatal("empty ECDSA response")
			}
			if sigBytes[0] != 0x30 {
				t.Errorf("ECDSA response does not start with ASN.1 SEQUENCE tag, got 0x%02x", sigBytes[0])
			}
		})
	}
}

func TestHSMECDHRequest(t *testing.T) {
	for _, path := range vectorFiles(t) {
		v := loadVectors(t, path)
		t.Run(v.Generator+"/ecdh_request", func(t *testing.T) {
			var req SpecECDHRequest
			if err := json.Unmarshal([]byte(v.HSM.ECDHRequestJSON), &req); err != nil {
				t.Fatalf("unmarshal: %v", err)
			}
			assertNonEmpty(t, "kid", req.Kid)
			assertNonEmpty(t, "public_key", req.PublicKey)
		})
	}
}

// ============================================================
// 2FA registration flow
// ============================================================

func TestTFARegistrationOPAQUE(t *testing.T) {
	for _, path := range vectorFiles(t) {
		v := loadVectors(t, path)
		t.Run(v.Generator+"/2fa_reg_evaluate", func(t *testing.T) {
			if v.Protocol.TFARegEvaluateReq == "" {
				t.Skip("no 2FA registration vectors")
			}
			var req r2ps.TFARequestData
			json.Unmarshal([]byte(v.Protocol.TFARegEvaluateReq), &req)
			if req.GetProtocol() != r2ps.TFAModeOPAQUE {
				t.Errorf("protocol=%q, want opaque", req.GetProtocol())
			}
			if req.State != r2ps.StateEvaluate {
				t.Errorf("state=%q, want evaluate", req.State)
			}
			assertNonEmpty(t, "p_data/request", req.GetPData())

			var resp r2ps.TFAResponseData
			json.Unmarshal([]byte(v.Protocol.TFARegEvaluateResp), &resp)
			assertNonEmpty(t, "p_data/response", resp.GetPData())
		})

		t.Run(v.Generator+"/2fa_reg_finalize", func(t *testing.T) {
			if v.Protocol.TFARegFinalizeReq == "" {
				t.Skip("no 2FA registration vectors")
			}
			var req r2ps.TFARequestData
			json.Unmarshal([]byte(v.Protocol.TFARegFinalizeReq), &req)
			if req.State != r2ps.StateFinalize {
				t.Errorf("state=%q, want finalize", req.State)
			}

			var resp r2ps.TFAResponseData
			json.Unmarshal([]byte(v.Protocol.TFARegFinalizeResp), &resp)
			if resp.Message != "success" {
				t.Errorf("message=%q, want success", resp.Message)
			}
		})
	}
}

// ============================================================
// 2FA authentication flow
// ============================================================

func TestTFAAuthenticationOPAQUE(t *testing.T) {
	for _, path := range vectorFiles(t) {
		v := loadVectors(t, path)
		t.Run(v.Generator+"/2fa_auth_evaluate", func(t *testing.T) {
			if v.Protocol.TFAAuthEvaluateReq == "" {
				t.Skip("no 2FA auth vectors")
			}
			var req r2ps.TFARequestData
			json.Unmarshal([]byte(v.Protocol.TFAAuthEvaluateReq), &req)
			if req.GetProtocol() != r2ps.TFAModeOPAQUE {
				t.Errorf("protocol=%q, want opaque", req.GetProtocol())
			}
			if req.State != r2ps.StateEvaluate {
				t.Errorf("state=%q, want evaluate", req.State)
			}

			var resp r2ps.TFAAuthResponseData
			json.Unmarshal([]byte(v.Protocol.TFAAuthEvaluateResp), &resp)
			assertNonEmpty(t, "session_id/2fa_session_id", resp.GetSessionID())
		})

		t.Run(v.Generator+"/2fa_auth_finalize", func(t *testing.T) {
			if v.Protocol.TFAAuthFinalizeReq == "" {
				t.Skip("no 2FA auth vectors")
			}
			var req r2ps.TFARequestData
			json.Unmarshal([]byte(v.Protocol.TFAAuthFinalizeReq), &req)
			if req.State != r2ps.StateFinalize {
				t.Errorf("state=%q, want finalize", req.State)
			}

			var resp r2ps.TFAAuthResponseData
			json.Unmarshal([]byte(v.Protocol.TFAAuthFinalizeResp), &resp)
			assertNonEmpty(t, "session_id/2fa_session_id", resp.GetSessionID())
			if resp.SessionExpirationTime == 0 {
				t.Error("session_expiration_time must not be zero")
			}
		})
	}
}

// ============================================================
// EUDIW service types
// ============================================================

func TestEUDIWWKA(t *testing.T) {
	for _, path := range vectorFiles(t) {
		v := loadVectors(t, path)
		t.Run(v.Generator+"/eudiw_wka", func(t *testing.T) {
			if v.EUDIW.WKARequestJSON == "" {
				t.Skip("no EUDIW WKA vectors")
			}
			var req SpecWKARequest
			json.Unmarshal([]byte(v.EUDIW.WKARequestJSON), &req)
			if len(req.KeysToAttest) == 0 {
				t.Error("keys_to_attest must not be empty")
			}
			assertNonEmpty(t, "ver", req.Ver)

			var resp SpecWKAResponse
			json.Unmarshal([]byte(v.EUDIW.WKAResponseJSON), &resp)
			assertNonEmpty(t, "wka", resp.WKA)
		})
	}
}

func TestEUDIWWIA(t *testing.T) {
	for _, path := range vectorFiles(t) {
		v := loadVectors(t, path)
		t.Run(v.Generator+"/eudiw_wia", func(t *testing.T) {
			if v.EUDIW.WIARequestJSON == "" {
				t.Skip("no EUDIW WIA vectors")
			}
			var req SpecWIARequest
			json.Unmarshal([]byte(v.EUDIW.WIARequestJSON), &req)
			if len(req.KeysToAttest) == 0 {
				t.Error("keys_to_attest must not be empty")
			}
			assertNonEmpty(t, "ver", req.Ver)

			var resp SpecWIAResponse
			json.Unmarshal([]byte(v.EUDIW.WIAResponseJSON), &resp)
			assertNonEmpty(t, "wia", resp.WIA)
		})
	}
}

// ============================================================
// Nonce echo
// ============================================================

func TestNonceEcho(t *testing.T) {
	for _, path := range vectorFiles(t) {
		v := loadVectors(t, path)
		for _, pair := range v.Protocol.RequestResponsePairs {
			t.Run(v.Generator+"/nonce_echo/"+pair.Name, func(t *testing.T) {
				var req r2ps.ServiceRequest
				json.Unmarshal([]byte(pair.Request), &req)
				var resp r2ps.ServiceResponse
				json.Unmarshal([]byte(pair.Response), &resp)
				if req.Nonce != resp.Nonce {
					t.Errorf("nonce mismatch: request=%q response=%q", req.Nonce, resp.Nonce)
				}
			})
		}
	}
}

// ============================================================
// All error codes
// ============================================================

func TestAllErrorCodes(t *testing.T) {
	for _, path := range vectorFiles(t) {
		v := loadVectors(t, path)
		for _, ne := range v.Protocol.AllErrorResponses {
			t.Run(v.Generator+"/error/"+ne.Name, func(t *testing.T) {
				var resp r2ps.ErrorResponse
				json.Unmarshal([]byte(ne.JSON), &resp)
				assertNonEmpty(t, "error_code", resp.ErrorCode)
				assertNonEmpty(t, "error_message", resp.ErrorMessage)
			})
		}
	}
}

// ============================================================
// Mode constraints
// ============================================================

func TestModeConstraints(t *testing.T) {
	for _, path := range vectorFiles(t) {
		v := loadVectors(t, path)
		for _, c := range v.Protocol.ModeConstraints {
			t.Run(v.Generator+"/mode/"+c.Type, func(t *testing.T) {
				if c.RequiredMode != "1FA" && c.RequiredMode != "2FA" {
					t.Errorf("mode=%q, want 1FA or 2FA", c.RequiredMode)
				}
			})
		}
	}
}

// ============================================================
// HKDF KEK derivation
// ============================================================

func TestHKDFKEKDerivation(t *testing.T) {
	for _, path := range vectorFiles(t) {
		v := loadVectors(t, path)
		if v.HKDF.SessionKeyHex == "" {
			continue
		}
		t.Run(v.Generator+"/hkdf_kek", func(t *testing.T) {
			sessionKey, _ := hex.DecodeString(v.HKDF.SessionKeyHex)
			expectedC2S, _ := hex.DecodeString(v.HKDF.KEKC2SHex)
			expectedS2C, _ := hex.DecodeString(v.HKDF.KEKS2CHex)

			gotC2S, err := icrypto.Derive2FAKEK(sessionKey, "c2s", v.HKDF.SessionID)
			if err != nil {
				t.Fatalf("derive c2s: %v", err)
			}
			if hex.EncodeToString(gotC2S) != hex.EncodeToString(expectedC2S) {
				t.Errorf("c2s KEK mismatch")
			}

			gotS2C, err := icrypto.Derive2FAKEK(sessionKey, "s2c", v.HKDF.SessionID)
			if err != nil {
				t.Fatalf("derive s2c: %v", err)
			}
			if hex.EncodeToString(gotS2C) != hex.EncodeToString(expectedS2C) {
				t.Errorf("s2c KEK mismatch")
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

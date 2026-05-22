package conformance

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/x509"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"os"
	"path/filepath"
	"testing"

	icrypto "github.com/sirosfoundation/go-r2ps-service/internal/crypto"
	"github.com/sirosfoundation/go-r2ps-service/pkg/r2ps"
)

// --- Shared test vector format (consumed by both Go and Rust) ---

// TestVectors is the top-level structure for cross-implementation conformance.
type TestVectors struct {
	Generator string          `json:"generator"`
	Version   string          `json:"version"`
	Keys      Keys            `json:"keys"`
	JWS       JWSVectors      `json:"jws"`
	JWEEcdh   JWEVectors      `json:"jwe_ecdh"`
	JWESym    JWEVectors      `json:"jwe_symmetric"`
	Protocol  ProtocolVectors `json:"protocol_types"`
	HSM       HSMVectors      `json:"hsm_service_types"`
	EUDIW     EUDIWVectors    `json:"eudiw_service_types,omitempty"`
}

type Keys struct {
	ECPrivatePKCS8PEM string `json:"ec_private_pkcs8_pem"`
	ECPublicSPKIPEM   string `json:"ec_public_spki_pem"`
	SymmetricKeyHex   string `json:"symmetric_key_hex"`
}

type JWSVectors struct {
	Compact    string `json:"compact"`
	PayloadHex string `json:"payload_hex"`
	Kid        string `json:"kid"`
	Typ        string `json:"typ"`
}

type JWEVectors struct {
	Compact      string `json:"compact"`
	PlaintextHex string `json:"plaintext_hex"`
}

type ProtocolVectors struct {
	ServiceRequestJSON  string `json:"service_request"`
	ServiceResponseJSON string `json:"service_response"`
	PAKERequestJSON     string `json:"pake_request"`
	PAKEResponseJSON    string `json:"pake_response"`
	ErrorResponseJSON   string `json:"error_response"`

	// Request/response pairs with nonce echo (rp2s-peter §3.1.3)
	RequestResponsePairs []RequestResponsePair `json:"request_response_pairs,omitempty"`

	// All error codes (rp2s-peter §3.2)
	AllErrorResponses []NamedJSON `json:"all_error_responses,omitempty"`

	// PAKE flows (rp2s-peter §3.3)
	PAKERegistrationEvaluateReq  string `json:"pake_reg_evaluate_req,omitempty"`
	PAKERegistrationEvaluateResp string `json:"pake_reg_evaluate_resp,omitempty"`
	PAKERegistrationFinalizeReq  string `json:"pake_reg_finalize_req,omitempty"`
	PAKERegistrationFinalizeResp string `json:"pake_reg_finalize_resp,omitempty"`
	PAKEAuthEvaluateReq          string `json:"pake_auth_evaluate_req,omitempty"`
	PAKEAuthEvaluateResp         string `json:"pake_auth_evaluate_resp,omitempty"`
	PAKEAuthFinalizeReq          string `json:"pake_auth_finalize_req,omitempty"`
	PAKEAuthFinalizeResp         string `json:"pake_auth_finalize_resp,omitempty"`
	PAKEPinChangeEvaluateReq     string `json:"pake_pinchange_evaluate_req,omitempty"`
	PAKEPinChangeFinalizeReq     string `json:"pake_pinchange_finalize_req,omitempty"`

	// Enc mode constraint vectors (rp2s-peter §3.3)
	EncModeConstraints []EncModeConstraint `json:"enc_mode_constraints,omitempty"`
}

// RequestResponsePair validates nonce echo and forbidden-field rules.
type RequestResponsePair struct {
	Name     string `json:"name"`
	Request  string `json:"request"`
	Response string `json:"response"`
}

// NamedJSON associates a name with a JSON string for tabular tests.
type NamedJSON struct {
	Name string `json:"name"`
	JSON string `json:"json"`
}

// EncModeConstraint pairs a service type with its required enc mode.
type EncModeConstraint struct {
	Type        string `json:"type"`
	RequiredEnc string `json:"required_enc"`
	RequestJSON string `json:"request_json"`
}

// HSMVectors uses the field names defined in the authoritative spec
// (security/remote-hsm-apake-service-types.md).
type HSMVectors struct {
	ECKeygenRequestJSON  string `json:"ec_keygen_request"`
	ECKeygenResponseJSON string `json:"ec_keygen_response"`
	ECDSARequestJSON     string `json:"ecdsa_request"`
	ECDSAResponseHex     string `json:"ecdsa_response_hex"`
	ECDHRequestJSON      string `json:"ecdh_request"`
	ECDHResponseHex      string `json:"ecdh_response_hex"`
	ListKeysRequestJSON  string `json:"list_keys_request"`
	ListKeysResponseJSON string `json:"list_keys_response"`

	// Multi-curve keygen vectors (§1)
	KeygenP384RequestJSON  string `json:"keygen_p384_request,omitempty"`
	KeygenP384ResponseJSON string `json:"keygen_p384_response,omitempty"`
	KeygenP521RequestJSON  string `json:"keygen_p521_request,omitempty"`
	KeygenP521ResponseJSON string `json:"keygen_p521_response,omitempty"`

	// Empty-filter list_keys: curve=[] means list all (§2.2)
	ListAllKeysRequestJSON  string `json:"list_all_keys_request,omitempty"`
	ListAllKeysResponseJSON string `json:"list_all_keys_response,omitempty"`
}

// EUDIWVectors holds vectors for EUDIW service types
// (security/r2ps-service-types-eudiw.md).
type EUDIWVectors struct {
	// WKA request/response (§1)
	WKARequestJSON  string `json:"wka_request"`
	WKAResponseJSON string `json:"wka_response"`
	// WIA request/response (§2)
	WIARequestJSON  string `json:"wia_request"`
	WIAResponseJSON string `json:"wia_response"`
}

// --- EUDIW spec-compliant types ---

// SpecWKARequest — EUDIW §1.1: { "keys_to_attest": [...], "ver": "d008" }
type SpecWKARequest struct {
	KeysToAttest []string `json:"keys_to_attest"`
	Ver          string   `json:"ver"`
}

// SpecWKAResponse — EUDIW §1.1: { "attestation": "<jwt>" }
type SpecWKAResponse struct {
	Attestation string `json:"attestation"`
}

// SpecWIARequest — EUDIW §2.1: { "ver": "d008" }
type SpecWIARequest struct {
	Ver string `json:"ver"`
}

// SpecWIAResponse — EUDIW §2.1: { "attestation": "<jwt>" }
type SpecWIAResponse struct {
	Attestation string `json:"attestation"`
}

// --- Spec-compliant HSM service type structures ---
// These mirror the field names from security/remote-hsm-apake-service-types.md.

// SpecECKeygenRequest — §1: { "curve": "P-256" }
type SpecECKeygenRequest struct {
	Curve string `json:"curve"`
}

// SpecECKeygenResponse — §1: { "created_key": "P-256" }
type SpecECKeygenResponse struct {
	CreatedKey string `json:"created_key"`
}

// SpecECDSARequest — §3: { "kid": "...", "tbs_hash": "..." }
type SpecECDSARequest struct {
	Kid     string `json:"kid"`
	TbsHash string `json:"tbs_hash"`
}

// SpecECDSAResponse — §3: raw DER signature bytes (not JSON)

// SpecECDHRequest — §4: { "kid": "...", "public_key": "..." }
type SpecECDHRequest struct {
	Kid       string `json:"kid"`
	PublicKey string `json:"public_key"`
}

// SpecECDHResponse — §4: raw shared secret bytes (not JSON)

// SpecListKeysRequest — §2: { "curve": ["P-256"] }
type SpecListKeysRequest struct {
	Curve []string `json:"curve"`
}

// SpecKeyInfo — §2
type SpecKeyInfo struct {
	Kid          string `json:"kid"`
	CurveName    string `json:"curve_name"`
	CreationTime int64  `json:"creation_time"`
	PublicKey    string `json:"public_key"`
}

// SpecListKeysResponse — §2: { "key_info": [...] }
type SpecListKeysResponse struct {
	KeyInfo []SpecKeyInfo `json:"key_info"`
}

// --- Vector generator ---

// TestGenerateGoVectors generates test vectors from the Go implementation
// and writes them to testdata/vectors_go.json.
func TestGenerateGoVectors(t *testing.T) {
	key, err := icrypto.GenerateECKey(elliptic.P256())
	if err != nil {
		t.Fatalf("generate key: %v", err)
	}

	privDER, err := x509.MarshalPKCS8PrivateKey(key)
	if err != nil {
		t.Fatalf("marshal private key: %v", err)
	}
	privPEM := pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: privDER})

	pubDER, err := x509.MarshalPKIXPublicKey(&key.PublicKey)
	if err != nil {
		t.Fatalf("marshal public key: %v", err)
	}
	pubPEM := pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: pubDER})

	symKey := icrypto.RandomBytes(32)

	// --- JWS ---
	payload := []byte("hello interop")
	kid := "conformance-kid-1"
	typ := "r2ps-request+json"
	jws, err := icrypto.SignJWS(payload, key, kid, typ)
	if err != nil {
		t.Fatalf("sign JWS: %v", err)
	}

	// --- JWE ECDH ---
	ecdhPlain := []byte("ecdh secret payload")
	jweEcdh, err := icrypto.EncryptJWE(ecdhPlain, &key.PublicKey)
	if err != nil {
		t.Fatalf("encrypt JWE ECDH: %v", err)
	}

	// --- JWE Symmetric ---
	symPlain := []byte("symmetric secret payload")
	jweSym, err := icrypto.EncryptJWESymmetric(symPlain, symKey)
	if err != nil {
		t.Fatalf("encrypt JWE symmetric: %v", err)
	}

	// --- Protocol types ---
	svcReq := r2ps.ServiceRequest{
		Ver:           r2ps.ProtocolVersion,
		Nonce:         "dGVzdG5vbmNl",
		Iat:           1716400000,
		Enc:           r2ps.EncDevice,
		Data:          "eyJhbGciOiJFQ0RILUVTK0EyNTZLVyJ9...",
		ClientID:      "test-client",
		Kid:           "key-1",
		Context:       "signing",
		Type:          r2ps.TypeHSMECDSA,
		PakeSessionID: "session-abc",
	}
	svcReqJSON, _ := json.Marshal(svcReq)

	svcResp := r2ps.ServiceResponse{
		Ver:   r2ps.ProtocolVersion,
		Nonce: "cmVzcG5vbmNl",
		Iat:   1716400001,
		Enc:   r2ps.EncUser,
		Data:  "eyJhbGciOiJkaXIifQ...",
	}
	svcRespJSON, _ := json.Marshal(svcResp)

	pakeReq := r2ps.PAKERequest{
		Protocol: r2ps.PAKEProtocolOPAQUE,
		State:    r2ps.PAKEStateEvaluate,
		Task:     "sign",
		Req:      "b3BhcXVlLXJlcXVlc3Q",
	}
	pakeReqJSON, _ := json.Marshal(pakeReq)

	pakeResp := r2ps.PAKEResponse{
		PakeSessionID:         "sess-123",
		Resp:                  "b3BhcXVlLXJlc3BvbnNl",
		Task:                  "sign",
		SessionExpirationTime: 1716403600,
	}
	pakeRespJSON, _ := json.Marshal(pakeResp)

	errResp := r2ps.ErrorResponse{
		ErrorCode:    r2ps.ErrUnauthorized,
		ErrorMessage: "invalid credentials",
	}
	errRespJSON, _ := json.Marshal(errResp)

	// --- Request/response pairs with matching nonce (rp2s-peter §3.1.3) ---
	sharedNonce := "Y29uZm9ybWFuY2Vub25jZQ"
	pairReq := r2ps.ServiceRequest{
		Ver:           r2ps.ProtocolVersion,
		Nonce:         sharedNonce,
		Iat:           1716400000,
		Enc:           r2ps.EncUser,
		Data:          "eyJhbGciOiJkaXIifQ...",
		ClientID:      "test-client",
		Kid:           "key-1",
		Context:       "hsm",
		Type:          r2ps.TypeHSMECDSA,
		PakeSessionID: "session-abc",
	}
	pairReqJSON, _ := json.Marshal(pairReq)
	pairResp := r2ps.ServiceResponse{
		Ver:   r2ps.ProtocolVersion,
		Nonce: sharedNonce, // must echo
		Iat:   1716400001,
		Enc:   r2ps.EncUser,
		Data:  "eyJhbGciOiJkaXIifQ...",
	}
	pairRespJSON, _ := json.Marshal(pairResp)

	// --- All error codes (rp2s-peter §3.2) ---
	allErrors := []NamedJSON{
		{Name: "ILLEGAL_REQUEST_DATA", JSON: mustJSON(r2ps.ErrorResponse{ErrorCode: r2ps.ErrIllegalRequestData, ErrorMessage: "malformed request"})},
		{Name: "UNAUTHORIZED", JSON: mustJSON(r2ps.ErrorResponse{ErrorCode: r2ps.ErrUnauthorized, ErrorMessage: "invalid credentials"})},
		{Name: "ACCESS_DENIED", JSON: mustJSON(r2ps.ErrorResponse{ErrorCode: r2ps.ErrAccessDenied, ErrorMessage: "service not allowed"})},
		{Name: "ILLEGAL_STATE", JSON: mustJSON(r2ps.ErrorResponse{ErrorCode: r2ps.ErrIllegalState, ErrorMessage: "unexpected state"})},
		{Name: "UNSUPPORTED_REQUEST_TYPE", JSON: mustJSON(r2ps.ErrorResponse{ErrorCode: r2ps.ErrUnsupportedType, ErrorMessage: "unknown type"})},
		{Name: "SERVER_ERROR", JSON: mustJSON(r2ps.ErrorResponse{ErrorCode: r2ps.ErrServerError, ErrorMessage: "internal error"})},
		{Name: "TRY_LATER", JSON: mustJSON(r2ps.ErrorResponse{ErrorCode: r2ps.ErrTryLater, ErrorMessage: "service busy"})},
	}

	// --- PAKE registration flow (rp2s-peter §3.3.3.1) ---
	pakeRegEvalReq, _ := json.Marshal(r2ps.PAKERequest{
		Protocol: r2ps.PAKEProtocolOPAQUE,
		State:    r2ps.PAKEStateEvaluate,
		Req:      "cmVnaXN0cmF0aW9uLXJlcXVlc3Q",
	})
	pakeRegEvalResp, _ := json.Marshal(r2ps.PAKEResponse{
		Resp: "cmVnaXN0cmF0aW9uLXJlc3BvbnNl",
	})
	pakeRegFinReq, _ := json.Marshal(r2ps.PAKERequest{
		Protocol:      r2ps.PAKEProtocolOPAQUE,
		State:         r2ps.PAKEStateFinalize,
		Authorization: "YXV0aG9yaXphdGlvbi1kYXRh",
		Req:           "cmVnaXN0cmF0aW9uLXJlY29yZA",
	})
	pakeRegFinResp, _ := json.Marshal(r2ps.PAKEResponse{
		Msg: "OK",
	})

	// --- PAKE authentication flow (rp2s-peter §3.3.3.2) ---
	pakeAuthEvalReq, _ := json.Marshal(r2ps.PAKERequest{
		Protocol: r2ps.PAKEProtocolOPAQUE,
		State:    r2ps.PAKEStateEvaluate,
		Req:      "S0UxLWJ5dGVz",
	})
	pakeAuthEvalResp, _ := json.Marshal(r2ps.PAKEResponse{
		PakeSessionID: "auth-session-001",
		Resp:          "S0UyLWJ5dGVz",
	})
	pakeAuthFinReq, _ := json.Marshal(r2ps.PAKERequest{
		Protocol:        r2ps.PAKEProtocolOPAQUE,
		State:           r2ps.PAKEStateFinalize,
		Task:            "sign",
		SessionDuration: 30,
		Req:             "S0UzLWJ5dGVz",
	})
	pakeAuthFinResp, _ := json.Marshal(r2ps.PAKEResponse{
		PakeSessionID:         "auth-session-001",
		Task:                  "sign",
		Msg:                   "OK",
		SessionExpirationTime: 1716403600,
	})

	// --- PAKE PIN change (rp2s-peter §3.3.3.3) ---
	pakePinChgEvalReq, _ := json.Marshal(r2ps.PAKERequest{
		Protocol: r2ps.PAKEProtocolOPAQUE,
		State:    r2ps.PAKEStateEvaluate,
		Req:      "bmV3LXBpbi1yZWdpc3RyYXRpb24tcmVxdWVzdA",
	})
	pakePinChgFinReq, _ := json.Marshal(r2ps.PAKERequest{
		Protocol: r2ps.PAKEProtocolOPAQUE,
		State:    r2ps.PAKEStateFinalize,
		Req:      "bmV3LXBpbi1yZWdpc3RyYXRpb24tcmVjb3Jk",
		// No authorization for PIN change (encrypted under existing session)
	})

	// --- Enc mode constraints (rp2s-peter §3.3) ---
	encConstraints := []EncModeConstraint{
		{Type: r2ps.TypePINRegistration, RequiredEnc: r2ps.EncDevice, RequestJSON: mustJSON(r2ps.ServiceRequest{
			Ver: r2ps.ProtocolVersion, Nonce: "bm9uY2U", Iat: 1716400000,
			Enc: r2ps.EncDevice, Data: "ZGF0YQ", ClientID: "c1", Kid: "k1",
			Context: "hsm", Type: r2ps.TypePINRegistration,
		})},
		{Type: r2ps.TypeAuthenticate, RequiredEnc: r2ps.EncDevice, RequestJSON: mustJSON(r2ps.ServiceRequest{
			Ver: r2ps.ProtocolVersion, Nonce: "bm9uY2U", Iat: 1716400000,
			Enc: r2ps.EncDevice, Data: "ZGF0YQ", ClientID: "c1", Kid: "k1",
			Context: "hsm", Type: r2ps.TypeAuthenticate,
		})},
		{Type: r2ps.TypePINChange, RequiredEnc: r2ps.EncUser, RequestJSON: mustJSON(r2ps.ServiceRequest{
			Ver: r2ps.ProtocolVersion, Nonce: "bm9uY2U", Iat: 1716400000,
			Enc: r2ps.EncUser, Data: "ZGF0YQ", ClientID: "c1", Kid: "k1",
			Context: "hsm", Type: r2ps.TypePINChange, PakeSessionID: "sess-1",
		})},
	}

	// --- HSM service types (spec-compliant field names) ---
	keygenReq, _ := json.Marshal(SpecECKeygenRequest{Curve: "P-256"})
	keygenResp, _ := json.Marshal(SpecECKeygenResponse{CreatedKey: "P-256"})

	ecdsaReq, _ := json.Marshal(SpecECDSARequest{
		Kid:     "03fbe636059033a07ee3099caf84a87474d94afa2c7d431f3391ebd8cf21a24216",
		TbsHash: "YUHJYghlxa4CTkBEKvtPmiA+jCMUURknHs19sd7bNjs=",
	})
	ecdsaRespDER, _ := hex.DecodeString("30440220260a6228484119be74f7f8f46f964af0433b1f1218e667a92e82e45e48ef488d02207cfe73d85a7b81d7853aa680ba4a0ee17120f7fd87b7542b34f79863052abcbf")

	ecdhReq, _ := json.Marshal(SpecECDHRequest{
		Kid:       "0294ddc3fd5554688bf619987b63bbb09b13e0d04b8a9da493309eef3f41767228",
		PublicKey: "MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAETpEgaHsA2UTbSkn7hJb3KfvrlAMb+p715Gw/q5x01ZgQZWL7xURVYB9Fw+B7TK+GYMShDJYjLlKva5f+KkTx3w==",
	})
	ecdhRespSecret, _ := hex.DecodeString("ad91d860a109cce0e7d334813f434be8d44a21f8b3677cfe00c25fb572950687")

	listReq, _ := json.Marshal(SpecListKeysRequest{Curve: []string{"P-256"}})
	listResp, _ := json.Marshal(SpecListKeysResponse{KeyInfo: []SpecKeyInfo{
		{
			Kid:          "03fbe636059033a07ee3099caf84a87474d94afa2c7d431f3391ebd8cf21a24216",
			CurveName:    "P-256",
			CreationTime: 1750751069,
			PublicKey:    "MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAE++Y2BZAzoH7jCZyvhKh0dNlK+ix9Qx8zkevYzyGiQhYdmIZjwS5S9fMegmKL685ctyQMNS8Jh1QayMYzwpL4AQ==",
		},
	}})

	// Multi-curve keygen (§1)
	keygenP384Req, _ := json.Marshal(SpecECKeygenRequest{Curve: "P-384"})
	keygenP384Resp, _ := json.Marshal(SpecECKeygenResponse{CreatedKey: "P-384"})
	keygenP521Req, _ := json.Marshal(SpecECKeygenRequest{Curve: "P-521"})
	keygenP521Resp, _ := json.Marshal(SpecECKeygenResponse{CreatedKey: "P-521"})

	// Empty-filter list_keys (§2.2: absent or empty list → list all)
	listAllReq, _ := json.Marshal(SpecListKeysRequest{Curve: []string{}})
	listAllResp, _ := json.Marshal(SpecListKeysResponse{KeyInfo: []SpecKeyInfo{
		{
			Kid:          "0308345940bc96d1ea6456ff753596281ff8cec4dfb0a1a82a0a3508b0ac5e17d8072b6bfcc17aa5e6d97d863f2017aa09",
			CurveName:    "P-384",
			CreationTime: 1750751069,
			PublicKey:    "MHYwEAYHKoZIzj0CAQYFK4EEACIDYgAECDRZQLyW0epkVv91NZYoH/jOxN+woagqCjUIsKxeF9gHK2v8wXql5tl9hj8gF6oJ3MZ45jdnRNGIG8O+LtWMraR0irerNaHb165jC9+reCXRkVZLr0q7nvgbq18zxuoR",
		},
		{
			Kid:          "03fbe636059033a07ee3099caf84a87474d94afa2c7d431f3391ebd8cf21a24216",
			CurveName:    "P-256",
			CreationTime: 1750751069,
			PublicKey:    "MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAE++Y2BZAzoH7jCZyvhKh0dNlK+ix9Qx8zkevYzyGiQhYdmIZjwS5S9fMegmKL685ctyQMNS8Jh1QayMYzwpL4AQ==",
		},
		{
			Kid:          "0301e5a88aca8d54fb87a52cdd5d6f4e8a16f147a10c133b7c4adc4cf3c867f68410d5de1582bc8d74d7f91853758931bd2c8badcd2ff9ab7b49832a4a058451c0a8d2",
			CurveName:    "P-521",
			CreationTime: 1750751069,
			PublicKey:    "MIGbMBAGByqGSM49AgEGBSuBBAAjA4GGAAQB5aiKyo1U+4elLN1db06KFvFHoQwTO3xK3EzzyGf2hBDV3hWCvI101/kYU3WJMb0si63NL/mre0mDKkoFhFHAqNIBQkoUyt32fqcaSSyf00VQvJHOKF8s7V8SF4HAJpTmFF53uGjoul02v6wy3LPlmKGYpfH/FJcK9/B3oqxDvI5ciis=",
		},
	}})

	// --- EUDIW service types (r2ps-service-types-eudiw.md) ---
	wkaReq, _ := json.Marshal(SpecWKARequest{
		KeysToAttest: []string{"key-0"},
		Ver:          "d008",
	})
	wkaResp, _ := json.Marshal(SpecWKAResponse{
		Attestation: "eyJ0eXAiOiJrZXktYXR0ZXN0YXRpb24rand0IiwiYWxnIjoiRVMyNTYiLCJ4NWMiOlsiTUlJRFFqQ0NBLi4uIl19.eyJpYXQiOjE3MTY0MDAwMDAsImV4cCI6MTcxNjQ4NjQwMCwid2FsbGV0X2xpbmsiOiJodHRwczovL3dwLmV4YW1wbGUuY29tL2V1ZGl3LWluZm8ifQ.fake-signature",
	})
	wiaReq, _ := json.Marshal(SpecWIARequest{
		Ver: "d008",
	})
	wiaResp, _ := json.Marshal(SpecWIAResponse{
		Attestation: "eyJ0eXAiOiJvYXV0aC1jbGllbnQtYXR0ZXN0YXRpb24rand0IiwiYWxnIjoiRVMyNTYiLCJ4NWMiOlsiTUlJRERUQ0NBLi4uIl19.eyJpYXQiOjE3MTY0MDAwMDAsImV4cCI6MTcxNjQ4NjQwMCwic3ViIjoiaHR0cHM6Ly9leGFtcGxlLmNvbS93YWxsZXQvMSJ9.fake-signature",
	})

	vectors := TestVectors{
		Generator: "go-r2ps-service",
		Version:   "1.0",
		Keys: Keys{
			ECPrivatePKCS8PEM: string(privPEM),
			ECPublicSPKIPEM:   string(pubPEM),
			SymmetricKeyHex:   hex.EncodeToString(symKey),
		},
		JWS: JWSVectors{
			Compact:    jws,
			PayloadHex: hex.EncodeToString(payload),
			Kid:        kid,
			Typ:        typ,
		},
		JWEEcdh: JWEVectors{
			Compact:      jweEcdh,
			PlaintextHex: hex.EncodeToString(ecdhPlain),
		},
		JWESym: JWEVectors{
			Compact:      jweSym,
			PlaintextHex: hex.EncodeToString(symPlain),
		},
		Protocol: ProtocolVectors{
			ServiceRequestJSON:  string(svcReqJSON),
			ServiceResponseJSON: string(svcRespJSON),
			PAKERequestJSON:     string(pakeReqJSON),
			PAKEResponseJSON:    string(pakeRespJSON),
			ErrorResponseJSON:   string(errRespJSON),

			RequestResponsePairs: []RequestResponsePair{
				{Name: "ecdsa_sign", Request: string(pairReqJSON), Response: string(pairRespJSON)},
			},
			AllErrorResponses: allErrors,

			PAKERegistrationEvaluateReq:  string(pakeRegEvalReq),
			PAKERegistrationEvaluateResp: string(pakeRegEvalResp),
			PAKERegistrationFinalizeReq:  string(pakeRegFinReq),
			PAKERegistrationFinalizeResp: string(pakeRegFinResp),
			PAKEAuthEvaluateReq:          string(pakeAuthEvalReq),
			PAKEAuthEvaluateResp:         string(pakeAuthEvalResp),
			PAKEAuthFinalizeReq:          string(pakeAuthFinReq),
			PAKEAuthFinalizeResp:         string(pakeAuthFinResp),
			PAKEPinChangeEvaluateReq:     string(pakePinChgEvalReq),
			PAKEPinChangeFinalizeReq:     string(pakePinChgFinReq),

			EncModeConstraints: encConstraints,
		},
		HSM: HSMVectors{
			ECKeygenRequestJSON:  string(keygenReq),
			ECKeygenResponseJSON: string(keygenResp),
			ECDSARequestJSON:     string(ecdsaReq),
			ECDSAResponseHex:     hex.EncodeToString(ecdsaRespDER),
			ECDHRequestJSON:      string(ecdhReq),
			ECDHResponseHex:      hex.EncodeToString(ecdhRespSecret),
			ListKeysRequestJSON:  string(listReq),
			ListKeysResponseJSON: string(listResp),

			KeygenP384RequestJSON:  string(keygenP384Req),
			KeygenP384ResponseJSON: string(keygenP384Resp),
			KeygenP521RequestJSON:  string(keygenP521Req),
			KeygenP521ResponseJSON: string(keygenP521Resp),

			ListAllKeysRequestJSON:  string(listAllReq),
			ListAllKeysResponseJSON: string(listAllResp),
		},
		EUDIW: EUDIWVectors{
			WKARequestJSON:  string(wkaReq),
			WKAResponseJSON: string(wkaResp),
			WIARequestJSON:  string(wiaReq),
			WIAResponseJSON: string(wiaResp),
		},
	}

	out, err := json.MarshalIndent(vectors, "", "  ")
	if err != nil {
		t.Fatalf("marshal vectors: %v", err)
	}

	outPath := filepath.Join("..", "..", "testdata", "vectors_go.json")
	if err := os.MkdirAll(filepath.Dir(outPath), 0o755); err != nil {
		t.Fatalf("mkdir: %v", err)
	}
	if err := os.WriteFile(outPath, out, 0o644); err != nil {
		t.Fatalf("write vectors: %v", err)
	}
	t.Logf("wrote %d bytes to %s", len(out), outPath)
}

// mustJSON marshals v to a JSON string; panics on error.
func mustJSON(v any) string {
	b, err := json.Marshal(v)
	if err != nil {
		panic(err)
	}
	return string(b)
}

// loadVectors reads and parses a test vectors JSON file.
func loadVectors(t *testing.T, path string) *TestVectors {
	t.Helper()
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read vectors %s: %v", path, err)
	}
	var v TestVectors
	if err := json.Unmarshal(data, &v); err != nil {
		t.Fatalf("parse vectors: %v", err)
	}
	return &v
}

// parseECPrivateKey extracts an *ecdsa.PrivateKey from PEM-encoded PKCS#8.
func parseECPrivateKey(t *testing.T, pemData string) *ecdsa.PrivateKey {
	t.Helper()
	block, _ := pem.Decode([]byte(pemData))
	if block == nil {
		t.Fatal("no PEM block found in private key")
	}
	key, err := x509.ParsePKCS8PrivateKey(block.Bytes)
	if err != nil {
		t.Fatalf("parse PKCS#8: %v", err)
	}
	ecKey, ok := key.(*ecdsa.PrivateKey)
	if !ok {
		t.Fatal("key is not ECDSA")
	}
	return ecKey
}

// parseECPublicKey extracts an *ecdsa.PublicKey from PEM-encoded SPKI.
func parseECPublicKey(t *testing.T, pemData string) *ecdsa.PublicKey {
	t.Helper()
	block, _ := pem.Decode([]byte(pemData))
	if block == nil {
		t.Fatal("no PEM block found in public key")
	}
	key, err := x509.ParsePKIXPublicKey(block.Bytes)
	if err != nil {
		t.Fatalf("parse SPKI: %v", err)
	}
	ecKey, ok := key.(*ecdsa.PublicKey)
	if !ok {
		t.Fatal("key is not ECDSA")
	}
	return ecKey
}

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

// vectorFiles returns the list of vector files to validate.
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
	HKDF      HKDFVectors     `json:"hkdf_vectors,omitempty"`
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
	TFARequestJSON      string `json:"tfa_request"`
	TFAResponseJSON     string `json:"tfa_response"`
	ErrorResponseJSON   string `json:"error_response"`

	RequestResponsePairs []RequestResponsePair `json:"request_response_pairs,omitempty"`
	AllErrorResponses    []NamedJSON           `json:"all_error_responses,omitempty"`

	// 2FA registration flow (r2ps-service-types.md §5.1)
	TFARegEvaluateReq  string `json:"tfa_reg_evaluate_req,omitempty"`
	TFARegEvaluateResp string `json:"tfa_reg_evaluate_resp,omitempty"`
	TFARegFinalizeReq  string `json:"tfa_reg_finalize_req,omitempty"`
	TFARegFinalizeResp string `json:"tfa_reg_finalize_resp,omitempty"`

	// 2FA auth flow (r2ps-service-types.md §5.2)
	TFAAuthEvaluateReq  string `json:"tfa_auth_evaluate_req,omitempty"`
	TFAAuthEvaluateResp string `json:"tfa_auth_evaluate_resp,omitempty"`
	TFAAuthFinalizeReq  string `json:"tfa_auth_finalize_req,omitempty"`
	TFAAuthFinalizeResp string `json:"tfa_auth_finalize_resp,omitempty"`

	// 2FA change flow (r2ps-service-types.md §5.3)
	TFAChangeEvaluateReq string `json:"tfa_change_evaluate_req,omitempty"`
	TFAChangeFinalizeReq string `json:"tfa_change_finalize_req,omitempty"`

	// Mode constraints
	ModeConstraints []ModeConstraint `json:"mode_constraints,omitempty"`
}

type RequestResponsePair struct {
	Name     string `json:"name"`
	Request  string `json:"request"`
	Response string `json:"response"`
}

type NamedJSON struct {
	Name string `json:"name"`
	JSON string `json:"json"`
}

type ModeConstraint struct {
	Type         string `json:"type"`
	RequiredMode string `json:"required_mode"`
}

type HSMVectors struct {
	ECKeygenRequestJSON  string `json:"ec_keygen_request"`
	ECKeygenResponseJSON string `json:"ec_keygen_response"`
	ECDSARequestJSON     string `json:"ecdsa_request"`
	ECDSAResponseHex     string `json:"ecdsa_response_hex"`
	ECDHRequestJSON      string `json:"ecdh_request"`
	ECDHResponseHex      string `json:"ecdh_response_hex"`
	ListKeysRequestJSON  string `json:"list_keys_request"`
	ListKeysResponseJSON string `json:"list_keys_response"`
}

type EUDIWVectors struct {
	WKARequestJSON  string `json:"wka_request"`
	WKAResponseJSON string `json:"wka_response"`
	WIARequestJSON  string `json:"wia_request"`
	WIAResponseJSON string `json:"wia_response"`
}

type HKDFVectors struct {
	SessionKeyHex string `json:"session_key_hex"`
	SessionID     string `json:"session_id"`
	KEKC2SHex     string `json:"kek_c2s_hex"`
	KEKS2CHex     string `json:"kek_s2c_hex"`
}

// --- Spec-compliant types ---

type SpecWKARequest struct {
	KeysToAttest []string `json:"keys_to_attest"`
	Ver          string   `json:"ver"`
}

type SpecWKAResponse struct {
	WKA string `json:"wka"`
}

type SpecWIARequest struct {
	KeysToAttest []string `json:"keys_to_attest"`
	Ver          string   `json:"ver"`
}

type SpecWIAResponse struct {
	WIA string `json:"wia"`
}

type SpecECKeygenRequest struct {
	Curve string `json:"curve"`
}

type SpecECKeygenResponse struct {
	CreatedKey string `json:"created_key"`
}

type SpecECDSARequest struct {
	Kid     string `json:"kid"`
	TbsHash string `json:"tbs_hash"`
}

type SpecECDHRequest struct {
	Kid       string `json:"kid"`
	PublicKey string `json:"public_key"`
}

type SpecListKeysRequest struct {
	Curve []string `json:"curve"`
}

type SpecKeyInfo struct {
	Kid          string `json:"kid"`
	CurveName    string `json:"curve_name"`
	CreationTime int64  `json:"creation_time"`
	PublicKey    string `json:"public_key"`
}

type SpecListKeysResponse struct {
	KeyInfo []SpecKeyInfo `json:"key_info"`
}

// --- Vector generator ---

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

	// JWS — using new typ value
	payload := []byte("hello interop")
	kid := "conformance-kid-1"
	typ := r2ps.TypRequest
	jws, err := icrypto.SignJWS(payload, key, kid, typ)
	if err != nil {
		t.Fatalf("sign JWS: %v", err)
	}

	// JWE ECDH
	ecdhPlain := []byte("ecdh secret payload")
	jweEcdh, err := icrypto.EncryptJWE(ecdhPlain, &key.PublicKey)
	if err != nil {
		t.Fatalf("encrypt JWE ECDH: %v", err)
	}

	// JWE Symmetric
	symPlain := []byte("symmetric secret payload")
	jweSym, err := icrypto.EncryptJWESymmetric(symPlain, symKey)
	if err != nil {
		t.Fatalf("encrypt JWE symmetric: %v", err)
	}

	// Service request — new spec structure
	svcReq := r2ps.ServiceRequest{
		Ver:          r2ps.ProtocolVersion,
		Nonce:        "dGVzdG5vbmNl",
		Iat:          1716400000,
		Data:         json.RawMessage(`{"kid":"key-0","tbs_hash":"YUHJYg=="}`),
		ClientID:     "test-client",
		Context:      "hsm",
		Type:         r2ps.TypeSignECDSA,
		TFASessionID: "session-abc",
	}
	svcReqJSON, _ := json.Marshal(svcReq)

	svcResp := r2ps.ServiceResponse{
		Ver:   r2ps.ProtocolVersion,
		Nonce: "cmVzcG5vbmNl",
		Iat:   1716400001,
		Data:  json.RawMessage(`{"signature":"MEQCIG..."}`),
	}
	svcRespJSON, _ := json.Marshal(svcResp)

	// 2FA request/response data
	tfaReq := r2ps.TFARequestData{
		Protocol: r2ps.TFAModeOPAQUE,
		State:   r2ps.StateEvaluate,
		PData: "b3BhcXVlLXJlcXVlc3Q",
	}
	tfaReqJSON, _ := json.Marshal(tfaReq)

	tfaResp := r2ps.TFAResponseData{
		PData:    "b3BhcXVlLXJlc3BvbnNl",
		Response: "b3BhcXVlLXJlc3BvbnNl",
	}
	tfaRespJSON, _ := json.Marshal(tfaResp)

	errResp := r2ps.ErrorResponse{
		ErrorCode:    r2ps.ErrUnauthorized,
		ErrorMessage: "invalid credentials",
	}
	errRespJSON, _ := json.Marshal(errResp)

	// Request/response pair
	sharedNonce := "Y29uZm9ybWFuY2Vub25jZQ"
	pairReq := r2ps.ServiceRequest{
		Ver:          r2ps.ProtocolVersion,
		Nonce:        sharedNonce,
		Iat:          1716400000,
		Data:         json.RawMessage(`{"kid":"key-0","tbs_hash":"YUHJYg=="}`),
		ClientID:     "test-client",
		Context:      "hsm",
		Type:         r2ps.TypeSignECDSA,
		TFASessionID: "session-abc",
	}
	pairReqJSON, _ := json.Marshal(pairReq)
	pairResp := r2ps.ServiceResponse{
		Ver:   r2ps.ProtocolVersion,
		Nonce: sharedNonce,
		Iat:   1716400001,
		Data:  json.RawMessage(`{"signature":"MEQCIG..."}`),
	}
	pairRespJSON, _ := json.Marshal(pairResp)

	// All error codes
	allErrors := []NamedJSON{
		{Name: "ILLEGAL_REQUEST_DATA", JSON: mustJSON(r2ps.ErrorResponse{ErrorCode: r2ps.ErrIllegalRequestData, ErrorMessage: "malformed request"})},
		{Name: "UNAUTHORIZED", JSON: mustJSON(r2ps.ErrorResponse{ErrorCode: r2ps.ErrUnauthorized, ErrorMessage: "invalid credentials"})},
		{Name: "ACCESS_DENIED", JSON: mustJSON(r2ps.ErrorResponse{ErrorCode: r2ps.ErrAccessDenied, ErrorMessage: "service not allowed"})},
		{Name: "ILLEGAL_STATE", JSON: mustJSON(r2ps.ErrorResponse{ErrorCode: r2ps.ErrIllegalState, ErrorMessage: "unexpected state"})},
		{Name: "UNSUPPORTED_REQUEST_TYPE", JSON: mustJSON(r2ps.ErrorResponse{ErrorCode: r2ps.ErrUnsupportedType, ErrorMessage: "unknown type"})},
		{Name: "SERVER_ERROR", JSON: mustJSON(r2ps.ErrorResponse{ErrorCode: r2ps.ErrServerError, ErrorMessage: "internal error"})},
		{Name: "TRY_LATER", JSON: mustJSON(r2ps.ErrorResponse{ErrorCode: r2ps.ErrTryLater, ErrorMessage: "service busy"})},
	}

	// 2FA registration flow
	tfaRegEvalReq, _ := json.Marshal(r2ps.TFARequestData{
		Protocol: r2ps.TFAModeOPAQUE,
		State:   r2ps.StateEvaluate,
		PData: "cmVnaXN0cmF0aW9uLXJlcXVlc3Q",
	})
	tfaRegEvalResp, _ := json.Marshal(r2ps.TFAResponseData{
		PData:    "cmVnaXN0cmF0aW9uLXJlc3BvbnNl",
		Response: "cmVnaXN0cmF0aW9uLXJlc3BvbnNl",
	})
	tfaRegFinReq, _ := json.Marshal(r2ps.TFARequestData{
		Protocol:      r2ps.TFAModeOPAQUE,
		State:         r2ps.StateFinalize,
		PData:         "cmVnaXN0cmF0aW9uLXJlY29yZA",
		Authorization: "YXV0aG9yaXphdGlvbi1kYXRh",
	})
	tfaRegFinResp, _ := json.Marshal(r2ps.TFAResponseData{
		Message: "success",
	})

	// 2FA auth flow
	tfaAuthEvalReq, _ := json.Marshal(r2ps.TFARequestData{
		Protocol: r2ps.TFAModeOPAQUE,
		State:   r2ps.StateEvaluate,
		PData: "S0UxLWJ5dGVz",
	})
	tfaAuthEvalResp, _ := json.Marshal(r2ps.TFAAuthResponseData{
		SessionID:    "auth-session-001",
		TFASessionID: "auth-session-001",
		PData:        "S0UyLWJ5dGVz",
		Response:     "S0UyLWJ5dGVz",
	})
	tfaAuthFinReq, _ := json.Marshal(r2ps.TFARequestData{
		Protocol: r2ps.TFAModeOPAQUE,
		State:   r2ps.StateFinalize,
		PData: "S0UzLWJ5dGVz",
	})
	tfaAuthFinResp, _ := json.Marshal(r2ps.TFAAuthResponseData{
		SessionID:             "auth-session-001",
		TFASessionID:          "auth-session-001",
		Message:               "authenticated",
		SessionExpirationTime: 1716403600,
	})

	// 2FA change flow
	tfaChgEvalReq, _ := json.Marshal(r2ps.TFARequestData{
		Protocol: r2ps.TFAModeOPAQUE,
		State:   r2ps.StateEvaluate,
		PData: "bmV3LXJlZ2lzdHJhdGlvbi1yZXF1ZXN0",
	})
	tfaChgFinReq, _ := json.Marshal(r2ps.TFARequestData{
		Protocol: r2ps.TFAModeOPAQUE,
		State:   r2ps.StateFinalize,
		PData: "bmV3LXJlZ2lzdHJhdGlvbi1yZWNvcmQ",
	})

	// Mode constraints
	modeConstraints := []ModeConstraint{
		{Type: r2ps.Type2FARegistration, RequiredMode: "1FA"},
		{Type: r2ps.Type2FAAuthenticate, RequiredMode: "1FA"},
		{Type: r2ps.Type2FAChange, RequiredMode: "2FA"},
		{Type: r2ps.TypeP256Generate, RequiredMode: "1FA"},
		{Type: r2ps.TypeSignECDSA, RequiredMode: "2FA"},
		{Type: r2ps.TypeAgreeECDH, RequiredMode: "2FA"},
		{Type: r2ps.TypeEUDIWWKAETSI, RequiredMode: "1FA"},
		{Type: r2ps.TypeEUDIWWIAETSI, RequiredMode: "1FA"},
	}

	// HSM service types
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
	listResp, _ := json.Marshal(SpecListKeysResponse{KeyInfo: []SpecKeyInfo{{
		Kid:       "03fbe636059033a07ee3099caf84a87474d94afa2c7d431f3391ebd8cf21a24216",
		CurveName: "P-256", CreationTime: 1750751069,
		PublicKey: "MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAE++Y2BZAzoH7jCZyvhKh0dNlK+ix9Qx8zkevYzyGiQhYdmIZjwS5S9fMegmKL685ctyQMNS8Jh1QayMYzwpL4AQ==",
	}}})

	// EUDIW service types — updated per r2ps-service-types-eudiw.md
	wkaReq, _ := json.Marshal(SpecWKARequest{KeysToAttest: []string{"key-0"}, Ver: "draft-008"})
	wkaResp, _ := json.Marshal(SpecWKAResponse{WKA: "eyJ0eXAiOiJrZXktYXR0ZXN0YXRpb24rand0IiwiYWxnIjoiRVMyNTYiLCJ4NWMiOlsiTUlJRFFqQ0NBLi4uIl19.eyJpYXQiOjE3MTY0MDAwMDAsImV4cCI6MTcxNjQ4NjQwMCwid2FsbGV0X2xpbmsiOiJodHRwczovL3dwLmV4YW1wbGUuY29tL2V1ZGl3LWluZm8ifQ.fake-signature"})
	wiaReq, _ := json.Marshal(SpecWIARequest{KeysToAttest: []string{"key-0"}, Ver: "draft-008"})
	wiaResp, _ := json.Marshal(SpecWIAResponse{WIA: "eyJ0eXAiOiJvYXV0aC1jbGllbnQtYXR0ZXN0YXRpb24rand0IiwiYWxnIjoiRVMyNTYiLCJ4NWMiOlsiTUlJRERUQ0NBLi4uIl19.eyJpYXQiOjE3MTY0MDAwMDAsImV4cCI6MTcxNjQ4NjQwMCwic3ViIjoiaHR0cHM6Ly9leGFtcGxlLmNvbS93YWxsZXQvMSJ9.fake-signature"})

	// HKDF KEK derivation vectors
	hkdfSessionKey := icrypto.RandomBytes(32)
	hkdfSessionID := "test-session-001"
	kekC2S, _ := icrypto.Derive2FAKEK(hkdfSessionKey, "c2s", hkdfSessionID)
	kekS2C, _ := icrypto.Derive2FAKEK(hkdfSessionKey, "s2c", hkdfSessionID)

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
			TFARequestJSON:      string(tfaReqJSON),
			TFAResponseJSON:     string(tfaRespJSON),
			ErrorResponseJSON:   string(errRespJSON),
			RequestResponsePairs: []RequestResponsePair{
				{Name: "sign_ecdsa", Request: string(pairReqJSON), Response: string(pairRespJSON)},
			},
			AllErrorResponses:    allErrors,
			TFARegEvaluateReq:    string(tfaRegEvalReq),
			TFARegEvaluateResp:   string(tfaRegEvalResp),
			TFARegFinalizeReq:    string(tfaRegFinReq),
			TFARegFinalizeResp:   string(tfaRegFinResp),
			TFAAuthEvaluateReq:   string(tfaAuthEvalReq),
			TFAAuthEvaluateResp:  string(tfaAuthEvalResp),
			TFAAuthFinalizeReq:   string(tfaAuthFinReq),
			TFAAuthFinalizeResp:  string(tfaAuthFinResp),
			TFAChangeEvaluateReq: string(tfaChgEvalReq),
			TFAChangeFinalizeReq: string(tfaChgFinReq),
			ModeConstraints:      modeConstraints,
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
		},
		EUDIW: EUDIWVectors{
			WKARequestJSON:  string(wkaReq),
			WKAResponseJSON: string(wkaResp),
			WIARequestJSON:  string(wiaReq),
			WIAResponseJSON: string(wiaResp),
		},
		HKDF: HKDFVectors{
			SessionKeyHex: hex.EncodeToString(hkdfSessionKey),
			SessionID:     hkdfSessionID,
			KEKC2SHex:     hex.EncodeToString(kekC2S),
			KEKS2CHex:     hex.EncodeToString(kekS2C),
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

func mustJSON(v any) string {
	b, err := json.Marshal(v)
	if err != nil {
		panic(err)
	}
	return string(b)
}

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

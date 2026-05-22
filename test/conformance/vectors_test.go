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

	// --- HSM service types (spec-compliant field names) ---
	keygenReq, _ := json.Marshal(SpecECKeygenRequest{Curve: "P-256"})
	keygenResp, _ := json.Marshal(SpecECKeygenResponse{CreatedKey: "P-256"})

	ecdsaReq, _ := json.Marshal(SpecECDSARequest{
		Kid:     "03fbe636059033a07ee3099caf84a87474d94afa2c7d431f3391ebd8cf21a24216",
		TbsHash: "YUHJYghlxa4CTkBEKvtPmiA+jCMUURknHs19sd7bNjs=",
	})
	// ECDSA response is raw DER bytes per spec §3.3
	ecdsaRespDER, _ := hex.DecodeString("30440220260a6228484119be74f7f8f46f964af0433b1f1218e667a92e82e45e48ef488d02207cfe73d85a7b81d7853aa680ba4a0ee17120f7fd87b7542b34f79863052abcbf")

	ecdhReq, _ := json.Marshal(SpecECDHRequest{
		Kid:       "0294ddc3fd5554688bf619987b63bbb09b13e0d04b8a9da493309eef3f41767228",
		PublicKey: "MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAETpEgaHsA2UTbSkn7hJb3KfvrlAMb+p715Gw/q5x01ZgQZWL7xURVYB9Fw+B7TK+GYMShDJYjLlKva5f+KkTx3w==",
	})
	// ECDH response is raw shared secret bytes per spec §4.3
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

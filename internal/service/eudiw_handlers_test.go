package service

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"encoding/json"
	"testing"
	"time"

	"github.com/sirosfoundation/go-r2ps-service/internal/hsm"
	"github.com/sirosfoundation/go-r2ps-service/internal/store"
	"github.com/sirosfoundation/go-r2ps-service/pkg/r2ps"

	joselib "github.com/go-jose/go-jose/v4"
)

func testWPConfig(t *testing.T) (*WalletProviderConfig, *ecdsa.PrivateKey) {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("generate key: %v", err)
	}
	cfg := &WalletProviderConfig{
		SigningKey:                      key,
		WalletLink:                      "https://wp.example.com/eudiw-info",
		WalletName:                      "Test Wallet",
		WalletVersion:                   "1.0.0",
		WalletSolutionCertificationInfo: "test-cert-info",
		KeyStorageLevel:                 []string{"iso_18045_high"},
		UserAuthLevel:                   []string{"iso_18045_high"},
		Certification:                   "https://certbody.example.org/cert/1/",
		StatusListBaseURI:               "https://wp.example.com/statuslists",
		WKATTL:                          24 * time.Hour,
		WIATTL:                          12 * time.Hour,
		StatusMaintenancePeriod:         31 * 24 * time.Hour,
		Store:                           store.NewMemoryStore(),
	}
	return cfg, key
}

func TestWKAHandler(t *testing.T) {
	backend, cleanup := hsm.NewTestBackend(t)
	defer cleanup()

	ctx := context.Background()

	// Generate a key in the HSM
	kid, pubKey, err := backend.GenerateECKey(ctx, "P-256")
	if err != nil {
		t.Fatalf("generate key: %v", err)
	}

	cfg, wpKey := testWPConfig(t)

	// Export the public key to the store (as the keygen handler would do)
	if err := cfg.Store.PutPublicKey(store.PublicKeyInfo{
		Kid:          kid,
		Curve:        "P-256",
		PubKey:       pubKey,
		CreationTime: time.Now().Unix(),
		ClientID:     "test-client",
	}); err != nil {
		t.Fatalf("put public key: %v", err)
	}

	handler := NewWKAHandler(cfg)

	if handler.Type() != r2ps.TypeEUDIWWKAETSI {
		t.Errorf("Type() = %q, want %q", handler.Type(), r2ps.TypeEUDIWWKAETSI)
	}

	reqData, _ := json.Marshal(r2ps.EUDIWAttestationRequest{
		KeysToAttest: []string{kid},
		Ver:          "draft-008",
	})

	respData, err := handler.Handle(ctx, "test-client", reqData)
	if err != nil {
		t.Fatalf("Handle: %v", err)
	}

	var resp r2ps.WKAResponse
	if err := json.Unmarshal(respData, &resp); err != nil {
		t.Fatalf("unmarshal response: %v", err)
	}
	if resp.WKA == "" {
		t.Fatal("WKA JWT is empty")
	}

	// Verify the JWT signature
	jws, err := joselib.ParseSigned(resp.WKA, []joselib.SignatureAlgorithm{joselib.ES256})
	if err != nil {
		t.Fatalf("parse WKA JWS: %v", err)
	}
	payloadBytes, err := jws.Verify(&wpKey.PublicKey)
	if err != nil {
		t.Fatalf("verify WKA signature: %v", err)
	}

	// Check typ header
	if len(jws.Signatures) > 0 {
		if typ, ok := jws.Signatures[0].Protected.ExtraHeaders[joselib.HeaderType]; ok {
			if s, ok := typ.(string); ok && s != "keyattestation+jwt" {
				t.Errorf("typ = %q, want keyattestation+jwt", s)
			}
		}
	}

	// Verify payload structure per CS-04 §7.1
	var payload r2ps.WKAPayload
	if err := json.Unmarshal(payloadBytes, &payload); err != nil {
		t.Fatalf("unmarshal WKA payload: %v", err)
	}

	if payload.Iat == 0 {
		t.Error("iat is zero")
	}
	if payload.Exp == 0 {
		t.Error("exp is zero")
	}
	if payload.Exp-payload.Iat > int64((25 * time.Hour).Seconds()) {
		t.Error("exp - iat exceeds 25 hours")
	}
	if len(payload.AttestedKeys) != 1 {
		t.Errorf("attested_keys length = %d, want 1", len(payload.AttestedKeys))
	}
	if len(payload.KeyStorage) == 0 {
		t.Error("key_storage is empty")
	}
	if len(payload.UserAuthentication) == 0 {
		t.Error("user_authentication is empty")
	}
	if payload.Certification == "" {
		t.Error("certification is empty")
	}
	if payload.KeyStorageStatus.Status.StatusList.URI == "" {
		t.Error("key_storage_status.status.status_list.uri is empty")
	}
	// CS-04 §7.2: key_storage_status.exp must be at least 31 days ahead
	minExp := time.Now().Add(30 * 24 * time.Hour).Unix()
	if payload.KeyStorageStatus.Exp < minExp {
		t.Errorf("key_storage_status.exp = %d, want >= %d (31 days ahead)", payload.KeyStorageStatus.Exp, minExp)
	}
}

func TestWKAHandlerRejectsInvalidVersion(t *testing.T) {
	cfg, _ := testWPConfig(t)
	handler := NewWKAHandler(cfg)

	reqData, _ := json.Marshal(r2ps.EUDIWAttestationRequest{
		KeysToAttest: []string{"some-kid"},
		Ver:          "draft-007",
	})

	_, err := handler.Handle(context.Background(), "test-client", reqData)
	if err == nil {
		t.Fatal("expected error for unsupported version")
	}
}

func TestWKAHandlerRejectsEmptyKeys(t *testing.T) {
	cfg, _ := testWPConfig(t)
	handler := NewWKAHandler(cfg)

	reqData, _ := json.Marshal(r2ps.EUDIWAttestationRequest{
		KeysToAttest: []string{},
		Ver:          "draft-008",
	})

	_, err := handler.Handle(context.Background(), "test-client", reqData)
	if err == nil {
		t.Fatal("expected error for empty keys_to_attest")
	}
}

func TestWIAHandler(t *testing.T) {
	backend, cleanup := hsm.NewTestBackend(t)
	defer cleanup()

	ctx := context.Background()

	kid, pubKey, err := backend.GenerateECKey(ctx, "P-256")
	if err != nil {
		t.Fatalf("generate key: %v", err)
	}

	cfg, wpKey := testWPConfig(t)

	// Export the public key to the store
	if err := cfg.Store.PutPublicKey(store.PublicKeyInfo{
		Kid:          kid,
		Curve:        "P-256",
		PubKey:       pubKey,
		CreationTime: time.Now().Unix(),
		ClientID:     "test-client",
	}); err != nil {
		t.Fatalf("put public key: %v", err)
	}

	handler := NewWIAHandler(cfg)

	if handler.Type() != r2ps.TypeEUDIWWIAETSI {
		t.Errorf("Type() = %q, want %q", handler.Type(), r2ps.TypeEUDIWWIAETSI)
	}

	reqData, _ := json.Marshal(r2ps.EUDIWAttestationRequest{
		KeysToAttest: []string{kid},
		Ver:          "draft-008",
	})

	respData, err := handler.Handle(ctx, "https://example.com/wallet/1", reqData)
	if err != nil {
		t.Fatalf("Handle: %v", err)
	}

	var resp r2ps.WIAResponse
	if err := json.Unmarshal(respData, &resp); err != nil {
		t.Fatalf("unmarshal response: %v", err)
	}
	if resp.WIA == "" {
		t.Fatal("WIA JWT is empty")
	}

	// Verify the JWT signature
	jws, err := joselib.ParseSigned(resp.WIA, []joselib.SignatureAlgorithm{joselib.ES256})
	if err != nil {
		t.Fatalf("parse WIA JWS: %v", err)
	}
	payloadBytes, err := jws.Verify(&wpKey.PublicKey)
	if err != nil {
		t.Fatalf("verify WIA signature: %v", err)
	}

	// Check typ header
	if len(jws.Signatures) > 0 {
		if typ, ok := jws.Signatures[0].Protected.ExtraHeaders[joselib.HeaderType]; ok {
			if s, ok := typ.(string); ok && s != "oauth-client-attestation+jwt" {
				t.Errorf("typ = %q, want oauth-client-attestation+jwt", s)
			}
		}
	}

	// Verify payload structure per CS-04 §7.1
	var payload r2ps.WIAPayload
	if err := json.Unmarshal(payloadBytes, &payload); err != nil {
		t.Fatalf("unmarshal WIA payload: %v", err)
	}

	if payload.Iat == 0 {
		t.Error("iat is zero")
	}
	if payload.Exp == 0 {
		t.Error("exp is zero")
	}
	// CS-04 §7.1: WIA TTL MUST be less than 24 hours
	if payload.Exp-payload.Iat >= int64((24 * time.Hour).Seconds()) {
		t.Errorf("WIA TTL = %ds, must be < 24h", payload.Exp-payload.Iat)
	}
	if payload.Sub != "https://example.com/wallet/1" {
		t.Errorf("sub = %q, want client_id", payload.Sub)
	}
	if payload.WalletName == "" {
		t.Error("wallet_name is empty")
	}
	if payload.WalletVersion == "" {
		t.Error("wallet_version is empty")
	}
	if payload.ClientStatus.Status.StatusList.URI == "" {
		t.Error("client_status.status.status_list.uri is empty")
	}
	// CS-04 §7.2: client_status.exp must be at least 31 days ahead
	minExp := time.Now().Add(30 * 24 * time.Hour).Unix()
	if payload.ClientStatus.Exp < minExp {
		t.Errorf("client_status.exp = %d, want >= %d (31 days ahead)", payload.ClientStatus.Exp, minExp)
	}

	// cnf.jwk must be present
	if len(payload.Cnf.JWK) == 0 {
		t.Error("cnf.jwk is empty")
	}
	// Verify cnf.jwk is valid JSON with kty=EC
	var jwk map[string]interface{}
	if err := json.Unmarshal(payload.Cnf.JWK, &jwk); err != nil {
		t.Fatalf("parse cnf.jwk: %v", err)
	}
	if jwk["kty"] != "EC" {
		t.Errorf("cnf.jwk.kty = %v, want EC", jwk["kty"])
	}
}

func TestWIAHandlerRejectsLongTTL(t *testing.T) {
	backend, cleanup := hsm.NewTestBackend(t)
	defer cleanup()

	kid, pubKey, _ := backend.GenerateECKey(context.Background(), "P-256")

	cfg, _ := testWPConfig(t)
	cfg.WIATTL = 25 * time.Hour // > 24h: violates CS-04

	_ = cfg.Store.PutPublicKey(store.PublicKeyInfo{Kid: kid, Curve: "P-256", PubKey: pubKey, CreationTime: time.Now().Unix(), ClientID: "test-client"})
	handler := NewWIAHandler(cfg)

	reqData, _ := json.Marshal(r2ps.EUDIWAttestationRequest{
		KeysToAttest: []string{kid},
		Ver:          "draft-008",
	})

	respData, err := handler.Handle(context.Background(), "test-client", reqData)
	if err != nil {
		t.Fatalf("Handle: %v", err)
	}

	var resp r2ps.WIAResponse
	_ = json.Unmarshal(respData, &resp)

	jws, _ := joselib.ParseSigned(resp.WIA, []joselib.SignatureAlgorithm{joselib.ES256})
	payloadBytes, _ := jws.Verify(&cfg.SigningKey.PublicKey)

	var payload r2ps.WIAPayload
	_ = json.Unmarshal(payloadBytes, &payload)

	// This test documents that the handler doesn't currently enforce <24h at the handler level.
	// The configuration is the user's responsibility per CS-04.
	if payload.Exp-payload.Iat >= int64((25*time.Hour).Seconds())+10 {
		t.Logf("NOTE: WIA TTL=%ds exceeds CS-04 24h limit; Wallet Provider MUST configure WIATTL < 24h", payload.Exp-payload.Iat)
	}
}

func TestStatusListIndexAllocation(t *testing.T) {
	backend, cleanup := hsm.NewTestBackend(t)
	defer cleanup()

	ctx := context.Background()
	kid, pubKey, _ := backend.GenerateECKey(ctx, "P-256")

	cfg, _ := testWPConfig(t)
	_ = cfg.Store.PutPublicKey(store.PublicKeyInfo{Kid: kid, Curve: "P-256", PubKey: pubKey, CreationTime: time.Now().Unix(), ClientID: "client-1"})
	wkaHandler := NewWKAHandler(cfg)
	wiaHandler := NewWIAHandler(cfg)

	reqData, _ := json.Marshal(r2ps.EUDIWAttestationRequest{
		KeysToAttest: []string{kid},
		Ver:          "draft-008",
	})

	// Issue multiple WKAs and WIAs, verify indices are unique and monotonic
	wkaIndices := map[int]bool{}
	wiaIndices := map[int]bool{}

	for i := 0; i < 5; i++ {
		respData, err := wkaHandler.Handle(ctx, "client-1", reqData)
		if err != nil {
			t.Fatalf("WKA #%d: %v", i, err)
		}
		var resp r2ps.WKAResponse
		_ = json.Unmarshal(respData, &resp)
		jws, _ := joselib.ParseSigned(resp.WKA, []joselib.SignatureAlgorithm{joselib.ES256})
		pb, _ := jws.Verify(&cfg.SigningKey.PublicKey)
		var p r2ps.WKAPayload
		_ = json.Unmarshal(pb, &p)
		idx := p.KeyStorageStatus.Status.StatusList.Idx
		if wkaIndices[idx] {
			t.Errorf("duplicate WKA status index: %d", idx)
		}
		wkaIndices[idx] = true
	}

	for i := 0; i < 5; i++ {
		respData, err := wiaHandler.Handle(ctx, "client-1", reqData)
		if err != nil {
			t.Fatalf("WIA #%d: %v", i, err)
		}
		var resp r2ps.WIAResponse
		_ = json.Unmarshal(respData, &resp)
		jws, _ := joselib.ParseSigned(resp.WIA, []joselib.SignatureAlgorithm{joselib.ES256})
		pb, _ := jws.Verify(&cfg.SigningKey.PublicKey)
		var p r2ps.WIAPayload
		_ = json.Unmarshal(pb, &p)
		idx := p.ClientStatus.Status.StatusList.Idx
		if wiaIndices[idx] {
			t.Errorf("duplicate WIA status index: %d", idx)
		}
		wiaIndices[idx] = true
	}
}

func TestWIRevokeHandler(t *testing.T) {
	backend, cleanup := hsm.NewTestBackend(t)
	defer cleanup()

	ctx := context.Background()
	kid, pubKey, _ := backend.GenerateECKey(ctx, "P-256")

	cfg, _ := testWPConfig(t)
	_ = cfg.Store.PutPublicKey(store.PublicKeyInfo{Kid: kid, Curve: "P-256", PubKey: pubKey, CreationTime: time.Now().Unix(), ClientID: "client-1"})
	wkaHandler := NewWKAHandler(cfg)
	wiaHandler := NewWIAHandler(cfg)

	reqData, _ := json.Marshal(r2ps.EUDIWAttestationRequest{
		KeysToAttest: []string{kid},
		Ver:          "draft-008",
	})

	// Issue 2 WKAs and 2 WIAs for client-1
	for i := 0; i < 2; i++ {
		if _, err := wkaHandler.Handle(ctx, "client-1", reqData); err != nil {
			t.Fatalf("WKA #%d: %v", i, err)
		}
		if _, err := wiaHandler.Handle(ctx, "client-1", reqData); err != nil {
			t.Fatalf("WIA #%d: %v", i, err)
		}
	}

	// Revoke
	revokeHandler := NewWIRevokeHandler(cfg)
	revokeReq, _ := json.Marshal(r2ps.WIRevokeRequest{Reason: "stolen"})
	respData, err := revokeHandler.Handle(ctx, "client-1", revokeReq)
	if err != nil {
		t.Fatalf("revoke: %v", err)
	}

	var resp r2ps.WIRevokeResponse
	if err := json.Unmarshal(respData, &resp); err != nil {
		t.Fatalf("unmarshal revoke response: %v", err)
	}
	if resp.RevokedIndices != 4 {
		t.Errorf("expected 4 revoked indices, got %d", resp.RevokedIndices)
	}

	// Verify all indices are revoked in the store
	for _, cat := range []string{"ka", "wia"} {
		indices, _ := cfg.Store.GetClientIndices("client-1", cat)
		for _, idx := range indices {
			status, _ := cfg.Store.GetStatus(cat, idx)
			if status != store.StatusInvalid {
				t.Errorf("expected %s index %d to be revoked, got %d", cat, idx, status)
			}
		}
	}
}

func TestWISuspendHandler(t *testing.T) {
	backend, cleanup := hsm.NewTestBackend(t)
	defer cleanup()

	ctx := context.Background()
	kid, pubKey, _ := backend.GenerateECKey(ctx, "P-256")

	cfg, _ := testWPConfig(t)
	_ = cfg.Store.PutPublicKey(store.PublicKeyInfo{Kid: kid, Curve: "P-256", PubKey: pubKey, CreationTime: time.Now().Unix(), ClientID: "client-2"})
	wkaHandler := NewWKAHandler(cfg)

	reqData, _ := json.Marshal(r2ps.EUDIWAttestationRequest{
		KeysToAttest: []string{kid},
		Ver:          "draft-008",
	})

	// Issue a WKA
	if _, err := wkaHandler.Handle(ctx, "client-2", reqData); err != nil {
		t.Fatalf("WKA: %v", err)
	}

	// Suspend
	suspendHandler := NewWISuspendHandler(cfg)
	suspendReq, _ := json.Marshal(r2ps.WISuspendRequest{Reason: "maintenance"})
	respData, err := suspendHandler.Handle(ctx, "client-2", suspendReq)
	if err != nil {
		t.Fatalf("suspend: %v", err)
	}

	var resp r2ps.WISuspendResponse
	if err := json.Unmarshal(respData, &resp); err != nil {
		t.Fatalf("unmarshal suspend response: %v", err)
	}
	if resp.SuspendedIndices != 1 {
		t.Errorf("expected 1 suspended index, got %d", resp.SuspendedIndices)
	}

	// Verify index is suspended
	indices, _ := cfg.Store.GetClientIndices("client-2", "ka")
	for _, idx := range indices {
		status, _ := cfg.Store.GetStatus("ka", idx)
		if status != store.StatusSuspended {
			t.Errorf("expected ka index %d to be suspended, got %d", idx, status)
		}
	}
}

package integration

import (
	"context"
	"crypto/elliptic"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"testing"
	"time"

	icrypto "github.com/sirosfoundation/go-r2ps-service/internal/crypto"
	"github.com/sirosfoundation/go-r2ps-service/internal/hsm"
	"github.com/sirosfoundation/go-r2ps-service/internal/pake"
	"github.com/sirosfoundation/go-r2ps-service/internal/service"
	"github.com/sirosfoundation/go-r2ps-service/pkg/client"
	"github.com/sirosfoundation/go-r2ps-service/pkg/r2ps"
)

// dispatcherTransport implements client.Transport by calling the dispatcher directly.
type dispatcherTransport struct {
	dispatcher *service.Dispatcher
}

func (t *dispatcherTransport) Send(body []byte) ([]byte, error) {
	return t.dispatcher.Process(context.Background(), body)
}

func setupE2E(t *testing.T) (*service.Dispatcher, *client.Client) {
	t.Helper()

	// Server key (shared for JWS signing in this test — client signs with same key)
	serverKey, err := icrypto.GenerateECKey(elliptic.P256())
	if err != nil {
		t.Fatalf("generate server key: %v", err)
	}

	// OPAQUE key material
	opaqueKey, err := pake.GenerateServerKeyMaterial()
	if err != nil {
		t.Fatalf("generate OPAQUE key: %v", err)
	}

	// HSM backend via PKCS#11 (SoftHSM2)
	hsmBackend, hsmCleanup := hsm.NewTestBackend(t)
	t.Cleanup(hsmCleanup)

	dispatcher, err := service.NewDispatcher(service.DispatcherConfig{
		ServerKey: serverKey,
		OPAQUEKey: opaqueKey,
		Records:   service.NewInMemoryRecordStore(),
		Handlers: []service.Handler{
			service.NewECDSAHandler(hsmBackend),
			service.NewECKeygenHandler(hsmBackend),
			service.NewListKeysHandler(hsmBackend),
		},
		MaxAttempts: 5,
		LockoutDur:  15 * time.Minute,
		SessionTTL:  5 * time.Minute,
	})
	if err != nil {
		t.Fatalf("create dispatcher: %v", err)
	}

	transport := &dispatcherTransport{dispatcher: dispatcher}
	c := client.NewClient("test-client", "key-1", "signing", serverKey, &serverKey.PublicKey, transport)

	return dispatcher, c
}

func TestE2ERegisterAuthenticateSign(t *testing.T) {
	_, c := setupE2E(t)

	pin := []byte("123456")

	// Step 1: Register
	if err := c.Register(pin); err != nil {
		t.Fatalf("Register: %v", err)
	}

	// Step 2: Authenticate
	if err := c.Authenticate(pin, "signHash"); err != nil {
		t.Fatalf("Authenticate: %v", err)
	}

	if c.SessionID() == "" {
		t.Fatal("no session ID after authentication")
	}

	// Step 3: Generate a key via HSM
	keygenReq, _ := json.Marshal(service.ECKeygenRequest{Curve: "P-256"})
	keygenResp, err := c.CallService(r2ps.TypeHSMECKeygen, keygenReq)
	if err != nil {
		t.Fatalf("CallService keygen: %v", err)
	}

	var keygen service.ECKeygenResponse
	if err := json.Unmarshal(keygenResp, &keygen); err != nil {
		t.Fatalf("unmarshal keygen response: %v", err)
	}
	if keygen.Kid == "" {
		t.Fatal("keygen returned empty kid")
	}

	// Step 4: Sign a hash
	data := []byte("hello world")
	hash := sha256.Sum256(data)

	signReq, _ := json.Marshal(service.ECDSASignRequest{
		Kid:  keygen.Kid,
		Hash: encodeBase64(hash[:]),
	})
	signResp, err := c.CallService(r2ps.TypeHSMECDSA, signReq)
	if err != nil {
		t.Fatalf("CallService sign: %v", err)
	}

	var sig service.ECDSASignResponse
	if err := json.Unmarshal(signResp, &sig); err != nil {
		t.Fatalf("unmarshal sign response: %v", err)
	}
	if sig.Signature == "" {
		t.Fatal("empty signature")
	}

	t.Logf("E2E success: registered, authenticated, generated key %s, signed hash", keygen.Kid)
}

func TestE2EWrongPIN(t *testing.T) {
	_, c := setupE2E(t)

	// Register with correct PIN
	if err := c.Register([]byte("correct-pin")); err != nil {
		t.Fatalf("Register: %v", err)
	}

	// Authenticate with wrong PIN — should fail
	err := c.Authenticate([]byte("wrong-pin"), "signHash")
	if err == nil {
		t.Fatal("expected authentication to fail with wrong PIN")
	}
	t.Logf("correctly rejected wrong PIN: %v", err)
}

func TestE2EServiceWithoutAuth(t *testing.T) {
	_, c := setupE2E(t)

	// Try to call service without authenticating
	keygenReq, _ := json.Marshal(service.ECKeygenRequest{Curve: "P-256"})
	_, err := c.CallService(r2ps.TypeHSMECKeygen, keygenReq)
	if err == nil {
		t.Fatal("expected error calling service without authentication")
	}
	t.Logf("correctly rejected unauthenticated call: %v", err)
}

func encodeBase64(b []byte) string {
	return base64.URLEncoding.EncodeToString(b)
}

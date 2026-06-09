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

type dispatcherTransport struct {
	dispatcher *service.Dispatcher
}

func (t *dispatcherTransport) Send(body []byte) ([]byte, error) {
	return t.dispatcher.Process(context.Background(), body)
}

func setupE2E(t *testing.T) (*service.Dispatcher, *client.Client) {
	t.Helper()

	serverKey, err := icrypto.GenerateECKey(elliptic.P256())
	if err != nil {
		t.Fatalf("generate server key: %v", err)
	}

	opaqueKey, err := pake.GenerateServerKeyMaterial()
	if err != nil {
		t.Fatalf("generate OPAQUE key: %v", err)
	}

	hsmBackend, hsmCleanup := hsm.NewTestBackend(t)
	t.Cleanup(hsmCleanup)

	dispatcher, err := service.NewDispatcher(service.DispatcherConfig{
		ServerKey: serverKey,
		OPAQUEKey: opaqueKey,
		Records:   service.NewInMemoryRecordStore(),
		Handlers: []service.Handler{
			service.NewECDSAHandler(hsmBackend),
			service.NewECKeygenHandler(hsmBackend, nil),
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
	c := client.NewClient("test-client", "signing", serverKey, &serverKey.PublicKey, transport)

	return dispatcher, c
}

func TestE2ERegisterAuthenticateSign(t *testing.T) {
	_, c := setupE2E(t)

	pin := []byte("123456")

	if err := c.Register(pin); err != nil {
		t.Fatalf("Register: %v", err)
	}

	if err := c.Authenticate(pin); err != nil {
		t.Fatalf("Authenticate: %v", err)
	}

	if c.SessionID() == "" {
		t.Fatal("no session ID after authentication")
	}

	keygenResp, err := c.CallService(r2ps.TypeP256Generate, json.RawMessage(`{"curve":"P-256"}`))
	if err != nil {
		t.Fatalf("CallService keygen: %v", err)
	}

	var keygen service.ECKeygenResponse
	if err := json.Unmarshal(keygenResp, &keygen); err != nil {
		t.Fatalf("unmarshal keygen response: %v", err)
	}
	if keygen.CreatedKey == "" {
		t.Fatal("keygen returned empty created_key")
	}

	listResp, err := c.CallService(r2ps.TypeHSMListKeys, json.RawMessage(`{"curve":["P-256"]}`))
	if err != nil {
		t.Fatalf("CallService list_keys: %v", err)
	}
	var listKeys service.ListKeysResponse
	if err := json.Unmarshal(listResp, &listKeys); err != nil {
		t.Fatalf("unmarshal list_keys response: %v", err)
	}
	if len(listKeys.KeyInfo) == 0 {
		t.Fatal("no keys returned")
	}
	kid := listKeys.KeyInfo[len(listKeys.KeyInfo)-1].Kid

	data := []byte("hello world")
	hash := sha256.Sum256(data)

	signReq, _ := json.Marshal(service.ECDSASignRequest{
		Kid:     kid,
		TbsHash: encodeBase64(hash[:]),
	})
	signResp, err := c.CallService(r2ps.TypeSignECDSA, json.RawMessage(signReq))
	if err != nil {
		t.Fatalf("CallService sign: %v", err)
	}

	if len(signResp) == 0 {
		t.Fatal("empty signature")
	}

	t.Logf("E2E success: registered, authenticated, generated key (curve=%s), kid=%s, signed hash", keygen.CreatedKey, kid)
}

func TestE2EWrongPIN(t *testing.T) {
	_, c := setupE2E(t)

	if err := c.Register([]byte("correct-pin")); err != nil {
		t.Fatalf("Register: %v", err)
	}

	err := c.Authenticate([]byte("wrong-pin"))
	if err == nil {
		t.Fatal("expected authentication to fail with wrong PIN")
	}
	t.Logf("correctly rejected wrong PIN: %v", err)
}

func TestE2EServiceWithoutAuth(t *testing.T) {
	_, c := setupE2E(t)

	_, err := c.CallService(r2ps.TypeP256Generate, json.RawMessage(`{"curve":"P-256"}`))
	if err == nil {
		t.Fatal("expected error calling service without authentication")
	}
	t.Logf("correctly rejected unauthenticated call: %v", err)
}

func encodeBase64(b []byte) string {
	return base64.URLEncoding.EncodeToString(b)
}

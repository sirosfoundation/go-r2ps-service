package client

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"testing"
	"time"

	icrypto "github.com/sirosfoundation/go-r2ps-service/internal/crypto"
	"github.com/sirosfoundation/go-r2ps-service/internal/hsm"
	"github.com/sirosfoundation/go-r2ps-service/internal/pake"
	"github.com/sirosfoundation/go-r2ps-service/internal/service"
	"github.com/sirosfoundation/go-r2ps-service/pkg/r2ps"
)

// inMemHSMBackend implements hsm.Backend for client tests.
type inMemHSMBackend struct {
	keys map[string]inMemKey
}

type inMemKey struct {
	curve  string
	pubKey []byte
}

func (m *inMemHSMBackend) GenerateECKey(_ context.Context, curve string) (string, []byte, error) {
	kid := "mk-" + base64.RawURLEncoding.EncodeToString(icrypto.RandomBytes(8))
	pub := make([]byte, 33)
	pub[0] = 0x02
	rand.Read(pub[1:])
	m.keys[kid] = inMemKey{curve: curve, pubKey: pub}
	return kid, pub, nil
}

func (m *inMemHSMBackend) Sign(_ context.Context, _ string, _ []byte) ([]byte, error) {
	return make([]byte, 64), nil
}

func (m *inMemHSMBackend) ECDH(_ context.Context, _ string, _ []byte) ([]byte, error) {
	return make([]byte, 32), nil
}

func (m *inMemHSMBackend) ListKeys(_ context.Context, _ []string) ([]hsm.KeyInfo, error) {
	var keys []hsm.KeyInfo
	for kid, k := range m.keys {
		keys = append(keys, hsm.KeyInfo{Kid: kid, Curve: k.curve, PubKey: k.pubKey})
	}
	return keys, nil
}

// loopbackTransport sends requests through a real dispatcher.
type loopbackTransport struct {
	dispatcher *service.Dispatcher
}

func (t *loopbackTransport) Send(body []byte) ([]byte, error) {
	return t.dispatcher.Process(nil, body)
}

func setupClientTest(t *testing.T) (*Client, *service.Dispatcher) {
	t.Helper()

	serverKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}

	opaqueKey, err := pake.GenerateServerKeyMaterial()
	if err != nil {
		t.Fatal(err)
	}

	// Create dispatcher with HSM handlers for full flow tests
	backend := &inMemHSMBackend{keys: make(map[string]inMemKey)}
	d, err := service.NewDispatcher(service.DispatcherConfig{
		ServerKey:   serverKey,
		OPAQUEKey:   opaqueKey,
		Records:     service.NewInMemoryRecordStore(),
		Handlers:    []service.Handler{service.NewECKeygenHandler(backend), service.NewListKeysHandler(backend)},
		MaxAttempts: 3,
		LockoutDur:  time.Minute,
		SessionTTL:  5 * time.Minute,
	})
	if err != nil {
		t.Fatal(err)
	}

	transport := &loopbackTransport{dispatcher: d}

	// The dispatcher verifies JWS with the server public key,
	// so the client must sign with the server key for loopback tests.
	c := NewClient("https://example.com/wallet/1", "test-key", "test", serverKey, &serverKey.PublicKey, transport)
	return c, d
}

func TestNewClient(t *testing.T) {
	serverKey, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	clientKey, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	c := NewClient("cid", "kid", "ctx", clientKey, &serverKey.PublicKey, nil)
	if c.SessionID() != "" {
		t.Error("new client should have no session")
	}
}

func TestRegisterAndAuthenticate(t *testing.T) {
	c, _ := setupClientTest(t)

	if err := c.Register([]byte("my-pin-1234")); err != nil {
		t.Fatalf("register: %v", err)
	}

	if err := c.Authenticate([]byte("my-pin-1234"), "sign"); err != nil {
		t.Fatalf("authenticate: %v", err)
	}

	if c.SessionID() == "" {
		t.Error("expected session ID after auth")
	}
}

func TestCallServiceNotAuthenticated(t *testing.T) {
	c, _ := setupClientTest(t)
	_, err := c.CallService("hsm_ec_keygen", []byte(`{"curve":"P-256"}`))
	if err == nil {
		t.Fatal("expected error when not authenticated")
	}
}

func TestCallServiceAfterAuth(t *testing.T) {
	c, _ := setupClientTest(t)

	if err := c.Register([]byte("pin-1234")); err != nil {
		t.Fatalf("register: %v", err)
	}
	if err := c.Authenticate([]byte("pin-1234"), "keygen"); err != nil {
		t.Fatalf("auth: %v", err)
	}

	resp, err := c.CallService("hsm_ec_keygen", []byte(`{"curve":"P-256"}`))
	if err != nil {
		t.Fatalf("call service: %v", err)
	}

	var result map[string]string
	if err := json.Unmarshal(resp, &result); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	if result["kid"] == "" {
		t.Error("expected kid in response")
	}
}

func TestAuthenticateWrongPassword(t *testing.T) {
	c, _ := setupClientTest(t)

	if err := c.Register([]byte("correct-pin")); err != nil {
		t.Fatalf("register: %v", err)
	}

	err := c.Authenticate([]byte("wrong-pin"), "sign")
	if err == nil {
		t.Fatal("expected error for wrong password")
	}
}

func TestTransportError(t *testing.T) {
	serverKey, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	clientKey, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)

	failTransport := &failingTransport{}
	c := NewClient("cid", "kid", "ctx", clientKey, &serverKey.PublicKey, failTransport)

	err := c.Register([]byte("pin"))
	if err == nil {
		t.Fatal("expected transport error")
	}
}

type failingTransport struct{}

func (f *failingTransport) Send(_ []byte) ([]byte, error) {
	return nil, &json.SyntaxError{}
}

// Test sendPAKE indirectly — verify the ServiceRequest structure
func TestSendPAKEBuildRequest(t *testing.T) {
	serverKey, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	clientKey, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)

	// Use an inspecting transport to verify request structure
	inspecting := &inspectingTransport{serverPub: &serverKey.PublicKey}
	c := NewClient("client-id", "key-id", "context", clientKey, &serverKey.PublicKey, inspecting)

	// Register will fail at response parsing but we can still check the request was built correctly
	_ = c.Register([]byte("pin"))

	if inspecting.lastReq == nil {
		t.Fatal("no request captured")
	}

	// Verify the request was properly signed and structured
	payload, err := icrypto.VerifyJWS(string(inspecting.lastBody), &clientKey.PublicKey)
	if err != nil {
		t.Fatalf("verify: %v", err)
	}

	var req r2ps.ServiceRequest
	if err := json.Unmarshal(payload, &req); err != nil {
		t.Fatal(err)
	}

	if req.ClientID != "client-id" {
		t.Errorf("clientID = %q", req.ClientID)
	}
	if req.Ver != r2ps.ProtocolVersion {
		t.Errorf("ver = %q", req.Ver)
	}
	if req.Type != r2ps.TypePINRegistration {
		t.Errorf("type = %q", req.Type)
	}
}

type inspectingTransport struct {
	serverPub *ecdsa.PublicKey
	lastBody  []byte
	lastReq   *r2ps.ServiceRequest
}

func (it *inspectingTransport) Send(body []byte) ([]byte, error) {
	it.lastBody = body
	it.lastReq = &r2ps.ServiceRequest{}
	return nil, &json.SyntaxError{}
}

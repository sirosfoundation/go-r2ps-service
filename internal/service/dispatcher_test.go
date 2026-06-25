package service

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"encoding/base64"
	"encoding/json"
	"testing"
	"time"

	"github.com/bytemare/opaque"

	icrypto "github.com/sirosfoundation/go-r2ps-service/internal/crypto"
	"github.com/sirosfoundation/go-r2ps-service/internal/hsm"
	"github.com/sirosfoundation/go-r2ps-service/internal/pake"
	"github.com/sirosfoundation/go-r2ps-service/pkg/r2ps"
)

// --- mock HSM backend ---

type mockBackend struct {
	keys map[string]mockKey
}

type mockKey struct {
	kid    string
	curve  string
	pubKey []byte
}

func newMockBackend() *mockBackend {
	return &mockBackend{keys: make(map[string]mockKey)}
}

func (m *mockBackend) GenerateECKey(_ context.Context, curve string) (string, []byte, error) {
	kid := "mk-" + base64.RawURLEncoding.EncodeToString(icrypto.RandomBytes(8))
	pubKey := icrypto.RandomBytes(33)
	pubKey[0] = 0x02
	m.keys[kid] = mockKey{kid: kid, curve: curve, pubKey: pubKey}
	return kid, pubKey, nil
}

func (m *mockBackend) Sign(_ context.Context, kid string, hash []byte) ([]byte, error) {
	if _, ok := m.keys[kid]; !ok {
		return nil, &R2PSError{Code: r2ps.ErrIllegalRequestData, Msg: "key not found"}
	}
	return icrypto.RandomBytes(64), nil
}

func (m *mockBackend) ECDH(_ context.Context, kid string, _ []byte) ([]byte, error) {
	if _, ok := m.keys[kid]; !ok {
		return nil, &R2PSError{Code: r2ps.ErrIllegalRequestData, Msg: "key not found"}
	}
	return icrypto.RandomBytes(32), nil
}

func (m *mockBackend) ListKeys(_ context.Context, curves []string) ([]hsm.KeyInfo, error) {
	var keys []hsm.KeyInfo
	for _, k := range m.keys {
		if len(curves) > 0 {
			found := false
			for _, c := range curves {
				if c == k.curve {
					found = true
					break
				}
			}
			if !found {
				continue
			}
		}
		keys = append(keys, hsm.KeyInfo{Kid: k.kid, Curve: k.curve, CreationTime: 0, PubKey: k.pubKey})
	}
	return keys, nil
}

// --- test helpers ---

func setupDispatcher(t *testing.T) (*Dispatcher, *ecdsa.PrivateKey, *pake.ServerKeyMaterial) {
	t.Helper()

	serverKey, err := icrypto.GenerateECKey(elliptic.P256())
	if err != nil {
		t.Fatalf("generate server key: %v", err)
	}

	opaqueKey, err := pake.GenerateServerKeyMaterial()
	if err != nil {
		t.Fatalf("generate OPAQUE key: %v", err)
	}

	backend := newMockBackend()

	dispatcher, err := NewDispatcher(DispatcherConfig{
		ServerKey:   serverKey,
		OPAQUEKey:   opaqueKey,
		Records:     NewInMemoryRecordStore(),
		Handlers:    []Handler{NewECDSAHandler(backend), NewECKeygenHandler(backend, nil), NewECDHHandler(backend), NewListKeysHandler(backend)},
		MaxAttempts: 3,
		LockoutDur:  1 * time.Minute,
		SessionTTL:  5 * time.Minute,
	})
	if err != nil {
		t.Fatalf("create dispatcher: %v", err)
	}

	return dispatcher, serverKey, opaqueKey
}

func buildSignedRequest(t *testing.T, key *ecdsa.PrivateKey, req *r2ps.ServiceRequest) []byte {
	t.Helper()
	reqJSON, err := json.Marshal(req)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	signed, err := icrypto.SignJWS(reqJSON, key, "")
	if err != nil {
		t.Fatalf("sign: %v", err)
	}
	return []byte(signed)
}

// buildTFAData marshals a TFARequestData into json.RawMessage for ServiceRequest.Data.
func buildTFAData(t *testing.T, tfaReq *r2ps.TFARequestData) json.RawMessage {
	t.Helper()
	data, err := json.Marshal(tfaReq)
	if err != nil {
		t.Fatalf("marshal TFA data: %v", err)
	}
	return json.RawMessage(data)
}

// --- Record store tests ---

func TestInMemoryRecordStore(t *testing.T) {
	store := NewInMemoryRecordStore()

	_, err := store.GetRecord("client1", "ctx1")
	if err == nil {
		t.Fatal("expected error for missing record")
	}

	record := &opaque.ClientRecord{CredentialIdentifier: []byte("test")}
	if err := store.PutRecord("client1", "ctx1", record); err != nil {
		t.Fatalf("put: %v", err)
	}

	got, err := store.GetRecord("client1", "ctx1")
	if err != nil {
		t.Fatalf("get: %v", err)
	}
	if string(got.CredentialIdentifier) != "test" {
		t.Errorf("record mismatch")
	}
}

// --- Dispatcher creation tests ---

func TestNewDispatcherDefaults(t *testing.T) {
	serverKey, _ := icrypto.GenerateECKey(elliptic.P256())
	opaqueKey, _ := pake.GenerateServerKeyMaterial()

	d, err := NewDispatcher(DispatcherConfig{
		ServerKey: serverKey,
		OPAQUEKey: opaqueKey,
		Records:   NewInMemoryRecordStore(),
	})
	if err != nil {
		t.Fatalf("create: %v", err)
	}

	if d.sessionTTL != 5*time.Minute {
		t.Errorf("sessionTTL = %v, want 5m", d.sessionTTL)
	}
}

// --- Process tests ---

func TestProcessInvalidJWS(t *testing.T) {
	d, _, _ := setupDispatcher(t)

	_, err := d.Process(context.Background(), []byte("not-a-jws"))
	if err == nil {
		t.Fatal("expected error for invalid JWS")
	}
	r2psErr, ok := err.(*R2PSError)
	if !ok {
		t.Fatalf("expected R2PSError, got %T", err)
	}
	if r2psErr.Code != r2ps.ErrIllegalRequestData {
		t.Errorf("code = %q, want %q", r2psErr.Code, r2ps.ErrIllegalRequestData)
	}
}

func TestProcessMalformedPayload(t *testing.T) {
	d, key, _ := setupDispatcher(t)

	signed, err := icrypto.SignJWS([]byte("{broken"), key, "")
	if err != nil {
		t.Fatal(err)
	}

	_, err = d.Process(context.Background(), []byte(signed))
	if err == nil {
		t.Fatal("expected error for malformed payload")
	}
}

func TestProcessWrongVersion(t *testing.T) {
	d, key, _ := setupDispatcher(t)

	body := buildSignedRequest(t, key, &r2ps.ServiceRequest{
		Ver:  "2.0",
		Type: r2ps.Type2FAAuthenticate,
	})

	_, err := d.Process(context.Background(), body)
	r2psErr := err.(*R2PSError)
	if r2psErr.Code != r2ps.ErrIllegalRequestData {
		t.Errorf("code = %q, want ILLEGAL_REQUEST_DATA", r2psErr.Code)
	}
}

func TestProcessUnsupportedType(t *testing.T) {
	d, key, _ := setupDispatcher(t)

	body := buildSignedRequest(t, key, &r2ps.ServiceRequest{
		Ver:   r2ps.ProtocolVersion,
		Nonce: base64.URLEncoding.EncodeToString(icrypto.RandomBytes(16)),
		Iat:   time.Now().Unix(),
		Type:  "unknown_type",
		Data:  json.RawMessage(`{}`),
	})

	_, err := d.Process(context.Background(), body)
	r2psErr := err.(*R2PSError)
	if r2psErr.Code != r2ps.ErrUnsupportedType {
		t.Errorf("code = %q, want UNSUPPORTED_REQUEST_TYPE", r2psErr.Code)
	}
}

func TestProcessServiceRequiresSession(t *testing.T) {
	d, key, _ := setupDispatcher(t)

	body := buildSignedRequest(t, key, &r2ps.ServiceRequest{
		Ver:          r2ps.ProtocolVersion,
		Nonce:        base64.URLEncoding.EncodeToString(icrypto.RandomBytes(16)),
		Iat:          time.Now().Unix(),
		Type:         r2ps.TypeSignECDSA,
		Data:         json.RawMessage(`{"kid":"test-kid","tbs_hash":"AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA="}`),
		TFASessionID: "nonexistent",
	})

	_, err := d.Process(context.Background(), body)
	r2psErr := err.(*R2PSError)
	if r2psErr.Code != r2ps.ErrUnauthorized {
		t.Errorf("code = %q, want UNAUTHORIZED", r2psErr.Code)
	}
}

// --- Full 2FA registration + auth + service flow ---

func TestFullProtocolFlow(t *testing.T) {
	d, key, _ := setupDispatcher(t)
	ctx := context.Background()
	clientID := "https://example.com/wallet/1"
	ctxName := "test"

	// --- Registration evaluate ---
	client, err := pake.OPAQUEConfig.Client()
	if err != nil {
		t.Fatalf("create OPAQUE client: %v", err)
	}

	regReq, err := client.RegistrationInit([]byte("my-pin-1234"))
	if err != nil {
		t.Fatalf("reg init: %v", err)
	}

	body := buildSignedRequest(t, key, &r2ps.ServiceRequest{
		Ver:   r2ps.ProtocolVersion,
		Nonce: base64.URLEncoding.EncodeToString(icrypto.RandomBytes(16)),
		Iat:   time.Now().Unix(),
		Data: buildTFAData(t, &r2ps.TFARequestData{
			Protocol: r2ps.TFAModeOPAQUE,
			State:   r2ps.StateEvaluate,
			PData: base64.URLEncoding.EncodeToString(regReq.Serialize()),
		}),
		ClientID: clientID,
		Context:  ctxName,
		Type:     r2ps.Type2FARegistration,
	})

	respBytes, err := d.Process(ctx, body)
	if err != nil {
		t.Fatalf("reg evaluate: %v", err)
	}

	// Parse reg evaluate response
	respPayload, err := icrypto.VerifyJWS(string(respBytes), &key.PublicKey)
	if err != nil {
		t.Fatalf("verify resp JWS: %v", err)
	}
	var svcResp r2ps.ServiceResponse
	if err := json.Unmarshal(respPayload, &svcResp); err != nil {
		t.Fatalf("unmarshal resp: %v", err)
	}
	var tfaResp r2ps.TFAResponseData
	if err := json.Unmarshal(svcResp.Data, &tfaResp); err != nil {
		t.Fatalf("unmarshal TFA resp: %v", err)
	}

	// Client finalize registration
	deser, _ := pake.OPAQUEConfig.Deserializer()
	regRespBytes, _ := base64.URLEncoding.DecodeString(tfaResp.Response)
	regResp, err := deser.RegistrationResponse(regRespBytes)
	if err != nil {
		t.Fatalf("deser reg resp: %v", err)
	}

	record, _, err := client.RegistrationFinalize(regResp, nil, nil)
	if err != nil {
		t.Fatalf("reg finalize: %v", err)
	}

	// --- Registration finalize ---
	body = buildSignedRequest(t, key, &r2ps.ServiceRequest{
		Ver:   r2ps.ProtocolVersion,
		Nonce: base64.URLEncoding.EncodeToString(icrypto.RandomBytes(16)),
		Iat:   time.Now().Unix(),
		Data: buildTFAData(t, &r2ps.TFARequestData{
			Protocol: r2ps.TFAModeOPAQUE,
			State:   r2ps.StateFinalize,
			PData: base64.URLEncoding.EncodeToString(record.Serialize()),
		}),
		ClientID: clientID,
		Context:  ctxName,
		Type:     r2ps.Type2FARegistration,
	})

	respBytes, err = d.Process(ctx, body)
	if err != nil {
		t.Fatalf("reg finalize: %v", err)
	}

	// --- Authentication evaluate ---
	authClient, _ := pake.OPAQUEConfig.Client()
	ke1, err := authClient.GenerateKE1([]byte("my-pin-1234"))
	if err != nil {
		t.Fatalf("KE1: %v", err)
	}

	body = buildSignedRequest(t, key, &r2ps.ServiceRequest{
		Ver:   r2ps.ProtocolVersion,
		Nonce: base64.URLEncoding.EncodeToString(icrypto.RandomBytes(16)),
		Iat:   time.Now().Unix(),
		Data: buildTFAData(t, &r2ps.TFARequestData{
			Protocol: r2ps.TFAModeOPAQUE,
			State:   r2ps.StateEvaluate,
			PData: base64.URLEncoding.EncodeToString(ke1.Serialize()),
		}),
		ClientID: clientID,
		Context:  ctxName,
		Type:     r2ps.Type2FAAuthenticate,
	})

	respBytes, err = d.Process(ctx, body)
	if err != nil {
		t.Fatalf("auth evaluate: %v", err)
	}

	// Parse auth evaluate response
	respPayload, _ = icrypto.VerifyJWS(string(respBytes), &key.PublicKey)
	json.Unmarshal(respPayload, &svcResp)
	var tfaAuthResp r2ps.TFAAuthResponseData
	json.Unmarshal(svcResp.Data, &tfaAuthResp)

	sessionID := tfaAuthResp.TFASessionID
	if sessionID == "" {
		t.Fatal("no session ID returned")
	}

	// Client processes KE2
	ke2Bytes, _ := base64.URLEncoding.DecodeString(tfaAuthResp.Response)
	ke2, err := deser.KE2(ke2Bytes)
	if err != nil {
		t.Fatalf("deser KE2: %v", err)
	}

	ke3, _, _, err := authClient.GenerateKE3(ke2, nil, nil)
	if err != nil {
		t.Fatalf("KE3: %v", err)
	}

	// --- Authentication finalize ---
	body = buildSignedRequest(t, key, &r2ps.ServiceRequest{
		Ver:   r2ps.ProtocolVersion,
		Nonce: base64.URLEncoding.EncodeToString(icrypto.RandomBytes(16)),
		Iat:   time.Now().Unix(),
		Data: buildTFAData(t, &r2ps.TFARequestData{
			Protocol: r2ps.TFAModeOPAQUE,
			State:   r2ps.StateFinalize,
			PData: base64.URLEncoding.EncodeToString(ke3.Serialize()),
		}),
		ClientID:     clientID,
		Context:      ctxName,
		Type:         r2ps.Type2FAAuthenticate,
		TFASessionID: sessionID,
	})

	respBytes, err = d.Process(ctx, body)
	if err != nil {
		t.Fatalf("auth finalize: %v", err)
	}

	// --- Service request: keygen ---
	body = buildSignedRequest(t, key, &r2ps.ServiceRequest{
		Ver:          r2ps.ProtocolVersion,
		Nonce:        base64.URLEncoding.EncodeToString(icrypto.RandomBytes(16)),
		Iat:          time.Now().Unix(),
		Data:         json.RawMessage(`{"curve":"P-256"}`),
		ClientID:     clientID,
		Context:      ctxName,
		Type:         r2ps.TypeP256Generate,
		TFASessionID: sessionID,
	})

	respBytes, err = d.Process(ctx, body)
	if err != nil {
		t.Fatalf("keygen service: %v", err)
	}

	// Parse keygen response
	respPayload, _ = icrypto.VerifyJWS(string(respBytes), &key.PublicKey)
	json.Unmarshal(respPayload, &svcResp)

	var keygenResp map[string]string
	if err := json.Unmarshal(svcResp.Data, &keygenResp); err != nil {
		t.Fatalf("unmarshal keygen resp: %v", err)
	}
	if keygenResp["created_key"] == "" {
		t.Error("expected created_key in keygen response")
	}
}

// --- 2FA error cases ---

func TestTFAUnsupportedMode(t *testing.T) {
	d, key, _ := setupDispatcher(t)

	body := buildSignedRequest(t, key, &r2ps.ServiceRequest{
		Ver:   r2ps.ProtocolVersion,
		Nonce: base64.URLEncoding.EncodeToString(icrypto.RandomBytes(16)),
		Iat:   time.Now().Unix(),
		Data: buildTFAData(t, &r2ps.TFARequestData{
			TFAMode: "scram",
			State:   r2ps.StateEvaluate,
			PData: base64.URLEncoding.EncodeToString([]byte("data")),
		}),
		ClientID: "c1",
		Context:  "ctx",
		Type:     r2ps.Type2FARegistration,
	})

	_, err := d.Process(context.Background(), body)
	r2psErr := err.(*R2PSError)
	if r2psErr.Code != r2ps.ErrIllegalRequestData {
		t.Errorf("code = %q, want ILLEGAL_REQUEST_DATA", r2psErr.Code)
	}
}

func TestTFAInvalidStateCombo(t *testing.T) {
	d, key, _ := setupDispatcher(t)

	body := buildSignedRequest(t, key, &r2ps.ServiceRequest{
		Ver:   r2ps.ProtocolVersion,
		Nonce: base64.URLEncoding.EncodeToString(icrypto.RandomBytes(16)),
		Iat:   time.Now().Unix(),
		Data: buildTFAData(t, &r2ps.TFARequestData{
			Protocol: r2ps.TFAModeOPAQUE,
			State:   "unknown_state",
			PData: base64.URLEncoding.EncodeToString([]byte("data")),
		}),
		ClientID: "c1",
		Context:  "ctx",
		Type:     r2ps.Type2FARegistration,
	})

	_, err := d.Process(context.Background(), body)
	r2psErr := err.(*R2PSError)
	if r2psErr.Code != r2ps.ErrIllegalState {
		t.Errorf("code = %q, want ILLEGAL_STATE", r2psErr.Code)
	}
}

func TestAuthEvaluateUnknownClient(t *testing.T) {
	d, key, _ := setupDispatcher(t)

	client, _ := pake.OPAQUEConfig.Client()
	ke1, _ := client.GenerateKE1([]byte("pin"))

	body := buildSignedRequest(t, key, &r2ps.ServiceRequest{
		Ver:   r2ps.ProtocolVersion,
		Nonce: base64.URLEncoding.EncodeToString(icrypto.RandomBytes(16)),
		Iat:   time.Now().Unix(),
		Data: buildTFAData(t, &r2ps.TFARequestData{
			Protocol: r2ps.TFAModeOPAQUE,
			State:   r2ps.StateEvaluate,
			PData: base64.URLEncoding.EncodeToString(ke1.Serialize()),
		}),
		ClientID: "unknown-client",
		Context:  "ctx",
		Type:     r2ps.Type2FAAuthenticate,
	})

	// With fake records, evaluate should succeed (returns KE2)
	resp, err := d.Process(context.Background(), body)
	if err != nil {
		t.Fatalf("expected success with fake record, got error: %v", err)
	}
	if len(resp) == 0 {
		t.Fatal("expected non-empty response")
	}
}

func TestR2PSErrorString(t *testing.T) {
	e := &R2PSError{Code: r2ps.ErrServerError, Msg: "test error"}
	got := e.Error()
	if got != "SERVER_ERROR: test error" {
		t.Errorf("error string = %q", got)
	}
}

func TestProcessIatValidation(t *testing.T) {
	d, key, _ := setupDispatcher(t)

	body := buildSignedRequest(t, key, &r2ps.ServiceRequest{
		Ver:   r2ps.ProtocolVersion,
		Nonce: base64.URLEncoding.EncodeToString(icrypto.RandomBytes(16)),
		Iat:   time.Now().Add(-10 * time.Minute).Unix(),
		Type:  r2ps.TypeP256Generate,
		Data:  json.RawMessage(`{"curve":"P-256"}`),
	})

	_, err := d.Process(context.Background(), body)
	r2psErr := err.(*R2PSError)
	if r2psErr.Code != r2ps.ErrIllegalRequestData {
		t.Errorf("code = %q, want ILLEGAL_REQUEST_DATA", r2psErr.Code)
	}
}

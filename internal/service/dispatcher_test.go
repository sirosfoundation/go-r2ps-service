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
		keys = append(keys, hsm.KeyInfo{Kid: k.kid, Curve: k.curve, PubKey: k.pubKey})
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
		Handlers:    []Handler{NewECDSAHandler(backend), NewECKeygenHandler(backend), NewECDHHandler(backend), NewListKeysHandler(backend)},
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

// --- Record store tests ---

func TestInMemoryRecordStore(t *testing.T) {
	store := NewInMemoryRecordStore()

	_, err := store.GetRecord("client1", "key1")
	if err == nil {
		t.Fatal("expected error for missing record")
	}

	record := &opaque.ClientRecord{CredentialIdentifier: []byte("test")}
	if err := store.PutRecord("client1", "key1", record); err != nil {
		t.Fatalf("put: %v", err)
	}

	got, err := store.GetRecord("client1", "key1")
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

	// Defaults should be applied
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

	// Sign invalid JSON
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
		Type: r2ps.TypeAuthenticate,
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
		Ver:  r2ps.ProtocolVersion,
		Type: "unknown_type",
		Enc:  r2ps.EncUser,
	})

	_, err := d.Process(context.Background(), body)
	r2psErr := err.(*R2PSError)
	if r2psErr.Code != r2ps.ErrUnsupportedType {
		t.Errorf("code = %q, want UNSUPPORTED_REQUEST_TYPE", r2psErr.Code)
	}
}

func TestProcessServiceRequiresUserEnc(t *testing.T) {
	d, key, _ := setupDispatcher(t)

	body := buildSignedRequest(t, key, &r2ps.ServiceRequest{
		Ver:  r2ps.ProtocolVersion,
		Type: r2ps.TypeHSMECKeygen,
		Enc:  r2ps.EncDevice,
	})

	_, err := d.Process(context.Background(), body)
	r2psErr := err.(*R2PSError)
	if r2psErr.Code != r2ps.ErrIllegalRequestData {
		t.Errorf("code = %q, want ILLEGAL_REQUEST_DATA", r2psErr.Code)
	}
}

func TestProcessServiceRequiresSession(t *testing.T) {
	d, key, _ := setupDispatcher(t)

	body := buildSignedRequest(t, key, &r2ps.ServiceRequest{
		Ver:           r2ps.ProtocolVersion,
		Type:          r2ps.TypeHSMECKeygen,
		Enc:           r2ps.EncUser,
		PakeSessionID: "nonexistent",
	})

	_, err := d.Process(context.Background(), body)
	r2psErr := err.(*R2PSError)
	if r2psErr.Code != r2ps.ErrUnauthorized {
		t.Errorf("code = %q, want UNAUTHORIZED", r2psErr.Code)
	}
}

// --- Full PAKE registration + auth + service flow ---

func TestFullProtocolFlow(t *testing.T) {
	d, key, _ := setupDispatcher(t)
	ctx := context.Background()
	clientID := "https://example.com/wallet/1"
	kid := "test-key-1"

	// --- Registration evaluate ---
	client, err := pake.OPAQUEConfig.Client()
	if err != nil {
		t.Fatalf("create OPAQUE client: %v", err)
	}

	regReq, err := client.RegistrationInit([]byte("my-pin-1234"))
	if err != nil {
		t.Fatalf("reg init: %v", err)
	}

	pakeReq := r2ps.PAKERequest{
		Protocol: r2ps.PAKEProtocolOPAQUE,
		State:    r2ps.PAKEStateEvaluate,
		Req:      base64.URLEncoding.EncodeToString(regReq.Serialize()),
	}
	pakeJSON, _ := json.Marshal(pakeReq)
	encData, _ := icrypto.EncryptJWE(pakeJSON, &key.PublicKey)

	body := buildSignedRequest(t, key, &r2ps.ServiceRequest{
		Ver:      r2ps.ProtocolVersion,
		Nonce:    base64.URLEncoding.EncodeToString(icrypto.RandomBytes(16)),
		Iat:      time.Now().Unix(),
		Enc:      r2ps.EncDevice,
		Data:     encData,
		ClientID: clientID,
		Kid:      kid,
		Context:  "test",
		Type:     r2ps.TypePINRegistration,
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
	respData, err := icrypto.DecryptJWE(svcResp.Data, key)
	if err != nil {
		t.Fatalf("decrypt resp: %v", err)
	}
	var pakeResp r2ps.PAKEResponse
	if err := json.Unmarshal(respData, &pakeResp); err != nil {
		t.Fatalf("unmarshal PAKE resp: %v", err)
	}

	// Client finalize registration
	deser, _ := pake.OPAQUEConfig.Deserializer()
	regRespBytes, _ := base64.URLEncoding.DecodeString(pakeResp.Resp)
	regResp, err := deser.RegistrationResponse(regRespBytes)
	if err != nil {
		t.Fatalf("deser reg resp: %v", err)
	}

	record, _, err := client.RegistrationFinalize(regResp, nil, nil)
	if err != nil {
		t.Fatalf("reg finalize: %v", err)
	}

	// --- Registration finalize ---
	pakeReqFin := r2ps.PAKERequest{
		Protocol: r2ps.PAKEProtocolOPAQUE,
		State:    r2ps.PAKEStateFinalize,
		Req:      base64.URLEncoding.EncodeToString(record.Serialize()),
	}
	pakeFinJSON, _ := json.Marshal(pakeReqFin)
	encDataFin, _ := icrypto.EncryptJWE(pakeFinJSON, &key.PublicKey)

	body = buildSignedRequest(t, key, &r2ps.ServiceRequest{
		Ver:      r2ps.ProtocolVersion,
		Nonce:    base64.URLEncoding.EncodeToString(icrypto.RandomBytes(16)),
		Iat:      time.Now().Unix(),
		Enc:      r2ps.EncDevice,
		Data:     encDataFin,
		ClientID: clientID,
		Kid:      kid,
		Context:  "test",
		Type:     r2ps.TypePINRegistration,
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

	pakeAuthReq := r2ps.PAKERequest{
		Protocol: r2ps.PAKEProtocolOPAQUE,
		State:    r2ps.PAKEStateEvaluate,
		Task:     "sign",
		Req:      base64.URLEncoding.EncodeToString(ke1.Serialize()),
	}
	pakeAuthJSON, _ := json.Marshal(pakeAuthReq)
	encDataAuth, _ := icrypto.EncryptJWE(pakeAuthJSON, &key.PublicKey)

	body = buildSignedRequest(t, key, &r2ps.ServiceRequest{
		Ver:      r2ps.ProtocolVersion,
		Nonce:    base64.URLEncoding.EncodeToString(icrypto.RandomBytes(16)),
		Iat:      time.Now().Unix(),
		Enc:      r2ps.EncDevice,
		Data:     encDataAuth,
		ClientID: clientID,
		Kid:      kid,
		Context:  "test",
		Type:     r2ps.TypeAuthenticate,
	})

	respBytes, err = d.Process(ctx, body)
	if err != nil {
		t.Fatalf("auth evaluate: %v", err)
	}

	// Parse auth evaluate response
	respPayload, _ = icrypto.VerifyJWS(string(respBytes), &key.PublicKey)
	json.Unmarshal(respPayload, &svcResp)
	respData, _ = icrypto.DecryptJWE(svcResp.Data, key)
	json.Unmarshal(respData, &pakeResp)

	sessionID := pakeResp.PakeSessionID
	if sessionID == "" {
		t.Fatal("no session ID returned")
	}

	// Client processes KE2
	ke2Bytes, _ := base64.URLEncoding.DecodeString(pakeResp.Resp)
	ke2, err := deser.KE2(ke2Bytes)
	if err != nil {
		t.Fatalf("deser KE2: %v", err)
	}

	ke3, sessionKey, _, err := authClient.GenerateKE3(ke2, nil, nil)
	if err != nil {
		t.Fatalf("KE3: %v", err)
	}

	// --- Authentication finalize ---
	pakeFinAuth := r2ps.PAKERequest{
		Protocol: r2ps.PAKEProtocolOPAQUE,
		State:    r2ps.PAKEStateFinalize,
		Req:      base64.URLEncoding.EncodeToString(ke3.Serialize()),
	}
	pakeFinAuthJSON, _ := json.Marshal(pakeFinAuth)
	encDataFinAuth, _ := icrypto.EncryptJWE(pakeFinAuthJSON, &key.PublicKey)

	body = buildSignedRequest(t, key, &r2ps.ServiceRequest{
		Ver:           r2ps.ProtocolVersion,
		Nonce:         base64.URLEncoding.EncodeToString(icrypto.RandomBytes(16)),
		Iat:           time.Now().Unix(),
		Enc:           r2ps.EncDevice,
		Data:          encDataFinAuth,
		ClientID:      clientID,
		Kid:           kid,
		Context:       "test",
		Type:          r2ps.TypeAuthenticate,
		PakeSessionID: sessionID,
	})

	respBytes, err = d.Process(ctx, body)
	if err != nil {
		t.Fatalf("auth finalize: %v", err)
	}

	// --- Service request: keygen ---
	keygenReq, _ := json.Marshal(map[string]string{"curve": "P-256"})
	encSvcData, _ := icrypto.EncryptJWESymmetric(keygenReq, sessionKey[:32])

	body = buildSignedRequest(t, key, &r2ps.ServiceRequest{
		Ver:           r2ps.ProtocolVersion,
		Nonce:         base64.URLEncoding.EncodeToString(icrypto.RandomBytes(16)),
		Iat:           time.Now().Unix(),
		Enc:           r2ps.EncUser,
		Data:          encSvcData,
		ClientID:      clientID,
		Kid:           kid,
		Context:       "test",
		Type:          r2ps.TypeHSMECKeygen,
		PakeSessionID: sessionID,
	})

	respBytes, err = d.Process(ctx, body)
	if err != nil {
		t.Fatalf("keygen service: %v", err)
	}

	// Parse keygen response
	respPayload, _ = icrypto.VerifyJWS(string(respBytes), &key.PublicKey)
	json.Unmarshal(respPayload, &svcResp)
	if svcResp.Enc != r2ps.EncUser {
		t.Errorf("resp enc = %q, want user", svcResp.Enc)
	}
	svcRespData, err := icrypto.DecryptJWESymmetric(svcResp.Data, sessionKey[:32])
	if err != nil {
		t.Fatalf("decrypt svc resp: %v", err)
	}

	var keygenResp map[string]string
	if err := json.Unmarshal(svcRespData, &keygenResp); err != nil {
		t.Fatalf("unmarshal keygen resp: %v", err)
	}
	if keygenResp["kid"] == "" {
		t.Error("expected kid in keygen response")
	}
}

// --- PAKE error cases ---

func TestPAKEUnsupportedProtocol(t *testing.T) {
	d, key, _ := setupDispatcher(t)

	pakeReq := r2ps.PAKERequest{
		Protocol: "scram",
		State:    r2ps.PAKEStateEvaluate,
		Req:      base64.URLEncoding.EncodeToString([]byte("data")),
	}
	pakeJSON, _ := json.Marshal(pakeReq)
	encData, _ := icrypto.EncryptJWE(pakeJSON, &key.PublicKey)

	body := buildSignedRequest(t, key, &r2ps.ServiceRequest{
		Ver:      r2ps.ProtocolVersion,
		Nonce:    "n1",
		Iat:      time.Now().Unix(),
		Enc:      r2ps.EncDevice,
		Data:     encData,
		ClientID: "c1",
		Kid:      "k1",
		Context:  "ctx",
		Type:     r2ps.TypePINRegistration,
	})

	_, err := d.Process(context.Background(), body)
	r2psErr := err.(*R2PSError)
	if r2psErr.Code != r2ps.ErrIllegalRequestData {
		t.Errorf("code = %q, want ILLEGAL_REQUEST_DATA", r2psErr.Code)
	}
}

func TestPAKEInvalidStateCombo(t *testing.T) {
	d, key, _ := setupDispatcher(t)

	pakeReq := r2ps.PAKERequest{
		Protocol: r2ps.PAKEProtocolOPAQUE,
		State:    "unknown_state",
		Req:      base64.URLEncoding.EncodeToString([]byte("data")),
	}
	pakeJSON, _ := json.Marshal(pakeReq)
	encData, _ := icrypto.EncryptJWE(pakeJSON, &key.PublicKey)

	body := buildSignedRequest(t, key, &r2ps.ServiceRequest{
		Ver:      r2ps.ProtocolVersion,
		Nonce:    "n1",
		Iat:      time.Now().Unix(),
		Enc:      r2ps.EncDevice,
		Data:     encData,
		ClientID: "c1",
		Kid:      "k1",
		Context:  "ctx",
		Type:     r2ps.TypePINRegistration,
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
	pakeReq := r2ps.PAKERequest{
		Protocol: r2ps.PAKEProtocolOPAQUE,
		State:    r2ps.PAKEStateEvaluate,
		Req:      base64.URLEncoding.EncodeToString(ke1.Serialize()),
	}
	pakeJSON, _ := json.Marshal(pakeReq)
	encData, _ := icrypto.EncryptJWE(pakeJSON, &key.PublicKey)

	body := buildSignedRequest(t, key, &r2ps.ServiceRequest{
		Ver:      r2ps.ProtocolVersion,
		Nonce:    "n1",
		Iat:      time.Now().Unix(),
		Enc:      r2ps.EncDevice,
		Data:     encData,
		ClientID: "unknown-client",
		Kid:      "unknown-key",
		Context:  "ctx",
		Type:     r2ps.TypeAuthenticate,
	})

	_, err := d.Process(context.Background(), body)
	r2psErr := err.(*R2PSError)
	if r2psErr.Code != r2ps.ErrUnauthorized {
		t.Errorf("code = %q, want UNAUTHORIZED", r2psErr.Code)
	}
}

func TestR2PSErrorString(t *testing.T) {
	e := &R2PSError{Code: r2ps.ErrServerError, Msg: "test error"}
	got := e.Error()
	if got != "SERVER_ERROR: test error" {
		t.Errorf("error string = %q", got)
	}
}

func TestDecryptRequestDataUnsupportedEnc(t *testing.T) {
	d, _, _ := setupDispatcher(t)
	_, err := d.decryptRequestData(&r2ps.ServiceRequest{Enc: "invalid"})
	if err == nil {
		t.Fatal("expected error for unsupported enc mode")
	}
}

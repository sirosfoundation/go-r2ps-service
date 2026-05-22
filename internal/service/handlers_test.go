package service

import (
	"context"
	"encoding/json"
	"testing"
)

func TestECDSAHandlerType(t *testing.T) {
	h := NewECDSAHandler(newMockBackend())
	if h.Type() != "hsm_ecdsa" {
		t.Errorf("type = %q", h.Type())
	}
}

func TestECDSAHandlerSuccess(t *testing.T) {
	backend := newMockBackend()
	kid, _, _ := backend.GenerateECKey(context.Background(), "P-256")

	h := NewECDSAHandler(backend)
	req, _ := json.Marshal(ECDSASignRequest{
		Kid:     kid,
		TbsHash: encodeBase64(make([]byte, 32)), // SHA-256 hash
	})

	resp, err := h.Handle(context.Background(), "client1", req)
	if err != nil {
		t.Fatalf("handle: %v", err)
	}

	// Spec §3.2: response is raw DER signature bytes.
	if len(resp) == 0 {
		t.Error("empty signature")
	}
}

func TestECDSAHandlerInvalidJSON(t *testing.T) {
	h := NewECDSAHandler(newMockBackend())
	_, err := h.Handle(context.Background(), "c1", []byte("{bad"))
	if err == nil {
		t.Fatal("expected error")
	}
}

func TestECDSAHandlerInvalidKid(t *testing.T) {
	h := NewECDSAHandler(newMockBackend())
	req, _ := json.Marshal(ECDSASignRequest{
		Kid:     "../../etc/passwd",
		TbsHash: encodeBase64(make([]byte, 32)),
	})
	_, err := h.Handle(context.Background(), "c1", req)
	if err == nil {
		t.Fatal("expected error for invalid kid")
	}
}

func TestECDSAHandlerInvalidHash(t *testing.T) {
	h := NewECDSAHandler(newMockBackend())
	req, _ := json.Marshal(ECDSASignRequest{
		Kid:     "validkid",
		TbsHash: encodeBase64(make([]byte, 16)), // wrong length
	})
	_, err := h.Handle(context.Background(), "c1", req)
	if err == nil {
		t.Fatal("expected error for invalid hash length")
	}
}

func TestECDSAHandlerBadBase64(t *testing.T) {
	h := NewECDSAHandler(newMockBackend())
	req, _ := json.Marshal(ECDSASignRequest{
		Kid:     "validkid",
		TbsHash: "not-valid-base64!!!",
	})
	_, err := h.Handle(context.Background(), "c1", req)
	if err == nil {
		t.Fatal("expected error for bad base64")
	}
}

// --- EC Keygen Handler ---

func TestECKeygenHandlerType(t *testing.T) {
	h := NewECKeygenHandler(newMockBackend())
	if h.Type() != "hsm_ec_keygen" {
		t.Errorf("type = %q", h.Type())
	}
}

func TestECKeygenHandlerSuccess(t *testing.T) {
	h := NewECKeygenHandler(newMockBackend())
	req, _ := json.Marshal(ECKeygenRequest{Curve: "P-256"})

	resp, err := h.Handle(context.Background(), "c1", req)
	if err != nil {
		t.Fatalf("handle: %v", err)
	}

	var keygenResp ECKeygenResponse
	if err := json.Unmarshal(resp, &keygenResp); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	if keygenResp.CreatedKey == "" {
		t.Error("empty created_key")
	}
}

func TestECKeygenHandlerInvalidJSON(t *testing.T) {
	h := NewECKeygenHandler(newMockBackend())
	_, err := h.Handle(context.Background(), "c1", []byte("{{"))
	if err == nil {
		t.Fatal("expected error")
	}
}

// --- ECDH Handler ---

func TestECDHHandlerType(t *testing.T) {
	h := NewECDHHandler(newMockBackend())
	if h.Type() != "hsm_ecdh" {
		t.Errorf("type = %q", h.Type())
	}
}

func TestECDHHandlerSuccess(t *testing.T) {
	backend := newMockBackend()
	kid, _, _ := backend.GenerateECKey(context.Background(), "P-256")

	h := NewECDHHandler(backend)
	peerKey := make([]byte, 33)
	peerKey[0] = 0x02
	for i := 1; i < 33; i++ {
		peerKey[i] = byte(i)
	}

	req, _ := json.Marshal(ECDHRequest{
		Kid:       kid,
		PublicKey: encodeBase64(peerKey),
	})

	resp, err := h.Handle(context.Background(), "c1", req)
	if err != nil {
		t.Fatalf("handle: %v", err)
	}

	// Spec §4.2: response is raw shared secret bytes.
	if len(resp) == 0 {
		t.Error("empty shared secret")
	}
}

func TestECDHHandlerInvalidJSON(t *testing.T) {
	h := NewECDHHandler(newMockBackend())
	_, err := h.Handle(context.Background(), "c1", []byte("bad"))
	if err == nil {
		t.Fatal("expected error")
	}
}

func TestECDHHandlerInvalidKid(t *testing.T) {
	h := NewECDHHandler(newMockBackend())
	req, _ := json.Marshal(ECDHRequest{
		Kid:       "bad kid !@#",
		PublicKey: encodeBase64(make([]byte, 33)),
	})
	_, err := h.Handle(context.Background(), "c1", req)
	if err == nil {
		t.Fatal("expected error for invalid kid")
	}
}

func TestECDHHandlerInvalidPeerKeyLength(t *testing.T) {
	h := NewECDHHandler(newMockBackend())
	req, _ := json.Marshal(ECDHRequest{
		Kid:       "validkid",
		PublicKey: encodeBase64(make([]byte, 10)), // wrong length
	})
	_, err := h.Handle(context.Background(), "c1", req)
	if err == nil {
		t.Fatal("expected error for invalid peer key length")
	}
}

func TestECDHHandlerBadPeerKeyBase64(t *testing.T) {
	h := NewECDHHandler(newMockBackend())
	req, _ := json.Marshal(ECDHRequest{
		Kid:       "validkid",
		PublicKey: "!!!bad!!!",
	})
	_, err := h.Handle(context.Background(), "c1", req)
	if err == nil {
		t.Fatal("expected error for bad base64")
	}
}

// --- ListKeys Handler ---

func TestListKeysHandlerType(t *testing.T) {
	h := NewListKeysHandler(newMockBackend())
	if h.Type() != "hsm_list_keys" {
		t.Errorf("type = %q", h.Type())
	}
}

func TestListKeysHandlerSuccess(t *testing.T) {
	backend := newMockBackend()
	backend.GenerateECKey(context.Background(), "P-256")
	backend.GenerateECKey(context.Background(), "P-384")

	h := NewListKeysHandler(backend)
	req, _ := json.Marshal(ListKeysRequest{})

	resp, err := h.Handle(context.Background(), "c1", req)
	if err != nil {
		t.Fatalf("handle: %v", err)
	}

	var listResp ListKeysResponse
	if err := json.Unmarshal(resp, &listResp); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	if len(listResp.KeyInfo) != 2 {
		t.Errorf("keys count = %d, want 2", len(listResp.KeyInfo))
	}
}

func TestListKeysHandlerWithFilter(t *testing.T) {
	backend := newMockBackend()
	backend.GenerateECKey(context.Background(), "P-256")
	backend.GenerateECKey(context.Background(), "P-384")

	h := NewListKeysHandler(backend)
	req, _ := json.Marshal(ListKeysRequest{Curve: []string{"P-256"}})

	resp, err := h.Handle(context.Background(), "c1", req)
	if err != nil {
		t.Fatalf("handle: %v", err)
	}

	var listResp ListKeysResponse
	json.Unmarshal(resp, &listResp)
	if len(listResp.KeyInfo) != 1 {
		t.Errorf("keys count = %d, want 1", len(listResp.KeyInfo))
	}
}

func TestListKeysHandlerInvalidJSON(t *testing.T) {
	h := NewListKeysHandler(newMockBackend())
	_, err := h.Handle(context.Background(), "c1", []byte("{{"))
	if err == nil {
		t.Fatal("expected error")
	}
}

// --- encoding ---

func TestEncoding(t *testing.T) {
	data := []byte("hello")
	encoded := encodeBase64(data)
	decoded, err := decodeBase64(encoded)
	if err != nil {
		t.Fatalf("decode: %v", err)
	}
	if string(decoded) != "hello" {
		t.Errorf("round-trip failed")
	}
}

// --- validateKid ---

func TestValidateKid(t *testing.T) {
	tests := []struct {
		kid   string
		valid bool
	}{
		{"abc123", true},
		{"a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4", true},
		{"my-key_1", true},
		{"", false},
		{"bad kid!", false},
		{"../etc/passwd", false},
		{string(make([]byte, 129)), false},
	}

	for _, tc := range tests {
		err := validateKid(tc.kid)
		if tc.valid && err != nil {
			t.Errorf("validateKid(%q) unexpected error: %v", tc.kid, err)
		}
		if !tc.valid && err == nil {
			t.Errorf("validateKid(%q) expected error", tc.kid)
		}
	}
}

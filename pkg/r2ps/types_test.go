package r2ps

import (
	"encoding/json"
	"testing"
)

func TestServiceRequestMarshal(t *testing.T) {
	req := ServiceRequest{
		Ver:      ProtocolVersion,
		Nonce:    "abc123",
		Iat:      1700000000,
		Enc:      EncDevice,
		Data:     "ZW5jcnlwdGVk",
		ClientID: "https://example.com/wallet/1",
		Kid:      "key1",
		Context:  "hsm",
		Type:     TypeAuthenticate,
	}

	data, err := json.Marshal(req)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}

	var got ServiceRequest
	if err := json.Unmarshal(data, &got); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}

	if got.Ver != req.Ver {
		t.Errorf("ver: got %q, want %q", got.Ver, req.Ver)
	}
	if got.ClientID != req.ClientID {
		t.Errorf("client_id: got %q, want %q", got.ClientID, req.ClientID)
	}
	if got.Type != req.Type {
		t.Errorf("type: got %q, want %q", got.Type, req.Type)
	}
	if got.PakeSessionID != "" {
		t.Errorf("pake_session_id should be omitted, got %q", got.PakeSessionID)
	}
}

func TestServiceRequestPakeSessionID(t *testing.T) {
	req := ServiceRequest{
		Ver:           ProtocolVersion,
		Nonce:         "abc123",
		Iat:           1700000000,
		Enc:           EncDevice,
		Data:          "ZW5jcnlwdGVk",
		ClientID:      "https://example.com/wallet/1",
		Kid:           "key1",
		Context:       "hsm",
		Type:          TypeAuthenticate,
		PakeSessionID: "session-1",
	}

	data, err := json.Marshal(req)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}

	var raw map[string]interface{}
	if err := json.Unmarshal(data, &raw); err != nil {
		t.Fatalf("unmarshal raw: %v", err)
	}

	if _, ok := raw["pake_session_id"]; !ok {
		t.Error("pake_session_id should be present when set")
	}
}

func TestServiceResponseMarshal(t *testing.T) {
	resp := ServiceResponse{
		Ver:   ProtocolVersion,
		Nonce: "abc123",
		Iat:   1700000000,
		Enc:   EncUser,
		Data:  "ZW5jcnlwdGVk",
	}

	data, err := json.Marshal(resp)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}

	var got ServiceResponse
	if err := json.Unmarshal(data, &got); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}

	if got.Enc != EncUser {
		t.Errorf("enc: got %q, want %q", got.Enc, EncUser)
	}
}

func TestPAKERequestMarshal(t *testing.T) {
	req := PAKERequest{
		Protocol: PAKEProtocolOPAQUE,
		State:    PAKEStateEvaluate,
		Req:      "b2xkX3JlcQ==",
	}

	data, err := json.Marshal(req)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}

	var raw map[string]interface{}
	if err := json.Unmarshal(data, &raw); err != nil {
		t.Fatalf("unmarshal raw: %v", err)
	}

	if _, ok := raw["authorization"]; ok {
		t.Error("authorization should be omitted when empty")
	}
	if _, ok := raw["task"]; ok {
		t.Error("task should be omitted when empty")
	}
}

func TestErrorResponseMarshal(t *testing.T) {
	resp := ErrorResponse{
		ErrorCode:    ErrAccessDenied,
		ErrorMessage: "The service type 'hsm_ecdsa' under context 'test' is not supported",
	}

	data, err := json.Marshal(resp)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}

	var got ErrorResponse
	if err := json.Unmarshal(data, &got); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}

	if got.ErrorCode != ErrAccessDenied {
		t.Errorf("error_code: got %q, want %q", got.ErrorCode, ErrAccessDenied)
	}
}

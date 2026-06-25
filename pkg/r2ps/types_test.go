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
		Data:     json.RawMessage(`{"kid":"key1","tbs_hash":"YUHJYg=="}`),
		ClientID: "https://example.com/wallet/1",
		Context:  "hsm",
		Type:     Type2FAAuthenticate,
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
	if got.TFASessionID != "" {
		t.Errorf("2fa_session_id should be omitted, got %q", got.TFASessionID)
	}
}

func TestServiceRequestTFASessionID(t *testing.T) {
	req := ServiceRequest{
		Ver:          ProtocolVersion,
		Nonce:        "abc123",
		Iat:          1700000000,
		Data:         json.RawMessage(`{"kid":"key1"}`),
		ClientID:     "https://example.com/wallet/1",
		Context:      "hsm",
		Type:         TypeSignECDSA,
		TFASessionID: "session-1",
	}

	data, err := json.Marshal(req)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}

	var raw map[string]interface{}
	if err := json.Unmarshal(data, &raw); err != nil {
		t.Fatalf("unmarshal raw: %v", err)
	}

	if _, ok := raw["2fa_session_id"]; !ok {
		t.Error("2fa_session_id should be present when set")
	}
}

func TestServiceResponseMarshal(t *testing.T) {
	resp := ServiceResponse{
		Ver:   ProtocolVersion,
		Nonce: "abc123",
		Iat:   1700000000,
		Data:  json.RawMessage(`{"signature":"MEQCIG..."}`),
	}

	data, err := json.Marshal(resp)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}

	var got ServiceResponse
	if err := json.Unmarshal(data, &got); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}

	if got.Ver != ProtocolVersion {
		t.Errorf("ver: got %q, want %q", got.Ver, ProtocolVersion)
	}
}

func TestTFARequestDataMarshal(t *testing.T) {
	req := TFARequestData{
		Protocol: TFAModeOPAQUE,
		State:    StateEvaluate,
		PData:    "b2xkX3JlcQ==",
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

	// Verify I-D field names are used in serialization
	if _, ok := raw["protocol"]; !ok {
		t.Error("expected 'protocol' field in serialized output")
	}
	if _, ok := raw["p_data"]; !ok {
		t.Error("expected 'p_data' field in serialized output")
	}
}

func TestTFARequestDataGetProtocolFallback(t *testing.T) {
	// Verify GetProtocol() falls back to TFAMode for legacy payloads
	legacy := `{"2fa_mode":"opaque","state":"evaluate","request":"dGVzdA=="}`
	var req TFARequestData
	if err := json.Unmarshal([]byte(legacy), &req); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	if got := req.GetProtocol(); got != TFAModeOPAQUE {
		t.Errorf("GetProtocol() = %q, want %q", got, TFAModeOPAQUE)
	}
	if got := req.GetPData(); got != "dGVzdA==" {
		t.Errorf("GetPData() = %q, want %q", got, "dGVzdA==")
	}
}

func TestTFARequestDataGetProtocolPreference(t *testing.T) {
	// When both protocol and 2fa_mode are set, protocol takes precedence
	both := `{"protocol":"fido2","2fa_mode":"opaque","p_data":"bmV3","request":"b2xk"}`
	var req TFARequestData
	if err := json.Unmarshal([]byte(both), &req); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	if got := req.GetProtocol(); got != TFAModeFIDO2 {
		t.Errorf("GetProtocol() = %q, want %q", got, TFAModeFIDO2)
	}
	if got := req.GetPData(); got != "bmV3" {
		t.Errorf("GetPData() = %q, want %q", got, "bmV3")
	}
}

func TestErrorResponseMarshal(t *testing.T) {
	resp := ErrorResponse{
		ErrorCode:    ErrAccessDenied,
		ErrorMessage: "The service type 'sign_ecdsa' under context 'test' is not supported",
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

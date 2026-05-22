package service

import (
	"context"
	"encoding/json"
	"fmt"
	"regexp"
	"time"

	"github.com/sirosfoundation/go-r2ps-service/internal/hsm"
	"github.com/sirosfoundation/go-r2ps-service/pkg/r2ps"
)

var validKid = regexp.MustCompile(`^[a-zA-Z0-9_-]{1,128}$`)

func validateKid(kid string) error {
	if !validKid.MatchString(kid) {
		return fmt.Errorf("invalid kid format")
	}
	return nil
}

// --- HSM ECDSA Sign Handler ---

// ECDSASignRequest matches spec §3.2: { "kid": "...", "tbs_hash": "..." }
type ECDSASignRequest struct {
	Kid     string `json:"kid"`
	TbsHash string `json:"tbs_hash"` // base64-encoded hash to sign
}

// ECDSASignResponse: spec §3.2 says response is raw DER signature bytes (not JSON).

type ECDSAHandler struct {
	backend hsm.Backend
}

func NewECDSAHandler(backend hsm.Backend) *ECDSAHandler {
	return &ECDSAHandler{backend: backend}
}

func (h *ECDSAHandler) Type() string { return r2ps.TypeHSMECDSA }

func (h *ECDSAHandler) Handle(ctx context.Context, _ string, reqData []byte) ([]byte, error) {
	start := time.Now()
	var req ECDSASignRequest
	if err := json.Unmarshal(reqData, &req); err != nil {
		return nil, fmt.Errorf("parse sign request: %w", err)
	}

	hashBytes, err := decodeBase64(req.TbsHash)
	if err != nil {
		return nil, fmt.Errorf("decode tbs_hash: %w", err)
	}

	if err := validateKid(req.Kid); err != nil {
		return nil, err
	}

	// Validate hash length: 32 (SHA-256), 48 (SHA-384), or 64 (SHA-512)
	if len(hashBytes) != 32 && len(hashBytes) != 48 && len(hashBytes) != 64 {
		return nil, fmt.Errorf("invalid hash length: %d", len(hashBytes))
	}

	sig, err := h.backend.Sign(ctx, req.Kid, hashBytes)
	HSMOperationDuration.WithLabelValues("sign").Observe(time.Since(start).Seconds())
	if err != nil {
		HSMOperationsTotal.WithLabelValues("sign", "error").Inc()
		return nil, fmt.Errorf("sign: %w", err)
	}
	HSMOperationsTotal.WithLabelValues("sign", "success").Inc()

	// Spec §3.2: response payload is raw DER signature bytes.
	return sig, nil
}

// --- HSM EC Keygen Handler ---

type ECKeygenRequest struct {
	Curve string `json:"curve"`
}

// ECKeygenResponse matches spec §1.2: { "created_key": "P-256" }
type ECKeygenResponse struct {
	CreatedKey string `json:"created_key"` // curve name confirming key creation
}

type ECKeygenHandler struct {
	backend hsm.Backend
}

func NewECKeygenHandler(backend hsm.Backend) *ECKeygenHandler {
	return &ECKeygenHandler{backend: backend}
}

func (h *ECKeygenHandler) Type() string { return r2ps.TypeHSMECKeygen }

func (h *ECKeygenHandler) Handle(ctx context.Context, _ string, reqData []byte) ([]byte, error) {
	start := time.Now()
	var req ECKeygenRequest
	if err := json.Unmarshal(reqData, &req); err != nil {
		return nil, fmt.Errorf("parse keygen request: %w", err)
	}

	kid, pubKey, err := h.backend.GenerateECKey(ctx, req.Curve)
	HSMOperationDuration.WithLabelValues("keygen").Observe(time.Since(start).Seconds())
	if err != nil {
		HSMOperationsTotal.WithLabelValues("keygen", "error").Inc()
		return nil, fmt.Errorf("keygen: %w", err)
	}
	HSMOperationsTotal.WithLabelValues("keygen", "success").Inc()
	_ = kid    // kid available via list_keys
	_ = pubKey // public key available via list_keys

	// Spec §1.2: response confirms the curve for which a key was created.
	resp := ECKeygenResponse{
		CreatedKey: req.Curve,
	}
	return json.Marshal(resp)
}

// --- HSM ECDH Handler ---

// ECDHRequest matches spec §4.2: { "kid": "...", "public_key": "..." }
type ECDHRequest struct {
	Kid       string `json:"kid"`
	PublicKey string `json:"public_key"` // SPKI DER-encoded peer public key (base64)
}

// ECDHResponse: spec §4.2 says response is raw shared secret bytes (not JSON).

type ECDHHandler struct {
	backend hsm.Backend
}

func NewECDHHandler(backend hsm.Backend) *ECDHHandler {
	return &ECDHHandler{backend: backend}
}

func (h *ECDHHandler) Type() string { return r2ps.TypeHSMECDH }

func (h *ECDHHandler) Handle(ctx context.Context, _ string, reqData []byte) ([]byte, error) {
	start := time.Now()
	var req ECDHRequest
	if err := json.Unmarshal(reqData, &req); err != nil {
		return nil, fmt.Errorf("parse ECDH request: %w", err)
	}

	peerKey, err := decodeBase64(req.PublicKey)
	if err != nil {
		return nil, fmt.Errorf("decode public_key: %w", err)
	}

	if err := validateKid(req.Kid); err != nil {
		return nil, err
	}

	// Validate peer public key length: 33 (compressed) or 65 (uncompressed) for P-256
	if len(peerKey) != 33 && len(peerKey) != 65 && len(peerKey) != 49 && len(peerKey) != 97 && len(peerKey) != 67 && len(peerKey) != 133 {
		return nil, fmt.Errorf("invalid peer public key length")
	}

	secret, err := h.backend.ECDH(ctx, req.Kid, peerKey)
	HSMOperationDuration.WithLabelValues("ecdh").Observe(time.Since(start).Seconds())
	if err != nil {
		HSMOperationsTotal.WithLabelValues("ecdh", "error").Inc()
		return nil, fmt.Errorf("ECDH: %w", err)
	}
	HSMOperationsTotal.WithLabelValues("ecdh", "success").Inc()

	// Spec §4.2: response payload is raw shared secret bytes.
	return secret, nil
}

// --- HSM List Keys Handler ---

// ListKeysRequest matches spec §2.2: { "curve": ["P-256"] }
type ListKeysRequest struct {
	Curve []string `json:"curve"`
}

// WireKeyInfo is the spec §2.2 key_info entry.
type WireKeyInfo struct {
	Kid          string `json:"kid"`
	CurveName    string `json:"curve_name"`
	CreationTime int64  `json:"creation_time"`
	PublicKey    string `json:"public_key"` // SPKI DER base64
}

// ListKeysResponse matches spec §2.2: { "key_info": [...] }
type ListKeysResponse struct {
	KeyInfo []WireKeyInfo `json:"key_info"`
}

type ListKeysHandler struct {
	backend hsm.Backend
}

func NewListKeysHandler(backend hsm.Backend) *ListKeysHandler {
	return &ListKeysHandler{backend: backend}
}

func (h *ListKeysHandler) Type() string { return r2ps.TypeHSMListKeys }

func (h *ListKeysHandler) Handle(ctx context.Context, _ string, reqData []byte) ([]byte, error) {
	start := time.Now()
	var req ListKeysRequest
	if err := json.Unmarshal(reqData, &req); err != nil {
		return nil, fmt.Errorf("parse list keys request: %w", err)
	}

	keys, err := h.backend.ListKeys(ctx, req.Curve)
	HSMOperationDuration.WithLabelValues("list_keys").Observe(time.Since(start).Seconds())
	if err != nil {
		HSMOperationsTotal.WithLabelValues("list_keys", "error").Inc()
		return nil, fmt.Errorf("list keys: %w", err)
	}
	HSMOperationsTotal.WithLabelValues("list_keys", "success").Inc()

	// Convert internal KeyInfo to spec-compliant wire format.
	wireKeys := make([]WireKeyInfo, len(keys))
	for i, k := range keys {
		wireKeys[i] = WireKeyInfo{
			Kid:          k.Kid,
			CurveName:    k.Curve,
			CreationTime: k.CreationTime,
			PublicKey:    encodeBase64(k.PubKey),
		}
	}

	resp := ListKeysResponse{KeyInfo: wireKeys}
	return json.Marshal(resp)
}

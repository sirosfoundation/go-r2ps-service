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

type ECDSASignRequest struct {
	Kid  string `json:"kid"`
	Hash string `json:"hash"` // base64url-encoded hash to sign
}

type ECDSASignResponse struct {
	Signature string `json:"signature"` // base64url-encoded ASN.1 DER signature
}

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

	hashBytes, err := decodeBase64(req.Hash)
	if err != nil {
		return nil, fmt.Errorf("decode hash: %w", err)
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

	resp := ECDSASignResponse{
		Signature: encodeBase64(sig),
	}
	return json.Marshal(resp)
}

// --- HSM EC Keygen Handler ---

type ECKeygenRequest struct {
	Curve string `json:"curve"`
}

type ECKeygenResponse struct {
	Kid    string `json:"kid"`
	PubKey string `json:"pub_key"` // base64url-encoded compressed public key
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

	resp := ECKeygenResponse{
		Kid:    kid,
		PubKey: encodeBase64(pubKey),
	}
	return json.Marshal(resp)
}

// --- HSM ECDH Handler ---

type ECDHRequest struct {
	Kid        string `json:"kid"`
	PeerPubKey string `json:"peer_pub_key"` // base64url-encoded peer public key
}

type ECDHResponse struct {
	SharedSecret string `json:"shared_secret"` // base64url-encoded shared secret
}

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

	peerKey, err := decodeBase64(req.PeerPubKey)
	if err != nil {
		return nil, fmt.Errorf("decode peer key: %w", err)
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

	resp := ECDHResponse{
		SharedSecret: encodeBase64(secret),
	}
	return json.Marshal(resp)
}

// --- HSM List Keys Handler ---

type ListKeysRequest struct {
	Curves []string `json:"curves,omitempty"`
}

type ListKeysResponse struct {
	Keys []hsm.KeyInfo `json:"keys"`
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

	keys, err := h.backend.ListKeys(ctx, req.Curves)
	HSMOperationDuration.WithLabelValues("list_keys").Observe(time.Since(start).Seconds())
	if err != nil {
		HSMOperationsTotal.WithLabelValues("list_keys", "error").Inc()
		return nil, fmt.Errorf("list keys: %w", err)
	}
	HSMOperationsTotal.WithLabelValues("list_keys", "success").Inc()

	resp := ListKeysResponse{Keys: keys}
	return json.Marshal(resp)
}

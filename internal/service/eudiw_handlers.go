package service

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"log/slog"
	"os"
	"time"

	"github.com/sirosfoundation/go-r2ps-service/internal/audit"
	icrypto "github.com/sirosfoundation/go-r2ps-service/internal/crypto"
	"github.com/sirosfoundation/go-r2ps-service/internal/hsm"
	"github.com/sirosfoundation/go-r2ps-service/internal/store"
	"github.com/sirosfoundation/go-r2ps-service/pkg/r2ps"
)

// WalletProviderConfig holds the Wallet Provider's attestation-signing
// material and metadata, shared by the WKA and WIA handlers.
type WalletProviderConfig struct {
	// SigningKey is the Wallet Provider's private key used to sign WKA/WIA JWTs.
	SigningKey *ecdsa.PrivateKey
	// X5CChain is the DER-encoded certificate chain (leaf first) for the x5c header.
	X5CChain [][]byte
	// WalletLink is the SHOULD-level wallet_link URL (TS-03 clause 2.3.1).
	WalletLink string
	// WalletName is the wallet product name (TS-03 clause 2.3.1).
	WalletName string
	// WalletVersion is the wallet product version string (TS-03 clause 2.3.1).
	WalletVersion string
	// WalletSolutionCertificationInfo is the certification body / scheme info (TS-03 clause 2.3.1).
	WalletSolutionCertificationInfo interface{}
	// KeyStorageLevel is the ISO 18045 AVA_VAN level for key_storage (TS-03 clause 2.3.2).
	KeyStorageLevel []string
	// UserAuthLevel is the ISO 18045 AVA_VAN level for user_authentication (TS-03 clause 2.3.2).
	UserAuthLevel []string
	// Certification is the WSCD certification URI / object (TS-03 clause 2.3.2).
	Certification string
	// StatusListBaseURI is the base URI for status list endpoints.
	StatusListBaseURI string
	// WKA TTL (exp - iat). CS-04 does not mandate <24h for KA; default 24h.
	WKATTL time.Duration
	// WIA TTL (exp - iat). CS-04 §7.1: MUST be less than 24 hours.
	WIATTL time.Duration
	// StatusMaintenancePeriod is the minimum client_status.exp / key_storage_status.exp
	// ahead of presentation time. CS-04 §7.2: at least 31 days.
	StatusMaintenancePeriod time.Duration
	// Store provides persistent status list index allocation and status tracking.
	// If nil, a no-op default is used (status indices start at 0, no persistence).
	Store store.Store
	// Audit is the audit logger. If nil, audit events are not emitted.
	Audit *audit.Logger
}

// --- WKA Handler ---

// WKAHandler produces Wallet Key Attestation JWTs per CS-04 / TS-03 clause 2.3.2.
type WKAHandler struct {
	backend hsm.Backend
	cfg     *WalletProviderConfig
}

func NewWKAHandler(backend hsm.Backend, cfg *WalletProviderConfig) *WKAHandler {
	return &WKAHandler{backend: backend, cfg: cfg}
}

func (h *WKAHandler) Type() string { return r2ps.TypeEUDIWWKAETSI }

func (h *WKAHandler) Handle(ctx context.Context, clientID string, reqData []byte) ([]byte, error) {
	var req r2ps.EUDIWAttestationRequest
	if err := json.Unmarshal(reqData, &req); err != nil {
		return nil, fmt.Errorf("parse WKA request: %w", err)
	}

	if req.Ver != "draft-008" {
		return nil, fmt.Errorf("unsupported ETSI version: %s", req.Ver)
	}
	if len(req.KeysToAttest) == 0 {
		return nil, fmt.Errorf("keys_to_attest must not be empty")
	}

	// Resolve each kid to its public key JWK via the HSM backend.
	attestedKeys := make([]json.RawMessage, 0, len(req.KeysToAttest))
	for _, kid := range req.KeysToAttest {
		if err := validateKid(kid); err != nil {
			return nil, fmt.Errorf("invalid kid %q: %w", kid, err)
		}
		jwk, err := h.resolveKeyJWK(ctx, kid)
		if err != nil {
			// CS-04 §7.1 / spec: MUST NOT include invalid keys — skip silently.
			continue
		}
		attestedKeys = append(attestedKeys, jwk)
	}
	if len(attestedKeys) == 0 {
		return nil, fmt.Errorf("no valid keys to attest")
	}

	now := time.Now()
	ttl := h.cfg.WKATTL
	if ttl == 0 {
		ttl = 24 * time.Hour
	}
	statusMaint := h.cfg.StatusMaintenancePeriod
	if statusMaint == 0 {
		statusMaint = 31 * 24 * time.Hour // CS-04 §7.2: at least 31 days
	}

	idx, err := h.cfg.Store.AllocateIndex("ka")
	if err != nil {
		return nil, fmt.Errorf("allocate status index: %w", err)
	}
	if err := h.cfg.Store.RecordWUA(clientID, "ka", idx); err != nil {
		return nil, fmt.Errorf("record WUA: %w", err)
	}

	payload := r2ps.WKAPayload{
		Iat:                now.Unix(),
		Exp:                now.Add(ttl).Unix(),
		AttestedKeys:       attestedKeys,
		KeyStorage:         h.cfg.KeyStorageLevel,
		UserAuthentication: h.cfg.UserAuthLevel,
		Certification:      h.cfg.Certification,
		WalletLink:         h.cfg.WalletLink,
		KeyStorageStatus: r2ps.StatusObject{
			Status: r2ps.StatusListStatus{
				StatusList: r2ps.StatusListRef{
					Idx: idx,
					URI: h.cfg.StatusListBaseURI + "/ka/" + fmt.Sprintf("%d", idx/1000),
				},
			},
			Exp: now.Add(statusMaint).Unix(),
		},
	}

	payloadJSON, err := json.Marshal(payload)
	if err != nil {
		return nil, fmt.Errorf("marshal WKA payload: %w", err)
	}

	jwt, err := icrypto.SignJWT(payloadJSON, h.cfg.SigningKey, "keyattestation+jwt", h.cfg.X5CChain)
	if err != nil {
		return nil, fmt.Errorf("sign WKA JWT: %w", err)
	}

	resp := r2ps.WKAResponse{WKA: jwt}
	if h.cfg.Audit != nil {
		h.cfg.Audit.Log(audit.EventWKAIssued, clientID, "wua",
			slog.Int("status_idx", idx),
			slog.Int("attested_keys", len(attestedKeys)))
	}
	return json.Marshal(resp)
}

// resolveKeyJWK looks up a key by kid from the HSM and returns its JWK JSON.
func (h *WKAHandler) resolveKeyJWK(ctx context.Context, kid string) (json.RawMessage, error) {
	keys, err := h.backend.ListKeys(ctx, nil)
	if err != nil {
		return nil, fmt.Errorf("list keys: %w", err)
	}

	for _, k := range keys {
		if k.Kid == kid {
			return pubKeyToJWK(k.PubKey, k.Curve)
		}
	}
	return nil, fmt.Errorf("key %q not found", kid)
}

// --- WIA Handler ---

// WIAHandler produces Wallet Instance Attestation JWTs per CS-04 / TS-03 clause 2.3.1.
type WIAHandler struct {
	backend hsm.Backend
	cfg     *WalletProviderConfig
}

func NewWIAHandler(backend hsm.Backend, cfg *WalletProviderConfig) *WIAHandler {
	return &WIAHandler{backend: backend, cfg: cfg}
}

func (h *WIAHandler) Type() string { return r2ps.TypeEUDIWWIAETSI }

func (h *WIAHandler) Handle(ctx context.Context, clientID string, reqData []byte) ([]byte, error) {
	var req r2ps.EUDIWAttestationRequest
	if err := json.Unmarshal(reqData, &req); err != nil {
		return nil, fmt.Errorf("parse WIA request: %w", err)
	}

	if req.Ver != "draft-008" {
		return nil, fmt.Errorf("unsupported ETSI version: %s", req.Ver)
	}
	if len(req.KeysToAttest) == 0 {
		return nil, fmt.Errorf("keys_to_attest must not be empty")
	}

	// Resolve the first key as the cnf key (DPoP key for the WIA).
	cnfKid := req.KeysToAttest[0]
	if err := validateKid(cnfKid); err != nil {
		return nil, fmt.Errorf("invalid kid %q: %w", cnfKid, err)
	}
	cnfJWK, err := h.resolveKeyJWK(ctx, cnfKid)
	if err != nil {
		return nil, fmt.Errorf("resolve cnf key: %w", err)
	}

	now := time.Now()
	ttl := h.cfg.WIATTL
	if ttl == 0 {
		ttl = 12 * time.Hour // CS-04 §7.1: MUST be less than 24 hours
	}
	statusMaint := h.cfg.StatusMaintenancePeriod
	if statusMaint == 0 {
		statusMaint = 31 * 24 * time.Hour
	}

	idx, err := h.cfg.Store.AllocateIndex("wia")
	if err != nil {
		return nil, fmt.Errorf("allocate status index: %w", err)
	}
	if err := h.cfg.Store.RecordWUA(clientID, "wia", idx); err != nil {
		return nil, fmt.Errorf("record WUA: %w", err)
	}

	payload := r2ps.WIAPayload{
		Iat:                                    now.Unix(),
		Exp:                                    now.Add(ttl).Unix(),
		Sub:                                    clientID,
		WalletName:                             h.cfg.WalletName,
		WalletVersion:                          h.cfg.WalletVersion,
		WalletSolutionCertificationInformation: h.cfg.WalletSolutionCertificationInfo,
		WalletLink:                             h.cfg.WalletLink,
		ClientStatus: r2ps.StatusObject{
			Status: r2ps.StatusListStatus{
				StatusList: r2ps.StatusListRef{
					Idx: idx,
					URI: h.cfg.StatusListBaseURI + "/wia/" + fmt.Sprintf("%d", idx/1000),
				},
			},
			Exp: now.Add(statusMaint).Unix(),
		},
		Cnf: r2ps.CnfClaim{JWK: cnfJWK},
	}

	payloadJSON, err := json.Marshal(payload)
	if err != nil {
		return nil, fmt.Errorf("marshal WIA payload: %w", err)
	}

	jwt, err := icrypto.SignJWT(payloadJSON, h.cfg.SigningKey, "oauth-client-attestation+jwt", h.cfg.X5CChain)
	if err != nil {
		return nil, fmt.Errorf("sign WIA JWT: %w", err)
	}

	resp := r2ps.WIAResponse{WIA: jwt}
	if h.cfg.Audit != nil {
		h.cfg.Audit.Log(audit.EventWIAIssued, clientID, "wua",
			slog.Int("status_idx", idx))
	}
	return json.Marshal(resp)
}

// resolveKeyJWK looks up a key by kid from the HSM and returns its JWK JSON.
func (h *WIAHandler) resolveKeyJWK(ctx context.Context, kid string) (json.RawMessage, error) {
	keys, err := h.backend.ListKeys(ctx, nil)
	if err != nil {
		return nil, fmt.Errorf("list keys: %w", err)
	}

	for _, k := range keys {
		if k.Kid == kid {
			return pubKeyToJWK(k.PubKey, k.Curve)
		}
	}
	return nil, fmt.Errorf("key %q not found", kid)
}

// pubKeyToJWK converts an EC point (compressed or uncompressed) to a JWK JSON representation.
func pubKeyToJWK(ecPoint []byte, curve string) (json.RawMessage, error) {
	crv := ""
	byteLen := 0
	var ecCurve elliptic.Curve
	switch curve {
	case "P-256":
		crv = "P-256"
		byteLen = 32
		ecCurve = elliptic.P256()
	case "P-384":
		crv = "P-384"
		byteLen = 48
		ecCurve = elliptic.P384()
	case "P-521":
		crv = "P-521"
		byteLen = 66
		ecCurve = elliptic.P521()
	default:
		return nil, fmt.Errorf("unsupported curve: %s", curve)
	}

	var xBytes, yBytes []byte

	if len(ecPoint) > 0 && ecPoint[0] == 0x04 {
		// Uncompressed: 0x04 || x || y
		if len(ecPoint) != 1+2*byteLen {
			return nil, fmt.Errorf("invalid uncompressed EC point: length %d", len(ecPoint))
		}
		xBytes = ecPoint[1 : 1+byteLen]
		yBytes = ecPoint[1+byteLen:]
	} else if len(ecPoint) > 0 && (ecPoint[0] == 0x02 || ecPoint[0] == 0x03) {
		// Compressed
		x, y := elliptic.UnmarshalCompressed(ecCurve, ecPoint) //nolint:staticcheck
		if x == nil {
			return nil, fmt.Errorf("invalid compressed EC point")
		}
		xBytes = x.Bytes()
		yBytes = y.Bytes()
		// Pad to full length
		for len(xBytes) < byteLen {
			xBytes = append([]byte{0}, xBytes...)
		}
		for len(yBytes) < byteLen {
			yBytes = append([]byte{0}, yBytes...)
		}
	} else {
		return nil, fmt.Errorf("invalid EC point prefix: 0x%02x (length %d)", ecPoint[0], len(ecPoint))
	}

	jwkJSON := fmt.Sprintf(`{"kty":"EC","crv":"%s","x":"%s","y":"%s"}`,
		crv,
		base64.RawURLEncoding.EncodeToString(xBytes),
		base64.RawURLEncoding.EncodeToString(yBytes),
	)

	return json.RawMessage(jwkJSON), nil
}

// --- WI Revoke Handler ---

// WIRevokeHandler revokes all status list entries for a wallet instance.
// CS-04 §7.2 req 8-9: on revocation, revoke all client_status entries.
type WIRevokeHandler struct {
	cfg *WalletProviderConfig
}

func NewWIRevokeHandler(cfg *WalletProviderConfig) *WIRevokeHandler {
	return &WIRevokeHandler{cfg: cfg}
}

func (h *WIRevokeHandler) Type() string { return r2ps.TypeEUDIWWIRevoke }

func (h *WIRevokeHandler) Handle(_ context.Context, clientID string, reqData []byte) ([]byte, error) {
	var req r2ps.WIRevokeRequest
	if err := json.Unmarshal(reqData, &req); err != nil {
		return nil, fmt.Errorf("parse revoke request: %w", err)
	}

	count, err := h.revokeAll(clientID, store.StatusInvalid)
	if err != nil {
		return nil, fmt.Errorf("revoke wallet instance: %w", err)
	}

	if h.cfg.Audit != nil {
		h.cfg.Audit.Log(audit.EventWIRevoked, clientID, "wua",
			slog.String("reason", req.Reason),
			slog.Int("revoked_indices", count))
	}

	resp := r2ps.WIRevokeResponse{
		RevokedIndices: count,
		Message:        "wallet instance revoked",
	}
	return json.Marshal(resp)
}

func (h *WIRevokeHandler) revokeAll(clientID string, status byte) (int, error) {
	count := 0
	for _, cat := range []string{"ka", "wia"} {
		indices, err := h.cfg.Store.GetClientIndices(clientID, cat)
		if err != nil {
			return count, fmt.Errorf("get indices for %s: %w", cat, err)
		}
		for _, idx := range indices {
			if err := h.cfg.Store.SetStatus(cat, idx, status); err != nil {
				slog.Warn("failed to set status", "category", cat, "idx", idx, "error", err)
				continue
			}
			count++
		}
	}
	return count, nil
}

// --- WI Suspend Handler ---

// WISuspendHandler suspends all status list entries for a wallet instance.
type WISuspendHandler struct {
	cfg *WalletProviderConfig
}

func NewWISuspendHandler(cfg *WalletProviderConfig) *WISuspendHandler {
	return &WISuspendHandler{cfg: cfg}
}

func (h *WISuspendHandler) Type() string { return r2ps.TypeEUDIWWISuspend }

func (h *WISuspendHandler) Handle(_ context.Context, clientID string, reqData []byte) ([]byte, error) {
	var req r2ps.WISuspendRequest
	if err := json.Unmarshal(reqData, &req); err != nil {
		return nil, fmt.Errorf("parse suspend request: %w", err)
	}

	count := 0
	for _, cat := range []string{"ka", "wia"} {
		indices, err := h.cfg.Store.GetClientIndices(clientID, cat)
		if err != nil {
			return nil, fmt.Errorf("get indices for %s: %w", cat, err)
		}
		for _, idx := range indices {
			if err := h.cfg.Store.SetStatus(cat, idx, store.StatusSuspended); err != nil {
				slog.Warn("failed to suspend", "category", cat, "idx", idx, "error", err)
				continue
			}
			count++
		}
	}

	if h.cfg.Audit != nil {
		h.cfg.Audit.Log(audit.EventWISuspended, clientID, "wua",
			slog.String("reason", req.Reason),
			slog.Int("suspended_indices", count))
	}

	resp := r2ps.WISuspendResponse{
		SuspendedIndices: count,
		Message:          "wallet instance suspended",
	}
	return json.Marshal(resp)
}

// --- x5c certificate chain loading ---

// LoadX5CChain reads a PEM file containing one or more certificates
// and returns them as DER-encoded byte slices (leaf first).
func LoadX5CChain(path string) ([][]byte, error) {
	if path == "" {
		return nil, nil
	}

	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("read x5c file: %w", err)
	}

	var chain [][]byte
	rest := data
	for {
		var block *pem.Block
		block, rest = pem.Decode(rest)
		if block == nil {
			break
		}
		if block.Type == "CERTIFICATE" {
			chain = append(chain, block.Bytes)
		}
	}
	if len(chain) == 0 {
		return nil, fmt.Errorf("no certificates found in PEM file %s", path)
	}
	return chain, nil
}

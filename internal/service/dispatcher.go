package service

import (
	"context"
	"crypto/ecdsa"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"log/slog"
	"time"

	icrypto "github.com/sirosfoundation/go-r2ps-service/internal/crypto"
	"github.com/sirosfoundation/go-r2ps-service/internal/pake"
	"github.com/sirosfoundation/go-r2ps-service/pkg/r2ps"

	"github.com/bytemare/opaque"
)

// RecordStore abstracts persistence of OPAQUE client records.
type RecordStore interface {
	GetRecord(clientID, context string) (*opaque.ClientRecord, error)
	PutRecord(clientID, context string, record *opaque.ClientRecord) error
}

// ClientKeyStore resolves a client's public key by kid (JWK thumbprint of CSK).
type ClientKeyStore interface {
	GetClientKey(kid string) (*ecdsa.PublicKey, error)
}

// InMemoryRecordStore is a test/dev record store.
type InMemoryRecordStore struct {
	records map[string]*opaque.ClientRecord
}

func NewInMemoryRecordStore() *InMemoryRecordStore {
	return &InMemoryRecordStore{records: make(map[string]*opaque.ClientRecord)}
}

func (s *InMemoryRecordStore) GetRecord(clientID, ctx string) (*opaque.ClientRecord, error) {
	r, ok := s.records[clientID+"|"+ctx]
	if !ok {
		return nil, fmt.Errorf("no record for %s/%s", clientID, ctx)
	}
	return r, nil
}

func (s *InMemoryRecordStore) PutRecord(clientID, ctx string, record *opaque.ClientRecord) error {
	s.records[clientID+"|"+ctx] = record
	return nil
}

// Dispatcher processes R2PS requests: verifies JWS, routes to 2FA or service handlers.
type Dispatcher struct {
	serverKey  *ecdsa.PrivateKey
	opaque     *pake.OPAQUEServer
	sessions   *pake.SessionStore
	counter    *pake.AttemptCounter
	records    RecordStore
	clientKeys ClientKeyStore
	handlers   map[string]Handler
	sessionTTL time.Duration
	iatMaxSkew time.Duration
}

// DispatcherConfig holds initialization parameters.
type DispatcherConfig struct {
	ServerKey   *ecdsa.PrivateKey
	OPAQUEKey   *pake.ServerKeyMaterial
	Records     RecordStore
	ClientKeys  ClientKeyStore // optional; if nil, server key is used for JWS verification
	Handlers    []Handler
	MaxAttempts int
	LockoutDur  time.Duration
	SessionTTL  time.Duration
	IatMaxSkew  time.Duration // max clock skew for iat validation; 0 = 5 minutes
}

// NewDispatcher creates a fully wired dispatcher.
func NewDispatcher(cfg DispatcherConfig) (*Dispatcher, error) {
	opaqueServer, err := pake.NewOPAQUEServer(cfg.OPAQUEKey)
	if err != nil {
		return nil, fmt.Errorf("create OPAQUE server: %w", err)
	}

	maxAttempts := cfg.MaxAttempts
	if maxAttempts == 0 {
		maxAttempts = 5
	}
	lockout := cfg.LockoutDur
	if lockout == 0 {
		lockout = 15 * time.Minute
	}
	sessionTTL := cfg.SessionTTL
	if sessionTTL == 0 {
		sessionTTL = 5 * time.Minute
	}

	hMap := make(map[string]Handler, len(cfg.Handlers))
	for _, h := range cfg.Handlers {
		hMap[h.Type()] = h
	}

	iatMaxSkew := cfg.IatMaxSkew
	if iatMaxSkew == 0 {
		iatMaxSkew = 5 * time.Minute
	}

	return &Dispatcher{
		serverKey:  cfg.ServerKey,
		opaque:     opaqueServer,
		sessions:   pake.NewSessionStore(),
		counter:    pake.NewAttemptCounter(maxAttempts, lockout),
		records:    cfg.Records,
		clientKeys: cfg.ClientKeys,
		handlers:   hMap,
		sessionTTL: sessionTTL,
		iatMaxSkew: iatMaxSkew,
	}, nil
}

// StartSessionCleanup runs a background goroutine that periodically removes expired sessions.
func (d *Dispatcher) StartSessionCleanup(interval time.Duration) {
	go func() {
		ticker := time.NewTicker(interval)
		defer ticker.Stop()
		for range ticker.C {
			count := d.sessions.CleanExpired()
			if count > 0 {
				slog.Debug("cleaned expired sessions", "count", count)
				ActiveSessions.Sub(float64(count))
			}
		}
	}()
}

// Process handles a raw R2PS request body (JWS compact serialization, already
// decrypted from the outer JWE at the transport layer).
// Returns a JWS compact serialization response or an error response.
func (d *Dispatcher) Process(ctx context.Context, body []byte) ([]byte, error) {
	// Look up the verification key using the JWS kid header.
	pubKey := &d.serverKey.PublicKey // default: server key (dev/test)
	if d.clientKeys != nil {
		headers, err := icrypto.PeekJWSHeaders(string(body))
		if err != nil {
			return nil, &R2PSError{Code: r2ps.ErrIllegalRequestData, Msg: "invalid JWS header"}
		}
		if kid, ok := headers["kid"].(string); ok && kid != "" {
			if pk, err := d.clientKeys.GetClientKey(kid); err == nil {
				pubKey = pk
			}
		}
	}

	payload, err := icrypto.VerifyJWS(string(body), pubKey)
	if err != nil {
		return nil, &R2PSError{Code: r2ps.ErrIllegalRequestData, Msg: "invalid JWS"}
	}

	var req r2ps.ServiceRequest
	if err := json.Unmarshal(payload, &req); err != nil {
		return nil, &R2PSError{Code: r2ps.ErrIllegalRequestData, Msg: "malformed request"}
	}

	if req.Ver != r2ps.ProtocolVersion {
		return nil, &R2PSError{Code: r2ps.ErrIllegalRequestData, Msg: "unsupported version"}
	}

	// Nonce must provide at least 64 bits of entropy (8 bytes when decoded)
	nonceBytes, err := base64.URLEncoding.DecodeString(req.Nonce)
	if err != nil || len(nonceBytes) < 8 {
		return nil, &R2PSError{Code: r2ps.ErrIllegalRequestData, Msg: "nonce must be at least 8 bytes"}
	}

	// Validate iat (issued-at) is within acceptable clock skew
	now := time.Now()
	iat := time.Unix(req.Iat, 0)
	if now.Sub(iat).Abs() > d.iatMaxSkew {
		return nil, &R2PSError{Code: r2ps.ErrIllegalRequestData, Msg: "iat outside acceptable range"}
	}

	// Route by type
	switch req.Type {
	case r2ps.Type2FARegistration:
		return d.handle2FA(ctx, &req)
	case r2ps.Type2FAAuthenticate:
		return d.handle2FA(ctx, &req)
	case r2ps.Type2FAChange:
		return d.handle2FAChange(ctx, &req)
	default:
		return d.handleService(ctx, &req)
	}
}

func (d *Dispatcher) handle2FA(ctx context.Context, req *r2ps.ServiceRequest) ([]byte, error) {
	var tfaReq r2ps.TFARequestData
	if err := json.Unmarshal(req.Data, &tfaReq); err != nil {
		return nil, &R2PSError{Code: r2ps.ErrIllegalRequestData, Msg: "malformed 2FA data"}
	}

	if tfaReq.TFAMode != r2ps.TFAModeOPAQUE {
		return nil, &R2PSError{Code: r2ps.ErrIllegalRequestData, Msg: "unsupported 2fa_mode"}
	}

	reqData, err := base64.URLEncoding.DecodeString(tfaReq.Request)
	if err != nil {
		return nil, &R2PSError{Code: r2ps.ErrIllegalRequestData, Msg: "invalid request encoding"}
	}

	switch {
	case req.Type == r2ps.Type2FARegistration && tfaReq.State == r2ps.StateEvaluate:
		return d.regEvaluate(ctx, req, &tfaReq, reqData)
	case req.Type == r2ps.Type2FARegistration && tfaReq.State == r2ps.StateFinalize:
		return d.regFinalize(ctx, req, &tfaReq, reqData)
	case req.Type == r2ps.Type2FAChange && tfaReq.State == r2ps.StateEvaluate:
		return d.regEvaluate(ctx, req, &tfaReq, reqData)
	case req.Type == r2ps.Type2FAChange && tfaReq.State == r2ps.StateFinalize:
		return d.regFinalize(ctx, req, &tfaReq, reqData)
	case req.Type == r2ps.Type2FAAuthenticate && tfaReq.State == r2ps.StateEvaluate:
		return d.authEvaluate(ctx, req, &tfaReq, reqData)
	case req.Type == r2ps.Type2FAAuthenticate && tfaReq.State == r2ps.StateFinalize:
		return d.authFinalize(ctx, req, &tfaReq, reqData)
	default:
		return nil, &R2PSError{Code: r2ps.ErrIllegalState, Msg: "invalid type/state combination"}
	}
}

func (d *Dispatcher) regEvaluate(_ context.Context, req *r2ps.ServiceRequest, _ *r2ps.TFARequestData, reqData []byte) ([]byte, error) {
	credID := []byte(req.Context + "|" + req.ClientID)
	respBytes, err := d.opaque.RegistrationResponse(reqData, credID)
	if err != nil {
		return nil, &R2PSError{Code: r2ps.ErrServerError, Msg: "registration evaluate failed"}
	}

	tfaResp := r2ps.TFAResponseData{
		Response: base64.URLEncoding.EncodeToString(respBytes),
	}
	return d.signResponse(req, &tfaResp)
}

func (d *Dispatcher) regFinalize(_ context.Context, req *r2ps.ServiceRequest, _ *r2ps.TFARequestData, reqData []byte) ([]byte, error) {
	record, err := d.opaque.DeserializeRegistrationRecord(reqData)
	if err != nil {
		return nil, &R2PSError{Code: r2ps.ErrIllegalRequestData, Msg: "invalid registration record"}
	}

	credID := []byte(req.Context + "|" + req.ClientID)
	clientRecord := &opaque.ClientRecord{
		RegistrationRecord:   record,
		CredentialIdentifier: credID,
		ClientIdentity:       nil,
	}

	if err := d.records.PutRecord(req.ClientID, req.Context, clientRecord); err != nil {
		return nil, &R2PSError{Code: r2ps.ErrServerError, Msg: "store record failed"}
	}

	tfaResp := r2ps.TFAResponseData{
		Message: "success",
	}
	return d.signResponse(req, &tfaResp)
}

func (d *Dispatcher) authEvaluate(_ context.Context, req *r2ps.ServiceRequest, _ *r2ps.TFARequestData, reqData []byte) ([]byte, error) {
	// Check lockout
	if err := d.counter.Check(req.ClientID, req.Context, req.Context); err != nil {
		return nil, &R2PSError{Code: r2ps.ErrAccessDenied, Msg: err.Error()}
	}

	record, err := d.records.GetRecord(req.ClientID, req.Context)
	if err != nil {
		// Unknown client: use fake record to prevent client enumeration
		record = d.opaque.FakeRecord([]byte(req.Context + "|" + req.ClientID))
	}

	ke2Bytes, clientMAC, sessionSecret, err := d.opaque.AuthEvaluate(reqData, record)
	if err != nil {
		return nil, &R2PSError{Code: r2ps.ErrServerError, Msg: "auth evaluate failed"}
	}

	sessionID := base64.URLEncoding.EncodeToString(icrypto.RandomBytes(32))
	sess := &pake.Session{
		ID:         sessionID,
		ClientID:   req.ClientID,
		Context:    req.Context,
		SessionKey: sessionSecret,
		ClientMAC:  clientMAC,
		ExpiresAt:  time.Now().Add(d.sessionTTL),
	}

	if err := d.sessions.Create(sess); err != nil {
		return nil, &R2PSError{Code: r2ps.ErrServerError, Msg: "session creation failed"}
	}

	tfaResp := r2ps.TFAAuthResponseData{
		TFASessionID: sessionID,
		Response:     base64.URLEncoding.EncodeToString(ke2Bytes),
	}
	return d.signResponse(req, &tfaResp)
}

func (d *Dispatcher) authFinalize(_ context.Context, req *r2ps.ServiceRequest, _ *r2ps.TFARequestData, reqData []byte) ([]byte, error) {
	sess := d.sessions.Get(req.TFASessionID)
	if sess == nil {
		return nil, &R2PSError{Code: r2ps.ErrIllegalState, Msg: "session not found or expired"}
	}

	if err := d.opaque.AuthFinalize(reqData, sess.ClientMAC); err != nil {
		_ = d.counter.RecordFailure(req.ClientID, req.Context, req.Context)
		d.sessions.Delete(req.TFASessionID)
		PAKEAuthTotal.WithLabelValues("failure").Inc()
		return nil, &R2PSError{Code: r2ps.ErrUnauthorized, Msg: "authentication failed"}
	}

	// Success — reset counter and mark session verified
	d.counter.RecordSuccess(req.ClientID, req.Context, req.Context)
	if err := d.sessions.MarkVerified(req.TFASessionID); err != nil {
		return nil, &R2PSError{Code: r2ps.ErrServerError, Msg: "session update failed"}
	}
	PAKEAuthTotal.WithLabelValues("success").Inc()
	ActiveSessions.Inc()

	tfaResp := r2ps.TFAAuthResponseData{
		TFASessionID:          req.TFASessionID,
		Message:               "authenticated",
		SessionExpirationTime: sess.ExpiresAt.Unix(),
	}
	return d.signResponse(req, &tfaResp)
}

// handle2FAChange requires an authenticated 2FA session before re-registering.
func (d *Dispatcher) handle2FAChange(ctx context.Context, req *r2ps.ServiceRequest) ([]byte, error) {
	sess := d.sessions.Get(req.TFASessionID)
	if sess == nil {
		return nil, &R2PSError{Code: r2ps.ErrUnauthorized, Msg: "session not found or expired"}
	}
	if !sess.Verified {
		return nil, &R2PSError{Code: r2ps.ErrUnauthorized, Msg: "session not verified"}
	}

	// Validate session context matches request context
	if sess.Context != req.Context {
		return nil, &R2PSError{Code: r2ps.ErrAccessDenied, Msg: "session context mismatch"}
	}

	return d.handle2FA(ctx, req)
}

func (d *Dispatcher) handleService(ctx context.Context, req *r2ps.ServiceRequest) ([]byte, error) {
	handler, ok := d.handlers[req.Type]
	if !ok {
		return nil, &R2PSError{Code: r2ps.ErrUnsupportedType, Msg: "unknown service type"}
	}

	// 2FA service types require an authenticated session
	sess := d.sessions.Get(req.TFASessionID)
	if sess == nil {
		return nil, &R2PSError{Code: r2ps.ErrUnauthorized, Msg: "session not found or expired"}
	}
	if !sess.Verified {
		return nil, &R2PSError{Code: r2ps.ErrUnauthorized, Msg: "session not verified"}
	}

	// Validate session context matches request context
	if sess.Context != req.Context {
		return nil, &R2PSError{Code: r2ps.ErrAccessDenied, Msg: "session context mismatch"}
	}

	// Data is now directly in the JWS payload (not separately encrypted)
	respData, err := handler.Handle(ctx, req.ClientID, req.Data)
	if err != nil {
		slog.Debug("service handler error", "type", req.Type, "error", err)
		return nil, &R2PSError{Code: r2ps.ErrServerError, Msg: req.Type + " failed"}
	}

	// If the handler returned raw bytes (not JSON), wrap as a JSON string
	var dataJSON json.RawMessage
	if json.Valid(respData) {
		dataJSON = json.RawMessage(respData)
	} else {
		encoded := base64.URLEncoding.EncodeToString(respData)
		dataJSON, _ = json.Marshal(encoded)
	}

	svcResp := r2ps.ServiceResponse{
		Ver:   r2ps.ProtocolVersion,
		Nonce: req.Nonce,
		Iat:   time.Now().Unix(),
		Data:  dataJSON,
	}

	respJSON, err := json.Marshal(svcResp)
	if err != nil {
		return nil, &R2PSError{Code: r2ps.ErrServerError, Msg: "marshal response failed"}
	}

	signed, err := icrypto.SignJWS(respJSON, d.serverKey, "", r2ps.TypResponse)
	if err != nil {
		return nil, &R2PSError{Code: r2ps.ErrServerError, Msg: "sign response failed"}
	}

	return []byte(signed), nil
}

func (d *Dispatcher) signResponse(req *r2ps.ServiceRequest, data any) ([]byte, error) {
	dataJSON, err := json.Marshal(data)
	if err != nil {
		return nil, &R2PSError{Code: r2ps.ErrServerError, Msg: "marshal data failed"}
	}

	svcResp := r2ps.ServiceResponse{
		Ver:   r2ps.ProtocolVersion,
		Nonce: req.Nonce,
		Iat:   time.Now().Unix(),
		Data:  json.RawMessage(dataJSON),
	}

	svcJSON, err := json.Marshal(svcResp)
	if err != nil {
		return nil, &R2PSError{Code: r2ps.ErrServerError, Msg: "marshal response failed"}
	}

	signed, err := icrypto.SignJWS(svcJSON, d.serverKey, "", r2ps.TypResponse)
	if err != nil {
		return nil, &R2PSError{Code: r2ps.ErrServerError, Msg: "sign response failed"}
	}

	return []byte(signed), nil
}

// R2PSError represents a protocol-level error.
type R2PSError struct {
	Code string
	Msg  string
}

func (e *R2PSError) Error() string {
	return fmt.Sprintf("%s: %s", e.Code, e.Msg)
}

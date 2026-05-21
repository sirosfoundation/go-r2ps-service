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
	GetRecord(clientID, kid string) (*opaque.ClientRecord, error)
	PutRecord(clientID, kid string, record *opaque.ClientRecord) error
}

// ClientKeyStore resolves a client's public key by kid.
// If not configured, the dispatcher falls back to using the server key for JWS verification.
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

func (s *InMemoryRecordStore) GetRecord(clientID, kid string) (*opaque.ClientRecord, error) {
	r, ok := s.records[clientID+"|"+kid]
	if !ok {
		return nil, fmt.Errorf("no record for %s/%s", clientID, kid)
	}
	return r, nil
}

func (s *InMemoryRecordStore) PutRecord(clientID, kid string, record *opaque.ClientRecord) error {
	s.records[clientID+"|"+kid] = record
	return nil
}

// Dispatcher processes R2PS requests: verifies JWS, routes to PAKE or service handlers.
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
	IatMaxSkew  time.Duration  // max clock skew for iat validation; 0 = 5 minutes
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

// Process handles a raw R2PS POST body (JWS compact serialization).
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
	case r2ps.TypePINRegistration:
		return d.handlePAKE(ctx, &req)
	case r2ps.TypeAuthenticate:
		return d.handlePAKE(ctx, &req)
	case r2ps.TypePINChange:
		return d.handlePINChange(ctx, &req)
	default:
		return d.handleService(ctx, &req)
	}
}

func (d *Dispatcher) handlePAKE(ctx context.Context, req *r2ps.ServiceRequest) ([]byte, error) {
	// Decrypt data (device-encrypted)
	dataBytes, err := d.decryptRequestData(req)
	if err != nil {
		return nil, &R2PSError{Code: r2ps.ErrIllegalRequestData, Msg: "decrypt failed"}
	}

	var pakeReq r2ps.PAKERequest
	if err := json.Unmarshal(dataBytes, &pakeReq); err != nil {
		return nil, &R2PSError{Code: r2ps.ErrIllegalRequestData, Msg: "malformed PAKE data"}
	}

	if pakeReq.Protocol != r2ps.PAKEProtocolOPAQUE {
		return nil, &R2PSError{Code: r2ps.ErrIllegalRequestData, Msg: "unsupported PAKE protocol"}
	}

	reqData, err := base64.URLEncoding.DecodeString(pakeReq.Req)
	if err != nil {
		return nil, &R2PSError{Code: r2ps.ErrIllegalRequestData, Msg: "invalid req encoding"}
	}

	switch {
	case req.Type == r2ps.TypePINRegistration && pakeReq.State == r2ps.PAKEStateEvaluate:
		return d.regEvaluate(ctx, req, &pakeReq, reqData)
	case req.Type == r2ps.TypePINRegistration && pakeReq.State == r2ps.PAKEStateFinalize:
		return d.regFinalize(ctx, req, &pakeReq, reqData)
	case req.Type == r2ps.TypePINChange && pakeReq.State == r2ps.PAKEStateEvaluate:
		return d.regEvaluate(ctx, req, &pakeReq, reqData)
	case req.Type == r2ps.TypePINChange && pakeReq.State == r2ps.PAKEStateFinalize:
		return d.regFinalize(ctx, req, &pakeReq, reqData)
	case req.Type == r2ps.TypeAuthenticate && pakeReq.State == r2ps.PAKEStateEvaluate:
		return d.authEvaluate(ctx, req, &pakeReq, reqData)
	case req.Type == r2ps.TypeAuthenticate && pakeReq.State == r2ps.PAKEStateFinalize:
		return d.authFinalize(ctx, req, &pakeReq, reqData)
	default:
		return nil, &R2PSError{Code: r2ps.ErrIllegalState, Msg: "invalid type/state combination"}
	}
}

func (d *Dispatcher) regEvaluate(_ context.Context, req *r2ps.ServiceRequest, _ *r2ps.PAKERequest, reqData []byte) ([]byte, error) {
	credID := []byte(req.Context + "|" + req.ClientID + "|" + req.Kid)
	respBytes, err := d.opaque.RegistrationResponse(reqData, credID)
	if err != nil {
		return nil, &R2PSError{Code: r2ps.ErrServerError, Msg: "registration evaluate failed"}
	}

	pakeResp := r2ps.PAKEResponse{
		Resp: base64.URLEncoding.EncodeToString(respBytes),
	}
	return d.encryptAndSign(req, &pakeResp)
}

func (d *Dispatcher) regFinalize(_ context.Context, req *r2ps.ServiceRequest, _ *r2ps.PAKERequest, reqData []byte) ([]byte, error) {
	record, err := d.opaque.DeserializeRegistrationRecord(reqData)
	if err != nil {
		return nil, &R2PSError{Code: r2ps.ErrIllegalRequestData, Msg: "invalid registration record"}
	}

	credID := []byte(req.Context + "|" + req.ClientID + "|" + req.Kid)
	clientRecord := &opaque.ClientRecord{
		RegistrationRecord:   record,
		CredentialIdentifier: credID,
		ClientIdentity:       nil,
	}

	if err := d.records.PutRecord(req.ClientID, req.Kid, clientRecord); err != nil {
		return nil, &R2PSError{Code: r2ps.ErrServerError, Msg: "store record failed"}
	}

	pakeResp := r2ps.PAKEResponse{
		Msg: "registration complete",
	}
	return d.encryptAndSign(req, &pakeResp)
}

func (d *Dispatcher) authEvaluate(_ context.Context, req *r2ps.ServiceRequest, pakeReq *r2ps.PAKERequest, reqData []byte) ([]byte, error) {
	// Check lockout
	if err := d.counter.Check(req.ClientID, req.Kid, req.Context); err != nil {
		return nil, &R2PSError{Code: r2ps.ErrAccessDenied, Msg: err.Error()}
	}

	record, err := d.records.GetRecord(req.ClientID, req.Kid)
	if err != nil {
		// Unknown client: use fake record to prevent client enumeration
		record = d.opaque.FakeRecord([]byte(req.Context + "|" + req.ClientID + "|" + req.Kid))
	}

	ke2Bytes, clientMAC, sessionSecret, err := d.opaque.AuthEvaluate(reqData, record)
	if err != nil {
		return nil, &R2PSError{Code: r2ps.ErrServerError, Msg: "auth evaluate failed"}
	}

	sessionID := base64.URLEncoding.EncodeToString(icrypto.RandomBytes(32))
	sess := &pake.Session{
		ID:         sessionID,
		ClientID:   req.ClientID,
		Kid:        req.Kid,
		Context:    req.Context,
		SessionKey: sessionSecret,
		ClientMAC:  clientMAC,
		ExpiresAt:  time.Now().Add(d.sessionTTL),
	}

	if err := d.sessions.Create(sess); err != nil {
		return nil, &R2PSError{Code: r2ps.ErrServerError, Msg: "session creation failed"}
	}

	pakeResp := r2ps.PAKEResponse{
		PakeSessionID: sessionID,
		Resp:          base64.URLEncoding.EncodeToString(ke2Bytes),
	}
	return d.encryptAndSign(req, &pakeResp)
}

func (d *Dispatcher) authFinalize(_ context.Context, req *r2ps.ServiceRequest, pakeReq *r2ps.PAKERequest, reqData []byte) ([]byte, error) {
	sess := d.sessions.Get(req.PakeSessionID)
	if sess == nil {
		return nil, &R2PSError{Code: r2ps.ErrIllegalState, Msg: "session not found or expired"}
	}

	if err := d.opaque.AuthFinalize(reqData, sess.ClientMAC); err != nil {
		_ = d.counter.RecordFailure(req.ClientID, req.Kid, req.Context)
		d.sessions.Delete(req.PakeSessionID)
		PAKEAuthTotal.WithLabelValues("failure").Inc()
		return nil, &R2PSError{Code: r2ps.ErrUnauthorized, Msg: "authentication failed"}
	}

	// Success — reset counter and mark session verified
	d.counter.RecordSuccess(req.ClientID, req.Kid, req.Context)
	if err := d.sessions.MarkVerified(req.PakeSessionID); err != nil {
		return nil, &R2PSError{Code: r2ps.ErrServerError, Msg: "session update failed"}
	}
	PAKEAuthTotal.WithLabelValues("success").Inc()
	ActiveSessions.Inc()

	// Apply task and session_duration from finalize request (per spec)
	if pakeReq.Task != "" {
		sess.Task = pakeReq.Task
	}
	if pakeReq.SessionDuration > 0 {
		requested := time.Duration(pakeReq.SessionDuration) * time.Second
		if requested < d.sessionTTL {
			sess.ExpiresAt = time.Now().Add(requested)
		}
	}

	pakeResp := r2ps.PAKEResponse{
		PakeSessionID:         req.PakeSessionID,
		Msg:                   "authenticated",
		Task:                  pakeReq.Task,
		SessionExpirationTime: sess.ExpiresAt.Unix(),
	}
	return d.encryptAndSign(req, &pakeResp)
}

// handlePINChange requires an authenticated session before re-registering a PIN.
func (d *Dispatcher) handlePINChange(ctx context.Context, req *r2ps.ServiceRequest) ([]byte, error) {
	// pin_change requires enc=user — the spec mandates user-authenticated encryption
	if req.Enc != r2ps.EncUser {
		return nil, &R2PSError{Code: r2ps.ErrIllegalRequestData, Msg: "pin_change requires enc=user"}
	}

	sess := d.sessions.Get(req.PakeSessionID)
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

	return d.handlePAKE(ctx, req)
}

func (d *Dispatcher) handleService(ctx context.Context, req *r2ps.ServiceRequest) ([]byte, error) {
	handler, ok := d.handlers[req.Type]
	if !ok {
		return nil, &R2PSError{Code: r2ps.ErrUnsupportedType, Msg: "unknown service type"}
	}

	// Service requests require an authenticated session (enc=user)
	if req.Enc != r2ps.EncUser {
		return nil, &R2PSError{Code: r2ps.ErrIllegalRequestData, Msg: "service requests require enc=user"}
	}

	sess := d.sessions.Get(req.PakeSessionID)
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

	// Decrypt service data using session key
	dataBytes, err := icrypto.DecryptJWESymmetric(req.Data, sess.SessionKey[:32])
	if err != nil {
		return nil, &R2PSError{Code: r2ps.ErrIllegalRequestData, Msg: "decrypt service data failed"}
	}

	respData, err := handler.Handle(ctx, req.ClientID, dataBytes)
	if err != nil {
		slog.Debug("service handler error", "type", req.Type, "error", err)
		return nil, &R2PSError{Code: r2ps.ErrServerError, Msg: req.Type + " failed"}
	}

	// Encrypt response data with session key
	encData, err := icrypto.EncryptJWESymmetric(respData, sess.SessionKey[:32])
	if err != nil {
		return nil, &R2PSError{Code: r2ps.ErrServerError, Msg: "encrypt response failed"}
	}

	svcResp := r2ps.ServiceResponse{
		Ver:   r2ps.ProtocolVersion,
		Nonce: req.Nonce,
		Iat:   time.Now().Unix(),
		Enc:   r2ps.EncUser,
		Data:  encData,
	}

	respJSON, err := json.Marshal(svcResp)
	if err != nil {
		return nil, &R2PSError{Code: r2ps.ErrServerError, Msg: "marshal response failed"}
	}

	signed, err := icrypto.SignJWS(respJSON, d.serverKey, "", "r2ps-response+json")
	if err != nil {
		return nil, &R2PSError{Code: r2ps.ErrServerError, Msg: "sign response failed"}
	}

	return []byte(signed), nil
}

func (d *Dispatcher) decryptRequestData(req *r2ps.ServiceRequest) ([]byte, error) {
	switch req.Enc {
	case r2ps.EncDevice:
		return icrypto.DecryptJWE(req.Data, d.serverKey)
	case r2ps.EncUser:
		sess := d.sessions.Get(req.PakeSessionID)
		if sess == nil {
			return nil, fmt.Errorf("no session for user-encrypted data")
		}
		return icrypto.DecryptJWESymmetric(req.Data, sess.SessionKey[:32])
	default:
		return nil, fmt.Errorf("unsupported enc mode: %s", req.Enc)
	}
}

func (d *Dispatcher) encryptAndSign(req *r2ps.ServiceRequest, pakeResp *r2ps.PAKEResponse) ([]byte, error) {
	respJSON, err := json.Marshal(pakeResp)
	if err != nil {
		return nil, &R2PSError{Code: r2ps.ErrServerError, Msg: "marshal failed"}
	}

	// Encrypt data to client's context key (device-mode ECDH).
	// Per spec: server encrypts to client's public context key.
	recipientKey := &d.serverKey.PublicKey // fallback for dev/test
	if d.clientKeys != nil {
		if pk, err := d.clientKeys.GetClientKey(req.Kid); err == nil {
			recipientKey = pk
		}
	}
	encData, err := icrypto.EncryptJWE(respJSON, recipientKey)
	if err != nil {
		return nil, &R2PSError{Code: r2ps.ErrServerError, Msg: "encrypt failed"}
	}

	svcResp := r2ps.ServiceResponse{
		Ver:   r2ps.ProtocolVersion,
		Nonce: req.Nonce,
		Iat:   time.Now().Unix(),
		Enc:   r2ps.EncDevice,
		Data:  encData,
	}

	svcJSON, err := json.Marshal(svcResp)
	if err != nil {
		return nil, &R2PSError{Code: r2ps.ErrServerError, Msg: "marshal response failed"}
	}

	signed, err := icrypto.SignJWS(svcJSON, d.serverKey, "", "r2ps-response+json")
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

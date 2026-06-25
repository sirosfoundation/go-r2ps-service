package client

import (
	"crypto"
	"crypto/ecdsa"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"time"

	"github.com/bytemare/opaque"

	icrypto "github.com/sirosfoundation/go-r2ps-service/internal/crypto"
	"github.com/sirosfoundation/go-r2ps-service/pkg/r2ps"
)

// OPAQUEConfig matches the server's configuration.
var OPAQUEConfig = &opaque.Configuration{
	OPRF: opaque.P256Sha256,
	AKE:  opaque.P256Sha256,
	KDF:  crypto.SHA256,
	MAC:  crypto.SHA256,
	Hash: crypto.SHA256,
}

// Transport sends a signed request and returns the raw response body.
type Transport interface {
	Send(body []byte) ([]byte, error)
}

// Client is an R2PS protocol client.
type Client struct {
	clientID  string
	context   string
	clientKey *ecdsa.PrivateKey
	serverPub *ecdsa.PublicKey
	transport Transport

	// State after authentication
	sessionID  string
	sessionKey []byte
}

// NewClient creates a new R2PS client.
func NewClient(clientID, context string, clientKey *ecdsa.PrivateKey, serverPub *ecdsa.PublicKey, transport Transport) *Client {
	return &Client{
		clientID:  clientID,
		context:   context,
		clientKey: clientKey,
		serverPub: serverPub,
		transport: transport,
	}
}

// Register performs OPAQUE registration (evaluate + finalize).
func (c *Client) Register(password []byte) error {
	client, err := OPAQUEConfig.Client()
	if err != nil {
		return fmt.Errorf("create OPAQUE client: %w", err)
	}

	// Phase 1: RegistrationInit
	regReq, err := client.RegistrationInit(password)
	if err != nil {
		return fmt.Errorf("registration init: %w", err)
	}

	tfaReq := r2ps.TFARequestData{
		Protocol: r2ps.TFAModeOPAQUE,
		State:   r2ps.StateEvaluate,
		PData: base64.URLEncoding.EncodeToString(regReq.Serialize()),
	}

	resp, err := c.send2FA(r2ps.Type2FARegistration, "", &tfaReq)
	if err != nil {
		return fmt.Errorf("registration evaluate: %w", err)
	}

	var tfaResp r2ps.TFAResponseData
	if err := json.Unmarshal(resp, &tfaResp); err != nil {
		return fmt.Errorf("unmarshal response: %w", err)
	}

	// Deserialize server's RegistrationResponse
	deser, err := OPAQUEConfig.Deserializer()
	if err != nil {
		return fmt.Errorf("create deserializer: %w", err)
	}

	respBytes, err := base64.URLEncoding.DecodeString(tfaResp.Response)
	if err != nil {
		return fmt.Errorf("decode response: %w", err)
	}

	regResp, err := deser.RegistrationResponse(respBytes)
	if err != nil {
		return fmt.Errorf("deserialize registration response: %w", err)
	}

	// Phase 2: RegistrationFinalize
	record, _, err := client.RegistrationFinalize(regResp, nil, nil)
	if err != nil {
		return fmt.Errorf("registration finalize: %w", err)
	}

	tfaReqFin := r2ps.TFARequestData{
		Protocol: r2ps.TFAModeOPAQUE,
		State:   r2ps.StateFinalize,
		PData: base64.URLEncoding.EncodeToString(record.Serialize()),
	}

	_, err = c.send2FA(r2ps.Type2FARegistration, "", &tfaReqFin)
	return err
}

// Authenticate performs OPAQUE authentication (evaluate + finalize).
// On success, sets session ID and key for subsequent service calls.
func (c *Client) Authenticate(password []byte) error {
	client, err := OPAQUEConfig.Client()
	if err != nil {
		return fmt.Errorf("create OPAQUE client: %w", err)
	}

	// Phase 1: GenerateKE1
	ke1, err := client.GenerateKE1(password)
	if err != nil {
		return fmt.Errorf("generate KE1: %w", err)
	}

	tfaReq := r2ps.TFARequestData{
		Protocol: r2ps.TFAModeOPAQUE,
		State:   r2ps.StateEvaluate,
		PData: base64.URLEncoding.EncodeToString(ke1.Serialize()),
	}

	resp, err := c.send2FA(r2ps.Type2FAAuthenticate, "", &tfaReq)
	if err != nil {
		return fmt.Errorf("auth evaluate: %w", err)
	}

	var authResp r2ps.TFAAuthResponseData
	if err := json.Unmarshal(resp, &authResp); err != nil {
		return fmt.Errorf("unmarshal auth response: %w", err)
	}

	// Phase 2: GenerateKE3
	deser, err := OPAQUEConfig.Deserializer()
	if err != nil {
		return fmt.Errorf("create deserializer: %w", err)
	}

	ke2Bytes, err := base64.URLEncoding.DecodeString(authResp.Response)
	if err != nil {
		return fmt.Errorf("decode KE2: %w", err)
	}

	ke2, err := deser.KE2(ke2Bytes)
	if err != nil {
		return fmt.Errorf("deserialize KE2: %w", err)
	}

	ke3, sessionKey, _, err := client.GenerateKE3(ke2, nil, nil)
	if err != nil {
		return fmt.Errorf("generate KE3: %w", err)
	}

	tfaReqFin := r2ps.TFARequestData{
		Protocol: r2ps.TFAModeOPAQUE,
		State:   r2ps.StateFinalize,
		PData: base64.URLEncoding.EncodeToString(ke3.Serialize()),
	}

	_, err = c.send2FA(r2ps.Type2FAAuthenticate, authResp.TFASessionID, &tfaReqFin)
	if err != nil {
		return fmt.Errorf("auth finalize: %w", err)
	}

	c.sessionID = authResp.TFASessionID
	c.sessionKey = sessionKey
	return nil
}

// CallService sends an authenticated service request using the session key.
// Data is passed directly as the service-specific payload in the JWS.
func (c *Client) CallService(serviceType string, reqData json.RawMessage) (json.RawMessage, error) {
	if c.sessionKey == nil {
		return nil, fmt.Errorf("not authenticated")
	}

	svcReq := r2ps.ServiceRequest{
		Ver:          r2ps.ProtocolVersion,
		Nonce:        base64.URLEncoding.EncodeToString(icrypto.RandomBytes(16)),
		Iat:          time.Now().Unix(),
		Data:         reqData,
		ClientID:     c.clientID,
		Context:      c.context,
		Type:         serviceType,
		TFASessionID: c.sessionID,
	}

	reqJSON, err := json.Marshal(svcReq)
	if err != nil {
		return nil, fmt.Errorf("marshal service request: %w", err)
	}

	signed, err := icrypto.SignJWS(reqJSON, c.clientKey, "", r2ps.TypRequest)
	if err != nil {
		return nil, fmt.Errorf("sign request: %w", err)
	}

	respBody, err := c.transport.Send([]byte(signed))
	if err != nil {
		return nil, fmt.Errorf("transport: %w", err)
	}

	// Verify and parse response JWS
	respPayload, err := icrypto.VerifyJWS(string(respBody), c.serverPub)
	if err != nil {
		return nil, fmt.Errorf("verify response JWS: %w", err)
	}

	var svcResp r2ps.ServiceResponse
	if err := json.Unmarshal(respPayload, &svcResp); err != nil {
		return nil, fmt.Errorf("unmarshal response: %w", err)
	}

	return svcResp.Data, nil
}

// SessionID returns the current session ID (empty if not authenticated).
func (c *Client) SessionID() string { return c.sessionID }

func (c *Client) send2FA(reqType, sessionID string, tfaReq *r2ps.TFARequestData) (json.RawMessage, error) {
	tfaJSON, err := json.Marshal(tfaReq)
	if err != nil {
		return nil, fmt.Errorf("marshal 2FA request: %w", err)
	}

	svcReq := r2ps.ServiceRequest{
		Ver:          r2ps.ProtocolVersion,
		Nonce:        base64.URLEncoding.EncodeToString(icrypto.RandomBytes(16)),
		Iat:          time.Now().Unix(),
		Data:         json.RawMessage(tfaJSON),
		ClientID:     c.clientID,
		Context:      c.context,
		Type:         reqType,
		TFASessionID: sessionID,
	}

	reqJSON, err := json.Marshal(svcReq)
	if err != nil {
		return nil, fmt.Errorf("marshal request: %w", err)
	}

	signed, err := icrypto.SignJWS(reqJSON, c.clientKey, "", r2ps.TypRequest)
	if err != nil {
		return nil, fmt.Errorf("sign request: %w", err)
	}

	respBody, err := c.transport.Send([]byte(signed))
	if err != nil {
		return nil, fmt.Errorf("transport: %w", err)
	}

	// Verify and parse response
	respPayload, err := icrypto.VerifyJWS(string(respBody), c.serverPub)
	if err != nil {
		return nil, fmt.Errorf("verify response: %w", err)
	}

	var svcResp r2ps.ServiceResponse
	if err := json.Unmarshal(respPayload, &svcResp); err != nil {
		return nil, fmt.Errorf("unmarshal response: %w", err)
	}

	return svcResp.Data, nil
}

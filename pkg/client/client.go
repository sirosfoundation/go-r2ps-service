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
	kid       string
	context   string
	clientKey *ecdsa.PrivateKey
	serverPub *ecdsa.PublicKey
	transport Transport

	// State after authentication
	sessionID  string
	sessionKey []byte
}

// NewClient creates a new R2PS client.
func NewClient(clientID, kid, context string, clientKey *ecdsa.PrivateKey, serverPub *ecdsa.PublicKey, transport Transport) *Client {
	return &Client{
		clientID:  clientID,
		kid:       kid,
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

	// Send evaluate request
	pakeReq := r2ps.PAKERequest{
		Protocol: r2ps.PAKEProtocolOPAQUE,
		State:    r2ps.PAKEStateEvaluate,
		Req:      base64.URLEncoding.EncodeToString(regReq.Serialize()),
	}

	resp, err := c.sendPAKE(r2ps.TypePINRegistration, r2ps.EncDevice, "", &pakeReq)
	if err != nil {
		return fmt.Errorf("registration evaluate: %w", err)
	}

	// Deserialize server's RegistrationResponse
	deser, err := OPAQUEConfig.Deserializer()
	if err != nil {
		return fmt.Errorf("create deserializer: %w", err)
	}

	respBytes, err := base64.URLEncoding.DecodeString(resp.Resp)
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

	pakeReqFin := r2ps.PAKERequest{
		Protocol: r2ps.PAKEProtocolOPAQUE,
		State:    r2ps.PAKEStateFinalize,
		Req:      base64.URLEncoding.EncodeToString(record.Serialize()),
	}

	_, err = c.sendPAKE(r2ps.TypePINRegistration, r2ps.EncDevice, "", &pakeReqFin)
	return err
}

// Authenticate performs OPAQUE authentication (evaluate + finalize).
// On success, sets session ID and key for subsequent service calls.
func (c *Client) Authenticate(password []byte, task string) error {
	client, err := OPAQUEConfig.Client()
	if err != nil {
		return fmt.Errorf("create OPAQUE client: %w", err)
	}

	// Phase 1: GenerateKE1
	ke1, err := client.GenerateKE1(password)
	if err != nil {
		return fmt.Errorf("generate KE1: %w", err)
	}

	pakeReq := r2ps.PAKERequest{
		Protocol: r2ps.PAKEProtocolOPAQUE,
		State:    r2ps.PAKEStateEvaluate,
		Task:     task,
		Req:      base64.URLEncoding.EncodeToString(ke1.Serialize()),
	}

	resp, err := c.sendPAKE(r2ps.TypeAuthenticate, r2ps.EncDevice, "", &pakeReq)
	if err != nil {
		return fmt.Errorf("auth evaluate: %w", err)
	}

	// Phase 2: GenerateKE3
	deser, err := OPAQUEConfig.Deserializer()
	if err != nil {
		return fmt.Errorf("create deserializer: %w", err)
	}

	ke2Bytes, err := base64.URLEncoding.DecodeString(resp.Resp)
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

	pakeReqFin := r2ps.PAKERequest{
		Protocol: r2ps.PAKEProtocolOPAQUE,
		State:    r2ps.PAKEStateFinalize,
		Req:      base64.URLEncoding.EncodeToString(ke3.Serialize()),
	}

	_, err = c.sendPAKE(r2ps.TypeAuthenticate, r2ps.EncDevice, resp.PakeSessionID, &pakeReqFin)
	if err != nil {
		return fmt.Errorf("auth finalize: %w", err)
	}

	c.sessionID = resp.PakeSessionID
	c.sessionKey = sessionKey
	return nil
}

// CallService sends an authenticated service request using the session key.
func (c *Client) CallService(serviceType string, reqData []byte) ([]byte, error) {
	if c.sessionKey == nil {
		return nil, fmt.Errorf("not authenticated")
	}

	// Encrypt service data with session key
	encData, err := icrypto.EncryptJWESymmetric(reqData, c.sessionKey[:32])
	if err != nil {
		return nil, fmt.Errorf("encrypt service data: %w", err)
	}

	svcReq := r2ps.ServiceRequest{
		Ver:           r2ps.ProtocolVersion,
		Nonce:         base64.URLEncoding.EncodeToString(icrypto.RandomBytes(16)),
		Iat:           time.Now().Unix(),
		Enc:           r2ps.EncUser,
		Data:          encData,
		ClientID:      c.clientID,
		Kid:           c.kid,
		Context:       c.context,
		Type:          serviceType,
		PakeSessionID: c.sessionID,
	}

	reqJSON, err := json.Marshal(svcReq)
	if err != nil {
		return nil, fmt.Errorf("marshal service request: %w", err)
	}

	signed, err := icrypto.SignJWS(reqJSON, c.clientKey, "")
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

	// Decrypt response data
	plaintext, err := icrypto.DecryptJWESymmetric(svcResp.Data, c.sessionKey[:32])
	if err != nil {
		return nil, fmt.Errorf("decrypt response: %w", err)
	}

	return plaintext, nil
}

// SessionID returns the current session ID (empty if not authenticated).
func (c *Client) SessionID() string { return c.sessionID }

func (c *Client) sendPAKE(reqType, enc, sessionID string, pakeReq *r2ps.PAKERequest) (*r2ps.PAKEResponse, error) {
	pakeJSON, err := json.Marshal(pakeReq)
	if err != nil {
		return nil, fmt.Errorf("marshal PAKE request: %w", err)
	}

	// Encrypt PAKE data
	encData, err := icrypto.EncryptJWE(pakeJSON, c.serverPub)
	if err != nil {
		return nil, fmt.Errorf("encrypt PAKE data: %w", err)
	}

	svcReq := r2ps.ServiceRequest{
		Ver:           r2ps.ProtocolVersion,
		Nonce:         base64.URLEncoding.EncodeToString(icrypto.RandomBytes(16)),
		Iat:           time.Now().Unix(),
		Enc:           enc,
		Data:          encData,
		ClientID:      c.clientID,
		Kid:           c.kid,
		Context:       c.context,
		Type:          reqType,
		PakeSessionID: sessionID,
	}

	reqJSON, err := json.Marshal(svcReq)
	if err != nil {
		return nil, fmt.Errorf("marshal request: %w", err)
	}

	signed, err := icrypto.SignJWS(reqJSON, c.clientKey, "")
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

	// Decrypt response data
	decrypted, err := icrypto.DecryptJWE(svcResp.Data, c.clientKey)
	if err != nil {
		return nil, fmt.Errorf("decrypt response: %w", err)
	}

	var pakeResp r2ps.PAKEResponse
	if err := json.Unmarshal(decrypted, &pakeResp); err != nil {
		return nil, fmt.Errorf("unmarshal PAKE response: %w", err)
	}

	return &pakeResp, nil
}

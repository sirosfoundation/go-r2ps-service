package r2ps

import "encoding/json"

// ServiceRequest is the JWS payload for an R2PS service request.
// See draft-santesson-r2ps §4.2 and r2ps-service-types.md §2.2.
type ServiceRequest struct {
	Ver          string          `json:"ver"`
	Nonce        string          `json:"nonce"`
	Iat          int64           `json:"iat"`
	Data         json.RawMessage `json:"data"`
	ClientID     string          `json:"client_id"`
	Context      string          `json:"context"`
	Type         string          `json:"type"`
	TFASessionID string          `json:"2fa_session_id,omitempty"`
	JWEHash      string          `json:"jwe_hash,omitempty"` // SHA-256 of JWE protected header (draft-santesson-r2ps §4.2.1)
}

// ServiceResponse is the JWS payload for an R2PS service response.
// See draft-santesson-r2ps §4.2.2 and r2ps-service-types.md §2.2.
type ServiceResponse struct {
	Ver     string          `json:"ver"`
	Nonce   string          `json:"nonce"`
	Iat     int64           `json:"iat"`
	Data    json.RawMessage `json:"data"`
	Success *bool           `json:"success,omitempty"` // draft-santesson-r2ps §4.2.2
}

// ErrorResponse is the JSON body returned on failure.
type ErrorResponse struct {
	ErrorCode    string `json:"error_code"`
	ErrorMessage string `json:"error_message"`
}

// TFARequestData is the data object for second-factor service requests.
// See draft-santesson-r2ps §4.3.1 and r2ps-service-types.md §4.1.
type TFARequestData struct {
	Protocol          string `json:"protocol"`           // I-D field name (draft-santesson-r2ps §4.3.1)
	TFAMode           string `json:"2fa_mode,omitempty"` // legacy alias — accepted on read
	State             string `json:"state,omitempty"`
	PData             string `json:"p_data,omitempty"`  // I-D field name
	Request           string `json:"request,omitempty"` // legacy alias — accepted on read
	Authorization     string `json:"authorization,omitempty"`
	AuthorizationType string `json:"authorization_type,omitempty"` // draft-santesson-r2ps §4.3.1
	SessionDuration   int64  `json:"session_duration,omitempty"`   // draft-santesson-r2ps §4.3.4
}

// GetProtocol returns the protocol identifier, accepting both I-D and legacy field names.
func (t *TFARequestData) GetProtocol() string {
	if t.Protocol != "" {
		return t.Protocol
	}
	return t.TFAMode
}

// GetPData returns the protocol data, accepting both I-D and legacy field names.
func (t *TFARequestData) GetPData() string {
	if t.PData != "" {
		return t.PData
	}
	return t.Request
}

// TFAResponseData is the data object for second-factor service responses.
// See draft-santesson-r2ps §4.3.2 and r2ps-service-types.md §4.1.
type TFAResponseData struct {
	PData    string `json:"p_data,omitempty"`   // I-D field name
	Response string `json:"response,omitempty"` // legacy alias — emitted for backward compat
	Message  string `json:"message,omitempty"`
}

// GetPData returns the protocol data, accepting both I-D and legacy field names.
func (t *TFAResponseData) GetPData() string {
	if t.PData != "" {
		return t.PData
	}
	return t.Response
}

// TFAAuthResponseData extends TFAResponseData with session establishment fields.
// See draft-santesson-r2ps §4.3.4.
type TFAAuthResponseData struct {
	SessionID             string `json:"session_id,omitempty"`     // I-D field name
	TFASessionID          string `json:"2fa_session_id,omitempty"` // legacy alias
	PData                 string `json:"p_data,omitempty"`         // I-D field name
	Response              string `json:"response,omitempty"`       // legacy alias
	Message               string `json:"message,omitempty"`
	SessionExpirationTime int64  `json:"session_expiration_time,omitempty"`
	Task                  string `json:"task,omitempty"` // echoed task binding (draft-santesson-r2ps §4.3.4)
}

// GetSessionID returns the session ID, accepting both I-D and legacy field names.
func (t *TFAAuthResponseData) GetSessionID() string {
	if t.SessionID != "" {
		return t.SessionID
	}
	return t.TFASessionID
}

// GetPData returns the protocol data, accepting both I-D and legacy field names.
func (t *TFAAuthResponseData) GetPData() string {
	if t.PData != "" {
		return t.PData
	}
	return t.Response
}

// Protocol version
const ProtocolVersion = "1.0"

// Second-factor mode identifiers — draft-santesson-r2ps §4.3.5
const (
	TFAModePassword = "password"
	TFAModeOPAQUE   = "opaque"
	TFAModeFIDO2    = "fido2"
)

// Second-factor states — draft-santesson-r2ps §4.3.5
const (
	StateEvaluate  = "evaluate"
	StateFinalize  = "finalize"
	StateChallenge = "challenge"
	StateRegister  = "register"
)

// Core service types — draft-santesson-r2ps §4.3.4
// I-D names are primary; legacy names are kept as aliases.
const (
	Type2FARegistration = "2fa_registration"
	TypeCreateSession   = "create_session"   // I-D name for 2fa_authenticate
	Type2FAUpdate       = "2fa_update"       // I-D name for 2fa_change
	Type2FAAuthenticate = "2fa_authenticate" // legacy alias for create_session
	Type2FAChange       = "2fa_change"       // legacy alias for 2fa_update
)

// Application service types — r2ps-service-types-register.md
const (
	TypeP256Generate = "p256_generate"
	TypeSignECDSA    = "sign_ecdsa"
	TypeAgreeECDH    = "agree_ecdh"
)

// EUDIW service types — r2ps-service-types-eudiw.md
const (
	TypeEUDIWWKAETSI = "eudiw_wka_etsi"
	TypeEUDIWWIAETSI = "eudiw_wia_etsi"
)

// EUDIW lifecycle service types — r2ps-service-types-register.md
const (
	TypeEUDIWWIRevoke  = "eudiw_wi_revoke"
	TypeEUDIWWISuspend = "eudiw_wi_suspend"
)

// EUDIW request/response types — r2ps-service-types-eudiw.md

// EUDIWAttestationRequest is the data payload for eudiw_wka_etsi and eudiw_wia_etsi.
type EUDIWAttestationRequest struct {
	KeysToAttest []string `json:"keys_to_attest"`
	Ver          string   `json:"ver"`
}

// StatusListRef is a Token Status List reference (RFC 9701).
type StatusListRef struct {
	Idx int    `json:"idx"`
	URI string `json:"uri"`
}

// StatusListStatus wraps a status_list reference.
type StatusListStatus struct {
	StatusList StatusListRef `json:"status_list"`
}

// StatusObject holds the status and optional expiry for WIA client_status / KA key_storage_status.
type StatusObject struct {
	Status StatusListStatus `json:"status"`
	Exp    int64            `json:"exp,omitempty"`
}

// WKAPayload is the decoded payload of a Wallet Key Attestation JWT.
// Per CS-04 §7.1 / TS-03 clause 2.3.2.
type WKAPayload struct {
	Iat                int64             `json:"iat"`
	Exp                int64             `json:"exp"`
	AttestedKeys       []json.RawMessage `json:"attested_keys"`
	KeyStorage         []string          `json:"key_storage"`
	UserAuthentication []string          `json:"user_authentication"`
	Certification      string            `json:"certification"`
	WalletLink         string            `json:"wallet_link,omitempty"`
	KeyStorageStatus   StatusObject      `json:"key_storage_status"`
}

// WIAPayload is the decoded payload of a Wallet Instance Attestation JWT.
// Per CS-04 §7.1 / TS-03 clause 2.3.1.
type WIAPayload struct {
	Iat                                    int64        `json:"iat"`
	Exp                                    int64        `json:"exp"`
	Sub                                    string       `json:"sub"`
	WalletName                             string       `json:"wallet_name"`
	WalletVersion                          string       `json:"wallet_version"`
	WalletSolutionCertificationInformation interface{}  `json:"wallet_solution_certification_information"`
	WalletLink                             string       `json:"wallet_link,omitempty"`
	ClientStatus                           StatusObject `json:"client_status"`
	Cnf                                    CnfClaim     `json:"cnf"`
}

// CnfClaim is the confirmation claim containing a JWK.
type CnfClaim struct {
	JWK json.RawMessage `json:"jwk"`
}

// WKAResponse is the data payload returned by eudiw_wka_etsi.
type WKAResponse struct {
	WKA string `json:"wka"`
}

// WIAResponse is the data payload returned by eudiw_wia_etsi.
type WIAResponse struct {
	WIA string `json:"wia"`
}

// WIRevokeRequest is the data payload for eudiw_wi_revoke.
type WIRevokeRequest struct {
	Reason string `json:"reason,omitempty"` // e.g. "lost", "stolen", "compromised"
}

// WIRevokeResponse is the data payload returned by eudiw_wi_revoke.
type WIRevokeResponse struct {
	RevokedIndices int    `json:"revoked_indices"`
	Message        string `json:"message"`
}

// WISuspendRequest is the data payload for eudiw_wi_suspend.
type WISuspendRequest struct {
	Reason string `json:"reason,omitempty"`
}

// WISuspendResponse is the data payload returned by eudiw_wi_suspend.
type WISuspendResponse struct {
	SuspendedIndices int    `json:"suspended_indices"`
	Message          string `json:"message"`
}

// JWS typ header values — r2ps-service-types.md §2.1
const (
	TypRequest  = "r2ps-request+jwt"
	TypResponse = "r2ps-response+jwt"
)

// JWE typ header values — draft-santesson-r2ps §4.1
const (
	JWETyp1FA = "r2ps-1fa"
	JWETyp2FA = "r2ps-2fa"
)

// Error codes — draft-santesson-r2ps §4.2.2.2
const (
	ErrIllegalRequestData = "ILLEGAL_REQUEST_DATA"
	ErrUnauthorized       = "UNAUTHORIZED"
	ErrAccessDenied       = "ACCESS_DENIED"
	ErrIllegalState       = "ILLEGAL_STATE"
	ErrUnsupportedType    = "UNSUPPORTED_REQUEST_TYPE"
	ErrServerError        = "SERVER_ERROR"
	ErrTryLater           = "TRY_LATER"
)

// Deprecated aliases for backward compatibility during migration.
// These will be removed in a future version.
const (
	TypePINRegistration = Type2FARegistration
	TypePINChange       = Type2FAChange
	TypeAuthenticate    = Type2FAAuthenticate
	TypeHSMECKeygen     = TypeP256Generate
	TypeHSMECDSA        = TypeSignECDSA
	TypeHSMECDH         = TypeAgreeECDH
	TypeHSMListKeys     = "hsm_list_keys" // removed from spec register
	EncDevice           = "device"        // deprecated: use 1FA JWE mode
	EncUser             = "user"          // deprecated: use 2FA JWE mode
	PAKEProtocolOPAQUE  = TFAModeOPAQUE
	PAKEStateEvaluate   = StateEvaluate
	PAKEStateFinalize   = StateFinalize
)

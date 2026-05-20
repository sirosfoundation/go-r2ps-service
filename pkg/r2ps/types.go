package r2ps

// ServiceRequest is the JWS payload for an R2PS service request.
// See R2PS-protocol.md §3.1.1 and §3.1.2.
type ServiceRequest struct {
	Ver           string `json:"ver"`
	Nonce         string `json:"nonce"`
	Iat           int64  `json:"iat"`
	Enc           string `json:"enc"`
	Data          string `json:"data"`
	ClientID      string `json:"client_id"`
	Kid           string `json:"kid"`
	Context       string `json:"context"`
	Type          string `json:"type"`
	PakeSessionID string `json:"pake_session_id,omitempty"`
}

// ServiceResponse is the JWS payload for an R2PS service response.
// See R2PS-protocol.md §3.1.1 and §3.1.3.
type ServiceResponse struct {
	Ver   string `json:"ver"`
	Nonce string `json:"nonce"`
	Iat   int64  `json:"iat"`
	Enc   string `json:"enc"`
	Data  string `json:"data"`
}

// ErrorResponse is the JSON body returned on failure.
// See R2PS-protocol.md §3.2.
type ErrorResponse struct {
	ErrorCode    string `json:"error_code"`
	ErrorMessage string `json:"error_message"`
}

// PAKERequest is the decrypted service data for PAKE exchanges.
// See R2PS-protocol.md §3.3.1.1.
type PAKERequest struct {
	Protocol        string `json:"protocol"`
	State           string `json:"state"`
	Authorization   string `json:"authorization,omitempty"`
	Task            string `json:"task,omitempty"`
	SessionDuration int    `json:"session_duration,omitempty"`
	Req             string `json:"req"`
}

// PAKEResponse is the decrypted service data for PAKE responses.
// See R2PS-protocol.md §3.3.1.2.
type PAKEResponse struct {
	PakeSessionID         string `json:"pake_session_id,omitempty"`
	Resp                  string `json:"resp,omitempty"`
	Msg                   string `json:"msg,omitempty"`
	Task                  string `json:"task,omitempty"`
	SessionExpirationTime int64  `json:"session_expiration_time,omitempty"`
}

// Protocol version
const ProtocolVersion = "1.0"

// Encryption modes
const (
	EncDevice = "device"
	EncUser   = "user"
)

// PAKE protocol identifiers
const (
	PAKEProtocolOPAQUE = "opaque"
)

// PAKE states
const (
	PAKEStateEvaluate = "evaluate"
	PAKEStateFinalize = "finalize"
)

// Service types (PAKE)
const (
	TypePINRegistration = "pin_registration"
	TypePINChange       = "pin_change"
	TypeAuthenticate    = "authenticate"
)

// Service types (HSM) — defined in common-R2PS-service-types.md
const (
	TypeHSMECKeygen = "hsm_ec_keygen"
	TypeHSMECDSA    = "hsm_ecdsa"
	TypeHSMECDH     = "hsm_ecdh"
	TypeHSMListKeys = "hsm_list_keys"
)

// Error codes — see R2PS-protocol.md §3.2
const (
	ErrIllegalRequestData = "ILLEGAL_REQUEST_DATA"
	ErrUnauthorized       = "UNAUTHORIZED"
	ErrAccessDenied       = "ACCESS_DENIED"
	ErrIllegalState       = "ILLEGAL_STATE"
	ErrUnsupportedType    = "UNSUPPORTED_REQUEST_TYPE"
	ErrServerError        = "SERVER_ERROR"
	ErrTryLater           = "TRY_LATER"
)

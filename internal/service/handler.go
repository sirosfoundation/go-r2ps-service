package service

import "context"

// ServiceMode indicates whether a handler requires 2FA session verification.
const (
	Mode1FA = "1fa" // bypass session requirement
	Mode2FA = "2fa" // require verified 2FA session
)

// Handler processes decrypted service data for a specific service type.
type Handler interface {
	// Type returns the service type identifier (e.g., "sign_ecdsa").
	Type() string

	// Mode returns the authentication mode: Mode1FA or Mode2FA.
	Mode() string

	// Handle processes the decrypted request data and returns response data.
	Handle(ctx context.Context, clientID string, reqData []byte) ([]byte, error)
}

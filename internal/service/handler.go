package service

import "context"

// Handler processes decrypted service data for a specific service type.
type Handler interface {
	// Type returns the service type identifier (e.g., "hsm_ecdsa").
	Type() string

	// Handle processes the decrypted request data and returns response data.
	Handle(ctx context.Context, clientID string, reqData []byte) ([]byte, error)
}

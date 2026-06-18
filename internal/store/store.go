// Package store defines the persistence interface for R2PS server state.
package store

// Status values per Token Status List (RFC 9701), 2-bit encoding.
const (
	StatusValid     byte = 0
	StatusInvalid   byte = 1 // revoked
	StatusSuspended byte = 2
)

// PublicKeyInfo holds a public key exported from the WSCD (HSM).
// Only public material is stored — the private key never leaves the HSM.
type PublicKeyInfo struct {
	Kid          string `json:"kid" bson:"kid"`
	Curve        string `json:"curve" bson:"curve"`
	PubKey       []byte `json:"pub_key" bson:"pub_key"`             // compressed EC point
	CreationTime int64  `json:"creation_time" bson:"creation_time"` // Unix seconds
	ClientID     string `json:"client_id" bson:"client_id"`         // owning wallet instance
}

// Store provides persistence for R2PS attestation lifecycle state.
type Store interface {
	// AllocateIndex returns the next available status list index for a category ("ka" or "wia").
	AllocateIndex(category string) (int, error)

	// GetStatus returns the status of a status list entry.
	GetStatus(category string, idx int) (byte, error)

	// SetStatus sets the status of a status list entry.
	SetStatus(category string, idx int, status byte) error

	// GetAllStatuses returns all status entries for a category (for status list publishing).
	GetAllStatuses(category string) (map[int]byte, error)

	// RecordWUA records the association between a client and a status list index.
	RecordWUA(clientID, category string, idx int) error

	// GetClientIndices returns all status list indices for a client in a category.
	GetClientIndices(clientID, category string) ([]int, error)

	// RecordUsage marks that a WUA at idx has been presented/used.
	RecordUsage(category string, idx int) error

	// IsUsed returns true if the WUA at idx has already been used.
	IsUsed(category string, idx int) (bool, error)

	// PutPublicKey stores a public key exported from the WSCD.
	PutPublicKey(key PublicKeyInfo) error

	// GetPublicKey retrieves a public key by kid.
	GetPublicKey(kid string) (*PublicKeyInfo, error)

	// ListPublicKeys returns all public keys, optionally filtered by client ID.
	ListPublicKeys(clientID string) ([]PublicKeyInfo, error)

	// PutRecord stores an OPAQUE client record.
	PutRecord(clientID, context string, record []byte) error

	// GetRecord retrieves an OPAQUE client record.
	GetRecord(clientID, context string) ([]byte, error)

	// PutWebAuthnCredential stores a WebAuthn credential for a client.
	PutWebAuthnCredential(clientID, context string, cred WebAuthnCredential) error

	// GetWebAuthnCredential retrieves WebAuthn credentials for a client and context.
	GetWebAuthnCredential(clientID, context string) ([]WebAuthnCredential, error)

	// UpdateWebAuthnSignCount updates the signature counter for a credential.
	UpdateWebAuthnSignCount(clientID, context string, credentialID []byte, signCount uint32) error
}

// WebAuthnCredential holds a stored WebAuthn credential.
type WebAuthnCredential struct {
	CredentialID []byte `json:"credential_id" bson:"credential_id"`
	PublicKey    []byte `json:"public_key" bson:"public_key"` // Uncompressed SEC1 P-256 point
	SignCount    uint32 `json:"sign_count" bson:"sign_count"` // Last known signature counter
	AAGUID       []byte `json:"aaguid" bson:"aaguid"`         // Authenticator AAGUID
	CreatedAt    int64  `json:"created_at" bson:"created_at"` // Unix timestamp
}

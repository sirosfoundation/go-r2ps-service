package hsm

import "context"

// KeyInfo describes an HSM-managed key (internal representation).
type KeyInfo struct {
	Kid          string `json:"kid"`
	Curve        string `json:"curve"`
	CreationTime int64  `json:"creation_time"`
	// PubKey is the compressed EC public key bytes.
	PubKey []byte `json:"pub_key"`
}

// Backend abstracts HSM key operations.
type Backend interface {
	// GenerateECKey creates a new EC key pair and returns its identifier and public key.
	GenerateECKey(ctx context.Context, curve string) (kid string, pubKey []byte, err error)

	// Sign computes an ECDSA signature over hash using the key identified by kid.
	Sign(ctx context.Context, kid string, hash []byte) (signature []byte, err error)

	// ECDH performs ECDH key agreement between the key identified by kid and peerPubKey,
	// returning the raw shared secret.
	ECDH(ctx context.Context, kid string, peerPubKey []byte) (sharedSecret []byte, err error)

	// ListKeys returns all keys matching the given curves. If curves is nil, returns all keys.
	ListKeys(ctx context.Context, curves []string) ([]KeyInfo, error)
}

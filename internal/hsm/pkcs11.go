package hsm

import (
	"context"
	"fmt"

	"github.com/sirosfoundation/go-cryptoutil/pkcs11pool"
)

// PKCS11Config holds configuration for connecting to a PKCS#11 token.
type PKCS11Config struct {
	ModulePath string // path to the PKCS#11 shared library (e.g. /usr/lib/softhsm/libsofthsm2.so)
	SlotID     uint   // slot number
	PIN        string // user PIN for the token
	TokenLabel string // optional: find slot by label instead of ID
	PoolSize   int    // number of concurrent PKCS#11 sessions (default 4)
}

// PKCS11Backend implements Backend using pkcs11pool for session management.
type PKCS11Backend struct {
	pool *pkcs11pool.Pool
}

// NewPKCS11Backend connects to a PKCS#11 token and creates a session pool.
func NewPKCS11Backend(cfg PKCS11Config) (*PKCS11Backend, error) {
	pool, err := pkcs11pool.New(pkcs11pool.Config{
		ModulePath: cfg.ModulePath,
		SlotID:     cfg.SlotID,
		PIN:        cfg.PIN,
		TokenLabel: cfg.TokenLabel,
		PoolSize:   cfg.PoolSize,
		ReadWrite:  true, // r2ps needs R/W sessions for key generation
	})
	if err != nil {
		return nil, err
	}

	return &PKCS11Backend{pool: pool}, nil
}

// GenerateECKey creates a new EC key pair and returns its identifier and compressed public key.
func (b *PKCS11Backend) GenerateECKey(ctx context.Context, curveName string) (string, []byte, error) {
	return b.pool.GenerateECKey(ctx, curveName)
}

// Sign computes an ECDSA signature over hash using the key identified by kid.
// Returns an ASN.1 DER-encoded signature.
func (b *PKCS11Backend) Sign(ctx context.Context, kid string, hash []byte) ([]byte, error) {
	session, err := b.pool.Acquire(ctx)
	if err != nil {
		return nil, fmt.Errorf("acquire session: %w", err)
	}
	defer b.pool.Release(session)

	privHandle, err := b.pool.FindPrivateKey(session, pkcs11pool.KeyByID([]byte(kid)))
	if err != nil {
		return nil, fmt.Errorf("find key: %w", err)
	}

	return b.pool.SignECDSA(session, privHandle, hash)
}

// ECDH performs ECDH key agreement between the key identified by kid and peerPubKey.
func (b *PKCS11Backend) ECDH(ctx context.Context, kid string, peerPubKey []byte) ([]byte, error) {
	return b.pool.ECDH(ctx, pkcs11pool.KeyByID([]byte(kid)), peerPubKey)
}

// ListKeys returns all EC keys matching the given curves.
func (b *PKCS11Backend) ListKeys(ctx context.Context, curves []string) ([]KeyInfo, error) {
	poolKeys, err := b.pool.ListECKeys(ctx, curves)
	if err != nil {
		return nil, err
	}

	keys := make([]KeyInfo, len(poolKeys))
	for i, k := range poolKeys {
		keys[i] = KeyInfo{
			Kid:          k.Kid,
			Curve:        k.Curve,
			CreationTime: 0, // PKCS#11 does not track creation time
			PubKey:       k.PubKey,
		}
	}
	return keys, nil
}

// PoolSize returns the configured pool size.
func (b *PKCS11Backend) PoolSize() int {
	return b.pool.PoolSize()
}

// Close logs out and cleans up all PKCS#11 sessions.
func (b *PKCS11Backend) Close() error {
	return b.pool.Close()
}

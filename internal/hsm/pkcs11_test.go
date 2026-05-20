package hsm

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"testing"

	icrypto "github.com/sirosfoundation/go-r2ps-service/internal/crypto"
)

func TestPKCS11_GenerateAndSign(t *testing.T) {
	backend, cleanup := NewTestBackend(t)
	defer cleanup()
	ctx := context.Background()

	kid, pubBytes, err := backend.GenerateECKey(ctx, "P-256")
	if err != nil {
		t.Fatalf("GenerateECKey: %v", err)
	}
	if kid == "" {
		t.Fatal("empty kid")
	}
	if len(pubBytes) == 0 {
		t.Fatal("empty public key")
	}

	// Sign a hash
	hash := sha256.Sum256([]byte("test data"))
	sig, err := backend.Sign(ctx, kid, hash[:])
	if err != nil {
		t.Fatalf("Sign: %v", err)
	}

	// Verify with public key
	pub, err := icrypto.DecompressPublicKey(elliptic.P256(), pubBytes)
	if err != nil {
		t.Fatalf("decompress pubkey: %v", err)
	}

	if !ecdsa.VerifyASN1(pub, hash[:], sig) {
		t.Error("signature verification failed")
	}
}

func TestPKCS11_ECDH(t *testing.T) {
	backend, cleanup := NewTestBackend(t)
	defer cleanup()
	ctx := context.Background()

	kid, _, err := backend.GenerateECKey(ctx, "P-256")
	if err != nil {
		t.Fatalf("GenerateECKey: %v", err)
	}

	// Generate a peer key (in software)
	peerKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("generate peer key: %v", err)
	}
	peerPubBytes := icrypto.MarshalCompressedPublicKey(&peerKey.PublicKey)

	secret, err := backend.ECDH(ctx, kid, peerPubBytes)
	if err != nil {
		t.Fatalf("ECDH: %v", err)
	}

	if len(secret) == 0 {
		t.Fatal("empty shared secret")
	}

	// Verify the peer can compute the same secret
	keys, err := backend.ListKeys(ctx, nil)
	if err != nil {
		t.Fatalf("ListKeys: %v", err)
	}
	if len(keys) != 1 {
		t.Fatalf("expected 1 key, got %d", len(keys))
	}

	hsmPub, err := icrypto.DecompressPublicKey(elliptic.P256(), keys[0].PubKey)
	if err != nil {
		t.Fatalf("decompress HSM pubkey: %v", err)
	}

	peerSecret, err := icrypto.ECDHSharedSecret(peerKey, hsmPub)
	if err != nil {
		t.Fatalf("peer ECDH: %v", err)
	}

	if string(secret) != string(peerSecret) {
		t.Error("shared secrets don't match")
	}
}

func TestPKCS11_ListKeys(t *testing.T) {
	backend, cleanup := NewTestBackend(t)
	defer cleanup()
	ctx := context.Background()

	backend.GenerateECKey(ctx, "P-256")
	backend.GenerateECKey(ctx, "P-256")
	backend.GenerateECKey(ctx, "P-384")

	// List all
	keys, err := backend.ListKeys(ctx, nil)
	if err != nil {
		t.Fatalf("ListKeys: %v", err)
	}
	if len(keys) != 3 {
		t.Errorf("expected 3 keys, got %d", len(keys))
	}

	// Filter by curve
	keys256, err := backend.ListKeys(ctx, []string{"P-256"})
	if err != nil {
		t.Fatalf("ListKeys P-256: %v", err)
	}
	if len(keys256) != 2 {
		t.Errorf("expected 2 P-256 keys, got %d", len(keys256))
	}
}

func TestPKCS11_SignUnknownKey(t *testing.T) {
	backend, cleanup := NewTestBackend(t)
	defer cleanup()

	_, err := backend.Sign(context.Background(), "nonexistent", []byte("hash"))
	if err == nil {
		t.Error("expected error for unknown key")
	}
}

func TestPKCS11_UnsupportedCurve(t *testing.T) {
	backend, cleanup := NewTestBackend(t)
	defer cleanup()

	_, _, err := backend.GenerateECKey(context.Background(), "secp256k1")
	if err == nil {
		t.Error("expected error for unsupported curve")
	}
}

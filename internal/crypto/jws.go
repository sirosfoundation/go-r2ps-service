package crypto

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"errors"
	"fmt"

	"github.com/go-jose/go-jose/v4"
)

// SignJWS creates a JWS compact serialization of payload signed with key.
// The key must be an *ecdsa.PrivateKey (ES256 for P-256, ES384 for P-384).
func SignJWS(payload []byte, key *ecdsa.PrivateKey, kid string) (string, error) {
	alg, err := ecAlgorithm(key.Curve)
	if err != nil {
		return "", err
	}

	opts := jose.SignerOptions{}
	opts.WithType("JOSE")
	if kid != "" {
		opts.WithHeader(jose.HeaderKey("kid"), kid)
	}

	signer, err := jose.NewSigner(jose.SigningKey{Algorithm: alg, Key: key}, &opts)
	if err != nil {
		return "", fmt.Errorf("create signer: %w", err)
	}

	jws, err := signer.Sign(payload)
	if err != nil {
		return "", fmt.Errorf("sign: %w", err)
	}

	return jws.CompactSerialize()
}

// VerifyJWS verifies a JWS compact serialization and returns the payload.
func VerifyJWS(compact string, key *ecdsa.PublicKey) ([]byte, error) {
	jws, err := jose.ParseSigned(compact, []jose.SignatureAlgorithm{jose.ES256, jose.ES384, jose.ES512})
	if err != nil {
		return nil, fmt.Errorf("parse JWS: %w", err)
	}

	payload, err := jws.Verify(key)
	if err != nil {
		return nil, fmt.Errorf("verify JWS: %w", err)
	}

	return payload, nil
}

// GenerateECKey generates a new ECDSA key pair for the given curve.
func GenerateECKey(curve elliptic.Curve) (*ecdsa.PrivateKey, error) {
	return ecdsa.GenerateKey(curve, rand.Reader)
}

// PublicKeyFromPrivate extracts the public key and returns it as crypto.PublicKey.
func PublicKeyFromPrivate(key *ecdsa.PrivateKey) crypto.PublicKey {
	return &key.PublicKey
}

func ecAlgorithm(curve elliptic.Curve) (jose.SignatureAlgorithm, error) {
	switch curve {
	case elliptic.P256():
		return jose.ES256, nil
	case elliptic.P384():
		return jose.ES384, nil
	case elliptic.P521():
		return jose.ES512, nil
	default:
		return "", errors.New("unsupported curve")
	}
}

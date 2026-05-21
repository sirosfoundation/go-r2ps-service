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
// The typ parameter sets the JWS typ header; if empty, defaults to "JOSE".
func SignJWS(payload []byte, key *ecdsa.PrivateKey, kid string, opts ...string) (string, error) {
	alg, err := ecAlgorithm(key.Curve)
	if err != nil {
		return "", err
	}

	typ := "JOSE"
	if len(opts) > 0 && opts[0] != "" {
		typ = opts[0]
	}

	sopts := jose.SignerOptions{}
	sopts.WithType(jose.ContentType(typ))
	if kid != "" {
		sopts.WithHeader(jose.HeaderKey("kid"), kid)
	}

	signer, err := jose.NewSigner(jose.SigningKey{Algorithm: alg, Key: key}, &sopts)
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

// PeekJWSHeaders parses a JWS compact serialization and returns the protected
// headers without verifying the signature. This is used to extract kid before
// looking up the verification key.
func PeekJWSHeaders(compact string) (map[string]interface{}, error) {
	jws, err := jose.ParseSigned(compact, []jose.SignatureAlgorithm{jose.ES256, jose.ES384, jose.ES512})
	if err != nil {
		return nil, fmt.Errorf("parse JWS: %w", err)
	}

	if len(jws.Signatures) == 0 {
		return nil, errors.New("no signatures in JWS")
	}

	headers := make(map[string]interface{})
	h := jws.Signatures[0].Protected
	if h.KeyID != "" {
		headers["kid"] = h.KeyID
	}
	if v, ok := h.ExtraHeaders[jose.HeaderType]; ok {
		if s, ok := v.(string); ok && s != "" {
			headers["typ"] = s
		}
	}
	return headers, nil
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

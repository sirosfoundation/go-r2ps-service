package crypto

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"fmt"

	"github.com/go-jose/go-jose/v4"
)

// EncryptJWE encrypts plaintext using ECDH-ES+A256KW key agreement with
// A256GCM content encryption, returning JWE compact serialization.
// recipientKey is the public key of the recipient.
func EncryptJWE(plaintext []byte, recipientKey *ecdsa.PublicKey) (string, error) {
	enc := jose.A256GCM
	alg, err := ecdhAlgorithm(recipientKey.Curve)
	if err != nil {
		return "", err
	}

	encrypter, err := jose.NewEncrypter(enc, jose.Recipient{
		Algorithm: alg,
		Key:       recipientKey,
	}, (&jose.EncrypterOptions{}).WithContentType("application/octet-stream"))
	if err != nil {
		return "", fmt.Errorf("create encrypter: %w", err)
	}

	jwe, err := encrypter.Encrypt(plaintext)
	if err != nil {
		return "", fmt.Errorf("encrypt: %w", err)
	}

	return jwe.CompactSerialize()
}

// DecryptJWE decrypts a JWE compact serialization using the recipient's private key.
func DecryptJWE(compact string, key *ecdsa.PrivateKey) ([]byte, error) {
	jwe, err := jose.ParseEncrypted(compact, []jose.KeyAlgorithm{jose.ECDH_ES_A256KW, jose.ECDH_ES_A128KW}, []jose.ContentEncryption{jose.A256GCM, jose.A128GCM})
	if err != nil {
		return nil, fmt.Errorf("parse JWE: %w", err)
	}

	plaintext, err := jwe.Decrypt(key)
	if err != nil {
		return nil, fmt.Errorf("decrypt JWE: %w", err)
	}

	return plaintext, nil
}

// EncryptJWESymmetric encrypts plaintext using a symmetric key (for enc=user mode).
// The key should be 32 bytes for A256GCM.
func EncryptJWESymmetric(plaintext []byte, key []byte) (string, error) {
	encrypter, err := jose.NewEncrypter(jose.A256GCM, jose.Recipient{
		Algorithm: jose.DIRECT,
		Key:       key,
	}, (&jose.EncrypterOptions{}).WithContentType("application/octet-stream"))
	if err != nil {
		return "", fmt.Errorf("create symmetric encrypter: %w", err)
	}

	jwe, err := encrypter.Encrypt(plaintext)
	if err != nil {
		return "", fmt.Errorf("encrypt: %w", err)
	}

	return jwe.CompactSerialize()
}

// DecryptJWESymmetric decrypts a JWE compact serialization using a symmetric key.
func DecryptJWESymmetric(compact string, key []byte) ([]byte, error) {
	jwe, err := jose.ParseEncrypted(compact, []jose.KeyAlgorithm{jose.DIRECT}, []jose.ContentEncryption{jose.A256GCM})
	if err != nil {
		return nil, fmt.Errorf("parse JWE: %w", err)
	}

	plaintext, err := jwe.Decrypt(key)
	if err != nil {
		return nil, fmt.Errorf("decrypt JWE: %w", err)
	}

	return plaintext, nil
}

func ecdhAlgorithm(curve elliptic.Curve) (jose.KeyAlgorithm, error) {
	switch curve {
	case elliptic.P256(), elliptic.P384(), elliptic.P521():
		return jose.ECDH_ES_A256KW, nil
	default:
		return "", fmt.Errorf("unsupported curve for ECDH: %v", curve)
	}
}

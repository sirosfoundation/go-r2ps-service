package crypto

import (
	"crypto/ecdsa"
	"crypto/sha256"
	"encoding/binary"
	"fmt"

	"github.com/go-jose/go-jose/v4"
	"golang.org/x/crypto/hkdf"
)

// EncryptJWE1FA encrypts plaintext using ECDH-ES / A256GCM for 1FA mode.
// apu and apv are set per r2ps.md §3.1: apu=client_id (requests) or context (responses),
// apv=context (requests) or client_id (responses).
func EncryptJWE1FA(plaintext []byte, recipientKey *ecdsa.PublicKey, kid, apu, apv string) (string, error) {
	opts := (&jose.EncrypterOptions{}).WithContentType(jose.ContentType("JWT"))
	opts.WithHeader(jose.HeaderKey("kid"), kid)
	opts.WithHeader(jose.HeaderKey("apu"), apu)
	opts.WithHeader(jose.HeaderKey("apv"), apv)

	encrypter, err := jose.NewEncrypter(jose.A256GCM, jose.Recipient{
		Algorithm: jose.ECDH_ES,
		Key:       recipientKey,
	}, opts)
	if err != nil {
		return "", fmt.Errorf("create 1FA encrypter: %w", err)
	}

	jwe, err := encrypter.Encrypt(plaintext)
	if err != nil {
		return "", fmt.Errorf("encrypt 1FA: %w", err)
	}

	return jwe.CompactSerialize()
}

// DecryptJWE1FA decrypts a 1FA mode JWE compact serialization.
func DecryptJWE1FA(compact string, key *ecdsa.PrivateKey) ([]byte, error) {
	jwe, err := jose.ParseEncrypted(compact,
		[]jose.KeyAlgorithm{jose.ECDH_ES},
		[]jose.ContentEncryption{jose.A256GCM})
	if err != nil {
		return nil, fmt.Errorf("parse 1FA JWE: %w", err)
	}

	plaintext, err := jwe.Decrypt(key)
	if err != nil {
		return nil, fmt.Errorf("decrypt 1FA JWE: %w", err)
	}

	return plaintext, nil
}

// Derive2FAKEK derives the key-encryption key for 2FA mode using HKDF per r2ps.md §3.2.
// direction is "c2s" or "s2c", sessionID is the 2FA session identifier.
func Derive2FAKEK(sessionKey []byte, direction, sessionID string) ([]byte, error) {
	dst := "R2PS-2FA-KEK-1.0"
	info := hkdfInfo(dst, direction, sessionID)

	h := hkdf.New(sha256.New, sessionKey, nil, info)
	kek := make([]byte, 32)
	if _, err := h.Read(kek); err != nil {
		return nil, fmt.Errorf("HKDF derive KEK: %w", err)
	}
	return kek, nil
}

// hkdfInfo builds the info parameter for 2FA KEK derivation per r2ps.md §3.2.
func hkdfInfo(dst, direction, sessionID string) []byte {
	buf := make([]byte, 0, 4+len(dst)+4+len(direction)+4+len(sessionID))
	buf = appendLenPrefixed(buf, []byte(dst))
	buf = appendLenPrefixed(buf, []byte(direction))
	buf = appendLenPrefixed(buf, []byte(sessionID))
	return buf
}

func appendLenPrefixed(buf, data []byte) []byte {
	var lenBuf [4]byte
	binary.BigEndian.PutUint32(lenBuf[:], uint32(len(data)))
	buf = append(buf, lenBuf[:]...)
	buf = append(buf, data...)
	return buf
}

// EncryptJWE2FA encrypts plaintext for 2FA mode using A256KW / A256GCM with a
// KEK derived from the session key. kid is the session identifier.
func EncryptJWE2FA(plaintext []byte, sessionKey []byte, sessionID, direction string) (string, error) {
	kek, err := Derive2FAKEK(sessionKey, direction, sessionID)
	if err != nil {
		return "", err
	}

	opts := (&jose.EncrypterOptions{}).WithContentType(jose.ContentType("JWT"))
	opts.WithHeader(jose.HeaderKey("kid"), sessionID)

	encrypter, err := jose.NewEncrypter(jose.A256GCM, jose.Recipient{
		Algorithm: jose.A256KW,
		Key:       kek,
	}, opts)
	if err != nil {
		return "", fmt.Errorf("create 2FA encrypter: %w", err)
	}

	jwe, err := encrypter.Encrypt(plaintext)
	if err != nil {
		return "", fmt.Errorf("encrypt 2FA: %w", err)
	}

	return jwe.CompactSerialize()
}

// DecryptJWE2FA decrypts a 2FA mode JWE compact serialization.
func DecryptJWE2FA(compact string, sessionKey []byte, sessionID, direction string) ([]byte, error) {
	kek, err := Derive2FAKEK(sessionKey, direction, sessionID)
	if err != nil {
		return nil, err
	}

	jwe, err := jose.ParseEncrypted(compact,
		[]jose.KeyAlgorithm{jose.A256KW},
		[]jose.ContentEncryption{jose.A256GCM})
	if err != nil {
		return nil, fmt.Errorf("parse 2FA JWE: %w", err)
	}

	plaintext, err := jwe.Decrypt(kek)
	if err != nil {
		return nil, fmt.Errorf("decrypt 2FA JWE: %w", err)
	}

	return plaintext, nil
}

// Legacy functions kept for backward compatibility during migration.

// EncryptJWE encrypts plaintext using ECDH-ES+A256KW (legacy device mode).
// Deprecated: Use EncryptJWE1FA instead.
func EncryptJWE(plaintext []byte, recipientKey *ecdsa.PublicKey) (string, error) {
	encrypter, err := jose.NewEncrypter(jose.A256GCM, jose.Recipient{
		Algorithm: jose.ECDH_ES_A256KW,
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

// DecryptJWE decrypts a JWE compact serialization (legacy, accepts both ECDH-ES and ECDH-ES+A256KW).
// Deprecated: Use DecryptJWE1FA instead.
func DecryptJWE(compact string, key *ecdsa.PrivateKey) ([]byte, error) {
	jwe, err := jose.ParseEncrypted(compact,
		[]jose.KeyAlgorithm{jose.ECDH_ES_A256KW, jose.ECDH_ES_A128KW, jose.ECDH_ES},
		[]jose.ContentEncryption{jose.A256GCM, jose.A128GCM})
	if err != nil {
		return nil, fmt.Errorf("parse JWE: %w", err)
	}

	plaintext, err := jwe.Decrypt(key)
	if err != nil {
		return nil, fmt.Errorf("decrypt JWE: %w", err)
	}

	return plaintext, nil
}

// EncryptJWESymmetric encrypts plaintext using dir/A256GCM (legacy user mode).
// Deprecated: Use EncryptJWE2FA instead.
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

// DecryptJWESymmetric decrypts a JWE compact serialization using a symmetric key (legacy).
// Deprecated: Use DecryptJWE2FA instead.
func DecryptJWESymmetric(compact string, key []byte) ([]byte, error) {
	jwe, err := jose.ParseEncrypted(compact,
		[]jose.KeyAlgorithm{jose.DIRECT, jose.A256KW},
		[]jose.ContentEncryption{jose.A256GCM})
	if err != nil {
		return nil, fmt.Errorf("parse JWE: %w", err)
	}

	plaintext, err := jwe.Decrypt(key)
	if err != nil {
		return nil, fmt.Errorf("decrypt JWE: %w", err)
	}

	return plaintext, nil
}

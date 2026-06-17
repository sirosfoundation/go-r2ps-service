package webauthn

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"encoding/json"
	"fmt"
	"time"
)

// ChallengeToken is the encrypted stateless token for FIDO2 authentication.
// Per spec §4.2.3.1: A256GCM(server_token_key, {iat, client_id, context, challenge})
type ChallengeToken struct {
	Iat       int64  `json:"iat"`
	ClientID  string `json:"client_id"`
	Context   string `json:"context"`
	Challenge string `json:"challenge"` // base64url-encoded challenge
}

// TokenEncryptor handles encrypted stateless challenge tokens.
type TokenEncryptor struct {
	gcm cipher.AEAD
	ttl time.Duration
}

// NewTokenEncryptor creates an encryptor with the given 256-bit key.
func NewTokenEncryptor(key []byte, ttl time.Duration) (*TokenEncryptor, error) {
	if len(key) != 32 {
		return nil, fmt.Errorf("token key must be 32 bytes, got %d", len(key))
	}

	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, fmt.Errorf("create AES cipher: %w", err)
	}

	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, fmt.Errorf("create GCM: %w", err)
	}

	if ttl == 0 {
		ttl = 60 * time.Second
	}

	return &TokenEncryptor{gcm: gcm, ttl: ttl}, nil
}

// Encrypt creates an encrypted token.
func (e *TokenEncryptor) Encrypt(token *ChallengeToken) ([]byte, error) {
	plaintext, err := json.Marshal(token)
	if err != nil {
		return nil, fmt.Errorf("marshal token: %w", err)
	}

	nonce := make([]byte, e.gcm.NonceSize())
	if _, err := rand.Read(nonce); err != nil {
		return nil, fmt.Errorf("generate nonce: %w", err)
	}

	// nonce || ciphertext (ciphertext includes GCM tag)
	ciphertext := e.gcm.Seal(nonce, nonce, plaintext, nil)
	return ciphertext, nil
}

// Decrypt decrypts and validates a token. Returns error if expired or tampered.
func (e *TokenEncryptor) Decrypt(data []byte) (*ChallengeToken, error) {
	nonceSize := e.gcm.NonceSize()
	if len(data) < nonceSize+1 {
		return nil, fmt.Errorf("token too short")
	}

	nonce := data[:nonceSize]
	ciphertext := data[nonceSize:]

	plaintext, err := e.gcm.Open(nil, nonce, ciphertext, nil)
	if err != nil {
		return nil, fmt.Errorf("decrypt token: %w", err)
	}

	var token ChallengeToken
	if err := json.Unmarshal(plaintext, &token); err != nil {
		return nil, fmt.Errorf("unmarshal token: %w", err)
	}

	// Check freshness
	elapsed := time.Since(time.Unix(token.Iat, 0))
	if elapsed > e.ttl {
		return nil, fmt.Errorf("token expired (age: %v, ttl: %v)", elapsed, e.ttl)
	}

	return &token, nil
}

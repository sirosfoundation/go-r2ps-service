package webauthn

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"encoding/asn1"
	"math/big"
	"testing"
	"time"
)

func TestTokenEncryptDecrypt(t *testing.T) {
	key := make([]byte, 32)
	if _, err := rand.Read(key); err != nil {
		t.Fatal(err)
	}

	enc, err := NewTokenEncryptor(key, 60*time.Second)
	if err != nil {
		t.Fatal(err)
	}

	token := &ChallengeToken{
		Iat:       time.Now().Unix(),
		ClientID:  "test-client",
		Context:   "test-context",
		Challenge: "dGVzdC1jaGFsbGVuZ2U",
	}

	ciphertext, err := enc.Encrypt(token)
	if err != nil {
		t.Fatal(err)
	}

	decrypted, err := enc.Decrypt(ciphertext)
	if err != nil {
		t.Fatal(err)
	}

	if decrypted.ClientID != token.ClientID {
		t.Errorf("client_id: got %q, want %q", decrypted.ClientID, token.ClientID)
	}
	if decrypted.Context != token.Context {
		t.Errorf("context: got %q, want %q", decrypted.Context, token.Context)
	}
	if decrypted.Challenge != token.Challenge {
		t.Errorf("challenge: got %q, want %q", decrypted.Challenge, token.Challenge)
	}
}

func TestTokenExpiry(t *testing.T) {
	key := make([]byte, 32)
	if _, err := rand.Read(key); err != nil {
		t.Fatal(err)
	}

	// Very short TTL
	enc, err := NewTokenEncryptor(key, 1*time.Millisecond)
	if err != nil {
		t.Fatal(err)
	}

	token := &ChallengeToken{
		Iat:       time.Now().Add(-1 * time.Second).Unix(), // 1 second ago
		ClientID:  "test",
		Context:   "ctx",
		Challenge: "ch",
	}

	ciphertext, err := enc.Encrypt(token)
	if err != nil {
		t.Fatal(err)
	}

	_, err = enc.Decrypt(ciphertext)
	if err == nil {
		t.Error("expected expiry error")
	}
}

func TestTokenTampered(t *testing.T) {
	key := make([]byte, 32)
	if _, err := rand.Read(key); err != nil {
		t.Fatal(err)
	}

	enc, err := NewTokenEncryptor(key, 60*time.Second)
	if err != nil {
		t.Fatal(err)
	}

	token := &ChallengeToken{
		Iat:       time.Now().Unix(),
		ClientID:  "test",
		Context:   "ctx",
		Challenge: "ch",
	}

	ciphertext, err := enc.Encrypt(token)
	if err != nil {
		t.Fatal(err)
	}

	// Tamper with ciphertext
	ciphertext[len(ciphertext)-1] ^= 0xFF

	_, err = enc.Decrypt(ciphertext)
	if err == nil {
		t.Error("expected tamper detection error")
	}
}

func TestTokenKeyLengthValidation(t *testing.T) {
	_, err := NewTokenEncryptor(make([]byte, 16), 60*time.Second)
	if err == nil {
		t.Error("expected error for 16-byte key")
	}
}

func TestParseAuthenticatorData(t *testing.T) {
	// Construct minimal valid authenticator data (37 bytes)
	// rpIdHash (32) + flags (1) + signCount (4)
	data := make([]byte, 37)
	data[32] = FlagUP | FlagUV // flags: UP + UV set
	data[33] = 0               // signCount big-endian
	data[34] = 0
	data[35] = 0
	data[36] = 5

	ad, err := ParseAuthenticatorData(data)
	if err != nil {
		t.Fatal(err)
	}

	if ad.Flags&FlagUP == 0 {
		t.Error("UP flag not set")
	}
	if ad.Flags&FlagUV == 0 {
		t.Error("UV flag not set")
	}
	if ad.SignCount != 5 {
		t.Errorf("signCount: got %d, want 5", ad.SignCount)
	}
}

func TestParseAuthenticatorDataTooShort(t *testing.T) {
	_, err := ParseAuthenticatorData(make([]byte, 10))
	if err == nil {
		t.Error("expected error for short data")
	}
}

func TestVerifyRPIDHash(t *testing.T) {
	rpID := "example.com"
	expected := sha256.Sum256([]byte(rpID))

	ad := &AuthenticatorData{RPIDHash: expected}
	if err := VerifyRPIDHash(ad, rpID); err != nil {
		t.Errorf("expected success for matching rpIdHash: %v", err)
	}

	// Mismatch
	ad2 := &AuthenticatorData{}
	if err := VerifyRPIDHash(ad2, rpID); err == nil {
		t.Error("expected error for mismatched rpIdHash")
	}
}

func TestVerifyECDSASignature(t *testing.T) {
	privKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}

	hash := make([]byte, 32)
	if _, err := rand.Read(hash); err != nil {
		t.Fatal(err)
	}

	r, s, err := ecdsa.Sign(rand.Reader, privKey, hash)
	if err != nil {
		t.Fatal(err)
	}

	// DER encode using asn1
	type ecdsaSig struct {
		R, S *big.Int
	}
	sig, err := asn1.Marshal(ecdsaSig{R: r, S: s})
	if err != nil {
		t.Fatal(err)
	}

	if !verifyECDSASignature(&privKey.PublicKey, hash, sig) {
		t.Error("expected valid signature")
	}

	// Tamper with hash
	tampered := make([]byte, 32)
	copy(tampered, hash)
	tampered[0] ^= 0xFF
	if verifyECDSASignature(&privKey.PublicKey, tampered, sig) {
		t.Error("expected invalid signature with tampered hash")
	}
}

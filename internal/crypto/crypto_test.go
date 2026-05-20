package crypto

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/elliptic"
	"testing"
)

func TestJWSRoundTrip(t *testing.T) {
	for _, curve := range []elliptic.Curve{elliptic.P256(), elliptic.P384()} {
		t.Run(curve.Params().Name, func(t *testing.T) {
			key, err := GenerateECKey(curve)
			if err != nil {
				t.Fatalf("generate key: %v", err)
			}

			payload := []byte(`{"ver":"1.0","nonce":"test"}`)
			compact, err := SignJWS(payload, key, "test-kid")
			if err != nil {
				t.Fatalf("sign: %v", err)
			}

			got, err := VerifyJWS(compact, &key.PublicKey)
			if err != nil {
				t.Fatalf("verify: %v", err)
			}

			if !bytes.Equal(got, payload) {
				t.Errorf("payload mismatch: got %q, want %q", got, payload)
			}
		})
	}
}

func TestJWSVerifyWrongKey(t *testing.T) {
	key1, _ := GenerateECKey(elliptic.P256())
	key2, _ := GenerateECKey(elliptic.P256())

	compact, err := SignJWS([]byte("test"), key1, "")
	if err != nil {
		t.Fatalf("sign: %v", err)
	}

	_, err = VerifyJWS(compact, &key2.PublicKey)
	if err == nil {
		t.Error("expected verification to fail with wrong key")
	}
}

func TestJWERoundTrip(t *testing.T) {
	key, _ := GenerateECKey(elliptic.P256())
	plaintext := []byte("hello R2PS")

	compact, err := EncryptJWE(plaintext, &key.PublicKey)
	if err != nil {
		t.Fatalf("encrypt: %v", err)
	}

	got, err := DecryptJWE(compact, key)
	if err != nil {
		t.Fatalf("decrypt: %v", err)
	}

	if !bytes.Equal(got, plaintext) {
		t.Errorf("plaintext mismatch: got %q, want %q", got, plaintext)
	}
}

func TestJWEDecryptWrongKey(t *testing.T) {
	key1, _ := GenerateECKey(elliptic.P256())
	key2, _ := GenerateECKey(elliptic.P256())

	compact, err := EncryptJWE([]byte("secret"), &key1.PublicKey)
	if err != nil {
		t.Fatalf("encrypt: %v", err)
	}

	_, err = DecryptJWE(compact, key2)
	if err == nil {
		t.Error("expected decryption to fail with wrong key")
	}
}

func TestJWESymmetricRoundTrip(t *testing.T) {
	key := make([]byte, 32)
	for i := range key {
		key[i] = byte(i)
	}
	plaintext := []byte("symmetric encryption test")

	compact, err := EncryptJWESymmetric(plaintext, key)
	if err != nil {
		t.Fatalf("encrypt: %v", err)
	}

	got, err := DecryptJWESymmetric(compact, key)
	if err != nil {
		t.Fatalf("decrypt: %v", err)
	}

	if !bytes.Equal(got, plaintext) {
		t.Errorf("plaintext mismatch: got %q, want %q", got, plaintext)
	}
}

func TestECDHSharedSecret(t *testing.T) {
	key1, _ := GenerateECKey(elliptic.P256())
	key2, _ := GenerateECKey(elliptic.P256())

	secret1, err := ECDHSharedSecret(key1, &key2.PublicKey)
	if err != nil {
		t.Fatalf("ECDH 1→2: %v", err)
	}

	secret2, err := ECDHSharedSecret(key2, &key1.PublicKey)
	if err != nil {
		t.Fatalf("ECDH 2→1: %v", err)
	}

	if !bytes.Equal(secret1, secret2) {
		t.Error("shared secrets don't match")
	}
}

func TestECDHCurveMismatch(t *testing.T) {
	key256, _ := GenerateECKey(elliptic.P256())
	key384, _ := GenerateECKey(elliptic.P384())

	_, err := ECDHSharedSecret(key256, &key384.PublicKey)
	if err == nil {
		t.Error("expected error for curve mismatch")
	}
}

func TestEphemeralECDH(t *testing.T) {
	serverKey, _ := GenerateECKey(elliptic.P256())

	ephPub, clientSecret, err := GenerateEphemeralECDH(&serverKey.PublicKey)
	if err != nil {
		t.Fatalf("ephemeral ECDH: %v", err)
	}

	serverSecret, err := ECDHSharedSecret(serverKey, ephPub)
	if err != nil {
		t.Fatalf("server ECDH: %v", err)
	}

	if !bytes.Equal(clientSecret, serverSecret) {
		t.Error("ephemeral shared secrets don't match")
	}
}

func TestPublicKeyMarshalRoundTrip(t *testing.T) {
	key, _ := GenerateECKey(elliptic.P256())

	// Uncompressed
	data := MarshalUncompressedPublicKey(&key.PublicKey)
	got, err := UnmarshalPublicKey(elliptic.P256(), data)
	if err != nil {
		t.Fatalf("unmarshal uncompressed: %v", err)
	}
	if !key.PublicKey.Equal(got) {
		t.Error("uncompressed round-trip failed")
	}

	// Compressed
	compressed := MarshalCompressedPublicKey(&key.PublicKey)
	got2, err := DecompressPublicKey(elliptic.P256(), compressed)
	if err != nil {
		t.Fatalf("decompress: %v", err)
	}
	if !key.PublicKey.Equal(got2) {
		t.Error("compressed round-trip failed")
	}
}

func TestPublicKeyCompressedBothParities(t *testing.T) {
	// Generate keys until we get both even and odd Y
	var evenKey, oddKey *ecdsa.PrivateKey
	for i := 0; i < 1000 && (evenKey == nil || oddKey == nil); i++ {
		k, _ := GenerateECKey(elliptic.P256())
		if k.PublicKey.Y.Bit(0) == 0 {
			evenKey = k
		} else {
			oddKey = k
		}
	}

	for _, tc := range []struct {
		name string
		key  *ecdsa.PrivateKey
	}{
		{"even_Y", evenKey},
		{"odd_Y", oddKey},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if tc.key == nil {
				t.Skip("didn't generate key with this parity")
			}
			compressed := MarshalCompressedPublicKey(&tc.key.PublicKey)
			got, err := DecompressPublicKey(elliptic.P256(), compressed)
			if err != nil {
				t.Fatalf("decompress: %v", err)
			}
			if !tc.key.PublicKey.Equal(got) {
				t.Error("round-trip failed")
			}
		})
	}
}

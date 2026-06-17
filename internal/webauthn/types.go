// Package webauthn implements FIDO2/WebAuthn credential management
// and assertion validation for R2PS 2FA authentication.
package webauthn

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/sha256"
	"encoding/base64"
	"encoding/binary"
	"encoding/json"
	"fmt"
	"math/big"
)

// Credential represents a registered WebAuthn credential.
type Credential struct {
	CredentialID []byte          // Credential identifier
	PublicKey    *ecdsa.PublicKey // P-256 credential public key
	SignCount    uint32          // Last known signature counter
	AAGUID      []byte          // Authenticator AAGUID
	CreatedAt   int64           // Unix timestamp of registration
}

// ClientDataJSON represents the parsed clientDataJSON structure.
type ClientDataJSON struct {
	Type        string `json:"type"`
	Challenge   string `json:"challenge"`
	Origin      string `json:"origin"`
	CrossOrigin bool   `json:"crossOrigin,omitempty"`
}

// AuthenticatorData holds parsed authenticator data.
type AuthenticatorData struct {
	RPIDHash  [32]byte
	Flags     byte
	SignCount uint32
	// For attestation (makeCredential) only:
	AAGUID       []byte
	CredentialID []byte
	PublicKey    *ecdsa.PublicKey
}

const (
	// Flag bits in authenticator data
	FlagUP byte = 0x01 // User Present
	FlagUV byte = 0x04 // User Verified
	FlagAT byte = 0x40 // Attested credential data present
)

// ParseClientDataJSON decodes and parses the clientDataJSON.
func ParseClientDataJSON(raw []byte) (*ClientDataJSON, error) {
	var cd ClientDataJSON
	if err := json.Unmarshal(raw, &cd); err != nil {
		return nil, fmt.Errorf("parse clientDataJSON: %w", err)
	}
	return &cd, nil
}

// ParseAuthenticatorData parses the raw authenticator data bytes.
func ParseAuthenticatorData(data []byte) (*AuthenticatorData, error) {
	if len(data) < 37 {
		return nil, fmt.Errorf("authenticator data too short: %d bytes", len(data))
	}

	ad := &AuthenticatorData{}
	copy(ad.RPIDHash[:], data[0:32])
	ad.Flags = data[32]
	ad.SignCount = binary.BigEndian.Uint32(data[33:37])

	// If attested credential data is present (AT flag)
	if ad.Flags&FlagAT != 0 {
		if len(data) < 55 {
			return nil, fmt.Errorf("authenticator data too short for attested credential data")
		}
		ad.AAGUID = make([]byte, 16)
		copy(ad.AAGUID, data[37:53])

		credIDLen := binary.BigEndian.Uint16(data[53:55])
		if len(data) < 55+int(credIDLen) {
			return nil, fmt.Errorf("authenticator data too short for credential ID")
		}
		ad.CredentialID = make([]byte, credIDLen)
		copy(ad.CredentialID, data[55:55+credIDLen])

		// Parse COSE public key (simplified: assume EC2 P-256)
		coseKeyData := data[55+credIDLen:]
		pubKey, err := parseCOSEKey(coseKeyData)
		if err != nil {
			return nil, fmt.Errorf("parse COSE public key: %w", err)
		}
		ad.PublicKey = pubKey
	}

	return ad, nil
}

// VerifyRPIDHash checks that rpIdHash matches SHA-256(rpId).
func VerifyRPIDHash(authData *AuthenticatorData, rpID string) error {
	expected := sha256.Sum256([]byte(rpID))
	if authData.RPIDHash != expected {
		return fmt.Errorf("rpIdHash mismatch")
	}
	return nil
}

// parseCOSEKey parses a minimal CBOR-encoded COSE_Key (EC2, P-256).
// This is a simplified parser that handles the common case.
func parseCOSEKey(data []byte) (*ecdsa.PublicKey, error) {
	// Decode CBOR map to extract x and y coordinates.
	// COSE_Key EC2: { 1:2, 3:-7, -1:1, -2:x, -3:y }
	// kty=2 (EC2), alg=-7 (ES256), crv=1 (P-256)
	m, err := decodeCBORMap(data)
	if err != nil {
		return nil, fmt.Errorf("decode CBOR: %w", err)
	}

	xBytes, ok := m[-2]
	if !ok || len(xBytes) != 32 {
		return nil, fmt.Errorf("missing or invalid x-coordinate")
	}
	yBytes, ok := m[-3]
	if !ok || len(yBytes) != 32 {
		return nil, fmt.Errorf("missing or invalid y-coordinate")
	}

	x := new(big.Int).SetBytes(xBytes)
	y := new(big.Int).SetBytes(yBytes)

	pub := &ecdsa.PublicKey{
		Curve: elliptic.P256(),
		X:     x,
		Y:     y,
	}

	if !pub.Curve.IsOnCurve(x, y) {
		return nil, fmt.Errorf("public key point not on P-256 curve")
	}

	return pub, nil
}

// decodeCBORMap is a minimal CBOR map decoder for COSE_Key.
// Handles integer keys with byte string values.
func decodeCBORMap(data []byte) (map[int][]byte, error) {
	if len(data) == 0 {
		return nil, fmt.Errorf("empty CBOR data")
	}

	result := make(map[int][]byte)
	pos := 0

	// Map header
	major := data[pos] >> 5
	additional := data[pos] & 0x1f
	if major != 5 { // major type 5 = map
		return nil, fmt.Errorf("expected CBOR map, got major type %d", major)
	}
	pos++

	numPairs := int(additional)
	if additional == 24 {
		if pos >= len(data) {
			return nil, fmt.Errorf("truncated CBOR")
		}
		numPairs = int(data[pos])
		pos++
	}

	for i := 0; i < numPairs && pos < len(data); i++ {
		// Decode key (integer)
		key, n, err := decodeCBORInt(data[pos:])
		if err != nil {
			return nil, fmt.Errorf("decode map key %d: %w", i, err)
		}
		pos += n

		// Decode value (byte string or integer — we only extract byte strings)
		if pos >= len(data) {
			return nil, fmt.Errorf("truncated CBOR at value %d", i)
		}

		valMajor := data[pos] >> 5
		valAdditional := data[pos] & 0x1f
		pos++

		switch valMajor {
		case 2: // byte string
			length := int(valAdditional)
			if valAdditional == 24 {
				if pos >= len(data) {
					return nil, fmt.Errorf("truncated CBOR byte string length")
				}
				length = int(data[pos])
				pos++
			} else if valAdditional == 25 {
				if pos+1 >= len(data) {
					return nil, fmt.Errorf("truncated CBOR byte string length")
				}
				length = int(binary.BigEndian.Uint16(data[pos : pos+2]))
				pos += 2
			}
			if pos+length > len(data) {
				return nil, fmt.Errorf("truncated CBOR byte string data")
			}
			val := make([]byte, length)
			copy(val, data[pos:pos+length])
			result[key] = val
			pos += length
		case 0: // unsigned integer (skip)
			if valAdditional < 24 {
				// inline value, already consumed
			} else if valAdditional == 24 {
				pos++
			} else if valAdditional == 25 {
				pos += 2
			}
		case 1: // negative integer (skip)
			if valAdditional < 24 {
				// inline value, already consumed
			} else if valAdditional == 24 {
				pos++
			} else if valAdditional == 25 {
				pos += 2
			}
		default:
			// Skip unknown types (crude: just advance)
			return result, nil
		}
	}

	return result, nil
}

// decodeCBORInt decodes a CBOR integer (positive or negative).
func decodeCBORInt(data []byte) (int, int, error) {
	if len(data) == 0 {
		return 0, 0, fmt.Errorf("empty data")
	}

	major := data[0] >> 5
	additional := data[0] & 0x1f

	var value int
	consumed := 1

	switch {
	case additional < 24:
		value = int(additional)
	case additional == 24:
		if len(data) < 2 {
			return 0, 0, fmt.Errorf("truncated")
		}
		value = int(data[1])
		consumed = 2
	case additional == 25:
		if len(data) < 3 {
			return 0, 0, fmt.Errorf("truncated")
		}
		value = int(binary.BigEndian.Uint16(data[1:3]))
		consumed = 3
	default:
		return 0, 0, fmt.Errorf("unsupported additional value: %d", additional)
	}

	if major == 1 { // negative integer
		value = -1 - value
	}

	return value, consumed, nil
}

// EncodeBase64URL encodes bytes to base64url without padding.
func EncodeBase64URL(data []byte) string {
	return base64.RawURLEncoding.EncodeToString(data)
}

// DecodeBase64URL decodes base64url (with or without padding).
func DecodeBase64URL(s string) ([]byte, error) {
	// Try without padding first, then with padding
	b, err := base64.RawURLEncoding.DecodeString(s)
	if err != nil {
		b, err = base64.URLEncoding.DecodeString(s)
	}
	return b, err
}

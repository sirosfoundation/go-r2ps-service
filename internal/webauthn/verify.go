package webauthn

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/sha256"
	"encoding/asn1"
	"encoding/binary"
	"fmt"
	"math/big"
)

// AssertionData contains the parsed WebAuthn assertion fields.
type AssertionData struct {
	CredentialID      []byte
	AuthenticatorData []byte
	ClientDataJSON    []byte
	Signature         []byte
}

// VerifyAssertion validates a WebAuthn assertion against a registered credential.
// It checks:
//   - clientDataJSON.type == "webauthn.get"
//   - clientDataJSON.challenge matches expected challenge
//   - clientDataJSON.origin matches expected origin
//   - rpIdHash matches SHA-256(rpID)
//   - UP and UV flags are set
//   - Signature is valid over (authData || SHA-256(clientDataJSON))
//   - signCount is strictly greater than stored (if either is non-zero)
func VerifyAssertion(
	assertion *AssertionData,
	credential *Credential,
	expectedChallenge string,
	rpID string,
	allowedOrigins []string,
) (*AuthenticatorData, error) {
	// 1. Parse clientDataJSON
	clientData, err := ParseClientDataJSON(assertion.ClientDataJSON)
	if err != nil {
		return nil, fmt.Errorf("parse clientDataJSON: %w", err)
	}

	// 2. Verify type
	if clientData.Type != "webauthn.get" {
		return nil, fmt.Errorf("unexpected clientData type: %q", clientData.Type)
	}

	// 3. Verify challenge
	if clientData.Challenge != expectedChallenge {
		return nil, fmt.Errorf("challenge mismatch")
	}

	// 4. Verify origin
	originValid := false
	for _, o := range allowedOrigins {
		if clientData.Origin == o {
			originValid = true
			break
		}
	}
	if !originValid {
		return nil, fmt.Errorf("origin %q not in allowed list", clientData.Origin)
	}

	// 5. Parse authenticator data
	authData, err := ParseAuthenticatorData(assertion.AuthenticatorData)
	if err != nil {
		return nil, fmt.Errorf("parse authenticator data: %w", err)
	}

	// 6. Verify rpIdHash
	if err := VerifyRPIDHash(authData, rpID); err != nil {
		return nil, err
	}

	// 7. Verify UP flag
	if authData.Flags&FlagUP == 0 {
		return nil, fmt.Errorf("user present (UP) flag not set")
	}

	// 8. Verify UV flag
	if authData.Flags&FlagUV == 0 {
		return nil, fmt.Errorf("user verified (UV) flag not set")
	}

	// 9. Verify signature: sign(authData || SHA-256(clientDataJSON))
	clientDataHash := sha256.Sum256(assertion.ClientDataJSON)
	verificationData := append(assertion.AuthenticatorData, clientDataHash[:]...)
	hash := sha256.Sum256(verificationData)

	if !verifyECDSASignature(credential.PublicKey, hash[:], assertion.Signature) {
		return nil, fmt.Errorf("signature verification failed")
	}

	// 10. Clone detection: check signCount
	if authData.SignCount != 0 || credential.SignCount != 0 {
		if authData.SignCount <= credential.SignCount {
			return nil, fmt.Errorf("signCount not incremented (possible cloned authenticator): got %d, stored %d",
				authData.SignCount, credential.SignCount)
		}
	}

	return authData, nil
}

// verifyECDSASignature verifies an ECDSA signature (DER-encoded) over the given hash.
func verifyECDSASignature(pub *ecdsa.PublicKey, hash, sig []byte) bool {
	// WebAuthn signatures are DER-encoded ASN.1
	var ecSig struct {
		R, S *big.Int
	}
	if _, err := asn1.Unmarshal(sig, &ecSig); err != nil {
		return false
	}

	return ecdsa.Verify(pub, hash, ecSig.R, ecSig.S)
}

// VerifyRegistration validates a WebAuthn registration ceremony.
// Returns the extracted credential ID and public key on success.
func VerifyRegistration(
	attestationObject []byte,
	clientDataJSON []byte,
	expectedChallenge string,
	rpID string,
	allowedOrigins []string,
) (*AuthenticatorData, error) {
	// 1. Parse clientDataJSON
	clientData, err := ParseClientDataJSON(clientDataJSON)
	if err != nil {
		return nil, fmt.Errorf("parse clientDataJSON: %w", err)
	}

	// 2. Verify type
	if clientData.Type != "webauthn.create" {
		return nil, fmt.Errorf("unexpected clientData type: %q", clientData.Type)
	}

	// 3. Verify challenge
	if clientData.Challenge != expectedChallenge {
		return nil, fmt.Errorf("challenge mismatch")
	}

	// 4. Verify origin
	originValid := false
	for _, o := range allowedOrigins {
		if clientData.Origin == o {
			originValid = true
			break
		}
	}
	if !originValid {
		return nil, fmt.Errorf("origin %q not in allowed list", clientData.Origin)
	}

	// 5. Parse attestation object (CBOR: { fmt, attStmt, authData })
	authDataBytes, err := extractAuthDataFromAttestation(attestationObject)
	if err != nil {
		return nil, fmt.Errorf("extract authData from attestation: %w", err)
	}

	// 6. Parse authenticator data
	authData, err := ParseAuthenticatorData(authDataBytes)
	if err != nil {
		return nil, fmt.Errorf("parse authenticator data: %w", err)
	}

	// 7. Verify rpIdHash
	if err := VerifyRPIDHash(authData, rpID); err != nil {
		return nil, err
	}

	// 8. Verify UP + UV flags
	if authData.Flags&FlagUP == 0 {
		return nil, fmt.Errorf("user present (UP) flag not set")
	}
	if authData.Flags&FlagUV == 0 {
		return nil, fmt.Errorf("user verified (UV) flag not set")
	}

	// 9. Verify attested credential data is present
	if authData.Flags&FlagAT == 0 {
		return nil, fmt.Errorf("attested credential data (AT) flag not set")
	}
	if authData.PublicKey == nil {
		return nil, fmt.Errorf("no public key in attested credential data")
	}

	return authData, nil
}

// extractAuthDataFromAttestation extracts the authData field from a CBOR-encoded
// attestation object. Simplified parser for the common case.
func extractAuthDataFromAttestation(data []byte) ([]byte, error) {
	// The attestation object is a CBOR map with keys: "fmt", "attStmt", "authData"
	// We need to find the "authData" byte string.
	// This is a simplified CBOR parser for this specific structure.
	if len(data) < 3 {
		return nil, fmt.Errorf("attestation object too short")
	}

	pos := 0
	// Map header
	major := data[pos] >> 5
	additional := data[pos] & 0x1f
	if major != 5 {
		return nil, fmt.Errorf("expected CBOR map, got major type %d", major)
	}
	pos++

	numPairs := int(additional)
	if additional == 24 {
		numPairs = int(data[pos])
		pos++
	}

	for i := 0; i < numPairs && pos < len(data); i++ {
		// Decode key (text string)
		keyMajor := data[pos] >> 5
		keyAdditional := data[pos] & 0x1f
		pos++

		if keyMajor != 3 { // text string
			// Skip this key-value pair
			pos = skipCBORValue(data, pos-1)
			pos = skipCBORValue(data, pos)
			continue
		}

		keyLen := int(keyAdditional)
		if keyAdditional == 24 {
			keyLen = int(data[pos])
			pos++
		}
		if pos+keyLen > len(data) {
			return nil, fmt.Errorf("truncated key string")
		}
		key := string(data[pos : pos+keyLen])
		pos += keyLen

		if key == "authData" {
			// Value should be a byte string
			valMajor := data[pos] >> 5
			valAdditional := data[pos] & 0x1f
			pos++
			if valMajor != 2 {
				return nil, fmt.Errorf("authData is not a byte string (major %d)", valMajor)
			}

			valLen := int(valAdditional)
			if valAdditional == 24 {
				valLen = int(data[pos])
				pos++
			} else if valAdditional == 25 {
				valLen = int(binary.BigEndian.Uint16(data[pos : pos+2]))
				pos += 2
			} else if valAdditional == 26 {
				valLen = int(binary.BigEndian.Uint32(data[pos : pos+4]))
				pos += 4
			}

			if pos+valLen > len(data) {
				return nil, fmt.Errorf("truncated authData")
			}
			return data[pos : pos+valLen], nil
		}

		// Skip the value
		pos = skipCBORValue(data, pos)
	}

	return nil, fmt.Errorf("authData not found in attestation object")
}

// skipCBORValue skips a CBOR value starting at data[pos] and returns the new position.
// This is a simplified implementation that handles common cases.
func skipCBORValue(data []byte, pos int) int {
	if pos >= len(data) {
		return pos
	}

	major := data[pos] >> 5
	additional := data[pos] & 0x1f
	pos++

	var length int
	switch {
	case additional < 24:
		length = int(additional)
	case additional == 24:
		length = int(data[pos])
		pos++
	case additional == 25:
		length = int(binary.BigEndian.Uint16(data[pos : pos+2]))
		pos += 2
	case additional == 26:
		length = int(binary.BigEndian.Uint32(data[pos : pos+4]))
		pos += 4
	}

	switch major {
	case 0, 1: // integer: already consumed
		return pos
	case 2, 3: // byte/text string
		return pos + length
	case 4: // array
		for i := 0; i < length; i++ {
			pos = skipCBORValue(data, pos)
		}
		return pos
	case 5: // map
		for i := 0; i < length; i++ {
			pos = skipCBORValue(data, pos)
			pos = skipCBORValue(data, pos)
		}
		return pos
	default:
		return pos
	}
}

// MarshalPublicKey serializes an ECDSA public key to uncompressed SEC1 format.
func MarshalPublicKey(pub *ecdsa.PublicKey) []byte {
	return elliptic.Marshal(pub.Curve, pub.X, pub.Y)
}

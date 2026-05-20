package crypto

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"fmt"
	"math/big"
)

// RandomBytes generates n cryptographically random bytes.
func RandomBytes(n int) []byte {
	b := make([]byte, n)
	if _, err := rand.Read(b); err != nil {
		panic("crypto/rand: " + err.Error())
	}
	return b
}

// ECDHSharedSecret performs ephemeral-static ECDH and returns the raw shared secret.
// This is used for enc=device mode where the client encrypts to the server's static key.
func ECDHSharedSecret(privKey *ecdsa.PrivateKey, pubKey *ecdsa.PublicKey) ([]byte, error) {
	if privKey.Curve != pubKey.Curve {
		return nil, fmt.Errorf("curve mismatch: %v vs %v", privKey.Curve.Params().Name, pubKey.Curve.Params().Name)
	}

	x, _ := privKey.Curve.ScalarMult(pubKey.X, pubKey.Y, privKey.D.Bytes())
	if x == nil {
		return nil, fmt.Errorf("ECDH scalar multiplication failed")
	}

	// Pad to curve byte size
	byteLen := (privKey.Curve.Params().BitSize + 7) / 8
	secret := x.Bytes()
	if len(secret) < byteLen {
		padded := make([]byte, byteLen)
		copy(padded[byteLen-len(secret):], secret)
		secret = padded
	}

	return secret, nil
}

// GenerateEphemeralECDH generates an ephemeral key pair, computes the shared
// secret with the peer's public key, and returns (ephemeral public key, shared secret).
func GenerateEphemeralECDH(peerPubKey *ecdsa.PublicKey) (*ecdsa.PublicKey, []byte, error) {
	ephemeral, err := ecdsa.GenerateKey(peerPubKey.Curve, rand.Reader)
	if err != nil {
		return nil, nil, fmt.Errorf("generate ephemeral key: %w", err)
	}

	secret, err := ECDHSharedSecret(ephemeral, peerPubKey)
	if err != nil {
		return nil, nil, err
	}

	return &ephemeral.PublicKey, secret, nil
}

// MarshalUncompressedPublicKey serializes an EC public key to uncompressed point format (04 || x || y).
func MarshalUncompressedPublicKey(pub *ecdsa.PublicKey) []byte {
	return elliptic.Marshal(pub.Curve, pub.X, pub.Y)
}

// UnmarshalPublicKey deserializes an EC public key from uncompressed point format.
func UnmarshalPublicKey(curve elliptic.Curve, data []byte) (*ecdsa.PublicKey, error) {
	x, y := elliptic.Unmarshal(curve, data)
	if x == nil {
		return nil, fmt.Errorf("invalid EC point")
	}

	return &ecdsa.PublicKey{
		Curve: curve,
		X:     x,
		Y:     y,
	}, nil
}

// MarshalCompressedPublicKey serializes an EC public key to compressed point format (02/03 || x).
func MarshalCompressedPublicKey(pub *ecdsa.PublicKey) []byte {
	byteLen := (pub.Curve.Params().BitSize + 7) / 8
	compressed := make([]byte, 1+byteLen)

	if pub.Y.Bit(0) == 0 {
		compressed[0] = 0x02
	} else {
		compressed[0] = 0x03
	}

	xBytes := pub.X.Bytes()
	copy(compressed[1+byteLen-len(xBytes):], xBytes)

	return compressed
}

// DecompressPublicKey deserializes an EC public key from compressed point format.
func DecompressPublicKey(curve elliptic.Curve, data []byte) (*ecdsa.PublicKey, error) {
	if len(data) == 0 {
		return nil, fmt.Errorf("empty data")
	}

	byteLen := (curve.Params().BitSize + 7) / 8

	switch data[0] {
	case 0x04:
		return UnmarshalPublicKey(curve, data)
	case 0x02, 0x03:
		if len(data) != 1+byteLen {
			return nil, fmt.Errorf("invalid compressed key length")
		}
		x := new(big.Int).SetBytes(data[1:])
		y, err := decompressY(curve, x, data[0] == 0x03)
		if err != nil {
			return nil, err
		}
		return &ecdsa.PublicKey{Curve: curve, X: x, Y: y}, nil
	default:
		return nil, fmt.Errorf("unsupported point format: 0x%02x", data[0])
	}
}

func decompressY(curve elliptic.Curve, x *big.Int, odd bool) (*big.Int, error) {
	p := curve.Params().P

	// y² = x³ - 3x + b (mod p) for NIST curves
	x3 := new(big.Int).Mul(x, x)
	x3.Mul(x3, x)
	x3.Mod(x3, p)

	threeX := new(big.Int).Mul(big.NewInt(3), x)
	threeX.Mod(threeX, p)

	y2 := new(big.Int).Sub(x3, threeX)
	y2.Add(y2, curve.Params().B)
	y2.Mod(y2, p)

	// y = sqrt(y²) mod p
	y := new(big.Int).ModSqrt(y2, p)
	if y == nil {
		return nil, fmt.Errorf("no square root exists for x coordinate")
	}

	if y.Bit(0) != boolToBit(odd) {
		y.Sub(p, y)
	}

	return y, nil
}

func boolToBit(b bool) uint {
	if b {
		return 1
	}
	return 0
}

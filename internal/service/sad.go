package service

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"strings"
)

// SADPolicy defines the Signature Activation Data binding requirements.
// When enabled, 2FA sessions created with a `task` field containing hash references
// will only authorize signing those specific hashes.

// SADTask represents a parsed task field for signature activation.
// Task format: "sign:<hex-hash1>,<hex-hash2>,..." or arbitrary string for non-signing tasks.
const sadTaskPrefix = "sign:"

// ParseSADTask extracts authorized hashes from a task string.
// Returns nil if the task is not a signing task.
func ParseSADTask(task string) [][]byte {
	if !strings.HasPrefix(task, sadTaskPrefix) {
		return nil
	}
	hashList := strings.TrimPrefix(task, sadTaskPrefix)
	if hashList == "" {
		return nil
	}
	parts := strings.Split(hashList, ",")
	hashes := make([][]byte, 0, len(parts))
	for _, p := range parts {
		p = strings.TrimSpace(p)
		if p == "" {
			continue
		}
		h, err := hex.DecodeString(p)
		if err != nil {
			continue
		}
		// Accept SHA-256, SHA-384, SHA-512 hash lengths
		if len(h) == 32 || len(h) == 48 || len(h) == 64 {
			hashes = append(hashes, h)
		}
	}
	if len(hashes) == 0 {
		return nil
	}
	return hashes
}

// ValidateSAD checks that a to-be-signed hash is authorized by the session's task binding.
// Returns nil if authorized, error if not.
func ValidateSAD(sessionTask string, tbsHash []byte) error {
	authorizedHashes := ParseSADTask(sessionTask)
	if authorizedHashes == nil {
		// Session was not bound to specific hashes — this is a policy decision.
		// For SCAL2 compliance, a session SHOULD be bound to specific hashes.
		// Return nil to allow backward compatibility; strict mode can reject this.
		return nil
	}

	// Check if tbsHash matches any authorized hash
	for _, auth := range authorizedHashes {
		if bytesEqualConstant(auth, tbsHash) {
			return nil
		}
	}

	// Also check SHA-256(tbsHash) in case the task contains a commitment
	commitment := sha256.Sum256(tbsHash)
	for _, auth := range authorizedHashes {
		if len(auth) == 32 && bytesEqualConstant(auth, commitment[:]) {
			return nil
		}
	}

	return fmt.Errorf("tbs_hash not authorized by session task (SAD binding violation)")
}

// bytesEqualConstant provides constant-time comparison for hash values.
func bytesEqualConstant(a, b []byte) bool {
	if len(a) != len(b) {
		return false
	}
	var result byte
	for i := range a {
		result |= a[i] ^ b[i]
	}
	return result == 0
}

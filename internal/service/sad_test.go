package service

import (
	"testing"
)

func TestParseSADTask(t *testing.T) {
	tests := []struct {
		name    string
		task    string
		wantNil bool
		wantLen int
	}{
		{"empty task", "", true, 0},
		{"non-signing task", "keygen", true, 0},
		{"sign prefix no hashes", "sign:", true, 0},
		{"single sha256 hash", "sign:" + repeat("ab", 32), false, 1},
		{"two sha256 hashes", "sign:" + repeat("aa", 32) + "," + repeat("bb", 32), false, 2},
		{"invalid hex", "sign:xyz", true, 0},
		{"wrong length", "sign:aabb", true, 0},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := ParseSADTask(tt.task)
			if tt.wantNil && result != nil {
				t.Errorf("expected nil, got %v", result)
			}
			if !tt.wantNil && result == nil {
				t.Fatalf("expected non-nil result")
			}
			if !tt.wantNil && len(result) != tt.wantLen {
				t.Errorf("expected %d hashes, got %d", tt.wantLen, len(result))
			}
		})
	}
}

func TestValidateSAD(t *testing.T) {
	// A valid SHA-256 hash (32 bytes)
	hash1 := make([]byte, 32)
	for i := range hash1 {
		hash1[i] = byte(i)
	}
	hash2 := make([]byte, 32)
	for i := range hash2 {
		hash2[i] = byte(i + 100)
	}

	// Encode as hex for task
	task := "sign:" + bytesToHex(hash1) + "," + bytesToHex(hash2)

	t.Run("authorized hash passes", func(t *testing.T) {
		if err := ValidateSAD(task, hash1); err != nil {
			t.Errorf("expected nil, got %v", err)
		}
	})

	t.Run("second authorized hash passes", func(t *testing.T) {
		if err := ValidateSAD(task, hash2); err != nil {
			t.Errorf("expected nil, got %v", err)
		}
	})

	t.Run("unauthorized hash fails", func(t *testing.T) {
		unauthorized := make([]byte, 32)
		for i := range unauthorized {
			unauthorized[i] = 0xFF
		}
		if err := ValidateSAD(task, unauthorized); err == nil {
			t.Error("expected error for unauthorized hash")
		}
	})

	t.Run("empty task allows any hash", func(t *testing.T) {
		if err := ValidateSAD("", hash1); err != nil {
			t.Errorf("expected nil for empty task, got %v", err)
		}
	})

	t.Run("non-sign task allows any hash", func(t *testing.T) {
		if err := ValidateSAD("keygen", hash1); err != nil {
			t.Errorf("expected nil for non-sign task, got %v", err)
		}
	})
}

func TestBytesEqualConstant(t *testing.T) {
	a := []byte{1, 2, 3, 4}
	b := []byte{1, 2, 3, 4}
	c := []byte{1, 2, 3, 5}
	d := []byte{1, 2, 3}

	if !bytesEqualConstant(a, b) {
		t.Error("expected equal")
	}
	if bytesEqualConstant(a, c) {
		t.Error("expected not equal")
	}
	if bytesEqualConstant(a, d) {
		t.Error("expected not equal for different lengths")
	}
}

func repeat(s string, n int) string {
	result := ""
	for i := 0; i < n; i++ {
		result += s
	}
	return result
}

func bytesToHex(b []byte) string {
	const hexChars = "0123456789abcdef"
	result := make([]byte, len(b)*2)
	for i, v := range b {
		result[i*2] = hexChars[v>>4]
		result[i*2+1] = hexChars[v&0x0f]
	}
	return string(result)
}

package hsm

import (
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"testing"
)

// TestPKCS11Config returns a PKCS11Config pointing at a freshly initialized SoftHSM2 token.
// The caller must call the returned cleanup function when done.
func TestPKCS11Config(t *testing.T) (PKCS11Config, func()) {
	t.Helper()

	// Find SoftHSM2 library
	modulePath := findSoftHSM2()
	if modulePath == "" {
		t.Skip("SoftHSM2 not found — install softhsm2 to run PKCS#11 tests")
	}

	// Create a temp dir for tokens
	tokenDir, err := os.MkdirTemp("", "softhsm-test-*")
	if err != nil {
		t.Fatalf("create temp dir: %v", err)
	}

	// Write softhsm2.conf
	confPath := filepath.Join(tokenDir, "softhsm2.conf")
	confContent := fmt.Sprintf("directories.tokendir = %s\nobjectstore.backend = file\n", tokenDir)
	if err := os.WriteFile(confPath, []byte(confContent), 0o600); err != nil {
		os.RemoveAll(tokenDir)
		t.Fatalf("write softhsm2.conf: %v", err)
	}

	// Set SOFTHSM2_CONF before initializing token
	origConf := os.Getenv("SOFTHSM2_CONF")
	os.Setenv("SOFTHSM2_CONF", confPath)

	// Initialize token
	cmd := exec.Command("softhsm2-util",
		"--init-token", "--free",
		"--label", "test-r2ps",
		"--pin", "1234",
		"--so-pin", "5678",
	)
	cmd.Env = append(os.Environ(), "SOFTHSM2_CONF="+confPath)
	out, err := cmd.CombinedOutput()
	if err != nil {
		os.RemoveAll(tokenDir)
		os.Setenv("SOFTHSM2_CONF", origConf)
		t.Fatalf("softhsm2-util init-token: %v\n%s", err, out)
	}

	cleanup := func() {
		os.Setenv("SOFTHSM2_CONF", origConf)
		os.RemoveAll(tokenDir)
	}

	return PKCS11Config{
		ModulePath: modulePath,
		TokenLabel: "test-r2ps",
		PIN:        "1234",
	}, cleanup
}

// NewTestBackend creates a PKCS11Backend connected to a test SoftHSM2 token.
func NewTestBackend(t *testing.T) (*PKCS11Backend, func()) {
	t.Helper()

	cfg, cleanup := TestPKCS11Config(t)
	backend, err := NewPKCS11Backend(cfg)
	if err != nil {
		cleanup()
		t.Fatalf("NewPKCS11Backend: %v", err)
	}

	return backend, func() {
		backend.Close()
		cleanup()
	}
}

func findSoftHSM2() string {
	paths := []string{
		"/usr/lib/softhsm/libsofthsm2.so",
		"/usr/lib/x86_64-linux-gnu/softhsm/libsofthsm2.so",
		"/usr/local/lib/softhsm/libsofthsm2.so",
		"/usr/lib64/softhsm/libsofthsm2.so",
		"/opt/homebrew/lib/softhsm/libsofthsm2.so",
	}
	for _, p := range paths {
		if _, err := os.Stat(p); err == nil {
			return p
		}
	}
	return ""
}

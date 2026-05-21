package main

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/sirosfoundation/go-r2ps-service/internal/pake"
	"github.com/sirosfoundation/go-r2ps-service/internal/service"
	"github.com/sirosfoundation/go-r2ps-service/pkg/r2ps"
)

func TestHandleHealthz(t *testing.T) {
	req := httptest.NewRequest("GET", "/healthz", nil)
	w := httptest.NewRecorder()
	handleHealthz(w, req)

	if w.Code != http.StatusOK {
		t.Errorf("status = %d, want 200", w.Code)
	}
	if ct := w.Header().Get("Content-Type"); ct != "application/json" {
		t.Errorf("Content-Type = %q", ct)
	}
	if !strings.Contains(w.Body.String(), `"ok"`) {
		t.Errorf("body = %q", w.Body.String())
	}
}

func TestMapErrorStatus(t *testing.T) {
	tests := []struct {
		code   string
		status int
	}{
		{"UNAUTHORIZED", http.StatusUnauthorized},
		{"ACCESS_DENIED", http.StatusForbidden},
		{"UNSUPPORTED_REQUEST_TYPE", http.StatusUnsupportedMediaType},
		{"ILLEGAL_REQUEST_DATA", http.StatusBadRequest},
		{"ILLEGAL_STATE", http.StatusConflict},
		{"TRY_LATER", http.StatusServiceUnavailable},
		{"SERVER_ERROR", http.StatusInternalServerError},
		{"UNKNOWN", http.StatusInternalServerError},
	}
	for _, tc := range tests {
		got := mapErrorStatus(tc.code)
		if got != tc.status {
			t.Errorf("mapErrorStatus(%q) = %d, want %d", tc.code, got, tc.status)
		}
	}
}

func TestWriteError(t *testing.T) {
	w := httptest.NewRecorder()
	writeError(w, http.StatusBadRequest, "ILLEGAL_REQUEST_DATA", "test msg")

	if w.Code != http.StatusBadRequest {
		t.Errorf("status = %d", w.Code)
	}

	var resp struct {
		ErrorCode    string `json:"error_code"`
		ErrorMessage string `json:"error_message"`
	}
	if err := json.NewDecoder(w.Body).Decode(&resp); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if resp.ErrorCode != "ILLEGAL_REQUEST_DATA" {
		t.Errorf("error_code = %q", resp.ErrorCode)
	}
}

func TestEnvOr(t *testing.T) {
	if got := envOr("NONEXISTENT_R2PS_VAR", "fallback"); got != "fallback" {
		t.Errorf("envOr = %q, want fallback", got)
	}

	t.Setenv("TEST_R2PS_VAR", "value")
	if got := envOr("TEST_R2PS_VAR", "fallback"); got != "value" {
		t.Errorf("envOr = %q, want value", got)
	}
}

func TestEnvInt(t *testing.T) {
	if got := envInt("NONEXISTENT_R2PS_VAR", 42); got != 42 {
		t.Errorf("envInt = %d, want 42", got)
	}

	t.Setenv("TEST_R2PS_INT", "7")
	if got := envInt("TEST_R2PS_INT", 42); got != 7 {
		t.Errorf("envInt = %d, want 7", got)
	}

	t.Setenv("TEST_R2PS_INT", "bad")
	if got := envInt("TEST_R2PS_INT", 42); got != 42 {
		t.Errorf("envInt with bad value = %d, want 42", got)
	}
}

func TestEnvDuration(t *testing.T) {
	if got := envDuration("NONEXISTENT_R2PS_VAR", 0); got != 0 {
		t.Errorf("envDuration = %v, want 0", got)
	}

	t.Setenv("TEST_R2PS_DUR", "10s")
	if got := envDuration("TEST_R2PS_DUR", 0); got.Seconds() != 10 {
		t.Errorf("envDuration = %v, want 10s", got)
	}

	t.Setenv("TEST_R2PS_DUR", "bad")
	if got := envDuration("TEST_R2PS_DUR", 0); got != 0 {
		t.Errorf("envDuration with bad value = %v, want 0", got)
	}
}

func TestInitLogging(t *testing.T) {
	// Just verify it doesn't panic with various levels
	for _, level := range []string{"DEBUG", "INFO", "WARN", "WARNING", "ERROR", ""} {
		t.Setenv("R2PS_LOG_LEVEL", level)
		t.Setenv("R2PS_LOG_FORMAT", "json")
		initLogging()
	}
	t.Setenv("R2PS_LOG_FORMAT", "text")
	initLogging()
}

func TestIsInfrastructurePanic(t *testing.T) {
	tests := []struct {
		stack string
		want  bool
	}{
		{"goroutine 1 [running]:\nmain.r2psHandler()\n\tinternal/hsm.Sign()", true},
		{"goroutine 1 [running]:\nmain.r2psHandler()\n\tinternal/pake.Create()", true},
		{"goroutine 1 [running]:\nsync.(*Pool).Get()", true},
		{"goroutine 1 [running]:\nruntime.fatal()", true},
		{"goroutine 1 [running]:\nmain.r2psHandler()\n\tencoding/json.Marshal()", false},
		{"goroutine 1 [running]:\nnet/http.HandlerFunc.ServeHTTP()", false},
	}

	for _, tc := range tests {
		got := isInfrastructurePanic(tc.stack)
		if got != tc.want {
			t.Errorf("isInfrastructurePanic(%q...) = %v, want %v", tc.stack[:30], got, tc.want)
		}
	}
}

func TestRecoverMiddlewareNoPanic(t *testing.T) {
	inner := http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
	})

	handler := recoverMiddleware(inner)
	req := httptest.NewRequest("GET", "/", nil)
	w := httptest.NewRecorder()
	handler.ServeHTTP(w, req)

	if w.Code != http.StatusOK {
		t.Errorf("status = %d, want 200", w.Code)
	}
}

func TestRecoverMiddlewareRequestPanic(t *testing.T) {
	inner := http.HandlerFunc(func(_ http.ResponseWriter, _ *http.Request) {
		panic("handler bug")
	})

	handler := recoverMiddleware(inner)
	req := httptest.NewRequest("GET", "/", nil)
	w := httptest.NewRecorder()
	handler.ServeHTTP(w, req)

	if w.Code != http.StatusInternalServerError {
		t.Errorf("status = %d, want 500", w.Code)
	}
}

func setupTestDispatcher(t *testing.T) (*service.Dispatcher, *ecdsa.PrivateKey) {
	t.Helper()
	serverKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	opaqueKey, err := pake.GenerateServerKeyMaterial()
	if err != nil {
		t.Fatal(err)
	}
	d, err := service.NewDispatcher(service.DispatcherConfig{
		ServerKey:   serverKey,
		OPAQUEKey:   opaqueKey,
		Records:     service.NewInMemoryRecordStore(),
		MaxAttempts: 3,
		LockoutDur:  time.Minute,
		SessionTTL:  5 * time.Minute,
	})
	if err != nil {
		t.Fatal(err)
	}
	return d, serverKey
}

func TestR2PSHandlerInvalidBody(t *testing.T) {
	d, _ := setupTestDispatcher(t)
	handler := r2psHandler(d, 10*time.Second)

	req := httptest.NewRequest("POST", "/r2ps", strings.NewReader("not-a-jws"))
	w := httptest.NewRecorder()
	handler.ServeHTTP(w, req)

	if w.Code != http.StatusBadRequest {
		t.Errorf("status = %d, want 400", w.Code)
	}

	var resp struct {
		ErrorCode string `json:"error_code"`
	}
	json.NewDecoder(w.Body).Decode(&resp)
	if resp.ErrorCode != r2ps.ErrIllegalRequestData {
		t.Errorf("error_code = %q", resp.ErrorCode)
	}
}

func TestR2PSHandlerEmptyBody(t *testing.T) {
	d, _ := setupTestDispatcher(t)
	handler := r2psHandler(d, 10*time.Second)

	req := httptest.NewRequest("POST", "/r2ps", strings.NewReader(""))
	w := httptest.NewRecorder()
	handler.ServeHTTP(w, req)

	if w.Code != http.StatusBadRequest {
		t.Errorf("status = %d, want 400", w.Code)
	}
}

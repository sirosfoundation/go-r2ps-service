package authmw_test

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	gojose "github.com/go-jose/go-jose/v4"
	"github.com/go-jose/go-jose/v4/jwt"

	"github.com/sirosfoundation/go-r2ps-service/internal/authmw"
	"github.com/sirosfoundation/go-tokenauth/claims"
	"github.com/sirosfoundation/go-tokenauth/validator"
)

// testJWKS spins up a JWKS endpoint and returns its URL and a token signer.
func testJWKS(t *testing.T) (jwksURL string, sign func(cl claims.AccessTokenClaims) string) {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	kid := "test-key-1"

	// JWKS endpoint
	pubJWK := gojose.JSONWebKey{Key: &key.PublicKey, KeyID: kid, Algorithm: string(gojose.ES256), Use: "sig"}
	jwksHandler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(gojose.JSONWebKeySet{Keys: []gojose.JSONWebKey{pubJWK}})
	})
	srv := httptest.NewServer(jwksHandler)
	t.Cleanup(srv.Close)

	signer, err := gojose.NewSigner(gojose.SigningKey{Algorithm: gojose.ES256, Key: key}, (&gojose.SignerOptions{}).WithType("JWT").WithHeader("kid", kid))
	if err != nil {
		t.Fatal(err)
	}

	return srv.URL, func(cl claims.AccessTokenClaims) string {
		tok, err := jwt.Signed(signer).Claims(cl).Serialize()
		if err != nil {
			t.Fatal(err)
		}
		return tok
	}
}

func setupValidator(t *testing.T, jwksURL string) *validator.Validator {
	t.Helper()
	v := validator.New(validator.Config{
		JWKSURL:   jwksURL,
		Issuer:    "test-issuer",
		Audiences: []string{"r2ps-admin"},
	})
	ctx, cancel := context.WithCancel(context.Background())
	v.Start(ctx)
	t.Cleanup(func() {
		v.Stop()
		cancel()
	})
	// Give JWKS fetcher time to load keys.
	time.Sleep(100 * time.Millisecond)
	return v
}

func TestTokenAuth_MissingToken(t *testing.T) {
	jwksURL, _ := testJWKS(t)
	v := setupValidator(t, jwksURL)

	handler := authmw.TokenAuth(v)(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))

	req := httptest.NewRequest(http.MethodGet, "/admin/store/keys", nil)
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)

	if rec.Code != http.StatusUnauthorized {
		t.Errorf("expected 401, got %d", rec.Code)
	}
}

func TestTokenAuth_InvalidToken(t *testing.T) {
	jwksURL, _ := testJWKS(t)
	v := setupValidator(t, jwksURL)

	handler := authmw.TokenAuth(v)(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))

	req := httptest.NewRequest(http.MethodGet, "/admin/store/keys", nil)
	req.Header.Set("Authorization", "Bearer invalid.token.here")
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)

	if rec.Code != http.StatusUnauthorized {
		t.Errorf("expected 401, got %d", rec.Code)
	}
}

func TestRequireTAC_Allowed(t *testing.T) {
	jwksURL, sign := testJWKS(t)
	v := setupValidator(t, jwksURL)

	now := time.Now()
	token := sign(claims.AccessTokenClaims{
		Claims: jwt.Claims{
			Issuer:   "test-issuer",
			Subject:  "user-1",
			Audience: jwt.Audience{"r2ps-admin"},
			IssuedAt: jwt.NewNumericDate(now),
			Expiry:   jwt.NewNumericDate(now.Add(5 * time.Minute)),
		},
		TAC: "rl",
	})

	// Chain: auth → require 'l' → handler
	handler := authmw.Chain(
		authmw.TokenAuth(v),
		authmw.RequireTAC("l"),
	)(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		result, ok := authmw.ResultFromContext(r.Context())
		if !ok {
			t.Error("expected result in context")
		}
		if result.UserID != "user-1" {
			t.Errorf("expected user-1, got %s", result.UserID)
		}
		w.WriteHeader(http.StatusOK)
	}))

	req := httptest.NewRequest(http.MethodGet, "/admin/store/keys", nil)
	req.Header.Set("Authorization", "Bearer "+token)
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Errorf("expected 200, got %d; body: %s", rec.Code, rec.Body.String())
	}
}

func TestRequireTAC_Forbidden(t *testing.T) {
	jwksURL, sign := testJWKS(t)
	v := setupValidator(t, jwksURL)

	now := time.Now()
	// Token only has 'r' (read), but endpoint requires 'w' (write).
	token := sign(claims.AccessTokenClaims{
		Claims: jwt.Claims{
			Issuer:   "test-issuer",
			Subject:  "user-1",
			Audience: jwt.Audience{"r2ps-admin"},
			IssuedAt: jwt.NewNumericDate(now),
			Expiry:   jwt.NewNumericDate(now.Add(5 * time.Minute)),
		},
		TAC: "r",
	})

	handler := authmw.Chain(
		authmw.TokenAuth(v),
		authmw.RequireTAC("w"),
	)(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))

	req := httptest.NewRequest(http.MethodGet, "/admin/store/status/ka/0", nil)
	req.Header.Set("Authorization", "Bearer "+token)
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)

	if rec.Code != http.StatusForbidden {
		t.Errorf("expected 403, got %d; body: %s", rec.Code, rec.Body.String())
	}
}

func TestRequireTAC_AdminBypass(t *testing.T) {
	jwksURL, sign := testJWKS(t)
	v := setupValidator(t, jwksURL)

	now := time.Now()
	// Token has 'a' (admin) — should bypass any specific TAC requirement.
	token := sign(claims.AccessTokenClaims{
		Claims: jwt.Claims{
			Issuer:   "test-issuer",
			Subject:  "admin-user",
			Audience: jwt.Audience{"r2ps-admin"},
			IssuedAt: jwt.NewNumericDate(now),
			Expiry:   jwt.NewNumericDate(now.Add(5 * time.Minute)),
		},
		TAC: "a",
	})

	handler := authmw.Chain(
		authmw.TokenAuth(v),
		authmw.RequireTAC("wid"), // write+insert+delete — admin should bypass
	)(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))

	req := httptest.NewRequest(http.MethodPut, "/admin/store/status/ka/0", nil)
	req.Header.Set("Authorization", "Bearer "+token)
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Errorf("expected 200 (admin bypass), got %d; body: %s", rec.Code, rec.Body.String())
	}
}

func TestDevTokenAuth_Valid(t *testing.T) {
	devToken := "my-secret-dev-token"

	handler := authmw.Chain(
		authmw.DevTokenAuth(devToken),
		authmw.RequireTAC("w"), // dev token has admin TAC, so this passes
	)(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		result, ok := authmw.ResultFromContext(r.Context())
		if !ok {
			t.Error("expected result in context")
		}
		if result.UserID != "dev-admin" {
			t.Errorf("expected dev-admin, got %s", result.UserID)
		}
		w.WriteHeader(http.StatusOK)
	}))

	req := httptest.NewRequest(http.MethodPut, "/admin/store/status/ka/0", nil)
	req.Header.Set("Authorization", "Bearer "+devToken)
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Errorf("expected 200, got %d; body: %s", rec.Code, rec.Body.String())
	}
}

func TestDevTokenAuth_Invalid(t *testing.T) {
	handler := authmw.DevTokenAuth("correct-token")(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))

	req := httptest.NewRequest(http.MethodGet, "/admin/store/keys", nil)
	req.Header.Set("Authorization", "Bearer wrong-token")
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)

	if rec.Code != http.StatusUnauthorized {
		t.Errorf("expected 401, got %d", rec.Code)
	}
}

func TestGenerateDevToken(t *testing.T) {
	token, err := authmw.GenerateDevToken()
	if err != nil {
		t.Fatal(err)
	}
	if len(token) != 64 { // 32 bytes = 64 hex chars
		t.Errorf("expected 64-char hex token, got %d chars", len(token))
	}

	// Ensure uniqueness.
	token2, _ := authmw.GenerateDevToken()
	if token == token2 {
		t.Error("expected unique tokens")
	}
}

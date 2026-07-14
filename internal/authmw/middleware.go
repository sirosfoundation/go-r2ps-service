// Package authmw provides net/http middleware for token-based authorization
// using go-tokenauth. It wraps the framework-agnostic validator to enforce
// TAC (Token Access Control) permissions on admin API endpoints.
package authmw

import (
	"context"
	"crypto/rand"
	"crypto/subtle"
	"encoding/hex"
	"fmt"
	"log/slog"
	"net/http"
	"strings"

	"github.com/sirosfoundation/go-tokenauth/claims"
	"github.com/sirosfoundation/go-tokenauth/validator"
)

type contextKey struct{}

// ResultFromContext extracts the validated token result from the request context.
func ResultFromContext(ctx context.Context) (*claims.Result, bool) {
	r, ok := ctx.Value(contextKey{}).(*claims.Result)
	return r, ok
}

// TokenAuth returns middleware that validates the Bearer token and stores
// the result in the request context. Returns 401 if the token is missing or invalid.
func TokenAuth(v *validator.Validator) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			auth := r.Header.Get("Authorization")
			if !strings.HasPrefix(auth, "Bearer ") {
				writeError(w, http.StatusUnauthorized, "missing or malformed authorization header")
				return
			}
			rawToken := strings.TrimPrefix(auth, "Bearer ")

			result, err := v.Validate(r.Context(), rawToken)
			if err != nil {
				slog.Warn("admin auth: token validation failed", "error", err)
				writeError(w, http.StatusUnauthorized, "invalid token")
				return
			}

			ctx := context.WithValue(r.Context(), contextKey{}, result)
			next.ServeHTTP(w, r.WithContext(ctx))
		})
	}
}

// DevTokenAuth returns middleware that accepts a single static Bearer token
// and grants full admin TAC. This is intended for local development only.
func DevTokenAuth(token string) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			auth := r.Header.Get("Authorization")
			if !strings.HasPrefix(auth, "Bearer ") {
				writeError(w, http.StatusUnauthorized, "missing or malformed authorization header")
				return
			}
			provided := strings.TrimPrefix(auth, "Bearer ")

			if subtle.ConstantTimeCompare([]byte(provided), []byte(token)) != 1 {
				slog.Warn("admin auth: invalid dev token")
				writeError(w, http.StatusUnauthorized, "invalid token")
				return
			}

			// Dev token grants full admin access.
			result := &claims.Result{
				UserID: "dev-admin",
				TAC:    claims.TAC("a"),
			}
			ctx := context.WithValue(r.Context(), contextKey{}, result)
			next.ServeHTTP(w, r.WithContext(ctx))
		})
	}
}

// GenerateDevToken generates a cryptographically random 32-byte hex token
// for development use.
func GenerateDevToken() (string, error) {
	b := make([]byte, 32)
	if _, err := rand.Read(b); err != nil {
		return "", fmt.Errorf("generate dev token: %w", err)
	}
	return hex.EncodeToString(b), nil
}

// RequireTAC returns middleware that checks the validated token has all
// specified TAC permissions. Must be placed after TokenAuth in the chain.
// Returns 403 if the token lacks the required permissions.
func RequireTAC(required string) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			result, ok := ResultFromContext(r.Context())
			if !ok {
				writeError(w, http.StatusUnauthorized, "no auth context")
				return
			}

			// Admin TAC grants all permissions implicitly.
			if !result.TAC.Has(claims.TACAdmin) && !result.TAC.HasAll(required) {
				slog.Warn("admin auth: insufficient permissions",
					"user_id", result.UserID,
					"tac", string(result.TAC),
					"required", required,
				)
				writeError(w, http.StatusForbidden, "insufficient permissions")
				return
			}

			next.ServeHTTP(w, r)
		})
	}
}

// Chain composes multiple middleware into one.
func Chain(middlewares ...func(http.Handler) http.Handler) func(http.Handler) http.Handler {
	return func(final http.Handler) http.Handler {
		for i := len(middlewares) - 1; i >= 0; i-- {
			final = middlewares[i](final)
		}
		return final
	}
}

func writeError(w http.ResponseWriter, status int, msg string) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_, _ = w.Write([]byte(`{"error":"` + msg + `"}`))
}

package main

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/tls"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"os"
	"os/signal"
	"runtime/debug"
	"strconv"
	"strings"
	"syscall"
	"time"

	"github.com/prometheus/client_golang/prometheus/promhttp"

	"github.com/sirosfoundation/go-r2ps-service/internal/audit"
	icrypto "github.com/sirosfoundation/go-r2ps-service/internal/crypto"
	"github.com/sirosfoundation/go-r2ps-service/internal/hsm"
	"github.com/sirosfoundation/go-r2ps-service/internal/pake"
	"github.com/sirosfoundation/go-r2ps-service/internal/service"
	"github.com/sirosfoundation/go-r2ps-service/internal/statuslist"
	"github.com/sirosfoundation/go-r2ps-service/internal/store"
	"github.com/sirosfoundation/go-r2ps-service/pkg/r2ps"
)

func main() {
	initLogging()

	listen := envOr("R2PS_LISTEN", ":8443")

	// Generate ephemeral server key (production would load from config/HSM)
	serverKey, err := icrypto.GenerateECKey(elliptic.P256())
	if err != nil {
		slog.Error("failed to generate server key", "error", err)
		os.Exit(1)
	}

	opaqueKey, err := pake.GenerateServerKeyMaterial()
	if err != nil {
		slog.Error("failed to generate OPAQUE key material", "error", err)
		os.Exit(1)
	}

	hsmModule := os.Getenv("R2PS_HSM_MODULE")
	if hsmModule == "" {
		slog.Error("R2PS_HSM_MODULE must be set")
		os.Exit(1)
	}
	hsmPIN := os.Getenv("R2PS_HSM_PIN")
	if hsmPIN == "" {
		slog.Error("R2PS_HSM_PIN must be set")
		os.Exit(1)
	}

	hsmCfg := hsm.PKCS11Config{
		ModulePath: hsmModule,
		PIN:        hsmPIN,
		PoolSize:   envInt("R2PS_HSM_POOL_SIZE", 4),
	}
	if label := os.Getenv("R2PS_HSM_TOKEN_LABEL"); label != "" {
		hsmCfg.TokenLabel = label
	}
	if slotStr := os.Getenv("R2PS_HSM_SLOT"); slotStr != "" {
		slot, err := strconv.ParseUint(slotStr, 10, 32)
		if err != nil {
			slog.Error("invalid R2PS_HSM_SLOT", "value", slotStr)
			os.Exit(1)
		}
		hsmCfg.SlotID = uint(slot)
	}

	hsmBackend, err := hsm.NewPKCS11Backend(hsmCfg)
	if err != nil {
		slog.Error("failed to connect to HSM", "error", err)
		os.Exit(1)
	}
	defer hsmBackend.Close() //nolint:errcheck // best-effort cleanup on shutdown

	handlers := []service.Handler{
		service.NewECDSAHandler(hsmBackend),
		service.NewECKeygenHandler(hsmBackend),
		service.NewECDHHandler(hsmBackend),
		service.NewListKeysHandler(hsmBackend),
	}

	// Lifecycle store and audit logger.
	lifecycleStore := store.NewMemoryStore()
	auditLogger := audit.New(slog.Default())

	// EUDIW Wallet Provider attestation handlers (WKA/WIA).
	wpCfg := walletProviderConfig(serverKey, lifecycleStore, auditLogger)
	handlers = append(handlers,
		service.NewWKAHandler(hsmBackend, wpCfg),
		service.NewWIAHandler(hsmBackend, wpCfg),
		service.NewWIRevokeHandler(wpCfg),
		service.NewWISuspendHandler(wpCfg),
	)

	maxAttempts := envInt("R2PS_MAX_ATTEMPTS", 5)
	lockoutDur := envDuration("R2PS_LOCKOUT_DURATION", 15*time.Minute)
	sessionTTL := envDuration("R2PS_SESSION_TTL", 5*time.Minute)

	dispatcher, err := service.NewDispatcher(service.DispatcherConfig{
		ServerKey:   serverKey,
		OPAQUEKey:   opaqueKey,
		Records:     service.NewInMemoryRecordStore(),
		Handlers:    handlers,
		MaxAttempts: maxAttempts,
		LockoutDur:  lockoutDur,
		SessionTTL:  sessionTTL,
	})
	if err != nil {
		slog.Error("failed to create dispatcher", "error", err)
		os.Exit(1)
	}

	// Start session cleanup goroutine
	dispatcher.StartSessionCleanup(1 * time.Minute)

	hsmTimeout := envDuration("R2PS_HSM_TIMEOUT", 5*time.Second)

	mux := http.NewServeMux()

	// Observability endpoints
	mux.HandleFunc("GET /healthz", handleHealthz)
	mux.HandleFunc("GET /readyz", readyzHandler(hsmBackend))
	mux.Handle("GET /metrics", promhttp.Handler())

	// Backward compat
	mux.HandleFunc("GET /health", handleHealthz)

	// R2PS protocol endpoint
	mux.HandleFunc("POST /r2ps", r2psHandler(dispatcher, hsmTimeout))

	// Token Status List endpoint (RFC 9701 / CS-04 §7.2)
	statusListHandler := statuslist.NewHandler(lifecycleStore, &statuslist.Config{
		SigningKey: serverKey,
		X5CChain:  wpCfg.X5CChain,
		BaseURI:   wpCfg.StatusListBaseURI,
	})
	mux.Handle("GET /statuslists/", statusListHandler)

	srv := &http.Server{
		Addr:              listen,
		Handler:           recoverMiddleware(mux),
		ReadHeaderTimeout: 5 * time.Second,
		ReadTimeout:       10 * time.Second,
		WriteTimeout:      30 * time.Second,
		IdleTimeout:       120 * time.Second,
	}

	// TLS configuration
	tlsCert := os.Getenv("R2PS_TLS_CERT")
	tlsKey := os.Getenv("R2PS_TLS_KEY")
	useTLS := tlsCert != "" && tlsKey != ""
	if useTLS {
		srv.TLSConfig = &tls.Config{
			MinVersion: tls.VersionTLS12,
		}
	}

	// Graceful shutdown
	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer stop()

	go func() {
		slog.Info("starting server", "addr", listen, "tls", useTLS,
			"hsm_pool_size", hsmBackend.PoolSize())
		var err error
		if useTLS {
			err = srv.ListenAndServeTLS(tlsCert, tlsKey)
		} else {
			slog.Warn("TLS disabled — set R2PS_TLS_CERT and R2PS_TLS_KEY for production")
			err = srv.ListenAndServe()
		}
		if err != nil && !errors.Is(err, http.ErrServerClosed) {
			slog.Error("server failed", "error", err)
			os.Exit(1)
		}
	}()

	<-ctx.Done()
	slog.Info("shutting down")

	shutdownCtx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	if err := srv.Shutdown(shutdownCtx); err != nil {
		slog.Error("shutdown error", "error", err)
	}

	slog.Info("server stopped")
}

// initLogging configures slog with level and format from environment.
func initLogging() {
	var level slog.Level
	switch strings.ToUpper(os.Getenv("R2PS_LOG_LEVEL")) {
	case "DEBUG":
		level = slog.LevelDebug
	case "INFO":
		level = slog.LevelInfo
	case "WARN", "WARNING":
		level = slog.LevelWarn
	case "ERROR":
		level = slog.LevelError
	default:
		level = slog.LevelWarn // default: only warn+error
	}

	opts := &slog.HandlerOptions{Level: level}
	var handler slog.Handler
	if strings.EqualFold(os.Getenv("R2PS_LOG_FORMAT"), "json") {
		handler = slog.NewJSONHandler(os.Stderr, opts)
	} else {
		handler = slog.NewTextHandler(os.Stderr, opts)
	}
	slog.SetDefault(slog.New(handler))
}

func handleHealthz(w http.ResponseWriter, _ *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	_, _ = fmt.Fprintf(w, `{"status":"ok"}`)
}

func readyzHandler(backend *hsm.PKCS11Backend) http.HandlerFunc {
	return func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		// Probe HSM by listing keys (lightweight operation)
		if _, err := backend.ListKeys(context.Background(), nil); err != nil {
			w.WriteHeader(http.StatusServiceUnavailable)
			_, _ = fmt.Fprintf(w, `{"status":"not ready","reason":"hsm"}`)
			return
		}
		w.WriteHeader(http.StatusOK)
		_, _ = fmt.Fprintf(w, `{"status":"ready"}`)
	}
}

func r2psHandler(dispatcher *service.Dispatcher, hsmTimeout time.Duration) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		service.R2PSRequestsTotal.WithLabelValues("received").Inc()
		start := time.Now()

		body, err := io.ReadAll(io.LimitReader(r.Body, 1<<20)) // 1 MB limit
		if err != nil {
			writeError(w, http.StatusBadRequest, r2ps.ErrIllegalRequestData, "read body failed")
			service.R2PSRequestsTotal.WithLabelValues("error").Inc()
			return
		}

		// Apply HSM operation timeout to request context
		ctx, cancel := context.WithTimeout(r.Context(), hsmTimeout)
		defer cancel()

		resp, err := dispatcher.Process(ctx, body)
		elapsed := time.Since(start).Seconds()

		if err != nil {
			var r2psErr *service.R2PSError
			if errors.As(err, &r2psErr) {
				status := mapErrorStatus(r2psErr.Code)
				writeError(w, status, r2psErr.Code, r2psErr.Msg)
			} else {
				writeError(w, http.StatusInternalServerError, r2ps.ErrServerError, "internal error")
			}
			service.R2PSRequestsTotal.WithLabelValues("error").Inc()
			service.R2PSRequestDuration.Observe(elapsed)
			return
		}

		w.Header().Set("Content-Type", "application/jose")
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write(resp)
		service.R2PSRequestsTotal.WithLabelValues("success").Inc()
		service.R2PSRequestDuration.Observe(elapsed)
	}
}

func writeError(w http.ResponseWriter, status int, code, msg string) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(r2ps.ErrorResponse{
		ErrorCode:    code,
		ErrorMessage: msg,
	})
}

func mapErrorStatus(code string) int {
	switch code {
	case r2ps.ErrUnauthorized:
		return http.StatusUnauthorized
	case r2ps.ErrAccessDenied:
		return http.StatusForbidden
	case r2ps.ErrUnsupportedType:
		return http.StatusUnsupportedMediaType
	case r2ps.ErrIllegalRequestData:
		return http.StatusBadRequest
	case r2ps.ErrIllegalState:
		return http.StatusConflict
	case r2ps.ErrTryLater:
		return http.StatusServiceUnavailable
	default:
		return http.StatusInternalServerError
	}
}

func recoverMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		defer func() {
			if err := recover(); err != nil {
				stack := string(debug.Stack())
				slog.Error("panic recovered", "error", err, "stack", stack)

				// If the panic originates from infrastructure code (HSM, pool, session store),
				// the service may be in an unrecoverable state. Re-panic so the process exits
				// and the orchestration layer (k8s, Docker) can restart a clean instance.
				if isInfrastructurePanic(stack) {
					panic(err)
				}

				http.Error(w, `{"error_code":"server_error","error_message":"internal error"}`, http.StatusInternalServerError)
			}
		}()
		next.ServeHTTP(w, r)
	})
}

// isInfrastructurePanic returns true if the panic stack trace indicates the
// failure originated in infrastructure code whose corruption cannot be safely
// recovered from at the request level.
func isInfrastructurePanic(stack string) bool {
	markers := []string{
		"internal/hsm.",
		"internal/pake.",
		"sync.(*Pool)",
		"runtime.fatal",
	}
	for _, m := range markers {
		if strings.Contains(stack, m) {
			return true
		}
	}
	return false
}

func envOr(key, fallback string) string {
	if v := os.Getenv(key); v != "" {
		return v
	}
	return fallback
}

func envInt(key string, fallback int) int {
	if v := os.Getenv(key); v != "" {
		if n, err := strconv.Atoi(v); err == nil {
			return n
		}
	}
	return fallback
}

func envDuration(key string, fallback time.Duration) time.Duration {
	if v := os.Getenv(key); v != "" {
		if d, err := time.ParseDuration(v); err == nil {
			return d
		}
	}
	return fallback
}

// walletProviderConfig builds the WalletProviderConfig from environment variables.
// In production, the signing key and x5c chain would come from a secure store;
// here we use the server key as a stand-in.
func walletProviderConfig(serverKey *ecdsa.PrivateKey, s store.Store, al *audit.Logger) *service.WalletProviderConfig {
	// Load x5c certificate chain if configured.
	var x5c [][]byte
	if x5cPath := os.Getenv("R2PS_WP_X5C_PATH"); x5cPath != "" {
		var err error
		x5c, err = service.LoadX5CChain(x5cPath)
		if err != nil {
			slog.Warn("failed to load x5c chain", "path", x5cPath, "error", err)
		} else {
			slog.Info("loaded x5c certificate chain", "path", x5cPath, "certs", len(x5c))
		}
	}

	return &service.WalletProviderConfig{
		SigningKey:                      serverKey,
		X5CChain:                        x5c,
		WalletLink:                      envOr("R2PS_WP_WALLET_LINK", ""),
		WalletName:                      envOr("R2PS_WP_WALLET_NAME", "SIROS EUDI Wallet"),
		WalletVersion:                   envOr("R2PS_WP_WALLET_VERSION", "0.1.0"),
		WalletSolutionCertificationInfo: envOr("R2PS_WP_CERT_INFO", ""),
		KeyStorageLevel:                 []string{envOr("R2PS_WP_KEY_STORAGE_LEVEL", "iso_18045_high")},
		UserAuthLevel:                   []string{envOr("R2PS_WP_USER_AUTH_LEVEL", "iso_18045_high")},
		Certification:                   envOr("R2PS_WP_CERTIFICATION", ""),
		StatusListBaseURI:               envOr("R2PS_WP_STATUS_LIST_BASE", "https://wp.example.com/statuslists"),
		WKATTL:                          envDuration("R2PS_WP_WKA_TTL", 24*time.Hour),
		WIATTL:                          envDuration("R2PS_WP_WIA_TTL", 12*time.Hour),
		StatusMaintenancePeriod:         envDuration("R2PS_WP_STATUS_MAINT", 31*24*time.Hour),
		Store:                           s,
		Audit:                           al,
	}
}

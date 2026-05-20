package main

import (
	"crypto/elliptic"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log"
	"net/http"
	"os"
	"strconv"
	"time"

	icrypto "github.com/sirosfoundation/go-r2ps-service/internal/crypto"
	"github.com/sirosfoundation/go-r2ps-service/internal/hsm"
	"github.com/sirosfoundation/go-r2ps-service/internal/pake"
	"github.com/sirosfoundation/go-r2ps-service/internal/service"
	"github.com/sirosfoundation/go-r2ps-service/pkg/r2ps"
)

func main() {
	listen := os.Getenv("R2PS_LISTEN")
	if listen == "" {
		listen = ":8443"
	}

	// Generate ephemeral server key (production would load from config/HSM)
	serverKey, err := icrypto.GenerateECKey(elliptic.P256())
	if err != nil {
		log.Fatalf("generate server key: %v", err)
	}

	// Generate OPAQUE key material
	opaqueKey, err := pake.GenerateServerKeyMaterial()
	if err != nil {
		log.Fatalf("generate OPAQUE key material: %v", err)
	}

	// Set up PKCS#11 HSM backend
	hsmModule := os.Getenv("R2PS_HSM_MODULE")
	if hsmModule == "" {
		log.Fatal("R2PS_HSM_MODULE must be set (path to PKCS#11 .so)")
	}
	hsmPIN := os.Getenv("R2PS_HSM_PIN")
	if hsmPIN == "" {
		log.Fatal("R2PS_HSM_PIN must be set")
	}

	hsmCfg := hsm.PKCS11Config{
		ModulePath: hsmModule,
		PIN:        hsmPIN,
	}
	if label := os.Getenv("R2PS_HSM_TOKEN_LABEL"); label != "" {
		hsmCfg.TokenLabel = label
	}
	if slotStr := os.Getenv("R2PS_HSM_SLOT"); slotStr != "" {
		slot, err := strconv.ParseUint(slotStr, 10, 32)
		if err != nil {
			log.Fatalf("invalid R2PS_HSM_SLOT: %v", err)
		}
		hsmCfg.SlotID = uint(slot)
	}

	hsmBackend, err := hsm.NewPKCS11Backend(hsmCfg)
	if err != nil {
		log.Fatalf("connect to HSM: %v", err)
	}
	defer hsmBackend.Close() //nolint:errcheck // best-effort cleanup on shutdown
	handlers := []service.Handler{
		service.NewECDSAHandler(hsmBackend),
		service.NewECKeygenHandler(hsmBackend),
		service.NewECDHHandler(hsmBackend),
		service.NewListKeysHandler(hsmBackend),
	}

	dispatcher, err := service.NewDispatcher(service.DispatcherConfig{
		ServerKey:   serverKey,
		OPAQUEKey:   opaqueKey,
		Records:     service.NewInMemoryRecordStore(),
		Handlers:    handlers,
		MaxAttempts: 5,
		LockoutDur:  15 * time.Minute,
		SessionTTL:  5 * time.Minute,
	})
	if err != nil {
		log.Fatalf("create dispatcher: %v", err)
	}

	mux := http.NewServeMux()
	mux.HandleFunc("/health", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		_, _ = fmt.Fprintf(w, `{"status":"ok"}`)
	})

	mux.HandleFunc("POST /r2ps", func(w http.ResponseWriter, r *http.Request) {
		body, err := io.ReadAll(io.LimitReader(r.Body, 1<<20)) // 1 MB limit
		if err != nil {
			writeError(w, http.StatusBadRequest, r2ps.ErrIllegalRequestData, "read body failed")
			return
		}

		resp, err := dispatcher.Process(r.Context(), body)
		if err != nil {
			var r2psErr *service.R2PSError
			if errors.As(err, &r2psErr) {
				status := mapErrorStatus(r2psErr.Code)
				writeError(w, status, r2psErr.Code, r2psErr.Msg)
			} else {
				writeError(w, http.StatusInternalServerError, r2ps.ErrServerError, "internal error")
			}
			return
		}

		w.Header().Set("Content-Type", "application/jose")
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write(resp)
	})

	log.Printf("go-r2ps-service listening on %s", listen)
	if err := http.ListenAndServe(listen, mux); err != nil {
		log.Fatalf("server: %v", err)
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
		return http.StatusBadRequest
	case r2ps.ErrIllegalRequestData, r2ps.ErrIllegalState:
		return http.StatusBadRequest
	case r2ps.ErrTryLater:
		return http.StatusServiceUnavailable
	default:
		return http.StatusInternalServerError
	}
}

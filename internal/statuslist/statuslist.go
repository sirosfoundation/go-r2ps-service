// Package statuslist implements Token Status List (RFC 9701 / draft-ietf-oauth-status-list-20)
// generation and serving for WKA/WIA revocation status.
package statuslist

import (
	"bytes"
	"compress/flate"
	"crypto/ecdsa"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"net/http"
	"strings"
	"time"

	icrypto "github.com/sirosfoundation/go-r2ps-service/internal/crypto"
	"github.com/sirosfoundation/go-r2ps-service/internal/store"
)

// Config holds the signing key and metadata for status list publishing.
type Config struct {
	SigningKey *ecdsa.PrivateKey
	X5CChain   [][]byte
	BaseURI    string        // e.g. "https://wp.example.com/statuslists"
	TTL        time.Duration // status list JWT validity; default 1h
}

// Handler serves Token Status List JWTs at /statuslists/{category}/{listID}.
type Handler struct {
	store store.Store
	cfg   *Config
}

// NewHandler creates a status list HTTP handler.
func NewHandler(s store.Store, cfg *Config) *Handler {
	return &Handler{store: s, cfg: cfg}
}

// statusListPayload is the JWT payload per RFC 9701 §5.
type statusListPayload struct {
	Sub        string     `json:"sub"`
	Iat        int64      `json:"iat"`
	Exp        int64      `json:"exp"`
	StatusList statusData `json:"status_list"`
}

type statusData struct {
	Bits int    `json:"bits"`
	Lst  string `json:"lst"` // base64url-encoded DEFLATE-compressed bitstring
}

// ServeHTTP handles GET /statuslists/{category}/{listID}
func (h *Handler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	// Parse path: expect /statuslists/{category}/{listID}
	path := strings.TrimPrefix(r.URL.Path, "/statuslists/")
	parts := strings.SplitN(path, "/", 2)
	if len(parts) != 2 {
		http.Error(w, "invalid path", http.StatusBadRequest)
		return
	}
	category := parts[0] // "ka" or "wia"

	entries, err := h.store.GetAllStatuses(category)
	if err != nil {
		http.Error(w, "internal error", http.StatusInternalServerError)
		return
	}

	// Build the status list bitstring.
	// 2 bits per entry, so each byte holds 4 entries.
	// Find the max index to determine the size.
	maxIdx := 0
	for idx := range entries {
		if idx > maxIdx {
			maxIdx = idx
		}
	}

	// Allocate byte array: ceil((maxIdx+1) * 2 / 8) bytes
	numEntries := maxIdx + 1
	if numEntries == 0 {
		numEntries = 1
	}
	byteLen := (numEntries*2 + 7) / 8
	bitstring := make([]byte, byteLen)

	for idx, status := range entries {
		// Each entry uses 2 bits at position idx*2
		bitPos := idx * 2
		byteIdx := bitPos / 8
		bitOffset := uint(bitPos % 8)
		bitstring[byteIdx] |= (status & 0x03) << bitOffset
	}

	// DEFLATE compress
	var buf bytes.Buffer
	fw, err := flate.NewWriter(&buf, flate.DefaultCompression)
	if err != nil {
		http.Error(w, "compression error", http.StatusInternalServerError)
		return
	}
	if _, err := fw.Write(bitstring); err != nil {
		http.Error(w, "compression error", http.StatusInternalServerError)
		return
	}
	if err := fw.Close(); err != nil {
		http.Error(w, "compression error", http.StatusInternalServerError)
		return
	}

	ttl := h.cfg.TTL
	if ttl == 0 {
		ttl = 1 * time.Hour
	}

	now := time.Now()
	sub := fmt.Sprintf("%s/%s/%s", h.cfg.BaseURI, category, parts[1])

	payload := statusListPayload{
		Sub: sub,
		Iat: now.Unix(),
		Exp: now.Add(ttl).Unix(),
		StatusList: statusData{
			Bits: 2,
			Lst:  base64.RawURLEncoding.EncodeToString(buf.Bytes()),
		},
	}

	payloadJSON, err := json.Marshal(payload)
	if err != nil {
		http.Error(w, "marshal error", http.StatusInternalServerError)
		return
	}

	jwt, err := icrypto.SignJWT(payloadJSON, h.cfg.SigningKey, "statuslist+jwt", h.cfg.X5CChain)
	if err != nil {
		http.Error(w, "sign error", http.StatusInternalServerError)
		return
	}

	w.Header().Set("Content-Type", "application/statuslist+jwt")
	w.Header().Set("Cache-Control", fmt.Sprintf("max-age=%d", int(ttl.Seconds())))
	w.WriteHeader(http.StatusOK)
	_, _ = w.Write([]byte(jwt))
}

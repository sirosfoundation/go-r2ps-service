// Package admin provides HTTP handlers for the R2PS admin API.
//
// The admin API exposes lifecycle-store inspection and management
// endpoints for debugging and provisioning. It MUST be served on a
// separate listener that is not reachable from the public internet
// (bind to localhost or use network policy).
package admin

import (
	"encoding/json"
	"log/slog"
	"net/http"
	"strconv"
	"strings"

	"github.com/sirosfoundation/go-r2ps-service/internal/store"
)

// Handler serves the admin API.
type Handler struct {
	store store.Store
	mux   *http.ServeMux
}

// New creates a new admin API handler.
func New(s store.Store) *Handler {
	h := &Handler{store: s}
	h.mux = http.NewServeMux()
	h.mux.HandleFunc("GET /admin/store/statuses/{category}", h.handleListStatuses)
	h.mux.HandleFunc("GET /admin/store/status/{category}/{idx}", h.handleGetStatus)
	h.mux.HandleFunc("PUT /admin/store/status/{category}/{idx}", h.handleSetStatus)
	h.mux.HandleFunc("GET /admin/store/clients/{clientID}/{category}", h.handleGetClientIndices)
	h.mux.HandleFunc("GET /admin/store/usage/{category}/{idx}", h.handleGetUsage)
	h.mux.HandleFunc("POST /admin/store/allocate/{category}", h.handleAllocateIndex)
	h.mux.HandleFunc("GET /admin/store/keys", h.handleListKeys)
	h.mux.HandleFunc("GET /admin/store/keys/{kid}", h.handleGetKey)
	return h
}

func (h *Handler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	h.mux.ServeHTTP(w, r)
}

// GET /admin/store/statuses/{category}
// Returns all status entries for a category (ka, wia).
func (h *Handler) handleListStatuses(w http.ResponseWriter, r *http.Request) {
	category := r.PathValue("category")
	statuses, err := h.store.GetAllStatuses(category)
	if err != nil {
		writeAdminError(w, http.StatusInternalServerError, err.Error())
		return
	}

	type entry struct {
		Idx    int    `json:"idx"`
		Status byte   `json:"status"`
		Label  string `json:"label"`
	}
	entries := make([]entry, 0, len(statuses))
	for idx, s := range statuses {
		entries = append(entries, entry{Idx: idx, Status: s, Label: statusLabel(s)})
	}

	writeJSON(w, http.StatusOK, map[string]any{
		"category": category,
		"count":    len(entries),
		"entries":  entries,
	})
}

// GET /admin/store/status/{category}/{idx}
func (h *Handler) handleGetStatus(w http.ResponseWriter, r *http.Request) {
	category := r.PathValue("category")
	idx, err := strconv.Atoi(r.PathValue("idx"))
	if err != nil {
		writeAdminError(w, http.StatusBadRequest, "invalid index")
		return
	}

	status, err := h.store.GetStatus(category, idx)
	if err != nil {
		if strings.Contains(err.Error(), "not found") {
			writeAdminError(w, http.StatusNotFound, err.Error())
		} else {
			writeAdminError(w, http.StatusInternalServerError, err.Error())
		}
		return
	}

	used, _ := h.store.IsUsed(category, idx)

	writeJSON(w, http.StatusOK, map[string]any{
		"category": category,
		"idx":      idx,
		"status":   status,
		"label":    statusLabel(status),
		"used":     used,
	})
}

// PUT /admin/store/status/{category}/{idx}
// Body: {"status": 0|1|2}
func (h *Handler) handleSetStatus(w http.ResponseWriter, r *http.Request) {
	category := r.PathValue("category")
	idx, err := strconv.Atoi(r.PathValue("idx"))
	if err != nil {
		writeAdminError(w, http.StatusBadRequest, "invalid index")
		return
	}

	var body struct {
		Status byte `json:"status"`
	}
	if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, 256)).Decode(&body); err != nil {
		writeAdminError(w, http.StatusBadRequest, "invalid request body")
		return
	}
	if body.Status > store.StatusSuspended {
		writeAdminError(w, http.StatusBadRequest, "status must be 0 (valid), 1 (revoked), or 2 (suspended)")
		return
	}

	if err := h.store.SetStatus(category, idx, body.Status); err != nil {
		if strings.Contains(err.Error(), "not found") {
			writeAdminError(w, http.StatusNotFound, err.Error())
		} else {
			writeAdminError(w, http.StatusInternalServerError, err.Error())
		}
		return
	}

	slog.Info("admin: status updated", "category", category, "idx", idx, "status", body.Status)
	writeJSON(w, http.StatusOK, map[string]any{
		"category": category,
		"idx":      idx,
		"status":   body.Status,
		"label":    statusLabel(body.Status),
	})
}

// GET /admin/store/clients/{clientID}/{category}
func (h *Handler) handleGetClientIndices(w http.ResponseWriter, r *http.Request) {
	clientID := r.PathValue("clientID")
	category := r.PathValue("category")

	indices, err := h.store.GetClientIndices(clientID, category)
	if err != nil {
		writeAdminError(w, http.StatusInternalServerError, err.Error())
		return
	}

	// Enrich with status for each index.
	type indexInfo struct {
		Idx    int    `json:"idx"`
		Status byte   `json:"status"`
		Label  string `json:"label"`
	}
	infos := make([]indexInfo, 0, len(indices))
	for _, idx := range indices {
		s, _ := h.store.GetStatus(category, idx)
		infos = append(infos, indexInfo{Idx: idx, Status: s, Label: statusLabel(s)})
	}

	writeJSON(w, http.StatusOK, map[string]any{
		"client_id": clientID,
		"category":  category,
		"indices":   infos,
	})
}

// GET /admin/store/usage/{category}/{idx}
func (h *Handler) handleGetUsage(w http.ResponseWriter, r *http.Request) {
	category := r.PathValue("category")
	idx, err := strconv.Atoi(r.PathValue("idx"))
	if err != nil {
		writeAdminError(w, http.StatusBadRequest, "invalid index")
		return
	}

	used, err := h.store.IsUsed(category, idx)
	if err != nil {
		writeAdminError(w, http.StatusInternalServerError, err.Error())
		return
	}

	writeJSON(w, http.StatusOK, map[string]any{
		"category": category,
		"idx":      idx,
		"used":     used,
	})
}

// POST /admin/store/allocate/{category}
// Allocates a new status list index (for provisioning/testing).
func (h *Handler) handleAllocateIndex(w http.ResponseWriter, r *http.Request) {
	category := r.PathValue("category")

	idx, err := h.store.AllocateIndex(category)
	if err != nil {
		writeAdminError(w, http.StatusInternalServerError, err.Error())
		return
	}

	slog.Info("admin: index allocated", "category", category, "idx", idx)
	writeJSON(w, http.StatusCreated, map[string]any{
		"category": category,
		"idx":      idx,
	})
}

// GET /admin/store/keys?client_id=...
// Lists public keys, optionally filtered by client_id.
func (h *Handler) handleListKeys(w http.ResponseWriter, r *http.Request) {
	clientID := r.URL.Query().Get("client_id")
	var keys []store.PublicKeyInfo
	var err error

	if clientID != "" {
		keys, err = h.store.ListPublicKeys(clientID)
	} else {
		// List all — use empty client_id to get all
		keys, err = h.store.ListPublicKeys("")
	}
	if err != nil {
		writeAdminError(w, http.StatusInternalServerError, err.Error())
		return
	}

	writeJSON(w, http.StatusOK, map[string]any{
		"count": len(keys),
		"keys":  keys,
	})
}

// GET /admin/store/keys/{kid}
// Returns a single public key by kid.
func (h *Handler) handleGetKey(w http.ResponseWriter, r *http.Request) {
	kid := r.PathValue("kid")

	key, err := h.store.GetPublicKey(kid)
	if err != nil {
		if strings.Contains(err.Error(), "not found") {
			writeAdminError(w, http.StatusNotFound, err.Error())
		} else {
			writeAdminError(w, http.StatusInternalServerError, err.Error())
		}
		return
	}

	writeJSON(w, http.StatusOK, key)
}

func statusLabel(s byte) string {
	switch s {
	case store.StatusValid:
		return "valid"
	case store.StatusInvalid:
		return "revoked"
	case store.StatusSuspended:
		return "suspended"
	default:
		return "unknown"
	}
}

func writeJSON(w http.ResponseWriter, status int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(v)
}

func writeAdminError(w http.ResponseWriter, status int, msg string) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(map[string]string{"error": msg})
}

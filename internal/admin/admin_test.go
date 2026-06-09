package admin

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/sirosfoundation/go-r2ps-service/internal/store"
)

func TestAdminAPI(t *testing.T) {
	s := store.NewMemoryStore()
	h := New(s)

	// Allocate an index.
	req := httptest.NewRequest("POST", "/admin/store/allocate/ka", nil)
	w := httptest.NewRecorder()
	h.ServeHTTP(w, req)
	if w.Code != http.StatusCreated {
		t.Fatalf("allocate: got %d, want %d; body: %s", w.Code, http.StatusCreated, w.Body.String())
	}
	var alloc map[string]any
	if err := json.Unmarshal(w.Body.Bytes(), &alloc); err != nil {
		t.Fatalf("decode allocate response: %v", err)
	}
	if alloc["idx"] != float64(0) {
		t.Fatalf("expected idx 0, got %v", alloc["idx"])
	}

	// Record client association (via store directly, admin uses the interface).
	if err := s.RecordWUA("client-1", "ka", 0); err != nil {
		t.Fatal(err)
	}

	// Get status.
	req = httptest.NewRequest("GET", "/admin/store/status/ka/0", nil)
	w = httptest.NewRecorder()
	h.ServeHTTP(w, req)
	if w.Code != http.StatusOK {
		t.Fatalf("get status: got %d; body: %s", w.Code, w.Body.String())
	}
	var status map[string]any
	if err := json.Unmarshal(w.Body.Bytes(), &status); err != nil {
		t.Fatal(err)
	}
	if status["label"] != "valid" {
		t.Fatalf("expected label=valid, got %v", status["label"])
	}
	if status["used"] != false {
		t.Fatalf("expected used=false, got %v", status["used"])
	}

	// Set status to revoked.
	body, _ := json.Marshal(map[string]byte{"status": store.StatusInvalid})
	req = httptest.NewRequest("PUT", "/admin/store/status/ka/0", bytes.NewReader(body))
	w = httptest.NewRecorder()
	h.ServeHTTP(w, req)
	if w.Code != http.StatusOK {
		t.Fatalf("set status: got %d; body: %s", w.Code, w.Body.String())
	}

	// Verify status changed.
	req = httptest.NewRequest("GET", "/admin/store/status/ka/0", nil)
	w = httptest.NewRecorder()
	h.ServeHTTP(w, req)
	if err := json.Unmarshal(w.Body.Bytes(), &status); err != nil {
		t.Fatal(err)
	}
	if status["label"] != "revoked" {
		t.Fatalf("expected label=revoked, got %v", status["label"])
	}

	// List statuses.
	req = httptest.NewRequest("GET", "/admin/store/statuses/ka", nil)
	w = httptest.NewRecorder()
	h.ServeHTTP(w, req)
	if w.Code != http.StatusOK {
		t.Fatalf("list statuses: got %d; body: %s", w.Code, w.Body.String())
	}

	// Get client indices.
	req = httptest.NewRequest("GET", "/admin/store/clients/client-1/ka", nil)
	w = httptest.NewRecorder()
	h.ServeHTTP(w, req)
	if w.Code != http.StatusOK {
		t.Fatalf("get client indices: got %d; body: %s", w.Code, w.Body.String())
	}
	var clientResp map[string]any
	if err := json.Unmarshal(w.Body.Bytes(), &clientResp); err != nil {
		t.Fatal(err)
	}
	indices := clientResp["indices"].([]any)
	if len(indices) != 1 {
		t.Fatalf("expected 1 index, got %d", len(indices))
	}

	// Check usage.
	req = httptest.NewRequest("GET", "/admin/store/usage/ka/0", nil)
	w = httptest.NewRecorder()
	h.ServeHTTP(w, req)
	if w.Code != http.StatusOK {
		t.Fatalf("get usage: got %d; body: %s", w.Code, w.Body.String())
	}

	// 404 for non-existent index.
	req = httptest.NewRequest("GET", "/admin/store/status/ka/999", nil)
	w = httptest.NewRecorder()
	h.ServeHTTP(w, req)
	if w.Code != http.StatusNotFound {
		t.Fatalf("expected 404 for non-existent index, got %d", w.Code)
	}

	// Bad status value.
	body, _ = json.Marshal(map[string]byte{"status": 5})
	req = httptest.NewRequest("PUT", "/admin/store/status/ka/0", bytes.NewReader(body))
	w = httptest.NewRecorder()
	h.ServeHTTP(w, req)
	if w.Code != http.StatusBadRequest {
		t.Fatalf("expected 400 for bad status, got %d", w.Code)
	}
}

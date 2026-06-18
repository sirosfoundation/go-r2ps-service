package store

import (
	"fmt"
	"sync"
)

// MemoryStore is an in-memory implementation of Store for development and testing.
type MemoryStore struct {
	mu            sync.Mutex
	counters      map[string]int                  // category -> next index
	statuses      map[string]map[int]byte         // category -> idx -> status
	clientIndices map[string][]int                // "clientID|category" -> []idx
	usage         map[string]bool                 // "category|idx" -> used
	publicKeys    map[string]PublicKeyInfo        // kid -> PublicKeyInfo
	records       map[string][]byte               // "clientID|context" -> OPAQUE record bytes
	webauthn      map[string][]WebAuthnCredential // "clientID|context" -> credentials
}

// NewMemoryStore creates a new in-memory store.
func NewMemoryStore() *MemoryStore {
	return &MemoryStore{
		counters:      make(map[string]int),
		statuses:      make(map[string]map[int]byte),
		clientIndices: make(map[string][]int),
		usage:         make(map[string]bool),
		publicKeys:    make(map[string]PublicKeyInfo),
		records:       make(map[string][]byte),
		webauthn:      make(map[string][]WebAuthnCredential),
	}
}

func (m *MemoryStore) AllocateIndex(category string) (int, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	idx := m.counters[category]
	m.counters[category] = idx + 1
	if m.statuses[category] == nil {
		m.statuses[category] = make(map[int]byte)
	}
	m.statuses[category][idx] = StatusValid
	return idx, nil
}

func (m *MemoryStore) GetStatus(category string, idx int) (byte, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.statuses[category] == nil {
		return 0, fmt.Errorf("category %q not found", category)
	}
	status, ok := m.statuses[category][idx]
	if !ok {
		return 0, fmt.Errorf("index %d not found in category %q", idx, category)
	}
	return status, nil
}

func (m *MemoryStore) SetStatus(category string, idx int, status byte) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.statuses[category] == nil {
		return fmt.Errorf("category %q not found", category)
	}
	if _, ok := m.statuses[category][idx]; !ok {
		return fmt.Errorf("index %d not found in category %q", idx, category)
	}
	m.statuses[category][idx] = status
	return nil
}

func (m *MemoryStore) GetAllStatuses(category string) (map[int]byte, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	entries := m.statuses[category]
	if entries == nil {
		return make(map[int]byte), nil
	}
	result := make(map[int]byte, len(entries))
	for k, v := range entries {
		result[k] = v
	}
	return result, nil
}

func (m *MemoryStore) RecordWUA(clientID, category string, idx int) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	key := clientID + "|" + category
	m.clientIndices[key] = append(m.clientIndices[key], idx)
	return nil
}

func (m *MemoryStore) GetClientIndices(clientID, category string) ([]int, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	key := clientID + "|" + category
	indices := m.clientIndices[key]
	result := make([]int, len(indices))
	copy(result, indices)
	return result, nil
}

func (m *MemoryStore) RecordUsage(category string, idx int) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	key := fmt.Sprintf("%s|%d", category, idx)
	m.usage[key] = true
	return nil
}

func (m *MemoryStore) IsUsed(category string, idx int) (bool, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	key := fmt.Sprintf("%s|%d", category, idx)
	return m.usage[key], nil
}

func (m *MemoryStore) PutPublicKey(key PublicKeyInfo) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.publicKeys[key.Kid] = key
	return nil
}

func (m *MemoryStore) GetPublicKey(kid string) (*PublicKeyInfo, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	k, ok := m.publicKeys[kid]
	if !ok {
		return nil, fmt.Errorf("key %q not found", kid)
	}
	return &k, nil
}

func (m *MemoryStore) ListPublicKeys(clientID string) ([]PublicKeyInfo, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	var result []PublicKeyInfo
	for _, k := range m.publicKeys {
		if clientID == "" || k.ClientID == clientID {
			result = append(result, k)
		}
	}
	return result, nil
}

func (m *MemoryStore) PutRecord(clientID, context string, record []byte) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	key := clientID + "|" + context
	m.records[key] = make([]byte, len(record))
	copy(m.records[key], record)
	return nil
}

func (m *MemoryStore) GetRecord(clientID, context string) ([]byte, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	key := clientID + "|" + context
	r, ok := m.records[key]
	if !ok {
		return nil, fmt.Errorf("no record for %s/%s", clientID, context)
	}
	result := make([]byte, len(r))
	copy(result, r)
	return result, nil
}

func (m *MemoryStore) PutWebAuthnCredential(clientID, context string, cred WebAuthnCredential) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	key := clientID + "|" + context
	m.webauthn[key] = append(m.webauthn[key], cred)
	return nil
}

func (m *MemoryStore) GetWebAuthnCredential(clientID, context string) ([]WebAuthnCredential, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	key := clientID + "|" + context
	creds := m.webauthn[key]
	if len(creds) == 0 {
		return nil, fmt.Errorf("no WebAuthn credentials for %s/%s", clientID, context)
	}
	// Return a copy
	result := make([]WebAuthnCredential, len(creds))
	copy(result, creds)
	return result, nil
}

func (m *MemoryStore) UpdateWebAuthnSignCount(clientID, context string, credentialID []byte, signCount uint32) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	key := clientID + "|" + context
	for i := range m.webauthn[key] {
		if bytesEqual(m.webauthn[key][i].CredentialID, credentialID) {
			m.webauthn[key][i].SignCount = signCount
			return nil
		}
	}
	return fmt.Errorf("credential not found")
}

func bytesEqual(a, b []byte) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}

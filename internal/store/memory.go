package store

import (
	"fmt"
	"sync"
)

// MemoryStore is an in-memory implementation of Store for development and testing.
type MemoryStore struct {
	mu            sync.Mutex
	counters      map[string]int         // category -> next index
	statuses      map[string]map[int]byte // category -> idx -> status
	clientIndices map[string][]int        // "clientID|category" -> []idx
	usage         map[string]bool         // "category|idx" -> used
}

// NewMemoryStore creates a new in-memory store.
func NewMemoryStore() *MemoryStore {
	return &MemoryStore{
		counters:      make(map[string]int),
		statuses:      make(map[string]map[int]byte),
		clientIndices: make(map[string][]int),
		usage:         make(map[string]bool),
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

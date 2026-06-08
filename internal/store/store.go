// Package store defines the persistence interface for R2PS server state.
package store

// Status values per Token Status List (RFC 9701), 2-bit encoding.
const (
	StatusValid     byte = 0
	StatusInvalid   byte = 1 // revoked
	StatusSuspended byte = 2
)

// Store provides persistence for R2PS attestation lifecycle state.
type Store interface {
	// AllocateIndex returns the next available status list index for a category ("ka" or "wia").
	AllocateIndex(category string) (int, error)

	// GetStatus returns the status of a status list entry.
	GetStatus(category string, idx int) (byte, error)

	// SetStatus sets the status of a status list entry.
	SetStatus(category string, idx int, status byte) error

	// GetAllStatuses returns all status entries for a category (for status list publishing).
	GetAllStatuses(category string) (map[int]byte, error)

	// RecordWUA records the association between a client and a status list index.
	RecordWUA(clientID, category string, idx int) error

	// GetClientIndices returns all status list indices for a client in a category.
	GetClientIndices(clientID, category string) ([]int, error)

	// RecordUsage marks that a WUA at idx has been presented/used.
	RecordUsage(category string, idx int) error

	// IsUsed returns true if the WUA at idx has already been used.
	IsUsed(category string, idx int) (bool, error)
}

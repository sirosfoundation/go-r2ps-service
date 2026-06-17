package pake

import (
	"fmt"
	"sync"
	"time"
)

// Session represents an active 2FA session with its negotiated key material.
type Session struct {
	ID         string
	ClientID   string
	Context    string
	SessionKey []byte
	ClientMAC  []byte // expected client MAC for KE3 verification
	ExpiresAt  time.Time
	Verified   bool   // true after KE3 has been verified
	Task       string // task binding for SAD (Signature Activation Data)
}

// SessionStore manages active PAKE sessions.
type SessionStore struct {
	mu       sync.RWMutex
	sessions map[string]*Session
}

// NewSessionStore creates a new in-memory session store.
func NewSessionStore() *SessionStore {
	return &SessionStore{
		sessions: make(map[string]*Session),
	}
}

// Create stores a new session. Returns error if the session ID already exists.
func (s *SessionStore) Create(session *Session) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	if _, exists := s.sessions[session.ID]; exists {
		return fmt.Errorf("session already exists: %s", session.ID)
	}

	s.sessions[session.ID] = session
	return nil
}

// Get retrieves a session by ID. Returns nil if not found or expired.
func (s *SessionStore) Get(id string) *Session {
	s.mu.RLock()
	defer s.mu.RUnlock()

	sess, ok := s.sessions[id]
	if !ok {
		return nil
	}

	if time.Now().After(sess.ExpiresAt) {
		return nil
	}

	return sess
}

// MarkVerified marks a session as verified after successful KE3 validation.
func (s *SessionStore) MarkVerified(id string) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	sess, ok := s.sessions[id]
	if !ok {
		return fmt.Errorf("session not found: %s", id)
	}

	sess.Verified = true
	return nil
}

// Delete removes a session.
func (s *SessionStore) Delete(id string) {
	s.mu.Lock()
	defer s.mu.Unlock()

	delete(s.sessions, id)
}

// CleanExpired removes all expired sessions.
func (s *SessionStore) CleanExpired() int {
	s.mu.Lock()
	defer s.mu.Unlock()

	now := time.Now()
	count := 0
	for id, sess := range s.sessions {
		if now.After(sess.ExpiresAt) {
			delete(s.sessions, id)
			count++
		}
	}
	return count
}

// Count returns the number of active sessions.
func (s *SessionStore) Count() int {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return len(s.sessions)
}

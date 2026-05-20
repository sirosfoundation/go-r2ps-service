package pake

import (
	"fmt"
	"sync"
	"time"
)

// AttemptCounter tracks failed authentication attempts per (client_id, kid, context).
type AttemptCounter struct {
	mu       sync.Mutex
	attempts map[string]*attemptRecord
	maxFails int
	lockout  time.Duration
}

type attemptRecord struct {
	failures int
	lockedAt time.Time
}

// NewAttemptCounter creates a counter that locks after maxFails failures
// for the given lockout duration.
func NewAttemptCounter(maxFails int, lockout time.Duration) *AttemptCounter {
	return &AttemptCounter{
		attempts: make(map[string]*attemptRecord),
		maxFails: maxFails,
		lockout:  lockout,
	}
}

func counterKey(clientID, kid, context string) string {
	return clientID + "|" + kid + "|" + context
}

// Check returns an error if the client is currently locked out.
func (c *AttemptCounter) Check(clientID, kid, context string) error {
	c.mu.Lock()
	defer c.mu.Unlock()

	key := counterKey(clientID, kid, context)
	rec, ok := c.attempts[key]
	if !ok {
		return nil
	}

	if rec.failures >= c.maxFails {
		if time.Now().Before(rec.lockedAt.Add(c.lockout)) {
			return fmt.Errorf("account locked: too many failed attempts")
		}
		// Lockout expired, reset
		delete(c.attempts, key)
	}

	return nil
}

// RecordFailure increments the failure counter. Returns error if now locked.
func (c *AttemptCounter) RecordFailure(clientID, kid, context string) error {
	c.mu.Lock()
	defer c.mu.Unlock()

	key := counterKey(clientID, kid, context)
	rec, ok := c.attempts[key]
	if !ok {
		rec = &attemptRecord{}
		c.attempts[key] = rec
	}

	rec.failures++
	if rec.failures >= c.maxFails {
		rec.lockedAt = time.Now()
		return fmt.Errorf("account locked after %d failures", c.maxFails)
	}

	return nil
}

// RecordSuccess resets the failure counter on successful authentication.
func (c *AttemptCounter) RecordSuccess(clientID, kid, context string) {
	c.mu.Lock()
	defer c.mu.Unlock()

	delete(c.attempts, counterKey(clientID, kid, context))
}

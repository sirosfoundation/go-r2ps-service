# ADR-008: Session Lifecycle and Cleanup

## Status

Accepted

## Context

PAKE authentication produces ephemeral sessions containing session keys and verification state. Sessions that are never finalized (client disconnect, network failure, abandoned flows) accumulate in memory indefinitely unless actively cleaned.

## Decision

- Sessions are stored in an in-memory map protected by `sync.RWMutex`
- Each session has a TTL (`R2PS_SESSION_TTL`, default 5 minutes)
- `Get()` returns `nil` for expired sessions (lazy check)
- A background goroutine runs `CleanExpired()` on a 60-second ticker to reclaim memory
- The `ActiveSessions` Prometheus gauge tracks live sessions for monitoring
- Session IDs are cryptographically random (32 bytes, base64url-encoded) — not predictable

## Rationale

- In-memory storage is acceptable because sessions are short-lived and non-durable by design
- The cleanup goroutine prevents memory exhaustion under sustained load or session-stuffing attacks
- Lazy expiry check on `Get()` ensures correctness even between cleanup ticks
- No persistent session store is needed — an interrupted PAKE flow simply retries from the beginning

## Consequences

- Server restarts invalidate all active sessions (acceptable — clients retry)
- `R2PS_SESSION_TTL` should be short (minutes, not hours) to limit exposure of session keys
- Horizontal scaling requires sticky sessions or a shared session store (future work)
- The cleanup goroutine is not stoppable — it runs for the server's lifetime

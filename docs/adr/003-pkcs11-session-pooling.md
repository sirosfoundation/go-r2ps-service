# ADR-003: PKCS#11 Session Pooling

## Status

Accepted

## Context

PKCS#11 operations are serialized per session handle. The original design used a single session protected by `sync.Mutex`, making all HSM operations sequential. Under concurrent load, requests queue on the mutex regardless of HSM capacity.

## Decision

Replace the single-session mutex with a channel-based session pool. Multiple PKCS#11 sessions are opened at startup and distributed to goroutines on demand via `acquire(ctx)`/`release(session)`.

- Pool size configured via `R2PS_HSM_POOL_SIZE` (default 4)
- `acquire()` respects `context.Context` — cancellation/timeout prevents indefinite blocking
- Login is performed once (per-token state in PKCS#11), additional sessions share the auth state
- All sessions are closed on shutdown via `Close()`

## Rationale

- Eliminates mutex contention under concurrent load
- Pool size can be tuned to match HSM hardware capabilities
- Context-aware acquisition prevents goroutine leaks when HSM is slow or unresponsive
- Channel-based pool is simpler and safer than a custom pool implementation

## Consequences

- HSM modules must support multiple concurrent sessions (SoftHSM2 and most hardware HSMs do)
- `R2PS_HSM_POOL_SIZE` should match deployment capacity — oversizing wastes HSM resources
- Pool exhaustion surfaces as context deadline exceeded, tracked by HSM operation metrics

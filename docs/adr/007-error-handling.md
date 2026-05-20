# ADR-007: Error Handling and Sanitization

## Status

Accepted

## Context

R2PS handles HSM operations and PAKE authentication. Internal error details (HSM model, PKCS#11 error codes, key identifiers) must never reach the client — they are useful to attackers and irrelevant to the wallet.

## Decision

1. **Protocol errors** use `R2PSError{Code, Msg}` with codes from `pkg/r2ps` (e.g. `ErrUnauthorized`, `ErrServerError`). Messages are generic.

2. **Handler errors** are logged at `slog.Debug` with full details, then replaced with a generic message before returning to the dispatcher.

3. **HSM/crypto internals** are never exposed in error messages sent to clients. Kid values, PKCS#11 error codes, and module paths are stripped.

4. **Error wrapping** (`%w`) is used internally for diagnostics but the dispatcher breaks the chain before responding.

5. **Panic recovery** (`recoverMiddleware`) only recovers from panics in request-scoped code (handlers, serialisation). If the stack trace indicates the failure originated in infrastructure code (HSM pool, PAKE session store, sync primitives, runtime fatal), the panic is re-raised so the process exits and the orchestration layer (Kubernetes, Docker) restarts a clean instance. A service that silently continues in a corrupted state is worse than a brief restart.

## Rationale

R2PS is used for PID issuance and presentation. Leaking HSM internals or key identifiers in error responses creates an information disclosure risk. The dispatcher acts as a sanitization boundary.

## Consequences

- `slog.Debug` must be used to log handler errors with full context
- Client-facing error messages must be opaque ("sign failed", not "PKCS#11 CKR_KEY_HANDLE_INVALID")
- `R2PS_LOG_LEVEL=DEBUG` must never be enabled in production
- Tests should verify that error responses do not contain internal details

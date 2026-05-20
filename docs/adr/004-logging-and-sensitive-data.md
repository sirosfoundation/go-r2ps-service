# ADR-004: Structured Logging and Sensitive Data Policy

## Status

Accepted

## Context

R2PS processes PID issuance and presentation — flows where correlation leaks have privacy implications. Logs must support incident investigation without creating a surveillance surface.

## Decision

- Use `log/slog` with JSON or text output, configured via `R2PS_LOG_FORMAT`
- Default log level is `WARN` — only errors and warnings in production
- `R2PS_LOG_LEVEL=DEBUG` enables detailed diagnostics (HSM errors, handler inputs, session IDs)
- **Never log**: PINs, session keys, OPAQUE messages, raw JWE/JWS payloads, client identifiers at WARN or above
- **No request IDs or correlation headers** — deferred to avoid cross-request linkability in PID flows
- Metrics use opaque labels (`outcome=success/error`) without request-identifying dimensions

## Rationale

Standard library `slog` is the org-wide convention (used in go-trust, go-wallet-backend, confit, goFF, go-spocp). It provides structured output, level filtering, and zero external dependencies.

The decision to omit request IDs is deliberate: R2PS is a privacy-sensitive protocol. Server-side correlation of requests across PAKE and service phases could leak usage patterns.

## Consequences

- `R2PS_LOG_LEVEL=DEBUG` must never be enabled in production
- Incident investigation relies on metrics + timestamps rather than per-request tracing
- Future tracing support should be opt-in and assessed for privacy impact before adoption

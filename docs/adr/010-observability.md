# ADR-010: Observability (Metrics and Health Checks)

## Status

Accepted

## Context

R2PS runs as a containerized service in Kubernetes. Operators need to distinguish between "process alive" and "ready to serve traffic", and need quantitative insight into HSM performance and authentication patterns.

## Decision

**Health endpoints** (unauthenticated, GET):
- `/healthz` — always returns 200 (liveness probe)
- `/readyz` — probes HSM via `ListKeys()`, returns 503 if HSM is unreachable (readiness probe)
- `/metrics` — Prometheus scrape endpoint

**Prometheus metrics** (namespace `r2ps`):
- `requests_total{outcome}` — counter of HTTP-level request outcomes
- `request_duration_seconds` — histogram of end-to-end processing time
- `pake_auth_total{outcome}` — counter of PAKE authentication outcomes (success/failure)
- `hsm_operations_total{operation,outcome}` — counter per HSM operation type
- `hsm_operation_duration_seconds{operation}` — histogram of HSM latency
- `active_sessions` — gauge of live PAKE sessions

Metrics use `promauto` for automatic registration, consistent with go-trust and go-wallet-backend.

## Rationale

The Kubernetes liveness/readiness split prevents traffic routing to an instance with a failed HSM connection. HSM latency metrics are essential for capacity planning — PKCS#11 operations have variable latency depending on the hardware.

## Consequences

- `/metrics` must not be exposed to untrusted networks (use network policy or reverse proxy)
- Metric cardinality is bounded — labels are fixed enumerations, not request-derived
- Alerting thresholds for `hsm_operation_duration_seconds` and `pake_auth_total{outcome=failure}` should be configured per deployment

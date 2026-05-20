# ADR-005: TLS Termination

## Status

Accepted

## Context

R2PS carries JWS/JWE-wrapped messages over HTTP POST. The JWE layer provides end-to-end encryption of service data, but the outer JWS and protocol metadata (nonce, type, kid) transit in cleartext without transport security.

## Decision

The server supports two modes:

1. **Direct TLS**: Set `R2PS_TLS_CERT` and `R2PS_TLS_KEY` — the server calls `ListenAndServeTLS` with TLS 1.2 minimum.
2. **Reverse proxy**: Omit TLS env vars — the server listens on plain HTTP and logs a warning at startup. TLS is terminated by Caddy, nginx, or a cloud load balancer.

The server does **not** enforce TLS — it trusts the deployer to configure one of the two modes.

## Rationale

- Many production deployments already use a reverse proxy for certificate management (Let's Encrypt, ACME)
- Direct TLS is simpler for standalone/container deployments
- The startup warning makes misconfiguration visible without blocking development use

## Consequences

- Deployment documentation must specify which TLS mode is in use
- Health checks (`/healthz`, `/readyz`) work identically in both modes
- Kubernetes deployments typically use reverse proxy mode with a sidecar or ingress

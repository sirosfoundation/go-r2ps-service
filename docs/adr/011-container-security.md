# ADR-011: Container Security

## Status

Accepted

## Context

R2PS runs in Docker/Kubernetes with access to HSM hardware or SoftHSM2. The container must follow least-privilege principles while supporting CGO (required for PKCS#11 bindings).

## Decision

- **Multi-stage build**: Go builder stage (alpine + gcc/musl-dev) → minimal alpine runtime
- **Non-root user**: `appuser` (uid 1000), no login shell (`/sbin/nologin`)
- **Minimal packages**: Only `ca-certificates`, `softhsm`, `curl` in runtime image
- **System upgrade**: `apk --upgrade` on every build to pick up security patches
- **`.dockerignore`**: Excludes `.git`, tests, docs, CI config from build context
- **HEALTHCHECK**: `curl -sf http://localhost:8443/healthz` with 30s interval
- **Dependabot**: Monitors `golang` (builder base), `alpine` (runtime base), and all Go modules weekly

## Rationale

CGO prevents fully static builds, so alpine with musl is the smallest viable runtime. The non-root user with no shell limits post-exploitation utility. Dependabot on the `docker` ecosystem catches base image CVEs automatically.

## Consequences

- Production deployments with hardware HSMs must replace `softhsm` with the vendor's PKCS#11 library
- CGO dependency means images are architecture-specific (CI builds `amd64` + `arm64`)
- `curl` is included solely for healthcheck — could be replaced with a static binary to further reduce attack surface

# ADR-002: Test Coverage

## Status

Accepted

## Context

The R2PS service handles PAKE authentication and HSM-backed cryptographic operations for PID issuance. High reliability is essential — failures could block credential workflows.

## Decision

Target >70% overall coverage, with >80% for:
- HSM backend operations (`internal/hsm`)
- PAKE authentication flows (`internal/pake`)
- Cryptographic utilities (`internal/crypto`)
- End-to-end protocol flows (`test/integration`)

Integration tests use SoftHSM2 as a PKCS#11 backend. CI runs tests with `-race` to detect concurrency issues in the session pool.

## Rationale

Given AI-assisted development, comprehensive tests reduce hallucination risk and catch regressions. The PKCS#11 session pool and OPAQUE state machine have complex concurrency and state semantics that require thorough testing.

## Consequences

- All new code must include tests
- PRs must not decrease coverage
- CI generates coverage badges per branch
- SoftHSM2 is a build-time dependency for testing

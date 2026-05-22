// Package conformance provides cross-implementation conformance tests for the
// R2PS protocol. These tests verify wire-level interoperability between
// go-r2ps-service and r2ps-client (Rust).
//
// The tests operate on a shared test vectors JSON file that can be generated
// by either implementation and consumed by the other. This enables:
//
//  1. Self-consistency: each implementation validates its own vectors
//  2. Cross-validation: each implementation validates the other's vectors
//  3. CI conformance: vectors are committed so tests run without the other impl
//
// Test layers:
//
//	Layer 1 — Crypto primitives (JWS sign/verify, JWE encrypt/decrypt)
//	Layer 2 — Protocol envelope (ServiceRequest/Response JSON compatibility)
//	Layer 3 — HSM service types (request/response format compatibility)
package conformance

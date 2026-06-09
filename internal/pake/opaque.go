package pake

import (
	"crypto"
	"fmt"

	"github.com/bytemare/opaque"
	"github.com/bytemare/opaque/message"
)

// OPAQUEConfig holds the OPAQUE configuration used by both server and client.
var OPAQUEConfig = &opaque.Configuration{
	OPRF: opaque.P256Sha256,
	AKE:  opaque.P256Sha256,
	KDF:  crypto.SHA256,
	MAC:  crypto.SHA256,
	Hash: crypto.SHA256,
}

// ServerKeyMaterial wraps the OPAQUE server key material.
type ServerKeyMaterial = opaque.ServerKeyMaterial

// GenerateServerKeyMaterial creates new server key material (private key + OPRF seed).
func GenerateServerKeyMaterial() (*ServerKeyMaterial, error) {
	sk, pk := OPAQUEConfig.KeyGen()
	oprfSeed := OPAQUEConfig.GenerateOPRFSeed()

	return &ServerKeyMaterial{
		PrivateKey:     sk,
		PublicKeyBytes: pk.Encode(),
		OPRFGlobalSeed: oprfSeed,
	}, nil
}

// OPAQUEServer wraps the bytemare/opaque Server with R2PS-specific logic.
type OPAQUEServer struct {
	server      *opaque.Server
	deserialize *opaque.Deserializer
}

// NewOPAQUEServer creates a new OPAQUE server with the given key material.
func NewOPAQUEServer(skm *ServerKeyMaterial) (*OPAQUEServer, error) {
	server, err := OPAQUEConfig.Server()
	if err != nil {
		return nil, fmt.Errorf("create OPAQUE server: %w", err)
	}

	if err := server.SetKeyMaterial(skm); err != nil {
		return nil, fmt.Errorf("set key material: %w", err)
	}

	deser, err := OPAQUEConfig.Deserializer()
	if err != nil {
		return nil, fmt.Errorf("create deserializer: %w", err)
	}

	return &OPAQUEServer{
		server:      server,
		deserialize: deser,
	}, nil
}

// Deserializer returns the OPAQUE deserializer for record deserialization.
func (s *OPAQUEServer) Deserializer() *opaque.Deserializer {
	return s.deserialize
}

// RegistrationResponse processes a client's registration request (evaluate phase).
// credentialID should be a stable per-client identifier (e.g. client_id + kid).
func (s *OPAQUEServer) RegistrationResponse(reqBytes []byte, credentialID []byte) ([]byte, error) {
	req, err := s.deserialize.RegistrationRequest(reqBytes)
	if err != nil {
		return nil, fmt.Errorf("deserialize registration request: %w", err)
	}

	resp, err := s.server.RegistrationResponse(req, credentialID, nil)
	if err != nil {
		return nil, fmt.Errorf("generate registration response: %w", err)
	}

	return resp.Serialize(), nil
}

// RegistrationFinalize stores the client's registration record.
// Returns the serialized RegistrationRecord that should be persisted.
func (s *OPAQUEServer) DeserializeRegistrationRecord(recordBytes []byte) (*message.RegistrationRecord, error) {
	return s.deserialize.RegistrationRecord(recordBytes)
}

// AuthEvaluate processes a KE1 message (evaluate phase of authentication).
// Returns (KE2 bytes, expectedClientMAC, sessionSecret, error).
func (s *OPAQUEServer) AuthEvaluate(ke1Bytes []byte, record *opaque.ClientRecord) ([]byte, []byte, []byte, error) {
	ke1, err := s.deserialize.KE1(ke1Bytes)
	if err != nil {
		return nil, nil, nil, fmt.Errorf("deserialize KE1: %w", err)
	}

	ke2, output, err := s.server.GenerateKE2(ke1, record)
	if err != nil {
		return nil, nil, nil, fmt.Errorf("generate KE2: %w", err)
	}

	return ke2.Serialize(), output.ClientMAC, output.SessionSecret, nil
}

// AuthFinalize verifies the client's KE3 message (finalize phase of authentication).
// If this returns nil, the session secret from AuthEvaluate is valid.
func (s *OPAQUEServer) AuthFinalize(ke3Bytes []byte, expectedClientMAC []byte) error {
	ke3, err := s.deserialize.KE3(ke3Bytes)
	if err != nil {
		return fmt.Errorf("deserialize KE3: %w", err)
	}

	return s.server.LoginFinish(ke3, expectedClientMAC)
}

// FakeRecord returns a fake ClientRecord for the given credential identifier.
// This is used when the client_id is unknown, to prevent client enumeration.
func (s *OPAQUEServer) FakeRecord(credentialID []byte) *opaque.ClientRecord {
	record, err := OPAQUEConfig.GetFakeRecord(credentialID)
	if err != nil {
		// Fallback: this should never fail with valid config
		record, _ = OPAQUEConfig.GetFakeRecord(credentialID)
	}
	return record
}

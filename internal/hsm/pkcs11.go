package hsm

import (
	"context"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"encoding/asn1"
	"encoding/hex"
	"fmt"
	"math/big"

	"github.com/miekg/pkcs11"
)

// PKCS11Config holds configuration for connecting to a PKCS#11 token.
type PKCS11Config struct {
	ModulePath string // path to the PKCS#11 shared library (e.g. /usr/lib/softhsm/libsofthsm2.so)
	SlotID     uint   // slot number
	PIN        string // user PIN for the token
	TokenLabel string // optional: find slot by label instead of ID
	PoolSize   int    // number of concurrent PKCS#11 sessions (default 4)
}

// PKCS11Backend implements Backend using a pool of PKCS#11 sessions.
type PKCS11Backend struct {
	ctx    *pkcs11.Ctx
	pool   chan pkcs11.SessionHandle
	slotID uint
}

// NewPKCS11Backend connects to a PKCS#11 token and creates a session pool.
func NewPKCS11Backend(cfg PKCS11Config) (*PKCS11Backend, error) {
	ctx := pkcs11.New(cfg.ModulePath)
	if ctx == nil {
		return nil, fmt.Errorf("failed to load PKCS#11 module: %s", cfg.ModulePath)
	}

	if err := ctx.Initialize(); err != nil {
		return nil, fmt.Errorf("PKCS#11 initialize: %w", err)
	}

	slotID := cfg.SlotID
	if cfg.TokenLabel != "" {
		slots, err := ctx.GetSlotList(true)
		if err != nil {
			_ = ctx.Finalize()
			return nil, fmt.Errorf("get slot list: %w", err)
		}
		found := false
		for _, s := range slots {
			ti, err := ctx.GetTokenInfo(s)
			if err != nil {
				continue
			}
			if ti.Label == cfg.TokenLabel {
				slotID = s
				found = true
				break
			}
		}
		if !found {
			_ = ctx.Finalize()
			return nil, fmt.Errorf("token with label %q not found", cfg.TokenLabel)
		}
	}

	poolSize := cfg.PoolSize
	if poolSize <= 0 {
		poolSize = 4
	}

	// Open first session and login (login is per-token, applies to all sessions)
	firstSession, err := ctx.OpenSession(slotID, pkcs11.CKF_SERIAL_SESSION|pkcs11.CKF_RW_SESSION)
	if err != nil {
		_ = ctx.Finalize()
		return nil, fmt.Errorf("open session: %w", err)
	}

	if err := ctx.Login(firstSession, pkcs11.CKU_USER, cfg.PIN); err != nil {
		_ = ctx.CloseSession(firstSession)
		_ = ctx.Finalize()
		return nil, fmt.Errorf("login: %w", err)
	}

	pool := make(chan pkcs11.SessionHandle, poolSize)
	pool <- firstSession

	// Open remaining sessions (login state is shared per-token)
	for i := 1; i < poolSize; i++ {
		sess, err := ctx.OpenSession(slotID, pkcs11.CKF_SERIAL_SESSION|pkcs11.CKF_RW_SESSION)
		if err != nil {
			// Close already-created sessions and bail
			close(pool)
			for s := range pool {
				_ = ctx.CloseSession(s)
			}
			_ = ctx.Logout(firstSession)
			_ = ctx.Finalize()
			return nil, fmt.Errorf("open pool session %d: %w", i, err)
		}
		pool <- sess
	}

	return &PKCS11Backend{
		ctx:    ctx,
		pool:   pool,
		slotID: slotID,
	}, nil
}

// acquire gets a session from the pool, respecting context cancellation.
func (b *PKCS11Backend) acquire(ctx context.Context) (pkcs11.SessionHandle, error) {
	select {
	case sess := <-b.pool:
		return sess, nil
	case <-ctx.Done():
		return 0, ctx.Err()
	}
}

// release returns a session to the pool.
func (b *PKCS11Backend) release(sess pkcs11.SessionHandle) {
	b.pool <- sess
}

// Close logs out and cleans up all PKCS#11 sessions.
func (b *PKCS11Backend) Close() error {
	// Drain pool and close all sessions
	close(b.pool)
	var first pkcs11.SessionHandle
	var gotFirst bool
	for s := range b.pool {
		if !gotFirst {
			first = s
			gotFirst = true
		}
		_ = b.ctx.CloseSession(s)
	}
	if gotFirst {
		_ = b.ctx.Logout(first)
	}
	_ = b.ctx.Finalize()
	return nil
}

func (b *PKCS11Backend) GenerateECKey(ctx context.Context, curveName string) (string, []byte, error) {
	session, err := b.acquire(ctx)
	if err != nil {
		return "", nil, fmt.Errorf("acquire session: %w", err)
	}
	defer b.release(session)

	oid, err := curveOID(curveName)
	if err != nil {
		return "", nil, err
	}

	// Encode OID as DER (required by PKCS#11)
	derOID, err := asn1.Marshal(oid)
	if err != nil {
		return "", nil, fmt.Errorf("marshal OID: %w", err)
	}

	// Generate a kid for CKA_ID
	kidBytes := make([]byte, 16)
	copy(kidBytes, randomBytes(16))

	pubTemplate := []*pkcs11.Attribute{
		pkcs11.NewAttribute(pkcs11.CKA_TOKEN, true),
		pkcs11.NewAttribute(pkcs11.CKA_VERIFY, true),
		pkcs11.NewAttribute(pkcs11.CKA_EC_PARAMS, derOID),
		pkcs11.NewAttribute(pkcs11.CKA_ID, kidBytes),
	}

	privTemplate := []*pkcs11.Attribute{
		pkcs11.NewAttribute(pkcs11.CKA_TOKEN, true),
		pkcs11.NewAttribute(pkcs11.CKA_SIGN, true),
		pkcs11.NewAttribute(pkcs11.CKA_SENSITIVE, true),
		pkcs11.NewAttribute(pkcs11.CKA_EXTRACTABLE, false),
		pkcs11.NewAttribute(pkcs11.CKA_DERIVE, true),
		pkcs11.NewAttribute(pkcs11.CKA_ID, kidBytes),
	}

	pubHandle, _, err := b.ctx.GenerateKeyPair(
		session,
		[]*pkcs11.Mechanism{pkcs11.NewMechanism(pkcs11.CKM_EC_KEY_PAIR_GEN, nil)},
		pubTemplate,
		privTemplate,
	)
	if err != nil {
		return "", nil, fmt.Errorf("generate key pair: %w", err)
	}

	// Read the EC point from the public key
	pubBytes, err := b.readECPoint(session, pubHandle, curveName)
	if err != nil {
		return "", nil, fmt.Errorf("read public key: %w", err)
	}

	// Compute kid from public key hash
	hash := sha256.Sum256(pubBytes)
	kid := hex.EncodeToString(hash[:16])

	// Update CKA_ID to match the computed kid
	if err := b.ctx.SetAttributeValue(session, pubHandle, []*pkcs11.Attribute{
		pkcs11.NewAttribute(pkcs11.CKA_ID, []byte(kid)),
	}); err != nil {
		return "", nil, fmt.Errorf("update pub CKA_ID: %w", err)
	}

	// Find the private key by the temporary kidBytes and update it
	privHandle, err := b.findPrivateKeyByID(session, kidBytes)
	if err != nil {
		return "", nil, fmt.Errorf("find private key: %w", err)
	}
	if err := b.ctx.SetAttributeValue(session, privHandle, []*pkcs11.Attribute{
		pkcs11.NewAttribute(pkcs11.CKA_ID, []byte(kid)),
	}); err != nil {
		return "", nil, fmt.Errorf("update priv CKA_ID: %w", err)
	}

	return kid, pubBytes, nil
}

func (b *PKCS11Backend) Sign(ctx context.Context, kid string, hash []byte) ([]byte, error) {
	session, err := b.acquire(ctx)
	if err != nil {
		return nil, fmt.Errorf("acquire session: %w", err)
	}
	defer b.release(session)

	privHandle, err := b.findPrivateKeyByID(session, []byte(kid))
	if err != nil {
		return nil, fmt.Errorf("find key: %w", err)
	}

	if err := b.ctx.SignInit(session, []*pkcs11.Mechanism{
		pkcs11.NewMechanism(pkcs11.CKM_ECDSA, nil),
	}, privHandle); err != nil {
		return nil, fmt.Errorf("sign init: %w", err)
	}

	rawSig, err := b.ctx.Sign(session, hash)
	if err != nil {
		return nil, fmt.Errorf("sign: %w", err)
	}

	// PKCS#11 returns raw r||s, convert to ASN.1 DER
	return rawSigToASN1(rawSig)
}

func (b *PKCS11Backend) ECDH(ctx context.Context, kid string, peerPubKey []byte) ([]byte, error) {
	session, err := b.acquire(ctx)
	if err != nil {
		return nil, fmt.Errorf("acquire session: %w", err)
	}
	defer b.release(session)

	privHandle, err := b.findPrivateKeyByID(session, []byte(kid))
	if err != nil {
		return nil, fmt.Errorf("find key: %w", err)
	}

	// Ensure peer key is in uncompressed form (0x04 || x || y)
	ecPoint := peerPubKey
	if len(ecPoint) > 0 && (ecPoint[0] == 0x02 || ecPoint[0] == 0x03) {
		// Compressed — need to decompress. Determine curve from our key.
		curveName, err := b.getKeyCurve(session, privHandle)
		if err != nil {
			return nil, fmt.Errorf("get key curve: %w", err)
		}
		curve, err := parseCurve(curveName)
		if err != nil {
			return nil, err
		}
		x, y := elliptic.UnmarshalCompressed(curve, ecPoint)
		if x == nil {
			return nil, fmt.Errorf("decompress peer public key failed")
		}
		ecPoint = elliptic.Marshal(curve, x, y) //nolint:staticcheck // PKCS#11 needs uncompressed format
	}

	// CKM_ECDH1_DERIVE with CKD_NULL
	params := pkcs11.NewECDH1DeriveParams(pkcs11.CKD_NULL, nil, ecPoint)

	deriveTemplate := []*pkcs11.Attribute{
		pkcs11.NewAttribute(pkcs11.CKA_CLASS, pkcs11.CKO_SECRET_KEY),
		pkcs11.NewAttribute(pkcs11.CKA_KEY_TYPE, pkcs11.CKK_GENERIC_SECRET),
		pkcs11.NewAttribute(pkcs11.CKA_EXTRACTABLE, true),
		pkcs11.NewAttribute(pkcs11.CKA_SENSITIVE, false),
		pkcs11.NewAttribute(pkcs11.CKA_VALUE_LEN, 32),
	}

	secretHandle, err := b.ctx.DeriveKey(
		session,
		[]*pkcs11.Mechanism{pkcs11.NewMechanism(pkcs11.CKM_ECDH1_DERIVE, params)},
		privHandle,
		deriveTemplate,
	)
	if err != nil {
		return nil, fmt.Errorf("ECDH derive: %w", err)
	}

	// Extract the secret value
	attrs, err := b.ctx.GetAttributeValue(session, secretHandle, []*pkcs11.Attribute{
		pkcs11.NewAttribute(pkcs11.CKA_VALUE, nil),
	})
	if err != nil {
		return nil, fmt.Errorf("get derived secret: %w", err)
	}

	if len(attrs) == 0 || len(attrs[0].Value) == 0 {
		return nil, fmt.Errorf("empty derived secret")
	}

	// Clean up the derived key object
	_ = b.ctx.DestroyObject(session, secretHandle)

	return attrs[0].Value, nil
}

func (b *PKCS11Backend) ListKeys(ctx context.Context, curves []string) ([]KeyInfo, error) {
	session, err := b.acquire(ctx)
	if err != nil {
		return nil, fmt.Errorf("acquire session: %w", err)
	}
	defer b.release(session)

	template := []*pkcs11.Attribute{
		pkcs11.NewAttribute(pkcs11.CKA_CLASS, pkcs11.CKO_PUBLIC_KEY),
		pkcs11.NewAttribute(pkcs11.CKA_KEY_TYPE, pkcs11.CKK_EC),
	}

	if err := b.ctx.FindObjectsInit(session, template); err != nil {
		return nil, fmt.Errorf("find init: %w", err)
	}

	var keys []KeyInfo
	for {
		handles, _, err := b.ctx.FindObjects(session, 32)
		if err != nil {
			_ = b.ctx.FindObjectsFinal(session)
			return nil, fmt.Errorf("find objects: %w", err)
		}
		if len(handles) == 0 {
			break
		}

		for _, h := range handles {
			curveName, err := b.getKeyCurve(session, h)
			if err != nil {
				continue
			}

			if len(curves) > 0 && !contains(curves, curveName) {
				continue
			}

			pubBytes, err := b.readECPoint(session, h, curveName)
			if err != nil {
				continue
			}

			attrs, err := b.ctx.GetAttributeValue(session, h, []*pkcs11.Attribute{
				pkcs11.NewAttribute(pkcs11.CKA_ID, nil),
			})
			if err != nil || len(attrs) == 0 {
				continue
			}

			kid := string(attrs[0].Value)
			keys = append(keys, KeyInfo{
				Kid:    kid,
				Curve:  curveName,
				PubKey: pubBytes,
			})
		}
	}

	_ = b.ctx.FindObjectsFinal(session)
	return keys, nil
}

// PoolSize returns the configured pool size (number of available + in-use sessions).
func (b *PKCS11Backend) PoolSize() int {
	return cap(b.pool)
}

// --- helpers ---

func (b *PKCS11Backend) findPrivateKeyByID(session pkcs11.SessionHandle, id []byte) (pkcs11.ObjectHandle, error) {
	template := []*pkcs11.Attribute{
		pkcs11.NewAttribute(pkcs11.CKA_CLASS, pkcs11.CKO_PRIVATE_KEY),
		pkcs11.NewAttribute(pkcs11.CKA_ID, id),
	}

	if err := b.ctx.FindObjectsInit(session, template); err != nil {
		return 0, fmt.Errorf("find init: %w", err)
	}
	defer b.ctx.FindObjectsFinal(session) //nolint:errcheck // best-effort cleanup

	handles, _, err := b.ctx.FindObjects(session, 1)
	if err != nil {
		return 0, fmt.Errorf("find objects: %w", err)
	}
	if len(handles) == 0 {
		return 0, fmt.Errorf("key not found")
	}
	return handles[0], nil
}

func (b *PKCS11Backend) readECPoint(session pkcs11.SessionHandle, handle pkcs11.ObjectHandle, curveName string) ([]byte, error) {
	attrs, err := b.ctx.GetAttributeValue(session, handle, []*pkcs11.Attribute{
		pkcs11.NewAttribute(pkcs11.CKA_EC_POINT, nil),
	})
	if err != nil {
		return nil, fmt.Errorf("get EC point: %w", err)
	}
	if len(attrs) == 0 || len(attrs[0].Value) == 0 {
		return nil, fmt.Errorf("empty EC point")
	}

	ecPoint := attrs[0].Value

	// PKCS#11 wraps EC_POINT in an OCTET STRING — unwrap it
	var rawPoint []byte
	rest, err := asn1.Unmarshal(ecPoint, &rawPoint)
	if err == nil && len(rest) == 0 {
		ecPoint = rawPoint
	}

	// ecPoint is now uncompressed: 0x04 || x || y
	// Compress it
	curve, err := parseCurve(curveName)
	if err != nil {
		return nil, err
	}

	x, y := elliptic.Unmarshal(curve, ecPoint) //nolint:staticcheck // PKCS#11 returns raw EC points
	if x == nil {
		return nil, fmt.Errorf("invalid uncompressed EC point (len=%d)", len(ecPoint))
	}

	return elliptic.MarshalCompressed(curve, x, y), nil
}

func (b *PKCS11Backend) getKeyCurve(session pkcs11.SessionHandle, handle pkcs11.ObjectHandle) (string, error) {
	attrs, err := b.ctx.GetAttributeValue(session, handle, []*pkcs11.Attribute{
		pkcs11.NewAttribute(pkcs11.CKA_EC_PARAMS, nil),
	})
	if err != nil {
		return "", fmt.Errorf("get EC params: %w", err)
	}
	if len(attrs) == 0 || len(attrs[0].Value) == 0 {
		return "", fmt.Errorf("empty EC params")
	}

	return oidToCurveName(attrs[0].Value)
}

// --- OID / curve mapping ---

var (
	oidP256 = asn1.ObjectIdentifier{1, 2, 840, 10045, 3, 1, 7}
	oidP384 = asn1.ObjectIdentifier{1, 3, 132, 0, 34}
	oidP521 = asn1.ObjectIdentifier{1, 3, 132, 0, 35}
)

func curveOID(name string) (asn1.ObjectIdentifier, error) {
	switch name {
	case "P-256":
		return oidP256, nil
	case "P-384":
		return oidP384, nil
	case "P-521":
		return oidP521, nil
	default:
		return nil, fmt.Errorf("unsupported curve: %s", name)
	}
}

func oidToCurveName(derParams []byte) (string, error) {
	var oid asn1.ObjectIdentifier
	if _, err := asn1.Unmarshal(derParams, &oid); err != nil {
		return "", fmt.Errorf("unmarshal OID: %w", err)
	}

	switch {
	case oid.Equal(oidP256):
		return "P-256", nil
	case oid.Equal(oidP384):
		return "P-384", nil
	case oid.Equal(oidP521):
		return "P-521", nil
	default:
		return "", fmt.Errorf("unknown curve OID: %v", oid)
	}
}

func parseCurve(name string) (elliptic.Curve, error) {
	switch name {
	case "P-256":
		return elliptic.P256(), nil
	case "P-384":
		return elliptic.P384(), nil
	case "P-521":
		return elliptic.P521(), nil
	default:
		return nil, fmt.Errorf("unsupported curve: %s", name)
	}
}

func rawSigToASN1(raw []byte) ([]byte, error) {
	if len(raw)%2 != 0 {
		return nil, fmt.Errorf("invalid raw signature length: %d", len(raw))
	}
	half := len(raw) / 2
	r := new(big.Int).SetBytes(raw[:half])
	s := new(big.Int).SetBytes(raw[half:])

	type ecdsaSig struct {
		R, S *big.Int
	}
	return asn1.Marshal(ecdsaSig{R: r, S: s})
}

func randomBytes(n int) []byte {
	b := make([]byte, n)
	if _, err := rand.Read(b); err != nil {
		panic("crypto/rand: " + err.Error())
	}
	return b
}

func contains(ss []string, s string) bool {
	for _, v := range ss {
		if v == s {
			return true
		}
	}
	return false
}

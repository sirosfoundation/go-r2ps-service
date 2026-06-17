package store

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"net/url"
	"os"
	"strings"
	"time"

	"go.mongodb.org/mongo-driver/bson"
	"go.mongodb.org/mongo-driver/mongo"
	"go.mongodb.org/mongo-driver/mongo/options"
)

// MongoDBConfig holds the MongoDB connection configuration.
type MongoDBConfig struct {
	URI          string
	Database     string
	Timeout      int    // seconds
	PasswordPath string // path to file containing MongoDB password (replaces placeholder in URI)

	// TLS / mTLS configuration
	TLSEnabled bool   // enable TLS for MongoDB connection
	CAPath     string // path to CA certificate for server verification
	CertPath   string // path to client certificate for mTLS
	KeyPath    string // path to client key for mTLS
}

// statusEntry is the BSON document for the statuses collection.
type statusEntry struct {
	Category string `bson:"category"`
	Idx      int    `bson:"idx"`
	Status   byte   `bson:"status"`
}

// clientIndexEntry is the BSON document for the client_indices collection.
type clientIndexEntry struct {
	ClientID string `bson:"client_id"`
	Category string `bson:"category"`
	Idx      int    `bson:"idx"`
}

// usageEntry is the BSON document for the usage collection.
type usageEntry struct {
	Category string    `bson:"category"`
	Idx      int       `bson:"idx"`
	UsedAt   time.Time `bson:"used_at"`
}

// MongoDBStore implements Store backed by MongoDB.
type MongoDBStore struct {
	client        *mongo.Client
	database      *mongo.Database
	counters      *mongo.Collection
	statuses      *mongo.Collection
	clientIndices *mongo.Collection
	usage         *mongo.Collection
	publicKeys    *mongo.Collection
	records       *mongo.Collection
	webauthnCreds *mongo.Collection
}

// NewMongoDBStore creates a new MongoDB-backed store.
func NewMongoDBStore(ctx context.Context, cfg *MongoDBConfig) (*MongoDBStore, error) {
	timeout := cfg.Timeout
	if timeout == 0 {
		timeout = 10
	}

	uri := cfg.URI

	// Replace password placeholder from file (same pattern as go-wallet-backend).
	if cfg.PasswordPath != "" {
		raw, err := os.ReadFile(cfg.PasswordPath)
		if err != nil {
			return nil, fmt.Errorf("failed to read MongoDB password file: %w", err)
		}
		password := strings.TrimSpace(string(raw))
		uri = strings.Replace(uri, "${MONGODB_PASSWORD}", url.QueryEscape(password), 1)
	}

	clientOptions := options.Client().
		ApplyURI(uri).
		SetConnectTimeout(time.Duration(timeout) * time.Second)

	// TLS / mTLS configuration (mirrors go-wallet-backend).
	if cfg.TLSEnabled {
		tlsCfg := &tls.Config{MinVersion: tls.VersionTLS12}
		if cfg.CAPath != "" {
			caCert, err := os.ReadFile(cfg.CAPath)
			if err != nil {
				return nil, fmt.Errorf("failed to read MongoDB CA certificate: %w", err)
			}
			pool := x509.NewCertPool()
			if !pool.AppendCertsFromPEM(caCert) {
				return nil, fmt.Errorf("failed to parse MongoDB CA certificate")
			}
			tlsCfg.RootCAs = pool
		}
		if cfg.CertPath != "" && cfg.KeyPath != "" {
			cert, err := tls.LoadX509KeyPair(cfg.CertPath, cfg.KeyPath)
			if err != nil {
				return nil, fmt.Errorf("failed to load MongoDB client certificate: %w", err)
			}
			tlsCfg.Certificates = []tls.Certificate{cert}
		}
		clientOptions.SetTLSConfig(tlsCfg)
	}

	client, err := mongo.Connect(ctx, clientOptions)
	if err != nil {
		return nil, fmt.Errorf("failed to connect to MongoDB: %w", err)
	}

	if err := client.Ping(ctx, nil); err != nil {
		return nil, fmt.Errorf("failed to ping MongoDB: %w", err)
	}

	dbName := cfg.Database
	if dbName == "" {
		dbName = "r2ps"
	}
	database := client.Database(dbName)

	s := &MongoDBStore{
		client:        client,
		database:      database,
		counters:      database.Collection("counters"),
		statuses:      database.Collection("statuses"),
		clientIndices: database.Collection("client_indices"),
		usage:         database.Collection("usage"),
		publicKeys:    database.Collection("public_keys"),
		records:       database.Collection("opaque_records"),
		webauthnCreds: database.Collection("webauthn_credentials"),
	}

	if err := s.createIndexes(ctx); err != nil {
		return nil, fmt.Errorf("failed to create indexes: %w", err)
	}

	return s, nil
}

func (s *MongoDBStore) createIndexes(ctx context.Context) error {
	// statuses: unique compound index on (category, idx)
	_, err := s.statuses.Indexes().CreateOne(ctx, mongo.IndexModel{
		Keys:    bson.D{{Key: "category", Value: 1}, {Key: "idx", Value: 1}},
		Options: options.Index().SetUnique(true),
	})
	if err != nil {
		return fmt.Errorf("failed to create statuses index: %w", err)
	}

	// client_indices: compound index on (client_id, category)
	_, err = s.clientIndices.Indexes().CreateOne(ctx, mongo.IndexModel{
		Keys: bson.D{{Key: "client_id", Value: 1}, {Key: "category", Value: 1}},
	})
	if err != nil {
		return fmt.Errorf("failed to create client_indices index: %w", err)
	}

	// usage: unique compound index on (category, idx)
	_, err = s.usage.Indexes().CreateOne(ctx, mongo.IndexModel{
		Keys:    bson.D{{Key: "category", Value: 1}, {Key: "idx", Value: 1}},
		Options: options.Index().SetUnique(true),
	})
	if err != nil {
		return fmt.Errorf("failed to create usage index: %w", err)
	}

	// public_keys: unique index on kid
	_, err = s.publicKeys.Indexes().CreateOne(ctx, mongo.IndexModel{
		Keys:    bson.D{{Key: "kid", Value: 1}},
		Options: options.Index().SetUnique(true),
	})
	if err != nil {
		return fmt.Errorf("failed to create public_keys index: %w", err)
	}

	// opaque_records: unique compound index on (client_id, context)
	_, err = s.records.Indexes().CreateOne(ctx, mongo.IndexModel{
		Keys:    bson.D{{Key: "client_id", Value: 1}, {Key: "context", Value: 1}},
		Options: options.Index().SetUnique(true),
	})
	if err != nil {
		return fmt.Errorf("failed to create records index: %w", err)
	}

	// webauthn_credentials: compound index on (client_id, context)
	_, err = s.webauthnCreds.Indexes().CreateOne(ctx, mongo.IndexModel{
		Keys: bson.D{{Key: "client_id", Value: 1}, {Key: "context", Value: 1}},
	})
	if err != nil {
		return fmt.Errorf("failed to create webauthn_credentials index: %w", err)
	}

	return nil
}

// Close disconnects from MongoDB.
func (s *MongoDBStore) Close(ctx context.Context) error {
	return s.client.Disconnect(ctx)
}

// Ping verifies the MongoDB connection is alive.
func (s *MongoDBStore) Ping(ctx context.Context) error {
	return s.client.Ping(ctx, nil)
}

func (s *MongoDBStore) AllocateIndex(category string) (int, error) {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	// Atomic increment counter (upsert so first call creates the doc).
	opts := options.FindOneAndUpdate().
		SetUpsert(true).
		SetReturnDocument(options.After)

	var doc struct {
		Value int `bson:"value"`
	}
	err := s.counters.FindOneAndUpdate(
		ctx,
		bson.M{"_id": category},
		bson.M{"$inc": bson.M{"value": 1}},
		opts,
	).Decode(&doc)
	if err != nil {
		return 0, fmt.Errorf("failed to allocate index for %q: %w", category, err)
	}

	// Counter returns 1-based after increment; convert to 0-based index.
	idx := doc.Value - 1

	// Insert initial status entry.
	_, err = s.statuses.InsertOne(ctx, statusEntry{
		Category: category,
		Idx:      idx,
		Status:   StatusValid,
	})
	if err != nil {
		return 0, fmt.Errorf("failed to insert status entry: %w", err)
	}

	return idx, nil
}

func (s *MongoDBStore) GetStatus(category string, idx int) (byte, error) {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	var entry statusEntry
	err := s.statuses.FindOne(ctx, bson.M{"category": category, "idx": idx}).Decode(&entry)
	if err != nil {
		if err == mongo.ErrNoDocuments {
			return 0, fmt.Errorf("index %d not found in category %q", idx, category)
		}
		return 0, fmt.Errorf("failed to get status: %w", err)
	}
	return entry.Status, nil
}

func (s *MongoDBStore) SetStatus(category string, idx int, status byte) error {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	result, err := s.statuses.UpdateOne(
		ctx,
		bson.M{"category": category, "idx": idx},
		bson.M{"$set": bson.M{"status": status}},
	)
	if err != nil {
		return fmt.Errorf("failed to set status: %w", err)
	}
	if result.MatchedCount == 0 {
		return fmt.Errorf("index %d not found in category %q", idx, category)
	}
	return nil
}

func (s *MongoDBStore) GetAllStatuses(category string) (map[int]byte, error) {
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	cursor, err := s.statuses.Find(ctx, bson.M{"category": category})
	if err != nil {
		return nil, fmt.Errorf("failed to find statuses: %w", err)
	}
	defer func() { _ = cursor.Close(ctx) }()

	result := make(map[int]byte)
	for cursor.Next(ctx) {
		var entry statusEntry
		if err := cursor.Decode(&entry); err != nil {
			return nil, fmt.Errorf("failed to decode status entry: %w", err)
		}
		result[entry.Idx] = entry.Status
	}
	if err := cursor.Err(); err != nil {
		return nil, fmt.Errorf("cursor error: %w", err)
	}
	return result, nil
}

func (s *MongoDBStore) RecordWUA(clientID, category string, idx int) error {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	_, err := s.clientIndices.InsertOne(ctx, clientIndexEntry{
		ClientID: clientID,
		Category: category,
		Idx:      idx,
	})
	if err != nil {
		return fmt.Errorf("failed to record WUA: %w", err)
	}
	return nil
}

func (s *MongoDBStore) GetClientIndices(clientID, category string) ([]int, error) {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	cursor, err := s.clientIndices.Find(ctx, bson.M{"client_id": clientID, "category": category})
	if err != nil {
		return nil, fmt.Errorf("failed to find client indices: %w", err)
	}
	defer func() { _ = cursor.Close(ctx) }()

	var indices []int
	for cursor.Next(ctx) {
		var entry clientIndexEntry
		if err := cursor.Decode(&entry); err != nil {
			return nil, fmt.Errorf("failed to decode client index: %w", err)
		}
		indices = append(indices, entry.Idx)
	}
	if err := cursor.Err(); err != nil {
		return nil, fmt.Errorf("cursor error: %w", err)
	}
	return indices, nil
}

func (s *MongoDBStore) RecordUsage(category string, idx int) error {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	_, err := s.usage.InsertOne(ctx, usageEntry{
		Category: category,
		Idx:      idx,
		UsedAt:   time.Now(),
	})
	if err != nil {
		if mongo.IsDuplicateKeyError(err) {
			// Already recorded — idempotent.
			return nil
		}
		return fmt.Errorf("failed to record usage: %w", err)
	}
	return nil
}

func (s *MongoDBStore) IsUsed(category string, idx int) (bool, error) {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	err := s.usage.FindOne(ctx, bson.M{"category": category, "idx": idx}).Err()
	if err != nil {
		if err == mongo.ErrNoDocuments {
			return false, nil
		}
		return false, fmt.Errorf("failed to check usage: %w", err)
	}
	return true, nil
}

func (s *MongoDBStore) PutPublicKey(key PublicKeyInfo) error {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	opts := options.Replace().SetUpsert(true)
	_, err := s.publicKeys.ReplaceOne(ctx, bson.M{"kid": key.Kid}, key, opts)
	if err != nil {
		return fmt.Errorf("failed to put public key: %w", err)
	}
	return nil
}

func (s *MongoDBStore) GetPublicKey(kid string) (*PublicKeyInfo, error) {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	var key PublicKeyInfo
	err := s.publicKeys.FindOne(ctx, bson.M{"kid": kid}).Decode(&key)
	if err != nil {
		if err == mongo.ErrNoDocuments {
			return nil, fmt.Errorf("key %q not found", kid)
		}
		return nil, fmt.Errorf("failed to get public key: %w", err)
	}
	return &key, nil
}

func (s *MongoDBStore) ListPublicKeys(clientID string) ([]PublicKeyInfo, error) {
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	filter := bson.M{}
	if clientID != "" {
		filter["client_id"] = clientID
	}

	cursor, err := s.publicKeys.Find(ctx, filter)
	if err != nil {
		return nil, fmt.Errorf("failed to find public keys: %w", err)
	}
	defer func() { _ = cursor.Close(ctx) }()

	var keys []PublicKeyInfo
	if err := cursor.All(ctx, &keys); err != nil {
		return nil, fmt.Errorf("failed to decode public keys: %w", err)
	}
	return keys, nil
}

type opaqueRecordDoc struct {
	ClientID string `bson:"client_id"`
	Context  string `bson:"context"`
	Record   []byte `bson:"record"`
}

func (s *MongoDBStore) PutRecord(clientID, ctxStr string, record []byte) error {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	opts := options.Replace().SetUpsert(true)
	_, err := s.records.ReplaceOne(
		ctx,
		bson.M{"client_id": clientID, "context": ctxStr},
		opaqueRecordDoc{ClientID: clientID, Context: ctxStr, Record: record},
		opts,
	)
	if err != nil {
		return fmt.Errorf("failed to put record: %w", err)
	}
	return nil
}

func (s *MongoDBStore) GetRecord(clientID, ctxStr string) ([]byte, error) {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	var doc opaqueRecordDoc
	err := s.records.FindOne(ctx, bson.M{"client_id": clientID, "context": ctxStr}).Decode(&doc)
	if err != nil {
		if err == mongo.ErrNoDocuments {
			return nil, fmt.Errorf("no record for %s/%s", clientID, ctxStr)
		}
		return nil, fmt.Errorf("failed to get record: %w", err)
	}
	return doc.Record, nil
}

// webauthnCredDoc is the BSON document for the webauthn_credentials collection.
type webauthnCredDoc struct {
	ClientID     string `bson:"client_id"`
	Context      string `bson:"context"`
	CredentialID []byte `bson:"credential_id"`
	PublicKey    []byte `bson:"public_key"`
	SignCount    uint32 `bson:"sign_count"`
	AAGUID       []byte `bson:"aaguid"`
	CreatedAt    int64  `bson:"created_at"`
}

func (s *MongoDBStore) PutWebAuthnCredential(clientID, ctxStr string, cred WebAuthnCredential) error {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	doc := webauthnCredDoc{
		ClientID:     clientID,
		Context:      ctxStr,
		CredentialID: cred.CredentialID,
		PublicKey:    cred.PublicKey,
		SignCount:    cred.SignCount,
		AAGUID:       cred.AAGUID,
		CreatedAt:    cred.CreatedAt,
	}

	_, err := s.webauthnCreds.InsertOne(ctx, doc)
	if err != nil {
		return fmt.Errorf("failed to put WebAuthn credential: %w", err)
	}
	return nil
}

func (s *MongoDBStore) GetWebAuthnCredential(clientID, ctxStr string) ([]WebAuthnCredential, error) {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	cursor, err := s.webauthnCreds.Find(ctx, bson.M{"client_id": clientID, "context": ctxStr})
	if err != nil {
		return nil, fmt.Errorf("failed to find WebAuthn credentials: %w", err)
	}
	defer cursor.Close(ctx)

	var docs []webauthnCredDoc
	if err := cursor.All(ctx, &docs); err != nil {
		return nil, fmt.Errorf("failed to decode WebAuthn credentials: %w", err)
	}

	if len(docs) == 0 {
		return nil, fmt.Errorf("no WebAuthn credentials for %s/%s", clientID, ctxStr)
	}

	creds := make([]WebAuthnCredential, len(docs))
	for i, d := range docs {
		creds[i] = WebAuthnCredential{
			CredentialID: d.CredentialID,
			PublicKey:    d.PublicKey,
			SignCount:    d.SignCount,
			AAGUID:       d.AAGUID,
			CreatedAt:    d.CreatedAt,
		}
	}
	return creds, nil
}

func (s *MongoDBStore) UpdateWebAuthnSignCount(clientID, ctxStr string, credentialID []byte, signCount uint32) error {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	result, err := s.webauthnCreds.UpdateOne(
		ctx,
		bson.M{"client_id": clientID, "context": ctxStr, "credential_id": credentialID},
		bson.M{"$set": bson.M{"sign_count": signCount}},
	)
	if err != nil {
		return fmt.Errorf("failed to update WebAuthn sign count: %w", err)
	}
	if result.MatchedCount == 0 {
		return fmt.Errorf("credential not found")
	}
	return nil
}

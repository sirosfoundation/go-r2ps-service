package store

import (
	"context"
	"fmt"
	"time"

	"go.mongodb.org/mongo-driver/bson"
	"go.mongodb.org/mongo-driver/mongo"
	"go.mongodb.org/mongo-driver/mongo/options"
)

// MongoDBConfig holds the MongoDB connection configuration.
type MongoDBConfig struct {
	URI      string
	Database string
	Timeout  int // seconds
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
}

// NewMongoDBStore creates a new MongoDB-backed store.
func NewMongoDBStore(ctx context.Context, cfg *MongoDBConfig) (*MongoDBStore, error) {
	timeout := cfg.Timeout
	if timeout == 0 {
		timeout = 10
	}

	clientOptions := options.Client().
		ApplyURI(cfg.URI).
		SetConnectTimeout(time.Duration(timeout) * time.Second)

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

	return nil
}

// Close disconnects from MongoDB.
func (s *MongoDBStore) Close(ctx context.Context) error {
	return s.client.Disconnect(ctx)
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

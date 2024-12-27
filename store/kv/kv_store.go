// Copyright 2022-2023 Tigris Data, Inc.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//      http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package kv

import (
	"context"

	"github.com/rs/zerolog/log"
	"github.com/tigrisdata/tigris/internal"
)

// Add a global or instance-level cache
var cache *LRUCache

// Initialize the cache
func init() {
	cache = NewLRUCache(1000) // Set capacity to 1000 items
}

// Get retrieves a value from the store with cache support
func (kv *KVStore) Get(key string) ([]byte, error) {
	// Check the cache first
	if value, found := cache.Get(key); found {
		return value, nil
	}

	// Fallback to the underlying store
	value, err := kv.backend.Get(key)
	if err != nil {
		return nil, err
	}

	// Store the result in the cache
	cache.Put(key, value)
	return value, nil
}

// Set stores a value in the store and updates the cache
func (kv *KVStore) Set(key string, value []byte) error {
	// Update the cache
	cache.Put(key, value)

	// Update the underlying store
	return kv.backend.Set(key, value)
}

// Initialize TTL-enabled cache
var ttlCache *TTLCache

func init() {
	ttlCache = NewTTLCache(1000, time.Minute) // Capacity 1000 items, cleanup every 1 minute
}

// Get with TTL support
func (kv *KVStore) Get(key string) ([]byte, error) {
	if value, found := ttlCache.Get(key); found {
		return value, nil
	}
	value, err := kv.backend.Get(key)
	if err != nil {
		return nil, err
	}
	ttlCache.Put(key, value, 5*time.Minute) // Default 5 minutes TTL
	return value, nil
}

// Set with TTL support
func (kv *KVStore) SetWithTTL(key string, value []byte, ttl time.Duration) error {
	ttlCache.Put(key, value, ttl)
	return kv.backend.Set(key, value)
}

type KeyValueTxStore struct {
	*fdbkv
}

func NewTxStore(kv *fdbkv) TxStore {
	return newTxStore(kv)
}

func newTxStore(kv *fdbkv) *KeyValueTxStore {
	return &KeyValueTxStore{fdbkv: kv}
}

func (k *KeyValueTxStore) BeginTx(ctx context.Context) (Tx, error) {
	btx, err := k.fdbkv.BeginTx(ctx)
	if err != nil {
		return nil, err
	}

	return &KeyValueTx{
		ftx: btx.(*ftx),
	}, nil
}

func (k *KeyValueTxStore) GetInternalDatabase() (any, error) {
	return k.db, nil
}

func (k *KeyValueTxStore) GetTableStats(ctx context.Context, table []byte) (*TableStats, error) {
	sz, err := k.TableSize(ctx, table)
	if err != nil {
		return nil, err
	}

	return &TableStats{OnDiskSize: sz}, nil
}

type KeyValueTx struct {
	*ftx
}

func (tx *KeyValueTx) Insert(ctx context.Context, table []byte, key Key, data *internal.TableData) error {
	enc, err := internal.Encode(data)
	if err != nil {
		return err
	}

	return tx.ftx.Insert(ctx, table, key, enc)
}

func (tx *KeyValueTx) Replace(ctx context.Context, table []byte, key Key, data *internal.TableData, isUpdate bool) error {
	enc, err := internal.Encode(data)
	if err != nil {
		return err
	}

	return tx.ftx.Replace(ctx, table, key, enc, isUpdate)
}

func (tx *KeyValueTx) Read(ctx context.Context, table []byte, key Key, reverse bool) (Iterator, error) {
	iter, err := tx.ftx.Read(ctx, table, key, false, reverse)
	if err != nil {
		return nil, err
	}

	return NewKeyValueIterator(ctx, iter), nil
}

func (tx *KeyValueTx) ReadRange(ctx context.Context, table []byte, lkey Key, rkey Key, isSnapshot bool, reverse bool) (Iterator, error) {
	iter, err := tx.ftx.ReadRange(ctx, table, lkey, rkey, isSnapshot, reverse)
	if err != nil {
		return nil, err
	}

	return NewKeyValueIterator(ctx, iter), nil
}

func (tx *KeyValueTx) GetMetadata(ctx context.Context, table []byte, key Key) (*internal.TableData, error) {
	b, err := tx.ftx.Get(ctx, getFDBKey(table, key), true).Get()
	if err != nil {
		return nil, err
	}

	if len(b) == 0 {
		return nil, ErrNotFound
	}

	log.Debug().Int("length", len(b)).Msg("getMetadata")

	return internal.Decode(b)
}

type KeyValueIterator struct {
	ctx context.Context
	baseIterator
	err error
}

func NewKeyValueIterator(ctx context.Context, iter baseIterator) *KeyValueIterator {
	return &KeyValueIterator{ctx: ctx, baseIterator: iter}
}

func (i *KeyValueIterator) Next(value *KeyValue) bool {
	var v baseKeyValue

	if !i.baseIterator.Next(&v) {
		i.err = i.baseIterator.Err()
		return false
	}

	value.Key = v.Key
	value.FDBKey = v.FDBKey
	value.Data, i.err = internal.Decode(v.Value)

	return i.err == nil
}

func (i *KeyValueIterator) Err() error {
	if i.err != nil {
		return i.err
	}

	return i.baseIterator.Err()
}

// BatchGet retrieves multiple keys at once
func (kv *KVStore) BatchGet(keys []string) (map[string][]byte, error) {
	results := make(map[string][]byte)
	missedKeys := []string{}

	for _, key := range keys {
		if value, found := cache.Get(key); found {
			results[key] = value
		} else {
			missedKeys = append(missedKeys, key)
		}
	}

	if len(missedKeys) > 0 {
		backendResults, err := kv.backend.BatchGet(missedKeys)
		if err != nil {
			return nil, err
		}
		for k, v := range backendResults {
			cache.Put(k, v)
			results[k] = v
		}
	}
	return results, nil
}


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

package metadata

import (
	"context"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
	"github.com/tigrisdata/tigris/errors"
	"github.com/tigrisdata/tigris/server/transaction"
	"github.com/tigrisdata/tigris/store/kv"
)

func testClearDictionary(ctx context.Context, k *Dictionary, kvStore kv.TxStore) {
	_ = kvStore.DropTable(ctx, k.EncodingSubspaceName())
	_ = kvStore.DropTable(ctx, k.ReservedSubspaceName())
	_ = kvStore.DropTable(ctx, k.NamespaceSubspaceName())
}

func TestDictionaryEncoding(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	nr := newTestNameRegistry(t)
	k := NewMetadataDictionary(nr)

	startId := nr.BaseCounterValue

	testClearDictionary(ctx, k, kvStore)

	tm := transaction.NewManager(kvStore)

	tx, err := tm.StartTx(ctx)
	require.NoError(t, err)
	require.NoError(t, k.ReserveNamespace(ctx, tx, "proj1-org-1", NewNamespaceMetadata(1234, "proj1-org-1", "proj1-org-1-display_name")))
	require.NoError(t, tx.Commit(ctx))

	tx, err = tm.StartTx(ctx)
	require.NoError(t, err)
	dbMeta, err := k.CreateDatabase(ctx, tx, "db-1", 1234)
	require.NoError(t, err)
	require.NoError(t, tx.Commit(ctx))

	tx, err = tm.StartTx(ctx)
	require.NoError(t, err)
	collMeta, err := k.CreateCollection(ctx, tx, "coll-1", 1234, startId)
	require.NoError(t, err)
	require.NoError(t, tx.Commit(ctx))

	tx, err = tm.StartTx(ctx)
	require.NoError(t, err)
	d, err := k.GetDatabase(ctx, tx, "db-1", 1234)
	require.NoError(t, err)
	require.Equal(t, d.ID, dbMeta.ID)

	c, err := k.GetCollection(ctx, tx, "coll-1", 1234, dbMeta.ID)
	require.NoError(t, err)
	require.Equal(t, c.ID, collMeta.ID)

	// try assigning the same namespace id to some other namespace
	tx, err = tm.StartTx(ctx)
	require.NoError(t, err)
	require.Error(t, k.ReserveNamespace(ctx, tx, "proj2-org-1", NewNamespaceMetadata(1234, "proj2-org-1", "proj2-org-1-display_name")))
	require.NoError(t, tx.Rollback(ctx))
}

func TestDictionaryEncodingDropped(t *testing.T) {
	t.Run("drop_database", func(t *testing.T) {
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()

		tm := transaction.NewManager(kvStore)

		k := NewMetadataDictionary(newTestNameRegistry(t))
		testClearDictionary(ctx, k, kvStore)

		tx, err := tm.StartTx(ctx)
		require.NoError(t, err)
		require.NoError(t, k.ReserveNamespace(ctx, tx, "proj1-org-1", NewNamespaceMetadata(1234, "proj1-org-1", "proj1-org-1-display_name")))
		require.NoError(t, tx.Commit(ctx))

		tx, err = tm.StartTx(ctx)
		require.NoError(t, err)
		dbMeta, err := k.CreateDatabase(ctx, tx, "db-1", 1234)
		require.NoError(t, err)
		require.NoError(t, tx.Commit(ctx))

		tx, err = tm.StartTx(ctx)
		require.NoError(t, err)
		v, err := k.GetDatabase(ctx, tx, "db-1", 1234)
		require.NoError(t, err)
		require.Equal(t, v.ID, dbMeta.ID)
		require.NoError(t, tx.Commit(ctx))

		tx, err = tm.StartTx(ctx)
		require.NoError(t, err)
		err = k.DropDatabase(ctx, tx, "db-1", 1234)
		require.NoError(t, err)
		require.NoError(t, tx.Commit(ctx))

		tx, err = tm.StartTx(ctx)
		require.NoError(t, err)
		_, err = k.GetDatabase(ctx, tx, "db-1", 1234)
		require.Equal(t, errors.ErrNotFound, err)

		require.NoError(t, tx.Commit(ctx))
	})

	t.Run("drop_collection", func(t *testing.T) {
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()

		tm := transaction.NewManager(kvStore)

		k := NewMetadataDictionary(newTestNameRegistry(t))
		testClearDictionary(ctx, k, kvStore)

		tx, err := tm.StartTx(ctx)
		require.NoError(t, err)
		require.NoError(t, k.ReserveNamespace(ctx, tx, "proj1-org-1", NewNamespaceMetadata(1234, "proj1-org-1", "proj1-org-1-display_name")))
		require.NoError(t, tx.Commit(ctx))

		tx, err = tm.StartTx(ctx)
		require.NoError(t, err)
		dbMeta, err := k.CreateDatabase(ctx, tx, "db-1", 1234)
		require.NoError(t, err)
		require.NoError(t, tx.Commit(ctx))

		tx, err = tm.StartTx(ctx)
		require.NoError(t, err)
		collMeta, err := k.CreateCollection(ctx, tx, "coll-1", 1234, dbMeta.ID)
		require.NoError(t, err)
		require.NoError(t, tx.Commit(ctx))

		tx, err = tm.StartTx(ctx)
		require.NoError(t, err)
		v, err := k.GetCollection(ctx, tx, "coll-1", 1234, dbMeta.ID)
		require.NoError(t, err)
		require.NoError(t, tx.Commit(ctx))
		require.Equal(t, v.ID, collMeta.ID)

		tx, err = tm.StartTx(ctx)
		require.NoError(t, err)
		err = k.DropCollection(ctx, tx, "coll-1", 1234, dbMeta.ID)
		require.NoError(t, err)
		require.NoError(t, tx.Commit(ctx))

		tx, err = tm.StartTx(ctx)
		require.NoError(t, err)
		_, err = k.GetCollection(ctx, tx, "coll-1", 1234, dbMeta.ID)
		require.Error(t, errors.ErrNotFound, err)

		require.NoError(t, tx.Commit(ctx))
	})

	t.Run("drop_collection_multiple", func(t *testing.T) {
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()

		tm := transaction.NewManager(kvStore)

		k := NewMetadataDictionary(newTestNameRegistry(t))
		testClearDictionary(ctx, k, kvStore)

		tx, err := tm.StartTx(ctx)
		require.NoError(t, err)
		require.NoError(t, k.ReserveNamespace(ctx, tx, "proj1-org-1", NewNamespaceMetadata(1234, "proj1-org-1", "proj1-org-1-display_name")))
		require.NoError(t, tx.Commit(ctx))

		tx, err = tm.StartTx(ctx)
		require.NoError(t, err)
		dbMeta, err := k.CreateDatabase(ctx, tx, "db-1", 1234)
		require.NoError(t, err)
		require.NoError(t, tx.Commit(ctx))

		tx, err = tm.StartTx(ctx)
		require.NoError(t, err)
		collMeta, err := k.CreateCollection(ctx, tx, "coll-1", 1234, dbMeta.ID)
		require.NoError(t, err)
		require.NoError(t, tx.Commit(ctx))

		tx, err = tm.StartTx(ctx)
		require.NoError(t, err)
		v, err := k.GetCollection(ctx, tx, "coll-1", 1234, dbMeta.ID)
		require.NoError(t, err)
		require.NoError(t, tx.Commit(ctx))
		require.Equal(t, v.ID, collMeta.ID)

		tx, err = tm.StartTx(ctx)
		require.NoError(t, err)
		err = k.DropCollection(ctx, tx, "coll-1", 1234, dbMeta.ID)
		require.NoError(t, err)
		require.NoError(t, tx.Commit(ctx))

		tx, err = tm.StartTx(ctx)
		require.NoError(t, err)
		_, err = k.GetCollection(ctx, tx, "coll-1", 1234, dbMeta.ID)
		require.Equal(t, errors.ErrNotFound, err)
		require.NoError(t, tx.Commit(ctx))

		tx, err = tm.StartTx(ctx)
		require.NoError(t, err)
		newColl, err := k.CreateCollection(ctx, tx, "coll-1", 1234, dbMeta.ID)
		require.NoError(t, err)
		require.NoError(t, tx.Commit(ctx))

		tx, err = tm.StartTx(ctx)
		require.NoError(t, err)
		v, err = k.GetCollection(ctx, tx, "coll-1", 1234, dbMeta.ID)
		require.NoError(t, err)
		require.NoError(t, tx.Commit(ctx))
		require.Equal(t, v.ID, newColl.ID)
	})
}

func TestDictionaryEncoding_Error(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	k := NewMetadataDictionary(newTestNameRegistry(t))
	testClearDictionary(ctx, k, kvStore)

	tm := transaction.NewManager(kvStore)

	tx, err := tm.StartTx(ctx)
	require.NoError(t, err)

	_, err = k.CreateDatabase(ctx, tx, "db-1", 0)
	require.Error(t, errors.InvalidArgument("invalid namespace id"), err)

	_, err = k.CreateCollection(ctx, tx, "coll-1", 1234, 0)
	require.Error(t, errors.InvalidArgument("invalid database id"), err)

	require.NoError(t, tx.Rollback(context.TODO()))
}

func TestDictionaryEncoding_GetMethods(t *testing.T) {
	tm := transaction.NewManager(kvStore)

	t.Run("get_databases", func(t *testing.T) {
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()

		k := NewMetadataDictionary(newTestNameRegistry(t))
		testClearDictionary(ctx, k, kvStore)

		tx, err := tm.StartTx(ctx)
		require.NoError(t, err)
		dbMeta1, err := k.CreateDatabase(ctx, tx, "db-1", 1)
		require.NoError(t, err)
		dbMeta2, err := k.CreateDatabase(ctx, tx, "db-2", 1)
		require.NoError(t, err)

		dbToId, err := k.GetDatabases(ctx, tx, 1)
		require.NoError(t, err)
		require.NoError(t, tx.Commit(ctx))
		require.Len(t, dbToId, 2)
		require.Equal(t, dbToId["db-1"].ID, dbMeta1.ID)
		require.Equal(t, dbToId["db-2"].ID, dbMeta2.ID)
	})

	t.Run("get_collections", func(t *testing.T) {
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()

		k := NewMetadataDictionary(newTestNameRegistry(t))
		testClearDictionary(ctx, k, kvStore)

		tx, err := tm.StartTx(ctx)
		require.NoError(t, err)
		dbMeta, err := k.CreateDatabase(ctx, tx, "db-1", 1)
		require.NoError(t, err)

		cid1, err := k.CreateCollection(ctx, tx, "coll-1", 1, dbMeta.ID)
		require.NoError(t, err)
		cid2, err := k.CreateCollection(ctx, tx, "coll-2", 1, dbMeta.ID)
		require.NoError(t, err)

		collToId, err := k.GetCollections(ctx, tx, 1, dbMeta.ID)
		require.NoError(t, err)
		require.NoError(t, tx.Commit(ctx))
		require.Len(t, collToId, 2)
		require.Equal(t, collToId["coll-1"], cid1)
		require.Equal(t, collToId["coll-2"], cid2)
	})
}

func TestReservedNamespace(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	r := newReservedSubspace(newTestNameRegistry(t))

	_ = kvStore.DropTable(ctx, r.EncodingSubspaceName())
	_ = kvStore.DropTable(ctx, r.ReservedSubspaceName())
	_ = kvStore.DropTable(ctx, r.NamespaceSubspaceName())

	tm := transaction.NewManager(kvStore)

	tx, err := tm.StartTx(ctx)
	require.NoError(t, err)
	require.NoError(t, r.reserveNamespace(ctx, tx, "p1-o1", NewNamespaceMetadata(123, "p1-o1", "p1-o1-display_name")))
	require.NoError(t, tx.Commit(ctx))

	// check in the allocated id is assigned
	tx, err = tm.StartTx(ctx)
	require.NoError(t, err)
	require.NoError(t, r.reload(ctx, tx))
	require.Equal(t, "p1-o1", r.idToNamespaceStruct[123].StrId)
	require.NoError(t, tx.Commit(ctx))

	// try assigning the same namespace id to some other namespace
	tx, err = tm.StartTx(context.TODO())
	require.NoError(t, err)
	expError := errors.AlreadyExists("id is already assigned to the namespace 'p1-o1'")
	require.Equal(t, expError, r.reserveNamespace(context.TODO(), tx, "p2-o2", NewNamespaceMetadata(123, "p2-o2", "p2-o2-display_name")))
	require.NoError(t, tx.Rollback(ctx))
}

func TestDecode(t *testing.T) {
	k := kv.BuildKey(encKeyVersion, UInt32ToByte(1234), dbKey, "db-1", keyEnd)
	mp, err := NewMetadataDictionary(newTestNameRegistry(t)).decode(context.TODO(), k)
	require.NoError(t, err)
	require.Equal(t, mp[dbKey], "db-1")
}

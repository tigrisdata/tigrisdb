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
	"unsafe"

	"github.com/apple/foundationdb/bindings/go/src/fdb"
	"github.com/rs/zerolog/log"
	"github.com/tigrisdata/tigris/internal"
	"github.com/tigrisdata/tigris/server/config"
	"github.com/tigrisdata/tigris/server/metrics"
)

type KeyValue struct {
	Key    Key
	FDBKey []byte
	Data   *internal.TableData
}

type fdbBaseType interface {
	[]byte | int64
}

// KeyValue type for when we not iterating over TableData.
type FdbBaseKeyValue[T fdbBaseType] struct {
	Key    Key
	FDBKey []byte
	Data   T
}

type Future fdb.FutureByteSlice

type KV interface {
	Insert(ctx context.Context, table []byte, key Key, data *internal.TableData) error
	Replace(ctx context.Context, table []byte, key Key, data *internal.TableData, isUpdate bool) error
	Delete(ctx context.Context, table []byte, key Key) error
	DeleteRange(ctx context.Context, table []byte, lKey Key, rKey Key) error
	Read(ctx context.Context, table []byte, key Key) (Iterator, error)
	ReadRange(ctx context.Context, table []byte, lkey Key, rkey Key, isSnapshot bool) (Iterator, error)
	Update(ctx context.Context, table []byte, key Key, apply func(*internal.TableData) (*internal.TableData, error)) (int32, error)
	UpdateRange(ctx context.Context, table []byte, lKey Key, rKey Key, apply func(*internal.TableData) (*internal.TableData, error)) (int32, error)
	SetVersionstampedValue(ctx context.Context, key []byte, value []byte) error
	SetVersionstampedKey(ctx context.Context, key []byte, value []byte) error
	Get(ctx context.Context, key []byte, isSnapshot bool) (Future, error)
	AtomicAdd(ctx context.Context, table []byte, key Key, value int64) error
	AtomicRead(ctx context.Context, table []byte, key Key) (int64, error)
	AtomicReadRange(ctx context.Context, table []byte, lkey Key, rkey Key, isSnapshot bool) (AtomicIterator, error)
}

type Tx interface {
	KV
	Commit(context.Context) error
	Rollback(context.Context) error
	IsRetriable() bool
	RangeSize(ctx context.Context, table []byte, lkey Key, rkey Key) (int64, error)
}

type KeyValueStore interface {
	KV
	BeginTx(ctx context.Context) (Tx, error)
	CreateTable(ctx context.Context, name []byte) error
	DropTable(ctx context.Context, name []byte) error
	GetInternalDatabase() (interface{}, error) // TODO: CDC remove workaround
	TableSize(ctx context.Context, name []byte) (int64, error)
}

type Iterator interface {
	Next(ctx context.Context, value *KeyValue) bool
	Err() error
}

type AtomicIterator interface {
	Next(ctx context.Context, value *FdbBaseKeyValue[int64]) bool
	Err() error
}

type KeyValueStoreImpl struct {
	*fdbkv
}

type KeyValueStoreImplWithMetrics struct {
	kv KeyValueStore
}

func NewKeyValueStore(cfg *config.FoundationDBConfig) (KeyValueStore, error) {
	kv, err := newFoundationDB(cfg)
	if err != nil {
		return nil, err
	}
	return &KeyValueStoreImpl{fdbkv: kv}, nil
}

func NewKeyValueStoreWithMetrics(cfg *config.FoundationDBConfig) (KeyValueStore, error) {
	kv, err := newFoundationDB(cfg)
	if err != nil {
		return nil, err
	}
	return &KeyValueStoreImplWithMetrics{
		&KeyValueStoreImpl{
			fdbkv: kv,
		},
	}, nil
}

func measureLow(ctx context.Context, name string, f func() error) {
	// Low level measurement wrapper that is called by the measure functions on the appropriate receiver
	measurement := metrics.NewMeasurement(metrics.KvTracingServiceName, name, metrics.FdbSpanType, metrics.GetFdbBaseTags(name))
	ctx = measurement.StartTracing(ctx, true)
	err := f()
	if err == nil {
		// Request was ok
		measurement.CountOkForScope(metrics.FdbOkCount, measurement.GetFdbOkTags())
		_ = measurement.FinishTracing(ctx)
		measurement.RecordDuration(metrics.FdbRespTime, measurement.GetFdbOkTags())
		return
	}
	// Request had an error
	measurement.CountErrorForScope(metrics.FdbOkCount, measurement.GetFdbErrorTags(err))
	_ = measurement.FinishWithError(ctx, err)
	measurement.RecordDuration(metrics.FdbErrorRespTime, measurement.GetFdbErrorTags(err))
}

func (m *KeyValueStoreImplWithMetrics) measure(ctx context.Context, name string, f func() error) {
	measureLow(ctx, name, f)
}

func (m *KeyValueStoreImplWithMetrics) Delete(ctx context.Context, table []byte, key Key) (err error) {
	m.measure(ctx, "Delete", func() error {
		err = m.kv.Delete(ctx, table, key)
		return err
	})
	return
}

func (m *KeyValueStoreImplWithMetrics) DeleteRange(ctx context.Context, table []byte, lKey Key, rKey Key) (err error) {
	m.measure(ctx, "DeleteRange", func() error {
		err = m.kv.DeleteRange(ctx, table, lKey, rKey)
		return err
	})
	return
}

func (m *KeyValueStoreImplWithMetrics) CreateTable(ctx context.Context, name []byte) (err error) {
	m.measure(ctx, "CreateTable", func() error {
		err = m.kv.CreateTable(ctx, name)
		return err
	})
	return
}

func (m *KeyValueStoreImplWithMetrics) DropTable(ctx context.Context, name []byte) (err error) {
	m.measure(ctx, "DropTable", func() error {
		err = m.kv.DropTable(ctx, name)
		return err
	})
	return
}

func (m *KeyValueStoreImplWithMetrics) TableSize(ctx context.Context, name []byte) (size int64, err error) {
	m.measure(ctx, "TableSize", func() error {
		size, err = m.kv.TableSize(ctx, name)
		return err
	})
	return
}

func (m *KeyValueStoreImplWithMetrics) SetVersionstampedValue(ctx context.Context, key []byte, value []byte) (err error) {
	m.measure(ctx, "SetVersionstampedValue", func() error {
		err = m.kv.SetVersionstampedValue(ctx, key, value)
		return err
	})
	return
}

func (m *KeyValueStoreImplWithMetrics) SetVersionstampedKey(ctx context.Context, key []byte, value []byte) (err error) {
	m.measure(ctx, "SetVersionstampedKey", func() error {
		err = m.kv.SetVersionstampedKey(ctx, key, value)
		return err
	})
	return
}

func (m *KeyValueStoreImplWithMetrics) Get(ctx context.Context, key []byte, isSnapshot bool) (val Future, err error) {
	m.measure(ctx, "Get", func() error {
		val, err = m.kv.Get(ctx, key, isSnapshot)
		return err
	})
	return
}

func (m *KeyValueStoreImplWithMetrics) AtomicAdd(ctx context.Context, table []byte, key Key, value int64) (err error) {
	m.measure(ctx, "AtomicAdd", func() error {
		err = m.kv.AtomicAdd(ctx, table, key, value)
		return err
	})
	return
}

func (m *KeyValueStoreImplWithMetrics) AtomicRead(ctx context.Context, table []byte, key Key) (value int64, err error) {
	m.measure(ctx, "AtomicRead", func() error {
		value, err = m.kv.AtomicRead(ctx, table, key)
		return err
	})
	return
}

func (m *KeyValueStoreImplWithMetrics) AtomicReadRange(ctx context.Context, table []byte, lkey Key, rkey Key, isSnapshot bool) (iter AtomicIterator, err error) {
	m.measure(ctx, "AtomicRead", func() error {
		iter, err = m.kv.AtomicReadRange(ctx, table, lkey, rkey, isSnapshot)
		return err
	})
	return
}

func (k *KeyValueStoreImpl) Insert(ctx context.Context, table []byte, key Key, data *internal.TableData) error {
	enc, err := internal.Encode(data)
	if err != nil {
		return err
	}

	return k.fdbkv.Insert(ctx, table, key, enc)
}

func (m *KeyValueStoreImplWithMetrics) Insert(ctx context.Context, table []byte, key Key, data *internal.TableData) (err error) {
	// Whatever parameters can be passed to measure before the func
	m.measure(ctx, "Insert", func() error {
		err = m.kv.Insert(ctx, table, key, data)
		return err
	})
	return
}

func (k *KeyValueStoreImpl) Replace(ctx context.Context, table []byte, key Key, data *internal.TableData, isUpdate bool) error {
	enc, err := internal.Encode(data)
	if err != nil {
		return err
	}

	return k.fdbkv.Replace(ctx, table, key, enc, isUpdate)
}

func (m *KeyValueStoreImplWithMetrics) Replace(ctx context.Context, table []byte, key Key, data *internal.TableData, isUpdate bool) (err error) {
	m.measure(ctx, "Replace", func() error {
		err = m.kv.Replace(ctx, table, key, data, isUpdate)
		return err
	})
	return
}

func (k *KeyValueStoreImpl) Read(ctx context.Context, table []byte, key Key) (Iterator, error) {
	iter, err := k.fdbkv.Read(ctx, table, key)
	if err != nil {
		return nil, err
	}
	return &IteratorImpl{
		baseIterator: iter,
	}, nil
}

func (m *KeyValueStoreImplWithMetrics) Read(ctx context.Context, table []byte, key Key) (it Iterator, err error) {
	m.measure(ctx, "Read", func() error {
		it, err = m.kv.Read(ctx, table, key)
		return err
	})
	return
}

func (k *KeyValueStoreImpl) ReadRange(ctx context.Context, table []byte, lkey Key, rkey Key, isSnapshot bool) (Iterator, error) {
	iter, err := k.fdbkv.ReadRange(ctx, table, lkey, rkey, isSnapshot)
	if err != nil {
		return nil, err
	}
	return &IteratorImpl{
		baseIterator: iter,
	}, nil
}

func (m *KeyValueStoreImplWithMetrics) ReadRange(ctx context.Context, table []byte, lkey Key, rkey Key, isSnapshot bool) (it Iterator, err error) {
	m.measure(ctx, "ReadRange", func() error {
		it, err = m.kv.ReadRange(ctx, table, lkey, rkey, isSnapshot)
		return err
	})
	return
}

func (k *KeyValueStoreImpl) Update(ctx context.Context, table []byte, key Key, apply func(*internal.TableData) (*internal.TableData, error)) (int32, error) {
	return k.fdbkv.Update(ctx, table, key, func(existing []byte) ([]byte, error) {
		decoded, err := internal.Decode(existing)
		if err != nil {
			return nil, err
		}

		newData, err := apply(decoded)
		if err != nil {
			return nil, err
		}

		encoded, err := internal.Encode(newData)
		if err != nil {
			return nil, err
		}

		return encoded, nil
	})
}

func (m *KeyValueStoreImplWithMetrics) Update(ctx context.Context, table []byte, key Key, apply func(*internal.TableData) (*internal.TableData, error)) (encoded int32, err error) {
	m.measure(ctx, "Update", func() error {
		encoded, err = m.kv.Update(ctx, table, key, apply)
		return err
	})
	return
}

func (k *KeyValueStoreImpl) UpdateRange(ctx context.Context, table []byte, lKey Key, rKey Key, apply func(*internal.TableData) (*internal.TableData, error)) (int32, error) {
	return k.fdbkv.UpdateRange(ctx, table, lKey, rKey, func(existing []byte) ([]byte, error) {
		decoded, err := internal.Decode(existing)
		if err != nil {
			return nil, err
		}

		newData, err := apply(decoded)
		if err != nil {
			return nil, err
		}

		encoded, err := internal.Encode(newData)
		if err != nil {
			return nil, err
		}

		return encoded, nil
	})
}

func (k *KeyValueStoreImpl) AtomicAdd(ctx context.Context, table []byte, key Key, value int64) error {
	return k.fdbkv.AtomicAdd(ctx, table, key, value)
}

func (k *KeyValueStoreImpl) AtomicRead(ctx context.Context, table []byte, key Key) (int64, error) {
	return k.fdbkv.AtomicRead(ctx, table, key)
}

func (k *KeyValueStoreImpl) AtomicReadRange(ctx context.Context, table []byte, lkey Key, rkey Key, isSnapshot bool) (AtomicIterator, error) {
	return k.fdbkv.AtomicReadRange(ctx, table, lkey, rkey, isSnapshot)
}

func (m *KeyValueStoreImplWithMetrics) UpdateRange(ctx context.Context, table []byte, lKey Key, rKey Key, apply func(*internal.TableData) (*internal.TableData, error)) (encoded int32, err error) {
	m.measure(ctx, "UpdateRange", func() error {
		encoded, err = m.kv.UpdateRange(ctx, table, lKey, rKey, apply)
		return err
	})
	return
}

func (k *KeyValueStoreImpl) BeginTx(ctx context.Context) (Tx, error) {
	btx, err := k.fdbkv.BeginTx(ctx)
	if err != nil {
		return nil, err
	}

	return &TxImpl{
		ftx: btx.(*ftx),
	}, nil
}

func (m *KeyValueStoreImplWithMetrics) BeginTx(ctx context.Context) (Tx, error) {
	// This needs to be a special case in order to have the tx metrics as well
	var btx Tx
	var err error
	m.measure(ctx, "BeginTx", func() error {
		btx, err = m.kv.BeginTx(ctx)
		return err
	})
	return &TxImplWithMetrics{
		btx,
	}, err
}

func (k *KeyValueStoreImpl) GetInternalDatabase() (interface{}, error) {
	return k.db, nil
}

func (m *KeyValueStoreImplWithMetrics) GetInternalDatabase() (k interface{}, err error) {
	k, err = m.kv.GetInternalDatabase()
	return
}

type TxImpl struct {
	*ftx
}

type TxImplWithMetrics struct {
	tx Tx
}

func (m *TxImplWithMetrics) measure(ctx context.Context, name string, f func() error) {
	measureLow(ctx, name, f)
}

func (m *TxImplWithMetrics) Delete(ctx context.Context, table []byte, key Key) (err error) {
	m.measure(ctx, "Delete", func() error {
		err = m.tx.Delete(ctx, table, key)
		return err
	})
	return
}

func (m *TxImplWithMetrics) DeleteRange(ctx context.Context, table []byte, lKey Key, rKey Key) (err error) {
	m.measure(ctx, "DeleteRange", func() error {
		err = m.tx.DeleteRange(ctx, table, lKey, rKey)
		return err
	})
	return
}

func (m *TxImplWithMetrics) SetVersionstampedValue(ctx context.Context, key []byte, value []byte) (err error) {
	m.measure(ctx, "SetVersionstampedValue", func() error {
		err = m.tx.SetVersionstampedValue(ctx, key, value)
		return err
	})
	return
}

func (m *TxImplWithMetrics) SetVersionstampedKey(ctx context.Context, key []byte, value []byte) (err error) {
	m.measure(ctx, "SetVersionstampedKey", func() error {
		err = m.tx.SetVersionstampedKey(ctx, key, value)
		return err
	})
	return
}

func (m *TxImplWithMetrics) AtomicAdd(ctx context.Context, table []byte, key Key, value int64) (err error) {
	m.measure(ctx, "AtomicAdd", func() error {
		err = m.tx.AtomicAdd(ctx, table, key, value)
		return err
	})
	return
}

func (m *TxImplWithMetrics) AtomicRead(ctx context.Context, table []byte, key Key) (value int64, err error) {
	m.measure(ctx, "AtomicRead", func() error {
		value, err = m.tx.AtomicRead(ctx, table, key)
		return err
	})
	return
}

func (m *TxImplWithMetrics) AtomicReadRange(ctx context.Context, table []byte, lkey Key, rkey Key, isSnapshot bool) (iter AtomicIterator, err error) {
	m.measure(ctx, "AtomicReadRange", func() error {
		iter, err = m.tx.AtomicReadRange(ctx, table, lkey, rkey, isSnapshot)
		return err
	})
	return
}

func (m *TxImplWithMetrics) Get(ctx context.Context, key []byte, isSnapshot bool) (val Future, err error) {
	m.measure(ctx, "Get", func() error {
		val, err = m.tx.Get(ctx, key, isSnapshot)
		return err
	})
	return
}

func (m *TxImplWithMetrics) RangeSize(ctx context.Context, table []byte, lkey Key, rkey Key) (size int64, err error) {
	m.measure(ctx, "RangeSize", func() error {
		size, err = m.tx.RangeSize(ctx, table, lkey, rkey)
		return err
	})
	return
}

func (m *TxImplWithMetrics) Commit(ctx context.Context) (err error) {
	m.measure(ctx, "Commit", func() error {
		err = m.tx.Commit(ctx)
		return err
	})
	return
}

func (m *TxImplWithMetrics) Rollback(ctx context.Context) (err error) {
	m.measure(ctx, "Rollback", func() error {
		err = m.tx.Rollback(ctx)
		return err
	})
	return
}

func (m *TxImplWithMetrics) IsRetriable() bool {
	return m.tx.IsRetriable()
}

func (tx *TxImpl) Insert(ctx context.Context, table []byte, key Key, data *internal.TableData) error {
	enc, err := internal.Encode(data)
	if err != nil {
		return err
	}

	return tx.ftx.Insert(ctx, table, key, enc)
}

func (m *TxImplWithMetrics) Insert(ctx context.Context, table []byte, key Key, data *internal.TableData) (err error) {
	m.measure(ctx, "Insert", func() error {
		err = m.tx.Insert(ctx, table, key, data)
		return err
	})
	return
}

func (tx *TxImpl) Replace(ctx context.Context, table []byte, key Key, data *internal.TableData, isUpdate bool) error {
	enc, err := internal.Encode(data)
	if err != nil {
		return err
	}

	return tx.ftx.Replace(ctx, table, key, enc, isUpdate)
}

func (m *TxImplWithMetrics) Replace(ctx context.Context, table []byte, key Key, data *internal.TableData, isUpdate bool) (err error) {
	m.measure(ctx, "Replace", func() error {
		err = m.tx.Replace(ctx, table, key, data, isUpdate)
		return err
	})
	return
}

func (tx *TxImpl) Read(ctx context.Context, table []byte, key Key) (Iterator, error) {
	iter, err := tx.ftx.Read(ctx, table, key)
	if err != nil {
		return nil, err
	}
	return &IteratorImpl{
		baseIterator: iter,
	}, nil
}

func (m *TxImplWithMetrics) Read(ctx context.Context, table []byte, key Key) (it Iterator, err error) {
	m.measure(ctx, "Read", func() error {
		it, err = m.tx.Read(ctx, table, key)
		return err
	})
	return
}

func (tx *TxImpl) ReadRange(ctx context.Context, table []byte, lkey Key, rkey Key, isSnapshot bool) (Iterator, error) {
	iter, err := tx.ftx.ReadRange(ctx, table, lkey, rkey, isSnapshot)
	if err != nil {
		return nil, err
	}
	return &IteratorImpl{
		baseIterator: iter,
	}, nil
}

func (m *TxImplWithMetrics) ReadRange(ctx context.Context, table []byte, lkey Key, rkey Key, isSnapshot bool) (it Iterator, err error) {
	m.measure(ctx, "ReadRange", func() error {
		it, err = m.tx.ReadRange(ctx, table, lkey, rkey, isSnapshot)
		return err
	})
	return
}

func (tx *TxImpl) Update(ctx context.Context, table []byte, key Key, apply func(*internal.TableData) (*internal.TableData, error)) (int32, error) {
	return tx.ftx.Update(ctx, table, key, func(existing []byte) ([]byte, error) {
		decoded, err := internal.Decode(existing)
		if err != nil {
			return nil, err
		}

		newData, err := apply(decoded)
		if err != nil {
			return nil, err
		}

		encoded, err := internal.Encode(newData)
		if err != nil {
			return nil, err
		}

		return encoded, nil
	})
}

func (m *TxImplWithMetrics) Update(ctx context.Context, table []byte, key Key, apply func(*internal.TableData) (*internal.TableData, error)) (encoded int32, err error) {
	m.measure(ctx, "Update", func() error {
		encoded, err = m.tx.Update(ctx, table, key, apply)
		return err
	})
	return
}

func (tx *TxImpl) UpdateRange(ctx context.Context, table []byte, lKey Key, rKey Key, apply func(*internal.TableData) (*internal.TableData, error)) (int32, error) {
	return tx.ftx.UpdateRange(ctx, table, lKey, rKey, func(existing []byte) ([]byte, error) {
		decoded, err := internal.Decode(existing)
		if err != nil {
			return nil, err
		}

		newData, err := apply(decoded)
		if err != nil {
			return nil, err
		}

		encoded, err := internal.Encode(newData)
		if err != nil {
			return nil, err
		}

		return encoded, nil
	})
}

func (m *TxImplWithMetrics) UpdateRange(ctx context.Context, table []byte, lKey Key, rKey Key, apply func(*internal.TableData) (*internal.TableData, error)) (encoded int32, err error) {
	m.measure(ctx, "UpdateRange", func() error {
		encoded, err = m.tx.UpdateRange(ctx, table, lKey, rKey, apply)
		return err
	})
	return
}

type IteratorImpl struct {
	baseIterator
	err error
}

func (i *IteratorImpl) Next(ctx context.Context, value *KeyValue) bool {
	var v baseKeyValue
	reqStatus, ok := metrics.RequestStatusFromContext(ctx)
	readBytes := 0
	if !ok {
		log.Info().Msg("Iterator did not get request status")
	}
	hasNext := i.baseIterator.Next(ctx, &v)
	if hasNext {
		value.Key = v.Key
		value.FDBKey = v.FDBKey
		decoded, err := internal.Decode(v.Value)
		if err != nil {
			i.err = err
			return false
		}
		value.Data = decoded
		readBytes += len(v.Value)
	}
	if reqStatus != nil {
		reqStatus.AddBytes(int64(readBytes))
		log.Info().Int64("Added bytes", int64(readBytes)).Msg("Read bytes in this iteration")
		log.Info().Int64("Total bytes", reqStatus.ReadBytes).Msg("Total read bytes")
	}
	return hasNext
}

func (i *IteratorImpl) Err() error {
	if i.err != nil {
		return i.err
	}
	return i.baseIterator.Err()
}

type AtomicIteratorImpl struct {
	baseIterator
	err error
}

func (i *AtomicIteratorImpl) Next(ctx context.Context, value *FdbBaseKeyValue[int64]) bool {
	var v baseKeyValue
	hasNext := i.baseIterator.Next(ctx, &v)
	if hasNext {
		value.Key = v.Key
		value.FDBKey = v.FDBKey
		num, err := fdbByteToInt64(&v.Value)
		if err != nil {
			i.err = err
			return false
		}
		value.Data = num
	}
	return hasNext
}

func (i *AtomicIteratorImpl) Err() error {
	if i.err != nil {
		return i.err
	}
	return i.baseIterator.Err()
}

type (
	KeyPart interface{}
	Key     []KeyPart
)

func BuildKey(parts ...interface{}) Key {
	ptr := unsafe.Pointer(&parts)
	return *(*Key)(ptr)
}

func (k *Key) AddPart(part interface{}) {
	*k = append(*k, KeyPart(part))
}

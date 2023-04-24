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

package database

import (
	"context"

	"github.com/rs/zerolog/log"
	"github.com/tigrisdata/tigris/errors"
	"github.com/tigrisdata/tigris/keys"
	"github.com/tigrisdata/tigris/query/filter"
	"github.com/tigrisdata/tigris/query/sort"
	"github.com/tigrisdata/tigris/schema"
	"github.com/tigrisdata/tigris/server/transaction"
	"github.com/tigrisdata/tigris/store/kv"
	"github.com/tigrisdata/tigris/value"
)

var PrimaryKeyPos = 6

type SecondaryIndexReaderImpl struct {
	ctx       context.Context
	coll      *schema.DefaultCollection
	filter    *filter.WrappedFilter
	tx        transaction.Tx
	err       error
	queryPlan *filter.QueryPlan
	kvIter    Iterator
}

func newSecondaryIndexReaderImpl(ctx context.Context, tx transaction.Tx, coll *schema.DefaultCollection, filter *filter.WrappedFilter, queryPlan *filter.QueryPlan) (*SecondaryIndexReaderImpl, error) {
	reader := &SecondaryIndexReaderImpl{
		ctx:       ctx,
		tx:        tx,
		coll:      coll,
		filter:    filter,
		err:       nil,
		queryPlan: queryPlan,
	}

	return reader.createIter()
}

func (reader *SecondaryIndexReaderImpl) createIter() (*SecondaryIndexReaderImpl, error) {
	var err error

	reader.dbgPrintIndex()
	log.Debug().Msgf("Query Plan Keys %v ascending: %v", reader.queryPlan.GetKeyInterfaceParts(), reader.queryPlan.Ascending)

	switch reader.queryPlan.QueryType {
	case filter.FULLRANGE, filter.RANGE:
		reader.kvIter, err = NewScanIterator(reader.ctx, reader.tx, reader.queryPlan.Keys[0], reader.queryPlan.Keys[1], reader.queryPlan.Reverse())
		if err != nil {
			return nil, err
		}
	case filter.EQUAL:
		reader.kvIter, err = NewKeyIterator(reader.ctx, reader.tx, reader.queryPlan.Keys, reader.queryPlan.Reverse())
		if err != nil {
			return nil, err
		}
	default:
		return nil, errors.InvalidArgument("Incorrectly created query key range")
	}

	return reader, nil
}

func BuildSecondaryIndexKeys(coll *schema.DefaultCollection, queryFilters []filter.Filter, sortFields *sort.Ordering) (*filter.QueryPlan, error) {
	if len(queryFilters) == 0 && sortFields == nil {
		return nil, errors.InvalidArgument("Cannot index with an empty filter")
	}

	indexeableFields := coll.GetActiveIndexedFields()
	if len(indexeableFields) == 0 {
		return nil, errors.InvalidArgument("No indexable fields")
	}

	encoder := func(indexParts ...interface{}) (keys.Key, error) {
		return newKeyWithPrimaryKey(indexParts, coll.EncodedTableIndexName, coll.SecondaryIndexKeyword(), "kvs"), nil
	}

	buildIndexParts := func(fieldName string, val value.Value) []interface{} {
		typeOrder := value.ToSecondaryOrder(val.DataType(), val)
		return []interface{}{fieldName, typeOrder, val.AsInterface()}
	}

	sortQueryPlan, err := filter.QueryPlanFromSort(sortFields, indexeableFields, encoder, buildIndexParts)
	if err != nil {
		return nil, err
	}

	eqKeyBuilder := filter.NewSecondaryKeyEqBuilder[*schema.QueryableField](encoder, buildIndexParts)
	eqPlans, err := eqKeyBuilder.Build(queryFilters, indexeableFields)
	if err == nil {
		for _, plan := range eqPlans {
			// If a user specifies an $eq with the same fields as the field defined in sort
			// we want to use the eq to narrow down the search
			if indexedDataType(plan) && worksWithSortPlan(plan, sortQueryPlan) {
				return mergeWithSortPlan(plan, sortQueryPlan), nil
			}
		}
	}

	rangKeyBuilder := filter.NewRangeKeyBuilder(filter.NewRangeKeyComposer[*schema.QueryableField](encoder, buildIndexParts), false)
	rangePlans, err := rangKeyBuilder.Build(queryFilters, indexeableFields)
	// If we could not find a range query plan then fall back to the sort plan if we have one
	if err != nil {
		if sortQueryPlan != nil {
			return sortQueryPlan, nil
		} else {
			return nil, err
		}
	}

	if len(rangePlans) == 0 && sortQueryPlan == nil {
		return nil, errors.InvalidArgument("Could not find a query range")
	}

	rangePlans = filter.SortQueryPlans(rangePlans)
	for _, plan := range rangePlans {
		if indexedDataType(plan) && worksWithSortPlan(plan, sortQueryPlan) {
			return mergeWithSortPlan(plan, sortQueryPlan), nil
		}
	}

	if sortQueryPlan != nil {
		return sortQueryPlan, nil
	}

	return nil, errors.InvalidArgument("Could not find a useuable query plan")
}

func indexedDataType(queryPlan filter.QueryPlan) bool {
	switch queryPlan.DataType {
	case schema.ByteType, schema.UnknownType, schema.ArrayType:
		return false
	default:
		return true
	}
}

func worksWithSortPlan(plan filter.QueryPlan, sortPlan *filter.QueryPlan) bool {
	if sortPlan == nil {
		return true
	}

	if plan.FieldName == sortPlan.FieldName {
		// plan.Ascending = sortPlan.Ascending
		return true
	}

	return false
}

func mergeWithSortPlan(plan filter.QueryPlan, sortPlan *filter.QueryPlan) *filter.QueryPlan {
	if sortPlan == nil {
		return &plan
	}

	plan.Ascending = sortPlan.Ascending
	return &plan
}

func (it *SecondaryIndexReaderImpl) Next(row *Row) bool {
	if it.err != nil {
		return false
	}

	if it.kvIter.Interrupted() != nil {
		it.err = it.kvIter.Interrupted()
		return false
	}

	var indexRow Row
	if it.kvIter.Next(&indexRow) {
		indexKey, err := keys.FromBinary(it.coll.EncodedTableIndexName, indexRow.Key)
		if err != nil {
			it.err = err
			return false
		}

		pks := indexKey.IndexParts()[PrimaryKeyPos:]
		pkIndexParts := keys.NewKey(it.coll.EncodedName, pks...)

		docIter, err := it.tx.Read(it.ctx, pkIndexParts, false)
		if err != nil {
			it.err = err
			return false
		}

		var keyValue kv.KeyValue
		if docIter.Next(&keyValue) {
			row.Data = keyValue.Data
			row.Key = keyValue.FDBKey
			return true
		}
	}
	return false
}

func (it *SecondaryIndexReaderImpl) Interrupted() error { return it.err }

// For local debugging and testing.
//

func (it *SecondaryIndexReaderImpl) dbgPrintIndex() {
	indexer := newSecondaryIndexerImpl(it.coll)
	tableIter, err := indexer.scanIndex(it.ctx, it.tx)
	if err != nil {
		panic(err)
	}
	var val kv.KeyValue
	for tableIter.Next(&val) {
		log.Debug().Msgf("%v", val.Key)
	}
}

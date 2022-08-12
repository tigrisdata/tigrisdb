// Copyright 2022 Tigris Data, Inc.
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

package v1

import (
	"bytes"
	"context"
	"math"
	"time"

	jsoniter "github.com/json-iterator/go"
	api "github.com/tigrisdata/tigris/api/server/v1"
	"github.com/tigrisdata/tigris/internal"
	"github.com/tigrisdata/tigris/keys"
	"github.com/tigrisdata/tigris/query/filter"
	"github.com/tigrisdata/tigris/query/read"
	qsearch "github.com/tigrisdata/tigris/query/search"
	"github.com/tigrisdata/tigris/query/update"
	"github.com/tigrisdata/tigris/schema"
	"github.com/tigrisdata/tigris/server/cdc"
	"github.com/tigrisdata/tigris/server/metadata"
	"github.com/tigrisdata/tigris/server/transaction"
	"github.com/tigrisdata/tigris/store/kv"
	"github.com/tigrisdata/tigris/store/search"
	ulog "github.com/tigrisdata/tigris/util/log"
)

// QueryRunner is responsible for executing the current query and return the response
type QueryRunner interface {
	Run(ctx context.Context, tx transaction.Tx, tenant *metadata.Tenant) (*Response, context.Context, error)
}

// QueryRunnerFactory is responsible for creating query runners for different queries
type QueryRunnerFactory struct {
	txMgr       *transaction.Manager
	encoder     metadata.Encoder
	cdcMgr      *cdc.Manager
	searchStore search.Store
}

// NewQueryRunnerFactory returns QueryRunnerFactory object
func NewQueryRunnerFactory(txMgr *transaction.Manager, cdcMgr *cdc.Manager, searchStore search.Store) *QueryRunnerFactory {
	return &QueryRunnerFactory{
		txMgr:       txMgr,
		encoder:     metadata.NewEncoder(),
		cdcMgr:      cdcMgr,
		searchStore: searchStore,
	}
}

func (f *QueryRunnerFactory) GetInsertQueryRunner(r *api.InsertRequest) *InsertQueryRunner {
	return &InsertQueryRunner{
		BaseQueryRunner: NewBaseQueryRunner(f.encoder, f.cdcMgr, f.txMgr, f.searchStore),
		req:             r,
	}
}

func (f *QueryRunnerFactory) GetReplaceQueryRunner(r *api.ReplaceRequest) *ReplaceQueryRunner {
	return &ReplaceQueryRunner{
		BaseQueryRunner: NewBaseQueryRunner(f.encoder, f.cdcMgr, f.txMgr, f.searchStore),
		req:             r,
	}
}

func (f *QueryRunnerFactory) GetUpdateQueryRunner(r *api.UpdateRequest) *UpdateQueryRunner {
	return &UpdateQueryRunner{
		BaseQueryRunner: NewBaseQueryRunner(f.encoder, f.cdcMgr, f.txMgr, f.searchStore),
		req:             r,
	}
}

func (f *QueryRunnerFactory) GetDeleteQueryRunner(r *api.DeleteRequest) *DeleteQueryRunner {
	return &DeleteQueryRunner{
		BaseQueryRunner: NewBaseQueryRunner(f.encoder, f.cdcMgr, f.txMgr, f.searchStore),
		req:             r,
	}
}

// GetStreamingQueryRunner returns StreamingQueryRunner
func (f *QueryRunnerFactory) GetStreamingQueryRunner(r *api.ReadRequest, streaming Streaming) *StreamingQueryRunner {
	return &StreamingQueryRunner{
		BaseQueryRunner: NewBaseQueryRunner(f.encoder, f.cdcMgr, f.txMgr, f.searchStore),
		req:             r,
		streaming:       streaming,
	}
}

// GetSearchQueryRunner for executing Search
func (f *QueryRunnerFactory) GetSearchQueryRunner(r *api.SearchRequest, streaming SearchStreaming) *SearchQueryRunner {
	return &SearchQueryRunner{
		BaseQueryRunner: NewBaseQueryRunner(f.encoder, f.cdcMgr, f.txMgr, f.searchStore),
		req:             r,
		streaming:       streaming,
	}
}

// GetSubscribeQueryRunner returns SubscribeQueryRunner
func (f *QueryRunnerFactory) GetSubscribeQueryRunner(r *api.SubscribeRequest, streaming SubscribeStreaming) *SubscribeQueryRunner {
	return &SubscribeQueryRunner{
		BaseQueryRunner: NewBaseQueryRunner(f.encoder, f.cdcMgr, f.txMgr, f.searchStore),
		req:             r,
		streaming:       streaming,
	}
}

func (f *QueryRunnerFactory) GetCollectionQueryRunner() *CollectionQueryRunner {
	return &CollectionQueryRunner{
		BaseQueryRunner: NewBaseQueryRunner(f.encoder, f.cdcMgr, f.txMgr, f.searchStore),
	}
}

func (f *QueryRunnerFactory) GetDatabaseQueryRunner() *DatabaseQueryRunner {
	return &DatabaseQueryRunner{
		BaseQueryRunner: NewBaseQueryRunner(f.encoder, f.cdcMgr, f.txMgr, f.searchStore),
	}
}

type BaseQueryRunner struct {
	encoder     metadata.Encoder
	cdcMgr      *cdc.Manager
	searchStore search.Store
	txMgr       *transaction.Manager
}

func NewBaseQueryRunner(encoder metadata.Encoder, cdcMgr *cdc.Manager, txMgr *transaction.Manager, searchStore search.Store) *BaseQueryRunner {
	return &BaseQueryRunner{
		encoder:     encoder,
		cdcMgr:      cdcMgr,
		searchStore: searchStore,
		txMgr:       txMgr,
	}
}

func (runner *BaseQueryRunner) GetDatabase(ctx context.Context, tx transaction.Tx, tenant *metadata.Tenant, dbName string) (*metadata.Database, error) {
	if tx.Context().GetStagedDatabase() != nil {
		// this means that some DDL operation has modified the database object, then we need to perform all the operations
		// on this staged database.
		return tx.Context().GetStagedDatabase().(*metadata.Database), nil
	}

	// otherwise, simply read from the in-memory cache/disk.
	db, err := tenant.GetDatabase(ctx, tx, dbName)
	if err != nil {
		return nil, err
	}
	if db == nil {
		// database not found
		return nil, api.Errorf(api.Code_NOT_FOUND, "database doesn't exist '%s'", dbName)
	}

	return db, nil
}

func (runner *BaseQueryRunner) GetCollections(db *metadata.Database, collName string) (*schema.DefaultCollection, error) {
	collection := db.GetCollection(collName)
	if collection == nil {
		return nil, api.Errorf(api.Code_NOT_FOUND, "collection doesn't exist '%s'", collName)
	}

	return collection, nil
}

func (runner *BaseQueryRunner) insertOrReplace(ctx context.Context, tx transaction.Tx, tenant *metadata.Tenant, db *metadata.Database, coll *schema.DefaultCollection, documents [][]byte, insert bool) (*internal.Timestamp, [][]byte, error) {
	var err error
	var ts = internal.NewTimestamp()
	var allKeys [][]byte
	for _, doc := range documents {
		var deserializedDoc map[string]interface{}
		dec := jsoniter.NewDecoder(bytes.NewReader(doc))
		dec.UseNumber()
		if err = dec.Decode(&deserializedDoc); ulog.E(err) {
			return nil, nil, err
		}
		for k, v := range deserializedDoc {
			// for schema validation, if the field is set to null, remove it.
			if v == nil {
				delete(deserializedDoc, k)
			}
		}
		if err = coll.Validate(deserializedDoc); err != nil {
			// schema validation failed
			return nil, nil, err
		}

		table, err := runner.encoder.EncodeTableName(tenant.GetNamespace(), db, coll)
		if err != nil {
			return nil, nil, err
		}

		keyGen := newKeyGenerator(doc, tenant.TableKeyGenerator, coll.Indexes.PrimaryKey)
		key, err := keyGen.generate(ctx, runner.txMgr, runner.encoder, table)
		if err != nil {
			return nil, nil, err
		}

		// we need to use keyGen updated document as it may be mutated by adding auto-generated keys.
		tableData := internal.NewTableDataWithTS(ts, nil, keyGen.document)
		if insert || keyGen.forceInsert {
			// we use Insert API, in case user is using autogenerated primary key and has primary key field
			// as Int64 or timestamp to ensure uniqueness if multiple workers end up generating same timestamp.
			err = tx.Insert(ctx, key, tableData)
		} else {
			err = tx.Replace(ctx, key, tableData)
		}
		if err != nil {
			return nil, nil, err
		}
		allKeys = append(allKeys, keyGen.getKeysForResp())
	}
	return ts, allKeys, err
}

func (runner *BaseQueryRunner) buildKeysUsingFilter(tenant *metadata.Tenant, db *metadata.Database, coll *schema.DefaultCollection, reqFilter []byte) ([]keys.Key, error) {
	filterFactory := filter.NewFactory(coll.QueryableFields)
	filters, err := filterFactory.Factorize(reqFilter)
	if err != nil {
		return nil, err
	}

	encodedTable, err := runner.encoder.EncodeTableName(tenant.GetNamespace(), db, coll)
	if err != nil {
		return nil, err
	}

	primaryKeyIndex := coll.Indexes.PrimaryKey
	kb := filter.NewKeyBuilder(filter.NewStrictEqKeyComposer(func(indexParts ...interface{}) (keys.Key, error) {
		return runner.encoder.EncodeKey(encodedTable, primaryKeyIndex, indexParts)
	}))

	return kb.Build(filters, coll.Indexes.PrimaryKey.Fields)
}

type InsertQueryRunner struct {
	*BaseQueryRunner

	req *api.InsertRequest
}

func (runner *InsertQueryRunner) Run(ctx context.Context, tx transaction.Tx, tenant *metadata.Tenant) (*Response, context.Context, error) {
	db, err := runner.GetDatabase(ctx, tx, tenant, runner.req.GetDb())
	if err != nil {
		return nil, ctx, err
	}

	ctx = runner.cdcMgr.WrapContext(ctx, db.Name())

	coll, err := runner.GetCollections(db, runner.req.GetCollection())
	if err != nil {
		return nil, ctx, err
	}

	ts, allKeys, err := runner.insertOrReplace(ctx, tx, tenant, db, coll, runner.req.GetDocuments(), true)
	if err != nil {
		if err == kv.ErrDuplicateKey {
			return nil, ctx, api.Errorf(api.Code_ALREADY_EXISTS, err.Error())
		}

		return nil, ctx, err
	}
	return &Response{
		createdAt: ts,
		allKeys:   allKeys,
		status:    InsertedStatus,
	}, ctx, nil
}

type ReplaceQueryRunner struct {
	*BaseQueryRunner

	req *api.ReplaceRequest
}

func (runner *ReplaceQueryRunner) Run(ctx context.Context, tx transaction.Tx, tenant *metadata.Tenant) (*Response, context.Context, error) {
	db, err := runner.GetDatabase(ctx, tx, tenant, runner.req.GetDb())
	if err != nil {
		return nil, ctx, err
	}

	ctx = runner.cdcMgr.WrapContext(ctx, db.Name())

	coll, err := runner.GetCollections(db, runner.req.GetCollection())
	if err != nil {
		return nil, ctx, err
	}

	ts, allKeys, err := runner.insertOrReplace(ctx, tx, tenant, db, coll, runner.req.GetDocuments(), false)
	if err != nil {
		return nil, ctx, err
	}
	return &Response{
		createdAt: ts,
		allKeys:   allKeys,
		status:    ReplacedStatus,
	}, ctx, nil
}

type UpdateQueryRunner struct {
	*BaseQueryRunner

	req *api.UpdateRequest
}

func (runner *UpdateQueryRunner) Run(ctx context.Context, tx transaction.Tx, tenant *metadata.Tenant) (*Response, context.Context, error) {
	var ts = internal.NewTimestamp()
	db, err := runner.GetDatabase(ctx, tx, tenant, runner.req.GetDb())
	if err != nil {
		return nil, ctx, err
	}

	ctx = runner.cdcMgr.WrapContext(ctx, db.Name())

	collection, err := runner.GetCollections(db, runner.req.GetCollection())
	if err != nil {
		return nil, ctx, err
	}

	iKeys, err := runner.buildKeysUsingFilter(tenant, db, collection, runner.req.Filter)
	if err != nil {
		return nil, ctx, err
	}

	var factory *update.FieldOperatorFactory
	factory, err = update.BuildFieldOperators(runner.req.Fields)
	if err != nil {
		return nil, ctx, err
	}

	for _, fieldOperators := range factory.FieldOperators {
		v, err := fieldOperators.DeserializeDoc()
		if err != nil {
			return nil, ctx, err
		}

		if vMap, ok := v.(map[string]interface{}); ok {
			for k, v := range vMap {
				// remove fields that are set as null as we don't need them for the validation
				if v == nil {
					delete(vMap, k)
				}
			}
		}

		if err = collection.Validate(v); err != nil {
			// schema validation failed
			return nil, ctx, err
		}
	}

	modifiedCount := int32(0)
	for _, key := range iKeys {
		// decode the fields now
		modified := int32(0)
		if modified, err = tx.Update(ctx, key, func(existing *internal.TableData) (*internal.TableData, error) {
			merged, er := factory.MergeAndGet(existing.RawData)
			if er != nil {
				return nil, er
			}

			// ToDo: may need to change the schema version
			return internal.NewTableDataWithTS(existing.CreatedAt, ts, merged), nil
		}); ulog.E(err) {
			return nil, ctx, err
		}
		modifiedCount += modified
	}

	return &Response{
		status:        UpdatedStatus,
		updatedAt:     ts,
		modifiedCount: modifiedCount,
	}, ctx, err
}

type DeleteQueryRunner struct {
	*BaseQueryRunner

	req *api.DeleteRequest
}

func (runner *DeleteQueryRunner) Run(ctx context.Context, tx transaction.Tx, tenant *metadata.Tenant) (*Response, context.Context, error) {
	var ts = internal.NewTimestamp()
	db, err := runner.GetDatabase(ctx, tx, tenant, runner.req.GetDb())
	if err != nil {
		return nil, ctx, err
	}

	ctx = runner.cdcMgr.WrapContext(ctx, db.Name())

	collection, err := runner.GetCollections(db, runner.req.GetCollection())
	if err != nil {
		return nil, ctx, err
	}

	iKeys, err := runner.buildKeysUsingFilter(tenant, db, collection, runner.req.Filter)
	if err != nil {
		return nil, ctx, err
	}

	for _, key := range iKeys {
		if err = tx.Delete(ctx, key); ulog.E(err) {
			return nil, ctx, err
		}
	}

	return &Response{
		status:    DeletedStatus,
		deletedAt: ts,
	}, ctx, nil
}

// StreamingQueryRunner is a runner used for Queries that are reads and needs to return result in streaming fashion
type StreamingQueryRunner struct {
	*BaseQueryRunner

	req       *api.ReadRequest
	streaming Streaming
}

// Run is responsible for running/executing the query
func (runner *StreamingQueryRunner) Run(ctx context.Context, tx transaction.Tx, tenant *metadata.Tenant) (*Response, context.Context, error) {
	db, err := runner.GetDatabase(ctx, tx, tenant, runner.req.GetDb())
	if err != nil {
		return nil, ctx, err
	}

	ctx = runner.cdcMgr.WrapContext(ctx, db.Name())

	collection, err := runner.GetCollections(db, runner.req.GetCollection())
	if err != nil {
		return nil, ctx, err
	}

	fieldFactory, err := read.BuildFields(runner.req.GetFields())
	if ulog.E(err) {
		return nil, ctx, err
	}

	var rowReader RowReader
	if filter.All(runner.req.GetFilter()) {
		table, err := runner.encoder.EncodeTableName(tenant.GetNamespace(), db, collection)
		if err != nil {
			return nil, nil, err
		}

		if rowReader, err = MakeDatabaseRowReader(ctx, tx, []keys.Key{keys.NewKey(table)}); ulog.E(err) {
			return nil, ctx, err
		}
	} else {
		wrappedFilter, err := filter.NewFactory(collection.QueryableFields).WrappedFilter(runner.req.Filter)
		if err != nil {
			return nil, ctx, err
		}

		// or this is a read request that needs to be streamed after filtering the keys.
		var iKeys []keys.Key
		if iKeys, err = runner.buildKeysUsingFilter(tenant, db, collection, runner.req.Filter); err == nil {
			rowReader, err = MakeDatabaseRowReader(ctx, tx, iKeys)
		} else {
			rowReader, err = NewSearchReader(ctx, runner.searchStore, collection, qsearch.NewBuilder().
				Filter(wrappedFilter).
				PageSize(defaultPerPage).
				Build())
		}
		if err != nil {
			return nil, ctx, err
		}
	}

	if err = runner.iterate(ctx, rowReader, fieldFactory); err != nil {
		return nil, ctx, err
	}

	return &Response{}, ctx, nil
}

func (runner *StreamingQueryRunner) iterate(ctx context.Context, reader RowReader, fieldFactory *read.FieldFactory) error {
	limit, totalResults := int64(0), int64(0)
	if runner.req.GetOptions() != nil {
		limit = runner.req.GetOptions().Limit
	}

	var row Row
	for reader.Next(ctx, &row) {
		if limit > 0 && limit <= totalResults {
			return nil
		}

		newValue, err := fieldFactory.Apply(row.Data.RawData)
		if ulog.E(err) {
			return err
		}

		if err := runner.streaming.Send(&api.ReadResponse{
			Data: newValue,
			Metadata: &api.ResponseMetadata{
				CreatedAt: row.Data.CreateToProtoTS(),
				UpdatedAt: row.Data.UpdatedToProtoTS(),
			},
			ResumeToken: row.Key,
		}); ulog.E(err) {
			return err
		}

		totalResults++
	}

	return reader.Err()
}

// SearchQueryRunner is a runner used for Queries that are reads and needs to return result in streaming fashion
type SearchQueryRunner struct {
	*BaseQueryRunner

	req       *api.SearchRequest
	streaming SearchStreaming
}

func (runner *SearchQueryRunner) Run(ctx context.Context, tx transaction.Tx, tenant *metadata.Tenant) (*Response, context.Context, error) {
	db, err := runner.GetDatabase(ctx, tx, tenant, runner.req.GetDb())
	if err != nil {
		return nil, ctx, err
	}

	ctx = runner.cdcMgr.WrapContext(ctx, db.Name())

	collection, err := runner.GetCollections(db, runner.req.GetCollection())
	if err != nil {
		return nil, ctx, err
	}

	wrappedF, err := filter.NewFactory(collection.QueryableFields).WrappedFilter(runner.req.Filter)
	if err != nil {
		return nil, ctx, err
	}

	searchFields, err := runner.getSearchFields(collection)
	if err != nil {
		return nil, ctx, err
	}

	facets, err := runner.getFacetFields(collection)
	if err != nil {
		return nil, ctx, err
	}

	fieldSelection, err := runner.getFieldSelection(collection)
	if err != nil {
		return nil, ctx, err
	}

	sortOrder, err := runner.getSortOrdering(collection)
	if err != nil {
		return nil, ctx, err
	}

	pageSize := int(runner.req.PageSize)
	if pageSize == 0 {
		pageSize = defaultPerPage
	}
	var totalPages *int32

	searchQ := qsearch.NewBuilder().
		Query(runner.req.Q).
		SearchFields(searchFields).
		Facets(facets).
		PageSize(pageSize).
		Filter(wrappedF).
		ReadFields(fieldSelection).
		SortOrder(sortOrder).
		Build()

	var rowReader *SearchRowReader
	if runner.req.Page != 0 {
		rowReader, err = SinglePageSearchReader(ctx, runner.searchStore, collection, searchQ, runner.req.Page)
	} else {
		rowReader, err = NewSearchReader(ctx, runner.searchStore, collection, searchQ)
	}
	if err != nil {
		return nil, ctx, err
	}

	var pageNo = int32(defaultPageNo)
	if runner.req.Page > 0 {
		pageNo = runner.req.Page
	}
	for {
		var resp = &api.SearchResponse{}
		var row Row
		for rowReader.Next(ctx, &row) {
			resp.Hits = append(resp.Hits, &api.SearchHit{
				Data: row.Data.RawData,
				Metadata: &api.SearchHitMeta{
					CreatedAt: row.Data.CreateToProtoTS(),
					UpdatedAt: row.Data.UpdatedToProtoTS(),
				},
			})

			if len(resp.Hits) == pageSize {
				break
			}
		}

		resp.Facets = rowReader.getFacets()
		if totalPages == nil {
			tp := int32(math.Ceil(float64(rowReader.getTotalFound()) / float64(pageSize)))
			totalPages = &tp
		}

		resp.Meta = &api.SearchMetadata{
			Found:      rowReader.getTotalFound(),
			TotalPages: *totalPages,
			Page: &api.Page{
				Current: pageNo,
				Size:    int32(searchQ.PageSize),
			},
		}
		// if no hits, got error, send only error
		// if no hits, no error, at least one response and break
		// if some hits, got an error, send current hits and then error (will be zero hits next time)
		// if some hits, no error, continue to send response
		if len(resp.Hits) == 0 {
			if rowReader.err != nil {
				return nil, ctx, rowReader.err
			}
			if pageNo > defaultPageNo && pageNo > runner.req.Page {
				break
			}
		}

		if err := runner.streaming.Send(resp); err != nil {
			return nil, ctx, err
		}

		pageNo++
	}

	return &Response{}, ctx, nil
}

func (runner *SearchQueryRunner) getSearchFields(coll *schema.DefaultCollection) ([]string, error) {
	var searchFields = runner.req.SearchFields
	if len(searchFields) == 0 {
		// this is to include all searchable fields if not present in the query
		for _, cf := range coll.GetQueryableFields() {
			if cf.DataType == schema.StringType {
				searchFields = append(searchFields, cf.FieldName)
			}
		}
	} else {
		for _, sf := range searchFields {
			cf, err := coll.GetQueryableField(sf)
			if err != nil {
				return nil, err
			}
			if cf.DataType != schema.StringType {
				return nil, api.Errorf(api.Code_INVALID_ARGUMENT, "`%s` is not a searchable field. Only string fields can be queried", sf)
			}
		}
	}
	return searchFields, nil
}

func (runner *SearchQueryRunner) getFacetFields(coll *schema.DefaultCollection) (qsearch.Facets, error) {
	facets, err := qsearch.UnmarshalFacet(runner.req.Facet)
	if err != nil {
		return qsearch.Facets{}, err
	}

	for _, ff := range facets.Fields {
		cf, err := coll.GetQueryableField(ff.Name)
		if err != nil {
			return qsearch.Facets{}, err
		}
		if !cf.Faceted {
			return qsearch.Facets{}, api.Errorf(api.Code_INVALID_ARGUMENT, "Cannot generate facets for `%s`. Faceting is only supported for numeric and text fields", ff.Name)
		}
	}

	return facets, nil
}

func (runner *SearchQueryRunner) getFieldSelection(coll *schema.DefaultCollection) (*read.FieldFactory, error) {
	var selectionFields []string

	// Only one of include/exclude. Honor inclusion over exclusion
	if len(runner.req.IncludeFields) > 0 {
		selectionFields = runner.req.IncludeFields
	} else if len(runner.req.ExcludeFields) > 0 {
		selectionFields = runner.req.ExcludeFields
	} else {
		return nil, nil
	}

	factory := &read.FieldFactory{
		Include: map[string]read.Field{},
		Exclude: map[string]read.Field{},
	}

	for _, sf := range selectionFields {
		cf, err := coll.GetQueryableField(sf)
		if err != nil {
			return nil, err
		}

		factory.AddField(&read.SimpleField{
			Name: cf.Name(),
			Incl: len(runner.req.IncludeFields) > 0,
		})
	}

	return factory, nil
}

func (runner *SearchQueryRunner) getSortOrdering(coll *schema.DefaultCollection) (*qsearch.Ordering, error) {
	ordering, err := qsearch.UnmarshalSort(runner.req.GetSort())
	if err != nil || ordering == nil {
		return nil, err
	}

	for _, sf := range *ordering {
		cf, err := coll.GetQueryableField(sf.Name)
		if err != nil {
			return nil, err
		}

		if !cf.Sortable {
			return nil, api.Errorf(api.Code_INVALID_ARGUMENT, "Cannot sort on `%s` field", sf.Name)
		}
	}
	return ordering, nil
}

type SubscribeQueryRunner struct {
	*BaseQueryRunner

	req       *api.SubscribeRequest
	streaming SubscribeStreaming
}

func (runner *SubscribeQueryRunner) Run(ctx context.Context, tx transaction.Tx, tenant *metadata.Tenant) (*Response, context.Context, error) {
	db, err := runner.GetDatabase(ctx, tx, tenant, runner.req.GetDb())
	if ulog.E(err) {
		return nil, ctx, err
	}

	collection, err := runner.GetCollections(db, runner.req.GetCollection())
	if ulog.E(err) {
		return nil, ctx, err
	}

	table, err := runner.encoder.EncodeTableName(tenant.GetNamespace(), db, collection)
	if ulog.E(err) {
		return nil, ctx, err
	}

	skipFirst := false
	startTime := time.Now().UTC().Format(time.RFC3339Nano)

	ticker := time.NewTicker(100 * time.Millisecond)
	defer ticker.Stop()

	for range ticker.C {
		tickerTx, err := runner.txMgr.StartTx(ctx)
		if ulog.E(err) {
			return nil, ctx, err
		}

		startKey, err := runner.encoder.EncodeKey(table, collection.Indexes.PrimaryKey, []interface{}{startTime})
		if ulog.E(err) {
			return nil, ctx, err
		}

		end, err := time.Parse(time.RFC3339, startTime)
		if ulog.E(err) {
			return nil, ctx, err
		}

		endTime := end.Add(34 * time.Second).Format(time.RFC3339)
		endKey, err := runner.encoder.EncodeKey(table, collection.Indexes.PrimaryKey, []interface{}{endTime})
		if ulog.E(err) {
			return nil, ctx, err
		}

		kvIterator, err := tickerTx.ReadRange(ctx, startKey, endKey)
		if ulog.E(err) {
			return nil, ctx, err
		}

		first := true
		var keyValue kv.KeyValue
		for kvIterator.Next(&keyValue) {
			if ulog.E(kvIterator.Err()) {
				return nil, ctx, kvIterator.Err()
			}

			if skipFirst && first {
				first = false
				continue
			}

			err = runner.streaming.Send(&api.SubscribeResponse{
				Message: keyValue.Data.RawData,
			})
			if ulog.E(err) {
				return nil, ctx, err
			}

			first = false
			skipFirst = true
			startTime = keyValue.Key[1].(string)
		}

		// TODO: read-only transaction should ignore any error like transaction timed-out
		err = tickerTx.Commit(ctx)
		if ulog.E(err) {
			return nil, ctx, err
		}
	}

	return &Response{}, ctx, nil
}

type CollectionQueryRunner struct {
	*BaseQueryRunner

	dropReq           *api.DropCollectionRequest
	listReq           *api.ListCollectionsRequest
	createOrUpdateReq *api.CreateOrUpdateCollectionRequest
	describeReq       *api.DescribeCollectionRequest
}

func (runner *CollectionQueryRunner) SetCreateOrUpdateCollectionReq(create *api.CreateOrUpdateCollectionRequest) {
	runner.createOrUpdateReq = create
}

func (runner *CollectionQueryRunner) SetDropCollectionReq(drop *api.DropCollectionRequest) {
	runner.dropReq = drop
}

func (runner *CollectionQueryRunner) SetListCollectionReq(list *api.ListCollectionsRequest) {
	runner.listReq = list
}

func (runner *CollectionQueryRunner) SetDescribeCollectionReq(describe *api.DescribeCollectionRequest) {
	runner.describeReq = describe
}

func (runner *CollectionQueryRunner) Run(ctx context.Context, tx transaction.Tx, tenant *metadata.Tenant) (*Response, context.Context, error) {
	if runner.dropReq != nil {
		db, err := runner.GetDatabase(ctx, tx, tenant, runner.dropReq.GetDb())
		if err != nil {
			return nil, ctx, err
		}

		if tx.Context().GetStagedDatabase() == nil {
			// do not modify the actual database object yet, just work on the clone
			db = db.Clone()
			tx.Context().StageDatabase(db)
		}

		if err = tenant.DropCollection(ctx, tx, db, runner.dropReq.GetCollection()); err != nil {
			return nil, ctx, err
		}

		return &Response{
			status: DroppedStatus,
		}, ctx, nil
	} else if runner.createOrUpdateReq != nil {
		db, err := runner.GetDatabase(ctx, tx, tenant, runner.createOrUpdateReq.GetDb())
		if err != nil {
			return nil, ctx, err
		}

		if db.GetCollection(runner.createOrUpdateReq.GetCollection()) != nil && runner.createOrUpdateReq.OnlyCreate {
			// check if onlyCreate is set and if set then return an error if collection already exist
			return nil, ctx, api.Errorf(api.Code_ALREADY_EXISTS, "collection already exist")
		}

		schFactory, err := schema.BuildWithType(runner.createOrUpdateReq.GetCollection(), runner.createOrUpdateReq.GetSchema(), runner.createOrUpdateReq.GetType())
		if err != nil {
			return nil, ctx, err
		}

		if tx.Context().GetStagedDatabase() == nil {
			// do not modify the actual database object yet, just work on the clone
			db = db.Clone()
			tx.Context().StageDatabase(db)
		}

		if err = tenant.CreateCollection(ctx, tx, db, schFactory); err != nil {
			if err == kv.ErrDuplicateKey {
				// this simply means, concurrently CreateCollection is called,
				return nil, ctx, api.Errorf(api.Code_ABORTED, "concurrent create collection request, aborting")
			}
			return nil, ctx, err
		}

		return &Response{
			status: CreatedStatus,
		}, ctx, nil
	} else if runner.listReq != nil {
		db, err := runner.GetDatabase(ctx, tx, tenant, runner.listReq.GetDb())
		if err != nil {
			return nil, ctx, err
		}

		collectionList := db.ListCollection()
		var collections = make([]*api.CollectionInfo, len(collectionList))
		for i, c := range collectionList {
			collections[i] = &api.CollectionInfo{
				Collection: c.GetName(),
			}
		}
		return &Response{
			Response: &api.ListCollectionsResponse{
				Collections: collections,
			},
		}, ctx, nil
	} else if runner.describeReq != nil {
		db, err := runner.GetDatabase(ctx, tx, tenant, runner.describeReq.GetDb())
		if err != nil {
			return nil, ctx, err
		}

		coll, err := runner.GetCollections(db, runner.describeReq.GetCollection())
		if err != nil {
			return nil, ctx, err
		}

		size, err := tenant.CollectionSize(ctx, db, coll)
		if err != nil {
			return nil, ctx, err
		}

		return &Response{
			Response: &api.DescribeCollectionResponse{
				Collection: coll.Name,
				Metadata:   &api.CollectionMetadata{},
				Schema:     coll.Schema,
				Size:       size,
			},
		}, ctx, nil
	}

	return &Response{}, ctx, api.Errorf(api.Code_UNKNOWN, "unknown request path")
}

type DatabaseQueryRunner struct {
	*BaseQueryRunner

	drop     *api.DropDatabaseRequest
	create   *api.CreateDatabaseRequest
	list     *api.ListDatabasesRequest
	describe *api.DescribeDatabaseRequest
}

func (runner *DatabaseQueryRunner) SetCreateDatabaseReq(create *api.CreateDatabaseRequest) {
	runner.create = create
}

func (runner *DatabaseQueryRunner) SetDropDatabaseReq(drop *api.DropDatabaseRequest) {
	runner.drop = drop
}

func (runner *DatabaseQueryRunner) SetListDatabaseReq(list *api.ListDatabasesRequest) {
	runner.list = list
}

func (runner *DatabaseQueryRunner) SetDescribeDatabaseReq(describe *api.DescribeDatabaseRequest) {
	runner.describe = describe
}

func (runner *DatabaseQueryRunner) Run(ctx context.Context, tx transaction.Tx, tenant *metadata.Tenant) (*Response, context.Context, error) {
	if runner.drop != nil {
		exist, err := tenant.DropDatabase(ctx, tx, runner.drop.GetDb())
		if err != nil {
			return nil, ctx, err
		}
		if !exist {
			return nil, ctx, api.Errorf(api.Code_NOT_FOUND, "database doesn't exist '%s'", runner.drop.GetDb())
		}

		return &Response{
			status: DroppedStatus,
		}, ctx, nil
	} else if runner.create != nil {
		exist, err := tenant.CreateDatabase(ctx, tx, runner.create.GetDb())
		if err != nil {
			return nil, ctx, err
		}
		if exist {
			return nil, ctx, api.Errorf(api.Code_ALREADY_EXISTS, "database already exist")
		}

		return &Response{
			status: CreatedStatus,
		}, ctx, nil
	} else if runner.list != nil {
		databaseList := tenant.ListDatabases(ctx, tx)

		var databases = make([]*api.DatabaseInfo, len(databaseList))
		for i, l := range databaseList {
			databases[i] = &api.DatabaseInfo{
				Db: l,
			}
		}
		return &Response{
			Response: &api.ListDatabasesResponse{
				Databases: databases,
			},
		}, ctx, nil
	} else if runner.describe != nil {
		db, err := runner.GetDatabase(ctx, tx, tenant, runner.describe.GetDb())
		if err != nil {
			return nil, ctx, err
		}

		collectionList := db.ListCollection()

		var collections = make([]*api.CollectionDescription, len(collectionList))
		for i, c := range collectionList {
			size, err := tenant.CollectionSize(ctx, db, c)
			if err != nil {
				return nil, ctx, err
			}
			collections[i] = &api.CollectionDescription{
				Collection: c.GetName(),
				Metadata:   &api.CollectionMetadata{},
				Schema:     c.Schema,
				Size:       size,
			}
		}

		size, err := tenant.DatabaseSize(ctx, db)
		if err != nil {
			return nil, ctx, err
		}

		return &Response{
			Response: &api.DescribeDatabaseResponse{
				Db:          db.Name(),
				Metadata:    &api.DatabaseMetadata{},
				Collections: collections,
				Size:        size,
			},
		}, ctx, nil
	}

	return &Response{}, ctx, api.Errorf(api.Code_UNKNOWN, "unknown request path")
}

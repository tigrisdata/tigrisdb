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

package schema

import (
	"fmt"

	jsoniter "github.com/json-iterator/go"
	api "github.com/tigrisdata/tigris/api/server/v1"
	"github.com/tigrisdata/tigris/errors"
	tsApi "github.com/typesense/typesense-go/typesense/api"
)

type SearchSourceType string

const (
	// SearchSourceTigris is when the source type is Tigris for the search index.
	SearchSourceTigris SearchSourceType = "tigris"
	// SearchSourceExternal is when the source type is external for the search index.
	SearchSourceExternal SearchSourceType = "external"
)

type SearchSource struct {
	// Type is the source type i.e. either it is Tigris or the index will be maintained by the user.
	Type SearchSourceType `json:"type,omitempty"`
	// CollectionName is the source name i.e. collection name in case of Tigris otherwise it is optional.
	CollectionName string `json:"collection,omitempty"`
	// DatabaseBranch is in case the collection is part of a database branch. Only applicable if Type is Tigris.
	DatabaseBranch string `json:"branch,omitempty"`
}

type SearchJSONSchema struct {
	Name        string              `json:"title,omitempty"`
	Description string              `json:"description,omitempty"`
	Properties  jsoniter.RawMessage `json:"properties,omitempty"`
	Source      *SearchSource       `json:"source,omitempty"`
}

// SearchFactory is used as an intermediate step so that collection can be initialized with properly encoded values.
type SearchFactory struct {
	// Name is the index name.
	Name string
	// Fields are derived from the user schema.
	Fields []*Field
	// Schema is the raw JSON schema received
	Schema jsoniter.RawMessage
	Sub    string
	Source SearchSource
}

func (fb *FactoryBuilder) BuildSearch(index string, reqSchema jsoniter.RawMessage) (*SearchFactory, error) {
	fb.setBuilderForSearch()

	searchSchema := make([]byte, len(reqSchema))
	copy(searchSchema, reqSchema)

	schema := &SearchJSONSchema{}
	if err := jsoniter.Unmarshal(searchSchema, schema); err != nil {
		return nil, api.Errorf(api.Code_INTERNAL, err.Error()).WithDetails(&api.ErrorDetails{
			Code:    api.Code_INTERNAL.String(),
			Message: fmt.Sprintf("schema: '%s', unmarshalling failed", string(searchSchema)),
		})
	}
	if len(schema.Properties) == 0 {
		return nil, errors.InvalidArgument("missing properties field in schema")
	}
	fields, err := fb.deserializeProperties(schema.Properties, nil, nil)
	if err != nil {
		return nil, err
	}

	var source SearchSource
	if schema.Source == nil {
		source = SearchSource{
			Type: SearchSourceExternal,
		}
		schema.Source = &source

		if searchSchema, err = jsoniter.Marshal(schema); err != nil {
			return nil, err
		}
	} else {
		source = *schema.Source
	}
	if schema.Source.Type == SearchSourceTigris && len(schema.Source.DatabaseBranch) == 0 {
		// we set main branch by default if branch is not explicitly provided
		schema.Source.DatabaseBranch = "main"
		if searchSchema, err = jsoniter.Marshal(schema); err != nil {
			return nil, err
		}
	}

	found := false
	for _, f := range fields {
		if f.FieldName == SearchId {
			found = true
			break
		}
	}
	if !found {
		// add id field if not in the schema
		fields = append(fields, &Field{
			FieldName: "id",
			DataType:  StringType,
		})
	}

	factory := &SearchFactory{
		Name:   index,
		Fields: fields,
		Schema: searchSchema,
		Source: source,
	}

	idFound := false
	for _, f := range factory.Fields {
		if f.FieldName == SearchId {
			idFound = true
			break
		}
	}
	if !idFound {
		factory.Fields = append(factory.Fields, &Field{
			FieldName: SearchId,
			DataType:  StringType,
		})
	}

	if fb.onUserRequest {
		if err = fb.validateSearchSchema(factory); err != nil {
			return nil, err
		}
	}

	return factory, nil
}

func (fb *FactoryBuilder) validateSearchSchema(factory *SearchFactory) error {
	if factory.Source.Type != SearchSourceExternal {
		return errors.InvalidArgument("unsupported index source '%s'", factory.Source.Type)
	}

	for _, f := range factory.Fields {
		if err := ValidateFieldAttributes(true, f); err != nil {
			return err
		}
	}

	return nil
}

// SearchIndex is to manage search index created by the user.
type SearchIndex struct {
	// Name is the name of the index.
	Name string
	// index version
	Version int
	// Fields are derived from the user schema.
	Fields []*Field
	// JSON schema.
	Schema jsoniter.RawMessage
	// StoreSchema is the search schema of the underlying search engine.
	StoreSchema *tsApi.CollectionSchema
	// QueryableFields are similar to Fields but these are flattened forms of fields. For instance, a simple field
	// will be one to one mapped to queryable field but complex fields like object type field there may be more than
	// one queryableFields. As queryableFields represent a flattened state these can be used as-is to index in memory.
	QueryableFields []*QueryableField
	// Source of this index
	Source SearchSource
}

func NewSearchIndex(ver int, searchStoreName string, factory *SearchFactory, fieldsInSearch []tsApi.Field) *SearchIndex {
	queryableFields := NewQueryableFieldsBuilder().BuildQueryableFields(factory.Fields, fieldsInSearch)

	index := &SearchIndex{
		Version:         ver,
		Name:            factory.Name,
		Fields:          factory.Fields,
		Schema:          factory.Schema,
		QueryableFields: queryableFields,
		Source:          factory.Source,
	}
	index.buildSearchSchema(searchStoreName)

	return index
}

func (s *SearchIndex) StoreIndexName() string {
	return s.StoreSchema.Name
}

func (s *SearchIndex) GetQueryableField(name string) (*QueryableField, error) {
	for _, qf := range s.QueryableFields {
		if qf.Name() == name {
			return qf, nil
		}
	}
	return nil, errors.InvalidArgument("Field `%s` is not present in collection", name)
}

func (s *SearchIndex) buildSearchSchema(name string) {
	ptrTrue, ptrFalse := true, false
	tsFields := make([]tsApi.Field, 0, len(s.QueryableFields))
	for _, s := range s.QueryableFields {
		tsFields = append(tsFields, tsApi.Field{
			Name:     s.Name(),
			Type:     s.SearchType,
			Facet:    &s.Faceted,
			Index:    &s.SearchIndexed,
			Sort:     &s.Sortable,
			Optional: &ptrTrue,
		})

		if s.InMemoryName() != s.Name() {
			// we are storing this field differently in in-memory store
			tsFields = append(tsFields, tsApi.Field{
				Name:     s.InMemoryName(),
				Type:     s.SearchType,
				Facet:    &s.Faceted,
				Index:    &s.SearchIndexed,
				Sort:     &s.Sortable,
				Optional: &ptrTrue,
			})
		}

		// Save original date as string to disk
		if !s.IsReserved() && s.DataType == DateTimeType {
			tsFields = append(tsFields, tsApi.Field{
				Name:     ToSearchDateKey(s.Name()),
				Type:     toSearchFieldType(StringType, UnknownType),
				Facet:    &ptrFalse,
				Index:    &ptrFalse,
				Sort:     &ptrFalse,
				Optional: &ptrTrue,
			})
		}
	}

	s.StoreSchema = &tsApi.CollectionSchema{
		Name:   name,
		Fields: tsFields,
	}
}

func (s *SearchIndex) GetSearchDeltaFields(existingFields []*QueryableField, fieldsInSearch []tsApi.Field) []tsApi.Field {
	ptrTrue := true

	incomingQueryable := NewQueryableFieldsBuilder().BuildQueryableFields(s.Fields, fieldsInSearch)

	existingFieldMap := make(map[string]*QueryableField)
	for _, f := range existingFields {
		existingFieldMap[f.FieldName] = f
	}

	fieldsInSearchMap := make(map[string]tsApi.Field)
	for _, f := range fieldsInSearch {
		fieldsInSearchMap[f.Name] = f
	}

	tsFields := make([]tsApi.Field, 0, len(incomingQueryable))
	for _, f := range incomingQueryable {
		e := existingFieldMap[f.FieldName]
		delete(existingFieldMap, f.FieldName)

		if e != nil && f.SearchType == e.SearchType && f.SearchIndexed == e.SearchIndexed && f.Faceted == e.Faceted && f.Sortable == e.Sortable {
			continue
		}

		// attribute changed, drop the field first
		if e != nil {
			tsFields = append(tsFields, tsApi.Field{
				Name: f.FieldName,
				Drop: &ptrTrue,
			})
		} else {
			// this can happen if update request is timed out on Tigris side but succeed on search
			if _, found := fieldsInSearchMap[f.FieldName]; found {
				tsFields = append(tsFields, tsApi.Field{
					Name: f.FieldName,
					Drop: &ptrTrue,
				})
			}
		}

		// add new field
		tsFields = append(tsFields, tsApi.Field{
			Name:     f.FieldName,
			Type:     f.SearchType,
			Facet:    &f.Faceted,
			Index:    &f.SearchIndexed,
			Sort:     &f.Sortable,
			Optional: &ptrTrue,
		})
	}

	// drop fields non existing in new schema
	for _, f := range existingFieldMap {
		tsField := tsApi.Field{
			Name: f.FieldName,
			Drop: &ptrTrue,
		}

		tsFields = append(tsFields, tsField)
	}

	return tsFields
}

// ImplicitSearchIndex is a search index that is automatically created by Tigris when a collection is created. Lifecycle
// of this index is tied to the collection.
type ImplicitSearchIndex struct {
	// Name is the name of the index.
	Name string
	// StoreSchema is the search schema of the underlying search engine.
	StoreSchema *tsApi.CollectionSchema
	// QueryableFields are similar to Fields but these are flattened forms of fields. For instance, a simple field
	// will be one to one mapped to queryable field but complex fields like object type field there may be more than
	// one queryableFields. As queryableFields represent a flattened state these can be used as-is to index in memory.
	QueryableFields []*QueryableField

	prevVersionInSearch []tsApi.Field
}

func NewImplicitSearchIndex(name string, searchStoreName string, fields []*Field, prevVersionInSearch []tsApi.Field) *ImplicitSearchIndex {
	// this is created by collection so the forSearchIndex is false.
	queryableFields := NewQueryableFieldsBuilder().BuildQueryableFields(fields, prevVersionInSearch)
	index := &ImplicitSearchIndex{
		Name:                name,
		QueryableFields:     queryableFields,
		prevVersionInSearch: prevVersionInSearch,
	}

	index.buildSearchSchema(searchStoreName)

	return index
}

func (s *ImplicitSearchIndex) StoreIndexName() string {
	return s.StoreSchema.Name
}

func (s *ImplicitSearchIndex) buildSearchSchema(searchStoreName string) {
	ptrTrue, ptrFalse := true, false
	tsFields := make([]tsApi.Field, 0, len(s.QueryableFields))

	for _, f := range s.QueryableFields {
		// the implicit search index by default index all the fields that are indexable and same applies to facet/sort.
		shouldIndex := SupportedSearchIndexableType(f.DataType, f.SubType)
		shouldFacet := DefaultFacetableType(f.DataType)
		shouldSort := DefaultSortableType(f.DataType)

		if !shouldSort && f.Sortable {
			// honor schema i.e. in case of strings user can explicitly enable sorting.
			shouldSort = true
		}
		if !shouldFacet && f.Faceted {
			shouldFacet = true
		}

		tsFields = append(tsFields, tsApi.Field{
			Name:     f.Name(),
			Type:     f.SearchType,
			Facet:    &shouldFacet,
			Index:    &shouldIndex,
			Sort:     &shouldSort,
			Optional: &ptrTrue,
		})

		if f.InMemoryName() != f.Name() {
			// we are storing this field differently in in-memory store
			tsFields = append(tsFields, tsApi.Field{
				Name:     f.InMemoryName(),
				Type:     f.SearchType,
				Facet:    &shouldFacet,
				Index:    &shouldIndex,
				Sort:     &shouldSort,
				Optional: &ptrTrue,
			})
		}
		// Save original date as string to disk
		if !f.IsReserved() && f.DataType == DateTimeType {
			tsFields = append(tsFields, tsApi.Field{
				Name:     ToSearchDateKey(f.Name()),
				Type:     toSearchFieldType(StringType, UnknownType),
				Facet:    &ptrFalse,
				Index:    &ptrFalse,
				Sort:     &ptrFalse,
				Optional: &ptrTrue,
			})
		}
	}

	s.StoreSchema = &tsApi.CollectionSchema{
		Name:   searchStoreName,
		Fields: tsFields,
	}
}

func (s *ImplicitSearchIndex) GetSearchDeltaFields(existingFields []*QueryableField, incomingFields []*Field) []tsApi.Field {
	ptrTrue := true

	incomingQueryable := NewQueryableFieldsBuilder().BuildQueryableFields(incomingFields, s.prevVersionInSearch)

	existingFieldMap := make(map[string]*QueryableField)
	for _, f := range existingFields {
		existingFieldMap[f.FieldName] = f
	}

	fieldsInSearchMap := make(map[string]tsApi.Field)
	for _, f := range s.prevVersionInSearch {
		fieldsInSearchMap[f.Name] = f
	}

	tsFields := make([]tsApi.Field, 0, len(incomingQueryable))
	for _, f := range incomingQueryable {
		e := existingFieldMap[f.FieldName]
		delete(existingFieldMap, f.FieldName)

		shouldIndex := SupportedSearchIndexableType(f.DataType, f.SubType)
		shouldFacet := DefaultFacetableType(f.DataType)
		shouldSort := DefaultSortableType(f.DataType)
		if !shouldSort && f.Sortable {
			shouldSort = true
		}
		if !shouldFacet && f.Faceted {
			shouldFacet = true
		}

		stateChanged := false
		if e != nil {
			inSearchState, found := fieldsInSearchMap[f.FieldName]
			if found && inSearchState.Index != nil && *inSearchState.Index != shouldIndex {
				stateChanged = true
			}
			if found && inSearchState.Facet != nil && *inSearchState.Facet != shouldFacet {
				stateChanged = true
			}
			if found && inSearchState.Sort != nil && *inSearchState.Sort != shouldSort {
				stateChanged = true
			}

			if !stateChanged {
				continue
			}
		}

		// attribute changed, drop the field first
		if e != nil && stateChanged {
			tsFields = append(tsFields, tsApi.Field{
				Name: f.FieldName,
				Drop: &ptrTrue,
			})
		} else {
			// this can happen if update request is timed out on Tigris side but succeed on search
			if _, found := fieldsInSearchMap[f.FieldName]; found {
				tsFields = append(tsFields, tsApi.Field{
					Name: f.FieldName,
					Drop: &ptrTrue,
				})
			}
		}

		// add new field
		tsFields = append(tsFields, tsApi.Field{
			Name:     f.FieldName,
			Type:     f.SearchType,
			Facet:    &shouldFacet,
			Index:    &shouldIndex,
			Sort:     &shouldSort,
			Optional: &ptrTrue,
		})
	}

	// drop fields non existing in new schema
	for _, f := range existingFieldMap {
		tsField := tsApi.Field{
			Name: f.FieldName,
			Drop: &ptrTrue,
		}

		tsFields = append(tsFields, tsField)
	}

	return tsFields
}

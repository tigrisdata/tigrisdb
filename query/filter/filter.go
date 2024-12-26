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

package filter

import (
	"bytes"
	"strings"

	"github.com/buger/jsonparser"
	jsoniter "github.com/json-iterator/go"
	api "github.com/tigrisdata/tigris/api/server/v1"
	"github.com/tigrisdata/tigris/errors"
	"github.com/tigrisdata/tigris/query/expression"
	"github.com/tigrisdata/tigris/schema"
	ulog "github.com/tigrisdata/tigris/util/log"
	"github.com/tigrisdata/tigris/value"
)

var (
	filterNone         = []byte(`{}`)
	emptyFilter        = &EmptyFilter{}
	wrappedEmptyFilter = &WrappedFilter{
		Filter:       emptyFilter,
		searchFilter: emptyFilter.ToSearchFilter(),
	}
)

// Filter 接口表示一个通用的查询过滤器，可以包含多种条件和逻辑操作。
// 支持 JSON 表示形式，例如：
// "filter: {\"f1\": 10}"
// "filter": [{"f1": 10}, {"f2": {"$gt": 10}}]
// 默认操作为 "$and"，默认选择器为 "$eq"。
type Filter interface {
	// Matches 判断输入的文档是否符合过滤条件
	Matches(doc []byte, metadata []byte) bool
	// MatchesDoc 判断已解析的文档是否符合过滤条件
	MatchesDoc(doc map[string]any) bool
	// ToSearchFilter 将过滤器转换为搜索条件的字符串
	ToSearchFilter() string
	// IsSearchIndexed 检查过滤条件中是否使用了搜索索引
	IsSearchIndexed() bool
}

// EmptyFilter 表示一个空过滤器，总是返回 true。
type EmptyFilter struct{}

func (*EmptyFilter) Matches(_ []byte, _ []byte) bool  { return true }
func (*EmptyFilter) MatchesDoc(_ map[string]any) bool { return true }
func (*EmptyFilter) ToSearchFilter() string           { return "" }
func (*EmptyFilter) IsSearchIndexed() bool            { return false }

// WrappedFilter 用于包装其他过滤器，并支持逻辑组合。
type WrappedFilter struct {
	Filter
	searchFilter string
}

// NewWrappedFilter 根据输入的过滤器数组创建一个 WrappedFilter。
func NewWrappedFilter(filters []Filter) *WrappedFilter {
	if len(filters) == 0 {
		return wrappedEmptyFilter
	} else if len(filters) <= 1 {
		return &WrappedFilter{
			Filter:       filters[0],
			searchFilter: filters[0].ToSearchFilter(),
		}
	}

	andFilter := &AndFilter{
		filter: filters,
	}

	return &WrappedFilter{
		Filter:       andFilter,
		searchFilter: andFilter.ToSearchFilter(),
	}
}

func (w *WrappedFilter) None() bool {
	return w.Filter == emptyFilter
}

func (w *WrappedFilter) SearchFilter() string {
	return w.searchFilter
}

func (w *WrappedFilter) IsSearchIndexed() bool {
	return w.Filter.IsSearchIndexed()
}

// Factory 是一个用于构建过滤器的工厂。
type Factory struct {
	fields                 []*schema.QueryableField
	collation              *value.Collation
	buildForSecondaryIndex bool
}

// NewFactory 创建一个新的过滤器工厂。
func NewFactory(fields []*schema.QueryableField, collation *value.Collation) *Factory {
	return &Factory{
		fields:                 fields,
		collation:              collation,
		buildForSecondaryIndex: false,
	}
}

// NewFactoryForSecondaryIndex 创建一个用于二级索引的过滤器工厂。
func NewFactoryForSecondaryIndex(fields []*schema.QueryableField) *Factory {
	return &Factory{
		fields:                 fields,
		collation:              value.NewSortKeyCollation(),
		buildForSecondaryIndex: true,
	}
}

// WrappedFilter 根据请求的 JSON 过滤器生成 WrappedFilter。
func (factory *Factory) WrappedFilter(reqFilter []byte) (*WrappedFilter, error) {
	filters, err := factory.Factorize(reqFilter)
	if err != nil {
		return nil, err
	}

	return NewWrappedFilter(filters), nil
}

// Factorize 将 JSON 过滤器解析为过滤器数组。
func (factory *Factory) Factorize(reqFilter []byte) ([]Filter, error) {
	if len(reqFilter) == 0 {
		return nil, nil
	}

	var filters []Filter
	var err error
	// 遍历 JSON 对象的每个键值对
	err = jsonparser.ObjectEach(reqFilter, func(k []byte, v []byte, jsonDataType jsonparser.ValueType, offset int) error {
		if err != nil {
			return err
		}

		var filter Filter
		switch string(k) {
		case string(AndOP):
			filter, err = factory.UnmarshalAnd(v)
		case string(OrOP):
			filter, err = factory.UnmarshalOr(v)
		default:
			filter, err = factory.ParseSelector(k, v, jsonDataType)
		}
		if err != nil {
			return err
		}
		filters = append(filters, filter)

		return nil
	})
	if err != nil {
		return nil, err
	}

	return filters, nil
}
// UnmarshalFilter 递归解析 JSON 并构造过滤器。
func (factory *Factory) UnmarshalFilter(input jsoniter.RawMessage) (Filter, error) {
	var err error
	var filter Filter

	// 遍历 JSON 对象并解析过滤器
	err = jsonparser.ObjectEach(input, func(k []byte, v []byte, dt jsonparser.ValueType, offset int) error {
		if err != nil {
			return err
		}

		switch string(k) {
		case string(AndOP):
			filter, err = factory.UnmarshalAnd(v)
		case string(OrOP):
			filter, err = factory.UnmarshalOr(v)
		default:
			filter, err = factory.ParseSelector(k, v, dt)
		}
		return nil
	})

	if err != nil {
		return nil, err
	}

	return filter, nil
}

// UnmarshalAnd 解析 AND 类型的过滤器。
func (factory *Factory) UnmarshalAnd(input jsoniter.RawMessage) (Filter, error) {
	filters, err := factory.convertExprListToFilters(input)
	if err != nil {
		return nil, err
	}
	return &AndFilter{filter: filters}, nil
}

// UnmarshalOr 解析 OR 类型的过滤器。
func (factory *Factory) UnmarshalOr(input jsoniter.RawMessage) (Filter, error) {
	filters, err := factory.convertExprListToFilters(input)
	if err != nil {
		return nil, err
	}
	return &OrFilter{filter: filters}, nil
}

// convertExprListToFilters 将表达式列表转换为过滤器列表。
func (factory *Factory) convertExprListToFilters(input jsoniter.RawMessage) ([]Filter, error) {
	var filters []Filter
	var err error

	_, err = jsonparser.ArrayEach(input, func(value []byte, dataType jsonparser.ValueType, offset int, errInner error) {
		if err != nil {
			return
		}

		var filter Filter
		filter, err = factory.UnmarshalFilter(value)
		if err != nil {
			return
		}
		filters = append(filters, filter)
	})

	if err != nil {
		return nil, err
	}

	return filters, nil
}

// filterToQueryableField 根据过滤字段名称获取可查询字段。
func (factory *Factory) filterToQueryableField(filterField string) (*schema.QueryableField, *schema.QueryableField) {
	for _, field := range factory.fields {
		if field.FieldName == filterField {
			return field, nil
		}

		if field.DataType == schema.ObjectType || field.DataType == schema.ArrayType {
			for _, subField := range field.Fields {
				if subField.FieldName == filterField {
					return subField, field
				}
			}
		}
	}
	return nil, nil
}

// ParseSelector 解析单一字段选择器过滤器。
func (factory *Factory) ParseSelector(k []byte, v []byte, dataType jsonparser.ValueType) (Filter, error) {
	filterField := string(k)
	field, parent := factory.filterToQueryableField(filterField)
	if field == nil {
		// 检查字段是否在 schema 中定义
		idx := strings.LastIndex(filterField, ".")
		if idx <= 0 {
			return nil, errors.InvalidArgument("querying on non schema field '%s'", string(k))
		}

		if field, parent = factory.filterToQueryableField(filterField[0:idx]); field == nil && parent == nil {
			return nil, errors.InvalidArgument("querying on non schema field '%s'", string(k))
		}

		parent = field
		field = schema.NewDynamicQueryableField(filterField, filterField[idx+1:], schema.UnknownType)
	}

	switch dataType {
	case jsonparser.Boolean, jsonparser.Number, jsonparser.String, jsonparser.Array, jsonparser.Null:
		tigrisType := toTigrisType(field, dataType)

		if dataType == jsonparser.Null {
			v = nil // 将 null 映射为 nil
		}

		var val value.Value
		var err error
		if factory.collation != nil {
			val, err = value.NewValueUsingCollation(tigrisType, v, factory.collation)
		} else {
			val, err = value.NewValue(tigrisType, v)
		}
		if err != nil {
			return nil, err
		}

		return NewSelector(parent, field, NewEqualityMatcher(val), factory.collation), nil
	case jsonparser.Object:
		valueMatcher, likeMatcher, collation, err := buildValueMatcher(v, field, factory.collation, factory.buildForSecondaryIndex)
		if err != nil {
			return nil, err
		}
		if likeMatcher != nil {
			return NewLikeFilter(field, likeMatcher), nil
		}

		if collation != nil {
			return NewSelector(parent, field, valueMatcher, collation), nil
		}
		return NewSelector(parent, field, valueMatcher, factory.collation), nil
	default:
		return nil, errors.InvalidArgument("unable to parse the comparison operator")
	}
}

// buildValueMatcher 构建用于匹配值的匹配器对象。
func buildValueMatcher(input jsoniter.RawMessage, field *schema.QueryableField, factoryCollation *value.Collation, buildForSecondaryIndex bool) (ValueMatcher, LikeMatcher, *value.Collation, error) {
	if len(input) == 0 {
		return nil, nil, nil, errors.InvalidArgument("empty object")
	}

	var (
		valueMatcher ValueMatcher
		likeMatcher  LikeMatcher
		collation    *value.Collation
		err          error
	)
	if collation, err = buildCollation(input, factoryCollation, buildForSecondaryIndex); err != nil {
		return nil, nil, nil, err
	}

	err = jsonparser.ObjectEach(input, func(key []byte, v []byte, dataType jsonparser.ValueType, offset int) error {
		if err != nil {
			return err
		}

		switch string(key) {
		case EQ, GT, GTE, LT, LTE:
			switch dataType {
			case jsonparser.Boolean, jsonparser.Number, jsonparser.String, jsonparser.Null, jsonparser.Array:
				tigrisType := toTigrisType(field, dataType)

				var val value.Value
				if buildForSecondaryIndex {
					val, err = value.NewValueUsingCollation(tigrisType, v, factoryCollation)
				} else if collation != nil {
					val, err = value.NewValueUsingCollation(tigrisType, v, collation)
				} else {
					val, err = value.NewValue(tigrisType, v)
				}
				if err != nil {
					return err
				}

				valueMatcher, err = NewMatcher(string(key), val)
				return err
			}
		case REGEX, CONTAINS, NOT:
			if dataType != jsonparser.String {
				return errors.InvalidArgument("string is only supported type for 'regex/contains/not' filters")
			}
			if !(field.DataType == schema.StringType || (field.DataType == schema.ArrayType && field.SubType == schema.StringType)) {
				return errors.InvalidArgument("field '%s' of type '%s' is not supported for 'regex/contains/not' filters. Only 'string' or an 'array of string' is supported", field.FieldName, schema.FieldNames[field.DataType])
			}

			likeMatcher, err = NewLikeMatcher(string(key), string(v), collation)
			return err
		case api.CollationKey:
		default:
			return errors.InvalidArgument("expression is not supported inside comparison operator %s", string(key))
		}
		return nil
	})

	return valueMatcher, likeMatcher, collation, err
}

// buildCollation 构建排序规则。
func buildCollation(input jsoniter.RawMessage, factoryCollation *value.Collation, buildForSecondaryIndex bool) (*value.Collation, error) {
	c, dt, _, _ := jsonparser.Get(input, api.CollationKey)
	if dt == jsonparser.NotExist {
		return factoryCollation, nil
	}

	var (
		err          error
		apiCollation *api.Collation
	)
	if err = jsoniter.Unmarshal(c, &apiCollation); err != nil {
		return nil, err
	}
	if err = apiCollation.IsValid(); err != nil {
		return nil, err
	}

	collation := value.NewCollationFrom(apiCollation)
	if buildForSecondaryIndex && collation.IsCaseInsensitive() {
		return nil, errors.InvalidArgument("found case insensitive collation")
	}

	return collation, nil
}

// toTigrisType 将 JSON 类型转换为 Tigris 数据类型。
func toTigrisType(field *schema.QueryableField, jsonType jsonparser.ValueType) schema.FieldType {
	switch field.DataType {
	case schema.ArrayType:
		if jsonType != jsonparser.Array && !(field.SubType == schema.ArrayType || field.SubType == schema.ObjectType) {
			return field.SubType
		}
		return jsonToTigrisType(jsonType)
	case schema.UnknownType:
		field.DataType = jsonToTigrisType(jsonType)
	}

	return field.DataType
}

// jsonToTigrisType 将 JSON 数据类型映射为 Tigris 数据类型。
func jsonToTigrisType(jsonType jsonparser.ValueType) schema.FieldType {
	switch jsonType {
	case jsonparser.Boolean:
		return schema.BoolType
	case jsonparser.String:
		return schema.StringType
	case jsonparser.Number:
		return schema.DoubleType
	case jsonparser.Array:
		return schema.ArrayType
	case jsonparser.Null:
		return schema.NullType
	}

	return schema.UnknownType
}


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
	"fmt"
	"regexp"
	"strings"

	"github.com/tigrisdata/tigris/errors"
	"github.com/tigrisdata/tigris/value"
)

const (
	EQ       = "$eq"
	NE       = "$ne"
	GT       = "$gt"
	LT       = "$lt"
	GTE      = "$gte"
	LTE      = "$lte"
	NOT      = "$not"
	REGEX    = "$regex"
	CONTAINS = "$contains"
)

type Matcher interface {
	// Type return the type of the value matcher, syntactic sugar for logging, etc
	Type() string
}

type LikeMatcher interface {
	Matcher

	Matches(docValue any) bool
}

// ValueMatcher is an interface that has method like Matches.
type ValueMatcher interface {
	Matcher

	// Matches returns true if the receiver has the value object that has the same value as input
	Matches(input value.Value) bool
	// GetValue returns the value on which the Matcher is operating
	GetValue() value.Value
}

// NewMatcher returns ValueMatcher that is derived from the key.
func NewMatcher(key string, v value.Value) (ValueMatcher, error) {
	switch key {
	case EQ:
		return &EqualityMatcher{
			Value: v,
		}, nil
	case NE:
		return &NotEqualMatcher{
			Value: v,
		}, nil
	case GT:
		return &GreaterThanMatcher{
			Value: v,
		}, nil
	case GTE:
		return &GreaterThanEqMatcher{
			Value: v,
		}, nil
	case LT:
		return &LessThanMatcher{
			Value: v,
		}, nil
	case LTE:
		return &LessThanEqMatcher{
			Value: v,
		}, nil
	default:
		return nil, errors.InvalidArgument("unsupported operand '%s'", key)
	}
}

func NewLikeMatcher(key string, input string, collation *value.Collation) (LikeMatcher, error) {
	if collation == nil {
		collation = value.EmptyCollation
	}

	switch key {
	case REGEX:
		return NewRegexMatcher(input, collation)
	case CONTAINS:
		return NewContainsMatcher(input, collation)
	case NOT:
		return NewNotMatcher(input, collation)
	default:
		return nil, errors.InvalidArgument("unsupported operand '%s'", key)
	}
}

// EqualityMatcher implements "$eq" operand.
type EqualityMatcher struct {
	Value value.Value
}

// NewEqualityMatcher returns EqualityMatcher object.
func NewEqualityMatcher(v value.Value) *EqualityMatcher {
	return &EqualityMatcher{
		Value: v,
	}
}

func (e *EqualityMatcher) GetValue() value.Value {
	return e.Value
}

func (e *EqualityMatcher) Matches(input value.Value) bool {
	res, _ := input.CompareTo(e.Value)
	return res == 0
}

func (e *EqualityMatcher) Type() string {
	return "$eq"
}

func (e *EqualityMatcher) String() string {
	return fmt.Sprintf("{$eq:%v}", e.Value)
}

// NotEqMatcher implements "$ne" operand.
type NotEqMatcher struct {
	Value value.Value
}

// NotEqualMatcher implements "$ne" operand.
func (n *NotEqMatcher) GetValue() value.Value {
	return n.Value
}

func (n *NotEqMatcher) Matches(input value.Value) bool {
	res, _ := input.CompareTo(n.Value)
	return res != 0
}

func (n *NotEqMatcher) Type() string {
	return "$ne"
}

func (n *NotEqMatcher) String() string {
	return fmt.Sprintf("{$ne:%v}", n.Value)
}

// GreaterThanMatcher implements "$gt" operand.
type GreaterThanMatcher struct {
	Value value.Value
}

func (g *GreaterThanMatcher) GetValue() value.Value {
	return g.Value
}

func (g *GreaterThanMatcher) Matches(input value.Value) bool {
	res, _ := input.CompareTo(g.Value)
	return res > 0
}

func (g *GreaterThanMatcher) Type() string {
	return "$gt"
}

func (g *GreaterThanMatcher) String() string {
	return fmt.Sprintf("{$gt:%v}", g.Value)
}

// GreaterThanEqMatcher implements "$gte" operand.
type GreaterThanEqMatcher struct {
	Value value.Value
}

func (g *GreaterThanEqMatcher) GetValue() value.Value {
	return g.Value
}

func (g *GreaterThanEqMatcher) Matches(input value.Value) bool {
	res, _ := input.CompareTo(g.Value)
	return res >= 0
}

func (g *GreaterThanEqMatcher) Type() string {
	return "$gte"
}

func (g *GreaterThanEqMatcher) String() string {
	return fmt.Sprintf("{$gte:%v}", g.Value)
}

// LessThanMatcher implements "$lt" operand.
type LessThanMatcher struct {
	Value value.Value
}

func (l *LessThanMatcher) GetValue() value.Value {
	return l.Value
}

func (l *LessThanMatcher) Matches(input value.Value) bool {
	res, _ := input.CompareTo(l.Value)
	return res < 0
}

func (l *LessThanMatcher) Type() string {
	return "$lt"
}

func (l *LessThanMatcher) String() string {
	return fmt.Sprintf("{$lt:%v}", l.Value)
}

// LessThanEqMatcher implements "$lte" operand.
type LessThanEqMatcher struct {
	Value value.Value
}

func (l *LessThanEqMatcher) GetValue() value.Value {
	return l.Value
}

func (l *LessThanEqMatcher) Matches(input value.Value) bool {
	res, _ := input.CompareTo(l.Value)
	return res <= 0
}

func (l *LessThanEqMatcher) Type() string {
	return "$lte"
}

func (l *LessThanEqMatcher) String() string {
	return fmt.Sprintf("{$lte:%v}", l.Value)
}

// RegexMatcher implements "$regex" operand.
// When matching against text, the regexp returns a match that
// begins as early as possible in the input (leftmost), and among those
// it chooses the one that a backtracking search would have found first.
// This so-called leftmost-first matching is the same semantics
// that Perl, Python, and other implementations use.
type RegexMatcher struct {
	regex     *regexp.Regexp
	collation *value.Collation
}

func NewRegexMatcher(value string, collation *value.Collation) (LikeMatcher, error) {
	regexp, err := regexp.Compile(value)
	if err != nil {
		return nil, err
	}

	return &RegexMatcher{
		regex:     regexp,
		collation: collation,
	}, nil
}

func (c *RegexMatcher) Matches(docValue any) bool {
	switch dv := docValue.(type) {
	case string:
		return c.regex.MatchString(dv)
	case []string:
		for _, e := range dv {
			if c.regex.MatchString(e) {
				return true
			}
		}
	case []byte:
		return c.regex.Match(dv)
	}
	return false
}

func (c *RegexMatcher) Type() string {
	return "$regex"
}

func (c *RegexMatcher) String() string {
	return fmt.Sprintf("{regex:%v}", c.regex.String())
}

// ContainsMatcher implements "$contains" operand.
type ContainsMatcher struct {
	value     string
	collation *value.Collation
}

func NewContainsMatcher(value string, collation *value.Collation) (LikeMatcher, error) {
	return &ContainsMatcher{
		value:     value,
		collation: collation,
	}, nil
}

func (c *ContainsMatcher) Matches(docValue any) bool {
	switch dv := docValue.(type) {
	case string:
		return StringContains(dv, c.value, c.collation)
	case []string:
		for _, e := range dv {
			if StringContains(e, c.value, c.collation) {
				return true
			}
		}
	case []byte:
		if c.collation.IsCaseInsensitive() {
			return bytes.Contains(bytes.ToLower(dv), bytes.ToLower([]byte(c.value)))
		}
		return bytes.Contains(dv, []byte(c.value))
	}
	return false
}

func (c *ContainsMatcher) Type() string {
	return "$contains"
}

func (c *ContainsMatcher) String() string {
	return fmt.Sprintf("{$contains:%v}", c.value)
}

// NotMatcher implements "$not" operand.
type NotMatcher struct {
	value     string
	collation *value.Collation
}

func NewNotMatcher(value string, collation *value.Collation) (LikeMatcher, error) {
	return &NotMatcher{
		value:     value,
		collation: collation,
	}, nil
}

func (n *NotMatcher) Matches(docValue any) bool {
	switch dv := docValue.(type) {
	case string:
		return !StringContains(dv, n.value, n.collation)
	case []string:
		for _, e := range dv {
			if StringContains(e, n.value, n.collation) {
				return false
			}
		}
		return true
	case []byte:
		if n.collation.IsCaseInsensitive() {
			return !bytes.Contains(bytes.ToLower(dv), bytes.ToLower([]byte(n.value)))
		}
		return !bytes.Contains(dv, []byte(n.value))
	}
	return false
}

func (n *NotMatcher) Type() string {
	return "$not"
}

func (n *NotMatcher) String() string {
	return fmt.Sprintf("{$not:%v}", n.value)
}

func StringContains(s string, substr string, collation *value.Collation) bool {
	if collation.IsCaseInsensitive() {
		return strings.Contains(strings.ToLower(s), strings.ToLower(substr))
	}
	return strings.Contains(s, substr)
}

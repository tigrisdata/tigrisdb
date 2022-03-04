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

//go:build integration

package server

import (
	"bytes"
	"encoding/json"
	"fmt"
	"net/http"

	"github.com/stretchr/testify/require"
	"github.com/stretchr/testify/suite"
	"github.com/tigrisdata/tigrisdb/test/config"
	"gopkg.in/gavv/httpexpect.v1"
)

type DocumentSuite struct {
	suite.Suite

	collection string
	database   string
}

func getDocumentURL(databaseName, collectionName string, methodName string) string {
	return fmt.Sprintf("/api/v1/databases/%s/collections/%s/documents/%s", databaseName, collectionName, methodName)
}

func (s *DocumentSuite) SetupSuite() {
	createDatabase(s.T(), s.database)
	createCollection(s.T(), s.database, s.collection, testCreateSchema)
}

func (s *DocumentSuite) TearDownSuite() {
	dropDatabase(s.T(), s.database)
}

func (s *DocumentSuite) TestInsert_BadRequest() {
	cases := []struct {
		databaseName   string
		collectionName string
		documents      []interface{}
		expMessage     string
	}{
		{
			"random_database1",
			s.collection,
			[]interface{}{
				map[string]interface{}{
					"pkey_int": 1,
				},
			},
			"database doesn't exists 'random_database1'",
		}, {
			s.database,
			"random_collection",
			[]interface{}{
				map[string]interface{}{
					"pkey_int": 1,
				},
			},
			"collection doesn't exists 'random_collection'",
		}, {
			"",
			s.collection,
			[]interface{}{
				map[string]interface{}{
					"pkey_int": 1,
				},
			},
			"invalid database name",
		}, {
			s.database,
			"",
			[]interface{}{
				map[string]interface{}{
					"pkey_int": 1,
				},
			},
			"invalid collection name",
		}, {
			s.database,
			s.collection,
			[]interface{}{},
			"empty documents received",
		},
	}
	for _, c := range cases {
		e := httpexpect.New(s.T(), config.GetBaseURL())
		e.POST(getDocumentURL(c.databaseName, c.collectionName, "insert")).
			WithJSON(map[string]interface{}{
				"documents": c.documents,
			}).
			Expect().
			Status(http.StatusBadRequest).
			JSON().
			Object().
			ValueEqual("message", c.expMessage)
	}
}

func (s *DocumentSuite) TestInsert_AlreadyExists() {
	inputDocument := []interface{}{
		map[string]interface{}{
			"pkey_int":     2,
			"int_value":    10,
			"string_value": "simple_insert",
			"bool_value":   true,
			"double_value": 10.01,
			"bytes_value":  []byte(`"simple_insert"`),
		},
	}

	e := httpexpect.New(s.T(), config.GetBaseURL())
	e.POST(getDocumentURL(s.database, s.collection, "insert")).
		WithJSON(map[string]interface{}{
			"documents": inputDocument,
		}).
		Expect().
		Status(http.StatusOK).
		JSON().
		Object().
		Empty()

	e.POST(getDocumentURL(s.database, s.collection, "insert")).
		WithJSON(map[string]interface{}{
			"documents": inputDocument,
		}).
		Expect().
		Status(http.StatusConflict).
		JSON().
		Object().
		ValueEqual("message", "row already exists")
}

func (s *DocumentSuite) TestInsert_SingleRow() {
	inputDocument := []interface{}{
		map[string]interface{}{
			"pkey_int":     10,
			"int_value":    10,
			"string_value": "simple_insert",
			"bool_value":   true,
			"double_value": 10.01,
			"bytes_value":  []byte(`"simple_insert"`),
		},
	}

	e := httpexpect.New(s.T(), config.GetBaseURL())
	e.POST(getDocumentURL(s.database, s.collection, "insert")).
		WithJSON(map[string]interface{}{
			"documents": inputDocument,
		}).
		Expect().
		Status(http.StatusOK).
		JSON().
		Object().
		Empty()

	readResp := s.readByFilter(map[string]interface{}{
		"pkey_int": 10,
	})

	var doc map[string]json.RawMessage
	require.NoError(s.T(), json.Unmarshal(readResp[0]["result"], &doc))

	var actualDoc = []byte(doc["doc"])
	expDoc, err := json.Marshal(inputDocument[0])
	require.NoError(s.T(), err)
	require.Equal(s.T(), expDoc, actualDoc)
}

func (s *DocumentSuite) TestInsert_MultipleRows() {
	inputDocument := []interface{}{
		map[string]interface{}{
			"pkey_int":     20,
			"int_value":    20,
			"string_value": "simple_insert1",
			"bool_value":   true,
			"double_value": 20.00001,
			"bytes_value":  []byte(`"simple_insert1"`),
		},
		map[string]interface{}{
			"pkey_int":     30,
			"int_value":    30,
			"string_value": "simple_insert2",
			"bool_value":   false,
			"double_value": 20.0002,
			"bytes_value":  []byte(`"simple_insert2"`),
		},
	}

	e := httpexpect.New(s.T(), config.GetBaseURL())
	e.POST(getDocumentURL(s.database, s.collection, "insert")).
		WithJSON(map[string]interface{}{
			"documents": inputDocument,
		}).
		Expect().
		Status(http.StatusOK).
		JSON().
		Object().
		Empty()

	readResp := s.readByFilter(map[string]interface{}{
		"$or": []interface{}{
			map[string]interface{}{
				"pkey_int": 20,
			},
			map[string]interface{}{
				"pkey_int": 30,
			},
		},
	})

	require.Equal(s.T(), 2, len(readResp))
	for i := 0; i < len(inputDocument); i++ {
		var doc map[string]json.RawMessage
		require.NoError(s.T(), json.Unmarshal(readResp[i]["result"], &doc))

		var actualDoc = []byte(doc["doc"])
		expDoc, err := json.Marshal(inputDocument[i])
		require.NoError(s.T(), err)
		require.Equal(s.T(), expDoc, actualDoc)
	}
}

func (s *DocumentSuite) readByFilter(filter map[string]interface{}) []map[string]json.RawMessage {
	e := httpexpect.New(s.T(), config.GetBaseURL())
	str := e.POST(getDocumentURL(s.database, s.collection, "read")).
		WithJSON(map[string]interface{}{
			"filter": filter,
		}).
		Expect().
		Status(http.StatusOK).
		Body().
		Raw()

	var resp []map[string]json.RawMessage
	dec := json.NewDecoder(bytes.NewReader([]byte(str)))
	for dec.More() {
		var mp map[string]json.RawMessage
		require.NoError(s.T(), dec.Decode(&mp))
		resp = append(resp, mp)
	}

	s.T().Logf("read response %s", str)
	return resp
}

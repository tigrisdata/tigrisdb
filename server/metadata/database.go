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
	"strings"

	jsoniter "github.com/json-iterator/go"
	"github.com/rs/zerolog/log"
	"github.com/tigrisdata/tigris/errors"
	"github.com/tigrisdata/tigris/internal"
	"github.com/tigrisdata/tigris/keys"
	"github.com/tigrisdata/tigris/schema"
	"github.com/tigrisdata/tigris/server/transaction"
	ulog "github.com/tigrisdata/tigris/util/log"
)

const (
	MainBranch          = "main"
	BranchNameSeparator = "_$branch$_"
)

// DatabaseMetadata contains database wide metadata.
type DatabaseMetadata struct {
	ID uint32 `json:"id,omitempty"`

	SchemaVersion    uint32 `json:"schema_version"`
	MinSchemaVersion uint32 `json:"min_schema_version"` // explicit version less than this value will be rejected
}

// DatabaseName represents a primary database and its branch name.
type DatabaseName struct {
	db     string
	branch string
}

func NewDatabaseNameWithBranch(db string, branch string) *DatabaseName {
	if branch == MainBranch {
		branch = ""
	}
	return &DatabaseName{
		db:     db,
		branch: branch,
	}
}

func NewDatabaseName(key string) *DatabaseName {
	s := strings.Split(key, BranchNameSeparator)
	if len(s) < 2 {
		return NewDatabaseNameWithBranch(s[0], "")
	}
	return NewDatabaseNameWithBranch(s[0], s[1])
}

// Name returns the internal name of the database
// db with name "catalog" and branch "main" will have internal name as "catalog"
// db with name "catalog" and branch "feature" will have internal name as "catalog_$branch$_feature".
func (b *DatabaseName) Name() string {
	if b.IsMainBranch() {
		return b.Db()
	}

	return b.Db() + BranchNameSeparator + b.Branch()
}

// Db is the user facing name of the primary database.
func (b *DatabaseName) Db() string {
	return b.db
}

// Branch belonging to Db.
func (b *DatabaseName) Branch() string {
	if b.IsMainBranch() {
		return MainBranch
	}

	return b.branch
}

// IsMainBranch returns "True" if this is primary Db or "False" if a branch.
func (b *DatabaseName) IsMainBranch() bool {
	return len(b.branch) == 0 || b.branch == MainBranch
}

// DatabaseSubspace is used to store metadata about Tigris databases.
type DatabaseSubspace struct {
	metadataSubspace
}

const dbMetaValueVersion int32 = 1

func newDatabaseStore(nameRegistry *NameRegistry) *DatabaseSubspace {
	return &DatabaseSubspace{
		metadataSubspace{
			SubspaceName: nameRegistry.EncodingSubspaceName(),
			KeyVersion:   []byte{encKeyVersion},
		},
	}
}

func (d *DatabaseSubspace) getKey(nsID uint32, name string) keys.Key {
	if name == "" {
		return keys.NewKey(d.SubspaceName, d.KeyVersion, UInt32ToByte(nsID), dbKey)
	}

	return keys.NewKey(d.SubspaceName, d.KeyVersion, UInt32ToByte(nsID), dbKey, name, keyEnd)
}

func (d *DatabaseSubspace) insert(ctx context.Context, tx transaction.Tx, nsID uint32, name string, metadata *DatabaseMetadata) error {
	return d.insertMetadata(ctx, tx,
		d.validateArgs(nsID, name, &metadata),
		d.getKey(nsID, name),
		dbMetaValueVersion,
		metadata,
	)
}

func (_ *DatabaseSubspace) decodeMetadata(_ string, payload *internal.TableData) (*DatabaseMetadata, error) {
	if payload == nil {
		return nil, errors.ErrNotFound
	}

	// Handle legacy metadata, which only contains database id.
	if payload.Ver == 0 {
		return &DatabaseMetadata{ID: ByteToUInt32(payload.RawData)}, nil
	}

	// Handle new JSON encoded metadata
	var metadata DatabaseMetadata
	if err := jsoniter.Unmarshal(payload.RawData, &metadata); ulog.E(err) {
		return nil, errors.Internal("failed to unmarshal database metadata")
	}

	return &metadata, nil
}

func (d *DatabaseSubspace) Get(ctx context.Context, tx transaction.Tx, nsID uint32, name string) (*DatabaseMetadata, error) {
	payload, err := d.getPayload(ctx, tx,
		d.validateArgs(nsID, name, nil),
		d.getKey(nsID, name),
	)
	if err != nil {
		return nil, err
	}

	return d.decodeMetadata(name, payload)
}

func (d *DatabaseSubspace) Update(ctx context.Context, tx transaction.Tx, nsID uint32, name string, metadata *DatabaseMetadata) error {
	return d.updateMetadata(ctx, tx,
		d.validateArgs(nsID, name, &metadata),
		d.getKey(nsID, name),
		dbMetaValueVersion,
		metadata,
	)
}

func (d *DatabaseSubspace) delete(ctx context.Context, tx transaction.Tx, nsID uint32, name string) error {
	return d.deleteMetadata(ctx, tx,
		d.validateArgs(nsID, name, nil),
		d.getKey(nsID, name),
	)
}

func (d *DatabaseSubspace) softDelete(ctx context.Context, tx transaction.Tx, nsID uint32, name string) error {
	newKey := keys.NewKey(d.SubspaceName, d.KeyVersion, UInt32ToByte(nsID), dbKey, name, keyDroppedEnd)

	return d.softDeleteMetadata(ctx, tx,
		d.validateArgs(nsID, name, nil),
		d.getKey(nsID, name),
		newKey,
	)
}

func (d *DatabaseSubspace) validateArgs(nsID uint32, name string, metadata **DatabaseMetadata) error {
	if nsID == 0 {
		return errors.InvalidArgument("invalid id")
	}

	if name == "" {
		return errors.InvalidArgument("database name is empty")
	}

	if metadata != nil && *metadata == nil {
		return errors.InvalidArgument("invalid nil payload")
	}

	return nil
}

func (d *DatabaseSubspace) list(ctx context.Context, tx transaction.Tx, namespaceId uint32,
) (map[string]*DatabaseMetadata, error) {
	databases := make(map[string]*DatabaseMetadata)
	droppedDatabases := make(map[string]uint32)

	if err := d.listMetadata(ctx, tx, d.getKey(namespaceId, ""), 5,
		func(dropped bool, name string, data *internal.TableData) error {
			m, err := d.decodeMetadata(name, data)
			if err != nil {
				return err
			}

			if dropped {
				droppedDatabases[name] = m.ID
			} else {
				databases[name] = m
			}

			return nil
		},
	); err != nil {
		return nil, err
	}

	// retrogression check; if created and dropped both exists then the created id should be greater than dropped id
	log.Debug().Interface("list", droppedDatabases).Msg("dropped databases")
	log.Debug().Interface("list", databases).Msg("created databases")

	for droppedDB, droppedValue := range droppedDatabases {
		if createdValue, ok := databases[droppedDB]; ok && droppedValue >= createdValue.ID {
			return nil, errors.Internal(
				"retrogression found in database assigned value database [%s] droppedValue [%d] createdValue [%d]",
				droppedDB, droppedValue, createdValue.ID)
		}
	}

	return databases, nil
}

func getMaxSchemaVersion(ctx context.Context, metaStore *Dictionary, tx transaction.Tx, nsID uint32, db *Database) (uint32, error) {
	var maxVer uint32

	for _, coll := range db.ListCollection() {
		sch, err := metaStore.Schema().GetLatest(ctx, tx, nsID, db.Id(), coll.Id)
		if err != nil {
			return 0, err
		}

		if sch.Version > maxVer {
			maxVer = sch.Version
		}
	}

	return maxVer, nil
}

func UpdateSchemaVersion(ctx context.Context, metaStore *Dictionary, tx transaction.Tx, nsID uint32, db *Database,
	schFactory *schema.Factory,
) error {
	if db.PendingSchemaVersion == 0 { // this is first create or update collection in the transaction
		dbMeta, err := metaStore.Database().Get(ctx, tx, nsID, db.Name())
		if err != nil {
			if err != errors.ErrNotFound {
				return errors.Internal("failed to read database metadata")
			}
			dbMeta = &DatabaseMetadata{}
		}

		curSchemaVersion := dbMeta.SchemaVersion

		// we know the schema version or user want to start versioning
		if dbMeta.SchemaVersion != 0 || schFactory.Version != 0 {
			switch {
			case dbMeta.SchemaVersion == 0:
				// start db schema versioning from the first version we see from the user
				maxVer, err := getMaxSchemaVersion(ctx, metaStore, tx, nsID, db)
				if err != nil {
					return err
				}

				// first database schema version should be greater than all existing individual collection versions
				if schFactory.Version <= maxVer {
					return errors.InvalidArgument("next schema version should be %d", maxVer+1)
				}

				dbMeta.SchemaVersion = schFactory.Version
				dbMeta.MinSchemaVersion = schFactory.Version
			case dbMeta.MinSchemaVersion > schFactory.Version:
				return errors.InvalidArgument("schema version cannot be less than %d", dbMeta.MinSchemaVersion)
			case dbMeta.SchemaVersion+1 < schFactory.Version:
				// if db schema version already set, ensure it's sequential
				return errors.InvalidArgument("next schema version should be %v", dbMeta.SchemaVersion+1)
			case dbMeta.SchemaVersion+1 == schFactory.Version:
				dbMeta.SchemaVersion += 1
			}

			db.PendingSchemaVersion = dbMeta.SchemaVersion
			db.CurrentSchemaVersion = curSchemaVersion // this is used to validate collection schema against in create collection

			if err = metaStore.Database().Update(ctx, tx, nsID, db.Name(), dbMeta); err != nil {
				return errors.Internal("failed to update database metadata")
			}
		}
	} else if schFactory.Version != db.PendingSchemaVersion { // subsequent requests should have the same schema version as the first one
		return errors.InvalidArgument("collection schema version should be the same in the transaction. got %v expected %v", schFactory.Version, db.PendingSchemaVersion)
	}

	return nil
}

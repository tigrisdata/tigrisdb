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

package metrics

import (
	"io"
	"time"

	prom "github.com/m3db/prometheus_client_golang/prometheus"
	"github.com/rs/zerolog/log"
	"github.com/tigrisdata/tigris/server/config"
	"github.com/tigrisdata/tigris/util"
	"github.com/uber-go/tally"
	promreporter "github.com/uber-go/tally/prometheus"
)

var (
	root           tally.Scope
	Reporter       promreporter.Reporter
	Requests       tally.Scope
	FdbMetrics     tally.Scope
	SearchMetrics  tally.Scope
	SessionMetrics tally.Scope
	SizeMetrics    tally.Scope
	NetworkMetrics tally.Scope
)

func GetGlobalTags() map[string]string {
	res := map[string]string{
		"service": util.Service,
		"env":     config.GetEnvironment(),
	}
	if res["version"] = util.Version; res["version"] == "" {
		res["version"] = "dev"
	}
	return res
}

func InitializeMetrics() io.Closer {
	var closer io.Closer
	log.Debug().Msg("Initializing metrics")
	registry := prom.NewRegistry()
	Reporter = promreporter.NewReporter(promreporter.Options{Registerer: registry})
	root, closer = tally.NewRootScope(tally.ScopeOptions{
		Tags:           GetGlobalTags(),
		CachedReporter: Reporter,
		// Panics with .
		Separator: promreporter.DefaultSeparator,
	}, 1*time.Second)
	if config.DefaultConfig.Tracing.Enabled {
		// Request level metrics (HTTP and GRPC)
		Requests = root.SubScope("requests")
		initializeRequestScopes()
		// FDB level metrics
		FdbMetrics = root.SubScope("fdb")
		initializeFdbScopes()
		// Search level metrics
		SearchMetrics = root.SubScope("search")
		initializeSearchScopes()
		// Session level metrics
		SessionMetrics = root.SubScope("session")
		initializeSessionScopes()
		// Size metrics
		SizeMetrics = root.SubScope("size")
		initializeSizeScopes()
		// Network netrics
		NetworkMetrics = root.SubScope("net")
		initializeNetorkScopes()
	}
	return closer
}

package apiserver

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"strings"
	"testing"

	logtest "github.com/sirupsen/logrus/hooks/test"
	"github.com/stretchr/testify/require"

	"github.com/crowdsecurity/crowdsec/pkg/csconfig"
	"github.com/crowdsecurity/crowdsec/pkg/database/ent"
	"github.com/crowdsecurity/crowdsec/pkg/types"
)

// dropDecisionColumn damages the decision table the same way the issue reporter did: the
// stream queries still run, LatestDecisionID still works, but selecting the broken column
// fails. It goes through a separate connection so ent keeps working for the assertions.
func dropDecisionColumn(t *testing.T, lapi LAPI, column string) {
	t.Helper()

	db, err := sql.Open("sqlite3", fmt.Sprintf("file:%s", lapi.DBConfig.DbPath))
	require.NoError(t, err)
	t.Cleanup(func() { db.Close() })

	_, err = db.Exec(fmt.Sprintf("ALTER TABLE decisions DROP COLUMN %s", column))
	require.NoError(t, err)
}

func bouncerStreamCursor(t *testing.T, ctx context.Context, lapi LAPI) int {
	t.Helper()

	b, err := lapi.DBClient.Ent.Bouncer.Query().Only(ctx)
	require.NoError(t, err)
	return b.StreamCursor
}

// A database failure while building a decision stream snapshot must not be reported as a
// successful, syntactically valid empty one: a bouncer pulling with startup=true would
// replace its whole active set with the empty answer and drop every ban (#4691).
func TestStreamDecisionQueryFailurePreCommit(t *testing.T) {
	ctx := t.Context()
	lapi := SetupLAPITest(t, ctx)

	seedOne(t, ctx, lapi, "1.0.0.1", "lists", "test/query-fail", types.Ip, "ban")

	// A working stream first, to prove the fault injection only breaks the queries that
	// select the damaged column.
	w := lapi.RecordResponse(t, ctx, "GET", "/v1/decisions/stream?startup=true", emptyBody, APIKEY)
	decisions, code := readDecisionsStreamResp(t, w)
	require.Equal(t, http.StatusOK, code)
	require.Len(t, decisions["new"], 1)

	firstCursor := bouncerStreamCursor(t, ctx, lapi)
	require.NotZero(t, firstCursor)

	// Same shape of fault as the issue: break a column the stream queries select, leaving
	// the table itself (and LatestDecisionID) working.
	dropDecisionColumn(t, lapi, "uuid")

	w = lapi.RecordResponse(t, ctx, "GET", "/v1/decisions/stream?startup=true", emptyBody, APIKEY)
	require.Equal(t, http.StatusInternalServerError, w.Code)

	var resp struct {
		Message string `json:"message"`
	}
	require.NoError(t, json.Unmarshal(w.Body.Bytes(), &resp))
	require.Contains(t, resp.Message, "unable to query")

	// The cursor must not have moved: the next pull retries the same window instead of
	// silently skipping past the decisions that were missed while the table was broken.
	require.Equal(t, firstCursor, bouncerStreamCursor(t, ctx, lapi))
}

// The mid-stream case: the first page of the "new" array is served, then the database fails on
// a later page. The response status is already committed, so the only correct behavior is to
// leave the document incomplete - a bouncer cannot parse it as a snapshot, so it keeps its
// state and retries. It is driven with an interceptor on the very client the handler uses,
// armed to fail a chosen page query after the ones that already ran.
func TestStreamDecisionQueryFailureMidStreamE2E(t *testing.T) {
	ctx := t.Context()

	config := LoadTestConfig(t)
	streamCfg := &csconfig.DecisionsStreamCfg{PageSize: 1}
	config.API.Server.DecisionsStream = streamCfg

	logger, _ := logtest.NewNullLogger()
	apiServer, err := NewServer(ctx, config.API.Server, logger.WithFields(nil))
	require.NoError(t, err)
	require.NoError(t, apiServer.InitController())
	router, err := apiServer.Router()
	require.NoError(t, err)

	apiKey, dbClient := CreateTestBouncer(t, ctx, config.API.Server.DbConfig)
	lapi := LAPI{router: router, bouncerKey: apiKey, DBClient: dbClient}

	for _, v := range []string{"1.0.0.1", "1.0.0.2"} {
		seedOne(t, ctx, lapi, v, "lists", "test/query-fail", types.Ip, "ban")
	}

	// Count the decision queries the handler runs: LatestDecisionID, the two first-page
	// prefetches, then page 2 of the "new" array. Fail exactly that one.
	var queries int
	failFourth := ent.InterceptFunc(func(next ent.Querier) ent.Querier {
		return ent.QuerierFunc(func(ctx context.Context, q ent.Query) (ent.Value, error) {
			queries++
			if queries == 5 {
				return nil, errors.New("injected failure")
			}
			return next.Query(ctx, q)
		})
	})
	apiServer.controller.HandlerV1.DBClient.Ent.Intercept(failFourth)

	w := lapi.RecordResponse(t, ctx, "GET", "/v1/decisions/stream?startup=true", emptyBody, APIKEY)
	require.Equal(t, http.StatusOK, w.Code, "status is already committed mid-stream")
	require.Equal(t, 5, queries, "the interceptor must have hit the exact page-2 query")

	var snapshot map[string]any
	require.Error(t, json.Unmarshal(w.Body.Bytes(), &snapshot),
		"a mid-stream failure must not close into a parseable snapshot")
	require.Contains(t, w.Body.String(), "1.0.0.1",
		"the first page was served before the failure")
	require.False(t, strings.HasSuffix(w.Body.String(), `]}`),
		"must not close into a valid empty snapshot")

	// The cursor must not advance past decisions that were never delivered.
	b, err := dbClient.Ent.Bouncer.Query().Only(ctx)
	require.NoError(t, err)
	require.Zero(t, b.StreamCursor, "cursor must not advance on a failed pull")
}

package v1

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/stretchr/testify/require"

	"github.com/crowdsecurity/crowdsec/pkg/database/ent"
)

// The mid-stream case cannot be triggered end to end from a test client: the fault has to land
// between two pages of the same response, and the handler runs synchronously. It is pinned at
// the unit level instead: once the first page of an array was streamed, a failure on a later
// page must leave the document incomplete - never close it as a valid empty snapshot.
func TestStreamDecisionQueryFailureMidStream(t *testing.T) {
	w := httptest.NewRecorder()
	c, _ := gin.CreateTestContext(w)
	c.Request = httptest.NewRequest(http.MethodGet, "/", http.NoBody)
	now := time.Now().UTC()
	filters := map[string][]string{}

	// page 1: one decision; page 2: the query fails.
	var queries int
	query := func(_ context.Context, _ time.Time, _ map[string][]string) ([]*ent.Decision, error) {
		queries++
		if queries == 1 {
			until := now.Add(time.Minute)
			return []*ent.Decision{{ID: 1, Until: &until, Scenario: "s", Type: "ban", Scope: "Ip", Value: "1.2.3.4", Origin: "lists"}}, nil
		}
		return nil, errors.New("query decision failed")
	}

	firstPage, err := query(t.Context(), now, filters)
	require.NoError(t, err)

	_, werr := w.WriteString(`{"new": [`)
	require.NoError(t, werr)
	err = writeDecisions(c, now, filters, 0, 1, query, firstPage)
	require.Error(t, err)
	require.Equal(t, 2, queries, "the pre-fetched first page must not be queried twice")
	require.Contains(t, w.Body.String(), "1.2.3.4", "the first page must be in the body")
	body := w.Body.String()
	require.False(t, strings.HasSuffix(body, `]}`), "must not close into a valid empty snapshot")
}

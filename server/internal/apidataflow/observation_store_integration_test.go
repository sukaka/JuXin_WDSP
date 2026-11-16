package apidataflow

import (
	"context"
	"os"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/jiuzhang-waf/server/internal/agents"
	"github.com/jiuzhang-waf/server/internal/apm"
)

func TestCHObservationStoreIntegration(t *testing.T) {
	dsn := os.Getenv("WDSP_CLICKHOUSE_TEST_DSN")
	if dsn == "" {
		t.Skip("WDSP_CLICKHOUSE_TEST_DSN is not configured")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	querier, err := apm.OpenClickHouse(dsn)
	if err != nil {
		t.Fatal(err)
	}
	record := validProjectionEnvelope()
	record.AgentID = uuid.New()
	record.EventID = "ev-integration-" + uuid.NewString()
	store := NewCHObservationStore(func(context.Context) apm.CHQuerier { return querier })
	if err := store.SaveBatch(ctx, []agents.APIObservationEnvelope{record}); err != nil {
		t.Fatal(err)
	}
	rows, err := querier.Query(ctx, `SELECT count() FROM wdsp.api_observations WHERE agent_id=? AND event_id=?`, record.AgentID, record.EventID)
	if err != nil {
		t.Fatal(err)
	}
	defer rows.Close()
	if !rows.Next() {
		t.Fatal("missing observation count")
	}
	var count uint64
	if err := rows.Scan(&count); err != nil {
		t.Fatal(err)
	}
	if count != 1 {
		t.Fatalf("observation count=%d", count)
	}
	fieldRows, err := querier.Query(ctx, `SELECT data_type, field_path FROM wdsp.api_field_observations WHERE agent_id=? AND event_id=?`, record.AgentID, record.EventID)
	if err != nil {
		t.Fatal(err)
	}
	defer fieldRows.Close()
	if !fieldRows.Next() {
		t.Fatal("missing field observation")
	}
	var dataType, path string
	if err := fieldRows.Scan(&dataType, &path); err != nil {
		t.Fatal(err)
	}
	if dataType != "PHONE" || path != "$.mobile" {
		t.Fatalf("unexpected field: %s %s", dataType, path)
	}
}

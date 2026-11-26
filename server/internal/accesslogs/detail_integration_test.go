package accesslogs

import (
	"context"
	"database/sql"
	"os"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/jiuzhang-waf/server/internal/database"
)

func TestAccessLogDetailTraceIntegration(t *testing.T) {
	dsn := os.Getenv("ACCESSLOGS_TEST_PG_DSN")
	if dsn == "" {
		t.Skip("ACCESSLOGS_TEST_PG_DSN not set, skipping PG integration test")
	}
	ctx := context.Background()
	pool, err := pgxpool.New(ctx, dsn)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(pool.Close)
	if err := database.Migrate(ctx, pool, "../../migrations", "up"); err != nil {
		t.Fatalf("migrate: %v", err)
	}

	ttfb := int64(42)
	entry := &LogEntry{
		OccurredAt: time.Now().UTC(), RequestID: "req-detail-trace-integration",
		TraceID: "0123456789abcdef0123456789abcdef", SpanID: "0123456789abcdef",
		EndpointKey: "POST /v1/login", PathTemplate: "/v1/login", TTFBMs: &ttfb,
		RequestHeaders: map[string][]string{}, ResponseHeaders: map[string][]string{},
	}
	if _, err := pool.Exec(ctx, `DELETE FROM access_logs WHERE request_id = $1`, entry.RequestID); err != nil {
		t.Fatalf("cleanup stale row: %v", err)
	}
	t.Cleanup(func() {
		_, _ = pool.Exec(context.Background(), `DELETE FROM access_logs WHERE request_id = $1`, entry.RequestID)
	})
	inserted, err := NewStore(pool).Insert(ctx, entry)
	if err != nil || !inserted {
		t.Fatalf("insert: inserted=%v err=%v", inserted, err)
	}
	var id string
	var trace, span, endpoint, path string
	var storedTTFB sql.NullInt64
	if err := pool.QueryRow(ctx, `SELECT id,trace_id,span_id,endpoint_key,path_template,ttfb_ms
		FROM access_logs WHERE request_id=$1`, entry.RequestID).
		Scan(&id, &trace, &span, &endpoint, &path, &storedTTFB); err != nil {
		t.Fatalf("read raw columns: %v", err)
	}
	if trace != entry.TraceID || span != entry.SpanID || !storedTTFB.Valid || storedTTFB.Int64 != ttfb {
		t.Fatalf("raw values were not stored correctly")
	}
	log, err := NewStore(pool).GetByID(ctx, uuidMustParse(t, id))
	if err != nil {
		t.Fatalf("GetByID: %v", err)
	}
	if log.TraceID != entry.TraceID || log.SpanID != entry.SpanID || log.EndpointKey != entry.EndpointKey ||
		log.PathTemplate != entry.PathTemplate || log.TTFBMs == nil || *log.TTFBMs != ttfb {
		t.Fatalf("GetByID lost fields: %+v", log)
	}
}

func uuidMustParse(t *testing.T, value string) uuid.UUID {
	t.Helper()
	parsed, err := uuid.Parse(value)
	if err != nil {
		t.Fatal(err)
	}
	return parsed
}

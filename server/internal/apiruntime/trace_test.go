package apiruntime

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/google/uuid"
)

const testTraceID = "0af7651916cd43dd8448eb211c80319c"

func TestParseRecordLineTraceID(t *testing.T) {
	tests := []struct {
		name    string
		traceID any
		want    string
	}{
		{name: "valid", traceID: testTraceID, want: testTraceID},
		{name: "legacy missing", traceID: nil},
		{name: "uppercase", traceID: strings.ToUpper(testTraceID)},
		{name: "all zero", traceID: strings.Repeat("0", 32)},
		{name: "too short", traceID: testTraceID[:31]},
		{name: "non hex", traceID: testTraceID[:31] + "g"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			record := map[string]any{"request_id": "r-trace-parse", "endpoint_key": "POST /login"}
			if tt.traceID != nil {
				record["trace_id"] = tt.traceID
			}
			rec, err := parseRecordLine([]byte(mustJSON(t, record)))
			if err != nil {
				t.Fatalf("parseRecordLine: %v", err)
			}
			if rec.TraceID != tt.want {
				t.Fatalf("TraceID = %q, want %q", rec.TraceID, tt.want)
			}
		})
	}
}

func TestCollectOnceTraceIDPropagates(t *testing.T) {
	dir := t.TempDir()
	logPath := filepath.Join(dir, "api-runtime-events.log")
	writeLines(t, logPath, []string{
		mustJSON(t, map[string]any{
			"request_id": "r-trace-collect", "endpoint_key": "POST /login",
			"trace_id": testTraceID, "final_action": "OBSERVE",
		}),
		mustJSON(t, map[string]any{
			"request_id": "r-trace-legacy", "endpoint_key": "POST /legacy",
			"final_action": "OBSERVE",
		}),
	})
	saver := &fakeSaver{}
	collector := NewCollector(saver, "trace-test", logPath, filepath.Join(dir, "checkpoint"), "node-1")
	if _, err := collector.CollectOnce(context.Background()); err != nil {
		t.Fatalf("CollectOnce: %v", err)
	}
	if len(saver.saved) != 2 {
		t.Fatalf("saved events = %d, want 2", len(saver.saved))
	}
	if saver.saved[0].TraceID != testTraceID {
		t.Fatalf("collected TraceID = %q, want %q", saver.saved[0].TraceID, testTraceID)
	}
	if saver.saved[1].TraceID != "" {
		t.Fatalf("legacy TraceID = %q, want empty", saver.saved[1].TraceID)
	}
}

func TestSavePrimaryTraceIDSQL(t *testing.T) {
	tests := []struct {
		name    string
		traceID string
		want    any
	}{
		{name: "valid", traceID: testTraceID, want: testTraceID},
		{name: "legacy missing", want: nil},
		{name: "uppercase", traceID: strings.ToUpper(testTraceID), want: nil},
		{name: "all zero", traceID: strings.Repeat("0", 32), want: nil},
		{name: "non hex", traceID: testTraceID[:31] + "g", want: nil},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			db := &captureArgsTx{}
			ev := ctxFieldEvent("req-trace-sql")
			ev.TraceID = tt.traceID
			if err := (&Store{db: db}).SavePrimary(context.Background(), ev); err != nil {
				t.Fatalf("SavePrimary: %v", err)
			}
			if len(db.sqls) != 1 || !strings.Contains(db.sqls[0], "trace_id") {
				t.Fatalf("primary INSERT must include trace_id: %v", db.sqls)
			}
			if len(db.args) != 1 || len(db.args[0]) != 25 {
				t.Fatalf("primary INSERT args = %+v, want 25", db.args)
			}
			if got := db.args[0][24]; got != tt.want {
				t.Fatalf("trace_id argument = %#v, want %#v", got, tt.want)
			}
		})
	}
}

func TestTraceIDMigrationStatic(t *testing.T) {
	up, err := os.ReadFile(filepath.Join("..", "..", "migrations", "000217_api_runtime_event_trace.up.sql"))
	if err != nil {
		t.Fatalf("read up migration: %v", err)
	}
	for _, fragment := range []string{
		"ADD COLUMN IF NOT EXISTS trace_id VARCHAR(32)",
		"chk_api_runtime_events_trace_id",
		"trace_id ~ '^[0-9a-f]{32}$'",
		"trace_id <> '00000000000000000000000000000000'",
		"CREATE INDEX IF NOT EXISTS idx_api_runtime_events_trace_id",
		"WHERE trace_id IS NOT NULL",
	} {
		if !strings.Contains(string(up), fragment) {
			t.Errorf("up migration missing %q", fragment)
		}
	}
	if strings.Contains(string(up), "UPDATE api_runtime_events") {
		t.Fatal("trace migration must not backfill historical events")
	}

	down, err := os.ReadFile(filepath.Join("..", "..", "migrations", "000217_api_runtime_event_trace.down.sql"))
	if err != nil {
		t.Fatalf("read down migration: %v", err)
	}
	for _, fragment := range []string{
		"DROP INDEX IF EXISTS idx_api_runtime_events_trace_id",
		"DROP COLUMN IF EXISTS trace_id",
	} {
		if !strings.Contains(string(down), fragment) {
			t.Errorf("down migration missing %q", fragment)
		}
	}
}

func TestSavePrimaryTraceIDIntegration(t *testing.T) {
	pool := integrationPool(t)
	ctx := context.Background()
	requestID := "req-trace-" + uuid.NewString()
	t.Cleanup(func() {
		_, _ = pool.Exec(context.Background(), `DELETE FROM api_runtime_events WHERE request_id = $1`, requestID)
	})

	first := ctxFieldEvent(requestID)
	first.TraceID = testTraceID
	if err := NewStore(pool).SavePrimary(ctx, first); err != nil {
		t.Fatalf("SavePrimary: %v", err)
	}
	replay := ctxFieldEvent(requestID)
	if err := NewStore(pool).SavePrimary(ctx, replay); err != nil {
		t.Fatalf("SavePrimary replay: %v", err)
	}

	var got *string
	if err := pool.QueryRow(ctx, `SELECT trace_id FROM api_runtime_events WHERE request_id = $1`, requestID).Scan(&got); err != nil {
		t.Fatalf("read trace_id: %v", err)
	}
	if got == nil || *got != testTraceID {
		t.Fatalf("trace_id after duplicate request = %v, want %q", got, testTraceID)
	}
	var rows int
	if err := pool.QueryRow(ctx, `SELECT count(*) FROM api_runtime_events WHERE request_id = $1`, requestID).Scan(&rows); err != nil {
		t.Fatalf("count duplicate request: %v", err)
	}
	if rows != 1 {
		t.Fatalf("rows for duplicate request = %d, want 1", rows)
	}
	if _, err := pool.Exec(ctx, `UPDATE api_runtime_events SET trace_id = $1 WHERE request_id = $2`, strings.Repeat("0", 32), requestID); err == nil {
		t.Fatal("database accepted an all-zero trace_id")
	}

	var indexes int
	if err := pool.QueryRow(ctx, `SELECT count(*) FROM pg_indexes WHERE tablename = 'api_runtime_events' AND indexname = 'idx_api_runtime_events_trace_id'`).Scan(&indexes); err != nil {
		t.Fatalf("read trace index: %v", err)
	}
	if indexes != 1 {
		t.Fatalf("trace_id partial index count = %d, want 1", indexes)
	}

	down, err := os.ReadFile(filepath.Join("..", "..", "migrations", "000217_api_runtime_event_trace.down.sql"))
	if err != nil {
		t.Fatalf("read down migration: %v", err)
	}
	if _, err := pool.Exec(ctx, string(down)); err != nil {
		t.Fatalf("down migration: %v", err)
	}
	var columns int
	if err := pool.QueryRow(ctx, `SELECT count(*) FROM information_schema.columns WHERE table_name = 'api_runtime_events' AND column_name = 'trace_id'`).Scan(&columns); err != nil {
		t.Fatalf("count trace_id columns after down: %v", err)
	}
	if columns != 0 {
		t.Fatalf("trace_id columns after down = %d, want 0", columns)
	}
	up, err := os.ReadFile(filepath.Join("..", "..", "migrations", "000217_api_runtime_event_trace.up.sql"))
	if err != nil {
		t.Fatalf("read up migration: %v", err)
	}
	for i := 0; i < 2; i++ {
		if _, err := pool.Exec(ctx, string(up)); err != nil {
			t.Fatalf("re-apply up migration #%d: %v", i+1, err)
		}
	}
}

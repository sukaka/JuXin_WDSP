package accesscontrolversions

import (
	"context"
	"os"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgxpool"
)

// TestPersistedSnapshotSelectionAfterProcessRestart verifies the AZ-13/AZ-14
// recovery boundary against PostgreSQL: a new Store instance must ignore the
// newest FAILED/PENDING rows and recover the most recent durable SUCCESS
// snapshot. The temporary table keeps this contract test isolated from the
// repository migration state while exercising the real Store SQL.
func TestPersistedSnapshotSelectionAfterProcessRestart(t *testing.T) {
	dsn := os.Getenv("AUTHZ_TEST_PG_DSN")
	if dsn == "" {
		t.Skip("AUTHZ_TEST_PG_DSN not set, skipping persisted recovery test")
	}

	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()
	config, err := pgxpool.ParseConfig(dsn)
	if err != nil {
		t.Fatalf("parse PostgreSQL DSN: %v", err)
	}
	config.MaxConns = 1
	config.MinConns = 1
	pool, err := pgxpool.NewWithConfig(ctx, config)
	if err != nil {
		t.Fatalf("connect PostgreSQL: %v", err)
	}
	defer pool.Close()

	_, err = pool.Exec(ctx, `
CREATE TEMP TABLE access_control_versions (
  id uuid PRIMARY KEY DEFAULT (md5(random()::text || clock_timestamp()::text)::uuid),
  version_no integer NOT NULL,
  config jsonb NOT NULL,
  config_hash text NOT NULL,
  change_summary text NOT NULL,
  previous_version_id uuid,
  publish_task_id uuid,
  publish_result text NOT NULL,
  created_by uuid,
  created_at timestamptz NOT NULL DEFAULT now()
) ON COMMIT PRESERVE ROWS`)
	if err != nil {
		t.Fatalf("create isolated versions table: %v", err)
	}

	first, err := NewStore(pool).Create(ctx, CreateInput{
		Config:        []byte(`{"api_authz_models":[{"endpoint_key":"GET /orders/{id}"}]}`),
		ChangeSummary: "first successful authorization snapshot",
	})
	if err != nil {
		t.Fatalf("create first version: %v", err)
	}
	if err := NewStore(pool).SetResult(ctx, first.ID, PublishSuccess); err != nil {
		t.Fatalf("mark first version successful: %v", err)
	}

	failed, err := NewStore(pool).Create(ctx, CreateInput{
		Config:            []byte(`{"api_authz_models":[{"endpoint_key":"GET /orders/{id}","required_relation":"ADMIN"}]}`),
		ChangeSummary:     "failed authorization snapshot",
		PreviousVersionID: &first.ID,
	})
	if err != nil {
		t.Fatalf("create failed version: %v", err)
	}
	if err := NewStore(pool).SetResult(ctx, failed.ID, PublishFailed); err != nil {
		t.Fatalf("mark failed version: %v", err)
	}

	pending, err := NewStore(pool).Create(ctx, CreateInput{
		Config:            []byte(`{"api_authz_models":[{"endpoint_key":"GET /orders/{id}","required_relation":"OWNER"}]}`),
		ChangeSummary:     "interrupted authorization snapshot",
		PreviousVersionID: &first.ID,
	})
	if err != nil {
		t.Fatalf("create pending version: %v", err)
	}

	// A fresh Store models a process restart: selection must be driven solely by
	// persisted publish_result, never by an in-memory previous pointer.
	restarted := NewStore(pool)
	got, err := restarted.GetLatestSuccessful(ctx)
	if err != nil {
		t.Fatalf("select latest successful after restart: %v", err)
	}
	if got == nil || got.ID != first.ID || got.PublishResult != PublishSuccess {
		t.Fatalf("recovered version = %+v, want first SUCCESS %s", got, first.ID)
	}
	if string(got.Config) != string(first.Config) {
		t.Fatalf("recovered config = %s, want durable first snapshot %s", got.Config, first.Config)
	}
	if got.ID == failed.ID || got.ID == pending.ID {
		t.Fatalf("unsuccessful version selected after restart: %s", got.ID)
	}

	if err := restarted.SetResult(ctx, pending.ID, PublishSuccess); err != nil {
		t.Fatalf("complete pending version: %v", err)
	}
	got, err = NewStore(pool).GetLatestSuccessful(ctx)
	if err != nil {
		t.Fatalf("select newly successful version: %v", err)
	}
	if got == nil || got.ID != pending.ID || got.PublishResult != PublishSuccess {
		t.Fatalf("new successful version = %+v, want pending row promoted to SUCCESS", got)
	}

	// Keep the imported UUID package in the test's compile-time contract: IDs
	// must remain real persisted UUIDs rather than process-local indexes.
	if got.ID == uuid.Nil || first.ID == uuid.Nil {
		t.Fatal("persisted snapshot IDs must be non-zero UUIDs")
	}
}

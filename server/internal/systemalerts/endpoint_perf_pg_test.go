// endpoint_perf_pg_test.go 端点性能统计的真实 PostgreSQL 契约。
// Opt-in（AUTHZ_TEST_PG_DSN）；独立 schema 避免依赖或污染业务表。
package systemalerts

import (
	"context"
	"fmt"
	"os"
	"slices"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/jiuzhang-waf/server/internal/metrics"
)

func openEndpointPerfPG(t *testing.T) (*pgxpool.Pool, context.Context) {
	t.Helper()
	dsn := os.Getenv("AUTHZ_TEST_PG_DSN")
	if dsn == "" {
		t.Skip("AUTHZ_TEST_PG_DSN not set, skipping endpoint perf PostgreSQL test")
	}
	cfg, err := pgxpool.ParseConfig(dsn)
	if err != nil {
		t.Fatalf("parse PostgreSQL DSN: %v", err)
	}
	schema := fmt.Sprintf("systemalerts_endpoint_perf_%d", time.Now().UnixNano())
	cfg.ConnConfig.RuntimeParams["search_path"] = schema
	ctx := context.Background()
	pool, err := pgxpool.NewWithConfig(ctx, cfg)
	if err != nil {
		t.Fatalf("create PostgreSQL pool: %v", err)
	}
	quotedSchema := pgx.Identifier{schema}.Sanitize()
	if _, err := pool.Exec(ctx, "CREATE SCHEMA "+quotedSchema); err != nil {
		pool.Close()
		t.Fatalf("create isolated schema: %v", err)
	}
	t.Cleanup(func() {
		cleanupCtx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancel()
		if _, err := pool.Exec(cleanupCtx, "DROP SCHEMA "+quotedSchema+" CASCADE"); err != nil {
			t.Errorf("drop isolated schema: %v", err)
		}
		pool.Close()
	})
	if _, err := pool.Exec(ctx, `
CREATE TABLE metric_minute_aggregates (
    bucket_start TIMESTAMPTZ NOT NULL,
    metric VARCHAR(64) NOT NULL,
    labels JSONB NOT NULL DEFAULT '{}',
    value DOUBLE PRECISION NOT NULL DEFAULT 0,
    extra JSONB NOT NULL DEFAULT '{}',
    updated_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    PRIMARY KEY (bucket_start, metric, labels)
)`); err != nil {
		t.Fatalf("create metric_minute_aggregates: %v", err)
	}
	return pool, ctx
}

func TestEndpointMinuteStatsPostgresContract(t *testing.T) {
	pool, ctx := openEndpointPerfPG(t)
	bucket := time.Date(2026, 11, 7, 10, 0, 0, 0, time.UTC)
	type metricRow struct {
		bucket time.Time
		metric string
		labels string
		value  float64
		extra  string
	}
	rows := []metricRow{
		{bucket, metrics.HTTPEndpointRequestsTotal, `{"app":"shop","endpoint":"GET /orders/{id}","status_class":"2xx","action":"allow"}`, 7, `{}`},
		{bucket, metrics.HTTPEndpointRequestsTotal, `{"app":"shop","endpoint":"GET /orders/{id}","status_class":"5xx","action":"allow"}`, 3, `{}`},
		{bucket, metrics.HTTPEndpointRequestsTotal, `{"app":"shop","endpoint":"GET /orders/{id}","status_class":"5xx","action":"block"}`, 2, `{}`},
		{bucket, metrics.HTTPEndpointDurationMs, `{"app":"shop","endpoint":"GET /orders/{id}","status_class":"2xx","action":"allow"}`, 7, `{"buckets":[1,2,0,1,0,0,0,0,0,0,0]}`},
		{bucket, metrics.HTTPEndpointDurationMs, `{"app":"shop","endpoint":"GET /orders/{id}","status_class":"5xx","action":"allow"}`, 3, `{"buckets":[0,1,2,0,1,0,0,0,0,0,0]}`},
		{bucket, metrics.HTTPEndpointDurationMs, `{"app":"shop","endpoint":"GET /orders/{id}","status_class":"5xx","action":"block"}`, 2, `{"buckets":[0,0,1,0,0,2,0,0,0,0,0]}`},
		{bucket.Add(-time.Minute), metrics.HTTPEndpointRequestsTotal, `{"app":"shop","endpoint":"GET /orders/{id}","status_class":"5xx","action":"allow"}`, 100, `{}`},
	}
	for _, row := range rows {
		if _, err := pool.Exec(ctx, `
INSERT INTO metric_minute_aggregates (bucket_start, metric, labels, value, extra)
VALUES ($1, $2, $3::jsonb, $4, $5::jsonb)`,
			row.bucket, row.metric, row.labels, row.value, row.extra); err != nil {
			t.Fatalf("insert %s fixture: %v", row.metric, err)
		}
	}

	stats, err := NewStore(pool).EndpointMinuteStats(ctx, bucket, bucket.Add(time.Minute))
	if err != nil {
		t.Fatalf("EndpointMinuteStats: %v", err)
	}
	if len(stats) != 1 {
		t.Fatalf("stats length = %d, want 1: %+v", len(stats), stats)
	}
	got := stats[0]
	if !got.BucketStart.Equal(bucket) || got.App != "shop" || got.Endpoint != "GET /orders/{id}" {
		t.Errorf("stat identity = (%s, %q, %q)", got.BucketStart, got.App, got.Endpoint)
	}
	if got.Requests != 12 || got.Err5xx != 5 {
		t.Errorf("requests/5xx = %v/%v, want 12/5", got.Requests, got.Err5xx)
	}
	wantDur := make([]int, len(metrics.DurationBucketsMs)+1)
	copy(wantDur, []int{1, 3, 3, 1, 1, 2})
	if !slices.Equal(got.DurBuckets, wantDur) {
		t.Errorf("duration buckets = %v, want %v", got.DurBuckets, wantDur)
	}
}

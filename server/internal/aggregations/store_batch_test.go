package aggregations

import (
	"context"
	"math"
	"os"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/jiuzhang-waf/server/internal/database"
)

func TestStoreBatchEmptySlices(t *testing.T) {
	ctx := context.Background()
	store := NewStore(nil)
	start := time.Date(2026, 11, 25, 10, 0, 0, 0, time.UTC)
	end := start.Add(10 * time.Minute)

	n, err := store.upsertMinute(ctx, start, nil)
	if err != nil || n != 0 {
		t.Fatalf("upsertMinute(nil) = (%d, %v), want (0, nil)", n, err)
	}

	sums, err := store.SumRangeBatch(ctx, "metric_minute_aggregates", nil, start, end)
	if err != nil || len(sums) != 0 {
		t.Fatalf("SumRangeBatch(nil) = (%v, %v), want (empty, nil)", sums, err)
	}

	times, vals, err := store.QueryRangeBatch(ctx, "metric_minute_aggregates", []string{}, start, end)
	if err != nil || len(times) != 0 || len(vals) != 0 {
		t.Fatalf("QueryRangeBatch(empty) = (%v, %v, %v), want (empty, empty, nil)", times, vals, err)
	}
}

func TestStoreBatchPGIntegration(t *testing.T) {
	dsn := os.Getenv("AGGREGATIONS_TEST_PG_DSN")
	if dsn == "" {
		t.Skip("AGGREGATIONS_TEST_PG_DSN not set, skipping PG integration test")
	}

	ctx := context.Background()
	pool, err := pgxpool.New(ctx, dsn)
	if err != nil {
		t.Fatalf("pgxpool.New: %v", err)
	}
	t.Cleanup(pool.Close)

	if err := database.Migrate(ctx, pool, "../../migrations", "up"); err != nil {
		t.Fatalf("migrate up: %v", err)
	}

	suffix := uuid.New().String()[:8]
	mReq := "test_batch_req_" + suffix
	mBlk := "test_batch_blk_" + suffix
	mEmpty := "test_batch_empty_" + suffix
	metrics := []string{mReq, mBlk, mEmpty}

	t.Cleanup(func() {
		_, _ = pool.Exec(context.Background(),
			`DELETE FROM metric_minute_aggregates WHERE metric = ANY($1)`, metrics)
	})

	store := NewStore(pool)
	b1 := time.Now().UTC().Truncate(time.Hour).Add(-2 * time.Hour)
	b2 := b1.Add(time.Minute)
	start := b1
	end := b2.Add(time.Minute)

	// 首次批量写入桶 1（含多标签）与桶 2
	n1, err := store.upsertMinute(ctx, b1, []AggRow{
		{Metric: mReq, Labels: map[string]string{"app": "a"}, Value: 10, Extra: map[string]interface{}{"src": "test"}},
		{Metric: mReq, Labels: map[string]string{"app": "b"}, Value: 5},
		{Metric: mBlk, Labels: map[string]string{"app": "a"}, Value: 2},
	})
	if err != nil || n1 != 3 {
		t.Fatalf("upsertMinute b1 = (%d, %v), want (3, nil)", n1, err)
	}

	// 验证同桶重复 upsert 幂等覆盖（app=a 从 10 更新为 15）
	n1Update, err := store.upsertMinute(ctx, b1, []AggRow{
		{Metric: mReq, Labels: map[string]string{"app": "a"}, Value: 15},
	})
	if err != nil || n1Update != 1 {
		t.Fatalf("upsertMinute b1 update = (%d, %v), want (1, nil)", n1Update, err)
	}

	n2, err := store.upsertMinute(ctx, b2, []AggRow{
		{Metric: mReq, Labels: map[string]string{"app": "a"}, Value: 25},
		{Metric: mBlk, Labels: map[string]string{"app": "a"}, Value: 3},
	})
	if err != nil || n2 != 2 {
		t.Fatalf("upsertMinute b2 = (%d, %v), want (2, nil)", n2, err)
	}

	// 1) 对比 SumRangeBatch 与逐项 SumRange
	sums, err := store.SumRangeBatch(ctx, "metric_minute_aggregates", metrics, start, end)
	if err != nil {
		t.Fatalf("SumRangeBatch: %v", err)
	}
	wantReqSum := 15.0 + 5.0 + 25.0
	wantBlkSum := 2.0 + 3.0
	if math.Abs(sums[mReq]-wantReqSum) > 1e-9 {
		t.Fatalf("SumRangeBatch[%s] = %v, want %v", mReq, sums[mReq], wantReqSum)
	}
	if math.Abs(sums[mBlk]-wantBlkSum) > 1e-9 {
		t.Fatalf("SumRangeBatch[%s] = %v, want %v", mBlk, sums[mBlk], wantBlkSum)
	}
	if sums[mEmpty] != 0 {
		t.Fatalf("SumRangeBatch[%s] = %v, want 0", mEmpty, sums[mEmpty])
	}
	for _, m := range metrics {
		single, err := store.SumRange(ctx, "metric_minute_aggregates", m, nil, start, end)
		if err != nil {
			t.Fatalf("SumRange(%s): %v", m, err)
		}
		if math.Abs(single-sums[m]) > 1e-9 {
			t.Fatalf("SumRange(%s)=%v != SumRangeBatch=%v", m, single, sums[m])
		}
	}

	// 2) 对比 QueryRangeBatch 与逐项 QueryRange（按桶累加）
	timesMap, valsMap, err := store.QueryRangeBatch(ctx, "metric_minute_aggregates", metrics, start, end)
	if err != nil {
		t.Fatalf("QueryRangeBatch: %v", err)
	}
	if len(timesMap[mEmpty]) != 0 || len(valsMap[mEmpty]) != 0 {
		t.Fatalf("expected empty series for %s, got times=%v vals=%v", mEmpty, timesMap[mEmpty], valsMap[mEmpty])
	}
	if len(timesMap[mReq]) != 2 || len(valsMap[mReq]) != 2 {
		t.Fatalf("QueryRangeBatch[%s] len = (%d, %d), want (2, 2)", mReq, len(timesMap[mReq]), len(valsMap[mReq]))
	}
	if !timesMap[mReq][0].Equal(b1) || !timesMap[mReq][1].Equal(b2) {
		t.Fatalf("QueryRangeBatch[%s] times = %v, want [%v, %v]", mReq, timesMap[mReq], b1, b2)
	}
	if math.Abs(valsMap[mReq][0]-20.0) > 1e-9 || math.Abs(valsMap[mReq][1]-25.0) > 1e-9 {
		t.Fatalf("QueryRangeBatch[%s] vals = %v, want [20, 25]", mReq, valsMap[mReq])
	}

	// 与 QueryRange 按桶归并结果严格对齐
	for _, m := range []string{mReq, mBlk} {
		rows, ts, err := store.QueryRange(ctx, "metric_minute_aggregates", m, nil, start, end)
		if err != nil {
			t.Fatalf("QueryRange(%s): %v", m, err)
		}
		bucketTotals := map[int64]float64{}
		for i, row := range rows {
			bucketTotals[ts[i].UTC().Unix()] += row.Value
		}
		if len(bucketTotals) != len(timesMap[m]) {
			t.Fatalf("metric %s bucket count mismatch: QueryRange=%d QueryRangeBatch=%d", m, len(bucketTotals), len(timesMap[m]))
		}
		for i, bt := range timesMap[m] {
			want := bucketTotals[bt.UTC().Unix()]
			if math.Abs(valsMap[m][i]-want) > 1e-9 {
				t.Fatalf("metric %s bucket %v: QueryRangeBatch=%v QueryRange=%v", m, bt, valsMap[m][i], want)
			}
		}
	}
}

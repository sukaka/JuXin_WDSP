package apiruntime

// 事务批量化基准（W22）：逐行 autocommit 插入 vs 每 2000 行单事务插入的吞吐对比。
// 仅在使用方显式提供真实 PG DSN 时运行：
//
//	APIRUNTIME_TEST_PG_DSN="postgres://user:pass@host:5432/db?sslmode=disable" \
//	  go test ./internal/apiruntime/ -run '^$' -bench BatchTx -benchtime=1x
//
// 表为基准自建自删的临时表（batchtx_bench_tmp），与生产表结构无关——
// 测量的是「事务边界」这一机制本身的成本差异，而非特定表写入路径。
import (
	"context"
	"fmt"
	"os"
	"testing"

	"github.com/jackc/pgx/v5/pgxpool"
)

const benchRows = 10000

func benchPool(tb testing.TB) *pgxpool.Pool {
	tb.Helper()
	dsn := os.Getenv("APIRUNTIME_TEST_PG_DSN")
	if dsn == "" {
		tb.Skip("APIRUNTIME_TEST_PG_DSN not set, skipping PG benchmark")
	}
	pool, err := pgxpool.New(context.Background(), dsn)
	if err != nil {
		tb.Fatalf("connect pg: %v", err)
	}
	tb.Cleanup(pool.Close)
	return pool
}

func benchPrepare(tb testing.TB, pool *pgxpool.Pool) {
	tb.Helper()
	ctx := context.Background()
	if _, err := pool.Exec(ctx, `DROP TABLE IF EXISTS batchtx_bench_tmp`); err != nil {
		tb.Fatalf("drop bench table: %v", err)
	}
	if _, err := pool.Exec(ctx, `CREATE TABLE batchtx_bench_tmp (id uuid PRIMARY KEY, request_id text, endpoint_key text, risk_score int, final_action text, occurred_at timestamptz)`); err != nil {
		tb.Fatalf("create bench table: %v", err)
	}
	tb.Cleanup(func() {
		_, _ = pool.Exec(context.Background(), `DROP TABLE IF EXISTS batchtx_bench_tmp`)
	})
}

func benchInsertSQL(i int) (string, string, string, int, string) {
	return fmt.Sprintf("req-bench-%d", i), "GET /bench", "ALLOW", i % 100, "OBSERVE"
}

// BenchmarkBatchTxAutocommit 逐行 autocommit（W20 行为基线）。
func BenchmarkBatchTxAutocommit(b *testing.B) {
	pool := benchPool(b)
	benchPrepare(b, pool)
	ctx := context.Background()
	const insert = `INSERT INTO batchtx_bench_tmp (id, request_id, endpoint_key, risk_score, final_action, occurred_at)
SELECT gen_random_uuid(), $1, $2, $3, $4, now() WHERE NOT EXISTS (SELECT 1 FROM batchtx_bench_tmp WHERE request_id = $1)`
	b.ResetTimer()
	for n := 0; n < b.N; n++ {
		for i := 0; i < benchRows; i++ {
			rid, ep, act, score, _ := benchInsertSQL(i)
			if _, err := pool.Exec(ctx, insert, rid, ep, score, act); err != nil {
				b.Fatalf("autocommit insert: %v", err)
			}
		}
		if _, err := pool.Exec(ctx, `TRUNCATE batchtx_bench_tmp`); err != nil {
			b.Fatalf("truncate: %v", err)
		}
	}
	b.ReportMetric(float64(benchRows*b.N)/b.Elapsed().Seconds(), "rows/s")
}

// BenchmarkBatchTxBatched 每 2000 行一个事务（W22 行为）。
func BenchmarkBatchTxBatched(b *testing.B) {
	pool := benchPool(b)
	benchPrepare(b, pool)
	ctx := context.Background()
	const insert = `INSERT INTO batchtx_bench_tmp (id, request_id, endpoint_key, risk_score, final_action, occurred_at)
SELECT gen_random_uuid(), $1, $2, $3, $4, now() WHERE NOT EXISTS (SELECT 1 FROM batchtx_bench_tmp WHERE request_id = $1)`
	const batchSize = defaultFlushBatch
	b.ResetTimer()
	for n := 0; n < b.N; n++ {
		for start := 0; start < benchRows; start += batchSize {
			tx, err := pool.Begin(ctx)
			if err != nil {
				b.Fatalf("begin: %v", err)
			}
			end := start + batchSize
			for i := start; i < end; i++ {
				rid, ep, act, score, _ := benchInsertSQL(i)
				if _, err := tx.Exec(ctx, insert, rid, ep, score, act); err != nil {
					_ = tx.Rollback(ctx)
					b.Fatalf("tx insert: %v", err)
				}
			}
			if err := tx.Commit(ctx); err != nil {
				b.Fatalf("commit: %v", err)
			}
		}
		if _, err := pool.Exec(ctx, `TRUNCATE batchtx_bench_tmp`); err != nil {
			b.Fatalf("truncate: %v", err)
		}
	}
	b.ReportMetric(float64(benchRows*b.N)/b.Elapsed().Seconds(), "rows/s")
}

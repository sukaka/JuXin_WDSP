// aggregations_minute_test.go 分钟聚合回归（审查 HIGH-9）：WAF 事件分钟聚合的
// 时间窗过滤曾误用不存在的表别名 m.event_occurred_at（FROM 仅 e/a），PostgreSQL
// 恒定报 42P01，waf_events_total 等指标永不写入。本用例造数后跑 RunMinute，
// 断言指标落表，防止回归。
// 真实 PostgreSQL/Valkey，无口令环境 t.Skip（纪律同 helper_test.go）。
package tests

import (
	"context"
	"testing"
	"time"

	"github.com/jiuzhang-waf/server/internal/aggregations"
)

func TestAggregationsMinuteWAFEvents(t *testing.T) {
	env := setupTestEnv(t)
	ctx := context.Background()

	// 造数桶取当前-2分钟，确保落在 RunMinute 的 [now-1min, now] 回看窗口内
	bucket := time.Now().UTC().Truncate(time.Minute).Add(-2 * time.Minute)
	actions := []string{"BLOCK", "BLOCK", "OBSERVE"}
	for i, action := range actions {
		if _, err := env.db.Exec(ctx, `
INSERT INTO security_events (request_id, occurred_at, attack_type, severity, action, response_status, request_method, request_uri)
VALUES ($1, $2, 'SQL_INJECTION', 'HIGH', $3, 403, 'GET', '/login')`,
			"req-agg-minute-"+string(rune('a'+i)), bucket.Add(10*time.Second), action); err != nil {
			t.Fatalf("insert security event: %v", err)
		}
	}

	jobs := aggregations.NewJobs(aggregations.NewStore(env.db))
	// RunMinute(now) 聚合 now-1min 与 now 两个分钟桶；传入 bucket+1min 覆盖造数桶
	if err := jobs.RunMinute(ctx, bucket.Add(time.Minute)); err != nil {
		t.Fatalf("RunMinute: %v", err)
	}

	sumMetric := func(metric string) float64 {
		t.Helper()
		var v float64
		if err := env.db.QueryRow(ctx, `
SELECT COALESCE(sum(value),0) FROM metric_minute_aggregates
WHERE bucket_start=$1 AND metric=$2`, bucket, metric).Scan(&v); err != nil {
			t.Fatalf("query %s: %v", metric, err)
		}
		return v
	}
	if v := sumMetric("waf_events_total"); v != 3 {
		t.Errorf("waf_events_total = %v, want 3", v)
	}
	if v := sumMetric("waf_blocks_total"); v != 2 {
		t.Errorf("waf_blocks_total = %v, want 2", v)
	}
	if v := sumMetric("waf_observes_total"); v != 1 {
		t.Errorf("waf_observes_total = %v, want 1", v)
	}

	// 任务台账应登记 SUCCESS（失败路径会记 FAILED 并返回错误，双保险）
	if n := s8Count(t, env,
		`SELECT count(*) FROM aggregation_jobs WHERE job_type='MINUTE' AND status='SUCCESS'`); n != 1 {
		t.Errorf("aggregation_jobs SUCCESS rows = %d, want 1", n)
	}
}

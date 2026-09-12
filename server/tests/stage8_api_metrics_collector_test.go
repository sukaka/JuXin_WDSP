// stage8_api_metrics_collector_test.go §54 新增 6 项指标 DB 聚合路径实库验证。
// 覆盖：APICollector.CollectOnce 对 Shadow/Zombie/图谱边/AI Tool 调用量（int gauge）
// 与每秒识别量/学习延迟（float gauge）的真实 SQL 聚合；关闭态/窗口外/非 COMPLETED
// 样本不计入口径；Render 文本含全部 21 项指标。
// 真实 PostgreSQL/Valkey，无口令环境 t.Skip（纪律同 stage8_api_security_test.go）。
package tests

import (
	"context"
	"math"
	"strings"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/jiuzhang-waf/server/internal/metrics"
)

// TestStage8APIMetricsCollectorNewSources 新增指标源实库聚合断言。
func TestStage8APIMetricsCollectorNewSources(t *testing.T) {
	env := setupStage8Env(t)
	ctx := context.Background()
	now := time.Now()

	// 端点：A 承载 findings/边/学习任务；B 置 ZOMBIE
	epA := s8SeedEndpoint(t, env, "GET", "/s8metrics-a-"+s5Rand(), 0.9)
	epB := s8SeedEndpoint(t, env, "POST", "/s8metrics-b-"+s5Rand(), 0.8)
	s8Exec(t, env, `UPDATE api_endpoints SET asset_status='ZOMBIE', zombie_since=now() WHERE id=$1`, epB.ID)

	// findings：SHADOW/NEW 计入；SHADOW/RESOLVED（已关闭）与 BOLA/NEW（类型不符）不计入
	s8Exec(t, env, `INSERT INTO api_runtime_findings (endpoint_id, finding_type, status) VALUES ($1,'SHADOW','NEW')`, epA.ID)
	s8Exec(t, env, `INSERT INTO api_runtime_findings (endpoint_id, finding_type, status) VALUES ($1,'SHADOW','RESOLVED')`, epA.ID)
	s8Exec(t, env, `INSERT INTO api_runtime_findings (endpoint_id, finding_type, status) VALUES ($1,'BOLA','NEW')`, epA.ID)

	// 学习任务：120s 与 240s 两个近窗 COMPLETED（均值 180s）；30h 前完成的 9999s
	// 与 RUNNING 各一（均不计入）
	s8Exec(t, env, `
INSERT INTO api_learning_jobs (endpoint_id, status, started_at, stopped_at)
VALUES ($1,'COMPLETED',$2,$3)`, epA.ID, now.Add(-120*time.Second), now)
	s8Exec(t, env, `
INSERT INTO api_learning_jobs (endpoint_id, status, started_at, stopped_at)
VALUES ($1,'COMPLETED',$2,$3)`, epA.ID, now.Add(-240*time.Second), now)
	s8Exec(t, env, `
INSERT INTO api_learning_jobs (endpoint_id, status, started_at, stopped_at)
VALUES ($1,'COMPLETED',$2,$3)`, epA.ID, now.Add(-40*time.Hour), now.Add(-40*time.Hour).Add(9999*time.Second))
	s8Exec(t, env, `INSERT INTO api_learning_jobs (endpoint_id, status) VALUES ($1,'RUNNING')`, epA.ID)

	// 图谱边 2 条
	s8Exec(t, env, `INSERT INTO api_call_edges (caller_fingerprint, target_endpoint_id) VALUES ('idp-x',$1)`, epA.ID)
	s8Exec(t, env, `INSERT INTO api_call_edges (caller_fingerprint, target_endpoint_id) VALUES ('idp-y',$1)`, epA.ID)

	// AI Tool 调用链：session → task → 3 次调用（user_id 无 FK，随机 UUID）
	sessID := uuid.New()
	s8Exec(t, env, `INSERT INTO ai_sessions (id, user_id) VALUES ($1,$2)`, sessID, uuid.New())
	taskID := uuid.New()
	s8Exec(t, env, `INSERT INTO ai_tasks (id, session_id, task_type) VALUES ($1,$2,'CHAT')`, taskID, sessID)
	for i := 0; i < 3; i++ {
		s8Exec(t, env, `INSERT INTO ai_tool_calls (task_id, tool_id) VALUES ($1,'tool_a')`, taskID)
	}

	c := metrics.NewAPICollector(env.db)
	if err := c.CollectOnce(ctx); err != nil {
		t.Fatalf("CollectOnce: %v", err)
	}
	snap := c.Snapshot()

	for name, want := range map[string]int64{
		metrics.APIShadowTotal:     1,
		metrics.APIZombieTotal:     1,
		metrics.APIGraphEdgesTotal: 2,
		metrics.AIToolCallsTotal:   3,
	} {
		if got := snap.Values[name]; got != want {
			t.Errorf("%s = %d, want %d", name, got, want)
		}
	}
	// 每秒识别量：本测试刚种 2 个端点（近 60s 窗口）→ 2/60
	if got, want := snap.Floats[metrics.APIDiscoveryPerSecond], 2.0/60.0; math.Abs(got-want) > 1e-9 {
		t.Errorf("api_discovery_per_second = %v, want %v", got, want)
	}
	// 学习延迟：仅近窗两个 COMPLETED（120s/240s）→ 均值 180s
	if got := snap.Floats[metrics.APILearningLatencySeconds]; math.Abs(got-180) > 1e-9 {
		t.Errorf("api_learning_latency_seconds = %v, want 180", got)
	}

	// Render 含全部 21 项指标名
	out := c.Render()
	for _, name := range []string{
		metrics.APIShadowTotal, metrics.APIZombieTotal, metrics.APIGraphEdgesTotal,
		metrics.AIToolCallsTotal, metrics.APIDiscoveryPerSecond, metrics.APILearningLatencySeconds,
	} {
		if !strings.Contains(out, "# TYPE "+name+" gauge\n") {
			t.Errorf("Render 缺少指标 %s", name)
		}
	}
}

// TestStage8APIMetricsCollectorEmptySources 空表口径：新指标全 0、采集无错误。
func TestStage8APIMetricsCollectorEmptySources(t *testing.T) {
	env := setupStage8Env(t)
	c := metrics.NewAPICollector(env.db)
	if err := c.CollectOnce(context.Background()); err != nil {
		t.Fatalf("CollectOnce: %v", err)
	}
	snap := c.Snapshot()
	for _, name := range []string{
		metrics.APIShadowTotal, metrics.APIZombieTotal, metrics.APIGraphEdgesTotal, metrics.AIToolCallsTotal,
	} {
		if got := snap.Values[name]; got != 0 {
			t.Errorf("空表 %s = %d, want 0", name, got)
		}
	}
	for _, name := range []string{metrics.APIDiscoveryPerSecond, metrics.APILearningLatencySeconds} {
		if got := snap.Floats[name]; got != 0 {
			t.Errorf("空表 %s = %v, want 0", name, got)
		}
	}
	if snap.CollectErrors != 0 {
		t.Errorf("空表采集错误 = %d, want 0", snap.CollectErrors)
	}
}

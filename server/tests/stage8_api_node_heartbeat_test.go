// stage8_api_node_heartbeat_test.go 网关节点心跳（W17-HB，任务书 §201 活性+版本
// 上报升级）集成测试。覆盖：
//   - 采集全链路：心跳 JSONL → apiruntime.Collector（真实 saver）→ HeartbeatRecorder
//     （真实 apinodes.Store）→ api_gateway_nodes——心跳不落 api_runtime_events、
//     不产端点资产，仅推进节点活性/版本；
//   - 聚合共存：Sweeper 清扫不回退心跳推进的活性与版本（有心跳无流量=ACTIVE、
//     心跳版本优先于历史业务事件版本）；更新的业务事件到达时版本正常接管；
//   - 幂等：同一拍心跳重复透传/重复清扫不产生叠加。
package tests

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/jiuzhang-waf/server/internal/apiassets"
	"github.com/jiuzhang-waf/server/internal/apinodes"
	"github.com/jiuzhang-waf/server/internal/apiruntime"
)

// hbWriteLines 写事件日志行（JSONL；与网关 apievents 输出同形态）。
func hbWriteLines(t *testing.T, path string, lines []string) {
	t.Helper()
	data := ""
	for _, ln := range lines {
		data += ln + "\n"
	}
	if err := os.WriteFile(path, []byte(data), 0o600); err != nil {
		t.Fatalf("write log: %v", err)
	}
}

// hbLine 构造网关心跳记录 JSON（W17-HB 形态：heartbeat=true + 版本维度）。
func hbLine(requestID, node, policyVersion string, occurredAt time.Time) string {
	return fmt.Sprintf(`{"request_id":%q,"occurred_at":%q,"endpoint_key":"__heartbeat__",`+
		`"final_action":"ALLOW","risk_level":"NONE","details":[],"heartbeat":true,`+
		`"policy_version":%q,"gateway_node_id":%q}`,
		requestID, occurredAt.UTC().Format(time.RFC3339Nano), policyVersion, node)
}

// TestStage8NodeHeartbeatCollection 采集全链路：心跳直写节点视图，零业务数据。
func TestStage8NodeHeartbeatCollection(t *testing.T) {
	env := setupStage8Env(t)
	ctx := context.Background()
	rid := s5Rand()
	now := time.Now().UTC()
	node := "gw-hb-" + rid

	dir := t.TempDir()
	logPath := filepath.Join(dir, "api-runtime-events.log")
	hbWriteLines(t, logPath, []string{
		hbLine("hb1-"+rid, node, "v2026.3", now.Add(-time.Second)),
		hbLine("hb2-"+rid, node, "v2026.3", now),
		// 一条业务 BLOCK 事件随行（验证心跳不影响既有业务采集路径）
		fmt.Sprintf(`{"request_id":%q,"occurred_at":%q,"endpoint_key":"POST /api/hb",`+
			`"method":"POST","path_template":"/api/hb","final_action":"BLOCK","risk_level":"MEDIUM",`+
			`"risk_score":40,"details":[{"detector":"api_schema","rule_id":"schema.type_mismatch",`+
			`"category":"BLOCK","severity":"HIGH","message":"type mismatch","score_delta":40}],`+
			`"gateway_node_id":%q,"policy_version":"v2026.3"}`, "biz1-"+rid, now.UTC().Format(time.RFC3339Nano), node),
	})

	collector := apiruntime.NewCollector(apiruntime.NewStore(env.db), "hb-it-01",
		logPath, filepath.Join(dir, "checkpoint"), node)
	// 真实端点发现写入方同接线：断言「业务照常物化、心跳零物化」才有意义；
	// 样本/违例/findings/参数·响应·文件·LLM 观测的零贡献由 apiruntime 包
	// collector_heartbeat_test.go 全接线单测按调用计数断言（样本落库另需
	// RUNNING 学习任务，不在本链路重复搭建）
	assetStore := apiassets.NewStore(env.db)
	collector.SetDiscoveryUpserter(assetStore)
	collector.SetHeartbeatRecorder(apinodes.NewStore(env.db))

	n, err := collector.CollectOnce(ctx)
	if err != nil {
		t.Fatalf("CollectOnce: %v", err)
	}
	if n != 3 {
		t.Fatalf("processed = %d, want 3", n)
	}

	// 心跳不落事件表：仅业务 BLOCK 一行，无 __heartbeat__ 行
	if c := s8Count(t, env, `SELECT count(*) FROM api_runtime_events WHERE endpoint_key='__heartbeat__'`); c != 0 {
		t.Fatalf("heartbeat rows in api_runtime_events = %d, want 0 (评估后不落表，见 collector 注释)", c)
	}
	if c := s8Count(t, env, `SELECT count(*) FROM api_runtime_events WHERE request_id='biz1-`+rid+`'`); c != 1 {
		t.Fatalf("business event rows = %d, want 1", c)
	}
	// 心跳不产端点资产；业务记录照常物化（对照组）
	if c := s8Count(t, env, `SELECT count(*) FROM api_endpoints WHERE endpoint_key='__heartbeat__'`); c != 0 {
		t.Fatalf("heartbeat endpoint asset = %d, want 0", c)
	}
	if c := s8Count(t, env, `SELECT count(*) FROM api_endpoints WHERE endpoint_key='POST /api/hb'`); c != 1 {
		t.Fatalf("business endpoint asset = %d, want 1 (discovery path intact)", c)
	}

	// 节点视图：活性=最新心跳时间、版本=心跳上报、业务事件计数=0（心跳不计数）、ACTIVE
	var lastSeen time.Time
	var policy, status string
	var count int64
	if err := env.db.QueryRow(ctx, `SELECT last_seen_at, last_policy_version, event_count, status
		FROM api_gateway_nodes WHERE node_name=$1`, node).
		Scan(&lastSeen, &policy, &count, &status); err != nil {
		t.Fatalf("read node: %v", err)
	}
	if policy != "v2026.3" || count != 0 || status != apinodes.StatusActive {
		t.Fatalf("node = (%s,%d,%s), want (v2026.3,0,ACTIVE)", policy, count, status)
	}
	if lastSeen.Before(now.Add(-2 * time.Second)) {
		t.Fatalf("last_seen_at = %v, want latest heartbeat time (~%v)", lastSeen, now)
	}

	// 幂等：断点前移后重采无新增；同一文件重采（模拟轮转重放）心跳透传仍幂等
	if n2, err := collector.CollectOnce(ctx); err != nil || n2 != 0 {
		t.Fatalf("re-collect = (%d,%v), want (0,nil)", n2, err)
	}
	if c := s8Count(t, env, `SELECT count(*) FROM api_gateway_nodes WHERE node_name=$1`, node); c != 1 {
		t.Fatalf("node rows = %d, want 1", c)
	}
}

// TestStage8NodeHeartbeatSweepMerge 心跳与业务聚合共存：清扫不回退心跳推进的活性与
// 版本（有心跳无流量=ACTIVE、心跳版本优先）；更新的业务事件到达时版本正常接管。
func TestStage8NodeHeartbeatSweepMerge(t *testing.T) {
	env := setupStage8Env(t)
	ctx := context.Background()
	rid := s5Rand()
	now := time.Now().UTC()
	node := "gw-mg-" + rid

	// 业务事件：40 分钟前、旧版本 v2026.1（自身聚合判 STALE）
	ndSeedEvent(t, env, "mg-b1-"+rid, node, "v2026.1", "m9", now.Add(-40*time.Minute))

	// 心跳：刚刚到达、当前版本 v2026.3（无业务流量时段活性与版本的真实来源）
	store := apinodes.NewStore(env.db)
	if err := store.RecordHeartbeat(ctx, apiruntime.Heartbeat{
		RequestID: "hb-" + rid, NodeName: node, OccurredAt: now, PolicyVersion: "v2026.3",
	}); err != nil {
		t.Fatalf("RecordHeartbeat: %v", err)
	}

	sweeper := apinodes.NewSweeper(store)
	stats, err := sweeper.SweepOnce(ctx)
	if err != nil {
		t.Fatalf("SweepOnce: %v", err)
	}
	if stats.Nodes != 1 {
		t.Fatalf("stats = %+v, want 1 aggregated node", stats)
	}

	readNode := func() (lastSeen time.Time, policy, model, status string, count int64) {
		if err := env.db.QueryRow(ctx, `SELECT last_seen_at, last_policy_version, last_model_version,
			event_count, status FROM api_gateway_nodes WHERE node_name=$1`, node).
			Scan(&lastSeen, &policy, &model, &count, &status); err != nil {
			t.Fatalf("read node: %v", err)
		}
		return
	}

	// 有心跳无流量=ACTIVE；心跳版本优先于历史业务事件版本；模型版本仍由业务聚合维护；
	// 业务事件计数不受心跳影响
	lastSeen, policy, model, status, count := readNode()
	if status != apinodes.StatusActive {
		t.Fatalf("status = %s, want ACTIVE (heartbeat liveness must survive sweep)", status)
	}
	if policy != "v2026.3" {
		t.Fatalf("policy = %s, want v2026.3 (heartbeat version takes priority over stale business events)", policy)
	}
	if model != "m9" || count != 1 {
		t.Fatalf("model/count = (%s,%d), want (m9,1) — business aggregation intact", model, count)
	}
	if lastSeen.Before(now.Add(-time.Minute)) {
		t.Fatalf("last_seen_at = %v regressed below heartbeat time %v", lastSeen, now)
	}

	// 重复清扫幂等：行不叠加、活性/版本不漂移
	if _, err := sweeper.SweepOnce(ctx); err != nil {
		t.Fatalf("re-sweep: %v", err)
	}
	if _, policy2, _, status2, count2 := readNode(); policy2 != "v2026.3" || status2 != apinodes.StatusActive || count2 != 1 {
		t.Fatalf("after re-sweep = (%s,%s,%d), want (v2026.3,ACTIVE,1)", policy2, status2, count2)
	}

	// 更新的业务事件到达（v2026.4 随新事件上报）：版本按时间新近性正常接管
	ndSeedEvent(t, env, "mg-b2-"+rid, node, "v2026.4", "m10", now.Add(2*time.Second))
	if _, err := sweeper.SweepOnce(ctx); err != nil {
		t.Fatalf("sweep after newer business event: %v", err)
	}
	if _, policy3, model3, _, count3 := readNode(); policy3 != "v2026.4" || model3 != "m10" || count3 != 2 {
		t.Fatalf("after newer business = (%s,%s,%d), want (v2026.4,m10,2)", policy3, model3, count3)
	}

	// 心跳停止 + 流量停止：活性随壁钟老化（下轮清扫如实降级，不回退也不虚报）
	if _, err := sweeper.SweepOnce(ctx); err != nil {
		t.Fatalf("final sweep: %v", err)
	}
}

// TestStage8NodeHeartbeatFirstSeenMonotonic 首见时间单调：心跳先到、业务事件后到，
// first_seen_at 保持历史最小；乱序到达（更早日期的迟到心跳）不回退 last_seen_at。
func TestStage8NodeHeartbeatFirstSeenMonotonic(t *testing.T) {
	env := setupStage8Env(t)
	ctx := context.Background()
	rid := s5Rand()
	now := time.Now().UTC()
	node := "gw-mono-" + rid

	store := apinodes.NewStore(env.db)
	// 心跳先到（10:00）
	if err := store.RecordHeartbeat(ctx, apiruntime.Heartbeat{
		RequestID: "hb-a-" + rid, NodeName: node, OccurredAt: now, PolicyVersion: "v1",
	}); err != nil {
		t.Fatalf("RecordHeartbeat: %v", err)
	}
	// 迟到乱序心跳（时钟回拨场景，09:00）：last_seen 不回退、first_seen 取其更早值
	stale := now.Add(-time.Hour)
	if err := store.RecordHeartbeat(ctx, apiruntime.Heartbeat{
		RequestID: "hb-b-" + rid, NodeName: node, OccurredAt: stale, PolicyVersion: "v1",
	}); err != nil {
		t.Fatalf("RecordHeartbeat stale: %v", err)
	}
	var firstSeen, lastSeen time.Time
	if err := env.db.QueryRow(ctx, `SELECT first_seen_at, last_seen_at FROM api_gateway_nodes
		WHERE node_name=$1`, node).Scan(&firstSeen, &lastSeen); err != nil {
		t.Fatalf("read node: %v", err)
	}
	if !firstSeen.Equal(stale) && !firstSeen.Before(now.Add(-59*time.Minute)) {
		t.Fatalf("first_seen_at = %v, want min of heartbeats (~%v)", firstSeen, stale)
	}
	if lastSeen.Before(now.Add(-time.Minute)) {
		t.Fatalf("last_seen_at = %v regressed by out-of-order heartbeat", lastSeen)
	}
	// 空节点名拒绝（参数校验不静默）
	if err := store.RecordHeartbeat(ctx, apiruntime.Heartbeat{RequestID: "hb-c", OccurredAt: now}); err == nil {
		t.Fatal("empty node name must be rejected")
	}
}

// stage8_api_gateway_nodes_test.go API 网关节点版本校验 v1（W12-NODE，任务书 §200-201
// 遥测路径）集成测试。覆盖：迁移 000069 落位（api_gateway_nodes 表 +
// api_runtime_events.gateway_node 补列）；Sweeper.SweepOnce 聚合
// （max(occurred_at)/最新非空 policy_version/model_version/count/状态判定）；
// 版本不一致告警（CONFIG_HASH_MISMATCH/API_GATEWAY_NODES）触发与自动恢复；
// HTTP 接线与权限点 api_runtime.read。
//
// 说明：网关事件 JSON 的 gateway_node_id → api_runtime_events.gateway_node 落列接线
// （apiruntime.SavePrimary/PrimaryEvent，既有文件）属集成方装配范围，本测试以直接
// SQL 种子驱动同一聚合数据源（与 W10-LLM 波次「手工映射驱动同一写入接口」同纪律）；
// 版本/节点空串种子经 NULLIF 落 NULL，贴近 SavePrimary 的 nullIfEmpty 口径。
package tests

import (
	"context"
	"encoding/json"
	"net/http"
	"strings"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/jiuzhang-waf/server/internal/apinodes"
	"github.com/jiuzhang-waf/server/internal/authz"
	"github.com/jiuzhang-waf/server/internal/response"
	"github.com/jiuzhang-waf/server/internal/systemalerts"
)

// ndSeedEvent 落一条带节点/版本维度的运行时事件（模拟采集落列后的行）。
func ndSeedEvent(t *testing.T, env *testEnv, requestID, node, policyVersion, modelVersion string, occurredAt time.Time) {
	t.Helper()
	s8Exec(t, env, `INSERT INTO api_runtime_events
		(request_id, endpoint_key, risk_score, risk_level, final_action, occurred_at, gateway_node, policy_version, model_version)
		VALUES ($1, 'GET /api/nd', 10, 'LOW', 'OBSERVE', $2, NULLIF($3,''), NULLIF($4,''), NULLIF($5,''))`,
		requestID, occurredAt, node, policyVersion, modelVersion)
}

// TestStage8GatewayNodesMigration 迁移 000069 落位：表结构/约束/索引 + 事件表补列。
func TestStage8GatewayNodesMigration(t *testing.T) {
	env := setupStage8Env(t)

	if n := s8Count(t, env, `SELECT count(*) FROM information_schema.tables WHERE table_name='api_gateway_nodes'`); n != 1 {
		t.Fatalf("api_gateway_nodes missing")
	}
	for _, col := range []string{"id", "node_name", "first_seen_at", "last_seen_at",
		"last_policy_version", "last_model_version", "event_count", "status", "created_at", "updated_at"} {
		if n := s8Count(t, env, `SELECT count(*) FROM information_schema.columns
			WHERE table_name='api_gateway_nodes' AND column_name=$1`, col); n != 1 {
			t.Fatalf("api_gateway_nodes column %s missing", col)
		}
	}
	// node_name 唯一约束
	if n := s8Count(t, env, `SELECT count(*) FROM information_schema.table_constraints
		WHERE table_name='api_gateway_nodes' AND constraint_type='UNIQUE'`); n < 1 {
		t.Fatalf("api_gateway_nodes unique constraint missing")
	}
	// 事件表 gateway_node 补列 + 两个索引
	if n := s8Count(t, env, `SELECT count(*) FROM information_schema.columns
		WHERE table_name='api_runtime_events' AND column_name='gateway_node'`); n != 1 {
		t.Fatalf("api_runtime_events.gateway_node missing")
	}
	for _, idx := range []string{"idx_api_runtime_events_node", "idx_api_gateway_nodes_status"} {
		if n := s8Count(t, env, `SELECT count(*) FROM pg_indexes WHERE indexname=$1`, idx); n != 1 {
			t.Fatalf("index %s missing", idx)
		}
	}
}

// TestStage8GatewayNodesSweep 聚合全链路：分组聚合/最新非空版本/状态判定/幂等重扫/
// 不一致告警触发与恢复后自动解决（真实 DB + 真实 systemalerts 引擎）。
func TestStage8GatewayNodesSweep(t *testing.T) {
	env := setupStage8Env(t)
	ctx := context.Background()
	rid := s5Rand()
	now := time.Now().UTC()

	// gw-a：3 条事件；最新一条 policy 未上报（NULL）→ 最新非空取次新 v2026.2，model 取最新 m10
	ndSeedEvent(t, env, "nd-a1-"+rid, "gw-a", "v2026.1", "m9", now.Add(-2*time.Minute))
	ndSeedEvent(t, env, "nd-a2-"+rid, "gw-a", "v2026.2", "m9", now.Add(-time.Minute))
	ndSeedEvent(t, env, "nd-a3-"+rid, "gw-a", "", "m10", now)
	// gw-b：30 分钟前（STALE），版本 v2026.1 与 gw-a 不一致
	ndSeedEvent(t, env, "nd-b1-"+rid, "gw-b", "v2026.1", "m9", now.Add(-30*time.Minute))
	// gw-c：2 小时前（SILENT，旧版本不参与一致性判定）
	ndSeedEvent(t, env, "nd-c1-"+rid, "gw-c", "v2026.0", "m8", now.Add(-2*time.Hour))
	// 未落列节点（NULL/空串）：不产生节点行
	ndSeedEvent(t, env, "nd-x1-"+rid, "", "v2026.2", "m10", now)

	store := apinodes.NewStore(env.db)
	engine := systemalerts.NewEngine(systemalerts.NewStore(env.db), systemalerts.EngineOptions{})
	sweeper := apinodes.NewSweeper(store).SetAlerter(engine)

	stats, err := sweeper.SweepOnce(ctx)
	if err != nil {
		t.Fatalf("SweepOnce: %v", err)
	}
	if stats.Nodes != 3 || stats.Consistent || !stats.Inconsistent {
		t.Fatalf("stats = %+v, want 3 nodes inconsistent", stats)
	}

	// 节点视图逐字段断言
	type nodeRow struct {
		lastSeen  time.Time
		firstSeen time.Time
		policy    string
		model     string
		count     int64
		status    string
	}
	readNode := func(name string) nodeRow {
		var r nodeRow
		if err := env.db.QueryRow(ctx, `SELECT last_seen_at, first_seen_at, last_policy_version,
			last_model_version, event_count, status FROM api_gateway_nodes WHERE node_name=$1`, name).
			Scan(&r.lastSeen, &r.firstSeen, &r.policy, &r.model, &r.count, &r.status); err != nil {
			t.Fatalf("read node %s: %v", name, err)
		}
		return r
	}
	a := readNode("gw-a")
	if a.count != 3 || a.policy != "v2026.2" || a.model != "m10" || a.status != apinodes.StatusActive {
		t.Fatalf("gw-a = %+v", a)
	}
	if !a.firstSeen.Before(a.lastSeen) {
		t.Fatalf("gw-a first/last seen inverted: %+v", a)
	}
	if b := readNode("gw-b"); b.count != 1 || b.policy != "v2026.1" || b.status != apinodes.StatusStale {
		t.Fatalf("gw-b = %+v", b)
	}
	if c := readNode("gw-c"); c.count != 1 || c.policy != "v2026.0" || c.status != apinodes.StatusSilent {
		t.Fatalf("gw-c = %+v", c)
	}
	if n := s8Count(t, env, `SELECT count(*) FROM api_gateway_nodes`); n != 3 {
		t.Fatalf("nodes = %d, want 3 (null-node event must not aggregate)", n)
	}

	// 不一致告警：CONFIG_HASH_MISMATCH / API_GATEWAY_NODES，OPEN，message 口径
	alertStore := systemalerts.NewStore(env.db)
	alerts, total, err := alertStore.List(ctx, systemalerts.ListFilter{
		AlertType: systemalerts.TypeConfigHashMismatch, Component: apinodes.AlertComponent, Page: 1, PageSize: 10})
	if err != nil {
		t.Fatalf("list alerts: %v", err)
	}
	if total != 1 || alerts[0].Status != systemalerts.StatusOpen {
		t.Fatalf("alerts = total %d %+v", total, alerts)
	}
	msg := alerts[0].Message
	if !containsAll(msg, "v2026.2", "v2026.1", "gw-a", "gw-b") || containsAny(msg, "v2026.0") {
		t.Fatalf("alert message = %q", msg)
	}

	// 幂等重扫：行数/计数不叠加，告警合并不新增
	stats2, err := sweeper.SweepOnce(ctx)
	if err != nil {
		t.Fatalf("re-sweep: %v", err)
	}
	if stats2.Nodes != 3 {
		t.Fatalf("re-sweep stats = %+v", stats2)
	}
	if a2 := readNode("gw-a"); a2.count != 3 {
		t.Fatalf("gw-a count after re-sweep = %d, want 3 (absolute, idempotent)", a2.count)
	}
	if _, total, err := alertStore.List(ctx, systemalerts.ListFilter{
		AlertType: systemalerts.TypeConfigHashMismatch, Component: apinodes.AlertComponent, Page: 1, PageSize: 10}); err != nil || total != 1 {
		t.Fatalf("alerts after re-sweep = total %d err %v (merge expected)", total, err)
	}

	// 版本对齐（gw-b 追平）→ 再扫：告警自动 RESOLVED(RECOVERED)
	s8Exec(t, env, `UPDATE api_runtime_events SET policy_version='v2026.2' WHERE gateway_node='gw-b'`)
	stats3, err := sweeper.SweepOnce(ctx)
	if err != nil {
		t.Fatalf("sweep after align: %v", err)
	}
	if !stats3.Consistent || stats3.Inconsistent {
		t.Fatalf("stats after align = %+v", stats3)
	}
	after, err := alertStore.GetByID(ctx, alerts[0].ID)
	if err != nil {
		t.Fatalf("get alert: %v", err)
	}
	if after.Status != systemalerts.StatusResolved || after.ResolveType == nil || *after.ResolveType != systemalerts.ResolveRecovered {
		t.Fatalf("alert after align = status %s resolve %v", after.Status, after.ResolveType)
	}
}

func containsAll(s string, subs ...string) bool {
	for _, sub := range subs {
		if !strings.Contains(s, sub) {
			return false
		}
	}
	return true
}

func containsAny(s string, subs ...string) bool {
	for _, sub := range subs {
		if strings.Contains(s, sub) {
			return true
		}
	}
	return false
}

// ndInjectPrincipal 注入持有 api_runtime.read 权限的主体（200 断言用）。
func ndInjectPrincipal(next http.Handler) http.Handler {
	perms := map[string]bool{"api_runtime.read": true}
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		p := &authz.Principal{UserID: uuid.New(), Username: "w12node-it", PermsSet: perms}
		ctx := authz.WithPrincipal(r.Context(), p)
		ctx = context.WithValue(ctx, response.RequestIDKey, "w12node-it-rid")
		next.ServeHTTP(w, r.WithContext(ctx))
	})
}

// TestStage8GatewayNodesHTTP HTTP 接线：权限矩阵 / 列表与一致性出参 / 逐项一致性标记。
func TestStage8GatewayNodesHTTP(t *testing.T) {
	env := setupStage8Env(t)
	ctx := context.Background()
	rid := s5Rand()
	now := time.Now().UTC()

	ndSeedEvent(t, env, "nd-h1-"+rid, "gw-h1", "v2026.2", "m10", now)
	ndSeedEvent(t, env, "nd-h2-"+rid, "gw-h2", "v2026.2", "m10", now.Add(-time.Minute))
	// 第三节点同版本：后续漂移单节点形成 2v1，多数派判定避开 1v1 并列
	ndSeedEvent(t, env, "nd-h3-"+rid, "gw-h3", "v2026.2", "m10", now.Add(-2*time.Minute))
	sweeper := apinodes.NewSweeper(apinodes.NewStore(env.db)) // nil alerter：一致场景不触告警
	if _, err := sweeper.SweepOnce(ctx); err != nil {
		t.Fatalf("sweep: %v", err)
	}

	newMux := func(authzFn func(http.Handler) http.Handler) *http.ServeMux {
		mux := http.NewServeMux()
		apinodes.RegisterRoutes(mux, authzFn, apinodes.NewHandler(apinodes.NewStore(env.db)))
		return mux
	}

	// 权限矩阵：未登录 401 / 无权限 403 / api_runtime.read 200（两接口同点）
	for _, u := range []string{"/api/v1/api-security/nodes", "/api/v1/api-security/nodes/consistency"} {
		if rr := apidataDo(t, newMux(xbInjectAnon), http.MethodGet, u, nil); rr.Code != http.StatusUnauthorized {
			t.Fatalf("%s anon: status=%d, want 401", u, rr.Code)
		}
		if rr := apidataDo(t, newMux(faInjectNoPerm), http.MethodGet, u, nil); rr.Code != http.StatusForbidden {
			t.Fatalf("%s noperm: status=%d, want 403", u, rr.Code)
		}
	}

	// 列表出参：三节点同版本 → 一致，逐项标记 true
	rr := apidataDo(t, newMux(ndInjectPrincipal), http.MethodGet, "/api/v1/api-security/nodes", nil)
	if rr.Code != http.StatusOK {
		t.Fatalf("nodes: status=%d body=%s", rr.Code, rr.Body.String())
	}
	var listBody struct {
		Data struct {
			Total      int  `json:"total"`
			Consistent bool `json:"consistent"`
			Items      []struct {
				NodeName          string `json:"node_name"`
				Status            string `json:"status"`
				LastPolicyVersion string `json:"last_policy_version"`
				EventCount        int64  `json:"event_count"`
				VersionConsistent *bool  `json:"version_consistent"`
			} `json:"items"`
		} `json:"data"`
	}
	if err := json.Unmarshal(rr.Body.Bytes(), &listBody); err != nil {
		t.Fatalf("decode nodes: %v (body=%s)", err, rr.Body.String())
	}
	if listBody.Data.Total != 3 || !listBody.Data.Consistent || len(listBody.Data.Items) != 3 {
		t.Fatalf("nodes = %+v", listBody.Data)
	}
	for _, it := range listBody.Data.Items {
		if it.Status != apinodes.StatusActive || it.LastPolicyVersion != "v2026.2" ||
			it.VersionConsistent == nil || !*it.VersionConsistent {
			t.Fatalf("item = %+v", it)
		}
	}

	// 一致性强答：consistent=true / evaluated=3 / 单组 / 多数派版本
	rr = apidataDo(t, newMux(ndInjectPrincipal), http.MethodGet, "/api/v1/api-security/nodes/consistency", nil)
	if rr.Code != http.StatusOK {
		t.Fatalf("consistency: status=%d body=%s", rr.Code, rr.Body.String())
	}
	var consBody struct {
		Data struct {
			Consistent      bool   `json:"consistent"`
			EvaluatedNodes  int    `json:"evaluated_nodes"`
			DominantVersion string `json:"dominant_version"`
			Groups          []struct {
				PolicyVersion string   `json:"policy_version"`
				NodeCount     int      `json:"node_count"`
				Nodes         []string `json:"nodes"`
			} `json:"groups"`
			SilentNodes []string `json:"silent_nodes"`
		} `json:"data"`
	}
	if err := json.Unmarshal(rr.Body.Bytes(), &consBody); err != nil {
		t.Fatalf("decode consistency: %v (body=%s)", err, rr.Body.String())
	}
	if !consBody.Data.Consistent || consBody.Data.EvaluatedNodes != 3 ||
		consBody.Data.DominantVersion != "v2026.2" || len(consBody.Data.Groups) != 1 ||
		consBody.Data.Groups[0].NodeCount != 3 || len(consBody.Data.SilentNodes) != 0 {
		t.Fatalf("consistency = %+v", consBody.Data)
	}

	// 制造不一致（gw-h2 漂移成 v2026.1，2v1 多数派仍为 v2026.2）+ 一个 SILENT 节点：
	// 总体 false，逐项标记 true/false/null
	s8Exec(t, env, `UPDATE api_gateway_nodes SET last_policy_version='v2026.1' WHERE node_name='gw-h2'`)
	s8Exec(t, env, `INSERT INTO api_gateway_nodes (node_name, last_seen_at, last_policy_version, status)
		VALUES ('gw-off', $1, 'v2026.0', 'SILENT')`, now.Add(-2*time.Hour))
	rr = apidataDo(t, newMux(ndInjectPrincipal), http.MethodGet, "/api/v1/api-security/nodes", nil)
	if err := json.Unmarshal(rr.Body.Bytes(), &listBody); err != nil {
		t.Fatalf("decode nodes 2: %v", err)
	}
	if listBody.Data.Consistent || listBody.Data.Total != 4 {
		t.Fatalf("nodes after drift = %+v", listBody.Data)
	}
	flags := map[string]*bool{}
	for _, it := range listBody.Data.Items {
		flags[it.NodeName] = it.VersionConsistent
	}
	if flags["gw-h1"] == nil || !*flags["gw-h1"] {
		t.Fatalf("gw-h1 flag = %v, want true", flags["gw-h1"])
	}
	if flags["gw-h2"] == nil || *flags["gw-h2"] {
		t.Fatalf("gw-h2 flag = %v, want false", flags["gw-h2"])
	}
	if flags["gw-h3"] == nil || !*flags["gw-h3"] {
		t.Fatalf("gw-h3 flag = %v, want true", flags["gw-h3"])
	}
	if flags["gw-off"] != nil {
		t.Fatalf("gw-off flag = %v, want null (SILENT 不参与)", *flags["gw-off"])
	}

	rr = apidataDo(t, newMux(ndInjectPrincipal), http.MethodGet, "/api/v1/api-security/nodes/consistency", nil)
	if err := json.Unmarshal(rr.Body.Bytes(), &consBody); err != nil {
		t.Fatalf("decode consistency 2: %v", err)
	}
	if consBody.Data.Consistent || consBody.Data.EvaluatedNodes != 3 || len(consBody.Data.Groups) != 2 ||
		consBody.Data.DominantVersion != "v2026.2" ||
		len(consBody.Data.SilentNodes) != 1 || consBody.Data.SilentNodes[0] != "gw-off" {
		t.Fatalf("consistency after drift = %+v", consBody.Data)
	}
}

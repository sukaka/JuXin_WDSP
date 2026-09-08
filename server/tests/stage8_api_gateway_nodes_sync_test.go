// stage8_api_gateway_nodes_sync_test.go W18-SYNC 多节点发布扇出（任务书 §200 配置面
// 主动同步 v2）集成测试。覆盖：迁移 000074 落位（api_gateway_nodes 同步登记/结果列）；
// PATCH /nodes/{id} 登记编辑全链路（真实认证链 + 权限点 api_policy.publish +
// 地址校验 + 操作审计落 operation_audits）；GET /nodes 带出 last_sync_* 读模型；
// Publisher.SyncConfigToNodes 扇出（真实 DB + 假 Caddy Admin httptest + 真实
// systemalerts 引擎告警）：成功逐节点回填 / 部分失败不阻断 / 哈希不一致 /
// 地址校验拦截 / 无次要节点零变化。
package tests

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/jiuzhang-waf/server/internal/apinodes"
	"github.com/jiuzhang-waf/server/internal/audits"
	"github.com/jiuzhang-waf/server/internal/authz"
	"github.com/jiuzhang-waf/server/internal/gatewayconfig"
	"github.com/jiuzhang-waf/server/internal/response"
	"github.com/jiuzhang-waf/server/internal/systemalerts"
)

// ndsSeedNode 落一条节点行（同步登记测试种子）。
func ndsSeedNode(t *testing.T, env *testEnv, name string) uuid.UUID {
	t.Helper()
	var id uuid.UUID
	if err := env.db.QueryRow(context.Background(), `
INSERT INTO api_gateway_nodes (node_name, last_seen_at, status)
VALUES ($1, now(), 'ACTIVE') RETURNING id`, name).Scan(&id); err != nil {
		t.Fatalf("seed node: %v", err)
	}
	return id
}

// TestStage8GatewayNodeSyncMigration 迁移 000074 落位：六列存在且空值口径正确
// （text 列 NOT NULL 默认 ”，sync_enabled 默认 FALSE，last_sync_at/version_id 可空）。
func TestStage8GatewayNodeSyncMigration(t *testing.T) {
	env := setupStage8Env(t)

	cols := map[string]string{ // 列名 → is_nullable
		"admin_addr":           "NO",
		"sync_enabled":         "NO",
		"last_sync_at":         "YES",
		"last_sync_result":     "NO",
		"last_sync_error":      "NO",
		"last_sync_version_id": "YES",
	}
	for col, nullable := range cols {
		var got string
		if err := env.db.QueryRow(context.Background(), `
SELECT is_nullable FROM information_schema.columns
WHERE table_name='api_gateway_nodes' AND column_name=$1`, col).Scan(&got); err != nil {
			t.Fatalf("column %s missing: %v", col, err)
		}
		if got != nullable {
			t.Fatalf("column %s is_nullable = %s, want %s", col, got, nullable)
		}
	}
	// 默认值：新行 sync_enabled=FALSE、admin_addr/result/error 为 ''
	var enabled bool
	var addr, result, syncErr string
	var syncAt *time.Time
	var versionID *uuid.UUID
	if err := env.db.QueryRow(context.Background(), `
INSERT INTO api_gateway_nodes (node_name) VALUES ('nds-defaults')
RETURNING sync_enabled, admin_addr, last_sync_result, last_sync_error, last_sync_at, last_sync_version_id`).
		Scan(&enabled, &addr, &result, &syncErr, &syncAt, &versionID); err != nil {
		t.Fatalf("insert default row: %v", err)
	}
	if enabled || addr != "" || result != "" || syncErr != "" || syncAt != nil || versionID != nil {
		t.Fatalf("defaults = enabled %v addr %q result %q err %q at %v version %v",
			enabled, addr, result, syncErr, syncAt, versionID)
	}
}

// TestStage8GatewayNodeSyncRegistrationHTTP 登记编辑全链路：真实认证链 PATCH →
// 地址校验 / DB 落库 / 操作审计 / GET /nodes 带出登记与同步结果读模型。
func TestStage8GatewayNodeSyncRegistrationHTTP(t *testing.T) {
	env := setupStage8Env(t)
	rid := s5Rand()
	nodeID := ndsSeedNode(t, env, "nds-reg-"+rid)
	// SECURITY_ADMIN 持有 api_policy.publish（迁移 000019 种子口径）
	cookies, csrf := env.s5Login(t, "s8nds", "SECURITY_ADMIN")
	path := "/api/v1/api-security/nodes/" + nodeID.String()

	// SYSTEM_ADMIN（000100 后 API 防护组整体移交，无 api_policy.publish）写操作 403 PERMISSION_DENIED
	roCookies, roCSRF := env.login(t, "test_sysadmin", env.adminPwd)
	resp := env.do(t, http.MethodPatch, path, `{"sync_enabled":true}`, roCookies, roCSRF)
	if resp.StatusCode != http.StatusForbidden {
		t.Fatalf("read-only role: status = %d, want 403", resp.StatusCode)
	}
	var roResp apiResp
	readJSON(t, resp, &roResp)
	if roResp.Code != "PERMISSION_DENIED" {
		t.Fatalf("read-only role: code = %q, want PERMISSION_DENIED", roResp.Code)
	}

	// 公网地址拦截 400
	resp = env.do(t, http.MethodPatch, path, `{"admin_addr":"http://8.8.8.8:2019"}`, cookies, csrf)
	if resp.StatusCode != http.StatusBadRequest {
		t.Fatalf("public addr: status = %d, want 400", resp.StatusCode)
	}
	resp.Body.Close()

	// 合法登记 200（内网 http 地址 + 开启扇出）
	resp = env.do(t, http.MethodPatch, path, `{"admin_addr":"http://10.9.8.7:2019","sync_enabled":true}`, cookies, csrf)
	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(resp.Body)
		t.Fatalf("register: status = %d body=%s", resp.StatusCode, body)
	}
	resp.Body.Close()

	// DB 落库
	var addr string
	var enabled bool
	if err := env.db.QueryRow(context.Background(),
		`SELECT admin_addr, sync_enabled FROM api_gateway_nodes WHERE id=$1`, nodeID).Scan(&addr, &enabled); err != nil {
		t.Fatalf("read node: %v", err)
	}
	if addr != "http://10.9.8.7:2019" || !enabled {
		t.Fatalf("registration = addr %q enabled %v", addr, enabled)
	}

	// 未登录写操作：真实链路下 CSRF 层先于鉴权拦截（403 CSRF_INVALID，写方法统一语义）
	resp = env.do(t, http.MethodPatch, path, `{"sync_enabled":false}`, nil, "")
	if resp.StatusCode != http.StatusForbidden {
		t.Fatalf("anon: status = %d, want 403 (CSRF layer)", resp.StatusCode)
	}
	var anonResp apiResp
	readJSON(t, resp, &anonResp)
	if anonResp.Code != "CSRF_INVALID" {
		t.Fatalf("anon: code = %q, want CSRF_INVALID", anonResp.Code)
	}

	// GET /nodes 列表带出登记列（同步结果列默认空）
	resp = env.get(t, "/api/v1/api-security/nodes", cookies)
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("nodes: status = %d", resp.StatusCode)
	}
	var listBody struct {
		Data struct {
			Items []struct {
				ID              uuid.UUID  `json:"id"`
				AdminAddr       string     `json:"admin_addr"`
				SyncEnabled     bool       `json:"sync_enabled"`
				LastSyncAt      *time.Time `json:"last_sync_at"`
				LastSyncResult  string     `json:"last_sync_result"`
				LastSyncVersion *uuid.UUID `json:"last_sync_version_id"`
			} `json:"items"`
		} `json:"data"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&listBody); err != nil {
		resp.Body.Close()
		t.Fatalf("decode nodes: %v", err)
	}
	resp.Body.Close()
	var found bool
	for _, it := range listBody.Data.Items {
		if it.ID == nodeID {
			found = true
			if it.AdminAddr != "http://10.9.8.7:2019" || !it.SyncEnabled ||
				it.LastSyncAt != nil || it.LastSyncResult != "" || it.LastSyncVersion != nil {
				t.Fatalf("node item = %+v", it)
			}
		}
	}
	if !found {
		t.Fatalf("registered node not in list")
	}

	// 操作审计：经生产同款装配（SetAudits 注入真实 audits.Service；app.go 装配
	// 属集成方范围，此处复刻同一接线）PATCH → 审计落 operation_audits。
	auditHandler := apinodes.NewHandler(apinodes.NewStore(env.db)).SetAudits(audits.NewService(env.db))
	mux := http.NewServeMux()
	apinodes.RegisterRoutes(mux, ndsInjectPublish, auditHandler)
	req := httptest.NewRequest(http.MethodPatch, path, strings.NewReader(`{"sync_enabled":false}`))
	req.Header.Set("Content-Type", "application/json")
	rr := httptest.NewRecorder()
	mux.ServeHTTP(rr, req)
	if rr.Code != http.StatusOK {
		t.Fatalf("audit-wired patch: status = %d body=%s", rr.Code, rr.Body.String())
	}
	if n := s8Count(t, env, `SELECT count(*) FROM operation_audits
		WHERE module='api_security' AND action='update' AND object_type='api_gateway_node'
		AND object_id=$1 AND username='w18sync-it'
		AND before_summary LIKE '%"sync_enabled":true%' AND after_summary LIKE '%"sync_enabled":false%'
		AND result='SUCCESS' AND risk_level='MEDIUM'`,
		nodeID.String()); n != 1 {
		t.Fatalf("audit rows = %d, want 1", n)
	}
}

// ndsInjectPublish 注入持有 api_policy.publish 权限的主体（审计接线 PATCH 用）。
func ndsInjectPublish(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		p := &authz.Principal{UserID: uuid.New(), Username: "w18sync-it",
			PermsSet: map[string]bool{apinodes.PermPolicyPublish: true}}
		ctx := authz.WithPrincipal(r.Context(), p)
		ctx = context.WithValue(ctx, response.RequestIDKey, "w18sync-it-rid")
		next.ServeHTTP(w, r.WithContext(ctx))
	})
}

// ---------- 扇出集成（真实 DB + 假 Caddy Admin + 真实告警引擎） ----------

// ndsFakeCaddy 假 Caddy Admin（/load 存原文；/config/ 返回 loaded 或 drift 覆盖）。
type ndsFakeCaddy struct {
	mu       sync.Mutex
	loaded   string
	loadCode int
	drift    string
}

func (f *ndsFakeCaddy) server(t *testing.T) *httptest.Server {
	t.Helper()
	mux := http.NewServeMux()
	mux.HandleFunc("POST /load", func(w http.ResponseWriter, r *http.Request) {
		body, _ := io.ReadAll(r.Body)
		f.mu.Lock()
		code := f.loadCode
		if code == 0 {
			f.loaded = string(body)
		}
		f.mu.Unlock()
		if code != 0 {
			http.Error(w, `{"error":"load rejected"}`, code)
			return
		}
		w.WriteHeader(http.StatusOK)
	})
	mux.HandleFunc("GET /config/", func(w http.ResponseWriter, r *http.Request) {
		f.mu.Lock()
		out := f.loaded
		if f.drift != "" {
			out = f.drift
		}
		f.mu.Unlock()
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(out))
	})
	srv := httptest.NewServer(mux)
	t.Cleanup(srv.Close)
	return srv
}

// engineSyncAlerter 真实告警引擎适配 gatewayconfig.SyncAlerter（同 app 装配片段口径）。
type engineSyncAlerter struct{ e *systemalerts.Engine }

func (a engineSyncAlerter) NotifyFailure(ctx context.Context, alertType, component, title, message string) error {
	_, err := a.e.NotifyFailure(ctx, alertType, component, title, message)
	return err
}

// ndsSyncRow 读取节点同步结果列。
type ndsSyncRow struct {
	result    string
	errMsg    string
	syncAt    *time.Time
	versionID *uuid.UUID
}

func ndsReadSync(t *testing.T, env *testEnv, nodeID uuid.UUID) ndsSyncRow {
	t.Helper()
	var r ndsSyncRow
	if err := env.db.QueryRow(context.Background(), `
SELECT last_sync_result, last_sync_error, last_sync_at, last_sync_version_id
FROM api_gateway_nodes WHERE id=$1`, nodeID).
		Scan(&r.result, &r.errMsg, &r.syncAt, &r.versionID); err != nil {
		t.Fatalf("read sync row: %v", err)
	}
	return r
}

func ndsNewPublisher(env *testEnv, t *testing.T) *gatewayconfig.Publisher {
	t.Helper()
	p := gatewayconfig.NewPublisher(nil, nil, nil, nil, "/nonexistent-admin.sock", t.TempDir(), nil, nil)
	p.SetNodeSyncStore(apinodes.NewStore(env.db))
	p.SetSyncAlerter(engineSyncAlerter{e: systemalerts.NewEngine(systemalerts.NewStore(env.db), systemalerts.EngineOptions{})})
	return p
}

const ndsFanoutConfig = `{"admin":{"listen":"unix//run/caddy.sock"},"apps":{"http":{"servers":{"s0":{}}}}}`

// ndsRegister 登记节点同步目标（直接 SQL，绕开 HTTP 以便指向 httptest 回环端口）。
func ndsRegister(t *testing.T, env *testEnv, nodeID uuid.UUID, addr string, enabled bool) {
	t.Helper()
	s8Exec(t, env, `UPDATE api_gateway_nodes SET admin_addr=$2, sync_enabled=$3 WHERE id=$1`, nodeID, addr, enabled)
}

// TestStage8GatewayNodeSyncFanout 扇出全链路：成功逐节点回填 last_sync_*（含版本）；
// 部分失败不阻断（失败节点 FAILED + 真实告警落 system_alerts，其余节点 SUCCESS）；
// 哈希不一致 HASH_MISMATCH + CONFIG_HASH_MISMATCH 告警；非法地址推送前拦截；
// 无次要节点时调用零变化。
func TestStage8GatewayNodeSyncFanout(t *testing.T) {
	env := setupStage8Env(t)
	ctx := context.Background()
	rid := s5Rand()
	versionID := uuid.New() // last_sync_version_id 无外键（版本语义为「尝试过的版本」引用）

	t.Run("无次要节点零变化", func(t *testing.T) {
		p := ndsNewPublisher(env, t)
		p.SyncConfigToNodes(ctx, ndsFanoutConfig, versionID)
		if n := s8Count(t, env, `SELECT count(*) FROM api_gateway_nodes WHERE last_sync_at IS NOT NULL`); n != 0 {
			t.Fatalf("synced rows = %d, want 0", n)
		}
	})

	// 三节点：A 正常 / B /load 拒绝 / C 哈希漂移；另有一个未开启扇出的节点不应被触碰
	fakeA := &ndsFakeCaddy{}
	srvA := fakeA.server(t)
	fakeB := &ndsFakeCaddy{loadCode: 500}
	srvB := fakeB.server(t)
	fakeC := &ndsFakeCaddy{drift: `{"apps":{"http":{"servers":{"other":{}}}}}`}
	srvC := fakeC.server(t)

	nodeA := ndsSeedNode(t, env, "nds-a-"+rid)
	nodeB := ndsSeedNode(t, env, "nds-b-"+rid)
	nodeC := ndsSeedNode(t, env, "nds-c-"+rid)
	nodeOff := ndsSeedNode(t, env, "nds-off-"+rid)
	nodeBad := ndsSeedNode(t, env, "nds-bad-"+rid)
	ndsRegister(t, env, nodeA, srvA.URL, true)
	ndsRegister(t, env, nodeB, srvB.URL, true)
	ndsRegister(t, env, nodeC, srvC.URL, true)
	ndsRegister(t, env, nodeBad, "http://8.8.8.8:2019", true) // DB 直改非法地址：推送前拦截
	// nodeOff 未开启：零触碰

	p := ndsNewPublisher(env, t)
	p.SyncConfigToNodes(ctx, ndsFanoutConfig, versionID)

	// A：SUCCESS + 原文推送（与发布内容一致，不重新构建）
	a := ndsReadSync(t, env, nodeA)
	if a.result != gatewayconfig.NodeSyncSuccess || a.errMsg != "" || a.syncAt == nil ||
		a.versionID == nil || *a.versionID != versionID {
		t.Fatalf("node A sync = %+v", a)
	}
	fakeA.mu.Lock()
	if fakeA.loaded != ndsFanoutConfig {
		t.Fatalf("node A loaded = %q, want exact fanout config", fakeA.loaded)
	}
	fakeA.mu.Unlock()

	// B：FAILED + 错误摘要 + CONFIG_PUBLISH_FAILED 告警
	b := ndsReadSync(t, env, nodeB)
	if b.result != gatewayconfig.NodeSyncFailed || b.errMsg == "" || b.versionID == nil || *b.versionID != versionID {
		t.Fatalf("node B sync = %+v", b)
	}
	if n := s8Count(t, env, `SELECT count(*) FROM system_alerts
		WHERE alert_type='CONFIG_PUBLISH_FAILED' AND component=$1
		AND title LIKE '%nds-b%'
		AND message LIKE '%`+versionID.String()+`%'`, gatewayconfig.SyncAlertComponent); n != 1 {
		t.Fatalf("publish-failed alerts = %d, want 1", n)
	}

	// C：HASH_MISMATCH + CONFIG_HASH_MISMATCH 告警
	c := ndsReadSync(t, env, nodeC)
	if c.result != gatewayconfig.NodeSyncHashMismatch || c.errMsg == "" {
		t.Fatalf("node C sync = %+v", c)
	}
	if n := s8Count(t, env, `SELECT count(*) FROM system_alerts
		WHERE alert_type='CONFIG_HASH_MISMATCH' AND component=$1 AND title LIKE '%nds-c%'`,
		gatewayconfig.SyncAlertComponent); n != 1 {
		t.Fatalf("hash-mismatch alerts = %d, want 1", n)
	}

	// Bad：地址非法 FAILED（推送前拦截，错误含地址原因）
	bad := ndsReadSync(t, env, nodeBad)
	if bad.result != gatewayconfig.NodeSyncFailed || !strings.Contains(bad.errMsg, "管理通道地址非法") {
		t.Fatalf("bad node sync = %+v", bad)
	}

	// Off：未开启扇出零触碰
	off := ndsReadSync(t, env, nodeOff)
	if off.result != "" || off.syncAt != nil {
		t.Fatalf("disabled node touched: %+v", off)
	}

	// 部分失败不阻断的反向验证：A/C/Bad 均有结果记录（顺序执行未中断）
	if a.syncAt == nil || c.syncAt == nil || bad.syncAt == nil {
		t.Fatalf("fanout interrupted: A %+v C %+v Bad %+v", a, c, bad)
	}
}

// TestStage8GatewayNodeSyncReadModel GET /nodes 带出 last_sync_*（同步结果读模型）。
func TestStage8GatewayNodeSyncReadModel(t *testing.T) {
	env := setupStage8Env(t)
	ctx := context.Background()
	rid := s5Rand()
	versionID := uuid.New()

	fake := &ndsFakeCaddy{}
	srv := fake.server(t)
	nodeID := ndsSeedNode(t, env, "nds-read-"+rid)
	ndsRegister(t, env, nodeID, srv.URL, true)

	p := ndsNewPublisher(env, t)
	p.SyncConfigToNodes(ctx, ndsFanoutConfig, versionID)

	// 000100 后 api_runtime.read 归安全管理员（系统管理员已移交 API 防护组）
	cookies, _ := env.s5Login(t, "s8ndr", "SECURITY_ADMIN")
	resp := env.get(t, "/api/v1/api-security/nodes", cookies)
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("nodes: status = %d", resp.StatusCode)
	}
	var listBody struct {
		Data struct {
			Items []struct {
				ID              uuid.UUID  `json:"id"`
				LastSyncAt      *time.Time `json:"last_sync_at"`
				LastSyncResult  string     `json:"last_sync_result"`
				LastSyncError   string     `json:"last_sync_error"`
				LastSyncVersion *uuid.UUID `json:"last_sync_version_id"`
			} `json:"items"`
		} `json:"data"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&listBody); err != nil {
		resp.Body.Close()
		t.Fatalf("decode: %v", err)
	}
	resp.Body.Close()
	var found bool
	for _, it := range listBody.Data.Items {
		if it.ID == nodeID {
			found = true
			if it.LastSyncResult != gatewayconfig.NodeSyncSuccess || it.LastSyncError != "" ||
				it.LastSyncAt == nil || it.LastSyncVersion == nil || *it.LastSyncVersion != versionID {
				t.Fatalf("read model item = %+v", it)
			}
		}
	}
	if !found {
		t.Fatalf("node not in list")
	}
}

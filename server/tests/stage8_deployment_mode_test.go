// WDSP 阶段B 部署模式配置化（server 侧）集成测试（docs/NETWORK_MODES_DESIGN.md §4.1）。
//
// 覆盖：applications.deployment_mode 列默认值与 CHECK 约束（迁移 000052，
// 000064 扩展四值）、创建/更新/详情/列表 API 的 deployment_mode 字段往返、
// 非法值 400（创建与更新路径）、更新审计沿用既有应用更新审计
// （module=applications / action=update / risk_level=HIGH）。
// MIRROR/TRANSPARENT 产品化行为见 stage8_mirror_transparent_test.go。
//
// 运行方式与 TestStage8 一致（无 PG/Valkey 凭据时 t.Skip）：
//
//	POSTGRES_PASSWORD=... VALKEY_PASSWORD=... go test ./tests -run TestStage8DeploymentMode -count=1
package tests

import (
	"context"
	"net/http"
	"strconv"
	"testing"
)

func TestStage8DeploymentMode(t *testing.T) {
	env := setupStage8Env(t)
	cookies, csrf := env.s5Login(t, "s8dm", "SECURITY_ADMIN")
	kw := "s8dm" + s5Rand()

	// ---------- 缺省创建：默认 REVERSE_PROXY ----------
	resp := env.post(t, "/api/v1/applications", `{"code":"`+kw+`-def","name":"默认模式"}`, cookies, csrf)
	result := s5OK(t, resp, "create app with default deployment_mode")
	if got := result.Data["deployment_mode"]; got != "REVERSE_PROXY" {
		t.Fatalf("default deployment_mode = %v, want REVERSE_PROXY", got)
	}
	defID, _ := result.Data["id"].(string)

	// ---------- 显式 ROUTED 创建：落库且响应可见 ----------
	resp = env.post(t, "/api/v1/applications",
		`{"code":"`+kw+`-rt","name":"路由牵引","deployment_mode":"ROUTED"}`, cookies, csrf)
	result = s5OK(t, resp, "create ROUTED app")
	if got := result.Data["deployment_mode"]; got != "ROUTED" {
		t.Fatalf("create ROUTED deployment_mode = %v, want ROUTED", got)
	}
	rtID, _ := result.Data["id"].(string)
	if n := s8Count(t, env,
		`SELECT count(*) FROM applications WHERE id = $1 AND deployment_mode = 'ROUTED'`, rtID); n != 1 {
		t.Fatal("ROUTED 未落库")
	}

	// ---------- 非法值：创建 400（四值枚举之外的词表） ----------
	for _, bad := range []string{"BRIDGE", "TAP", "routed"} {
		resp = env.post(t, "/api/v1/applications",
			`{"code":"`+kw+`-bad","name":"非法","deployment_mode":"`+bad+`"}`, cookies, csrf)
		s5Expect(t, resp, http.StatusBadRequest, "create with deployment_mode="+bad)
	}

	// ---------- 详情与列表均携带 deployment_mode ----------
	result = s5OK(t, env.get(t, "/api/v1/applications/"+rtID, cookies), "get app detail")
	if got := result.Data["deployment_mode"]; got != "ROUTED" {
		t.Fatalf("detail deployment_mode = %v, want ROUTED", got)
	}
	result = s5OK(t, env.get(t, "/api/v1/applications?keyword="+kw, cookies), "list apps")
	items, _ := result.Data["items"].([]interface{})
	if len(items) != 2 {
		t.Fatalf("list items = %d, want 2", len(items))
	}
	for _, it := range items {
		m := it.(map[string]interface{})
		code, _ := m["code"].(string)
		want := "REVERSE_PROXY"
		if code == kw+"-rt" {
			want = "ROUTED"
		}
		if got := m["deployment_mode"]; got != want {
			t.Fatalf("list item %s deployment_mode = %v, want %s", code, got, want)
		}
	}

	// ---------- 更新为 ROUTED：生效 + 高风险审计 ----------
	defApp := s5OK(t, env.get(t, "/api/v1/applications/"+defID, cookies), "get default app")
	version := int(s5Num(t, defApp.Data, "version"))
	resp = env.do(t, http.MethodPut, "/api/v1/applications/"+defID,
		`{"name":"默认模式","version":`+strconv.Itoa(version)+`,"deployment_mode":"ROUTED"}`, cookies, csrf)
	result = s5OK(t, resp, "update deployment_mode to ROUTED")
	if got := result.Data["deployment_mode"]; got != "ROUTED" {
		t.Fatalf("after update deployment_mode = %v, want ROUTED", got)
	}
	if n := s8Count(t, env,
		`SELECT count(*) FROM applications WHERE id = $1 AND deployment_mode = 'ROUTED'`, defID); n != 1 {
		t.Fatal("更新 ROUTED 未落库")
	}
	if n := s8Count(t, env,
		`SELECT count(*) FROM operation_audits WHERE module = 'applications' AND action = 'update'
		   AND risk_level = 'HIGH' AND object_id = $1`, defID); n < 1 {
		t.Fatal("缺少 deployment_mode 变更的高风险审计")
	}

	// ---------- 更新非法值 400；空串不修改 ----------
	defApp = s5OK(t, env.get(t, "/api/v1/applications/"+defID, cookies), "get routed app")
	version = int(s5Num(t, defApp.Data, "version"))
	resp = env.do(t, http.MethodPut, "/api/v1/applications/"+defID,
		`{"name":"默认模式","version":`+strconv.Itoa(version)+`,"deployment_mode":"BRIDGE"}`, cookies, csrf)
	s5Expect(t, resp, http.StatusBadRequest, "update with invalid deployment_mode")
	resp = env.do(t, http.MethodPut, "/api/v1/applications/"+defID,
		`{"name":"默认模式","version":`+strconv.Itoa(version)+`}`, cookies, csrf)
	result = s5OK(t, resp, "update without deployment_mode keeps value")
	if got := result.Data["deployment_mode"]; got != "ROUTED" {
		t.Fatalf("empty deployment_mode must not modify, got %v", got)
	}

	// ---------- CHECK 约束：绕过应用层直写非法值必须失败 ----------
	_, err := env.db.Exec(context.Background(),
		`UPDATE applications SET deployment_mode = 'BRIDGE' WHERE id = $1`, defID)
	if err == nil {
		t.Fatal("CHECK 约束未拦截非法 deployment_mode")
	}
}

// stage_exceptions_p0_test.go WDSP P0-04 决策范围例外 server 侧接口/存储测试
// （任务书 docs/tasks/wdsp-p0/P0-04_DECISION_SCOPED_EXCEPTIONS.md §10 验收矩阵
// EXC-04/07/12/13；冻结契约 S4_DESIGN_BASELINE.md §3/§4/§5/§8/§9）。
// 真实 PG/Valkey（未设置环境或 -short 即 skip）。覆盖：
//   - 迁移 000130 扩展列存在；
//   - EXC-04 不支持动作（LOG_ONLY/ADJUST_SCORE）：可保存为 DRAFT+NEEDS_REVIEW，
//     启用 400 UNSUPPORTED_ACTION 且带迁移预览；预览 unsupported 段列出迁移预览；
//   - 引擎×动作矩阵（API+WAF 动作 / WAF+OBSERVE_RULE 保存层 400 字段级错误）；
//   - EXC-12 乐观锁：陈旧 version 更新 409、预览 expected_version 不符 409、
//     改动后 compiled_fingerprint 变化；
//   - 预览契约 §8 全字段（含 estimated_match_count 恒 null、protected_modules_unchanged、
//     required_publish_targets 为绑定应用编码）；
//   - EXC-07 事件→草稿：绑定真实事件（application_id/methods/uri_exact 无 query/
//     rule_ids/source_event_id），VALID 草稿可启用；缺应用+缺规则证据草稿
//     NEEDS_REVIEW 且启用 400；
//   - EXC-13 AUDIT_ADMIN 无 exceptions.manage → create/enable/preview 403；
//   - provider 直测：ListForPublish 稳定 marker/effect ID（8000001+2i）、到期跳过、
//     未来生效照常下发、NEEDS_REVIEW/DISABLED 排除、编译失败 fail-hard、容量 2000 上限、
//     REMOVE_RULE_TAG 经规则目录展开冻结；ListAPIExceptionsForGuard 按应用编码下发。
// 真实网关行为（EXC-01/02/03/05/08）由 gateway/corazasemantics 实测锁定，不在本文件。
package tests

import (
	"context"
	"fmt"
	"net/http"
	"strings"
	"testing"

	"github.com/google/uuid"
	"github.com/jiuzhang-waf/server/internal/exceptions"
)

// p0ExcURL 例外接口路径前缀。
const p0ExcURL = "/api/v1/exceptions"

// p0CreateException 创建例外并返回响应 data（断言 200）。
func p0CreateException(t *testing.T, env *testEnv, cookies []*http.Cookie, csrf, body string) map[string]interface{} {
	t.Helper()
	resp := env.post(t, p0ExcURL, body, cookies, csrf)
	result := s5OK(t, resp, "create exception")
	return result.Data
}

// p0ExcField 从创建/详情响应 data 中取 exception 对象。
func p0ExcField(t *testing.T, data map[string]interface{}) map[string]interface{} {
	t.Helper()
	exc, ok := data["exception"].(map[string]interface{})
	if !ok {
		t.Fatalf("data.exception missing: %+v", data)
	}
	return exc
}

// p0GetException 查询例外详情。
func p0GetException(t *testing.T, env *testEnv, cookies []*http.Cookie, id string) map[string]interface{} {
	t.Helper()
	result := s5OK(t, env.get(t, p0ExcURL+"/"+id, cookies), "get exception")
	return p0ExcField(t, result.Data)
}

// TestP0ExceptionMigrationColumns 迁移 000130 的七条扩展列存在且默认值正确。
func TestP0ExceptionMigrationColumns(t *testing.T) {
	env := setupTestEnv(t)
	ctx := context.Background()
	for _, col := range []string{"target_engine", "api_rule_refs", "resolved_rule_ids",
		"source_event_id", "validation_status", "compiled_fingerprint", "unsupported_reasons"} {
		var n int
		if err := env.db.QueryRow(ctx, `SELECT count(*) FROM information_schema.columns
WHERE table_name='exception_policies' AND column_name=$1`, col).Scan(&n); err != nil || n != 1 {
			t.Fatalf("exception_policies.%s missing: n=%d err=%v", col, n, err)
		}
	}
	// 历史行标记语义：VALID 默认（迁移内 UPDATE 负责 NEEDS_REVIEW 打标）
	var def string
	if err := env.db.QueryRow(ctx, `SELECT column_default FROM information_schema.columns
WHERE table_name='exception_policies' AND column_name='validation_status'`).Scan(&def); err != nil || !strings.Contains(def, "VALID") {
		t.Errorf("validation_status default = %q, want VALID (err %v)", def, err)
	}
}

// TestP0ExceptionUnsupportedActionGate EXC-04：LOG_ONLY/ADJUST_SCORE 可保存为
// DRAFT+NEEDS_REVIEW（不静默删除、不静默降级），启用 400 UNSUPPORTED_ACTION 且
// field_errors 携带迁移预览；预览 unsupported 段同样列出迁移预览。
func TestP0ExceptionUnsupportedActionGate(t *testing.T) {
	env := setupTestEnv(t)
	cookies, csrf := env.s5Login(t, "p0exc_unsup", "SECURITY_ADMIN")
	appID := jwtTestApp(t, env, cookies, csrf, "p0unsup-"+s5Rand())

	for _, action := range []string{"LOG_ONLY", "ADJUST_SCORE"} {
		data := p0CreateException(t, env, cookies, csrf, fmt.Sprintf(
			`{"name":"legacy-%s","scope_type":"APPLICATION","application_id":%q,"uri_exact":"/api/orders",`+
				`"methods":["POST"],"rule_ids":[942100],"exception_action":%q}`, action, appID, action))
		exc := p0ExcField(t, data)
		if exc["status"] != "DRAFT" {
			t.Errorf("%s: new exception status = %v, want DRAFT（P0-04 起创建默认草稿）", action, exc["status"])
		}
		if exc["validation_status"] != "NEEDS_REVIEW" {
			t.Errorf("%s: validation_status = %v, want NEEDS_REVIEW（不支持动作自动审查标记）", action, exc["validation_status"])
		}
		id, _ := exc["id"].(string)
		version := int(s5Num(t, exc, "version"))

		// 启用 → 400 + UNSUPPORTED_ACTION + 迁移预览
		resp := env.post(t, p0ExcURL+"/"+id+"/enable", ``, cookies, csrf)
		defer resp.Body.Close()
		if resp.StatusCode != http.StatusBadRequest {
			t.Fatalf("%s: enable status = %d, want 400, body: %s", action, resp.StatusCode, readBodyString(t, resp))
		}
		var errResp apiResp
		readJSON(t, resp, &errResp)
		if errResp.Code != "UNSUPPORTED_ACTION" {
			t.Errorf("%s: enable error code = %q, want UNSUPPORTED_ACTION", action, errResp.Code)
		}
		details, _ := errResp.Details.(map[string]interface{})
		fieldErrs, _ := details["field_errors"].([]interface{})
		if len(fieldErrs) == 0 {
			t.Fatalf("%s: enable 400 must carry details.field_errors: %+v", action, errResp)
		}
		// UNSUPPORTED_ACTION 与 NEEDS_REVIEW 自检可并存，遍历找 exception_action 条目
		var fe map[string]interface{}
		for _, raw := range fieldErrs {
			cand, _ := raw.(map[string]interface{})
			if cand["field"] == "exception_action" {
				fe = cand
				break
			}
		}
		if fe == nil || fe["code"] != "UNSUPPORTED_ACTION" {
			t.Errorf("%s: field_errors has no exception_action/UNSUPPORTED_ACTION entry: %+v", action, fieldErrs)
		}
		if msg, _ := fe["message"].(string); !strings.Contains(msg, "REMOVE_VAR_DETECTION") {
			t.Errorf("%s: migration preview must point to REMOVE_VAR_DETECTION: %q", action, msg)
		}

		// 预览（契约 §8 unsupported 段）：NEEDS_REVIEW + 迁移预览
		result := s5OK(t, env.post(t, p0ExcURL+"/"+id+"/preview",
			fmt.Sprintf(`{"expected_version":%d}`, version), cookies, csrf), "preview "+action)
		if result.Data["validation_status"] != "NEEDS_REVIEW" {
			t.Errorf("%s: preview validation_status = %v", action, result.Data["validation_status"])
		}
		unsupported, _ := result.Data["unsupported"].([]interface{})
		if len(unsupported) == 0 {
			t.Fatalf("%s: preview must list unsupported items: %+v", action, result.Data)
		}
		u0, _ := unsupported[0].(map[string]interface{})
		if u0["field_or_action"] != action {
			t.Errorf("%s: unsupported.field_or_action = %v", action, u0["field_or_action"])
		}
		if mp, _ := u0["migration_preview"].(string); !strings.Contains(mp, "REMOVE_VAR_DETECTION") {
			t.Errorf("%s: unsupported.migration_preview = %q", action, mp)
		}
	}
}

// TestP0ExceptionEngineActionMatrix 引擎×动作矩阵保存层字段级错误（不静默舍弃）。
func TestP0ExceptionEngineActionMatrix(t *testing.T) {
	env := setupTestEnv(t)
	cookies, csrf := env.s5Login(t, "p0exc_matrix", "SECURITY_ADMIN")
	appID := jwtTestApp(t, env, cookies, csrf, "p0matrix-"+s5Rand())

	// API 引擎 + WAF 动作 → 400 field_errors(exception_action)
	resp := env.post(t, p0ExcURL, fmt.Sprintf(
		`{"name":"api-waf-action","scope_type":"APPLICATION","application_id":%q,"uri_exact":"/api/orders",`+
			`"methods":["POST"],"target_engine":"API","api_rule_refs":[{"detector_id":"api_schema","rule_id":"body.name"}],`+
			`"exception_action":"REMOVE_RULE"}`, appID), cookies, csrf)
	s5Expect(t, resp, http.StatusBadRequest, "API engine with WAF action")

	// WAF 引擎 + OBSERVE_RULE → 400
	resp = env.post(t, p0ExcURL, fmt.Sprintf(
		`{"name":"waf-observe","scope_type":"APPLICATION","application_id":%q,"uri_exact":"/api/orders",`+
			`"methods":["POST"],"rule_ids":[942100],"exception_action":"OBSERVE_RULE"}`, appID), cookies, csrf)
	s5Expect(t, resp, http.StatusBadRequest, "WAF engine with OBSERVE_RULE")

	// API 引擎 + 未注册 detector（EXC-11：JWT/协议底线不可经例外跳过）→ 400
	resp = env.post(t, p0ExcURL, fmt.Sprintf(
		`{"name":"api-jwt","scope_type":"APPLICATION","application_id":%q,"uri_exact":"/api/orders",`+
			`"methods":["POST"],"target_engine":"API","exception_action":"OBSERVE_RULE",`+
			`"api_rule_refs":[{"detector_id":"jwt_verify","rule_id":"expired"}]}`, appID), cookies, csrf)
	s5Expect(t, resp, http.StatusBadRequest, "API exception targeting unregistered detector")

	// API 引擎 + OBSERVE_RULE + 合法引用 → 200 DRAFT VALID
	data := p0CreateException(t, env, cookies, csrf, fmt.Sprintf(
		`{"name":"api-observe","scope_type":"APPLICATION","application_id":%q,"uri_exact":"/api/orders",`+
			`"methods":["POST"],"target_engine":"API","exception_action":"OBSERVE_RULE",`+
			`"api_rule_refs":[{"detector_id":"api_schema","rule_id":"body.name","model_version":"v1"}]}`, appID))
	exc := p0ExcField(t, data)
	if exc["target_engine"] != "API" || exc["validation_status"] != "VALID" {
		t.Errorf("clean API exception = engine %v status %v, want API/VALID", exc["target_engine"], exc["validation_status"])
	}
	// API 例外可启用（不下发 SecLang，经 api_exceptions 段）
	id, _ := exc["id"].(string)
	result := s5OK(t, env.post(t, p0ExcURL+"/"+id+"/enable", ``, cookies, csrf), "enable API exception")
	enabled := p0ExcField(t, result.Data)
	if enabled["status"] != "ENABLED" {
		t.Errorf("API exception enable = %v, want ENABLED", enabled["status"])
	}
}

// TestP0ExceptionLifecyclePreviewPublish EXC-12 + 契约 §8：创建（policy_id 接线）
// → 预览版本门禁与全字段 → 启用 → 陈旧更新 409 → 更新后指纹变化 → 停用。
func TestP0ExceptionLifecyclePreviewPublish(t *testing.T) {
	env := setupTestEnv(t)
	cookies, csrf := env.s5Login(t, "p0exc_life", "SECURITY_ADMIN")
	appCode := "p0life-" + s5Rand()
	appID := jwtTestApp(t, env, cookies, csrf, appCode)
	policyID := uuid.NewString() // policy_id 列无 FK（预留作用域），仅验证接线不丢

	data := p0CreateException(t, env, cookies, csrf, fmt.Sprintf(
		`{"name":"精确例外","scope_type":"APPLICATION","application_id":%q,"policy_id":%q,`+
			`"domain":"shop.example.com","uri_exact":"/api/orders","methods":["post","get"],`+
			`"source_ips":["10.0.0.0/8"],"param_names":["comment"],"rule_ids":[942100],`+
			`"exception_action":"REMOVE_RULE","reason":"误报处置"}`, appID, policyID))
	exc := p0ExcField(t, data)
	id, _ := exc["id"].(string)
	version := int(s5Num(t, exc, "version"))
	if exc["status"] != "DRAFT" || exc["validation_status"] != "VALID" {
		t.Fatalf("full-dimension draft = %v/%v, want DRAFT/VALID", exc["status"], exc["validation_status"])
	}
	// policy_id 创建接线（旧实现 PUT/POST 丢 policy_id）
	if exc["policy_id"] != policyID {
		t.Errorf("policy_id = %v, want %s（创建接线）", exc["policy_id"], policyID)
	}
	fp0, _ := exc["compiled_fingerprint"].(string)
	if len(fp0) != 64 {
		t.Errorf("compiled_fingerprint = %q, want 64-hex sha256", fp0)
	}

	// 预览：版本不符 → 409
	s5Expect(t, env.post(t, p0ExcURL+"/"+id+"/preview",
		fmt.Sprintf(`{"expected_version":%d}`, version+99), cookies, csrf),
		http.StatusConflict, "preview with stale expected_version")

	// 预览：契约 §8 全字段
	result := s5OK(t, env.post(t, p0ExcURL+"/"+id+"/preview",
		fmt.Sprintf(`{"expected_version":%d}`, version), cookies, csrf), "preview")
	d := result.Data
	if d["validation_status"] != "VALID" {
		t.Errorf("preview validation_status = %v", d["validation_status"])
	}
	if v, ok := d["estimated_match_count"]; !ok || v != nil {
		t.Errorf("estimated_match_count must be present and null, got ok=%v v=%v", ok, v)
	}
	if v, ok := d["historical_sample_coverage"]; !ok || v != nil {
		t.Errorf("historical_sample_coverage must be present and null, got ok=%v v=%v", ok, v)
	}
	window, _ := d["effective_window"].(map[string]interface{})
	if window["half_open"] != true {
		t.Errorf("effective_window.half_open = %v, want true（半开区间）", window["half_open"])
	}
	scope, _ := d["normalized_scope"].(map[string]interface{})
	if methods, _ := scope["methods"].([]interface{}); len(methods) != 2 || methods[0] != "GET" || methods[1] != "POST" {
		t.Errorf("normalized_scope.methods = %v, want normalized [GET POST]", scope["methods"])
	}
	refs, _ := d["resolved_rule_refs"].([]interface{})
	foundRef := false
	for _, r := range refs {
		rm, _ := r.(map[string]interface{})
		if rm["engine"] == "WAF" && rm["rule_id"] == float64(942100) {
			foundRef = true
		}
	}
	if !foundRef {
		t.Errorf("resolved_rule_refs must contain WAF rule 942100: %v", refs)
	}
	modules, _ := d["protected_modules_unchanged"].([]interface{})
	foundJWT := false
	for _, m := range modules {
		if m == "JWT" {
			foundJWT = true
		}
	}
	if !foundJWT || len(modules) != 7 {
		t.Errorf("protected_modules_unchanged = %v, want 7 modules incl. JWT", modules)
	}
	targets, _ := d["required_publish_targets"].([]interface{})
	if len(targets) != 1 || targets[0] != appCode {
		t.Errorf("required_publish_targets = %v, want [%s]", targets, appCode)
	}
	if fp, _ := d["compiled_fingerprint"].(string); len(fp) != 64 {
		t.Errorf("preview compiled_fingerprint = %q", fp)
	}

	// 启用 → ENABLED + 版本推进 + 指纹落库
	result = s5OK(t, env.post(t, p0ExcURL+"/"+id+"/enable", ``, cookies, csrf), "enable")
	enabled := p0ExcField(t, result.Data)
	if enabled["status"] != "ENABLED" || int(s5Num(t, enabled, "version")) != version+1 {
		t.Errorf("enabled = %v v%v, want ENABLED v%d", enabled["status"], enabled["version"], version+1)
	}
	fp1, _ := enabled["compiled_fingerprint"].(string)
	if len(fp1) != 64 || fp1 == fp0 {
		t.Errorf("enable fingerprint must be recomputed with new version: %q vs %q", fp1, fp0)
	}

	// 陈旧版本更新 → 409（EXC-12 并发编辑）
	s5Expect(t, env.request(t, http.MethodPut, p0ExcURL+"/"+id, fmt.Sprintf(
		`{"name":"陈旧更新","scope_type":"APPLICATION","application_id":%q,"uri_exact":"/api/orders",`+
			`"methods":["GET"],"rule_ids":[942100],"exception_action":"REMOVE_RULE","version":%d}`, appID, version),
		cookies, csrf), http.StatusConflict, "update with stale version")

	// 正确版本更新（改目标名）→ 指纹变化（预览后草稿被改可检出）
	result = s5OK(t, env.request(t, http.MethodPut, p0ExcURL+"/"+id, fmt.Sprintf(
		`{"name":"精确例外v2","scope_type":"APPLICATION","application_id":%q,"policy_id":%q,`+
			`"domain":"shop.example.com","uri_exact":"/api/orders","methods":["GET","POST"],`+
			`"source_ips":["10.0.0.0/8"],"param_names":["other_field"],"rule_ids":[942100],`+
			`"exception_action":"REMOVE_RULE","version":%d}`, appID, policyID, version+1),
		cookies, csrf), "update with current version")
	updated := p0ExcField(t, result.Data)
	fp2, _ := updated["compiled_fingerprint"].(string)
	if fp2 == "" || fp2 == fp1 {
		t.Errorf("fingerprint must change after content+version change: %q vs %q", fp2, fp1)
	}
	if updated["policy_id"] != policyID {
		t.Errorf("PUT must persist policy_id: %v", updated["policy_id"])
	}

	// 停用
	s5Expect(t, env.post(t, p0ExcURL+"/"+id+"/disable", ``, cookies, csrf), http.StatusOK, "disable")
}

// TestP0ExceptionFromEventDraft EXC-07：事件→草稿绑定真实事件字段（可信源）；
// 缺应用/规则证据 → NEEDS_REVIEW 禁止启用。
func TestP0ExceptionFromEventDraft(t *testing.T) {
	env := setupTestEnv(t)
	ctx := context.Background()
	cookies, csrf := env.s5Login(t, "p0exc_evt", "SECURITY_ADMIN")
	appID := jwtTestApp(t, env, cookies, csrf, "p0evt-"+s5Rand())

	// 事件 1：绑定应用 + 规则匹配证据（URI 带 query——草稿 uri_exact 必须剔除）
	eventID := uuid.New()
	if _, err := env.db.Exec(ctx, `INSERT INTO security_events
(id, request_id, occurred_at, application_id, domain, client_ip, request_method, request_uri, request_path,
 attack_type, severity, action, rule_match_count)
VALUES ($1, $2, now(), $3, 'shop.example.com', '203.0.113.9'::inet, 'POST', '/api/orders?token=secret123',
 '/api/orders', 'SQL_INJECTION', 'HIGH', 'BLOCK', 1)`,
		eventID, "req-"+s5Rand(), uuid.MustParse(appID)); err != nil {
		t.Fatalf("insert event: %v", err)
	}
	if _, err := env.db.Exec(ctx, `INSERT INTO security_event_matches
(event_id, event_occurred_at, rule_id, rule_name)
VALUES ($1, (SELECT occurred_at FROM security_events WHERE id=$1), 942100, 'SQL Injection Attack')`,
		eventID); err != nil {
		t.Fatalf("insert match: %v", err)
	}

	result := s5OK(t, env.post(t,
		"/api/v1/security-events/"+eventID.String()+"/create-exception", ``, cookies, csrf), "create exception from event")
	excID, _ := result.Data["exception_id"].(string)
	if excID == "" {
		t.Fatalf("no exception_id: %+v", result.Data)
	}
	exc := p0GetException(t, env, cookies, excID)
	if exc["application_id"] != appID {
		t.Errorf("draft application_id = %v, want event app %s（不跨应用）", exc["application_id"], appID)
	}
	if exc["source_event_id"] != eventID.String() {
		t.Errorf("draft source_event_id = %v, want %s", exc["source_event_id"], eventID)
	}
	if exc["uri_exact"] != "/api/orders" {
		t.Errorf("draft uri_exact = %v, want /api/orders（query 剔除，EXC-08）", exc["uri_exact"])
	}
	if methods, _ := exc["methods"].([]interface{}); len(methods) != 1 || methods[0] != "POST" {
		t.Errorf("draft methods = %v, want [POST]（事件原方法，不擅自扩为全部）", exc["methods"])
	}
	if ruleIDs, _ := exc["rule_ids"].([]interface{}); len(ruleIDs) != 1 || ruleIDs[0] != float64(942100) {
		t.Errorf("draft rule_ids = %v, want [942100]（事件 matches 可信提取）", exc["rule_ids"])
	}
	if ips, _ := exc["source_ips"].([]interface{}); len(ips) != 1 || ips[0] != "203.0.113.9" {
		t.Errorf("draft source_ips = %v, want [203.0.113.9]", exc["source_ips"])
	}
	if exc["is_temporary"] != true || exc["status"] != "DRAFT" || exc["validation_status"] != "VALID" {
		t.Errorf("draft = temp %v status %v valid %v, want true/DRAFT/VALID",
			exc["is_temporary"], exc["status"], exc["validation_status"])
	}
	// 证据齐备的草稿可直接启用（30 分钟临时例外，到期运行时失效无需再发布）
	s5Expect(t, env.post(t, p0ExcURL+"/"+excID+"/enable", ``, cookies, csrf), http.StatusOK, "enable event draft")

	// 事件 2：无应用绑定、无规则匹配 → 草稿 NEEDS_REVIEW，禁止启用
	event2ID := uuid.New()
	if _, err := env.db.Exec(ctx, `INSERT INTO security_events
(id, request_id, occurred_at, domain, request_method, request_uri, request_path, attack_type, action)
VALUES ($1, $2, now(), 'internal.example.com', 'GET', '/health', '/health', 'OTHER', 'OBSERVE')`,
		event2ID, "req-"+s5Rand()); err != nil {
		t.Fatalf("insert event2: %v", err)
	}
	result = s5OK(t, env.post(t,
		"/api/v1/security-events/"+event2ID.String()+"/create-exception", ``, cookies, csrf), "create exception from event2")
	exc2ID, _ := result.Data["exception_id"].(string)
	exc2 := p0GetException(t, env, cookies, exc2ID)
	if exc2["validation_status"] != "NEEDS_REVIEW" {
		t.Fatalf("event2 draft validation_status = %v, want NEEDS_REVIEW（缺应用+规则证据）", exc2["validation_status"])
	}
	reasons, _ := exc2["unsupported_reasons"].([]interface{})
	joined := fmt.Sprintf("%v", reasons)
	if !strings.Contains(joined, "应用") || !strings.Contains(joined, "规则") {
		t.Errorf("unsupported_reasons must name missing evidence: %v", reasons)
	}
	// 风险勾选不得替代结构化范围校验（契约 §9：即使勾选也禁止启用）
	s5Expect(t, env.post(t, p0ExcURL+"/"+exc2ID+"/enable", ``, cookies, csrf),
		http.StatusBadRequest, "enable NEEDS_REVIEW draft")
}

// TestP0ExceptionRBAC EXC-13：AUDIT_ADMIN 无 exceptions.manage → 写操作 403。
func TestP0ExceptionRBAC(t *testing.T) {
	env := setupTestEnv(t)
	secCookies, secCSRF := env.s5Login(t, "p0exc_sec", "SECURITY_ADMIN")
	appID := jwtTestApp(t, env, secCookies, secCSRF, "p0rbac-"+s5Rand())
	data := p0CreateException(t, env, secCookies, secCSRF, fmt.Sprintf(
		`{"name":"rbac","scope_type":"APPLICATION","application_id":%q,"uri_exact":"/api/x",`+
			`"methods":["GET"],"rule_ids":[942100],"exception_action":"REMOVE_RULE"}`, appID))
	excID, _ := p0ExcField(t, data)["id"].(string)

	auditCookies, auditCSRF := env.s5Login(t, "p0exc_aud", "AUDIT_ADMIN")
	s5Expect(t, env.post(t, p0ExcURL,
		`{"name":"x","scope_type":"APPLICATION","exception_action":"REMOVE_RULE"}`, auditCookies, auditCSRF),
		http.StatusForbidden, "AUDIT_ADMIN create exception")
	s5Expect(t, env.post(t, p0ExcURL+"/"+excID+"/enable", ``, auditCookies, auditCSRF),
		http.StatusForbidden, "AUDIT_ADMIN enable exception")
	s5Expect(t, env.post(t, p0ExcURL+"/"+excID+"/preview", `{"expected_version":1}`, auditCookies, auditCSRF),
		http.StatusForbidden, "AUDIT_ADMIN preview exception")
	// 迁移 000100 已将 AUDIT_ADMIN 收紧为纯审计角色：无 exceptions.read，读 403
	s5Expect(t, env.get(t, p0ExcURL+"/"+excID, auditCookies), http.StatusForbidden, "AUDIT_ADMIN read exception")
}

// TestP0ExceptionListForPublish provider 直测：全量快照、稳定 marker/effect ID、
// 到期跳过、未来生效照常、NEEDS_REVIEW/DISABLED 排除、编译失败 fail-hard、容量上限、
// REMOVE_RULE_TAG 规则目录展开冻结。
func TestP0ExceptionListForPublish(t *testing.T) {
	env := setupTestEnv(t)
	ctx := context.Background()
	cookies, csrf := env.s5Login(t, "p0exc_pub", "SECURITY_ADMIN")
	appID := jwtTestApp(t, env, cookies, csrf, "p0pub-"+s5Rand())
	appUUID := uuid.MustParse(appID)
	store := exceptions.NewStore(env.db)

	insert := func(id, name, status, validation, action string) {
		t.Helper()
		if _, err := env.db.Exec(ctx, `INSERT INTO exception_policies
(id, name, scope_type, application_id, uri_exact, methods, rule_ids, exception_action, status, validation_status, target_engine)
VALUES ($1, $2, 'APPLICATION', $3, '/api/pay', '["POST"]'::jsonb, '[942100]'::jsonb, $4, $5, $6, 'WAF')`,
			uuid.MustParse(id), name, appUUID, action, status, validation); err != nil {
			t.Fatalf("insert %s: %v", name, err)
		}
	}
	// 按 exception_id 字典序（= uuid ASC）固定六行
	idA := "00000000-0000-4000-8000-0000000000a1"
	idB := "00000000-0000-4000-8000-0000000000b2"
	idC := "00000000-0000-4000-8000-0000000000c3"
	idD := "00000000-0000-4000-8000-0000000000d4"
	idE := "00000000-0000-4000-8000-0000000000e5"
	idF := "00000000-0000-4000-8000-0000000000f6"
	insert(idA, "A-enabled-valid", "ENABLED", "VALID", "REMOVE_RULE")
	insert(idB, "B-enabled-valid", "ENABLED", "VALID", "REMOVE_RULE")
	insert(idC, "C-needs-review", "ENABLED", "NEEDS_REVIEW", "REMOVE_RULE")
	insert(idD, "D-disabled", "DISABLED", "VALID", "REMOVE_RULE")
	// E：已到期（effective_until 过去）→ 跳过；F：未来生效 → 照常下发（TIME_EPOCH 运行时门控）
	if _, err := env.db.Exec(ctx, `INSERT INTO exception_policies
(id, name, scope_type, application_id, uri_exact, methods, rule_ids, exception_action, status, validation_status,
 target_engine, is_temporary, effective_from, effective_until)
VALUES ($1, 'E-expired', 'APPLICATION', $2, '/api/pay', '["POST"]'::jsonb, '[942100]'::jsonb, 'REMOVE_RULE',
 'ENABLED', 'VALID', 'WAF', true, now()-interval '2 hour', now()-interval '1 hour')`,
		uuid.MustParse(idE), appUUID); err != nil {
		t.Fatalf("insert E: %v", err)
	}
	if _, err := env.db.Exec(ctx, `INSERT INTO exception_policies
(id, name, scope_type, application_id, uri_exact, methods, rule_ids, exception_action, status, validation_status,
 target_engine, is_temporary, effective_from, effective_until)
VALUES ($1, 'F-future', 'APPLICATION', $2, '/api/pay', '["POST"]'::jsonb, '[942100]'::jsonb, 'REMOVE_RULE',
 'ENABLED', 'VALID', 'WAF', true, now()+interval '1 hour', now()+interval '2 hour')`,
		uuid.MustParse(idF), appUUID); err != nil {
		t.Fatalf("insert F: %v", err)
	}

	rules, err := store.ListForPublish(ctx)
	if err != nil {
		t.Fatalf("ListForPublish: %v", err)
	}
	if len(rules) != 3 {
		t.Fatalf("published rules = %d, want 3（A/B/F；C/D/E 排除）: %+v", len(rules), rules)
	}
	// 稳定排序与 ID 分配：marker=8000001+2i，RuleID=effect=marker+1
	wantIDs := []string{idA, idB, idF}
	for i, r := range rules {
		wantMarker := 8000001 + 2*i
		if r.RuleID != wantMarker+1 {
			t.Errorf("rules[%d].RuleID = %d, want effect %d", i, r.RuleID, wantMarker+1)
		}
		if r.ExceptionID != wantIDs[i] {
			t.Errorf("rules[%d].ExceptionID = %s, want %s（按 exception_id 字典序）", i, r.ExceptionID, wantIDs[i])
		}
		if r.ExceptionVersion != 1 {
			t.Errorf("rules[%d].ExceptionVersion = %d, want 1", i, r.ExceptionVersion)
		}
		if !strings.Contains(r.SecLang, fmt.Sprintf("id:%d,", wantMarker)) ||
			!strings.Contains(r.SecLang, fmt.Sprintf("id:%d,", wantMarker+1)) {
			t.Errorf("rules[%d] SecLang missing marker/effect ids %d/%d:\n%s", i, wantMarker, wantMarker+1, r.SecLang)
		}
		if !strings.Contains(r.SecLang, "tag:'exc:"+wantIDs[i]+"'") {
			t.Errorf("rules[%d] SecLang missing exc tag:\n%s", i, r.SecLang)
		}
		if r.ApplicationID != appID || r.ScopeType != "APPLICATION" {
			t.Errorf("rules[%d] scope = %s/%s", i, r.ScopeType, r.ApplicationID)
		}
	}
	// 未来生效的 F 必须带时间链（运行时门控，不由发布侧过滤）
	if !strings.Contains(rules[2].SecLang, "TIME_EPOCH") {
		t.Errorf("future-dated exception must carry TIME_EPOCH chain:\n%s", rules[2].SecLang)
	}

	// 编译失败 fail-hard：LOG_ONLY 行经 SQL 直插伪造为 ENABLED+VALID（正常链路到不了该状态）
	idG := "00000000-0000-4000-8000-0000000000a9"
	insert(idG, "G-logonly-forged", "ENABLED", "VALID", "LOG_ONLY")
	if _, err := store.ListForPublish(ctx); err == nil || !strings.Contains(err.Error(), "compile exception") {
		t.Errorf("LOG_ONLY enabled row must fail publish hard, got %v", err)
	}
	if _, err := env.db.Exec(ctx, `DELETE FROM exception_policies WHERE id=$1`, uuid.MustParse(idG)); err != nil {
		t.Fatalf("delete G: %v", err)
	}

	// 容量上限 2000（A/B/F 3 条 + 2001 条 → 超限明确失败）
	if _, err := env.db.Exec(ctx, `INSERT INTO exception_policies
(id, name, scope_type, application_id, uri_exact, methods, rule_ids, exception_action, status, validation_status, target_engine)
SELECT gen_random_uuid(), 'cap-'||g, 'APPLICATION', $1, '/api/cap/'||g, '["GET"]'::jsonb, '[942100]'::jsonb,
 'REMOVE_RULE', 'ENABLED', 'VALID', 'WAF'
FROM generate_series(1, 2001) g`, appUUID); err != nil {
		t.Fatalf("insert capacity rows: %v", err)
	}
	if _, err := store.ListForPublish(ctx); err == nil || !strings.Contains(err.Error(), "容量上限") {
		t.Errorf("over-capacity publish must fail with capacity error, got %v", err)
	}
	if _, err := env.db.Exec(ctx, `DELETE FROM exception_policies WHERE name LIKE 'cap-%'`); err != nil {
		t.Fatalf("cleanup capacity rows: %v", err)
	}

	// REMOVE_RULE_TAG：规则目录展开冻结（waf_rules.tags JSONB）
	for _, rid := range []int{941160, 942100} {
		if _, err := env.db.Exec(ctx, `INSERT INTO waf_rules (rule_id, rule_source, file_name, name, tags, crs_version)
VALUES ($1, 'OWASP_CRS', 'p0test.conf', 'p0-test-rule', '["attack-sqli"]'::jsonb, 'p0-test')
ON CONFLICT (rule_id, rule_source, crs_version) DO NOTHING`, rid); err != nil {
			t.Fatalf("insert waf_rules %d: %v", rid, err)
		}
	}
	data := p0CreateException(t, env, cookies, csrf, fmt.Sprintf(
		`{"name":"tag-exc","scope_type":"APPLICATION","application_id":%q,"uri_exact":"/api/tag",`+
			`"methods":["GET"],"rule_tags":["attack-sqli"],"exception_action":"REMOVE_RULE_TAG"}`, appID))
	exc := p0ExcField(t, data)
	if exc["validation_status"] != "VALID" {
		t.Fatalf("tag exception validation_status = %v: %v", exc["validation_status"], exc["unsupported_reasons"])
	}
	frozen, _ := exc["resolved_rule_ids"].([]interface{})
	if len(frozen) != 2 || frozen[0] != float64(941160) || frozen[1] != float64(942100) {
		t.Errorf("resolved_rule_ids = %v, want frozen sorted [941160 942100]", frozen)
	}
	tagExcID, _ := exc["id"].(string)
	result := s5OK(t, env.post(t, p0ExcURL+"/"+tagExcID+"/enable", ``, cookies, csrf), "enable tag exception")
	enabled := p0ExcField(t, result.Data)
	if frozen, _ := enabled["resolved_rule_ids"].([]interface{}); len(frozen) != 2 {
		t.Errorf("enabled tag exception resolved_rule_ids = %v, want frozen set persisted", frozen)
	}
}

// TestP0ExceptionListAPIExceptionsForGuard API 引擎例外 guard 快照：按应用编码下发、
// 方法大写归一、时间转 unix、到期跳过、绑定悬空 fail-hard。
func TestP0ExceptionListAPIExceptionsForGuard(t *testing.T) {
	env := setupTestEnv(t)
	ctx := context.Background()
	cookies, csrf := env.s5Login(t, "p0exc_api", "SECURITY_ADMIN")
	appCode := "p0api-" + s5Rand()
	appID := jwtTestApp(t, env, cookies, csrf, appCode)
	store := exceptions.NewStore(env.db)

	excID := uuid.New()
	if _, err := env.db.Exec(ctx, `INSERT INTO exception_policies
(id, name, scope_type, application_id, uri_exact, methods, exception_action, status, validation_status,
 target_engine, api_rule_refs, is_temporary, effective_from, effective_until)
VALUES ($1, 'api-exc', 'APPLICATION', $2, '/api/orders', '["post"]'::jsonb, 'OBSERVE_RULE', 'ENABLED', 'VALID',
 'API', '[{"detector_id":"api_schema","rule_id":"body.name","model_version":"v1"}]'::jsonb,
 true, now()-interval '1 hour', now()+interval '1 hour')`,
		excID, uuid.MustParse(appID)); err != nil {
		t.Fatalf("insert api exception: %v", err)
	}
	// 已到期 API 例外 → 跳过
	if _, err := env.db.Exec(ctx, `INSERT INTO exception_policies
(id, name, scope_type, application_id, uri_exact, methods, exception_action, status, validation_status,
 target_engine, api_rule_refs, is_temporary, effective_from, effective_until)
VALUES ($1, 'api-exc-expired', 'APPLICATION', $2, '/api/old', '["GET"]'::jsonb, 'OBSERVE_RULE', 'ENABLED', 'VALID',
 'API', '[{"detector_id":"api_parser","rule_id":"body"}]'::jsonb,
 true, now()-interval '2 hour', now()-interval '1 hour')`,
		uuid.New(), uuid.MustParse(appID)); err != nil {
		t.Fatalf("insert expired api exception: %v", err)
	}

	snapshot, err := store.ListAPIExceptionsForGuard(ctx)
	if err != nil {
		t.Fatalf("ListAPIExceptionsForGuard: %v", err)
	}
	list := snapshot[appCode]
	if len(list) != 1 {
		t.Fatalf("snapshot[%s] = %d items, want 1（到期跳过）: %+v", appCode, len(list), snapshot)
	}
	item := list[0]
	if item.SchemaVersion != 1 || item.ExceptionID != excID.String() || item.Version != 1 {
		t.Errorf("item identity = v%d %s ver%d", item.SchemaVersion, item.ExceptionID, item.Version)
	}
	if len(item.Methods) != 1 || item.Methods[0] != "POST" {
		t.Errorf("methods = %v, want normalized [POST]", item.Methods)
	}
	if item.EffectiveFrom == nil || item.EffectiveUntil == nil {
		t.Error("effective window must be unix timestamps")
	}
	if len(item.RuleRefs) != 1 || item.RuleRefs[0].DetectorID != "api_schema" ||
		item.RuleRefs[0].RuleID != "body.name" || item.RuleRefs[0].ModelVersion != "v1" {
		t.Errorf("rule_refs = %+v", item.RuleRefs)
	}

	// 绑定悬空（应用不存在）ENABLED+VALID 行 → fail-hard
	if _, err := env.db.Exec(ctx, `INSERT INTO exception_policies
(id, name, scope_type, application_id, uri_exact, methods, exception_action, status, validation_status,
 target_engine, api_rule_refs)
VALUES ($1, 'api-dangling', 'APPLICATION', $2, '/api/x', '["GET"]'::jsonb, 'OBSERVE_RULE', 'ENABLED', 'VALID',
 'API', '[{"detector_id":"api_schema","rule_id":"y"}]'::jsonb)`,
		uuid.New(), uuid.New()); err != nil {
		t.Fatalf("insert dangling api exception: %v", err)
	}
	if _, err := store.ListAPIExceptionsForGuard(ctx); err == nil {
		t.Error("dangling application binding must fail hard (publish abort)")
	}
}

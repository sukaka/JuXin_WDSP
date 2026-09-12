package tests

import (
	"fmt"
	"net/http"
	"strings"
	"testing"
)

// notificationCreateBody 构造创建渠道请求体。
func notificationCreateBody(name, typ, minSev string, categories []string, config string) string {
	cats := `[]`
	if len(categories) > 0 {
		quoted := make([]string, len(categories))
		for i, c := range categories {
			quoted[i] = fmt.Sprintf("%q", c)
		}
		cats = `[` + strings.Join(quoted, `,`) + `]`
	}
	return fmt.Sprintf(`{"name":%q,"type":%q,"enabled":true,"min_severity":%q,"categories":%s,"config":%s}`,
		name, typ, minSev, cats, config)
}

// createWecomChannel 创建一个企业微信渠道并返回渠道 ID（密值读出应为 ********）。
func createWecomChannel(t *testing.T, env *testEnv, cookies []*http.Cookie, csrf string) string {
	t.Helper()
	body := notificationCreateBody("值班群", "wecom", "LOW", nil,
		`{"webhook_url":"https://qyapi.weixin.qq.com/cgi-bin/webhook/send?key=k1","mention_all":false}`)
	resp := env.post(t, "/api/v1/notification-channels", body, cookies, csrf)
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("创建渠道 status = %d, body: %s", resp.StatusCode, readBodyString(t, resp))
	}
	var result apiResp
	readJSON(t, resp, &result)
	id, _ := result.Data["id"].(string)
	if id == "" {
		t.Fatalf("创建响应缺 id: %v", result.Data)
	}
	// 密值读出脱敏
	cfg, _ := result.Data["config"].(map[string]interface{})
	if cfg["webhook_url"] != "********" {
		t.Errorf("webhook_url 读出应脱敏, got %v", cfg["webhook_url"])
	}
	return id
}

// TestNotificationMeta 元数据接口：固定 9 类（APM 阶段新增「业务性能」）+ 4 级。
func TestNotificationMeta(t *testing.T) {
	env := setupTestEnv(t)
	cookies, _ := env.login(t, "test_sysadmin", env.adminPwd)

	resp := env.get(t, "/api/v1/notification-meta", cookies)
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("meta status = %d, body: %s", resp.StatusCode, readBodyString(t, resp))
	}
	var result apiResp
	readJSON(t, resp, &result)
	cats, _ := result.Data["categories"].([]interface{})
	if len(cats) != 9 {
		t.Fatalf("categories 应为 9 类, got %d", len(cats))
	}
	wantCodes := []string{"infrastructure", "storage", "certificate", "collection", "config_publish", "api_security", "ops", "security_events", "apm"}
	totalTypes := 0
	for i, c := range cats {
		m, _ := c.(map[string]interface{})
		if m["code"] != wantCodes[i] {
			t.Errorf("categories[%d].code = %v, want %s", i, m["code"], wantCodes[i])
		}
		if m["name"] == "" {
			t.Errorf("categories[%d] 缺中文名", i)
		}
		types, _ := m["alert_types"].([]interface{})
		totalTypes += len(types)
	}
	if totalTypes != 36 {
		t.Errorf("alert_types 总数应为 36, got %d", totalTypes)
	}
	sevs, _ := result.Data["severities"].([]interface{})
	if len(sevs) != 4 || sevs[0] != "LOW" || sevs[3] != "CRITICAL" {
		t.Errorf("severities = %v, want [LOW MEDIUM HIGH CRITICAL]", sevs)
	}
}

// TestNotificationChannelCRUD 渠道增删改查 + 密值脱敏 + 保留原值 + 内置 syslog 渠道。
func TestNotificationChannelCRUD(t *testing.T) {
	env := setupTestEnv(t)
	cookies, csrf := env.login(t, "test_sysadmin", env.adminPwd)

	// 迁移种子的内置 syslog 渠道应存在（默认停用）
	resp := env.get(t, "/api/v1/notification-channels", cookies)
	var list apiResp
	readJSON(t, resp, &list)
	resp.Body.Close()
	items, _ := list.Data["items"].([]interface{})
	builtin := 0
	for _, it := range items {
		m, _ := it.(map[string]interface{})
		if m["type"] == "syslog" {
			builtin++
			if m["enabled"] != false {
				t.Errorf("内置 syslog 渠道应默认停用: %v", m)
			}
			if name, _ := m["name"].(string); !strings.Contains(name, "syslog") {
				t.Errorf("内置 syslog 渠道名称错误: %v", name)
			}
		}
	}
	if builtin != 1 {
		t.Fatalf("应有 1 条内置 syslog 渠道, got %d", builtin)
	}

	// 创建
	id := createWecomChannel(t, env, cookies, csrf)

	// 列表包含新渠道且密值脱敏
	resp = env.get(t, "/api/v1/notification-channels", cookies)
	readJSON(t, resp, &list)
	resp.Body.Close()
	found := false
	for _, it := range list.Data["items"].([]interface{}) {
		m, _ := it.(map[string]interface{})
		if m["id"] == id {
			found = true
			if m["min_severity"] != "LOW" || m["type"] != "wecom" || m["enabled"] != true {
				t.Errorf("渠道字段错误: %v", m)
			}
			cfg, _ := m["config"].(map[string]interface{})
			if cfg["webhook_url"] != "********" {
				t.Errorf("列表读出密值应脱敏: %v", cfg)
			}
		}
	}
	if !found {
		t.Fatal("列表未包含新建渠道")
	}

	// 更新：密值写 ******** = 保留原值（验证 DB 中密文仍可解密——通过 test 接口发真实请求不行，
	// 此处验证更新成功且读出仍脱敏；密文正确性由 notify 包单测覆盖）
	update := notificationCreateBody("值班群-改名", "wecom", "HIGH", []string{"infrastructure"},
		`{"webhook_url":"********","mention_all":true}`)
	resp = env.do(t, http.MethodPut, "/api/v1/notification-channels/"+id, update, cookies, csrf)
	var upd apiResp
	readJSON(t, resp, &upd)
	resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("更新 status = %d, body: %v", resp.StatusCode, upd)
	}
	if upd.Data["name"] != "值班群-改名" || upd.Data["min_severity"] != "HIGH" {
		t.Errorf("更新结果错误: %v", upd.Data)
	}

	// 更新不存在的 ID → 404
	resp = env.do(t, http.MethodPut, "/api/v1/notification-channels/00000000-0000-0000-0000-000000000000",
		update, cookies, csrf)
	resp.Body.Close()
	if resp.StatusCode != http.StatusNotFound {
		t.Errorf("更新不存在渠道 status = %d, want 404", resp.StatusCode)
	}

	// 删除
	resp = env.do(t, http.MethodDelete, "/api/v1/notification-channels/"+id, "", cookies, csrf)
	resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Errorf("删除 status = %d, want 200", resp.StatusCode)
	}
	resp = env.do(t, http.MethodDelete, "/api/v1/notification-channels/"+id, "", cookies, csrf)
	resp.Body.Close()
	if resp.StatusCode != http.StatusNotFound {
		t.Errorf("重复删除 status = %d, want 404", resp.StatusCode)
	}
}

// TestNotificationSMSChannel 短信渠道（二期）：创建 + app_secret 脱敏读出 + 保留原值更新。
func TestNotificationSMSChannel(t *testing.T) {
	env := setupTestEnv(t)
	cookies, csrf := env.login(t, "test_sysadmin", env.adminPwd)

	body := notificationCreateBody("值班短信", "sms", "MEDIUM", []string{"security_events"},
		`{"gateway_url":"https://sms.example.com/send","app_key":"ak-1","app_secret":"sk-1","template_id":"TPL1","phones":["13800138000","+8613900139000"]}`)
	resp := env.post(t, "/api/v1/notification-channels", body, cookies, csrf)
	var created apiResp
	readJSON(t, resp, &created)
	resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("创建 sms 渠道 status = %d, body: %v", resp.StatusCode, created)
	}
	id, _ := created.Data["id"].(string)
	cfg, _ := created.Data["config"].(map[string]interface{})
	if cfg["app_secret"] != "********" {
		t.Errorf("app_secret 读出应脱敏, got %v", cfg["app_secret"])
	}
	if cfg["app_key"] != "ak-1" || cfg["gateway_url"] != "https://sms.example.com/send" {
		t.Errorf("非密值字段应明文读出: %v", cfg)
	}

	// 更新：app_secret 写 ******** = 保留原值
	update := notificationCreateBody("值班短信", "sms", "HIGH", []string{"security_events"},
		`{"gateway_url":"https://sms.example.com/send","app_key":"ak-1","app_secret":"********","template_id":"TPL2","phones":["13800138000"]}`)
	resp = env.do(t, http.MethodPut, "/api/v1/notification-channels/"+id, update, cookies, csrf)
	var upd apiResp
	readJSON(t, resp, &upd)
	resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("保留原值更新 status = %d, body: %v", resp.StatusCode, upd)
	}
	if updCfg, _ := upd.Data["config"].(map[string]interface{}); updCfg["template_id"] != "TPL2" {
		t.Errorf("更新后 template_id 应为 TPL2: %v", updCfg)
	}
}

// TestNotificationChannelBadRequest 非法入参 400。
func TestNotificationChannelBadRequest(t *testing.T) {
	env := setupTestEnv(t)
	cookies, csrf := env.login(t, "test_sysadmin", env.adminPwd)

	cases := []struct {
		name string
		body string
	}{
		{"非法类型", notificationCreateBody("x", "dingtalk", "LOW", nil, `{}`)},
		{"非法级别", notificationCreateBody("x", "wecom", "URGENT", nil, `{}`)},
		{"未知类别", notificationCreateBody("x", "wecom", "LOW", []string{"unknown"}, `{}`)},
		{"创建写占位符", notificationCreateBody("x", "wecom", "LOW", nil, `{"webhook_url":"********"}`)},
		{"空webhook", notificationCreateBody("x", "wecom", "LOW", nil, `{"webhook_url":""}`)},
		{"smtp非法security", notificationCreateBody("x", "smtp", "LOW", nil,
			`{"host":"smtp.x.com","port":25,"security":"tls12","from":"a@b.c","to":["d@e.f"]}`)},
		{"smtp空收件人", notificationCreateBody("x", "smtp", "LOW", nil,
			`{"host":"smtp.x.com","port":25,"security":"none","from":"a@b.c","to":[]}`)},
		{"sms空手机号", notificationCreateBody("x", "sms", "LOW", nil,
			`{"gateway_url":"https://sms.x.com/send","app_key":"ak","app_secret":"sk","template_id":"T1","phones":[]}`)},
		{"sms非法手机号", notificationCreateBody("x", "sms", "LOW", nil,
			`{"gateway_url":"https://sms.x.com/send","app_key":"ak","template_id":"T1","phones":["abc"]}`)},
		{"sms缺template_id", notificationCreateBody("x", "sms", "LOW", nil,
			`{"gateway_url":"https://sms.x.com/send","app_key":"ak","phones":["13800138000"]}`)},
		{"未知config字段", notificationCreateBody("x", "wecom", "LOW", nil,
			`{"webhook_url":"https://x.com/h","bogus":1}`)},
	}
	for _, c := range cases {
		resp := env.post(t, "/api/v1/notification-channels", c.body, cookies, csrf)
		resp.Body.Close()
		if resp.StatusCode != http.StatusBadRequest {
			t.Errorf("%s: status = %d, want 400", c.name, resp.StatusCode)
		}
	}
}

// TestNotificationPermissions 权限矩阵：SYSTEM_ADMIN 全量；SECURITY_ADMIN 只读；
// AUDIT_ADMIN 无权；未登录 401。
func TestNotificationPermissions(t *testing.T) {
	env := setupTestEnv(t)
	adminCookies, adminCSRF := env.login(t, "test_sysadmin", env.adminPwd)

	// 未登录 → 401
	resp := env.get(t, "/api/v1/notification-channels", nil)
	resp.Body.Close()
	if resp.StatusCode != http.StatusUnauthorized {
		t.Errorf("未登录 status = %d, want 401", resp.StatusCode)
	}

	// SECURITY_ADMIN：read 放行，update/test 拒绝
	env.createUserDirect(t, "sec_notify", "SecNotify@2026!", "SECURITY_ADMIN")
	secCookies, secCSRF := env.login(t, "sec_notify", "SecNotify@2026!")
	resp = env.get(t, "/api/v1/notification-channels", secCookies)
	resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Errorf("SECURITY_ADMIN 读 status = %d, want 200", resp.StatusCode)
	}
	resp = env.get(t, "/api/v1/notification-meta", secCookies)
	resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Errorf("SECURITY_ADMIN meta status = %d, want 200", resp.StatusCode)
	}
	body := notificationCreateBody("x", "wecom", "LOW", nil,
		`{"webhook_url":"https://qyapi.weixin.qq.com/x","mention_all":false}`)
	resp = env.post(t, "/api/v1/notification-channels", body, secCookies, secCSRF)
	resp.Body.Close()
	if resp.StatusCode != http.StatusForbidden {
		t.Errorf("SECURITY_ADMIN 写 status = %d, want 403", resp.StatusCode)
	}

	// test 接口：SECURITY_ADMIN 无 notification.test → 403
	id := createWecomChannel(t, env, adminCookies, adminCSRF)
	resp = env.post(t, "/api/v1/notification-channels/"+id+"/test", ``, secCookies, secCSRF)
	resp.Body.Close()
	if resp.StatusCode != http.StatusForbidden {
		t.Errorf("SECURITY_ADMIN test status = %d, want 403", resp.StatusCode)
	}

	// AUDIT_ADMIN：全部无权
	env.createUserDirect(t, "audit_notify", "AuditNotify@2026!", "AUDIT_ADMIN")
	auditCookies, auditCSRF := env.login(t, "audit_notify", "AuditNotify@2026!")
	resp = env.get(t, "/api/v1/notification-channels", auditCookies)
	resp.Body.Close()
	if resp.StatusCode != http.StatusForbidden {
		t.Errorf("AUDIT_ADMIN 读 status = %d, want 403", resp.StatusCode)
	}
	resp = env.post(t, "/api/v1/notification-channels/"+id+"/test", ``, auditCookies, auditCSRF)
	resp.Body.Close()
	if resp.StatusCode != http.StatusForbidden {
		t.Errorf("AUDIT_ADMIN test status = %d, want 403", resp.StatusCode)
	}
}

// TestNotificationTestEndpoint test 接口：syslog 未启用时返回真实错误（不吞错），
// 不可达 webhook 返回对端错误；成功/失败均落审计（审计记录由 handler 层覆盖，范式同 syslog-test）。
func TestNotificationTestEndpoint(t *testing.T) {
	env := setupTestEnv(t)
	cookies, csrf := env.login(t, "test_sysadmin", env.adminPwd)

	// 内置 syslog 渠道：syslog 外发默认未启用 → 400 + 真实原因
	resp := env.get(t, "/api/v1/notification-channels", cookies)
	var list apiResp
	readJSON(t, resp, &list)
	resp.Body.Close()
	var syslogID string
	for _, it := range list.Data["items"].([]interface{}) {
		m, _ := it.(map[string]interface{})
		if m["type"] == "syslog" {
			syslogID, _ = m["id"].(string)
		}
	}
	if syslogID == "" {
		t.Fatal("未找到内置 syslog 渠道")
	}
	resp = env.post(t, "/api/v1/notification-channels/"+syslogID+"/test", ``, cookies, csrf)
	body := readBodyString(t, resp)
	resp.Body.Close()
	if resp.StatusCode != http.StatusBadRequest {
		t.Errorf("syslog 未启用时 test status = %d, want 400", resp.StatusCode)
	}
	if !strings.Contains(body, "syslog 外发未启用") {
		t.Errorf("test 应返回真实失败原因, body: %s", body)
	}

	// 不可达 webhook：400 + 连接错误
	hook := notificationCreateBody("不可达", "wecom", "LOW", nil,
		`{"webhook_url":"http://127.0.0.1:1/hook","mention_all":false}`)
	resp = env.post(t, "/api/v1/notification-channels", hook, cookies, csrf)
	var created apiResp
	readJSON(t, resp, &created)
	resp.Body.Close()
	id, _ := created.Data["id"].(string)
	resp = env.post(t, "/api/v1/notification-channels/"+id+"/test", ``, cookies, csrf)
	body = readBodyString(t, resp)
	resp.Body.Close()
	if resp.StatusCode != http.StatusBadRequest {
		t.Errorf("不可达 webhook test status = %d, want 400", resp.StatusCode)
	}
	if !strings.Contains(body, "测试消息发送失败") {
		t.Errorf("test 应返回真实失败原因, body: %s", body)
	}
}

// TestNotifySettingsUpdate notify 组抑制参数：白名单放行合法更新（200），非法值 400。
func TestNotifySettingsUpdate(t *testing.T) {
	env := setupTestEnv(t)
	cookies, csrf := env.login(t, "test_sysadmin", env.adminPwd)

	keys := []struct {
		key      string
		goodVal  string
		badVal   string
		wantType string
	}{
		{"notify_rate_limit_per_minute", "20", `"x"`, "integer"},
		{"notify_mute_minutes", "15", `"x"`, "integer"},
		{"notify_group_window_seconds", "120", `"x"`, "integer"},
		{"notify_resolved", "true", `"x"`, "boolean"},
		{"notify_security_spike_threshold", "15", `"x"`, "integer"},
		{"notify_cc_spike_threshold", "30", `"x"`, "integer"},
	}
	for _, k := range keys {
		// 读当前版本
		resp := env.get(t, "/api/v1/system-settings?group=notify", cookies)
		var listRes apiRespPage2
		readJSON(t, resp, &listRes)
		resp.Body.Close()
		version := -1
		for _, item := range listRes.Data.Items {
			if item["setting_key"] == k.key {
				version = int(item["version"].(float64))
			}
		}
		if version < 0 {
			t.Fatalf("notify 组缺少设置键 %s（迁移未生效）", k.key)
		}
		// 非法类型 → 400
		bad := fmt.Sprintf(`{"setting_group":"notify","setting_key":%q,"setting_value":%s,"version":%d}`,
			k.key, k.badVal, version)
		resp = env.do(t, http.MethodPut, "/api/v1/system-settings", bad, cookies, csrf)
		resp.Body.Close()
		if resp.StatusCode != http.StatusBadRequest {
			t.Errorf("%s 非法值 status = %d, want 400", k.key, resp.StatusCode)
		}
		// 合法更新 → 200（验证白名单放行）
		good := fmt.Sprintf(`{"setting_group":"notify","setting_key":%q,"setting_value":%s,"version":%d}`,
			k.key, k.goodVal, version)
		resp = env.do(t, http.MethodPut, "/api/v1/system-settings", good, cookies, csrf)
		resp.Body.Close()
		if resp.StatusCode != http.StatusOK {
			t.Errorf("%s 合法更新 status = %d, want 200", k.key, resp.StatusCode)
		}
	}
}

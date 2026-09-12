package tests

import (
	"context"
	"fmt"
	"net/http"
	"strings"
	"testing"

	"github.com/jiuzhang-waf/server/internal/audits"
	"github.com/jiuzhang-waf/server/internal/loginlogs"
)

// syslogKindKeys 是 syslog 外发范围扩展（六类）新增的 3 个设置键。
var syslogKindKeys = []string{
	"syslog_forward_operation_audits",
	"syslog_forward_login_logs",
	"syslog_forward_system_alerts",
}

// loggingSettingVersion 读取 logging 组指定设置键的当前版本号。
func loggingSettingVersion(t *testing.T, env *testEnv, cookies []*http.Cookie, key string) int {
	t.Helper()
	resp := env.get(t, "/api/v1/system-settings?group=logging", cookies)
	defer resp.Body.Close()
	var list apiRespPage2
	readJSON(t, resp, &list)
	for _, item := range list.Data.Items {
		if item["setting_key"] == key {
			return int(item["version"].(float64))
		}
	}
	t.Fatalf("setting %s not found in logging group", key)
	return 0
}

// TestSyslogForwardKindSettingsUpdate 新增 3 个外发开关可通过接口更新（200），非法值被拒（400）。
func TestSyslogForwardKindSettingsUpdate(t *testing.T) {
	env := setupTestEnv(t)
	cookies, csrf := env.login(t, "test_sysadmin", env.adminPwd)

	for _, key := range syslogKindKeys {
		version := loggingSettingVersion(t, env, cookies, key)

		// 非法值（字符串而非 boolean）→ 400
		bad := fmt.Sprintf(`{"setting_group":"logging","setting_key":%q,"setting_value":"notabool","version":%d}`, key, version)
		resp := env.do(t, http.MethodPut, "/api/v1/system-settings", bad, cookies, csrf)
		if resp.StatusCode != http.StatusBadRequest {
			t.Errorf("%s 非法值 status = %d, want 400", key, resp.StatusCode)
		}
		resp.Body.Close()

		// 合法更新 → 200
		good := fmt.Sprintf(`{"setting_group":"logging","setting_key":%q,"setting_value":false,"version":%d}`, key, version)
		resp = env.do(t, http.MethodPut, "/api/v1/system-settings", good, cookies, csrf)
		if resp.StatusCode != http.StatusOK {
			t.Errorf("%s 更新 status = %d, want 200, body: %s", key, resp.StatusCode, readBodyString(t, resp))
		}
		resp.Body.Close()
	}
}

// TestAuditsRecordSyslogFanOut 审计写库成功后向 syslog 投递（payload 复用脱敏摘要）。
func TestAuditsRecordSyslogFanOut(t *testing.T) {
	env := setupTestEnv(t)

	var gotHint string
	var gotPayload map[string]interface{}
	calls := 0
	svc := audits.NewService(env.db)
	svc.SetSyslogForwarder(func(severityHint string, payload interface{}) {
		calls++
		gotHint = severityHint
		gotPayload, _ = payload.(map[string]interface{})
	})

	err := svc.Record(context.Background(), audits.RecordInput{
		Username:      "test_sysadmin",
		Module:        "users",
		Action:        "delete",
		ObjectType:    "user",
		ObjectID:      "u1",
		BeforeSummary: `{"username":"victim","password":"secret123"}`,
		Result:        audits.ResultSuccess,
		RiskLevel:     audits.RiskHigh,
		RequestID:     "req-syslog-1",
	})
	if err != nil {
		t.Fatalf("Record: %v", err)
	}
	if calls != 1 {
		t.Fatalf("写库成功后应投递 1 次, got %d", calls)
	}
	if gotHint != "warning" { // delete 类操作
		t.Errorf("severity 提示 = %q, want warning", gotHint)
	}
	if gotPayload["module"] != "users" || gotPayload["action"] != "delete" ||
		gotPayload["request_id"] != "req-syslog-1" {
		t.Errorf("payload 字段错误: %v", gotPayload)
	}
	if before, _ := gotPayload["before_summary"].(string); strings.Contains(before, "secret123") {
		t.Errorf("payload 泄露敏感字段: %s", before)
	}
}

// TestLoginLogsRecordSyslogFanOut 登录日志写库成功后向 syslog 投递（失败 warning / 成功 info）。
func TestLoginLogsRecordSyslogFanOut(t *testing.T) {
	env := setupTestEnv(t)

	var hints []string
	svc := loginlogs.NewService(env.db)
	svc.SetSyslogForwarder(func(severityHint string, payload interface{}) {
		hints = append(hints, severityHint)
		p, _ := payload.(map[string]interface{})
		if p["event_type"] == "" || p["username"] != "test_sysadmin" {
			t.Errorf("payload 字段错误: %v", p)
		}
	})

	if err := svc.Record(context.Background(), loginlogs.RecordInput{
		Username: "test_sysadmin", EventType: loginlogs.EventLoginFailure,
		Result: loginlogs.ResultFailure, FailureCode: "BAD_CREDENTIALS", RequestID: "req-lg-1",
	}); err != nil {
		t.Fatalf("Record failure: %v", err)
	}
	if err := svc.Record(context.Background(), loginlogs.RecordInput{
		Username: "test_sysadmin", EventType: loginlogs.EventLoginSuccess,
		Result: loginlogs.ResultSuccess, RequestID: "req-lg-2",
	}); err != nil {
		t.Fatalf("Record success: %v", err)
	}
	if len(hints) != 2 {
		t.Fatalf("写库成功后应各投递 1 次, got %d", len(hints))
	}
	if hints[0] != "warning" || hints[1] != "" {
		t.Errorf("severity 提示 = %v, want [warning \"\"]", hints)
	}
}

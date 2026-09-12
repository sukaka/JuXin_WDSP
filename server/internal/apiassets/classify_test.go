package apiassets

import (
	"testing"
)

// TestClassifyActionVocabulary §34.2 操作动作词表抽样覆盖：每个有规则的词表项至少一个命中样例。
func TestClassifyActionVocabulary(t *testing.T) {
	cases := []struct {
		method, path, want string
	}{
		{"POST", "/api/v1/users", "CREATE"},
		{"GET", "/api/v1/users", "READ_LIST"},
		{"GET", "/api/v1/users/{id}", "READ_DETAIL"},
		{"GET", "/api/v1/users/42", "READ_DETAIL"},
		{"GET", "/api/v1/users/list", "READ_LIST"},
		{"GET", "/api/v1/orders/search", "SEARCH"},
		{"POST", "/api/v1/orders/search", "SEARCH"},
		{"GET", "/api/v1/orders/count", "COUNT"},
		{"PUT", "/api/v1/users/{id}", "UPDATE"},
		{"PATCH", "/api/v1/users/{id}", "PATCH"},
		{"DELETE", "/api/v1/users/{id}", "DELETE"},
		{"POST", "/api/v1/users/batch", "BATCH_CREATE"},
		{"POST", "/api/v1/bulk-import/users", "BATCH_CREATE"},
		{"PUT", "/api/v1/users/batch", "BATCH_UPDATE"},
		{"DELETE", "/api/v1/users/batch", "BATCH_DELETE"},
		{"POST", "/api/v1/accounts/register", "REGISTER"},
		{"POST", "/api/v1/auth/login", "LOGIN"},
		{"POST", "/api/v1/auth/signin", "LOGIN"},
		{"POST", "/api/v1/auth/logout", "LOGOUT"},
		{"POST", "/api/v1/oauth/token", "TOKEN_ISSUE"},
		{"POST", "/api/v1/oauth/token/refresh", "TOKEN_REFRESH"},
		{"POST", "/api/v1/oauth/revoke", "TOKEN_REVOKE"},
		{"POST", "/api/v1/captcha/verify", "VERIFY"},
		{"POST", "/api/v1/orders/{id}/submit", "SUBMIT"},
		{"POST", "/api/v1/tickets/{id}/approve", "APPROVE"},
		{"POST", "/api/v1/tickets/{id}/reject", "REJECT"},
		{"POST", "/api/v1/orders/{id}/withdraw", "WITHDRAW"},
		{"POST", "/api/v1/tickets/{id}/assign", "ASSIGN"},
		{"POST", "/api/v1/accounts/transfer", "TRANSFER"},
		{"POST", "/api/v1/articles/{id}/publish", "PUBLISH"},
		{"POST", "/api/v1/articles/{id}/unpublish", "UNPUBLISH"},
		{"POST", "/api/v1/users/{id}/enable", "ENABLE"},
		{"POST", "/api/v1/users/{id}/disable", "DISABLE"},
		{"POST", "/api/v1/users/{id}/lock", "LOCK"},
		{"POST", "/api/v1/users/{id}/unlock", "UNLOCK"},
		{"POST", "/api/v1/data/import", "IMPORT"},
		{"GET", "/api/v1/data/export", "EXPORT"},
		{"POST", "/api/v1/files/upload", "UPLOAD"},
		{"GET", "/api/v1/files/{id}/download", "DOWNLOAD"},
		{"GET", "/api/v1/files/{id}/preview", "PREVIEW"},
		{"POST", "/api/v1/devices/sync", "SYNC"},
		{"POST", "/api/v1/pay/callback", "CALLBACK"},
		{"POST", "/api/v1/jobs/{id}/start", "START"},
		{"POST", "/api/v1/jobs/{id}/stop", "STOP"},
		{"POST", "/api/v1/jobs/{id}/retry", "RETRY"},
		{"POST", "/api/v1/system/backup", "BACKUP"},
		{"POST", "/api/v1/system/restore", "RESTORE"},
		{"POST", "/api/v1/tasks/{id}/execute", "EXECUTE"},
	}
	for _, c := range cases {
		got, conf := classifyAction(c.method, c.path)
		if got != c.want {
			t.Errorf("%s %s: got %s want %s", c.method, c.path, got, c.want)
			continue
		}
		if conf < 0.5 || conf > 1 {
			t.Errorf("%s %s: conf=%v 超出规则/方法映射置信区间", c.method, c.path, conf)
		}
	}
}

// TestClassifyActionNoMisfire 不误伤：方法约束不达成、子串非 token、兜底语义正确。
func TestClassifyActionNoMisfire(t *testing.T) {
	cases := []struct {
		method, path, want string
	}{
		// GET /tokens 是令牌资源列表，不是签发（TOKEN_ISSUE 限定 POST）
		{"GET", "/api/v1/tokens", "READ_LIST"},
		// publisher 与 publish 是不同 token，不命中 PUBLISH
		{"GET", "/api/v1/publishers/{id}", "READ_DETAIL"},
		// 驼峰段拆分：refreshToken → refresh + token
		{"POST", "/api/v1/auth/refreshToken", "TOKEN_REFRESH"},
		// 路径含 refresh 但无 token 上下文，不判 TOKEN_REFRESH，落方法兜底
		{"POST", "/api/v1/cache/refresh", "CREATE"},
		// GET 审批列表是读操作，不是 APPROVE（限定写方法）
		{"GET", "/api/v1/approvals", "READ_LIST"},
		// 根路径与空路径不 panic，落 READ_LIST
		{"GET", "/", "READ_LIST"},
		{"GET", "", "READ_LIST"},
		// 非常规方法兜底 CUSTOM
		{"OPTIONS", "/api/v1/users", "CUSTOM"},
	}
	for _, c := range cases {
		got, _ := classifyAction(c.method, c.path)
		if got != c.want {
			t.Errorf("%s %s: got %s want %s", c.method, c.path, got, c.want)
		}
	}
}

// TestClassifyBusinessDomain §34.1 业务领域映射：种子编码命中与低置信不打标。
func TestClassifyBusinessDomain(t *testing.T) {
	cases := []struct {
		path     string
		wantCode string
		wantOK   bool
	}{
		{"/api/v1/auth/login", "IDENTITY_AUTH", true},
		{"/api/v1/users/{id}/profile", "USER_ACCOUNT", true},
		{"/api/v1/roles/{id}/permissions", "ORG_PERMISSION", true},
		{"/api/v1/orders/{id}", "TRANSACTION_FUND", true},
		{"/api/v1/files/upload", "FILE_CONTENT", true},
		{"/api/v1/reports/dashboard", "QUERY_ANALYTICS", true},
		{"/api/v1/data/import", "IMPORT_EXPORT", true},
		{"/api/v1/messages/sms", "MESSAGE_NOTIFICATION", true},
		{"/api/v1/webhooks/callback", "EXTERNAL_INTEGRATION", true},
		{"/api/v1/system/settings", "SYSTEM_CONFIG", true},
		{"/api/v1/ops/jobs/{id}", "SYSTEM_OPS", true},
		{"/api/v1/devices/{id}/telemetry", "DEVICE_IOT", true},
		{"/api/v1/ai/models/{id}", "AI_INTELLIGENCE", true},
		{"/api/v1/privacy/consents", "PRIVACY_COMPLIANCE", true},
		{"/api/v1/tickets/{id}/approve", "PROCESS_APPROVAL", true},
		// 无关键词命中：不打标
		{"/api/v1/foobar/{id}", "", false},
		// 多领域各命中 1 次并列：低置信不打标
		{"/api/v1/users/{id}/orders", "", false},
		// 变量段与纯数字段不参与命中
		{"/api/v1/{resource}/123", "", false},
	}
	for _, c := range cases {
		code, conf, ok := classifyBusinessDomain(c.path)
		if ok != c.wantOK || code != c.wantCode {
			t.Errorf("%s: got (%s,%v) want (%s,%v)", c.path, code, ok, c.wantCode, c.wantOK)
			continue
		}
		if ok && conf < 0.5 {
			t.Errorf("%s: conf=%v 低于打标阈值", c.path, conf)
		}
	}
}

// TestClassifyByPathDimensions 自动分类维度组合：ACTION 恒产出，BUSINESS_DOMAIN 条件产出。
func TestClassifyByPathDimensions(t *testing.T) {
	dims := classifyByPath("POST", "/api/v1/auth/login")
	got := map[string]string{}
	for _, d := range dims {
		if d.Source != "AUTO" {
			t.Fatalf("dim source: %+v", d)
		}
		got[d.Dimension] = d.Value
	}
	if got["PURPOSE"] != "AUTH" || got["ACCESS"] != "WRITE" || got["EXPOSURE"] != "INTERNAL" {
		t.Fatalf("legacy dims: %v", got)
	}
	if got["ACTION"] != "LOGIN" {
		t.Fatalf("ACTION=%s", got["ACTION"])
	}
	if got["BUSINESS_DOMAIN"] != "IDENTITY_AUTH" {
		t.Fatalf("BUSINESS_DOMAIN=%s", got["BUSINESS_DOMAIN"])
	}
	// 无领域命中时维度数为 4，不编造 BUSINESS_DOMAIN
	dims = classifyByPath("GET", "/api/v1/widgets/{id}")
	if len(dims) != 4 {
		t.Fatalf("dims=%v", dims)
	}
	for _, d := range dims {
		if d.Dimension == "BUSINESS_DOMAIN" {
			t.Fatalf("unexpected domain dim: %+v", d)
		}
	}
}

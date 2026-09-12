// scan_test.go 领域逻辑单测：授权状态机（生效/过期/撤销/时间窗）、探针集解析白名单、
// 主机白名单、发现处置词表。
package apiscan

import (
	"testing"
	"time"
)

// TestAuthorizationActive 授权状态机：未撤销+未过期+时间窗内才有效。
func TestAuthorizationActive(t *testing.T) {
	now := time.Date(2026, 8, 18, 12, 0, 0, 0, time.UTC)
	future := now.Add(time.Hour)
	past := now.Add(-time.Hour)
	later := now.Add(2 * time.Hour)

	cases := []struct {
		name string
		a    Authorization
		want string // 期望失效原因（空 = 有效）
	}{
		{"有效", Authorization{ExpiresAt: future}, ""},
		{"已过期", Authorization{ExpiresAt: past}, "授权已过期"},
		{"恰好到期视为失效", Authorization{ExpiresAt: now}, "授权已过期"},
		{"已撤销", Authorization{ExpiresAt: future, RevokedAt: &past}, "授权已撤销"},
		{"撤销优先于过期判定", Authorization{ExpiresAt: past, RevokedAt: &past}, "授权已撤销"},
		{"时间窗内", Authorization{ExpiresAt: later, TimeWindow: TimeWindow{Start: &past, End: &later}}, ""},
		{"未到时间窗", Authorization{ExpiresAt: later, TimeWindow: TimeWindow{Start: &future}}, "未到授权时间窗起点"},
		{"超出时间窗", Authorization{ExpiresAt: later, TimeWindow: TimeWindow{End: &past}}, "已超出授权时间窗终点"},
		{"仅起点窗", Authorization{ExpiresAt: later, TimeWindow: TimeWindow{Start: &past}}, ""},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			if got := c.a.InactiveReason(now); got != c.want {
				t.Fatalf("InactiveReason=%q, want %q", got, c.want)
			}
			if active := c.a.Active(now); active != (c.want == "") {
				t.Fatalf("Active=%v, want %v", active, c.want == "")
			}
		})
	}
	// nil 授权单
	var nilAuthz *Authorization
	if nilAuthz.Active(now) {
		t.Fatal("nil authorization should not be active")
	}
}

// TestResolveProbeSets 探针集解析：任务指定/授权画像/默认全集三级回退 + 白名单强约束。
func TestResolveProbeSets(t *testing.T) {
	cases := []struct {
		name    string
		job     string
		profile string
		wantLen int
		wantErr bool
	}{
		{"均为空默认全集", "", "", len(AllProbeSets()), false},
		{"任务指定子集", "auth_required, method_enum", "", 2, false},
		{"任务空回退画像", "", "AUTH_REQUIRED", 1, false},
		{"任务集须在画像内", "METHOD_ENUM", "AUTH_REQUIRED", 0, true},
		{"任务集词表外", "FUZZ_ALL", "", 0, true},
		{"画像词表外", "", "BRUTE_FORCE", 0, true},
		{"大小写归一", "auth_required", "AUTH_REQUIRED", 1, false},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			sets, err := resolveProbeSets(c.job, c.profile)
			if (err != nil) != c.wantErr {
				t.Fatalf("err=%v, wantErr=%v", err, c.wantErr)
			}
			if err == nil && len(sets) != c.wantLen {
				t.Fatalf("len(sets)=%d, want %d (%v)", len(sets), c.wantLen, sets)
			}
		})
	}
}

// TestHostAllowed 主机白名单：空名单 = 仅 base_url 主机；非空须精确命中（支持 host:port 形态）。
func TestHostAllowed(t *testing.T) {
	cases := []struct {
		name      string
		baseURL   string
		allowlist []string
		want      bool
	}{
		{"空名单放行自身", "http://127.0.0.1:8080", nil, true},
		{"精确命中", "https://api.example.com", []string{"api.example.com"}, true},
		{"大小写不敏感", "https://API.example.com", []string{"api.example.com"}, true},
		{"未命中", "https://evil.example.com", []string{"api.example.com"}, false},
		{"host:port 形态按主机命中", "http://10.0.0.1:9000", []string{"10.0.0.1:9000"}, true},
		{"端口不同不影响主机命中", "http://10.0.0.1:9000", []string{"10.0.0.1:80"}, true},
		{"非法地址拒绝", "://bad", nil, false},
		{"空主机拒绝", "http://", nil, false},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			if got := hostAllowed(c.baseURL, c.allowlist); got != c.want {
				t.Fatalf("hostAllowed=%v, want %v", got, c.want)
			}
		})
	}
}

// TestFindingPathAndScope 发现端点键还原与复测范围校验。
func TestFindingPathAndScope(t *testing.T) {
	f := &Finding{EndpointKey: "GET /v1/users/1"}
	if got := findingPath(f); got != "/v1/users/1" {
		t.Fatalf("findingPath=%q", got)
	}
	if got := findingPath(&Finding{EndpointKey: "no-space"}); got != "" {
		t.Fatalf("findingPath invalid key=%q", got)
	}
	if got := findingPath(&Finding{EndpointKey: "GET relative"}); got != "" {
		t.Fatalf("findingPath relative=%q", got)
	}
	if !pathInScope("/v1/users/1", []string{"/v1/users/1"}) {
		t.Fatal("pathInScope exact should pass")
	}
	if pathInScope("/v1/users/2", []string{"/v1/users/1"}) {
		t.Fatal("pathInScope mismatch should fail")
	}
}

// TestVocab 词表校验。
func TestVocab(t *testing.T) {
	for _, s := range AllProbeSets() {
		if !IsValidProbeSet(s) {
			t.Fatalf("probe set %s should be valid", s)
		}
	}
	if IsValidProbeSet("FUZZ") || IsValidProbeSet("") {
		t.Fatal("invalid probe set accepted")
	}
	if !IsValidFindingStatus(FindingStatusNew) || IsValidFindingStatus("OPEN") {
		t.Fatal("finding status vocab broken")
	}
	if !IsValidSeverity(SeverityHigh) || IsValidSeverity("P0") {
		t.Fatal("severity vocab broken")
	}
}

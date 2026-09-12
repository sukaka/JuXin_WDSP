// agents_types_test.go Agent 状态机 / 派生态 / 配置夹紧单元测试。
package apm

import (
	"testing"
	"time"
)

func TestCanTransitionAgent_Matrix(t *testing.T) {
	cases := []struct {
		from, to string
		want     bool
	}{
		// §8.3 合法迁移
		{AgentStatusEnrolling, AgentStatusConnectedBaseline, true}, // 注册成功
		{AgentStatusEnrolling, AgentStatusRevoked, true},
		{AgentStatusConnectedBaseline, AgentStatusDiagnosing, true}, // 开启诊断（阶段4）
		{AgentStatusConnectedBaseline, AgentStatusRevoked, true},
		{AgentStatusDiagnosing, AgentStatusConnectedBaseline, true}, // 诊断到期/停止
		{AgentStatusDiagnosing, AgentStatusRevoked, true},
		// 非法迁移
		{AgentStatusRevoked, AgentStatusConnectedBaseline, false}, // 终态不可恢复
		{AgentStatusRevoked, AgentStatusEnrolling, false},
		{AgentStatusEnrolling, AgentStatusDiagnosing, false}, // 不可跳级
		{AgentStatusConnectedBaseline, AgentStatusEnrolling, false},
		{AgentStatusDiagnosing, AgentStatusDiagnosing, false},     // 无自环
		{AgentStatusOffline, AgentStatusConnectedBaseline, false}, // OFFLINE 为派生态，不参与存态迁移
		{AgentStatusConnectedBaseline, AgentStatusOffline, false},
		{"", AgentStatusConnectedBaseline, false},
		{AgentStatusConnectedBaseline, "", false},
	}
	for _, c := range cases {
		if got := CanTransitionAgent(c.from, c.to); got != c.want {
			t.Errorf("CanTransitionAgent(%s, %s) = %v, want %v", c.from, c.to, got, c.want)
		}
	}
}

func TestDeriveAgentStatus(t *testing.T) {
	now := time.Now()
	offlineAfter := 10 * time.Minute
	hb := now.Add(-5 * time.Minute)

	// REVOKED 恒为 REVOKED（即使心跳新鲜）
	if got := DeriveAgentStatus(AgentStatusRevoked, &hb, now, offlineAfter, now); got != AgentStatusRevoked {
		t.Errorf("revoked derived = %s", got)
	}
	// 心跳新鲜 → 存态原样
	if got := DeriveAgentStatus(AgentStatusConnectedBaseline, &hb, now.Add(-time.Hour), offlineAfter, now); got != AgentStatusConnectedBaseline {
		t.Errorf("fresh heartbeat derived = %s", got)
	}
	// 心跳超时 → OFFLINE
	stale := now.Add(-11 * time.Minute)
	if got := DeriveAgentStatus(AgentStatusConnectedBaseline, &stale, now.Add(-time.Hour), offlineAfter, now); got != AgentStatusOffline {
		t.Errorf("stale heartbeat derived = %s", got)
	}
	// 无心跳 → 退化按注册时间推导
	if got := DeriveAgentStatus(AgentStatusConnectedBaseline, nil, now.Add(-time.Hour), offlineAfter, now); got != AgentStatusOffline {
		t.Errorf("no-heartbeat old registration derived = %s", got)
	}
	if got := DeriveAgentStatus(AgentStatusEnrolling, nil, now.Add(-time.Minute), offlineAfter, now); got != AgentStatusEnrolling {
		t.Errorf("fresh registration derived = %s", got)
	}
}

func TestNewAgentControlConfig_Clamp(t *testing.T) {
	cfg := NewAgentControlConfig("127.0.0.1:4317", 72, 10)
	if cfg.CertTTL != 72*time.Hour || cfg.OfflineAfter != 10*time.Minute {
		t.Errorf("defaults = %v/%v", cfg.CertTTL, cfg.OfflineAfter)
	}
	if cfg.PolicyValidity != defaultPolicyValidity {
		t.Errorf("policy validity = %v", cfg.PolicyValidity)
	}
	// 越界回退默认
	cfg = NewAgentControlConfig("", 1, 0)
	if cfg.CertTTL != defaultAgentCertTTL {
		t.Errorf("cert ttl clamp = %v, want %v", cfg.CertTTL, defaultAgentCertTTL)
	}
	if cfg.OfflineAfter != 10*time.Minute {
		t.Errorf("offline clamp = %v", cfg.OfflineAfter)
	}
	cfg = NewAgentControlConfig("", 10000, 100000)
	if cfg.CertTTL != defaultAgentCertTTL || cfg.OfflineAfter != 10*time.Minute {
		t.Errorf("over-max clamp = %v/%v", cfg.CertTTL, cfg.OfflineAfter)
	}
}

func TestValidateAgentLanguage(t *testing.T) {
	for _, lang := range []string{"java", "go", "dotnet", "nodejs", "python", "php"} {
		if !ValidateAgentLanguage(lang) {
			t.Errorf("language %s rejected", lang)
		}
	}
	for _, bad := range []string{"", "JAVA", "golang", "rust", "c++"} {
		if ValidateAgentLanguage(bad) {
			t.Errorf("language %q accepted", bad)
		}
	}
}

func TestEnrollmentTokenRow_LanguageAllowed(t *testing.T) {
	row := &EnrollmentTokenRow{AllowedLanguages: []string{}}
	if !row.LanguageAllowed("java") {
		t.Error("empty allowlist must allow all")
	}
	row.AllowedLanguages = []string{"java", "go"}
	if !row.LanguageAllowed("go") || row.LanguageAllowed("python") {
		t.Error("allowlist semantics broken")
	}
}

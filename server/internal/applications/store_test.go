package applications

import (
	"context"
	"strings"
	"testing"
)

func TestValidProtectionMode(t *testing.T) {
	for _, m := range []string{ModeOff, ModeObserve, ModeProtect, ModeBypass} {
		if !validProtectionMode(m) {
			t.Errorf("mode %s should be valid", m)
		}
	}
	for _, m := range []string{"", "INVALID", "bypass", "PASSTHROUGH"} {
		if validProtectionMode(m) {
			t.Errorf("mode %q should be invalid", m)
		}
	}
}

// 无效模式在触达数据库前被拒绝（Store.db 为 nil 也不会 panic）
func TestCreateRejectsInvalidMode(t *testing.T) {
	s := &Store{}
	err := s.Create(context.Background(), &Application{Code: "test-app", Name: "测试应用", ProtectionMode: "INVALID"})
	if err == nil || !strings.Contains(err.Error(), "无效的防护模式") {
		t.Fatalf("expected 无效的防护模式 error, got %v", err)
	}
}

func TestValidDeploymentMode(t *testing.T) {
	for _, m := range []string{DeployModeReverseProxy, DeployModeRouted, DeployModeMirror, DeployModeTransparent} {
		if !validDeploymentMode(m) {
			t.Errorf("deployment mode %s should be valid", m)
		}
	}
	for _, m := range []string{"", "routed", "mirror", "INVALID"} {
		if validDeploymentMode(m) {
			t.Errorf("deployment mode %q should be invalid", m)
		}
	}
}

// 无效部署模式在触达数据库前被拒绝（Store.db 为 nil 也不会 panic）
func TestCreateRejectsInvalidDeploymentMode(t *testing.T) {
	s := &Store{}
	err := s.Create(context.Background(), &Application{
		Code: "test-app", Name: "测试应用", ProtectionMode: ModeObserve, DeploymentMode: "BRIDGE",
	})
	if err == nil || !strings.Contains(err.Error(), "无效的部署模式") {
		t.Fatalf("expected 无效的部署模式 error, got %v", err)
	}
}

// 更新路径同样拒绝无效部署模式（在触达数据库前）
func TestUpdateRejectsInvalidDeploymentMode(t *testing.T) {
	s := &Store{}
	err := s.Update(context.Background(), &Application{Name: "测试应用", ProtectionMode: ModeObserve, DeploymentMode: "TAP"})
	if err == nil || !strings.Contains(err.Error(), "无效的部署模式") {
		t.Fatalf("expected 无效的部署模式 error, got %v", err)
	}
}

// 更新路径同样拒绝无效防护模式（在触达数据库前）——非法值发布后会在
// generator modeToRuleEngine 静默回落 DetectionOnly（fail-open 且无提示）
func TestUpdateRejectsInvalidProtectionMode(t *testing.T) {
	s := &Store{}
	err := s.Update(context.Background(), &Application{Name: "测试应用", ProtectionMode: "PASSTHROUGH", DeploymentMode: DeployModeReverseProxy})
	if err == nil || !strings.Contains(err.Error(), "无效的防护模式") {
		t.Fatalf("expected 无效的防护模式 error, got %v", err)
	}
}

// 更新路径与 Create 同口径校验名称（在触达数据库前）
func TestUpdateRejectsInvalidName(t *testing.T) {
	s := &Store{}
	err := s.Update(context.Background(), &Application{ProtectionMode: ModeObserve, DeploymentMode: DeployModeReverseProxy})
	if err == nil || !strings.Contains(err.Error(), "应用名称不能为空") {
		t.Fatalf("empty name should be rejected, got %v", err)
	}
	err = s.Update(context.Background(), &Application{
		Name: strings.Repeat("长", 129), ProtectionMode: ModeObserve, DeploymentMode: DeployModeReverseProxy,
	})
	if err == nil || !strings.Contains(err.Error(), "128") {
		t.Fatalf("overlong name should be rejected, got %v", err)
	}
}

func TestValidAPIAdmissionMode(t *testing.T) {
	for _, m := range []string{AdmissionModeOff, AdmissionModeObserve, AdmissionModeProtect} {
		if !validAPIAdmissionMode(m) {
			t.Errorf("admission mode %s should be valid", m)
		}
	}
	// BYPASS 不属于准入词表（准入无透传语义）；小写/空串/未知值非法
	for _, m := range []string{"", "INVALID", "protect", ModeBypass} {
		if validAPIAdmissionMode(m) {
			t.Errorf("admission mode %q should be invalid", m)
		}
	}
}

// 无效准入模式在触达数据库前被拒绝（Store.db 为 nil 也不会 panic）
func TestCreateRejectsInvalidAdmissionMode(t *testing.T) {
	s := &Store{}
	err := s.Create(context.Background(), &Application{
		Code: "test-app", Name: "测试应用", ProtectionMode: ModeObserve,
		APIAdmissionMode: "STRICT", DeploymentMode: DeployModeReverseProxy,
	})
	if err == nil || !strings.Contains(err.Error(), "无效的API准入模式") {
		t.Fatalf("expected 无效的API准入模式 error, got %v", err)
	}
}

// 更新路径同样拒绝无效准入模式（在触达数据库前）——非法值经发布会进入
// guardconfig api_admission 段，必须在写入侧拦截
func TestUpdateRejectsInvalidAdmissionMode(t *testing.T) {
	s := &Store{}
	err := s.Update(context.Background(), &Application{
		Name: "测试应用", ProtectionMode: ModeObserve,
		APIAdmissionMode: "BLOCK", DeploymentMode: DeployModeReverseProxy,
	})
	if err == nil || !strings.Contains(err.Error(), "无效的API准入模式") {
		t.Fatalf("expected 无效的API准入模式 error, got %v", err)
	}
}

// UpdateUpstream 与 AddUpstream 同口径校验协议（在触达数据库前）
func TestUpdateUpstreamRejectsInvalidScheme(t *testing.T) {
	s := &Store{}
	u := &Upstream{Host: "192.0.2.1", Port: 9001, Weight: 10, Scheme: "gopher"}
	err := s.UpdateUpstream(context.Background(), u)
	if err == nil || !strings.Contains(err.Error(), "源站协议仅支持 http、https、h2c 或 tlcp") {
		t.Fatalf("expected scheme error, got %v", err)
	}
	// h2c 合法路径由 PG 契约覆盖（合法 scheme 会触达 db，本测试 Store{} 无实例；
	// 此处仅断言拒绝分支文案未退化）
}

// UpdateDomain 与 AddDomain 同口径校验端口范围与至少启用 HTTP/HTTPS 之一（P1-7，在触达数据库前）。
func TestUpdateDomainValidation(t *testing.T) {
	s := &Store{}
	intPtr := func(v int) *int { return &v }

	cases := []struct {
		name string
		d    *Domain
		want string
	}{
		{
			name: "HTTP和HTTPS均未启用",
			d:    &Domain{Hostname: "www.example.com", HTTPEnabled: false, HTTPSEnabled: false},
			want: "至少启用HTTP或HTTPS之一",
		},
		{
			name: "HTTP端口为0",
			d:    &Domain{Hostname: "www.example.com", HTTPEnabled: true, HTTPPort: intPtr(0)},
			want: "端口",
		},
		{
			name: "HTTP端口超范围",
			d:    &Domain{Hostname: "www.example.com", HTTPEnabled: true, HTTPPort: intPtr(70000)},
			want: "端口",
		},
		{
			name: "HTTPS端口超范围",
			d:    &Domain{Hostname: "www.example.com", HTTPSEnabled: true, HTTPSPort: intPtr(65536)},
			want: "端口",
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			err := s.UpdateDomain(context.Background(), tc.d)
			if err == nil || !strings.Contains(err.Error(), tc.want) {
				t.Fatalf("UpdateDomain(%s) err = %v, want containing %q", tc.name, err, tc.want)
			}
		})
	}
}

func TestDefaultUpstreamHealthStatus(t *testing.T) {
	if got := defaultUpstreamHealthStatus("ACTIVE", false); got != UpstreamHealthDisabled {
		t.Errorf("health_check_enabled=false => %q, want %q", got, UpstreamHealthDisabled)
	}
	if got := defaultUpstreamHealthStatus("DISABLED", false); got != UpstreamHealthDisabled {
		t.Errorf("disabled + health_check_enabled=false => %q, want %q", got, UpstreamHealthDisabled)
	}
	if got := defaultUpstreamHealthStatus("ACTIVE", true); got != UpstreamHealthUnknown {
		t.Errorf("active + health_check_enabled=true => %q, want %q", got, UpstreamHealthUnknown)
	}
	if got := defaultUpstreamHealthStatus("DISABLED", true); got != UpstreamHealthUnknown {
		t.Errorf("disabled + health_check_enabled=true => %q, want %q", got, UpstreamHealthUnknown)
	}
}

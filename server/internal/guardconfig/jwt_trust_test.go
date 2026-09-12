// jwt_trust_test.go jwt_trust 段组装与发布门禁单元测试（WDSP P0-03）。
package guardconfig

import (
	"context"
	"errors"
	"strings"
	"testing"

	"github.com/jiuzhang-waf/server/internal/gatewayconfig"
)

type fakeJWTTrustLister struct {
	policies map[string]*gatewayconfig.GuardJWTTrustPolicy
	err      error
}

func (f fakeJWTTrustLister) ListForGuard(context.Context) (map[string]*gatewayconfig.GuardJWTTrustPolicy, error) {
	return f.policies, f.err
}

func protectPolicy() *gatewayconfig.GuardJWTTrustPolicy {
	return &gatewayconfig.GuardJWTTrustPolicy{SchemaVersion: 1, Mode: "PROTECT", Version: 2}
}

// TestLoadJWTTrustInject 策略段注入 GuardConfig（key=应用编码）。
func TestLoadJWTTrustInject(t *testing.T) {
	p := &Provider{jwtTrust: fakeJWTTrustLister{policies: map[string]*gatewayconfig.GuardJWTTrustPolicy{
		"shop": {SchemaVersion: 1, Mode: "OBSERVE", Version: 1},
	}}}
	cfg := &gatewayconfig.GuardConfig{}
	if err := p.loadJWTTrust(context.Background(), cfg, "OBSERVE"); err != nil {
		t.Fatalf("loadJWTTrust: %v", err)
	}
	if cfg.JWTTrust["shop"] == nil || cfg.JWTTrust["shop"].Mode != "OBSERVE" {
		t.Fatalf("jwt_trust not injected: %+v", cfg.JWTTrust)
	}
}

// TestLoadJWTTrustReadErrorFailsHard 读取失败中止发布（防已 PROTECT 应用静默丢失强制校验）。
func TestLoadJWTTrustReadErrorFailsHard(t *testing.T) {
	p := &Provider{jwtTrust: fakeJWTTrustLister{err: errors.New("db down")}}
	if err := p.loadJWTTrust(context.Background(), &gatewayconfig.GuardConfig{}, "PROTECT"); err == nil {
		t.Fatal("read error must abort publish")
	}
}

// TestLoadJWTTrustProtectGate PROTECT 策略 + 管线非 PROTECT → 拒绝发布（防静默降级）。
func TestLoadJWTTrustProtectGate(t *testing.T) {
	p := &Provider{jwtTrust: fakeJWTTrustLister{policies: map[string]*gatewayconfig.GuardJWTTrustPolicy{
		"shop": protectPolicy(),
	}}}
	for _, mode := range []string{"OFF", "OBSERVE", ""} {
		// 身份密钥已配置：拒绝必须来自管线模式门禁而非密钥门禁
		cfg := &gatewayconfig.GuardConfig{IdentitySalt: "test-salt"}
		if err := p.loadJWTTrust(context.Background(), cfg, mode); err == nil {
			t.Errorf("PROTECT policy with pipeline mode %q must refuse publish", mode)
		}
	}
	cfg := &gatewayconfig.GuardConfig{IdentitySalt: "test-salt"}
	if err := p.loadJWTTrust(context.Background(), cfg, "PROTECT"); err != nil {
		t.Fatalf("PROTECT policy with PROTECT pipeline should pass: %v", err)
	}
	if cfg.JWTTrust["shop"] == nil {
		t.Fatal("jwt_trust not injected after gate pass")
	}
}

// TestLoadJWTTrustSecretGate 身份指纹密钥门禁：PROTECT 策略 + identity_salt
// 未配置（含快照脱敏占位）→ 拒绝发布并给可读原因（与网关 fail-closed 对应）；
// OBSERVE/OFF 策略不受密钥门禁（网关 OBSERVE 空密钥可运行，不产可信主体）。
func TestLoadJWTTrustSecretGate(t *testing.T) {
	p := &Provider{jwtTrust: fakeJWTTrustLister{policies: map[string]*gatewayconfig.GuardJWTTrustPolicy{
		"shop": protectPolicy(),
	}}}
	for _, salt := range []string{"", "  ", redactPlaceholder} {
		err := p.loadJWTTrust(context.Background(), &gatewayconfig.GuardConfig{IdentitySalt: salt}, "PROTECT")
		if err == nil {
			t.Errorf("PROTECT policy with identity_salt=%q must refuse publish", salt)
		} else if !strings.Contains(err.Error(), "identity_salt") {
			t.Errorf("error must name the missing secret, got: %v", err)
		}
	}
	// OBSERVE 策略不要求身份密钥（不门禁）
	p2 := &Provider{jwtTrust: fakeJWTTrustLister{policies: map[string]*gatewayconfig.GuardJWTTrustPolicy{
		"shop": {SchemaVersion: 1, Mode: "OBSERVE", Version: 1},
	}}}
	if err := p2.loadJWTTrust(context.Background(), &gatewayconfig.GuardConfig{}, "OBSERVE"); err != nil {
		t.Fatalf("OBSERVE policy without salt should pass: %v", err)
	}
}

// TestLoadJWTTrustObserveNoGate OBSERVE/OFF 策略不受管线模式门禁。
func TestLoadJWTTrustObserveNoGate(t *testing.T) {
	p := &Provider{jwtTrust: fakeJWTTrustLister{policies: map[string]*gatewayconfig.GuardJWTTrustPolicy{
		"shop": {SchemaVersion: 1, Mode: "OBSERVE", Version: 1},
	}}}
	if err := p.loadJWTTrust(context.Background(), &gatewayconfig.GuardConfig{}, "OBSERVE"); err != nil {
		t.Fatalf("OBSERVE policy should not be gated: %v", err)
	}
}

// TestLoadJWTTrustNodeGuard 节点门禁：存在已知同步失败节点时拒绝发布 PROTECT。
func TestLoadJWTTrustNodeGuard(t *testing.T) {
	called := false
	p := &Provider{
		jwtTrust: fakeJWTTrustLister{policies: map[string]*gatewayconfig.GuardJWTTrustPolicy{"shop": protectPolicy()}},
		jwtTrustNodeGuard: func(_ context.Context, apps []string) error {
			called = true
			if len(apps) != 1 || apps[0] != "shop" {
				t.Errorf("protect apps = %v", apps)
			}
			return errors.New("节点 gw-02 同步失败")
		},
	}
	if err := p.loadJWTTrust(context.Background(), &gatewayconfig.GuardConfig{IdentitySalt: "test-salt"}, "PROTECT"); err == nil {
		t.Fatal("node guard failure must refuse publish")
	}
	if !called {
		t.Fatal("node guard not called")
	}
}

// TestLoadJWTTrustNilLister 未注入 lister 时跳过（零行为变化）。
func TestLoadJWTTrustNilLister(t *testing.T) {
	p := &Provider{}
	cfg := &gatewayconfig.GuardConfig{}
	if err := p.loadJWTTrust(context.Background(), cfg, "PROTECT"); err != nil {
		t.Fatalf("nil lister should skip: %v", err)
	}
	if cfg.JWTTrust != nil {
		t.Fatal("jwt_trust should stay nil")
	}
}

// TestAPIPolicyVersionCoversJWTTrust 版本戳覆盖 jwt_trust 段（内容变化即版本戳变化；
// 未下发时与既有版本逐字节一致——omitempty 零变化）。
func TestAPIPolicyVersionCoversJWTTrust(t *testing.T) {
	base := &gatewayconfig.GuardConfig{APIProtectionMode: "PROTECT"}
	v1 := computeAPIPolicyVersion(base)
	withJWT := &gatewayconfig.GuardConfig{
		APIProtectionMode: "PROTECT",
		JWTTrust:          map[string]*gatewayconfig.GuardJWTTrustPolicy{"shop": protectPolicy()},
	}
	v2 := computeAPIPolicyVersion(withJWT)
	if v1 == v2 {
		t.Error("api_policy_version must change when jwt_trust section is present")
	}
	// 同内容恒得同版本戳
	if v2 != computeAPIPolicyVersion(withJWT) {
		t.Error("api_policy_version must be deterministic")
	}
}

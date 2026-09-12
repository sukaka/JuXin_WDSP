// revoked_credentials_test.go 已吊销凭据下发单测（§35，纯 fake，不依赖数据库）：
// 表缺失容忍（Warn 跳过）、未注入零行为、真实错误 fail-hard、正常读取透传、
// api_policy_version 纳入吊销清单段。
package guardconfig

import (
	"context"
	"errors"
	"testing"

	"github.com/jiuzhang-waf/server/internal/gatewayconfig"
)

// fakeRevokedCredentialLister 内存版已吊销凭据读取（可注入错误路径）。
type fakeRevokedCredentialLister struct {
	items []gatewayconfig.GuardRevokedCredential
	err   error
}

func (f *fakeRevokedCredentialLister) ListActiveRevokedCredentials(ctx context.Context) ([]gatewayconfig.GuardRevokedCredential, error) {
	_ = ctx
	return f.items, f.err
}

func testRevokedCredentials() []gatewayconfig.GuardRevokedCredential {
	return []gatewayconfig.GuardRevokedCredential{
		{CredentialType: "auth", Fingerprint: "0123456789abcdef0123456789abcdef"},
		{CredentialType: "sess", Fingerprint: "fedcba9876543210fedcba9876543210", ExpiresAt: "2027-01-01T00:00:00Z"},
	}
}

// TestLoadAPIRevokedCredentialsTolerance 吊销清单：未注入 nil；表缺失 Warn 跳过返回 nil；
// 真实查询错误 fail-hard；空清单不下发；正常读取透传。
func TestLoadAPIRevokedCredentialsTolerance(t *testing.T) {
	// 未注入
	p := &Provider{}
	if got, err := p.loadAPIRevokedCredentialsStrict(context.Background()); err != nil || got != nil {
		t.Fatalf("nil lister must yield nil: %v %v", got, err)
	}
	// 表不存在 → 容忍跳过
	p = &Provider{revokedCredentials: &fakeRevokedCredentialLister{err: errors.New(`relation "api_revoked_credentials" does not exist`)}}
	if got, err := p.loadAPIRevokedCredentialsStrict(context.Background()); err != nil || got != nil {
		t.Fatalf("missing table must be tolerated: %v %v", got, err)
	}
	// 真实查询错误 → fail-hard（不静默发布为空清单）
	p = &Provider{revokedCredentials: &fakeRevokedCredentialLister{err: errors.New("connection refused")}}
	if _, err := p.loadAPIRevokedCredentialsStrict(context.Background()); err == nil {
		t.Fatal("real query error must abort candidate publication")
	}
	// 空清单 → 不下发
	p = &Provider{revokedCredentials: &fakeRevokedCredentialLister{items: []gatewayconfig.GuardRevokedCredential{}}}
	if got, err := p.loadAPIRevokedCredentialsStrict(context.Background()); err != nil || got != nil {
		t.Fatalf("empty list must yield nil: %v %v", got, err)
	}
	// 正常读取
	p = &Provider{revokedCredentials: &fakeRevokedCredentialLister{items: testRevokedCredentials()}}
	got, err := p.loadAPIRevokedCredentialsStrict(context.Background())
	if err != nil {
		t.Fatalf("load: %v", err)
	}
	if len(got) != 2 || got[0].CredentialType != "auth" || got[1].ExpiresAt == "" {
		t.Fatalf("revoked credentials = %+v", got)
	}
}

// TestComputeAPIPolicyVersionRevoked 版本戳纳入吊销清单段：内容变更即变；缺省（nil/空）零变化。
func TestComputeAPIPolicyVersionRevoked(t *testing.T) {
	schemas := map[string]map[string]string{"POST /v1/orders": {"amount": "number"}}

	base := computeAPIPolicyVersion(&gatewayconfig.GuardConfig{APIFormalSchemas: schemas})
	withRevoked := computeAPIPolicyVersion(&gatewayconfig.GuardConfig{
		APIFormalSchemas: schemas, APIRevokedCredentials: testRevokedCredentials()})
	if withRevoked == base {
		t.Fatal("revoked credentials must be part of policy version")
	}
	// 同内容恒同（确定性）
	if v := computeAPIPolicyVersion(&gatewayconfig.GuardConfig{
		APIFormalSchemas: schemas, APIRevokedCredentials: testRevokedCredentials()}); v != withRevoked {
		t.Fatalf("same content must yield same version: %s != %s", v, withRevoked)
	}
	// 清单内容变更（到期时间变化）→ 版本变化
	changed := testRevokedCredentials()
	changed[0].ExpiresAt = "2027-06-01T00:00:00Z"
	if v := computeAPIPolicyVersion(&gatewayconfig.GuardConfig{
		APIFormalSchemas: schemas, APIRevokedCredentials: changed}); v == withRevoked {
		t.Fatal("revoked credential content change must change version")
	}
	// 空切片与 nil 等价（omitempty 缺省零变化，与既有版本逐字节一致）
	if v := computeAPIPolicyVersion(&gatewayconfig.GuardConfig{
		APIFormalSchemas: schemas, APIRevokedCredentials: []gatewayconfig.GuardRevokedCredential{}}); v != base {
		t.Fatal("empty revoked credentials must not change version")
	}
}

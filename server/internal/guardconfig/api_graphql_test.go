// api_graphql_test.go api_graphql 段组装单元测试（NG-GQL-03）：
// 策略注入 GuardConfig（key=application_id）、nil lister 不下发、空集不下发、
// 读取失败 fail-hard、版本戳覆盖该段。
package guardconfig

import (
	"context"
	"errors"
	"testing"

	"github.com/jiuzhang-waf/gateway/dynamic_security/gqlast"
	"github.com/jiuzhang-waf/server/internal/gatewayconfig"
)

type fakeAPIGraphQLLister struct {
	policies map[string]*gatewayconfig.GuardGraphQLPolicy
	err      error
}

func (f fakeAPIGraphQLLister) ListForGuard(context.Context) (map[string]*gatewayconfig.GuardGraphQLPolicy, error) {
	return f.policies, f.err
}

// TestLoadAPIGraphQLInject 策略注入 GuardConfig（key=application_id）。
func TestLoadAPIGraphQLInject(t *testing.T) {
	p := &Provider{apiGraphQL: fakeAPIGraphQLLister{policies: map[string]*gatewayconfig.GuardGraphQLPolicy{
		"app-1": {Enabled: true, Budget: gqlast.BudgetConfig{PerRequest: 100}, TrustedDocDigests: []string{"abc"}},
	}}}
	cfg := &gatewayconfig.GuardConfig{}
	if err := p.loadAPIGraphQL(context.Background(), cfg); err != nil {
		t.Fatalf("loadAPIGraphQL: %v", err)
	}
	pol := cfg.APIGraphQL["app-1"]
	if pol == nil || !pol.Enabled || pol.Budget.PerRequest != 100 || len(pol.TrustedDocDigests) != 1 {
		t.Fatalf("策略未注入: %+v", cfg.APIGraphQL)
	}
}

// TestLoadAPIGraphQLNilLister 未注入 lister：不下发该段（纯 WAF 装配形态零行为变化）。
func TestLoadAPIGraphQLNilLister(t *testing.T) {
	p := &Provider{}
	cfg := &gatewayconfig.GuardConfig{}
	if err := p.loadAPIGraphQL(context.Background(), cfg); err != nil {
		t.Fatalf("nil lister: %v", err)
	}
	if cfg.APIGraphQL != nil {
		t.Fatal("nil lister must not inject api_graphql")
	}
}

// TestLoadAPIGraphQLEmpty 无启用应用：不下发该段。
func TestLoadAPIGraphQLEmpty(t *testing.T) {
	p := &Provider{apiGraphQL: fakeAPIGraphQLLister{policies: map[string]*gatewayconfig.GuardGraphQLPolicy{}}}
	cfg := &gatewayconfig.GuardConfig{}
	if err := p.loadAPIGraphQL(context.Background(), cfg); err != nil {
		t.Fatalf("empty: %v", err)
	}
	if cfg.APIGraphQL != nil {
		t.Fatal("empty policies must not inject api_graphql")
	}
}

// TestLoadAPIGraphQLFailHard 读取失败中止发布（fail-hard，不静默丢失预算拦截）。
func TestLoadAPIGraphQLFailHard(t *testing.T) {
	p := &Provider{apiGraphQL: fakeAPIGraphQLLister{err: errors.New("db down")}}
	if err := p.loadAPIGraphQL(context.Background(), &gatewayconfig.GuardConfig{}); err == nil {
		t.Fatal("读取失败必须中止发布（fail-hard）")
	}
}

// TestAPIGraphQLVersionStamp GraphQL 段纳入 api_policy_version 版本戳。
func TestAPIGraphQLVersionStamp(t *testing.T) {
	base := &gatewayconfig.GuardConfig{APIProtectionMode: "OBSERVE"}
	withGQL := &gatewayconfig.GuardConfig{APIProtectionMode: "OBSERVE",
		APIGraphQL: map[string]*gatewayconfig.GuardGraphQLPolicy{
			"app-1": {Enabled: true, Budget: gqlast.BudgetConfig{PerRequest: 100}},
		}}
	v1 := computeAPIPolicyVersion(base)
	v2 := computeAPIPolicyVersion(withGQL)
	if v1 == v2 {
		t.Error("api_graphql section must be covered by api_policy_version")
	}
	if v2 != computeAPIPolicyVersion(withGQL) {
		t.Error("version stamp must be deterministic")
	}
	// 未下发段保持与旧版本逐字节一致（零变化约束）
	if v := computeAPIPolicyVersion(&gatewayconfig.GuardConfig{APIProtectionMode: "OBSERVE"}); v != v1 {
		t.Error("nil api_graphql must keep version stamp unchanged")
	}
}

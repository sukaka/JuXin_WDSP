// api_exceptions_test.go api_exceptions 段组装单元测试（WDSP P0-04 A 侧，契约 §6/§10）。
package guardconfig

import (
	"context"
	"errors"
	"strings"
	"testing"

	"github.com/jiuzhang-waf/server/internal/gatewayconfig"
)

type fakeAPIExceptionLister struct {
	exceptions map[string][]gatewayconfig.GuardAPIException
	err        error
}

func (f fakeAPIExceptionLister) ListAPIExceptionsForGuard(context.Context) (map[string][]gatewayconfig.GuardAPIException, error) {
	return f.exceptions, f.err
}

func p0APIException() gatewayconfig.GuardAPIException {
	until := int64(1700003600)
	return gatewayconfig.GuardAPIException{
		SchemaVersion:  1,
		ExceptionID:    "11111111-2222-3333-4444-555555555555",
		Version:        2,
		URIExact:       "/api/orders",
		Methods:        []string{"POST"},
		EffectiveUntil: &until,
		RuleRefs:       []gatewayconfig.GuardAPIRuleRef{{DetectorID: "api_schema", RuleID: "body.name"}},
	}
}

// TestLoadAPIExceptionsInject 例外段注入 GuardConfig（key=应用编码）。
func TestLoadAPIExceptionsInject(t *testing.T) {
	p := &Provider{apiExceptions: fakeAPIExceptionLister{exceptions: map[string][]gatewayconfig.GuardAPIException{
		"shop": {p0APIException()},
	}}}
	cfg := &gatewayconfig.GuardConfig{}
	if err := p.loadAPIExceptions(context.Background(), cfg); err != nil {
		t.Fatalf("loadAPIExceptions: %v", err)
	}
	got := cfg.APIExceptions["shop"]
	if len(got) != 1 || got[0].ExceptionID != "11111111-2222-3333-4444-555555555555" || got[0].Version != 2 {
		t.Fatalf("api_exceptions not injected: %+v", cfg.APIExceptions)
	}
}

// TestLoadAPIExceptionsReadErrorFailsHard 读取失败中止发布
// （防已启用例外在新配置中整段丢失 = 静默恢复执法且无告警）。
func TestLoadAPIExceptionsReadErrorFailsHard(t *testing.T) {
	p := &Provider{apiExceptions: fakeAPIExceptionLister{err: errors.New("db down")}}
	err := p.loadAPIExceptions(context.Background(), &gatewayconfig.GuardConfig{})
	if err == nil {
		t.Fatal("read error must abort publish")
	}
	if got := err.Error(); !strings.Contains(got, "list api exceptions") {
		t.Errorf("error must identify the failed read: %v", err)
	}
}

// TestLoadAPIExceptionsNilOrEmptySkips 未注入 lister 或无启用行 → 不下发该段
// （nil map，网关 API 决策零行为变化）。
func TestLoadAPIExceptionsNilOrEmptySkips(t *testing.T) {
	p := &Provider{}
	cfg := &gatewayconfig.GuardConfig{}
	if err := p.loadAPIExceptions(context.Background(), cfg); err != nil || cfg.APIExceptions != nil {
		t.Fatalf("nil lister must skip section: %v %+v", err, cfg.APIExceptions)
	}
	p2 := &Provider{apiExceptions: fakeAPIExceptionLister{}}
	if err := p2.loadAPIExceptions(context.Background(), cfg); err != nil || cfg.APIExceptions != nil {
		t.Fatalf("empty result must skip section: %v %+v", err, cfg.APIExceptions)
	}
}

// TestAPIExceptionsVersionStamp 例外段纳入 api_policy_version 版本戳
// （omitempty：未下发时与既有版本逐字节一致）。
func TestAPIExceptionsVersionStamp(t *testing.T) {
	base := &gatewayconfig.GuardConfig{}
	v1 := computeAPIPolicyVersion(base)
	withExceptions := &gatewayconfig.GuardConfig{APIExceptions: map[string][]gatewayconfig.GuardAPIException{
		"shop": {p0APIException()},
	}}
	v2 := computeAPIPolicyVersion(withExceptions)
	if v1 == v2 {
		t.Error("api_exceptions section must be covered by api_policy_version")
	}
	if v2 != computeAPIPolicyVersion(withExceptions) {
		t.Error("version stamp must be deterministic")
	}
	if v := computeAPIPolicyVersion(&gatewayconfig.GuardConfig{}); v != v1 {
		t.Error("empty section must be byte-identical to previous versions (omitempty)")
	}
}

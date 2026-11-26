package guardconfig

import (
	"context"
	"errors"
	"testing"

	"github.com/jiuzhang-waf/server/internal/gatewayconfig"
)

type fakeClientSideLister struct {
	policies map[string]*gatewayconfig.GuardClientSidePolicy
	err      error
}

func (f fakeClientSideLister) ListForGuard(context.Context) (map[string]*gatewayconfig.GuardClientSidePolicy, error) {
	return f.policies, f.err
}

func TestLoadClientSidePolicyAndFailHard(t *testing.T) {
	// 1. nil lister -> no-op
	cfg := &gatewayconfig.GuardConfig{}
	if err := (&Provider{}).loadClientSidePolicy(context.Background(), cfg); err != nil {
		t.Fatalf("nil lister should succeed: %v", err)
	}
	if cfg.ClientSidePolicy != nil {
		t.Fatalf("expected nil ClientSidePolicy, got %+v", cfg.ClientSidePolicy)
	}

	// 2. lister 失败中止发布（fail-hard）
	pErr := &Provider{clientSide: fakeClientSideLister{err: errors.New("db down")}}
	if err := pErr.loadClientSidePolicy(context.Background(), &gatewayconfig.GuardConfig{}); err == nil {
		t.Fatal("lister error must fail-hard")
	}

	// 3. 空策略列表不下发段
	pEmpty := &Provider{clientSide: fakeClientSideLister{policies: map[string]*gatewayconfig.GuardClientSidePolicy{}}}
	cfgEmpty := &gatewayconfig.GuardConfig{}
	if err := pEmpty.loadClientSidePolicy(context.Background(), cfgEmpty); err != nil {
		t.Fatalf("empty map should succeed: %v", err)
	}
	if cfgEmpty.ClientSidePolicy != nil {
		t.Fatalf("empty map must keep ClientSidePolicy nil, got %+v", cfgEmpty.ClientSidePolicy)
	}

	// 4. 正常加载填充
	pol := &gatewayconfig.GuardClientSidePolicy{
		SchemaVersion:        1,
		ApplicationID:        "app-1",
		Mode:                 "PROTECT",
		Version:              2,
		CSPMode:              "ENFORCE",
		SensitivePaths:       []string{"/checkout"},
		ProbeEnabled:         true,
		AllowedScriptOrigins: []string{"'self'"},
		AuthorizedScripts: []gatewayconfig.GuardClientSideScript{
			{ScriptURL: "https://cdn.example.com/pay.js", ScriptType: "EXTERNAL", SRIHash: "sha384-dGVzdA==", Status: "AUTHORIZED"},
		},
	}
	pOK := &Provider{clientSide: fakeClientSideLister{policies: map[string]*gatewayconfig.GuardClientSidePolicy{"shop": pol}}}
	cfgOK := &gatewayconfig.GuardConfig{}
	if err := pOK.loadClientSidePolicy(context.Background(), cfgOK); err != nil {
		t.Fatalf("loadClientSidePolicy: %v", err)
	}
	if cfgOK.ClientSidePolicy["shop"] == nil || cfgOK.ClientSidePolicy["shop"].Version != 2 {
		t.Fatalf("unexpected cfg.ClientSidePolicy: %+v", cfgOK.ClientSidePolicy)
	}
}

func TestAPIPolicyVersionIncludesClientSidePolicy(t *testing.T) {
	base := computeAPIPolicyVersion(&gatewayconfig.GuardConfig{})

	cfg1 := &gatewayconfig.GuardConfig{
		ClientSidePolicy: map[string]*gatewayconfig.GuardClientSidePolicy{
			"shop": {
				SchemaVersion: 1,
				ApplicationID: "app-1",
				Mode:          "OBSERVE",
				Version:       1,
				CSPMode:       "REPORT_ONLY",
				AuthorizedScripts: []gatewayconfig.GuardClientSideScript{
					{ScriptURL: "https://cdn.example.com/a.js", ScriptType: "EXTERNAL", SRIHash: "sha384-AAAA", Status: "AUTHORIZED"},
				},
			},
		},
	}
	v1 := computeAPIPolicyVersion(cfg1)
	if v1 == base {
		t.Fatal("adding client_side_policy must change api_policy_version")
	}

	// 变更授权脚本 SRI 必须产生新版本戳
	cfg2 := &gatewayconfig.GuardConfig{
		ClientSidePolicy: map[string]*gatewayconfig.GuardClientSidePolicy{
			"shop": {
				SchemaVersion: 1,
				ApplicationID: "app-1",
				Mode:          "OBSERVE",
				Version:       1,
				CSPMode:       "REPORT_ONLY",
				AuthorizedScripts: []gatewayconfig.GuardClientSideScript{
					{ScriptURL: "https://cdn.example.com/a.js", ScriptType: "EXTERNAL", SRIHash: "sha384-BBBB", Status: "AUTHORIZED"},
				},
			},
		},
	}
	v2 := computeAPIPolicyVersion(cfg2)
	if v2 == v1 {
		t.Fatal("changing authorized script SRI must change api_policy_version")
	}
	// 同内容哈希稳定
	if v1Again := computeAPIPolicyVersion(cfg1); v1Again != v1 {
		t.Fatalf("hash not deterministic: %s vs %s", v1, v1Again)
	}
}

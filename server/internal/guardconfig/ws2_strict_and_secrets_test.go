package guardconfig

import (
	"context"
	"errors"
	"strings"
	"testing"

	"github.com/jiuzhang-waf/server/internal/gatewayconfig"
)

type fakeBehaviorPolicyLister struct {
	pol *gatewayconfig.GuardIdentityBehavior
	err error
}

func (f *fakeBehaviorPolicyLister) GetGuardBehaviorPolicy(context.Context) (*gatewayconfig.GuardIdentityBehavior, error) {
	return f.pol, f.err
}

type fakeRiskPolicyGlobalLister struct {
	pol         *gatewayconfig.GuardRiskPolicy
	err         error
	overrides   []gatewayconfig.GuardRiskPolicyOverride
	overrideErr error
}

func (f *fakeRiskPolicyGlobalLister) GetGuardRiskPolicy(context.Context) (*gatewayconfig.GuardRiskPolicy, error) {
	return f.pol, f.err
}

func (f *fakeRiskPolicyGlobalLister) ListGuardRiskPolicyOverrides(context.Context) ([]gatewayconfig.GuardRiskPolicyOverride, error) {
	return f.overrides, f.overrideErr
}

// TestStrictLoadersFailHardOnDBErrorAndTolerateMissingTable 验证全部 8 个策略加载器：
// 真实数据库故障中止候选发布（fail-hard），仅旧库未建表（relation ... does not exist）允许 Warn 跳过。
func TestStrictLoadersFailHardOnDBErrorAndTolerateMissingTable(t *testing.T) {
	ctx := context.Background()
	dbErr := errors.New("connection reset by peer")

	// 1. strongflow
	p := &Provider{strongFlows: &fakeStrongFlowLister{err: dbErr}}
	if _, err := p.loadAPIStrongFlowsStrict(ctx); err == nil {
		t.Fatal("strongflow strict loader must fail hard on real DB error")
	}
	p = &Provider{strongFlows: &fakeStrongFlowLister{err: errors.New(`relation "api_strong_flow_definitions" does not exist`)}}
	if got, err := p.loadAPIStrongFlowsStrict(ctx); err != nil || got != nil {
		t.Fatalf("strongflow missing table should tolerate: got=%v err=%v", got, err)
	}

	// 2. response_baselines
	p = &Provider{responseBaselines: &fakeResponseBaselineLister{err: dbErr}}
	if _, err := p.loadAPIResponseBaselinesStrict(ctx); err == nil {
		t.Fatal("response_baselines strict loader must fail hard on real DB error")
	}
	p = &Provider{responseBaselines: &fakeResponseBaselineLister{err: errors.New(`relation "api_response_schemas" does not exist`)}}
	if got, err := p.loadAPIResponseBaselinesStrict(ctx); err != nil || got != nil {
		t.Fatalf("response_baselines missing table should tolerate: got=%v err=%v", got, err)
	}

	// 3. grpc_descriptors
	p = &Provider{grpcDescriptors: &fakeGRPCDescriptorLister{err: dbErr}}
	if _, err := p.loadAPIGRPCDescriptorsStrict(ctx); err == nil {
		t.Fatal("grpc_descriptors strict loader must fail hard on real DB error")
	}
	p = &Provider{grpcDescriptors: &fakeGRPCDescriptorLister{err: errors.New(`relation "api_grpc_descriptors" does not exist`)}}
	if got, err := p.loadAPIGRPCDescriptorsStrict(ctx); err != nil || got != nil {
		t.Fatalf("grpc_descriptors missing table should tolerate: got=%v err=%v", got, err)
	}

	// 4. grpc_bindings
	p = &Provider{grpcBindings: &fakeGRPCBindingLister{err: dbErr}}
	if _, err := p.loadAPIGRPCBindingsStrict(ctx); err == nil {
		t.Fatal("grpc_bindings strict loader must fail hard on real DB error")
	}
	p = &Provider{grpcBindings: &fakeGRPCBindingLister{err: errors.New(`relation "api_grpc_bindings" does not exist`)}}
	if got, err := p.loadAPIGRPCBindingsStrict(ctx); err != nil || got != nil {
		t.Fatalf("grpc_bindings missing table should tolerate: got=%v err=%v", got, err)
	}

	// 5. mcp_catalogs & mcp_bindings
	p = &Provider{mcpCatalogs: &fakeMCPCatalogLister{err: dbErr}}
	if _, err := p.loadAPIMCPToolCatalogsStrict(ctx); err == nil {
		t.Fatal("mcp_catalogs strict loader must fail hard on real DB error")
	}
	p = &Provider{mcpBindings: &fakeMCPBindingLister{err: dbErr}}
	if _, err := p.loadAPIMCPBindingsStrict(ctx); err == nil {
		t.Fatal("mcp_bindings strict loader must fail hard on real DB error")
	}
	p = &Provider{mcpCatalogs: &fakeMCPCatalogLister{err: errors.New(`relation "mcp_tool_catalogs" does not exist`)}}
	if got, err := p.loadAPIMCPToolCatalogsStrict(ctx); err != nil || got != nil {
		t.Fatalf("mcp_catalogs missing table should tolerate: got=%v err=%v", got, err)
	}

	// 6. machine_identities (identity/binding/meta)
	p = &Provider{machineIdentities: &fakeMachineIdentityLister{err: dbErr}}
	if _, _, _, err := p.loadAPIMachineIdentitySectionsStrict(ctx); err == nil {
		t.Fatal("machine_identities strict loader must fail hard on real DB error")
	}
	p = &Provider{machineIDBindings: &fakeMachineIdentityBindingLister{err: dbErr}}
	if _, _, _, err := p.loadAPIMachineIdentitySectionsStrict(ctx); err == nil {
		t.Fatal("machine_identity_bindings strict loader must fail hard on real DB error")
	}
	p = &Provider{
		machineIdentities: &fakeMachineIdentityLister{identities: midRows()},
		machineIDMeta:     &fakeMachineIdentityMetaLister{err: dbErr},
	}
	if _, _, _, err := p.loadAPIMachineIdentitySectionsStrict(ctx); err == nil {
		t.Fatal("machine_identity_meta strict loader must fail hard on real DB error")
	}
	p = &Provider{
		machineIdentities: &fakeMachineIdentityLister{identities: midRows()},
		machineIDMeta:     &fakeMachineIdentityMetaLister{err: errors.New(`relation "machine_identity_revocation_watermark" does not exist`)},
	}
	ids, binds, meta, err := p.loadAPIMachineIdentitySectionsStrict(ctx)
	if err != nil || ids != nil || binds != nil || meta != nil {
		t.Fatalf("missing watermark table should drop sections without error: ids=%v binds=%v meta=%v err=%v", ids, binds, meta, err)
	}

	// 7. identity_behavior
	p = &Provider{behaviorPolicy: &fakeBehaviorPolicyLister{err: dbErr}}
	if err := p.loadIdentityBehaviorStrict(ctx, &gatewayconfig.GuardConfig{}); err == nil {
		t.Fatal("identity_behavior strict loader must fail hard on real DB error")
	}
	p = &Provider{behaviorPolicy: &fakeBehaviorPolicyLister{err: errors.New(`relation "security_behavior_policy" does not exist`)}}
	if err := p.loadIdentityBehaviorStrict(ctx, &gatewayconfig.GuardConfig{}); err != nil {
		t.Fatalf("identity_behavior missing table should tolerate: %v", err)
	}

	// 8. risk_policy & overrides
	p = &Provider{riskPolicy: &fakeRiskPolicyGlobalLister{err: dbErr}}
	if err := p.loadRiskPolicyStrict(ctx, &gatewayconfig.GuardConfig{}); err == nil {
		t.Fatal("risk_policy global strict loader must fail hard on real DB error")
	}
	p = &Provider{riskPolicy: &fakeRiskPolicyGlobalLister{
		pol:         &gatewayconfig.GuardRiskPolicy{Enabled: true, Mode: "PROTECT", Version: 2},
		overrideErr: dbErr,
	}}
	if err := p.loadRiskPolicyStrict(ctx, &gatewayconfig.GuardConfig{}); err == nil {
		t.Fatal("risk_policy overrides strict loader must fail hard on real DB error")
	}
	cfg := &gatewayconfig.GuardConfig{}
	p = &Provider{riskPolicy: &fakeRiskPolicyGlobalLister{
		pol:         &gatewayconfig.GuardRiskPolicy{Enabled: true, Mode: "PROTECT", Version: 2},
		overrideErr: errors.New(`relation "security_risk_policy_overrides" does not exist`),
	}}
	if err := p.loadRiskPolicyStrict(ctx, cfg); err != nil || cfg.RiskPolicy == nil {
		t.Fatalf("risk_policy missing overrides table should keep global policy: cfg=%+v err=%v", cfg, err)
	}
}

// TestReplayRuntimeSecretsClearsAllRuntimeFlagsAndReinjectsStrongFlowKey 验证回滚重放：
// 清零新增 3 个 runtime 字段（DebugCCCounter / APINodeHeartbeatSeconds / APIAuthzClockSkewMaxSeconds），
// 并为强流程-only 快照重注入 APIAuthzObjectHMACKeyHex。
func TestReplayRuntimeSecretsClearsAllRuntimeFlagsAndReinjectsStrongFlowKey(t *testing.T) {
	const currentKey = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"
	p := &Provider{
		runtimeSettingsLoader: func(context.Context) (map[string]string, error) {
			return map[string]string{}, nil
		},
		authzObjectHMACKey: func(context.Context) (string, error) { return currentKey, nil },
	}
	cfg := &gatewayconfig.GuardConfig{
		DebugCCCounter:              true,
		APINodeHeartbeatSeconds:     60,
		APIAuthzClockSkewMaxSeconds: 90,
		APIStrongFlows:              testStrongFlows(),
		APIAuthzObjectHMACKeyHex:    redactPlaceholder,
	}
	if err := p.replayRuntimeSecrets(context.Background(), cfg); err != nil {
		t.Fatalf("replayRuntimeSecrets: %v", err)
	}
	if cfg.DebugCCCounter || cfg.APINodeHeartbeatSeconds != 0 || cfg.APIAuthzClockSkewMaxSeconds != 0 {
		t.Fatalf("stale runtime flags not cleared on replay: debug=%v hb=%d skew=%d",
			cfg.DebugCCCounter, cfg.APINodeHeartbeatSeconds, cfg.APIAuthzClockSkewMaxSeconds)
	}
	if cfg.APIAuthzObjectHMACKeyHex != currentKey {
		t.Fatalf("strong-flow-only snapshot authz HMAC key = %q, want %q", cfg.APIAuthzObjectHMACKeyHex, currentKey)
	}
}

// TestLoadCurrentSecretsDecoupledFromPolicyTables 验证 LoadCurrentSecrets 仅加载运行时密钥与 Valkey，
// 即使其他策略 lister 全部报错或非密钥运行时键非法，应急回滚重注入密钥仍能成功。
func TestLoadCurrentSecretsDecoupledFromPolicyTables(t *testing.T) {
	const (
		ticketKey = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"
		maskKey   = "fedcba9876543210fedcba9876543210fedcba9876543210fedcba9876543210"
		authzKey  = "111122223333444455556666777788889999aaaabbbbccccddddeeeeffff0000"
		labKey    = "aaaabbbbccccddddeeeeffff0000111122223333444455556666777788889999"
	)
	p := &Provider{
		valkeyAddr:     "valkey:6379",
		valkeyPassword: "vk-secret",
		valkeyDB:       2,
		// 故意设置坏的策略 lister 与非法的非密钥 runtime 配置，验证 LoadCurrentSecrets 不受影响
		strongFlows: &fakeStrongFlowLister{err: errors.New("broken policy table")},
		riskPolicy:  &fakeRiskPolicyGlobalLister{err: errors.New("broken risk table")},
		runtimeSettingsLoader: func(context.Context) (map[string]string, error) {
			return map[string]string{
				"identity_salt":          "salt-v2",
				"tls_session_ticket_key": ticketKey,
				"behavior_store":         "INVALID_VALUE_MUST_BE_IGNORED",
			}, nil
		},
		scanVerification: func(context.Context) (string, error) { return scanTestKeyHex, nil },
		fileSignature:    func(context.Context) (string, string, error) { return "fs-kid", sigTestKeyHex, nil },
		maskCrypto:       func(context.Context) (string, string, error) { return "mk-kid", maskKey, nil },
		authzObjectHMACKey: func(context.Context) (string, error) {
			return authzKey, nil
		},
		botSigningKeys: func(context.Context) (map[string]string, error) {
			return map[string]string{"bot-k1": ticketKey}, nil
		},
		aiCrawlLabyrinthKey: func(_ context.Context, createIfAbsent bool) (string, error) {
			if createIfAbsent {
				t.Error("LoadCurrentSecrets must not create labyrinth key on rollback")
			}
			return labKey, nil
		},
	}

	cur, err := p.LoadCurrentSecrets(context.Background())
	if err != nil {
		t.Fatalf("LoadCurrentSecrets: %v", err)
	}
	if cur.Valkey == nil || cur.Valkey.Address != "valkey:6379" || cur.Valkey.Password != "vk-secret" || cur.Valkey.DB != 2 {
		t.Fatalf("valkey = %+v", cur.Valkey)
	}
	if cur.IdentitySalt != "salt-v2" || cur.TLSSessionTicketKey != ticketKey {
		t.Fatalf("salt=%q ticket=%q", cur.IdentitySalt, cur.TLSSessionTicketKey)
	}
	if cur.APIScanVerification == nil || cur.APIScanVerification.KeyHex != scanTestKeyHex {
		t.Fatalf("scanVerify = %+v", cur.APIScanVerification)
	}
	if cur.APIFileSignature == nil || cur.APIFileSignature.KeyHex != sigTestKeyHex {
		t.Fatalf("fileSig = %+v", cur.APIFileSignature)
	}
	if cur.APIMaskCrypto == nil || cur.APIMaskCrypto.KID != "mk-kid" || !strings.EqualFold(cur.APIMaskCrypto.KeyHex, maskKey) {
		t.Fatalf("maskCrypto = %+v", cur.APIMaskCrypto)
	}
	if cur.APIAuthzObjectHMACKeyHex != authzKey || cur.BotSigningKeys["bot-k1"] != ticketKey || cur.AICrawlLabyrinthKeyHex != labKey {
		t.Fatalf("authz/bot/labyrinth mismatch: authz=%q bot=%+v lab=%q",
			cur.APIAuthzObjectHMACKeyHex, cur.BotSigningKeys, cur.AICrawlLabyrinthKeyHex)
	}
}

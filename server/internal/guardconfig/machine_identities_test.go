// machine_identities_test.go 机器身份登记册与绑定下发单测（NG-ID g1 批次 B1，纯函数
// 不依赖数据库）：三加载器未注入/查询失败 Warn 跳过返回 nil（空段=网关机器身份零行为）、
// 正常读取透传（形状+稳定序）；meta 段组合语义——身份或绑定任一非空才下发、meta 读取
// 失败三段整体不下发（避免「有登记册无水位」模糊态）、登记册缺席而绑定在属设计 §1.8
// COV_NO_REGISTRY 明示降级保留。ENABLED-only/全键状态/稳定序由 PG 契约测试覆盖。
package guardconfig

import (
	"context"
	"errors"
	"testing"

	"github.com/jiuzhang-waf/server/internal/gatewayconfig"
)

// fakeMachineIdentityLister 内存版机器身份登记册读取（可注入错误路径）。
type fakeMachineIdentityLister struct {
	identities []gatewayconfig.GuardMachineIdentity
	err        error
}

func (f *fakeMachineIdentityLister) ListEnabledMachineIdentities(ctx context.Context) ([]gatewayconfig.GuardMachineIdentity, error) {
	_ = ctx
	return f.identities, f.err
}

// fakeMachineIdentityBindingLister 内存版机器身份绑定读取（可注入错误路径）。
type fakeMachineIdentityBindingLister struct {
	bindings []gatewayconfig.GuardMachineIdentityBinding
	err      error
}

func (f *fakeMachineIdentityBindingLister) ListAllMachineIdentityBindings(ctx context.Context) ([]gatewayconfig.GuardMachineIdentityBinding, error) {
	_ = ctx
	return f.bindings, f.err
}

// fakeMachineIdentityMetaLister 内存版机器身份元数据读取（可注入错误路径）。
type fakeMachineIdentityMetaLister struct {
	meta *gatewayconfig.GuardMachineIdentityMeta
	err  error
}

func (f *fakeMachineIdentityMetaLister) LoadMachineIdentityMeta(ctx context.Context) (*gatewayconfig.GuardMachineIdentityMeta, error) {
	_ = ctx
	return f.meta, f.err
}

func midRows() []gatewayconfig.GuardMachineIdentity {
	tenant := "tenant-a"
	revokedSeq := int64(3)
	return []gatewayconfig.GuardMachineIdentity{{
		IdentityName: "pay-gateway", TenantID: &tenant, Status: "ENABLED",
		Keys: []gatewayconfig.GuardMachineIdentityKey{
			{Kid: "k1", Alg: "ed25519", PublicKeyPEM: "pem-1", Status: "ACTIVE"},
			{Kid: "k2", Alg: "rsa-pss-sha512", PublicKeyPEM: "pem-2", Status: "REVOKED", RevokedSeq: &revokedSeq},
		},
	}}
}

func midBindingRows() []gatewayconfig.GuardMachineIdentityBinding {
	return []gatewayconfig.GuardMachineIdentityBinding{
		{ApplicationID: "a1", PathPrefix: "/api", Mode: "OBSERVE"},
		{ApplicationID: "a2", PathExact: "/api/pay", Mode: "PROTECT", ProofRequired: true},
	}
}

// TestMachineIDPrincipalBindingFP 发布域换算跨轨对齐（S7 批次 C 裁决 3 修复，
// S6 偏差 1 先例）：黄金值由独立实现（Python hmac 与 gateway
// detectors/machineid.principalFingerprint 实跑）三方互证一致——
// HMAC-SHA256(key=identity_salt, "jwt-principal:"+录入值) 截前 16 字节 hex；
// 空盐与网关同一缺省盐兜底；nil/空白录入不动（DB 保留运营录入值，换算仅发布边界）。
func TestMachineIDPrincipalBindingFP(t *testing.T) {
	const entered = "0123456789abcdef0123456789abcdef" // 管理面录入的 VerifiedPrincipalID 指纹值形态
	if got := machineIDPrincipalBindingFP("s7-align-salt", entered); got != "1c8f1dd2bbb7127cefe8138a5cb7787d" {
		t.Fatalf("有盐换算偏离网关域: %s", got)
	}
	if got := machineIDPrincipalBindingFP("", entered); got != "2fce1efdab9980f0dba3cb0385d26c25" {
		t.Fatalf("空盐缺省兜底偏离网关域: %s", got)
	}
	cfg := &gatewayconfig.GuardConfig{IdentitySalt: "s7-align-salt"}
	raw, blank := entered, "   "
	cfg.APIMachineIdentities = []gatewayconfig.GuardMachineIdentity{
		{IdentityName: "a", PrincipalBinding: &raw},
		{IdentityName: "b", PrincipalBinding: nil},
		{IdentityName: "c", PrincipalBinding: &blank},
	}
	applyMachineIDPrincipalBindingFP(cfg)
	if cfg.APIMachineIdentities[0].PrincipalBinding == nil ||
		*cfg.APIMachineIdentities[0].PrincipalBinding != "1c8f1dd2bbb7127cefe8138a5cb7787d" {
		t.Fatalf("发布域换算未生效: %+v", cfg.APIMachineIdentities[0].PrincipalBinding)
	}
	if cfg.APIMachineIdentities[1].PrincipalBinding != nil {
		t.Fatalf("nil 录入不得换算: %+v", cfg.APIMachineIdentities[1].PrincipalBinding)
	}
	if *cfg.APIMachineIdentities[2].PrincipalBinding != blank {
		t.Fatalf("空白录入不得换算: %+v", *cfg.APIMachineIdentities[2].PrincipalBinding)
	}
	applyMachineIDPrincipalBindingFP(nil) // nil 配置防御
}

// TestLoadAPIMachineIdentitiesTolerance 身份段：未注入 nil；查询失败（如 000183 表未
// 建立）Warn 跳过返回 nil（空段=零行为，不 fail-hard 拖垮发布）；正常读取透传
// （身份头+全状态键行形状原样——ENABLED-only 过滤在 SQL 层，PG 契约覆盖）。
func TestLoadAPIMachineIdentitiesTolerance(t *testing.T) {
	p := &Provider{}
	if got := p.loadAPIMachineIdentities(context.Background()); got != nil {
		t.Fatalf("nil lister must yield nil: %v", got)
	}
	p = &Provider{machineIdentities: &fakeMachineIdentityLister{err: errors.New(`relation "machine_identities" does not exist`)}}
	if got := p.loadAPIMachineIdentities(context.Background()); got != nil {
		t.Fatalf("missing table must be tolerated: %v", got)
	}
	p = &Provider{machineIdentities: &fakeMachineIdentityLister{identities: midRows()}}
	got := p.loadAPIMachineIdentities(context.Background())
	if len(got) != 1 || got[0].IdentityName != "pay-gateway" || len(got[0].Keys) != 2 ||
		got[0].Keys[1].Status != "REVOKED" || *got[0].Keys[1].RevokedSeq != 3 {
		t.Fatalf("身份段透传（全状态键行+revoked_seq）: %+v", got)
	}
}

// TestLoadAPIMachineIdentityBindingsTolerance 绑定段：未注入 nil；查询失败 Warn 跳过
// 返回 nil；正常读取透传（application_id/path_exact/path_prefix/mode/proof_required 全字段原样）。
func TestLoadAPIMachineIdentityBindingsTolerance(t *testing.T) {
	p := &Provider{}
	if got := p.loadAPIMachineIdentityBindings(context.Background()); got != nil {
		t.Fatalf("nil lister must yield nil: %v", got)
	}
	p = &Provider{machineIDBindings: &fakeMachineIdentityBindingLister{err: errors.New(`relation "machine_identity_bindings" does not exist`)}}
	if got := p.loadAPIMachineIdentityBindings(context.Background()); got != nil {
		t.Fatalf("missing table must be tolerated: %v", got)
	}
	p = &Provider{machineIDBindings: &fakeMachineIdentityBindingLister{bindings: midBindingRows()}}
	got := p.loadAPIMachineIdentityBindings(context.Background())
	if len(got) != 2 || got[0].Mode != "OBSERVE" || got[1].PathExact != "/api/pay" ||
		got[1].Mode != "PROTECT" || !got[1].ProofRequired {
		t.Fatalf("绑定段透传: %+v", got)
	}
}

// TestLoadAPIMachineIdentitySectionsMeta meta 段组合语义（§1.12/§1.6）：
// ① 身份与绑定皆空 → meta 不下发（三段全省略，NG-T-C01 零行为）；
// ② 身份或绑定任一非空 + meta 正常 → 三段同发（水位随行）；
// ③ meta 未注入 → 身份/绑定透传 meta 缺省（向后兼容——旧装配不读 meta）；
// ④ meta 读取失败 → 三段整体不下发（登记册不带水位单独下发会制造「有登记册无水位」
//
//	模糊态——网关保留旧配置比部分下发更安全，下次发布重试）；
//
// ⑤ 身份段加载失败（Warn 跳过）而绑定在 + meta 正常 → 绑定+meta 照发
//
//	（设计 §1.8 COV_NO_REGISTRY 明示降级，绑定驱动识别不因登记册缺席隐藏）。
func TestLoadAPIMachineIdentitySectionsMeta(t *testing.T) {
	meta := &gatewayconfig.GuardMachineIdentityMeta{RevocationWatermark: 3, RegistryVersion: 1760000000000}
	// ① 皆空 → meta 不下发
	p := &Provider{
		machineIdentities: &fakeMachineIdentityLister{},
		machineIDBindings: &fakeMachineIdentityBindingLister{},
		machineIDMeta:     &fakeMachineIdentityMetaLister{meta: meta},
	}
	ids, binds, m := p.loadAPIMachineIdentitySections(context.Background())
	if len(ids) != 0 || len(binds) != 0 || m != nil {
		t.Fatalf("皆空应三段全省略: %v %v %v", ids, binds, m)
	}
	// ② 任一非空 + meta 正常 → 三段同发
	p = &Provider{
		machineIdentities: &fakeMachineIdentityLister{identities: midRows()},
		machineIDBindings: &fakeMachineIdentityBindingLister{bindings: midBindingRows()},
		machineIDMeta:     &fakeMachineIdentityMetaLister{meta: meta},
	}
	ids, binds, m = p.loadAPIMachineIdentitySections(context.Background())
	if len(ids) != 1 || len(binds) != 2 || m == nil || m.RevocationWatermark != 3 {
		t.Fatalf("非空应三段同发: %v %v %v", ids, binds, m)
	}
	// 仅绑定非空也同发 meta（绑定驱动识别——水位比对不因登记册空而跳过）
	p = &Provider{
		machineIdentities: &fakeMachineIdentityLister{},
		machineIDBindings: &fakeMachineIdentityBindingLister{bindings: midBindingRows()},
		machineIDMeta:     &fakeMachineIdentityMetaLister{meta: meta},
	}
	ids, binds, m = p.loadAPIMachineIdentitySections(context.Background())
	if len(ids) != 0 || len(binds) != 2 || m == nil {
		t.Fatalf("仅绑定非空应绑定+meta 同发: %v %v %v", ids, binds, m)
	}
	// ③ meta 未注入 → 身份/绑定透传 meta 缺省
	p = &Provider{
		machineIdentities: &fakeMachineIdentityLister{identities: midRows()},
		machineIDBindings: &fakeMachineIdentityBindingLister{bindings: midBindingRows()},
	}
	ids, binds, m = p.loadAPIMachineIdentitySections(context.Background())
	if len(ids) != 1 || len(binds) != 2 || m != nil {
		t.Fatalf("meta 未注入应透传身份/绑定: %v %v %v", ids, binds, m)
	}
	// ④ meta 读取失败 → 三段整体不下发
	p = &Provider{
		machineIdentities: &fakeMachineIdentityLister{identities: midRows()},
		machineIDBindings: &fakeMachineIdentityBindingLister{bindings: midBindingRows()},
		machineIDMeta:     &fakeMachineIdentityMetaLister{err: errors.New(`relation "machine_identity_revocation_watermark" does not exist`)},
	}
	ids, binds, m = p.loadAPIMachineIdentitySections(context.Background())
	if ids != nil || binds != nil || m != nil {
		t.Fatalf("meta 失败应三段同弃: %v %v %v", ids, binds, m)
	}
	// ⑤ 登记册缺席而绑定在 → 绑定+meta 照发（COV_NO_REGISTRY 明示降级）
	p = &Provider{
		machineIdentities: &fakeMachineIdentityLister{err: errors.New(`relation "machine_identities" does not exist`)},
		machineIDBindings: &fakeMachineIdentityBindingLister{bindings: midBindingRows()},
		machineIDMeta:     &fakeMachineIdentityMetaLister{meta: meta},
	}
	ids, binds, m = p.loadAPIMachineIdentitySections(context.Background())
	if ids != nil || len(binds) != 2 || m == nil {
		t.Fatalf("登记册缺席应绑定+meta 照发: %v %v %v", ids, binds, m)
	}
}

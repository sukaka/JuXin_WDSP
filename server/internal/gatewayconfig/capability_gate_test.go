// capability_gate_test.go 节点能力发布门单元测试（NG-COV-04）：
// 空需求零门禁（存量发布不受影响）、特性段→需求映射逐键、缺 manifest fail-closed、
// stale manifest fail-closed、层级不足列出缺口（CAP_MISSING:<key>）、满足时放行、
// 次要节点 v1 边界 fail-closed。
package gatewayconfig

import (
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/jiuzhang-waf/gateway/dynamic_security/capability"
)

// writeManifest 落一份清单到 sidecar 目录（测试辅助）。
func writeManifest(t *testing.T, dir string, m capability.Manifest) {
	t.Helper()
	raw, err := json.Marshal(m)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, capabilityManifestFile), raw, 0o644); err != nil {
		t.Fatal(err)
	}
}

// fullManifest 满足全部 v1 需求的节点清单（与网关自报同形）。
func fullManifest(nodeID string, generatedAt time.Time) capability.Manifest {
	return capability.Manifest{
		ContractVersion: capability.ContractVersion,
		NodeID:          nodeID,
		ProductVersion:  "jiuzhang-guard/wdsp",
		Protocols:       map[string]string{"http": "1.1", "graphql": "parse", "grpc": "unary_g1", "mcp": "observe"},
		Detectors: []capability.DetectorCap{
			{Name: "pipeline", Version: "pipeline/1"},
			{Name: "authzdecide", Version: "az/2"}, // NG-AZ-02：当前网关自报（az/1 为旧节点）
			{Name: "graphql.parser", Version: "gql/1"},
			{Name: "grpc.frame", Version: "grpc/1"},
			{Name: "grpc.unary", Version: "grpc/1"},
			{Name: "mcp.observe", Version: "mcp/1"},
		},
		Actions:     []string{"block", "temp_block", "rate_limit", "mask_response", "observe", "allow"},
		Limits:      map[string]int64{"max_grpc_frame_bytes": 64 << 20},
		GeneratedAt: generatedAt.UTC().Format(time.RFC3339),
	}
}

// grpcGuardCfg 构造含 grpc 特性段的发布负载。
func grpcGuardCfg(f CapabilityFacts) *GuardConfig {
	cfg := &GuardConfig{
		APIGRPCAllowCompression: f.GRPCAllowCompression,
		APIGRPCMaxFrameBytes:    f.GRPCMaxFrameBytes,
	}
	for i := 0; i < f.GRPCDescriptorSets; i++ {
		cfg.APIGRPCDescriptors = append(cfg.APIGRPCDescriptors, GuardGRPCDescriptor{})
	}
	return cfg
}

// 空需求零门禁：guardCfg nil / 无特性段 / 清单不存在，发布均不受影响（存量兼容约束）。
func TestCapabilityGateEmptyRequiredZeroGate(t *testing.T) {
	p := &Publisher{sidecarDir: t.TempDir()} // 目录无 manifest——空需求时根本不应读
	for _, cfg := range []*GuardConfig{nil, {}, {APIGRPCAllowCompression: false}} {
		ok, code, msg := p.evaluateCapabilityGate(context.Background(), cfg)
		if !ok || code != "" || msg != "" {
			t.Fatalf("空需求必须免门禁（存量发布零变化）: cfg=%+v ok=%t code=%s msg=%s", cfg, ok, code, msg)
		}
	}
	if !requiredEmpty(RequiredCapabilities(CapabilityFacts{})) {
		t.Fatal("零值事实必须推导空需求")
	}
}

// 特性段→需求映射逐键锚定。
func TestRequiredCapabilitiesMapping(t *testing.T) {
	// 描述符非空 → protocols.grpc=unary_g1 + detectors.grpc.unary
	r := RequiredCapabilities(CapabilityFacts{GRPCDescriptorSets: 2})
	if r.Protocols["grpc"] != "unary_g1" {
		t.Fatalf("描述符非空应需求 unary_g1: %+v", r.Protocols)
	}
	if len(r.Detectors) != 1 || r.Detectors[0].Name != "grpc.unary" || r.Detectors[0].Version != "grpc/1" {
		t.Fatalf("描述符非空应需求 grpc.unary 检测器: %+v", r.Detectors)
	}
	// 仅压缩 → 同族 frame + grpc.frame（unary 隐含 frame，二者不重复需求）
	r = RequiredCapabilities(CapabilityFacts{GRPCAllowCompression: true})
	if r.Protocols["grpc"] != "frame" || len(r.Detectors) != 1 || r.Detectors[0].Name != "grpc.frame" {
		t.Fatalf("压缩应需求 frame 同族: %+v %+v", r.Protocols, r.Detectors)
	}
	// 描述符+压缩：unary_g1 主导（不降级 frame）
	r = RequiredCapabilities(CapabilityFacts{GRPCDescriptorSets: 1, GRPCAllowCompression: true})
	if r.Protocols["grpc"] != "unary_g1" {
		t.Fatalf("unary_g1 应主导: %+v", r.Protocols)
	}
	// 帧上限 → limits.max_grpc_frame_bytes
	r = RequiredCapabilities(CapabilityFacts{GRPCMaxFrameBytes: 8 << 20})
	if r.Limits["max_grpc_frame_bytes"] != 8<<20 {
		t.Fatalf("帧上限需求不符: %+v", r.Limits)
	}
	// 组合
	r = RequiredCapabilities(CapabilityFacts{GRPCDescriptorSets: 1, GRPCMaxFrameBytes: 4 << 20})
	if requiredEmpty(r) || r.Protocols["grpc"] != "unary_g1" || r.Limits["max_grpc_frame_bytes"] != 4<<20 {
		t.Fatalf("组合需求不符: %+v", r)
	}
	// 契约版本恒置（协商一致性检查前提）
	if r.ContractVersion != capability.ContractVersion {
		t.Fatalf("契约版本不符: %q", r.ContractVersion)
	}
}

// NG-AZ-02 D4-4：v2 授权快照 → detectors.authzdecide=az/2 需求。
func TestRequiredCapabilitiesAuthzV2(t *testing.T) {
	// v1 快照（schema 空）→ 无 authzdecide 需求
	r := RequiredCapabilities(CapabilityFacts{AuthzSnapshotV2: false})
	for _, d := range r.Detectors {
		if d.Name == "authzdecide" {
			t.Fatalf("v1 快照不得需求 authzdecide: %+v", r.Detectors)
		}
	}
	// v2 快照 → az/2 需求
	r = RequiredCapabilities(CapabilityFacts{AuthzSnapshotV2: true})
	found := false
	for _, d := range r.Detectors {
		if d.Name == "authzdecide" {
			found = true
			if d.Version != "az/2" {
				t.Fatalf("v2 快照应需求 az/2: %+v", d)
			}
		}
	}
	if !found {
		t.Fatalf("v2 快照必须需求 authzdecide: %+v", r.Detectors)
	}
	if requiredEmpty(r) {
		t.Fatal("v2 快照需求不得为空（门禁激活）")
	}
}

// NG-AZ-02 D4-4 门控：az/1 旧节点对 v2 快照 fail-closed（CAPABILITY_MISSING）；
// az/2 节点放行。
func TestCapabilityGateAuthzV2(t *testing.T) {
	dir := t.TempDir()
	// az/1 旧节点 manifest
	old := fullManifest("gw-old", time.Now().UTC())
	for i := range old.Detectors {
		if old.Detectors[i].Name == "authzdecide" {
			old.Detectors[i].Version = "az/1"
		}
	}
	writeManifest(t, dir, old)
	p := &Publisher{sidecarDir: dir}
	cfg := &GuardConfig{APIAuthzSchema: "authz-snap/2"}
	ok, code, msg := p.evaluateCapabilityGate(context.Background(), cfg)
	if ok || code != "CAPABILITY_MISSING" {
		t.Fatalf("az/1 旧节点应 fail-closed: ok=%t code=%s", ok, code)
	}
	if !strings.Contains(msg, "CAP_MISSING:detectors.authzdecide") {
		t.Fatalf("缺口应含 detectors.authzdecide: %s", msg)
	}
	// az/2 节点放行（fullManifest 已含 az/2）
	dir2 := t.TempDir()
	writeManifest(t, dir2, fullManifest("gw-new", time.Now().UTC()))
	p2 := &Publisher{sidecarDir: dir2}
	if ok, code, msg := p2.evaluateCapabilityGate(context.Background(), cfg); !ok || code != "" {
		t.Fatalf("az/2 节点应放行: ok=%t code=%s msg=%s", ok, code, msg)
	}
}

// 缺 manifest → fail-closed CAPABILITY_MANIFEST_UNAVAILABLE（有需求时）。
func TestCapabilityGateMissingManifestFailClosed(t *testing.T) {
	p := &Publisher{sidecarDir: t.TempDir()}
	ok, code, msg := p.evaluateCapabilityGate(context.Background(), grpcGuardCfg(CapabilityFacts{GRPCDescriptorSets: 1}))
	if ok || code != "CAPABILITY_MANIFEST_UNAVAILABLE" {
		t.Fatalf("缺 manifest 必须 fail-closed: ok=%t code=%s", ok, code)
	}
	if !strings.Contains(msg, capabilityManifestFile) {
		t.Fatalf("message 应含清单路径: %s", msg)
	}
}

// 契约违规 manifest（坏 contract_version）→ 同样清单不可用 fail-closed。
func TestCapabilityGateContractMismatchFailClosed(t *testing.T) {
	dir := t.TempDir()
	m := fullManifest("gw-1", time.Now().UTC())
	m.ContractVersion = "ngc/9.9"
	writeManifest(t, dir, m)
	p := &Publisher{sidecarDir: dir}
	ok, code, _ := p.evaluateCapabilityGate(context.Background(), grpcGuardCfg(CapabilityFacts{GRPCDescriptorSets: 1}))
	if ok || code != "CAPABILITY_MANIFEST_UNAVAILABLE" {
		t.Fatalf("契约版本不一致应拒绝协商: ok=%t code=%s", ok, code)
	}
}

// stale manifest（generated_at 超 3×tick）→ fail-closed 并注明陈旧度。
func TestCapabilityGateStaleManifestFailClosed(t *testing.T) {
	dir := t.TempDir()
	writeManifest(t, dir, fullManifest("gw-1", time.Now().UTC().Add(-10*time.Minute)))
	p := &Publisher{sidecarDir: dir}
	ok, code, msg := p.evaluateCapabilityGate(context.Background(), grpcGuardCfg(CapabilityFacts{GRPCDescriptorSets: 1}))
	if ok || code != "CAPABILITY_MANIFEST_UNAVAILABLE" {
		t.Fatalf("stale manifest 必须 fail-closed: ok=%t code=%s", ok, code)
	}
	if !strings.Contains(msg, "过期") || !strings.Contains(msg, "陈旧") {
		t.Fatalf("message 应注明过期与陈旧度: %s", msg)
	}
	// generated_at 不可解析同样按过期处理
	writeManifest(t, dir, func() capability.Manifest {
		m := fullManifest("gw-1", time.Now().UTC())
		m.GeneratedAt = "not-a-time"
		return m
	}())
	if stale, _ := ManifestStale(fullManifest("gw-1", time.Now()), time.Now(), capabilityStaleAfter); stale {
		t.Fatal("新鲜清单不得误判 stale")
	}
	ok, code, _ = p.evaluateCapabilityGate(context.Background(), grpcGuardCfg(CapabilityFacts{GRPCDescriptorSets: 1}))
	if ok || code != "CAPABILITY_MANIFEST_UNAVAILABLE" {
		t.Fatalf("generated_at 不可解析应按过期 fail-closed: ok=%t code=%s", ok, code)
	}
}

// 层级不足 → CAPABILITY_MISSING，message 含全部缺口明细（CAP_MISSING:<key>）。
func TestCapabilityGateMissingListsGaps(t *testing.T) {
	dir := t.TempDir()
	m := fullManifest("gw-1", time.Now().UTC())
	m.Protocols["grpc"] = "frame" // 层级不足
	m.Detectors = m.Detectors[:4] // 去掉 grpc.unary
	m.Limits["max_grpc_frame_bytes"] = 4 << 20
	writeManifest(t, dir, m)
	p := &Publisher{sidecarDir: dir}
	cfg := grpcGuardCfg(CapabilityFacts{GRPCDescriptorSets: 1, GRPCMaxFrameBytes: 8 << 20})
	ok, code, msg := p.evaluateCapabilityGate(context.Background(), cfg)
	if ok || code != "CAPABILITY_MISSING" {
		t.Fatalf("层级不足必须拒绝: ok=%t code=%s", ok, code)
	}
	for _, want := range []string{"CAP_MISSING:protocols.grpc", "CAP_MISSING:detectors.grpc.unary", "CAP_MISSING:limits.max_grpc_frame_bytes", "gw-1"} {
		if !strings.Contains(msg, want) {
			t.Fatalf("message 缺缺口明细 %q: %s", want, msg)
		}
	}
}

// 满足时放行。
func TestCapabilityGateSatisfiedAllows(t *testing.T) {
	dir := t.TempDir()
	writeManifest(t, dir, fullManifest("gw-1", time.Now().UTC()))
	p := &Publisher{sidecarDir: dir}
	cfg := grpcGuardCfg(CapabilityFacts{GRPCDescriptorSets: 1, GRPCAllowCompression: true, GRPCMaxFrameBytes: 8 << 20})
	ok, code, msg := p.evaluateCapabilityGate(context.Background(), cfg)
	if !ok || code != "" || msg != "" {
		t.Fatalf("满足应放行: ok=%t code=%s msg=%s", ok, code, msg)
	}
}

// 次要节点 v1 边界：有需求且登记了次要节点 → fail-closed 并列出节点。
type fakeNodeSync struct {
	targets []SyncTarget
	err     error
}

func (f fakeNodeSync) ListSyncTargets(ctx context.Context) ([]SyncTarget, error) {
	return f.targets, f.err
}
func (f fakeNodeSync) RecordSyncResult(ctx context.Context, nodeID uuid.UUID, result, errMsg string, versionID uuid.UUID) error {
	return nil
}

func TestCapabilityGateSecondaryNodesFailClosed(t *testing.T) {
	dir := t.TempDir()
	writeManifest(t, dir, fullManifest("gw-1", time.Now().UTC()))
	p := &Publisher{sidecarDir: dir}
	p.SetNodeSyncStore(fakeNodeSync{targets: []SyncTarget{{NodeID: uuid.New(), NodeName: "gw-b"}}})
	cfg := grpcGuardCfg(CapabilityFacts{GRPCDescriptorSets: 1})
	ok, code, msg := p.evaluateCapabilityGate(context.Background(), cfg)
	if ok || code != "CAPABILITY_MANIFEST_UNAVAILABLE" {
		t.Fatalf("次要节点 manifest 通道 v1 未建必须 fail-closed: ok=%t code=%s", ok, code)
	}
	if !strings.Contains(msg, "gw-b") {
		t.Fatalf("message 应列出次要节点: %s", msg)
	}
	// 无次要节点时不受 v1 边界影响
	p2 := &Publisher{sidecarDir: dir}
	p2.SetNodeSyncStore(fakeNodeSync{})
	if ok, code, _ := p2.evaluateCapabilityGate(context.Background(), cfg); !ok || code != "" {
		t.Fatalf("无次要节点应放行: ok=%t code=%s", ok, code)
	}
}

// LoadNodeManifest 读侧契约：文件缺失/坏 JSON/契约违规三类错误。
func TestLoadNodeManifestErrors(t *testing.T) {
	dir := t.TempDir()
	if _, err := LoadNodeManifest(dir); err == nil {
		t.Fatal("缺文件应报错")
	}
	if err := os.WriteFile(filepath.Join(dir, capabilityManifestFile), []byte("{bad"), 0o644); err != nil {
		t.Fatal(err)
	}
	if _, err := LoadNodeManifest(dir); err == nil {
		t.Fatal("坏 JSON 应报错")
	}
	m := fullManifest("gw-1", time.Now().UTC())
	m.NodeID = "" // 契约违规
	writeManifest(t, dir, m)
	if _, err := LoadNodeManifest(dir); err == nil {
		t.Fatal("契约违规应报错")
	}
	writeManifest(t, dir, fullManifest("gw-1", time.Now().UTC()))
	if _, err := LoadNodeManifest(dir); err != nil {
		t.Fatalf("合法清单应读取成功: %v", err)
	}
}

// NG-AZ-03 D6：含任一 enforcement=PROTECT 端点的快照 → detectors.authzdecide=az/3 需求
// （覆盖 az/2 需求；az/1/az/2 节点 fail-closed——不得在看不见资格的节点上实断或漏断）。
func TestRequiredCapabilitiesAuthzV3(t *testing.T) {
	// PROTECT 无 v2 schema（如 baselines-only 发布路径）→ 仍需求 az/3（实断消费语义与水位无关）
	r := RequiredCapabilities(CapabilityFacts{AuthzEnforceProtect: true})
	az := detectorVersion(r, "authzdecide")
	if az != "az/3" {
		t.Fatalf("含 PROTECT 快照应需求 az/3: %+v", r.Detectors)
	}
	// PROTECT + v2 schema：az/3 主导，不得同时列 az/2（需求互斥——az/3 已涵盖 v2 消费语义）
	r = RequiredCapabilities(CapabilityFacts{AuthzSnapshotV2: true, AuthzEnforceProtect: true})
	az = detectorVersion(r, "authzdecide")
	if az != "az/3" {
		t.Fatalf("PROTECT 应主导需求 az/3: %+v", r.Detectors)
	}
	count := 0
	for _, d := range r.Detectors {
		if d.Name == "authzdecide" {
			count++
		}
	}
	if count != 1 {
		t.Fatalf("authzdecide 需求应恰一条: %+v", r.Detectors)
	}
	// 全 OBSERVE（AuthzEnforceProtect=false）+ v2 → az/2（既有行为不变，滚动升级可行）
	r = RequiredCapabilities(CapabilityFacts{AuthzSnapshotV2: true})
	if az := detectorVersion(r, "authzdecide"); az != "az/2" {
		t.Fatalf("全 OBSERVE v2 快照应需求 az/2: %+v", r.Detectors)
	}
}

// detectorVersion 取需求清单中指定检测器的版本（不存在返回 ""）。
func detectorVersion(m capability.Manifest, name string) string {
	for _, d := range m.Detectors {
		if d.Name == name {
			return d.Version
		}
	}
	return ""
}

// NG-AZ-03 D6 聚合：门评估输入从发布负载 enforcement 字段聚合（编译期已知）——
// 对象模型与角色基线任一 PROTECT 行即构成「含实断配置的快照」。
func TestCapabilityFactsFromGuardAuthzProtect(t *testing.T) {
	if f := capabilityFactsFromGuard(nil); f.AuthzEnforceProtect {
		t.Fatal("nil guardCfg 不得聚合出 PROTECT 事实")
	}
	// 全 OBSERVE：模型与角色基线均不产生需求（D10 缺省零变化）
	allObserve := &GuardConfig{
		APIAuthzModels:        []GuardAuthzObjectModel{{EndpointKey: "GET /v1/a/{id}", Enforcement: "OBSERVE", OnUnknown: "ALLOW_UNKNOWN"}},
		APIAuthzRoleBaselines: []GuardAuthzRoleBaseline{{EndpointKey: "GET /v1/a", Role: "ops", Enforcement: "OBSERVE"}},
	}
	if f := capabilityFactsFromGuard(allObserve); f.AuthzEnforceProtect {
		t.Fatalf("全 OBSERVE 不得聚合出 PROTECT 事实: %+v", f)
	}
	// 对象模型含一条 PROTECT → true
	modelProtect := &GuardConfig{
		APIAuthzModels: []GuardAuthzObjectModel{
			{EndpointKey: "GET /v1/a/{id}", Enforcement: "OBSERVE"},
			{EndpointKey: "GET /v1/b/{id}", Enforcement: "PROTECT", EnforcementOwner: "owner-1", EvidenceSource: "AUTHORITY_SYNC", OnUnknown: "ALLOW_UNKNOWN"},
		},
	}
	if f := capabilityFactsFromGuard(modelProtect); !f.AuthzEnforceProtect {
		t.Fatalf("模型含 PROTECT 应聚合出 PROTECT 事实: %+v", f)
	}
	// 仅角色基线含 PROTECT（baselines-only 路径）→ true
	baselineProtect := &GuardConfig{
		APIAuthzRoleBaselines: []GuardAuthzRoleBaseline{{EndpointKey: "GET /v1/a", Role: "ops", Enforcement: "PROTECT"}},
	}
	if f := capabilityFactsFromGuard(baselineProtect); !f.AuthzEnforceProtect {
		t.Fatalf("角色基线含 PROTECT 应聚合出 PROTECT 事实: %+v", f)
	}
}

// NG-AZ-03 D6 门控两态（NG-T-C08 同形态）：az/2 自报节点收到含 PROTECT 快照
// fail-closed（CAP_MISSING az/3）；az/3 节点正常应用；enforcement 全 OBSERVE 快照
// 在 az/2 节点照常放行（滚动升级路径）。
func TestCapabilityGateAuthzV3(t *testing.T) {
	protectCfg := &GuardConfig{
		APIAuthzSchema: "authz-snap/2",
		APIAuthzModels: []GuardAuthzObjectModel{{EndpointKey: "GET /v1/b/{id}", Enforcement: "PROTECT", EnforcementOwner: "owner-1", EvidenceSource: "AUTHORITY_SYNC", OnUnknown: "ALLOW_UNKNOWN"}},
	}
	// az/2 节点 + 含 PROTECT 快照 → fail-closed
	dir := t.TempDir()
	writeManifest(t, dir, fullManifest("gw-az2", time.Now().UTC())) // fullManifest 自报 az/2
	p := &Publisher{sidecarDir: dir}
	ok, code, msg := p.evaluateCapabilityGate(context.Background(), protectCfg)
	if ok || code != "CAPABILITY_MISSING" {
		t.Fatalf("az/2 节点收含 PROTECT 快照应 fail-closed: ok=%t code=%s", ok, code)
	}
	if !strings.Contains(msg, "CAP_MISSING:detectors.authzdecide(required=az/3,actual=az/2)") {
		t.Fatalf("缺口应为 az/3 vs az/2: %s", msg)
	}
	// az/3 节点 + 含 PROTECT 快照 → 放行
	dir2 := t.TempDir()
	az3 := fullManifest("gw-az3", time.Now().UTC())
	for i := range az3.Detectors {
		if az3.Detectors[i].Name == "authzdecide" {
			az3.Detectors[i].Version = "az/3"
		}
	}
	writeManifest(t, dir2, az3)
	p2 := &Publisher{sidecarDir: dir2}
	if ok, code, msg := p2.evaluateCapabilityGate(context.Background(), protectCfg); !ok || code != "" {
		t.Fatalf("az/3 节点应收含 PROTECT 快照: ok=%t code=%s msg=%s", ok, code, msg)
	}
	// 全 OBSERVE 快照 + az/2 节点 → 放行（滚动升级可行；az/2 需求已被满足）
	observeCfg := &GuardConfig{
		APIAuthzSchema: "authz-snap/2",
		APIAuthzModels: []GuardAuthzObjectModel{{EndpointKey: "GET /v1/a/{id}", Enforcement: "OBSERVE", OnUnknown: "ALLOW_UNKNOWN"}},
	}
	if ok, code, msg := p.evaluateCapabilityGate(context.Background(), observeCfg); !ok || code != "" {
		t.Fatalf("az/2 节点收全 OBSERVE 快照应放行（滚动升级）: ok=%t code=%s msg=%s", ok, code, msg)
	}
}

// NG-FLOW-02 D12：含任一 mode=PROTECT 强流程定义的快照 → detectors.flowguard=flow/1
// 需求；全 OBSERVE 不产生需求（滚动升级可行——az/3 同纪律先例）。
func TestRequiredCapabilitiesStrongFlow(t *testing.T) {
	// 无强流程段 → 无 flowguard 需求
	r := RequiredCapabilities(CapabilityFacts{})
	if az := detectorVersion(r, "flowguard"); az != "" {
		t.Fatalf("无强流程段不得需求 flowguard: %+v", r.Detectors)
	}
	// 全 OBSERVE → 无需求
	r = RequiredCapabilities(CapabilityFacts{StrongFlowProtect: false})
	if az := detectorVersion(r, "flowguard"); az != "" {
		t.Fatalf("全 OBSERVE 不产生需求: %+v", r.Detectors)
	}
	// 含 PROTECT → flow/1
	r = RequiredCapabilities(CapabilityFacts{StrongFlowProtect: true})
	if az := detectorVersion(r, "flowguard"); az != "flow/1" {
		t.Fatalf("含 PROTECT 定义应需求 flow/1: %+v", r.Detectors)
	}
	// 聚合：APIStrongFlows 任一 PROTECT
	cfg := &GuardConfig{APIStrongFlows: []GuardStrongFlowDefinition{{Name: "f1", Mode: "OBSERVE"}, {Name: "f2", Mode: "PROTECT"}}}
	if f := capabilityFactsFromGuard(cfg); !f.StrongFlowProtect {
		t.Fatalf("含 PROTECT 定义应聚合出 StrongFlowProtect: %+v", f)
	}
	if f := capabilityFactsFromGuard(&GuardConfig{APIStrongFlows: []GuardStrongFlowDefinition{{Name: "f1", Mode: "OBSERVE"}}}); f.StrongFlowProtect {
		t.Fatal("全 OBSERVE 不得聚合出 StrongFlowProtect")
	}
}

// NG-FLOW-02 D12 门控：flow/0 旧节点（无 flowguard 自报）收含 PROTECT 快照
// fail-closed；flow/1 节点放行；全 OBSERVE 快照在无 flowguard 自报节点照常（滚动升级）。
func TestCapabilityGateStrongFlow(t *testing.T) {
	protectCfg := &GuardConfig{APIStrongFlows: []GuardStrongFlowDefinition{{Name: "f1", Mode: "PROTECT"}}}
	// 旧节点（fullManifest 无 flowguard 自报）→ fail-closed
	dir := t.TempDir()
	writeManifest(t, dir, fullManifest("gw-old", time.Now().UTC()))
	p := &Publisher{sidecarDir: dir}
	ok, code, msg := p.evaluateCapabilityGate(context.Background(), protectCfg)
	if ok || code != "CAPABILITY_MISSING" {
		t.Fatalf("无 flowguard 自报节点应收含 PROTECT 快照 fail-closed: ok=%t code=%s", ok, code)
	}
	if !strings.Contains(msg, "CAP_MISSING:detectors.flowguard(required=flow/1") {
		t.Fatalf("缺口应含 flowguard flow/1: %s", msg)
	}
	// flow/1 节点 → 放行
	dir2 := t.TempDir()
	m := fullManifest("gw-new", time.Now().UTC())
	m.Detectors = append(m.Detectors, capability.DetectorCap{Name: "flowguard", Version: "flow/1"})
	writeManifest(t, dir2, m)
	p2 := &Publisher{sidecarDir: dir2}
	if ok, code, msg := p2.evaluateCapabilityGate(context.Background(), protectCfg); !ok || code != "" {
		t.Fatalf("flow/1 节点应收含 PROTECT 快照: ok=%t code=%s msg=%s", ok, code, msg)
	}
	// 全 OBSERVE 快照 → 旧节点放行（滚动升级）
	observeCfg := &GuardConfig{APIStrongFlows: []GuardStrongFlowDefinition{{Name: "f1", Mode: "OBSERVE"}}}
	if ok, code, msg := p.evaluateCapabilityGate(context.Background(), observeCfg); !ok || code != "" {
		t.Fatalf("旧节点收全 OBSERVE 快照应放行: ok=%t code=%s msg=%s", ok, code, msg)
	}
}

// TestRequiredCapabilitiesGRPCBindingProtect NG-GRPC G1 批次 B1 能力门两态：
// 含任一 PROTECT 绑定 → detectors.grpc.unary=grpc/2（协议化执行消费语义——旧节点
// 不得把违规实断成 HTTP 403 误形态）；全 OBSERVE/空绑定 → grpc/1 现状零变化
// （滚动升级可行）；无描述符集的孤立 PROTECT 绑定同样产 grpc/2（意图实断即需求）。
func TestRequiredCapabilitiesGRPCBindingProtect(t *testing.T) {
	// PROTECT 绑定+描述符集 → grpc/2（unary_g1 层级不动）
	r := RequiredCapabilities(CapabilityFacts{GRPCDescriptorSets: 1, GRPCBindingProtect: true})
	if r.Protocols["grpc"] != "unary_g1" {
		t.Fatalf("unary_g1 层级: %+v", r.Protocols)
	}
	if len(r.Detectors) != 1 || r.Detectors[0].Name != "grpc.unary" || r.Detectors[0].Version != "grpc/2" {
		t.Fatalf("PROTECT 绑定应需求 grpc.unary grpc/2: %+v", r.Detectors)
	}
	// 孤立 PROTECT 绑定（无描述符集）→ 同样 grpc/2（意图实断即需求）；protocols 不报 unary_g1
	r = RequiredCapabilities(CapabilityFacts{GRPCBindingProtect: true})
	if _, has := r.Protocols["grpc"]; has {
		t.Fatalf("无描述符集不报 protocols.grpc: %+v", r.Protocols)
	}
	if len(r.Detectors) != 1 || r.Detectors[0].Version != "grpc/2" {
		t.Fatalf("孤立 PROTECT 绑定应需求 grpc/2: %+v", r.Detectors)
	}
	// 全 OBSERVE（无 PROTECT 事实）→ grpc/1 现状（滚动升级零新需求）
	r = RequiredCapabilities(CapabilityFacts{GRPCDescriptorSets: 2})
	if len(r.Detectors) != 1 || r.Detectors[0].Version != "grpc/1" {
		t.Fatalf("全 OBSERVE 应保持 grpc/1: %+v", r.Detectors)
	}
	// 空事实（零值 = 免门禁）
	if r2 := RequiredCapabilities(CapabilityFacts{}); !requiredEmpty(r2) {
		t.Fatalf("空事实应免门禁: %+v", r2)
	}
}

// TestCapabilityFactsFromGuardGRPCBindings NG-GRPC G1 批次 B1 事实聚合：
// guardCfg.APIGRPCBindings 任一 mode=PROTECT → GRPCBindingProtect=true；
// 全 OBSERVE/空绑定 → false（零需求滚动升级）。
func TestCapabilityFactsFromGuardGRPCBindings(t *testing.T) {
	allObserve := &GuardConfig{APIGRPCBindings: []GuardGRPCBinding{
		{ApplicationID: "a1", Service: "pkg.Svc", DescriptorName: "set-a", Mode: "OBSERVE"},
	}}
	if f := capabilityFactsFromGuard(allObserve); f.GRPCBindingProtect {
		t.Fatal("全 OBSERVE 绑定不应构成 PROTECT 事实")
	}
	withProtect := &GuardConfig{APIGRPCBindings: []GuardGRPCBinding{
		{ApplicationID: "a1", Service: "pkg.Svc", DescriptorName: "set-a", Mode: "OBSERVE"},
		{ApplicationID: "a2", Service: "pkg.Other", DescriptorName: "set-a", Mode: "PROTECT"},
	}}
	if f := capabilityFactsFromGuard(withProtect); !f.GRPCBindingProtect {
		t.Fatal("任一 PROTECT 绑定即构成 PROTECT 事实")
	}
	if f := capabilityFactsFromGuard(&GuardConfig{}); f.GRPCBindingProtect {
		t.Fatal("空配置不应有 PROTECT 事实")
	}
}

// TestRequiredCapabilitiesMCPToolCallProtect NG-MCP G1 批次 B1 能力门两态：
// 含任一 PROTECT MCP 绑定 → protocols.mcp=acl_v1 + detectors.mcp.toolcall=mcp/2
// （工具调用 ACL 实断消费语义——不认识 MCP 目录段的旧节点 fail-closed，不得漏放行）；
// 全 OBSERVE/空绑定 → 零需求免门禁（滚动升级可行——grpc/2、flow/1 同纪律）。
func TestRequiredCapabilitiesMCPToolCallProtect(t *testing.T) {
	// 含 PROTECT → 两项需求
	r := RequiredCapabilities(CapabilityFacts{MCPToolCallProtect: true})
	if r.Protocols["mcp"] != "acl_v1" {
		t.Fatalf("PROTECT 绑定应需求 protocols.mcp=acl_v1: %+v", r.Protocols)
	}
	if len(r.Detectors) != 1 || r.Detectors[0].Name != "mcp.toolcall" || r.Detectors[0].Version != "mcp/2" {
		t.Fatalf("PROTECT 绑定应需求 mcp.toolcall mcp/2: %+v", r.Detectors)
	}
	// 空事实 → 免门禁（存量发布零变化）
	if r2 := RequiredCapabilities(CapabilityFacts{}); !requiredEmpty(r2) {
		t.Fatalf("空事实应免门禁: %+v", r2)
	}
	// 全 OBSERVE（无 PROTECT 事实）→ 零需求
	if r3 := RequiredCapabilities(CapabilityFacts{MCPToolCallProtect: false}); !requiredEmpty(r3) {
		t.Fatalf("全 OBSERVE 不应产生 MCP 需求: %+v", r3)
	}
}

// TestCapabilityFactsFromGuardMCPBindings NG-MCP G1 批次 B1 事实聚合：
// guardCfg.APIMCPBindings 任一 mode=PROTECT → MCPToolCallProtect=true；
// 全 OBSERVE/空绑定 → false（零需求滚动升级）。
func TestCapabilityFactsFromGuardMCPBindings(t *testing.T) {
	allObserve := &GuardConfig{APIMCPBindings: []GuardMCPBinding{
		{ApplicationID: "a1", EndpointPath: "/mcp/pay", CatalogName: "pay-mcp", Mode: "OBSERVE"},
	}}
	if f := capabilityFactsFromGuard(allObserve); f.MCPToolCallProtect {
		t.Fatal("全 OBSERVE 绑定不应构成 PROTECT 事实")
	}
	withProtect := &GuardConfig{APIMCPBindings: []GuardMCPBinding{
		{ApplicationID: "a1", EndpointPath: "/mcp/pay", CatalogName: "pay-mcp", Mode: "OBSERVE"},
		{ApplicationID: "a2", EndpointPath: "/mcp/refund", CatalogName: "pay-mcp", Mode: "PROTECT"},
	}}
	if f := capabilityFactsFromGuard(withProtect); !f.MCPToolCallProtect {
		t.Fatal("任一 PROTECT 绑定即构成 PROTECT 事实")
	}
	if f := capabilityFactsFromGuard(&GuardConfig{}); f.MCPToolCallProtect {
		t.Fatal("空配置不应有 PROTECT 事实")
	}
	if f := capabilityFactsFromGuard(nil); f.MCPToolCallProtect {
		t.Fatal("nil 配置不应有 PROTECT 事实")
	}
}

// TestCapabilityGateMCPToolCallProtect NG-MCP G1 批次 B1 门控：mcp/1 旧节点
// （protocols.mcp=observe、无 mcp.toolcall 自报）收含 PROTECT 绑定快照 fail-closed
// （缺口 protocols.mcp + detectors.mcp.toolcall 双列）；mcp/2+acl_v1 节点放行；
// 全 OBSERVE 快照在旧节点照常（滚动升级）。
func TestCapabilityGateMCPToolCallProtect(t *testing.T) {
	protectCfg := &GuardConfig{APIMCPBindings: []GuardMCPBinding{
		{ApplicationID: "a1", EndpointPath: "/mcp/pay", CatalogName: "pay-mcp", Mode: "PROTECT"},
	}}
	// 旧节点（fullManifest：mcp=observe + 无 mcp.toolcall 自报）→ fail-closed
	dir := t.TempDir()
	writeManifest(t, dir, fullManifest("gw-old", time.Now().UTC()))
	p := &Publisher{sidecarDir: dir}
	ok, code, msg := p.evaluateCapabilityGate(context.Background(), protectCfg)
	if ok || code != "CAPABILITY_MISSING" {
		t.Fatalf("mcp/1 旧节点应收含 PROTECT 快照 fail-closed: ok=%t code=%s", ok, code)
	}
	if !strings.Contains(msg, "CAP_MISSING:protocols.mcp(required=acl_v1") {
		t.Fatalf("缺口应含 protocols.mcp acl_v1: %s", msg)
	}
	if !strings.Contains(msg, "CAP_MISSING:detectors.mcp.toolcall(required=mcp/2") {
		t.Fatalf("缺口应含 detectors.mcp.toolcall mcp/2: %s", msg)
	}
	// mcp/2+acl_v1 节点 → 放行
	dir2 := t.TempDir()
	m := fullManifest("gw-new", time.Now().UTC())
	m.Protocols["mcp"] = "acl_v1"
	m.Detectors = append(m.Detectors, capability.DetectorCap{Name: "mcp.toolcall", Version: "mcp/2"})
	writeManifest(t, dir2, m)
	p2 := &Publisher{sidecarDir: dir2}
	if ok, code, msg := p2.evaluateCapabilityGate(context.Background(), protectCfg); !ok || code != "" {
		t.Fatalf("mcp/2 节点应收含 PROTECT 快照: ok=%t code=%s msg=%s", ok, code, msg)
	}
	// 全 OBSERVE 快照 → 旧节点放行（滚动升级）
	observeCfg := &GuardConfig{APIMCPBindings: []GuardMCPBinding{
		{ApplicationID: "a1", EndpointPath: "/mcp/pay", CatalogName: "pay-mcp", Mode: "OBSERVE"},
	}}
	if ok, code, msg := p.evaluateCapabilityGate(context.Background(), observeCfg); !ok || code != "" {
		t.Fatalf("旧节点收全 OBSERVE 快照应放行: ok=%t code=%s msg=%s", ok, code, msg)
	}
	// 空绑定快照 → 旧节点放行（零行为）
	if ok, code, msg := p.evaluateCapabilityGate(context.Background(), &GuardConfig{}); !ok || code != "" {
		t.Fatalf("旧节点收空绑定快照应放行: ok=%t code=%s msg=%s", ok, code, msg)
	}
}

// TestRequiredCapabilitiesMachineIDProtect NG-ID g1 批次 B1 能力门两态（D11）：
// 含任一 PROTECT 机器身份绑定 → detectors.machineid=mid/1（签名验证实断消费语义——
// 不认识机器身份段的旧节点 fail-closed，不得漏验放行）；ProtocolLevels 不动
// （机器身份是检测器能力不是协议层级）；全 OBSERVE/空绑定 → 零需求免门禁（滚动升级可行）。
func TestRequiredCapabilitiesMachineIDProtect(t *testing.T) {
	// 含 PROTECT → 检测器需求（无协议项）
	r := RequiredCapabilities(CapabilityFacts{MachineIDProtect: true})
	if len(r.Detectors) != 1 || r.Detectors[0].Name != "machineid" || r.Detectors[0].Version != "mid/1" {
		t.Fatalf("PROTECT 绑定应需求 machineid mid/1: %+v", r.Detectors)
	}
	if len(r.Protocols) != 0 {
		t.Fatalf("机器身份不应产生协议层级需求（ProtocolLevels 不动）: %+v", r.Protocols)
	}
	// 空事实 → 免门禁（存量发布零变化）
	if r2 := RequiredCapabilities(CapabilityFacts{}); !requiredEmpty(r2) {
		t.Fatalf("空事实应免门禁: %+v", r2)
	}
	// 全 OBSERVE（无 PROTECT 事实）→ 零需求
	if r3 := RequiredCapabilities(CapabilityFacts{MachineIDProtect: false}); !requiredEmpty(r3) {
		t.Fatalf("全 OBSERVE 不应产生 machineid 需求: %+v", r3)
	}
}

// TestCapabilityFactsFromGuardMachineIDBindings NG-ID g1 批次 B1 事实聚合：
// guardCfg.APIMachineIdentityBindings 任一 mode=PROTECT → MachineIDProtect=true；
// 全 OBSERVE/空绑定/nil → false（零需求滚动升级）。
func TestCapabilityFactsFromGuardMachineIDBindings(t *testing.T) {
	allObserve := &GuardConfig{APIMachineIdentityBindings: []GuardMachineIdentityBinding{
		{ApplicationID: "a1", PathPrefix: "/api", Mode: "OBSERVE"},
	}}
	if f := capabilityFactsFromGuard(allObserve); f.MachineIDProtect {
		t.Fatal("全 OBSERVE 绑定不应构成 PROTECT 事实")
	}
	withProtect := &GuardConfig{APIMachineIdentityBindings: []GuardMachineIdentityBinding{
		{ApplicationID: "a1", PathPrefix: "/api", Mode: "OBSERVE"},
		{ApplicationID: "a2", PathExact: "/api/pay", Mode: "PROTECT"},
	}}
	if f := capabilityFactsFromGuard(withProtect); !f.MachineIDProtect {
		t.Fatal("任一 PROTECT 绑定即构成 PROTECT 事实")
	}
	if f := capabilityFactsFromGuard(&GuardConfig{}); f.MachineIDProtect {
		t.Fatal("空配置不应有 PROTECT 事实")
	}
	if f := capabilityFactsFromGuard(nil); f.MachineIDProtect {
		t.Fatal("nil 配置不应有 PROTECT 事实")
	}
}

// TestCapabilityGateMachineIDProtect NG-ID g1 批次 B1 门控：无 machineid 自报的旧节点
// 收含 PROTECT 绑定快照 fail-closed（缺口 detectors.machineid(required=mid/1)）；
// mid/1 新节点放行；全 OBSERVE/空绑定快照在旧节点照常（滚动升级）。
func TestCapabilityGateMachineIDProtect(t *testing.T) {
	protectCfg := &GuardConfig{APIMachineIdentityBindings: []GuardMachineIdentityBinding{
		{ApplicationID: "a1", PathPrefix: "/api", Mode: "PROTECT"},
	}}
	// 旧节点（fullManifest：无 machineid 自报）→ fail-closed
	dir := t.TempDir()
	writeManifest(t, dir, fullManifest("gw-old", time.Now().UTC()))
	p := &Publisher{sidecarDir: dir}
	ok, code, msg := p.evaluateCapabilityGate(context.Background(), protectCfg)
	if ok || code != "CAPABILITY_MISSING" {
		t.Fatalf("旧节点应收含 PROTECT 快照 fail-closed: ok=%t code=%s", ok, code)
	}
	if !strings.Contains(msg, "CAP_MISSING:detectors.machineid(required=mid/1") {
		t.Fatalf("缺口应含 detectors.machineid mid/1: %s", msg)
	}
	// mid/1 新节点 → 放行
	dir2 := t.TempDir()
	m := fullManifest("gw-new", time.Now().UTC())
	m.Detectors = append(m.Detectors, capability.DetectorCap{Name: "machineid", Version: "mid/1"})
	writeManifest(t, dir2, m)
	p2 := &Publisher{sidecarDir: dir2}
	if ok, code, msg := p2.evaluateCapabilityGate(context.Background(), protectCfg); !ok || code != "" {
		t.Fatalf("mid/1 节点应收含 PROTECT 快照: ok=%t code=%s msg=%s", ok, code, msg)
	}
	// 全 OBSERVE 快照 → 旧节点放行（滚动升级）
	observeCfg := &GuardConfig{APIMachineIdentityBindings: []GuardMachineIdentityBinding{
		{ApplicationID: "a1", PathPrefix: "/api", Mode: "OBSERVE"},
	}}
	if ok, code, msg := p.evaluateCapabilityGate(context.Background(), observeCfg); !ok || code != "" {
		t.Fatalf("旧节点收全 OBSERVE 快照应放行: ok=%t code=%s msg=%s", ok, code, msg)
	}
	// 空绑定快照 → 旧节点放行（零行为）
	if ok, code, msg := p.evaluateCapabilityGate(context.Background(), &GuardConfig{}); !ok || code != "" {
		t.Fatalf("旧节点收空绑定快照应放行: ok=%t code=%s msg=%s", ok, code, msg)
	}
}

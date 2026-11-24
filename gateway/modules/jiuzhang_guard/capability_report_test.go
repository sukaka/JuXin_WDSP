// capability_report_test.go 能力清单自报测试：清单契约合法、原子写无残留、
// 刷新轮转、关闭开关零文件、grpc 层级随描述符翻转、默认 limits 兜底链。
package jiuzhang_guard

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/jiuzhang-waf/gateway/dynamic_security/capability"
	dsctx "github.com/jiuzhang-waf/gateway/dynamic_security/context"
)

func readManifest(t *testing.T, dir string) capability.Manifest {
	t.Helper()
	raw, err := os.ReadFile(filepath.Join(dir, capFileName))
	if err != nil {
		t.Fatalf("read capability.json: %v", err)
	}
	var m capability.Manifest
	if err := json.Unmarshal(raw, &m); err != nil {
		t.Fatalf("capability.json not json: %v", err)
	}
	return m
}

// 清单内容合法：契约 Validate 空串 + 关键自报键逐键有据。
func TestCapabilityManifestValid(t *testing.T) {
	m := buildCapabilityManifest(capabilityInputs{NodeID: "gw-t1"}, time.Date(2026, 10, 3, 15, 0, 0, 0, time.UTC))
	if msg := m.Validate(); msg != "" {
		t.Fatalf("清单契约校验失败: %s", msg)
	}
	if m.ContractVersion != capability.ContractVersion || m.NodeID != "gw-t1" {
		t.Fatalf("契约版本/节点不符: %+v", m)
	}
	if m.Protocols["http"] != "1.1" || m.Protocols["graphql"] != "parse" ||
		m.Protocols["grpc"] != "frame" || m.Protocols["mcp"] != "acl_v1" {
		t.Fatalf("协议层级不符: %+v", m.Protocols)
	}
	if m.Limits["max_grpc_frame_bytes"] != dsctx.DefaultGRPCMaxFrameBytes {
		t.Fatalf("limits 兜底不符: %+v（≤0 应按 4MiB 兜底）", m.Limits)
	}
	if m.BuildDigest != "" {
		t.Fatalf("build_digest 不可得必须空串不编造: %q", m.BuildDigest)
	}
	for _, a := range m.Actions {
		if a == "grpc_error" {
			t.Fatal("grpc_error 无协议适配执行层不得报")
		}
	}
	// 生效值覆盖兜底链
	m2 := buildCapabilityManifest(capabilityInputs{NodeID: "gw-t1", MaxGRPCFrameBytes: 8 << 20}, time.Now())
	if m2.Limits["max_grpc_frame_bytes"] != 8<<20 {
		t.Fatalf("limits 生效值不符: %+v", m2.Limits)
	}
}

// GRPCDescriptors 有/无 → grpc 层级 frame↔unary_g1 翻转 + detectors 增减。
func TestCapabilityGRPCLevelFlip(t *testing.T) {
	base := buildCapabilityManifest(capabilityInputs{NodeID: "gw-t1", GRPCUnary: false}, time.Now())
	if base.Protocols["grpc"] != "frame" {
		t.Fatalf("无描述符应报 frame: %s", base.Protocols["grpc"])
	}
	for _, d := range base.Detectors {
		if d.Name == "grpc.unary" {
			t.Fatal("无描述符不得报 grpc.unary 检测器")
		}
	}
	unary := buildCapabilityManifest(capabilityInputs{NodeID: "gw-t1", GRPCUnary: true}, time.Now())
	if unary.Protocols["grpc"] != "unary_g1" {
		t.Fatalf("有描述符应报 unary_g1: %s", unary.Protocols["grpc"])
	}
	found := false
	for _, d := range unary.Detectors {
		if d.Name == "grpc.unary" {
			found = true
		}
	}
	if !found {
		t.Fatal("有描述符应增报 grpc.unary 检测器")
	}
	if msg := unary.Validate(); msg != "" {
		t.Fatalf("unary 清单契约校验失败: %s", msg)
	}
}

// 原子写：写后目录无 .tmp 残留，capability.json 存在且合法，sidecars 目录为 0770（不因 umask 丧失组写位）。
func TestCapabilityAtomicWriteNoTmp(t *testing.T) {
	dir := filepath.Join(t.TempDir(), "sidecars")
	h := &capReportHandle{dir: dir, stopJan: make(chan struct{}), janDone: make(chan struct{})}
	h.update(capabilityInputs{NodeID: "gw-t1"})
	dinfo, err := os.Stat(dir)
	if err != nil {
		t.Fatal(err)
	}
	if dinfo.Mode().Perm() != 0o770 {
		t.Fatalf("sidecars 目录权限应为 0770，实际 %o", dinfo.Mode().Perm())
	}
	m := readManifest(t, dir)
	if msg := m.Validate(); msg != "" {
		t.Fatalf("写盘清单契约校验失败: %s", msg)
	}
	entries, err := os.ReadDir(dir)
	if err != nil {
		t.Fatal(err)
	}
	for _, e := range entries {
		if strings.HasSuffix(e.Name(), ".tmp") {
			t.Fatalf("原子写后不得残留 .tmp: %s", e.Name())
		}
	}
}

// 刷新轮转：generated_at 随 writeOnce 推进（ staleness 判定以 generated_at 为准）。
func TestCapabilityRefreshAdvances(t *testing.T) {
	dir := t.TempDir()
	h := &capReportHandle{dir: dir, stopJan: make(chan struct{}), janDone: make(chan struct{})}
	h.update(capabilityInputs{NodeID: "gw-t1"})
	first := readManifest(t, dir).GeneratedAt
	time.Sleep(1100 * time.Millisecond) // generated_at 为 RFC3339 秒级
	h.writeOnce()
	second := readManifest(t, dir).GeneratedAt
	if second <= first {
		t.Fatalf("刷新后 generated_at 未推进: %s → %s", first, second)
	}
	// 输入刷新即时生效（不等 tick）
	h.update(capabilityInputs{NodeID: "gw-t1", GRPCUnary: true})
	if got := readManifest(t, dir).Protocols["grpc"]; got != "unary_g1" {
		t.Fatalf("输入刷新后 grpc 层级应即时翻转: %s", got)
	}
}

// 关闭开关零文件：CAPABILITY_REPORT_DISABLED=1 时 Provision 装配不产生任何文件。
func TestCapabilityDisabledZeroFile(t *testing.T) {
	resetCapabilityReportForTest()
	defer resetCapabilityReportForTest()
	dir := t.TempDir()
	t.Setenv(capDisabledEnv, "1")
	t.Setenv(capSidecarEnv, dir)
	g := &Guard{GatewayNode: "gw-t1"}
	g.provisionCapabilityReport()
	if _, err := os.Stat(filepath.Join(dir, capFileName)); !os.IsNotExist(err) {
		t.Fatal("关闭开关时不得生成 capability.json")
	}
}

// 默认开启端到端：env 注入 sidecar 目录 → Provision 装配 → 文件存在且 node_id 取 GatewayNode。
func TestCapabilityProvisionEndToEnd(t *testing.T) {
	resetCapabilityReportForTest()
	defer resetCapabilityReportForTest()
	dir := t.TempDir()
	t.Setenv(capSidecarEnv, dir)
	g := &Guard{GatewayNode: "gateway-stage5-01"}
	g.provisionCapabilityReport()
	m := readManifest(t, dir)
	if m.NodeID != "gateway-stage5-01" {
		t.Fatalf("node_id 应取 GatewayNode: %q", m.NodeID)
	}
	if msg := m.Validate(); msg != "" {
		t.Fatalf("端到端清单契约校验失败: %s", msg)
	}
}

func TestCapabilityManifestRiskChallenge(t *testing.T) {
	m := buildCapabilityManifest(capabilityInputs{NodeID: "gw-risk-challenge"}, time.Now())
	required := capability.Manifest{ContractVersion: capability.ContractVersion, Actions: []string{"risk_challenge"}}
	if missing := capability.CheckRequirements(required, m); len(missing) != 0 {
		t.Fatalf("actions.risk_challenge must be self-reported: %+v", missing)
	}
}

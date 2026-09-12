// handler_test.go 处理器辅助逻辑单元测试（WDSP P0-03；HTTP 层由 server/tests 接口测试覆盖）。
package jwttrust

import (
	"context"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/jiuzhang-waf/server/internal/apinodes"
)

// fakeNodeLister 可编程节点查询（NodeLister 接口）。
type fakeNodeLister struct {
	nodes []apinodes.Node
	err   error
}

func (f fakeNodeLister) ListNodes(context.Context) ([]apinodes.Node, error) {
	return f.nodes, f.err
}

func testNodes() []apinodes.Node {
	return []apinodes.Node{
		{ID: uuid.New(), NodeName: "gw-ok", SyncEnabled: true, LastSyncResult: "SUCCESS", Status: apinodes.StatusActive},
		{ID: uuid.New(), NodeName: "gw-bad", SyncEnabled: true, LastSyncResult: "FAILED", LastSyncError: "load rejected", Status: apinodes.StatusActive},
		{ID: uuid.New(), NodeName: "gw-nosync", SyncEnabled: false, LastSyncResult: "FAILED", Status: apinodes.StatusActive},
	}
}

func testNodesHealthy() []apinodes.Node {
	return []apinodes.Node{
		{ID: uuid.New(), NodeName: "gw-ok", SyncEnabled: true, LastSyncResult: "SUCCESS", Status: apinodes.StatusActive},
	}
}

// TestNodeChecks 预检节点检查：PROTECT 遇已知失败节点判 FAIL 且 publishable=false；
// 非 PROTECT 降级 WARN；无扇出节点 SKIP。
func TestNodeChecks(t *testing.T) {
	h := &Handler{nodes: fakeNodeLister{nodes: testNodes()}}
	publishable := true
	checks := h.nodeChecks(true, &publishable)
	if publishable {
		t.Error("PROTECT + 同步失败节点 → publishable 应为 false")
	}
	foundFail := false
	for _, c := range checks {
		if c.Status == CheckFail {
			foundFail = true
		}
	}
	if !foundFail {
		t.Errorf("应有 FAIL 检查项: %+v", checks)
	}

	publishable = true
	checks = h.nodeChecks(false, &publishable)
	if !publishable {
		t.Error("OBSERVE + 同步失败节点 → 仅 WARN，不应阻断")
	}
	for _, c := range checks {
		if c.Status == CheckFail {
			t.Errorf("非 PROTECT 不应 FAIL: %+v", c)
		}
	}

	h2 := &Handler{nodes: fakeNodeLister{nodes: nil}}
	publishable = true
	checks = h2.nodeChecks(true, &publishable)
	if !publishable || len(checks) != 1 || checks[0].Status != CheckSkip {
		t.Errorf("无扇出节点应 SKIP 且可发布: %+v publishable=%v", checks, publishable)
	}
}

// TestSummarizePolicyRedaction 审计摘要不含完整 JWKS 文本（仅 keyset 指纹）。
func TestSummarizePolicyRedaction(t *testing.T) {
	p := basePolicy(t)
	s := summarizePolicy(p, "首次配置")
	if s.Reason != "首次配置" || s.Mode != ModeObserve {
		t.Errorf("summary = %+v", s)
	}
	if len(s.Issuers) != 1 {
		t.Fatalf("summary issuers = %+v", s.Issuers)
	}
	d := s.Issuers[0]
	if d.KeysetVersion == "" || d.KeysetVersion == p.Issuers[0].KeySource.JWKS {
		t.Errorf("keyset 摘要应为指纹而非原文: %+v", d)
	}
	if len(d.KeysetVersion) != 32 {
		t.Errorf("keyset_version = %q, want 32 hex（与网关派生一致的截断指纹）", d.KeysetVersion)
	}
}

// TestPipelineStateFailSafe 管线状态未注入时按未启用处理（PROTECT 预检将拒绝）。
func TestPipelineStateFailSafe(t *testing.T) {
	h := &Handler{}
	enabled, mode, err := h.pipelineState(context.Background())
	if err != nil || enabled || mode != "" {
		t.Errorf("nil pipeline should be disabled, got %v %q %v", enabled, mode, err)
	}
}

// TestDefaultPolicyShape 默认策略形状冻结（GET 对无记录应用返回）。
func TestDefaultPolicyShape(t *testing.T) {
	id := uuid.New()
	p := DefaultPolicy(id)
	if p.Mode != ModeOff || p.Version != 0 || len(p.Selectors) != 0 || len(p.Issuers) != 0 {
		t.Errorf("default policy = %+v", p)
	}
	if p.ApplicationID != id {
		t.Errorf("application id mismatch")
	}
}

var _ = time.Now // 保留 time 供后续时间相关用例

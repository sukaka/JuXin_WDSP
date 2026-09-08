// file_compliance_test.go 文件合规规则下发（W13-GW / P2-03）单测：
// 发布侧容错（未注入/查询失败 Warn 跳过/空规则不下发/正常读取透传，
// 与 loadAPIMaskRules 同一纪律）；fakeSettingsGet/fakeDecrypt 复用 scan_verify_test.go。
package guardconfig

import (
	"context"
	"errors"
	"testing"

	"github.com/jiuzhang-waf/server/internal/gatewayconfig"
)

// fakeFileComplianceLister 内存版文件合规规则读取（可注入错误路径）。
type fakeFileComplianceLister struct {
	rules []gatewayconfig.GuardFileComplianceRule
	err   error
}

func (f *fakeFileComplianceLister) ListEnabledFileComplianceRules(ctx context.Context) ([]gatewayconfig.GuardFileComplianceRule, error) {
	_ = ctx
	return f.rules, f.err
}

// TestLoadAPIFileComplianceRulesTolerance 文件合规规则：未注入 nil；查询失败（如表尚未建立）
// Warn 跳过返回 nil；空规则不下发；正常读取透传。
func TestLoadAPIFileComplianceRulesTolerance(t *testing.T) {
	// 未注入
	p := &Provider{}
	if got := p.loadAPIFileComplianceRules(context.Background()); got != nil {
		t.Fatalf("nil lister must yield nil: %v", got)
	}
	// 查询失败 → 容忍跳过（不阻断发布主流程）
	p = &Provider{fileComplianceRules: &fakeFileComplianceLister{err: errors.New("relation does not exist")}}
	if got := p.loadAPIFileComplianceRules(context.Background()); got != nil {
		t.Fatalf("list failure must be tolerated: %v", got)
	}
	// 空规则 → 不下发
	p = &Provider{fileComplianceRules: &fakeFileComplianceLister{}}
	if got := p.loadAPIFileComplianceRules(context.Background()); got != nil {
		t.Fatalf("empty rules must yield nil: %v", got)
	}
	// 正常读取透传
	want := []gatewayconfig.GuardFileComplianceRule{
		{Direction: "UPLOAD", Match: "EXT", Value: "exe", Action: "BLOCK", Reason: "可执行文件"},
		{Direction: "DOWNLOAD", Match: "MIME", Value: "image/", Action: "OBSERVE"},
	}
	p = &Provider{fileComplianceRules: &fakeFileComplianceLister{rules: want}}
	got := p.loadAPIFileComplianceRules(context.Background())
	if len(got) != 2 || got[0] != want[0] || got[1] != want[1] {
		t.Fatalf("rules = %+v", got)
	}
}

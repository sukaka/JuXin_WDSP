// response_baselines_test.go 响应结构基线下发（W9-GW）单测：
// 发布侧容错（未注入/表缺失查询失败 Warn 跳过/空集不下发）与阈值常量约定。
package guardconfig

import (
	"context"
	"errors"
	"testing"

	"github.com/jiuzhang-waf/server/internal/gatewayconfig"
)

// fakeResponseBaselineLister 内存版响应基线读取（可注入错误路径）。
type fakeResponseBaselineLister struct {
	baselines []gatewayconfig.GuardResponseBaseline
	err       error
}

func (f *fakeResponseBaselineLister) ListResponseBaselines(ctx context.Context) ([]gatewayconfig.GuardResponseBaseline, error) {
	_ = ctx
	return f.baselines, f.err
}

// TestLoadAPIResponseBaselinesTolerance 响应基线：未注入 nil；查询失败（如 000051 学习列未建立）
// Warn 跳过返回 nil；空集不下发；正常读取透传。
func TestLoadAPIResponseBaselinesTolerance(t *testing.T) {
	// 未注入
	p := &Provider{}
	if got := p.loadAPIResponseBaselines(context.Background()); got != nil {
		t.Fatalf("nil lister must yield nil: %v", got)
	}
	// 查询失败（表/列不存在）→ 容忍跳过
	p = &Provider{responseBaselines: &fakeResponseBaselineLister{err: errors.New(`relation "api_response_schemas" does not exist`)}}
	if got := p.loadAPIResponseBaselines(context.Background()); got != nil {
		t.Fatalf("missing table must be tolerated: %v", got)
	}
	// 空集 → 不下发
	p = &Provider{responseBaselines: &fakeResponseBaselineLister{baselines: []gatewayconfig.GuardResponseBaseline{}}}
	if got := p.loadAPIResponseBaselines(context.Background()); got != nil {
		t.Fatalf("empty baselines must yield nil: %v", got)
	}
	// 正常读取
	want := []gatewayconfig.GuardResponseBaseline{{
		EndpointKey: "GET /v1/users/{id}", StatusCode: 200,
		Fields: map[string]string{"id": "number", "name": "string"},
	}}
	p = &Provider{responseBaselines: &fakeResponseBaselineLister{baselines: want}}
	got := p.loadAPIResponseBaselines(context.Background())
	if len(got) != 1 || got[0].EndpointKey != want[0].EndpointKey || got[0].StatusCode != 200 || got[0].Fields["name"] != "string" {
		t.Fatalf("baselines = %+v", got)
	}
}

// TestResponseBaselineMinSamples 阈值约定（任务书：仅取 sample_count≥20 的学习行）。
func TestResponseBaselineMinSamples(t *testing.T) {
	if ResponseBaselineMinSamples != 20 {
		t.Fatalf("ResponseBaselineMinSamples = %d, want 20", ResponseBaselineMinSamples)
	}
}

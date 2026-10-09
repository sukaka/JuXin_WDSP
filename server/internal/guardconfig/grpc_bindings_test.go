// grpc_bindings_test.go gRPC 描述符 per-app 绑定下发单测（NG-GRPC G1 批次 B1，
// 纯函数不依赖数据库）：未注入/查询失败（迁移 000179 表未建立）Warn 跳过返回 nil
// （空绑定=全局可见现状语义）、全行读取透传（GuardGRPCBinding 形状+稳定排序）、
// 空绑定不下发段（omitempty 零变化 NG-T-C01）。
package guardconfig

import (
	"context"
	"errors"
	"testing"

	"github.com/jiuzhang-waf/server/internal/gatewayconfig"
)

// fakeGRPCBindingLister 内存版 gRPC 绑定读取（可注入错误路径）。
type fakeGRPCBindingLister struct {
	bindings []gatewayconfig.GuardGRPCBinding
	err      error
}

func (f *fakeGRPCBindingLister) ListAllGRPCBindings(ctx context.Context) ([]gatewayconfig.GuardGRPCBinding, error) {
	_ = ctx
	return f.bindings, f.err
}

// TestLoadAPIGRPCBindingsTolerance 绑定段：未注入 nil；查询失败（如 000179 表未建立）
// Warn 跳过返回 nil（空绑定=全局可见现状语义，不 fail-hard 拖垮发布）；空集不下发；
// 正常读取透传（application_id/service/descriptor_name/mode 全字段）。
func TestLoadAPIGRPCBindingsTolerance(t *testing.T) {
	// 未注入
	p := &Provider{}
	if got := p.loadAPIGRPCBindings(context.Background()); got != nil {
		t.Fatalf("nil lister must yield nil: %v", got)
	}
	// 查询失败（表不存在）→ 容忍跳过（空绑定现状语义）
	p = &Provider{grpcBindings: &fakeGRPCBindingLister{err: errors.New(`relation "api_grpc_bindings" does not exist`)}}
	if got := p.loadAPIGRPCBindings(context.Background()); got != nil {
		t.Fatalf("missing table must be tolerated: %v", got)
	}
	// 正常读取透传（全字段+顺序原样）
	rows := []gatewayconfig.GuardGRPCBinding{
		{ApplicationID: "a1", Service: "pkg.svc", DescriptorName: "set-a", Mode: "OBSERVE"},
		{ApplicationID: "a2", Service: "pkg.other", DescriptorName: "set-b", Mode: "PROTECT"},
	}
	p = &Provider{grpcBindings: &fakeGRPCBindingLister{bindings: rows}}
	got := p.loadAPIGRPCBindings(context.Background())
	if len(got) != 2 || got[0].Mode != "OBSERVE" || got[1].DescriptorName != "set-b" || got[1].Mode != "PROTECT" {
		t.Fatalf("绑定段透传: %+v", got)
	}
}

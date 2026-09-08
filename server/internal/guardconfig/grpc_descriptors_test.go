// grpc_descriptors_test.go gRPC 描述符集下发单测（W14-DESC / P2-05 深化，纯函数不依赖数据库）：
// 未注入/查询失败（表未建立）Warn 跳过返回 nil、空集不下发、正常读取透传、
// 描述符集内容纳入 api_policy_version 版本戳且空集时版本戳与既有版本逐字节一致。
package guardconfig

import (
	"context"
	"errors"
	"testing"

	"github.com/jiuzhang-waf/server/internal/gatewayconfig"
)

// fakeGRPCDescriptorLister 内存版 gRPC 描述符集读取（可注入错误路径）。
type fakeGRPCDescriptorLister struct {
	sets []gatewayconfig.GuardGRPCDescriptor
	err  error
}

func (f *fakeGRPCDescriptorLister) ListEnabledGRPCDescriptors(ctx context.Context) ([]gatewayconfig.GuardGRPCDescriptor, error) {
	_ = ctx
	return f.sets, f.err
}

// TestLoadAPIGRPCDescriptorsTolerance 描述符集：未注入 nil；查询失败（如 000076 表未建立）
// Warn 跳过返回 nil；空集不下发；正常读取透传。
func TestLoadAPIGRPCDescriptorsTolerance(t *testing.T) {
	// 未注入
	p := &Provider{}
	if got := p.loadAPIGRPCDescriptors(context.Background()); got != nil {
		t.Fatalf("nil lister must yield nil: %v", got)
	}
	// 查询失败（表不存在）→ 容忍跳过
	p = &Provider{grpcDescriptors: &fakeGRPCDescriptorLister{err: errors.New(`relation "api_grpc_descriptors" does not exist`)}}
	if got := p.loadAPIGRPCDescriptors(context.Background()); got != nil {
		t.Fatalf("missing table must be tolerated: %v", got)
	}
	// 空集 → 不下发
	p = &Provider{grpcDescriptors: &fakeGRPCDescriptorLister{sets: []gatewayconfig.GuardGRPCDescriptor{}}}
	if got := p.loadAPIGRPCDescriptors(context.Background()); got != nil {
		t.Fatalf("empty sets must yield nil: %v", got)
	}
	// 正常读取
	want := []gatewayconfig.GuardGRPCDescriptor{
		{Name: "orders", ContentBase64: "CgsKCg"},
	}
	p = &Provider{grpcDescriptors: &fakeGRPCDescriptorLister{sets: want}}
	got := p.loadAPIGRPCDescriptors(context.Background())
	if len(got) != 1 || got[0].Name != "orders" || got[0].ContentBase64 != "CgsKCg" {
		t.Fatalf("sets = %+v", got)
	}
}

// TestComputeAPIPolicyVersionGRPCDescriptors 描述符集纳入版本戳（启停/变更即变）；
// 空集（nil/空切片）时序列化与既有版本逐字节一致（版本戳零变化纪律）。
func TestComputeAPIPolicyVersionGRPCDescriptors(t *testing.T) {
	schemas := map[string]map[string]string{"POST /v1/orders": {"amount": "number"}}
	base := computeAPIPolicyVersion(&gatewayconfig.GuardConfig{APIFormalSchemas: schemas})
	// 空切片与 nil 同为空集语义：版本戳不变
	if v := computeAPIPolicyVersion(&gatewayconfig.GuardConfig{APIFormalSchemas: schemas,
		APIGRPCDescriptors: []gatewayconfig.GuardGRPCDescriptor{}}); v != base {
		t.Fatal("empty descriptor slice must not change version")
	}
	// 内容变更即变
	sets := []gatewayconfig.GuardGRPCDescriptor{{Name: "orders", ContentBase64: "CgsKCg"}}
	v := computeAPIPolicyVersion(&gatewayconfig.GuardConfig{APIFormalSchemas: schemas, APIGRPCDescriptors: sets})
	if v == base {
		t.Fatal("grpc descriptors must be part of policy version")
	}
	// 同内容恒同（确定性）
	if v2 := computeAPIPolicyVersion(&gatewayconfig.GuardConfig{APIFormalSchemas: schemas, APIGRPCDescriptors: sets}); v2 != v {
		t.Fatal("same descriptors must yield same version")
	}
	// 名称/内容任一变化即变
	if v3 := computeAPIPolicyVersion(&gatewayconfig.GuardConfig{APIFormalSchemas: schemas,
		APIGRPCDescriptors: []gatewayconfig.GuardGRPCDescriptor{{Name: "orders", ContentBase64: "AAAA"}}}); v3 == v {
		t.Fatal("descriptor content change must change version")
	}
}

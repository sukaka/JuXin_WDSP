// grpc_bindings.go gRPC 描述符 per-app 绑定下发（NG-GRPC G1 批次 B1，设计
// docs/nextgen/NG-GRPC-g1-unary.md §1.3/§1.9）：
// api_grpc_bindings 表全行（迁移 000179）→ api_grpc_bindings
// [{application_id, service, descriptor_name, mode}] 随发布通道下发网关
// （表缺失/查询失败 Warn 跳过，与 GRPCDescriptorStore 同一模式；空绑定=不下发段
// （omitempty），网关按全局注册表语义（现状）零变化；含任一 PROTECT 绑定的快照
// 能力门 required detectors.grpc.unary=grpc/2——capability_gate 从本段聚合）。
package guardconfig

import (
	"context"
	"log/slog"

	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/jiuzhang-waf/server/internal/gatewayconfig"
)

// GRPCBindingLister gRPC 绑定读取接口（api_grpc_bindings 表；包内单测可 fake 错误路径）。
type GRPCBindingLister interface {
	ListAllGRPCBindings(ctx context.Context) ([]gatewayconfig.GuardGRPCBinding, error)
}

// GRPCBindingStore api_grpc_bindings 读取（表由迁移 000179 建立；按冻结列名读取）。
type GRPCBindingStore struct {
	db *pgxpool.Pool
}

// NewGRPCBindingStore 创建绑定读取仓储。
func NewGRPCBindingStore(db *pgxpool.Pool) *GRPCBindingStore { return &GRPCBindingStore{db: db} }

var _ GRPCBindingLister = (*GRPCBindingStore)(nil)

// ListAllGRPCBindings 读取全部绑定（应用+服务稳定排序——同内容恒得同序列化，版本戳确定）。
func (s *GRPCBindingStore) ListAllGRPCBindings(ctx context.Context) ([]gatewayconfig.GuardGRPCBinding, error) {
	rows, err := s.db.Query(ctx, `SELECT application_id, service, descriptor_name, mode
		FROM api_grpc_bindings ORDER BY application_id, service`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := []gatewayconfig.GuardGRPCBinding{}
	for rows.Next() {
		var b gatewayconfig.GuardGRPCBinding
		if err := rows.Scan(&b.ApplicationID, &b.Service, &b.DescriptorName, &b.Mode); err != nil {
			return nil, err
		}
		out = append(out, b)
	}
	return out, rows.Err()
}

// SetGRPCBindingLister 注入 gRPC 绑定读取（nil 时不下发 api_grpc_bindings 段）。
func (p *Provider) SetGRPCBindingLister(l GRPCBindingLister) { p.grpcBindings = l }

// loadAPIGRPCBindings 读取全部 gRPC 绑定；未注入或查询失败（如迁移 000179 表尚未建立）
// Warn 跳过不下发（空绑定=全局可见的现状语义，与历史版本一致）。
func (p *Provider) loadAPIGRPCBindings(ctx context.Context) []gatewayconfig.GuardGRPCBinding {
	if p.grpcBindings == nil {
		return nil
	}
	bindings, err := p.grpcBindings.ListAllGRPCBindings(ctx)
	if err != nil {
		slog.Warn("api_grpc_bindings load failed, skipping section", "error", err)
		return nil
	}
	return bindings
}

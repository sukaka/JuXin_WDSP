// grpc_descriptors.go gRPC 描述符集下发（W14-DESC / P2-05 深化）：
// api_grpc_descriptors 表 ENABLED 行 → api_grpc_descriptors [{name, content_base64}]
// 随发布通道下发网关（表由迁移 000076 建立；缺失/失败 Warn 跳过，与 MaskRuleStore 同一模式）。
package guardconfig

import (
	"context"
	"encoding/base64"
	"log/slog"

	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/jiuzhang-waf/server/internal/gatewayconfig"
)

// GRPCDescriptorLister gRPC 描述符集读取接口（api_grpc_descriptors 表；包内单测可 fake 错误路径）。
type GRPCDescriptorLister interface {
	ListEnabledGRPCDescriptors(ctx context.Context) ([]gatewayconfig.GuardGRPCDescriptor, error)
}

// GRPCDescriptorStore api_grpc_descriptors 读取（表由迁移 000076 建立；按冻结列名读取，
// 列：name/content；仅取 status='ENABLED' 行）。
type GRPCDescriptorStore struct {
	db *pgxpool.Pool
}

// NewGRPCDescriptorStore 创建 gRPC 描述符集读取仓储。
func NewGRPCDescriptorStore(db *pgxpool.Pool) *GRPCDescriptorStore {
	return &GRPCDescriptorStore{db: db}
}

var _ GRPCDescriptorLister = (*GRPCDescriptorStore)(nil)

// ListEnabledGRPCDescriptors 读取 ENABLED 描述符集（按 name 稳定排序；content 转 base64 下发）。
func (s *GRPCDescriptorStore) ListEnabledGRPCDescriptors(ctx context.Context) ([]gatewayconfig.GuardGRPCDescriptor, error) {
	rows, err := s.db.Query(ctx, `
SELECT name, content
FROM api_grpc_descriptors
WHERE status = 'ENABLED'
ORDER BY name`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := []gatewayconfig.GuardGRPCDescriptor{}
	for rows.Next() {
		var d gatewayconfig.GuardGRPCDescriptor
		var content []byte
		if err := rows.Scan(&d.Name, &content); err != nil {
			return nil, err
		}
		d.ContentBase64 = base64.StdEncoding.EncodeToString(content)
		out = append(out, d)
	}
	return out, rows.Err()
}

// SetGRPCDescriptorLister 注入 gRPC 描述符集读取（nil 时不下发 api_grpc_descriptors 段）。
func (p *Provider) SetGRPCDescriptorLister(l GRPCDescriptorLister) { p.grpcDescriptors = l }

// loadAPIGRPCDescriptors 读取 ENABLED gRPC 描述符集；未注入或查询失败（如迁移 000076 表尚未建立）
// Warn 并跳过，不阻断发布主流程（与脱敏/值级敏感规则同一纪律：描述符解析为增量观测能力，
// 缺失时网关退化为 v1 帧结构校验，行为与历史版本一致）。
func (p *Provider) loadAPIGRPCDescriptors(ctx context.Context) []gatewayconfig.GuardGRPCDescriptor {
	if p.grpcDescriptors == nil {
		return nil
	}
	sets, err := p.grpcDescriptors.ListEnabledGRPCDescriptors(ctx)
	if err != nil {
		slog.Warn("list api grpc descriptors failed, skip api_grpc_descriptors", "error", err)
		return nil
	}
	if len(sets) == 0 {
		return nil
	}
	return sets
}

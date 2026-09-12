// response_baselines.go 响应结构基线下发（W9-GW，背景B 响应偏离检测运行时消费前置）：
// api_response_schemas 表 sample_count 达阈值的学习行 → api_response_baselines 下发网关
// （端点×状态码 → 一级字段路径/类型基线，网关响应相位比对产出偏离明细）。
// 表由迁移 000018 建立、000051 补齐运行时学习列；表缺失/查询失败 Warn 跳过，与 MaskRuleStore 同一模式。
package guardconfig

import (
	"context"
	"encoding/json"
	"log/slog"

	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/jiuzhang-waf/server/internal/gatewayconfig"
)

// ResponseBaselineMinSamples 响应基线下发的最小学习样本数（样本不足的学习行结构不稳定，
// 不下发避免网关偏离检测误报；与任务书「sample_count≥20」约定一致）。
const ResponseBaselineMinSamples = 20

// ResponseBaselineLister 响应结构基线读取接口（api_response_schemas 表；包内单测可 fake 错误路径）。
type ResponseBaselineLister interface {
	ListResponseBaselines(ctx context.Context) ([]gatewayconfig.GuardResponseBaseline, error)
}

// ResponseBaselineStore api_response_schemas 读取（表由迁移 000018/000051 建立；按冻结列名读取，
// 仅取运行时学习行（model_version_id 为空）且 sample_count 达阈值；版本快照行不下发）。
type ResponseBaselineStore struct {
	db *pgxpool.Pool
}

// NewResponseBaselineStore 创建响应结构基线读取仓储。
func NewResponseBaselineStore(db *pgxpool.Pool) *ResponseBaselineStore {
	return &ResponseBaselineStore{db: db}
}

var _ ResponseBaselineLister = (*ResponseBaselineStore)(nil)

// responseBaselineDoc schema_json 文档形态（与 apiruntime 写入方同一约定，只读解析；
// 只含一级字段路径与类型标签，不落值）。
type responseBaselineDoc struct {
	Fields map[string]string `json:"fields"`
}

// ListResponseBaselines 读取达阈值的响应结构基线（按端点与状态码稳定排序）。
func (s *ResponseBaselineStore) ListResponseBaselines(ctx context.Context) ([]gatewayconfig.GuardResponseBaseline, error) {
	rows, err := s.db.Query(ctx, `
SELECT endpoint_key, status_code, schema_json
FROM api_response_schemas
WHERE model_version_id IS NULL AND endpoint_key IS NOT NULL AND sample_count >= $1
ORDER BY endpoint_key, status_code`, ResponseBaselineMinSamples)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := []gatewayconfig.GuardResponseBaseline{}
	for rows.Next() {
		var b gatewayconfig.GuardResponseBaseline
		var raw []byte
		if err := rows.Scan(&b.EndpointKey, &b.StatusCode, &raw); err != nil {
			return nil, err
		}
		doc := responseBaselineDoc{Fields: map[string]string{}}
		if len(raw) > 0 {
			_ = json.Unmarshal(raw, &doc)
		}
		if len(doc.Fields) == 0 {
			continue // 无字段基线的行不下发（学习写入方本不产空字段行，防御性跳过）
		}
		b.Fields = doc.Fields
		out = append(out, b)
	}
	return out, rows.Err()
}

// SetResponseBaselineLister 注入响应结构基线读取（nil 时不下发 api_response_baselines 段）。
func (p *Provider) SetResponseBaselineLister(l ResponseBaselineLister) { p.responseBaselines = l }

// loadAPIResponseBaselines 读取达阈值响应结构基线；未注入或查询失败（如迁移 000051 列尚未建立）
// Warn 并跳过，不阻断发布主流程（与 MaskRuleStore 同一纪律：增量能力，缺失时保持发布通道
// 既有行为，网关无基线下发时响应偏离检测零行为）。
func (p *Provider) loadAPIResponseBaselines(ctx context.Context) []gatewayconfig.GuardResponseBaseline {
	if p.responseBaselines == nil {
		return nil
	}
	baselines, err := p.responseBaselines.ListResponseBaselines(ctx)
	if err != nil {
		slog.Warn("list api response baselines failed, skip api_response_baselines", "error", err)
		return nil
	}
	if len(baselines) == 0 {
		return nil
	}
	return baselines
}

// sensitive_rules.go 值级敏感检测规则下发（W3-E）：
// api_sensitive_data_types 表 status=ENABLED 且 regex 非空的类型 → api_sensitive_value_rules
// 随发布通道下发网关（表由迁移 000040 建立；缺失/失败 Warn 跳过，与 MaskRuleStore 同一模式）。
package guardconfig

import (
	"context"
	"encoding/json"
	"log/slog"

	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/jiuzhang-waf/server/internal/gatewayconfig"
)

// SensitiveValueRuleLister 值级敏感检测规则读取接口（api_sensitive_data_types 表；包内单测可 fake 错误路径）。
type SensitiveValueRuleLister interface {
	ListEnabledSensitiveValueRules(ctx context.Context) ([]gatewayconfig.GuardSensitiveValueRule, error)
}

// SensitiveValueRuleStore api_sensitive_data_types 读取（表由迁移 000040 建立；按冻结列名读取，
// 列：data_type/regex/locations/level；仅取 status=ENABLED 且 regex 非空的类型）。
type SensitiveValueRuleStore struct {
	db *pgxpool.Pool
}

// NewSensitiveValueRuleStore 创建值级敏感检测规则读取仓储。
func NewSensitiveValueRuleStore(db *pgxpool.Pool) *SensitiveValueRuleStore {
	return &SensitiveValueRuleStore{db: db}
}

var _ SensitiveValueRuleLister = (*SensitiveValueRuleStore)(nil)

// ListEnabledSensitiveValueRules 读取启用且配置值级 regex 的敏感数据类型（按 data_type 稳定排序）。
func (s *SensitiveValueRuleStore) ListEnabledSensitiveValueRules(ctx context.Context) ([]gatewayconfig.GuardSensitiveValueRule, error) {
	rows, err := s.db.Query(ctx, `
SELECT data_type, regex, locations, level, exclude_fields
FROM api_sensitive_data_types
WHERE status = 'ENABLED' AND regex <> ''
ORDER BY data_type`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := []gatewayconfig.GuardSensitiveValueRule{}
	for rows.Next() {
		var r gatewayconfig.GuardSensitiveValueRule
		var rawLocs, rawExcludes []byte
		if err := rows.Scan(&r.DataType, &r.Regex, &rawLocs, &r.Level, &rawExcludes); err != nil {
			return nil, err
		}
		if len(rawLocs) > 0 {
			if err := json.Unmarshal(rawLocs, &r.Locations); err != nil {
				return nil, err
			}
		}
		if len(rawExcludes) > 0 {
			if err := json.Unmarshal(rawExcludes, &r.ExcludeFields); err != nil {
				return nil, err
			}
		}
		out = append(out, r)
	}
	return out, rows.Err()
}

// SetSensitiveValueRuleLister 注入值级敏感检测规则读取（nil 时不下发 api_sensitive_value_rules 段）。
func (p *Provider) SetSensitiveValueRuleLister(l SensitiveValueRuleLister) { p.sensitiveValueRules = l }

// loadAPISensitiveValueRules 读取启用值级敏感检测规则；未注入或查询失败（如迁移 000040 表尚未建立）
// Warn 并跳过，不阻断发布主流程（与脱敏规则同一纪律：增量能力，缺失时保持发布通道既有行为，
// 网关无规则下发时关闭值级检测，行为与历史版本一致）。
func (p *Provider) loadAPISensitiveValueRules(ctx context.Context) []gatewayconfig.GuardSensitiveValueRule {
	rules, err := p.loadAPISensitiveValueRulesStrict(ctx)
	if err != nil {
		slog.Warn("list api sensitive value rules failed, skip api_sensitive_value_rules", "error", err)
	}
	return rules
}

func (p *Provider) loadAPISensitiveValueRulesStrict(ctx context.Context) ([]gatewayconfig.GuardSensitiveValueRule, error) {
	if p.sensitiveValueRules == nil {
		return nil, nil
	}
	rules, err := p.sensitiveValueRules.ListEnabledSensitiveValueRules(ctx)
	if err != nil {
		if isMissingLegacyTableError(err, "api_sensitive_data_types") {
			slog.Warn("optional legacy table api_sensitive_data_types is unavailable", "error", err)
			return nil, nil
		}
		return nil, wrapLegacyLoaderError("api_sensitive_data_types", err)
	}
	if len(rules) == 0 {
		return nil, nil
	}
	return rules, nil
}

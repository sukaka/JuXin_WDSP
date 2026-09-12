// file_compliance.go 文件合规规则下发（W13-GW / P2-03，任务书 §44 文件异常检测子集）：
// api_file_compliance_rules 表 enabled 行 → api_file_compliance_rules 随发布通道下发网关
// （表由迁移 000071 另一分片建立；缺失/失败 Warn 跳过，与 MaskRuleStore 同一模式）。
// 规则内容纳入 api_policy_version 版本戳（见 apiruntime.go computeAPIPolicyVersion）。
package guardconfig

import (
	"context"
	"log/slog"

	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/jiuzhang-waf/server/internal/gatewayconfig"
)

// FileComplianceRuleLister 文件合规规则读取接口（api_file_compliance_rules 表；包内单测可 fake 错误路径）。
type FileComplianceRuleLister interface {
	ListEnabledFileComplianceRules(ctx context.Context) ([]gatewayconfig.GuardFileComplianceRule, error)
}

// FileComplianceRuleStore api_file_compliance_rules 读取（表由迁移 000071 另一分片建立；
// 按冻结列名读取：direction/match_type/match_value/action/reason/enabled；
// 下发 JSON 键为 direction/match/value/action/reason——跨分片契约见 GuardFileComplianceRule）。
type FileComplianceRuleStore struct {
	db *pgxpool.Pool
}

// NewFileComplianceRuleStore 创建文件合规规则读取仓储。
func NewFileComplianceRuleStore(db *pgxpool.Pool) *FileComplianceRuleStore {
	return &FileComplianceRuleStore{db: db}
}

var _ FileComplianceRuleLister = (*FileComplianceRuleStore)(nil)

// ListEnabledFileComplianceRules 读取 enabled 文件合规规则（按方向/匹配类型/取值稳定排序，
// 版本戳与下发内容确定性一致）。
func (s *FileComplianceRuleStore) ListEnabledFileComplianceRules(ctx context.Context) ([]gatewayconfig.GuardFileComplianceRule, error) {
	rows, err := s.db.Query(ctx, `
SELECT direction, match_type, match_value, action, COALESCE(reason,'')
FROM api_file_compliance_rules
WHERE enabled
ORDER BY direction, match_type, match_value`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := []gatewayconfig.GuardFileComplianceRule{}
	for rows.Next() {
		var r gatewayconfig.GuardFileComplianceRule
		if err := rows.Scan(&r.Direction, &r.Match, &r.Value, &r.Action, &r.Reason); err != nil {
			return nil, err
		}
		out = append(out, r)
	}
	return out, rows.Err()
}

// SetFileComplianceRuleLister 注入文件合规规则读取（nil 时不下发 api_file_compliance_rules 段）。
func (p *Provider) SetFileComplianceRuleLister(l FileComplianceRuleLister) { p.fileComplianceRules = l }

// loadAPIFileComplianceRules 读取 enabled 文件合规规则；未注入或查询失败（如表尚未建立）
// Warn 并跳过，不阻断发布主流程（与脱敏规则同一纪律：增量能力，缺失时保持发布通道既有行为，
// 网关无规则下发时合规检测零行为，与历史版本一致）。
func (p *Provider) loadAPIFileComplianceRules(ctx context.Context) []gatewayconfig.GuardFileComplianceRule {
	rules, err := p.loadAPIFileComplianceRulesStrict(ctx)
	if err != nil {
		slog.Warn("list api file compliance rules failed, skip api_file_compliance_rules", "error", err)
	}
	return rules
}

func (p *Provider) loadAPIFileComplianceRulesStrict(ctx context.Context) ([]gatewayconfig.GuardFileComplianceRule, error) {
	if p.fileComplianceRules == nil {
		return nil, nil
	}
	rules, err := p.fileComplianceRules.ListEnabledFileComplianceRules(ctx)
	if err != nil {
		if isMissingLegacyTableError(err, "api_file_compliance_rules") {
			slog.Warn("optional legacy table api_file_compliance_rules is unavailable", "error", err)
			return nil, nil
		}
		return nil, wrapLegacyLoaderError("api_file_compliance_rules", err)
	}
	if len(rules) == 0 {
		return nil, nil
	}
	return rules, nil
}

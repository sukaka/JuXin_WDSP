package securityevents

import (
	"context"
	"fmt"
	"strconv"
	"strings"
	"time"
)

// RuleEffectStat 是规则版本按日聚合的效果统计。
type RuleEffectStat struct {
	Date                        time.Time `json:"date"`
	RuleID                      int       `json:"rule_id"`
	RuleKey                     string    `json:"rule_key"`
	RuleName                    string    `json:"rule_name"`
	RuleSource                  string    `json:"rule_source"`
	RuleVersion                 string    `json:"rule_version"`
	Hits                        int64     `json:"hits"`
	Blocks                      int64     `json:"blocks"`
	Unresolved                  int64     `json:"unresolved"`
	ConfirmedAttacks            int64     `json:"confirmed_attacks"`
	FalsePositives              int64     `json:"false_positives"`
	Reviewed                    int64     `json:"reviewed"`
	ConfirmationRate            *float64  `json:"confirmation_rate"`
	FPRate                      *float64  `json:"fp_rate"`
	ProtectRecommendation       bool      `json:"protect_recommendation"`
	ProtectRecommendationReason string    `json:"protect_recommendation_reason,omitempty"`
}

const (
	protectRecommendationMinReviewed    int64   = 20
	protectRecommendationMinConfirmRate float64 = 0.80
	protectRecommendationMaxFPRate      float64 = 0.05
)

// applyProtectRecommendation 只生成运营建议，不改变任何运行时策略。
// 门槛保持保守：至少 20 条已研判事件、确认率不低于 80%、误报率不高于 5%。
func applyProtectRecommendation(stat *RuleEffectStat) {
	if stat == nil || stat.Reviewed < protectRecommendationMinReviewed ||
		stat.ConfirmationRate == nil || stat.FPRate == nil ||
		*stat.ConfirmationRate < protectRecommendationMinConfirmRate ||
		*stat.FPRate > protectRecommendationMaxFPRate {
		return
	}
	stat.ProtectRecommendation = true
	stat.ProtectRecommendationReason = fmt.Sprintf("已研判 %d 条，确认率 %.1f%%、误报率 %.1f%%，可人工评估切换 PROTECT", stat.Reviewed, *stat.ConfirmationRate*100, *stat.FPRate*100)
}

type RuleEffectStatsFilter struct {
	From        *time.Time
	To          *time.Time
	RuleID      *int
	RuleVersion string
	Page        int
	PageSize    int
}

func (s *Store) RuleEffectStats(ctx context.Context, f RuleEffectStatsFilter) ([]RuleEffectStat, int64, error) {
	if f.Page <= 0 {
		f.Page = 1
	}
	if f.PageSize <= 0 || f.PageSize > 200 {
		f.PageSize = 50
	}
	where := []string{"1=1"}
	args := make([]interface{}, 0, 4)
	add := func(clause string, value interface{}) {
		args = append(args, value)
		where = append(where, fmt.Sprintf(clause, len(args)))
	}
	if f.From != nil {
		add("s.stat_date >= ($%d AT TIME ZONE 'UTC')::date", *f.From)
	}
	if f.To != nil {
		add("s.stat_date < ($%d AT TIME ZONE 'UTC')::date", *f.To)
	}
	if f.RuleID != nil {
		add("s.rule_id = $%d", *f.RuleID)
	}
	if strings.TrimSpace(f.RuleVersion) != "" {
		add("s.rule_version = $%d", strings.TrimSpace(f.RuleVersion))
	}
	whereSQL := strings.Join(where, " AND ")
	grouped := `
SELECT s.stat_date::timestamp AT TIME ZONE 'UTC' AS day, s.rule_id, s.rule_key,
       s.rule_name, s.rule_source, s.rule_version,
       s.observed_count AS hits, s.blocked_count AS blocks,
       s.confirmed_attack_count AS confirmed_attacks,
       s.confirmed_false_positive_count AS false_positives,
       s.unresolved_count AS unresolved
FROM rule_statistics_daily s
WHERE ` + whereSQL
	var total int64
	if err := s.db.QueryRow(ctx, `SELECT COUNT(*) FROM (`+grouped+`) grouped_stats`, args...).Scan(&total); err != nil {
		return nil, 0, err
	}
	argsPage := append(append([]interface{}{}, args...), f.PageSize, (f.Page-1)*f.PageSize)
	rows, err := s.db.Query(ctx, `SELECT day, rule_id, rule_key, rule_name, rule_source, rule_version,
hits, blocks, confirmed_attacks, false_positives, unresolved FROM (`+grouped+`) grouped_stats
ORDER BY day DESC, rule_id, rule_version LIMIT $`+strconv.Itoa(len(args)+1)+` OFFSET $`+strconv.Itoa(len(args)+2), argsPage...)
	if err != nil {
		return nil, 0, err
	}
	defer rows.Close()
	out := make([]RuleEffectStat, 0)
	for rows.Next() {
		var stat RuleEffectStat
		if err := rows.Scan(&stat.Date, &stat.RuleID, &stat.RuleKey, &stat.RuleName, &stat.RuleSource, &stat.RuleVersion,
			&stat.Hits, &stat.Blocks, &stat.ConfirmedAttacks, &stat.FalsePositives, &stat.Unresolved); err != nil {
			return nil, 0, err
		}
		stat.Reviewed = stat.ConfirmedAttacks + stat.FalsePositives
		if stat.Reviewed > 0 {
			confirmationRate := float64(stat.ConfirmedAttacks) / float64(stat.Reviewed)
			fpRate := float64(stat.FalsePositives) / float64(stat.Reviewed)
			stat.ConfirmationRate = &confirmationRate
			stat.FPRate = &fpRate
		}
		applyProtectRecommendation(&stat)
		out = append(out, stat)
	}
	return out, total, rows.Err()
}

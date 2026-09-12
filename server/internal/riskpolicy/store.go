// store.go 风险策略仓储（security_risk_policy 表 GLOBAL 单行；
// 读取侧同时供管理面接口与 guardconfig 发布下发——GetGuardRiskPolicy 实现
// guardconfig.RiskPolicyLister 接口，Go 隐式接口无需 guardconfig 反向导入本包）。
package riskpolicy

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/jiuzhang-waf/server/internal/gatewayconfig"
)

// ErrNotFound 策略行不存在（迁移 000101 种子缺失——按内部错误处理）。
var ErrNotFound = errors.New("risk policy not found")

// ErrConflict 乐观锁冲突（version 不匹配：并发修改，需刷新后重试）。
var ErrConflict = errors.New("risk policy version conflict")

// Store 是风险策略仓储。
type Store struct {
	db *pgxpool.Pool
}

// NewStore 创建仓储。
func NewStore(db *pgxpool.Pool) *Store {
	return &Store{db: db}
}

// policyColumns 查询列清单（与 scanPolicy 顺序一致）。
const policyColumns = `id, scope, enabled, mode, version,
  block_threshold, rate_limit_threshold, rate_limit_rps, signal_window_seconds,
  scores, risk_levels, updated_by, created_at, updated_at`

// scanPolicy 扫描一行策略（JSONB 列经 json.RawMessage 中转反序列化）。
func scanPolicy(row pgx.Row) (*Policy, error) {
	var p Policy
	var scores, riskLevels []byte
	var updatedBy *string
	err := row.Scan(&p.ID, &p.Scope, &p.Enabled, &p.Mode, &p.Version,
		&p.BlockThreshold, &p.RateLimitThreshold, &p.RateLimitRPS, &p.SignalWindowSeconds,
		&scores, &riskLevels, &updatedBy, &p.CreatedAt, &p.UpdatedAt)
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return nil, ErrNotFound
		}
		return nil, err
	}
	if updatedBy != nil {
		p.UpdatedBy = *updatedBy
	}
	p.Scores = map[string]int{}
	p.RiskLevels = map[string]int{}
	if err := json.Unmarshal(scores, &p.Scores); err != nil {
		return nil, fmt.Errorf("decode scores: %w", err)
	}
	if err := json.Unmarshal(riskLevels, &p.RiskLevels); err != nil {
		return nil, fmt.Errorf("decode risk_levels: %w", err)
	}
	return &p, nil
}

// Get 读取 GLOBAL 全局策略单行。
func (s *Store) Get(ctx context.Context) (*Policy, error) {
	row := s.db.QueryRow(ctx, `SELECT `+policyColumns+` FROM security_risk_policy WHERE scope = $1`, ScopeGlobal)
	return scanPolicy(row)
}

// Update 全量更新 GLOBAL 策略（乐观锁：version 不匹配则 ErrConflict；scope 不可变）。
func (s *Store) Update(ctx context.Context, p *Policy, updatedBy string) error {
	if errs := Validate(p); len(errs) > 0 {
		return &ValidationError{Errors: errs}
	}
	scores, err := json.Marshal(nonNilScores(p.Scores))
	if err != nil {
		return err
	}
	riskLevels, err := json.Marshal(nonNilScores(p.RiskLevels))
	if err != nil {
		return err
	}
	res, err := s.db.Exec(ctx, `
UPDATE security_risk_policy SET enabled=$1, mode=$2,
  block_threshold=$3, rate_limit_threshold=$4, rate_limit_rps=$5, signal_window_seconds=$6,
  scores=$7, risk_levels=$8, updated_by=$9, updated_at=now(), version=version+1
WHERE scope=$10 AND version=$11`,
		p.Enabled, p.Mode,
		p.BlockThreshold, p.RateLimitThreshold, p.RateLimitRPS, p.SignalWindowSeconds,
		scores, riskLevels, updatedBy, ScopeGlobal, p.Version)
	if err != nil {
		return err
	}
	if res.RowsAffected() == 0 {
		return ErrConflict
	}
	p.Version++
	return nil
}

// GetGuardRiskPolicy 读取并映射为网关下发契约（guardconfig 发布通道注入用；
// version 为策略乐观锁版本号，网关随风险处置事件回报 policy_version 供溯源）。
func (s *Store) GetGuardRiskPolicy(ctx context.Context) (*gatewayconfig.GuardRiskPolicy, error) {
	p, err := s.Get(ctx)
	if err != nil {
		return nil, err
	}
	return &gatewayconfig.GuardRiskPolicy{
		Enabled:             p.Enabled,
		Mode:                p.Mode,
		Version:             p.Version,
		BlockThreshold:      p.BlockThreshold,
		RateLimitThreshold:  p.RateLimitThreshold,
		RateLimitRPS:        p.RateLimitRPS,
		SignalWindowSeconds: p.SignalWindowSeconds,
		Scores:              nonNilScores(p.Scores),
		RiskLevels:          nonNilScores(p.RiskLevels),
	}, nil
}

// nonNilScores JSON 对象列空值归一（nil → 空对象，下发契约对象恒出）。
func nonNilScores(in map[string]int) map[string]int {
	if in == nil {
		return map[string]int{}
	}
	return in
}

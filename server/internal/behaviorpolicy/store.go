// store.go 行为策略仓储（security_behavior_policy 表 GLOBAL 单行；
// 读取侧同时供管理面接口与 guardconfig 发布下发——GetGuardBehaviorPolicy 实现
// guardconfig.BehaviorPolicyLister 接口，Go 隐式接口无需 guardconfig 反向导入本包）。
package behaviorpolicy

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"strconv"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/jiuzhang-waf/server/internal/gatewayconfig"
)

// ErrNotFound 策略行不存在（迁移 000098 种子缺失——按内部错误处理）。
var ErrNotFound = errors.New("behavior policy not found")

// ErrConflict 乐观锁冲突（version 不匹配：并发修改，需刷新后重试）。
var ErrConflict = errors.New("behavior policy version conflict")

// Store 是行为策略仓储。
type Store struct {
	db *pgxpool.Pool
}

// NewStore 创建仓储。
func NewStore(db *pgxpool.Pool) *Store {
	return &Store{db: db}
}

// policyColumns 查询列清单（与 scanPolicy 顺序一致）。
const policyColumns = `id, scope, enabled, mode, version,
  uri_enum_unique_threshold, uri_enum_new_ratio_threshold, not_found_ratio_threshold, not_found_min_requests,
  method_enum_threshold, param_mutation_threshold, auth_fail_threshold, low_slow_sensitive_min_hits,
  account_enum_threshold, object_enum_threshold, account_identifier_fields, object_identifier_fields,
  sensitive_paths, scores, whitelist_ips, whitelist_uas, updated_by, created_at, updated_at`

// scanPolicy 扫描一行策略（JSONB 列经 json.RawMessage 中转反序列化）。
func scanPolicy(row pgx.Row) (*Policy, error) {
	var p Policy
	var accountIdentifierFields, objectIdentifierFields, sensitivePaths, scores, whitelistIPs, whitelistUAs []byte
	var updatedBy *string
	err := row.Scan(&p.ID, &p.Scope, &p.Enabled, &p.Mode, &p.Version,
		&p.URIEnumUniqueThreshold, &p.URIEnumNewRatioThreshold, &p.NotFoundRatioThreshold, &p.NotFoundMinRequests,
		&p.MethodEnumThreshold, &p.ParamMutationThreshold, &p.AuthFailThreshold, &p.LowSlowSensitiveMinHits,
		&p.AccountEnumThreshold, &p.ObjectEnumThreshold, &accountIdentifierFields, &objectIdentifierFields,
		&sensitivePaths, &scores, &whitelistIPs, &whitelistUAs, &updatedBy, &p.CreatedAt, &p.UpdatedAt)
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return nil, ErrNotFound
		}
		return nil, err
	}
	if updatedBy != nil {
		p.UpdatedBy = *updatedBy
	}
	p.SensitivePaths = []string{}
	p.AccountIdentifierFields = []string{}
	p.ObjectIdentifierFields = []string{}
	p.Scores = map[string]int{}
	p.WhitelistIPs = []string{}
	p.WhitelistUAs = []string{}
	if err := json.Unmarshal(sensitivePaths, &p.SensitivePaths); err != nil {
		return nil, fmt.Errorf("decode sensitive_paths: %w", err)
	}
	if err := json.Unmarshal(accountIdentifierFields, &p.AccountIdentifierFields); err != nil {
		return nil, fmt.Errorf("decode account_identifier_fields: %w", err)
	}
	if err := json.Unmarshal(objectIdentifierFields, &p.ObjectIdentifierFields); err != nil {
		return nil, fmt.Errorf("decode object_identifier_fields: %w", err)
	}
	if err := json.Unmarshal(scores, &p.Scores); err != nil {
		return nil, fmt.Errorf("decode scores: %w", err)
	}
	if err := json.Unmarshal(whitelistIPs, &p.WhitelistIPs); err != nil {
		return nil, fmt.Errorf("decode whitelist_ips: %w", err)
	}
	if err := json.Unmarshal(whitelistUAs, &p.WhitelistUAs); err != nil {
		return nil, fmt.Errorf("decode whitelist_uas: %w", err)
	}
	return &p, nil
}

// Get 读取 GLOBAL 全局策略单行。
func (s *Store) Get(ctx context.Context) (*Policy, error) {
	row := s.db.QueryRow(ctx, `SELECT `+policyColumns+` FROM security_behavior_policy WHERE scope = $1`, ScopeGlobal)
	return scanPolicy(row)
}

// Update 全量更新 GLOBAL 策略（乐观锁：version 不匹配则 ErrConflict；scope 不可变）。
func (s *Store) Update(ctx context.Context, p *Policy, updatedBy string) error {
	if errs := Validate(p); len(errs) > 0 {
		return &ValidationError{Errors: errs}
	}
	sensitivePaths, err := json.Marshal(nonNilStrings(p.SensitivePaths))
	if err != nil {
		return err
	}
	scores, err := json.Marshal(nonNilScores(p.Scores))
	if err != nil {
		return err
	}
	whitelistIPs, err := json.Marshal(nonNilStrings(p.WhitelistIPs))
	if err != nil {
		return err
	}
	whitelistUAs, err := json.Marshal(nonNilStrings(p.WhitelistUAs))
	if err != nil {
		return err
	}
	accountIdentifierFields, err := json.Marshal(nonNilStrings(p.AccountIdentifierFields))
	if err != nil {
		return err
	}
	objectIdentifierFields, err := json.Marshal(nonNilStrings(p.ObjectIdentifierFields))
	if err != nil {
		return err
	}
	res, err := s.db.Exec(ctx, `
UPDATE security_behavior_policy SET enabled=$1, mode=$2,
  uri_enum_unique_threshold=$3, uri_enum_new_ratio_threshold=$4, not_found_ratio_threshold=$5,
  not_found_min_requests=$6, method_enum_threshold=$7, param_mutation_threshold=$8,
  auth_fail_threshold=$9, low_slow_sensitive_min_hits=$10,
  account_enum_threshold=$11, object_enum_threshold=$12,
  account_identifier_fields=$13, object_identifier_fields=$14,
  sensitive_paths=$15, scores=$16, whitelist_ips=$17, whitelist_uas=$18,
  updated_by=$19, updated_at=now(), version=version+1
WHERE scope=$20 AND version=$21`,
		p.Enabled, p.Mode,
		p.URIEnumUniqueThreshold, p.URIEnumNewRatioThreshold, p.NotFoundRatioThreshold,
		p.NotFoundMinRequests, p.MethodEnumThreshold, p.ParamMutationThreshold,
		p.AuthFailThreshold, p.LowSlowSensitiveMinHits,
		p.AccountEnumThreshold, p.ObjectEnumThreshold,
		accountIdentifierFields, objectIdentifierFields,
		sensitivePaths, scores, whitelistIPs, whitelistUAs,
		updatedBy, ScopeGlobal, p.Version)
	if err != nil {
		return err
	}
	if res.RowsAffected() == 0 {
		return ErrConflict
	}
	p.Version++
	return nil
}

// GetGuardBehaviorPolicy 读取并映射为网关下发契约（guardconfig 发布通道注入用；
// policy_version 为策略 version 十进制字符串）。
func (s *Store) GetGuardBehaviorPolicy(ctx context.Context) (*gatewayconfig.GuardIdentityBehavior, error) {
	p, err := s.Get(ctx)
	if err != nil {
		return nil, err
	}
	return &gatewayconfig.GuardIdentityBehavior{
		Enabled:                  p.Enabled,
		Mode:                     p.Mode,
		PolicyVersion:            strconv.Itoa(p.Version),
		URIEnumUniqueThreshold:   p.URIEnumUniqueThreshold,
		URIEnumNewRatioThreshold: p.URIEnumNewRatioThreshold,
		NotFoundRatioThreshold:   p.NotFoundRatioThreshold,
		NotFoundMinRequests:      p.NotFoundMinRequests,
		MethodEnumThreshold:      p.MethodEnumThreshold,
		ParamMutationThreshold:   p.ParamMutationThreshold,
		AuthFailThreshold:        p.AuthFailThreshold,
		LowSlowSensitiveMinHits:  p.LowSlowSensitiveMinHits,
		AccountEnumThreshold:     p.AccountEnumThreshold,
		ObjectEnumThreshold:      p.ObjectEnumThreshold,
		AccountIdentifierFields:  nonNilStrings(p.AccountIdentifierFields),
		ObjectIdentifierFields:   nonNilStrings(p.ObjectIdentifierFields),
		SensitivePaths:           nonNilStrings(p.SensitivePaths),
		Scores:                   nonNilScores(p.Scores),
		WhitelistIPs:             nonNilStrings(p.WhitelistIPs),
		WhitelistUAs:             nonNilStrings(p.WhitelistUAs),
	}, nil
}

// nonNilStrings JSON 数组列空值归一（nil → 空数组，下发契约数组恒出）。
func nonNilStrings(in []string) []string {
	if in == nil {
		return []string{}
	}
	return in
}

// nonNilScores JSON 对象列空值归一（nil → 空对象）。
func nonNilScores(in map[string]int) map[string]int {
	if in == nil {
		return map[string]int{}
	}
	return in
}

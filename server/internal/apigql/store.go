// store.go GraphQL 成本预算策略存储（NG-GQL-03 管理面；迁移 000171）。
// 读（管理 API）与发布下发（ListForGuard，enabled=true 应用行 → GuardConfig.api_graphql
// 段，与 api_admission 段同一 fail-hard 纪律：读取失败中止发布——静默丢失会让已启用
// 应用在新配置中失去成本预算拦截）。
package apigql

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/jiuzhang-waf/gateway/dynamic_security/gqlast"
	"github.com/jiuzhang-waf/server/internal/gatewayconfig"
)

// Policy 策略（管理 API 与发布 payload 同构；config 冻结契约见迁移 000171 头注释）。
type Policy struct {
	Enabled           bool                             `json:"enabled"`
	Limits            gatewayconfig.GuardGraphQLLimits `json:"limits,omitempty"`
	Weights           gqlast.WeightsConfig             `json:"weights,omitempty"`
	Budget            gqlast.BudgetConfig              `json:"budget,omitempty"`
	TrustedDocDigests []string                         `json:"trusted_doc_digests,omitempty"`
}

// PolicyView 管理 API 视图（附版本/更新时间；无行时 enabled=false version=0 的
// 默认视图——「无段=关闭」语义，前端无需区分 404）。
type PolicyView struct {
	ApplicationID string `json:"application_id"`
	Policy
	Version   int    `json:"version"`
	UpdatedAt string `json:"updated_at,omitempty"`
	UpdatedBy string `json:"updated_by,omitempty"`
}

// Store 策略存储接口（PGStore 实现；测试注入 fake）。
type Store interface {
	GetPolicy(ctx context.Context, appID uuid.UUID) (PolicyView, error)
	UpsertPolicy(ctx context.Context, appID uuid.UUID, p Policy, operatorID uuid.UUID) (PolicyView, error)
	DeletePolicy(ctx context.Context, appID uuid.UUID, operatorID uuid.UUID) error
	ListForGuard(ctx context.Context) (map[string]*gatewayconfig.GuardGraphQLPolicy, error)
}

// ErrAppNotFound 应用不存在（FK 违例映射；软删除应用按不存在处理）。
var ErrAppNotFound = errors.New("application not found")

// PGStore PostgreSQL 存储。
type PGStore struct {
	db *pgxpool.Pool
}

// NewStore 创建 PG 存储。
func NewStore(db *pgxpool.Pool) *PGStore { return &PGStore{db: db} }

// appExists 应用存在且未软删除（写入前校验；软删除应用视为不存在）。
func (s *PGStore) appExists(ctx context.Context, appID uuid.UUID) (bool, error) {
	var exists bool
	if err := s.db.QueryRow(ctx,
		`SELECT EXISTS(SELECT 1 FROM applications WHERE id = $1 AND deleted_at IS NULL)`, appID).Scan(&exists); err != nil {
		return false, fmt.Errorf("check application: %w", err)
	}
	return exists, nil
}

// GetPolicy 读单应用策略（无行返回 enabled=false version=0 默认视图，不报错）。
func (s *PGStore) GetPolicy(ctx context.Context, appID uuid.UUID) (PolicyView, error) {
	view := PolicyView{ApplicationID: appID.String()}
	var (
		enabled   bool
		config    []byte
		version   int
		updatedAt interface{}
		updatedBy *uuid.UUID
	)
	err := s.db.QueryRow(ctx, `
SELECT enabled, config, version, updated_at, updated_by
FROM api_graphql_policies WHERE application_id = $1`, appID).
		Scan(&enabled, &config, &version, &updatedAt, &updatedBy)
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return view, nil // 无行 = 关闭（默认视图）
		}
		return view, fmt.Errorf("get api_graphql_policy: %w", err)
	}
	view.Enabled = enabled
	if err := json.Unmarshal(config, &view.Policy); err != nil {
		return view, fmt.Errorf("decode api_graphql_policy config: %w", err)
	}
	view.Enabled = enabled // Unmarshal 不覆盖（config 不含 enabled 键——列存）
	view.Version = version
	if t, ok := updatedAt.(interface{ String() string }); ok {
		view.UpdatedAt = t.String()
	}
	if updatedBy != nil {
		view.UpdatedBy = updatedBy.String()
	}
	return view, nil
}

// UpsertPolicy 写入策略（不存在插入/存在覆盖，version+1；应用不存在/已软删 ErrAppNotFound）。
func (s *PGStore) UpsertPolicy(ctx context.Context, appID uuid.UUID, p Policy, operatorID uuid.UUID) (PolicyView, error) {
	exists, err := s.appExists(ctx, appID)
	if err != nil {
		return PolicyView{}, err
	}
	if !exists {
		return PolicyView{}, ErrAppNotFound
	}
	// config 不含 enabled（列存单一事实源）；写前重新序列化剔除可能带入的 enabled 键
	type configOnly Policy
	raw, err := json.Marshal(configOnly(p))
	if err != nil {
		return PolicyView{}, fmt.Errorf("marshal api_graphql_policy config: %w", err)
	}
	var operator *uuid.UUID
	if operatorID != uuid.Nil {
		operator = &operatorID
	}
	_, err = s.db.Exec(ctx, `
INSERT INTO api_graphql_policies (application_id, enabled, config, version, updated_by)
VALUES ($1,$2,$3,1,$4)
ON CONFLICT (application_id) DO UPDATE SET
  enabled = EXCLUDED.enabled,
  config = EXCLUDED.config,
  version = api_graphql_policies.version + 1,
  updated_by = EXCLUDED.updated_by,
  updated_at = now()`,
		appID, p.Enabled, raw, operator)
	if err != nil {
		return PolicyView{}, fmt.Errorf("upsert api_graphql_policy: %w", err)
	}
	return s.GetPolicy(ctx, appID)
}

// DeletePolicy 删除策略行（→ 关闭；应用不存在或本无行均不报错——目标态即关闭）。
func (s *PGStore) DeletePolicy(ctx context.Context, appID uuid.UUID, operatorID uuid.UUID) error {
	if _, err := s.db.Exec(ctx,
		`DELETE FROM api_graphql_policies WHERE application_id = $1`, appID); err != nil {
		return fmt.Errorf("delete api_graphql_policy: %w", err)
	}
	return nil
}

// ListForGuard 发布下发读取（enabled=true 应用行；config 与发布 payload 同构）。
func (s *PGStore) ListForGuard(ctx context.Context) (map[string]*gatewayconfig.GuardGraphQLPolicy, error) {
	rows, err := s.db.Query(ctx, `
SELECT application_id, config FROM api_graphql_policies
WHERE enabled = TRUE ORDER BY application_id`)
	if err != nil {
		return nil, fmt.Errorf("list api_graphql_policies: %w", err)
	}
	defer rows.Close()
	out := map[string]*gatewayconfig.GuardGraphQLPolicy{}
	for rows.Next() {
		var appID uuid.UUID
		var raw []byte
		if err := rows.Scan(&appID, &raw); err != nil {
			return nil, err
		}
		var p Policy
		if err := json.Unmarshal(raw, &p); err != nil {
			return nil, fmt.Errorf("decode api_graphql_policy config for %s: %w", appID, err)
		}
		out[appID.String()] = &gatewayconfig.GuardGraphQLPolicy{
			Enabled:           true,
			Limits:            p.Limits,
			Weights:           p.Weights,
			Budget:            p.Budget,
			TrustedDocDigests: p.TrustedDocDigests,
		}
	}
	if err := rows.Err(); err != nil {
		return nil, err
	}
	if len(out) == 0 {
		return nil, nil // 无启用应用：不下发该段（nil map 语义）
	}
	return out, nil
}

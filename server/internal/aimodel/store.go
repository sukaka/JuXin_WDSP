// store.go 模型与供应商持久化（密钥加密存储）。
package aimodel

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/jiuzhang-waf/server/internal/encryption"
)

// ErrNotFound 资源不存在。
var ErrNotFound = errors.New("model or provider not found")

// ErrProviderHasModels 供应商下仍有模型，禁止删除。
var ErrProviderHasModels = errors.New("provider still has models")

// Store 模型仓储。
type Store struct {
	db  *pgxpool.Pool
	enc *encryption.Service
}

// NewStore 创建模型仓储。
func NewStore(db *pgxpool.Pool, enc *encryption.Service) *Store {
	return &Store{db: db, enc: enc}
}

// ---------- 供应商 ----------

// CreateProvider 创建供应商（可选同时保存密钥）。
// 携带密钥时：enc 未装配直接报错（不得静默丢弃用户密钥）；供应商行与密钥密文
// 同一事务落库，密钥保存失败整体回滚——不得建出「有引用无密文」的残缺供应商
// （运行期 401 静默切备用模型会掩盖配置故障，见审查 LOW-S11）。
func (s *Store) CreateProvider(ctx context.Context, p *Provider, plainKey string) error {
	if plainKey != "" && s.enc == nil {
		return fmt.Errorf("encryption service unavailable")
	}
	if err := prepareProviderForSave(ctx, p); err != nil {
		return err
	}
	p.ID = uuid.New()
	if plainKey != "" && p.KeyReference == "" {
		p.KeyReference = "provider-" + p.ID.String()[:8]
	}
	tx, err := s.db.Begin(ctx)
	if err != nil {
		return err
	}
	defer func() { _ = tx.Rollback(ctx) }()
	if _, err := tx.Exec(ctx, `
INSERT INTO ai_model_providers
  (id, name, provider_type, base_url, canonical_origin, allowed_targets, api_key_reference, status)
VALUES ($1,$2,$3,$4,$5,$6,$7,$8)`,
		p.ID, p.Name, string(p.Type), p.BaseURL, p.CanonicalOrigin, p.AllowedTargets, p.KeyReference, p.Status); err != nil {
		return err
	}
	if plainKey != "" {
		if err := s.saveSecret(ctx, tx, p.KeyReference, plainKey); err != nil {
			return err
		}
	}
	return tx.Commit(ctx)
}

// execer 抽象 *pgxpool.Pool 与 pgx.Tx 的 Exec（saveSecret 事务内外复用）。
type execer interface {
	Exec(ctx context.Context, sql string, args ...interface{}) (pgconn.CommandTag, error)
}

// saveSecret 加密保存密钥（enc 未装配返回错误，调用方不得静默降级）。
func (s *Store) saveSecret(ctx context.Context, ex execer, reference, plainKey string) error {
	if s.enc == nil {
		return fmt.Errorf("encryption service unavailable")
	}
	ct, err := s.enc.Encrypt(plainKey)
	if err != nil {
		return err
	}
	_, err = ex.Exec(ctx, `
INSERT INTO ai_provider_secrets (reference, encrypted_key, rotated_at)
VALUES ($1,$2,now())
ON CONFLICT (reference) DO UPDATE SET encrypted_key = EXCLUDED.encrypted_key, rotated_at = now()`,
		reference, ct)
	return err
}

// DecryptSecret 实现 KeyResolver（仅服务端内部使用，绝不外传）。
func (s *Store) DecryptSecret(ctx context.Context, reference string) (string, error) {
	if s.enc == nil {
		return "", fmt.Errorf("encryption service unavailable")
	}
	var ct string
	err := s.db.QueryRow(ctx, `SELECT encrypted_key FROM ai_provider_secrets WHERE reference=$1`, reference).Scan(&ct)
	if err != nil {
		return "", err
	}
	return s.enc.Decrypt(ct)
}

// ListProviders 列出供应商（不含密钥）。
func (s *Store) ListProviders(ctx context.Context) ([]Provider, error) {
	rows, err := s.db.Query(ctx, `
SELECT id, name, provider_type, base_url, canonical_origin, allowed_targets, api_key_reference, status
FROM ai_model_providers ORDER BY name`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []Provider
	for rows.Next() {
		var p Provider
		var t string
		if err := rows.Scan(&p.ID, &p.Name, &t, &p.BaseURL, &p.CanonicalOrigin, &p.AllowedTargets, &p.KeyReference, &p.Status); err != nil {
			return nil, err
		}
		p.Type = ProviderType(t)
		out = append(out, p)
	}
	if err := rows.Err(); err != nil {
		rows.Close()
		return nil, err
	}
	rows.Close()
	// Release the result cursor before lazily backfilling legacy bindings. This
	// also works with a pool configured with a single connection.
	for i := range out {
		if err := s.persistLegacyProviderBinding(ctx, &out[i]); err != nil {
			return nil, err
		}
	}
	return out, nil
}

// GetProvider 查询供应商（不含密钥）。
func (s *Store) GetProvider(ctx context.Context, id uuid.UUID) (*Provider, error) {
	var p Provider
	var t string
	err := s.db.QueryRow(ctx, `
SELECT id, name, provider_type, base_url, canonical_origin, allowed_targets, api_key_reference, status
FROM ai_model_providers WHERE id=$1`, id).
		Scan(&p.ID, &p.Name, &t, &p.BaseURL, &p.CanonicalOrigin, &p.AllowedTargets, &p.KeyReference, &p.Status)
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return nil, ErrNotFound
		}
		return nil, err
	}
	p.Type = ProviderType(t)
	if err := s.persistLegacyProviderBinding(ctx, &p); err != nil {
		return nil, err
	}
	return &p, nil
}

// UpdateProvider 更新供应商基本信息（不含密钥；密钥走 RotateKey）。
func (s *Store) UpdateProvider(ctx context.Context, p *Provider) error {
	if err := prepareProviderForSave(ctx, p); err != nil {
		return err
	}
	tx, err := s.db.Begin(ctx)
	if err != nil {
		return err
	}
	defer func() { _ = tx.Rollback(ctx) }()
	var oldOrigin, oldBaseURL, oldReference string
	err = tx.QueryRow(ctx, `
SELECT canonical_origin, base_url, api_key_reference
FROM ai_model_providers WHERE id=$1 FOR UPDATE`, p.ID).Scan(&oldOrigin, &oldBaseURL, &oldReference)
	if errors.Is(err, pgx.ErrNoRows) {
		return ErrNotFound
	}
	if err != nil {
		return err
	}
	originChanged, err := providerOriginChanged(oldOrigin, oldBaseURL, p.CanonicalOrigin)
	if err != nil {
		return err
	}
	if originChanged && oldReference != "" {
		if _, err := tx.Exec(ctx, `DELETE FROM ai_provider_secrets WHERE reference=$1`, oldReference); err != nil {
			return err
		}
		p.KeyReference = ""
	} else {
		p.KeyReference = oldReference
	}
	tag, err := tx.Exec(ctx, `
UPDATE ai_model_providers
SET name=$2, provider_type=$3, base_url=$4, canonical_origin=$5, allowed_targets=$6,
    api_key_reference=$7, status=$8, updated_at=now()
WHERE id=$1`, p.ID, p.Name, string(p.Type), p.BaseURL, p.CanonicalOrigin,
		p.AllowedTargets, p.KeyReference, p.Status)
	if err != nil {
		return err
	}
	if tag.RowsAffected() == 0 {
		return ErrNotFound
	}
	return tx.Commit(ctx)
}

func providerOriginChanged(oldOrigin, oldBaseURL, newOrigin string) (bool, error) {
	if oldOrigin == "" {
		var err error
		oldOrigin, err = CanonicalOrigin(oldBaseURL)
		if err != nil {
			return false, err
		}
	}
	return oldOrigin != newOrigin, nil
}

// RotateKey 轮换供应商密钥（明文仅入参，加密落库；引用名缺省时自动生成并回写）。
func (s *Store) RotateKey(ctx context.Context, id uuid.UUID, plainKey string) error {
	if plainKey == "" {
		return fmt.Errorf("plain key required")
	}
	if s.enc == nil {
		return fmt.Errorf("encryption service unavailable")
	}
	tx, err := s.db.Begin(ctx)
	if err != nil {
		return err
	}
	defer func() { _ = tx.Rollback(ctx) }()
	var p Provider
	var providerType string
	err = tx.QueryRow(ctx, `
SELECT id, name, provider_type, base_url, canonical_origin, allowed_targets, api_key_reference, status
FROM ai_model_providers WHERE id=$1 FOR UPDATE`, id).Scan(
		&p.ID, &p.Name, &providerType, &p.BaseURL, &p.CanonicalOrigin,
		&p.AllowedTargets, &p.KeyReference, &p.Status,
	)
	if errors.Is(err, pgx.ErrNoRows) {
		return ErrNotFound
	}
	if err != nil {
		return err
	}
	p.Type = ProviderType(providerType)
	if err := prepareProviderForSave(ctx, &p); err != nil {
		return err
	}
	ref := p.KeyReference
	if ref == "" {
		ref = "provider-" + p.ID.String()[:8]
	}
	if err := s.saveSecret(ctx, tx, ref, plainKey); err != nil {
		return err
	}
	if _, err := tx.Exec(ctx, `
UPDATE ai_model_providers
SET api_key_reference=$1, canonical_origin=$2, allowed_targets=$3, updated_at=now()
WHERE id=$4`, ref, p.CanonicalOrigin, p.AllowedTargets, p.ID); err != nil {
		return err
	}
	return tx.Commit(ctx)
}

func prepareProviderForSave(ctx context.Context, p *Provider) error {
	origin, err := CanonicalOrigin(p.BaseURL)
	if err != nil {
		return err
	}
	p.CanonicalOrigin = origin
	for i := range p.AllowedTargets {
		p.AllowedTargets[i] = strings.ToLower(strings.TrimSuffix(strings.TrimSpace(p.AllowedTargets[i]), "."))
	}
	return ValidateProviderEndpoint(ctx, p)
}

// persistLegacyProviderBinding upgrades rows created before the origin-binding
// columns existed. The conditional update keeps concurrent readers harmless.
func (s *Store) persistLegacyProviderBinding(ctx context.Context, p *Provider) error {
	if p.CanonicalOrigin != "" {
		return nil
	}
	origin, err := CanonicalOrigin(p.BaseURL)
	if err != nil {
		return err
	}
	if _, err := s.db.Exec(ctx, `
UPDATE ai_model_providers SET canonical_origin=$1, updated_at=now()
WHERE id=$2 AND canonical_origin=''`, origin, p.ID); err != nil {
		return err
	}
	p.CanonicalOrigin = origin
	return nil
}

// CountModelsByProvider 统计供应商下模型数量。
func (s *Store) CountModelsByProvider(ctx context.Context, providerID uuid.UUID) (int, error) {
	var n int
	err := s.db.QueryRow(ctx, `SELECT count(*) FROM ai_models WHERE provider_id=$1`, providerID).Scan(&n)
	return n, err
}

// DeleteProvider 删除供应商：若仍有关联模型则拒绝；同时清理密钥密文。
func (s *Store) DeleteProvider(ctx context.Context, id uuid.UUID) error {
	p, err := s.GetProvider(ctx, id)
	if err != nil {
		return err
	}
	n, err := s.CountModelsByProvider(ctx, id)
	if err != nil {
		return err
	}
	if n > 0 {
		return ErrProviderHasModels
	}
	tx, err := s.db.Begin(ctx)
	if err != nil {
		return err
	}
	defer func() { _ = tx.Rollback(ctx) }()
	if p.KeyReference != "" {
		if _, err := tx.Exec(ctx, `DELETE FROM ai_provider_secrets WHERE reference=$1`, p.KeyReference); err != nil {
			return err
		}
	}
	tag, err := tx.Exec(ctx, `DELETE FROM ai_model_providers WHERE id=$1`, id)
	if err != nil {
		return err
	}
	if tag.RowsAffected() == 0 {
		return ErrNotFound
	}
	return tx.Commit(ctx)
}

// ---------- 模型 ----------

// CreateModel 创建模型。
func (s *Store) CreateModel(ctx context.Context, m *Model) error {
	m.ID = uuid.New()
	_, err := s.db.Exec(ctx, `
INSERT INTO ai_models (id, provider_id, model_code, display_name, context_window, max_output_tokens,
  supports_tools, supports_streaming, supports_structured_output, supports_embeddings,
  priority, timeout_seconds, cost_input_unit, cost_output_unit, status)
VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,$14,$15)`,
		m.ID, m.ProviderID, m.Code, m.DisplayName, m.ContextWindow, m.MaxOutputTokens,
		m.SupportsTools, m.SupportsStreaming, false, false,
		m.Priority, m.TimeoutSeconds, m.CostInputUnit, m.CostOutputUnit, m.Status)
	return err
}

// UpdateModel 更新模型（不含密钥）。
func (s *Store) UpdateModel(ctx context.Context, m *Model) error {
	tag, err := s.db.Exec(ctx, `
UPDATE ai_models SET display_name=$2, context_window=$3, max_output_tokens=$4,
  priority=$5, timeout_seconds=$6, cost_input_unit=$7, cost_output_unit=$8, updated_at=now()
WHERE id=$1`,
		m.ID, m.DisplayName, m.ContextWindow, m.MaxOutputTokens,
		m.Priority, m.TimeoutSeconds, m.CostInputUnit, m.CostOutputUnit)
	if err != nil {
		return err
	}
	if tag.RowsAffected() == 0 {
		return ErrNotFound
	}
	return nil
}

// SetModelStatus 启停模型。
func (s *Store) SetModelStatus(ctx context.Context, id uuid.UUID, status string) error {
	tag, err := s.db.Exec(ctx, `UPDATE ai_models SET status=$2, updated_at=now() WHERE id=$1`, id, status)
	if err != nil {
		return err
	}
	if tag.RowsAffected() == 0 {
		return ErrNotFound
	}
	return nil
}

// DeleteModel 删除模型。
func (s *Store) DeleteModel(ctx context.Context, id uuid.UUID) error {
	tag, err := s.db.Exec(ctx, `DELETE FROM ai_models WHERE id=$1`, id)
	if err != nil {
		return err
	}
	if tag.RowsAffected() == 0 {
		return ErrNotFound
	}
	return nil
}

// ListModels 列出模型（含供应商，不含密钥）。
func (s *Store) ListModels(ctx context.Context) ([]Model, []Provider, error) {
	providers, err := s.ListProviders(ctx)
	if err != nil {
		return nil, nil, err
	}
	rows, err := s.db.Query(ctx, `
SELECT id, provider_id, model_code, display_name, context_window, max_output_tokens,
  supports_tools, supports_streaming, priority, timeout_seconds, cost_input_unit, cost_output_unit, status
FROM ai_models ORDER BY priority, display_name`)
	if err != nil {
		return nil, nil, err
	}
	defer rows.Close()
	var models []Model
	for rows.Next() {
		var m Model
		if err := rows.Scan(&m.ID, &m.ProviderID, &m.Code, &m.DisplayName, &m.ContextWindow, &m.MaxOutputTokens,
			&m.SupportsTools, &m.SupportsStreaming, &m.Priority, &m.TimeoutSeconds,
			&m.CostInputUnit, &m.CostOutputUnit, &m.Status); err != nil {
			return nil, nil, err
		}
		models = append(models, m)
	}
	return models, providers, rows.Err()
}

// LoadRoutes 从数据库加载启用模型的路由表。
func (s *Store) LoadRoutes(ctx context.Context, simpleModelCode, standardModelCode, highModelCode string) (map[TaskComplexity][]struct {
	Model    *Model
	Provider *Provider
}, error,
) {
	models, providers, err := s.ListModels(ctx)
	if err != nil {
		return nil, err
	}
	byID := map[uuid.UUID]*Provider{}
	for i := range providers {
		byID[providers[i].ID] = &providers[i]
	}
	routes := map[TaskComplexity][]struct {
		Model    *Model
		Provider *Provider
	}{}
	add := func(c TaskComplexity, code string) {
		for i := range models {
			if models[i].Code == code && models[i].Status == "ENABLED" {
				if p, ok := byID[models[i].ProviderID]; ok && p.Status == "ENABLED" {
					routes[c] = append(routes[c], struct {
						Model    *Model
						Provider *Provider
					}{&models[i], p})
				}
			}
		}
	}
	add(ComplexitySimple, simpleModelCode)
	add(ComplexityStandard, standardModelCode)
	add(ComplexityHigh, highModelCode)
	// 未配置时所有启用模型都进入标准路由兜底
	if len(routes[ComplexityStandard]) == 0 {
		for i := range models {
			if models[i].Status == "ENABLED" {
				if p, ok := byID[models[i].ProviderID]; ok && p.Status == "ENABLED" {
					routes[ComplexityStandard] = append(routes[ComplexityStandard], struct {
						Model    *Model
						Provider *Provider
					}{&models[i], p})
				}
			}
		}
	}
	return routes, nil
}

// GetModel 查询模型。
func (s *Store) GetModel(ctx context.Context, id uuid.UUID) (*Model, error) {
	var m Model
	err := s.db.QueryRow(ctx, `
SELECT id, provider_id, model_code, display_name, context_window, max_output_tokens,
  supports_tools, supports_streaming, priority, timeout_seconds, cost_input_unit, cost_output_unit, status
FROM ai_models WHERE id=$1`, id).Scan(&m.ID, &m.ProviderID, &m.Code, &m.DisplayName, &m.ContextWindow,
		&m.MaxOutputTokens, &m.SupportsTools, &m.SupportsStreaming, &m.Priority, &m.TimeoutSeconds,
		&m.CostInputUnit, &m.CostOutputUnit, &m.Status)
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return nil, ErrNotFound
		}
		return nil, err
	}
	return &m, nil
}

var _ = time.Now

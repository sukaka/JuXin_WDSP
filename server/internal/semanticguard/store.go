// store.go 本地离线语义防火墙仓储：semantic_guard_policies 与 semantic_guard_policy_versions（迁移 000248）。
// 实现 Repository 与 guardconfig.SemanticGuardLister 接口。
package semanticguard

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"strings"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/jiuzhang-waf/server/internal/gatewayconfig"
)

// ErrNotFound 资源不存在。
var ErrNotFound = errors.New("semantic guard resource not found")

// ErrConflict 策略乐观锁冲突。
var ErrConflict = errors.New("semantic guard policy conflict")

// Repository 定义处理器所需的仓储接口（*Store 实现，单测可注入内存桩）。
type Repository interface {
	GetPolicyByApp(ctx context.Context, appID uuid.UUID) (*Policy, error)
	SavePolicyDraft(ctx context.Context, p *Policy, expectedVersion int, reason, updatedBy string) error
	PublishedVersion(ctx context.Context, appCode string) (int, error)
}

// Store 是本地离线语义防火墙策略仓储。
type Store struct {
	db *pgxpool.Pool
}

// NewStore 创建仓储。
func NewStore(db *pgxpool.Pool) *Store {
	return &Store{db: db}
}

var _ Repository = (*Store)(nil)

const policyColumns = `id, application_id, mode, version, socket_path, timeout_ms,
	max_concurrency, max_input_runes, block_threshold, observe_threshold, fail_policy,
	inspect_llm_prompts, inspect_mcp_content, inspect_web_grayzone,
	circuit_failure_threshold, circuit_open_seconds, updated_by, created_at, updated_at`

func scanPolicy(row pgx.Row) (*Policy, error) {
	var (
		p         Policy
		updatedBy *string
	)
	err := row.Scan(
		&p.ID, &p.ApplicationID, &p.Mode, &p.Version, &p.SocketPath, &p.TimeoutMs,
		&p.MaxConcurrency, &p.MaxInputRunes, &p.BlockThreshold, &p.ObserveThreshold, &p.FailPolicy,
		&p.InspectLLMPrompts, &p.InspectMCPContent, &p.InspectWebGrayzone,
		&p.CircuitFailureThreshold, &p.CircuitOpenSeconds, &updatedBy, &p.CreatedAt, &p.UpdatedAt,
	)
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return nil, ErrNotFound
		}
		return nil, err
	}
	p.SchemaVersion = SchemaVersion
	if updatedBy != nil {
		p.UpdatedBy = *updatedBy
	}
	return &p, nil
}

// GetPolicyByApp 读取应用当前语义防火墙策略草稿；无记录返回 ErrNotFound。
func (s *Store) GetPolicyByApp(ctx context.Context, appID uuid.UUID) (*Policy, error) {
	row := s.db.QueryRow(ctx, `SELECT `+policyColumns+` FROM semantic_guard_policies WHERE application_id = $1`, appID)
	return scanPolicy(row)
}

// SavePolicyDraft 校验并保存策略草稿（expected_version 乐观锁 + 同事务写入不可变版本历史）。
func (s *Store) SavePolicyDraft(ctx context.Context, p *Policy, expectedVersion int, reason, updatedBy string) error {
	if errs := ValidatePolicy(p); len(errs) > 0 {
		return &ValidationError{Errors: errs}
	}
	if strings.TrimSpace(reason) == "" {
		return &ValidationError{Errors: []FieldError{{Field: "reason", Message: "变更理由不能为空"}}}
	}
	snapshotJSON, err := json.Marshal(map[string]interface{}{
		"mode":                      p.Mode,
		"socket_path":               p.SocketPath,
		"timeout_ms":                p.TimeoutMs,
		"max_concurrency":           p.MaxConcurrency,
		"max_input_runes":           p.MaxInputRunes,
		"block_threshold":           p.BlockThreshold,
		"observe_threshold":         p.ObserveThreshold,
		"fail_policy":               p.FailPolicy,
		"inspect_llm_prompts":       p.InspectLLMPrompts,
		"inspect_mcp_content":       p.InspectMCPContent,
		"inspect_web_grayzone":      p.InspectWebGrayzone,
		"circuit_failure_threshold": p.CircuitFailureThreshold,
		"circuit_open_seconds":      p.CircuitOpenSeconds,
	})
	if err != nil {
		return err
	}

	tx, err := s.db.Begin(ctx)
	if err != nil {
		return err
	}
	defer func() { _ = tx.Rollback(ctx) }()

	var newVersion int
	if expectedVersion == 0 {
		err = tx.QueryRow(ctx, `
INSERT INTO semantic_guard_policies (
	application_id, mode, version, socket_path, timeout_ms,
	max_concurrency, max_input_runes, block_threshold, observe_threshold, fail_policy,
	inspect_llm_prompts, inspect_mcp_content, inspect_web_grayzone,
	circuit_failure_threshold, circuit_open_seconds, updated_by
) VALUES ($1,$2,1,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,$14,$15)
RETURNING id, version`,
			p.ApplicationID, p.Mode, p.SocketPath, p.TimeoutMs,
			p.MaxConcurrency, p.MaxInputRunes, p.BlockThreshold, p.ObserveThreshold, p.FailPolicy,
			p.InspectLLMPrompts, p.InspectMCPContent, p.InspectWebGrayzone,
			p.CircuitFailureThreshold, p.CircuitOpenSeconds, updatedBy,
		).Scan(&p.ID, &newVersion)
		if err != nil {
			if isUniqueViolation(err) {
				return ErrConflict
			}
			return err
		}
	} else {
		err = tx.QueryRow(ctx, `
UPDATE semantic_guard_policies SET
	mode=$1, socket_path=$2, timeout_ms=$3, max_concurrency=$4,
	max_input_runes=$5, block_threshold=$6, observe_threshold=$7, fail_policy=$8,
	inspect_llm_prompts=$9, inspect_mcp_content=$10, inspect_web_grayzone=$11,
	circuit_failure_threshold=$12, circuit_open_seconds=$13,
	updated_by=$14, updated_at=now(), version=version+1
WHERE application_id=$15 AND version=$16
RETURNING id, version`,
			p.Mode, p.SocketPath, p.TimeoutMs, p.MaxConcurrency,
			p.MaxInputRunes, p.BlockThreshold, p.ObserveThreshold, p.FailPolicy,
			p.InspectLLMPrompts, p.InspectMCPContent, p.InspectWebGrayzone,
			p.CircuitFailureThreshold, p.CircuitOpenSeconds,
			updatedBy, p.ApplicationID, expectedVersion,
		).Scan(&p.ID, &newVersion)
		if err != nil {
			if errors.Is(err, pgx.ErrNoRows) {
				return ErrConflict
			}
			return err
		}
	}

	if _, err := tx.Exec(ctx, `
INSERT INTO semantic_guard_policy_versions (
	application_id, version, mode, policy_snapshot, reason, created_by
) VALUES ($1,$2,$3,$4::jsonb,$5,$6)`,
		p.ApplicationID, newVersion, p.Mode, string(snapshotJSON), reason, updatedBy,
	); err != nil {
		return err
	}
	if err := tx.Commit(ctx); err != nil {
		return err
	}
	p.Version = newVersion
	p.UpdatedBy = updatedBy
	return nil
}

// PublishedVersion 读取最近 SUCCESS 访问控制发布快照中本应用的语义防火墙策略版本。
func (s *Store) PublishedVersion(ctx context.Context, appCode string) (int, error) {
	var raw []byte
	err := s.db.QueryRow(ctx, `
SELECT config FROM access_control_versions
WHERE publish_result = 'SUCCESS'
ORDER BY version_no DESC LIMIT 1`).Scan(&raw)
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return 0, nil
		}
		return 0, err
	}
	var cfg struct {
		SemanticGuardPolicy map[string]struct {
			Version int `json:"version"`
		} `json:"semantic_guard_policy"`
	}
	if err := json.Unmarshal(raw, &cfg); err != nil {
		return 0, fmt.Errorf("decode published guard config: %w", err)
	}
	if pol, ok := cfg.SemanticGuardPolicy[appCode]; ok {
		return pol.Version, nil
	}
	return 0, nil
}

// ListForGuard 读取全部应用的语义防火墙策略并映射为网关冻结契约（实现 guardconfig.SemanticGuardLister；key=应用编码）。
func (s *Store) ListForGuard(ctx context.Context) (map[string]*gatewayconfig.GuardSemanticGuardPolicy, error) {
	rows, err := s.db.Query(ctx, `
SELECT p.application_id, a.code, p.mode, p.version, p.socket_path, p.timeout_ms,
	p.max_concurrency, p.max_input_runes, p.block_threshold, p.observe_threshold, p.fail_policy,
	p.inspect_llm_prompts, p.inspect_mcp_content, p.inspect_web_grayzone,
	p.circuit_failure_threshold, p.circuit_open_seconds
FROM semantic_guard_policies p
JOIN applications a ON a.id = p.application_id
WHERE a.deleted_at IS NULL
ORDER BY a.code ASC`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	out := map[string]*gatewayconfig.GuardSemanticGuardPolicy{}
	for rows.Next() {
		var (
			p    Policy
			code string
		)
		if err := rows.Scan(
			&p.ApplicationID, &code, &p.Mode, &p.Version, &p.SocketPath, &p.TimeoutMs,
			&p.MaxConcurrency, &p.MaxInputRunes, &p.BlockThreshold, &p.ObserveThreshold, &p.FailPolicy,
			&p.InspectLLMPrompts, &p.InspectMCPContent, &p.InspectWebGrayzone,
			&p.CircuitFailureThreshold, &p.CircuitOpenSeconds,
		); err != nil {
			return nil, err
		}
		out[code] = toGuardPolicy(&p)
	}
	return out, rows.Err()
}

// toGuardPolicy 将领域策略映射为网关 semantic_guard_policy 冻结契约（schema_version=1，无额外字段）。
func toGuardPolicy(p *Policy) *gatewayconfig.GuardSemanticGuardPolicy {
	return &gatewayconfig.GuardSemanticGuardPolicy{
		SchemaVersion:           SchemaVersion,
		ApplicationID:           p.ApplicationID.String(),
		Mode:                    p.Mode,
		Version:                 p.Version,
		SocketPath:              p.SocketPath,
		TimeoutMs:               p.TimeoutMs,
		MaxConcurrency:          p.MaxConcurrency,
		MaxInputRunes:           p.MaxInputRunes,
		BlockThreshold:          p.BlockThreshold,
		ObserveThreshold:        p.ObserveThreshold,
		FailPolicy:              p.FailPolicy,
		InspectLLMPrompts:       p.InspectLLMPrompts,
		InspectMCPContent:       p.InspectMCPContent,
		InspectWebGrayzone:      p.InspectWebGrayzone,
		CircuitFailureThreshold: p.CircuitFailureThreshold,
		CircuitOpenSeconds:      p.CircuitOpenSeconds,
	}
}

func isUniqueViolation(err error) bool {
	var pgErr *pgconn.PgError
	return errors.As(err, &pgErr) && pgErr.Code == "23505"
}

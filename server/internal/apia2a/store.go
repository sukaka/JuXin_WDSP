// store.go A2A 协议安全治理仓储：api_a2a_policies、api_a2a_policy_versions、
// api_a2a_agents（AgBOM）与 api_a2a_events（迁移 000247）。
// 实现 guardconfig.A2ALister 与 accesscontrolevents.A2AIngester 接口。
package apia2a

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/jiuzhang-waf/server/internal/accesscontrolevents"
	"github.com/jiuzhang-waf/server/internal/gatewayconfig"
)

// ErrNotFound 资源不存在。
var ErrNotFound = errors.New("a2a resource not found")

// ErrConflict 策略乐观锁冲突或 Agent 唯一约束冲突。
var ErrConflict = errors.New("a2a resource conflict")

// sqlExecer 最小 SQL 执行接口（*pgxpool.Pool 实现，便于单测注入内存桩验证 IngestEvent SQL 与参数）。
type sqlExecer interface {
	Exec(ctx context.Context, sql string, arguments ...any) (pgconn.CommandTag, error)
}

// Repository 定义处理器所需的仓储接口（*Store 实现，单测可注入内存桩）。
type Repository interface {
	GetPolicyByApp(ctx context.Context, appID uuid.UUID) (*Policy, error)
	SavePolicyDraft(ctx context.Context, p *Policy, expectedVersion int, reason, updatedBy string) error
	PublishedVersion(ctx context.Context, appCode string) (int, error)
	ListAgents(ctx context.Context, f AgentFilter) ([]Agent, int64, error)
	GetAgent(ctx context.Context, id uuid.UUID) (*Agent, error)
	CreateAgent(ctx context.Context, a *Agent) error
	UpdateAgent(ctx context.Context, id uuid.UUID, status, description string, allowedSkills []string) (*Agent, error)
	DeleteAgent(ctx context.Context, id uuid.UUID) error
	ListEvents(ctx context.Context, f EventFilter) ([]Event, int64, error)
}

// Store 是 A2A 协议安全治理仓储。
type Store struct {
	db   *pgxpool.Pool
	exec sqlExecer
}

// NewStore 创建仓储。
func NewStore(db *pgxpool.Pool) *Store {
	return &Store{db: db, exec: db}
}

var _ Repository = (*Store)(nil)

// ---------- 应用级 A2A 安全策略 ----------

const policyColumns = `id, application_id, mode, version, card_discovery_enabled,
	a2a_path_prefixes, allowed_caller_agents, max_delegation_depth, enforce_scope_attenuation,
	loop_window_seconds, max_calls_per_task_window, lethal_trifecta_enabled,
	confidential_read_patterns, external_egress_patterns, updated_by, created_at, updated_at`

func scanPolicy(row pgx.Row) (*Policy, error) {
	var (
		p                                               Policy
		prefixesRaw, callersRaw, readPatRaw, egressRaw  []byte
		updatedBy                                       *string
	)
	err := row.Scan(
		&p.ID, &p.ApplicationID, &p.Mode, &p.Version, &p.CardDiscoveryEnabled,
		&prefixesRaw, &callersRaw, &p.MaxDelegationDepth, &p.EnforceScopeAttenuation,
		&p.LoopWindowSeconds, &p.MaxCallsPerTaskWindow, &p.LethalTrifectaEnabled,
		&readPatRaw, &egressRaw, &updatedBy, &p.CreatedAt, &p.UpdatedAt,
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
	if err := decodeStringSlice(prefixesRaw, &p.A2APathPrefixes); err != nil {
		return nil, fmt.Errorf("decode a2a_path_prefixes: %w", err)
	}
	if err := decodeStringSlice(callersRaw, &p.AllowedCallerAgents); err != nil {
		return nil, fmt.Errorf("decode allowed_caller_agents: %w", err)
	}
	if err := decodeStringSlice(readPatRaw, &p.ConfidentialReadPatterns); err != nil {
		return nil, fmt.Errorf("decode confidential_read_patterns: %w", err)
	}
	if err := decodeStringSlice(egressRaw, &p.ExternalEgressPatterns); err != nil {
		return nil, fmt.Errorf("decode external_egress_patterns: %w", err)
	}
	return &p, nil
}

func decodeStringSlice(raw []byte, dst *[]string) error {
	*dst = []string{}
	if len(raw) == 0 {
		return nil
	}
	if err := json.Unmarshal(raw, dst); err != nil {
		return err
	}
	if *dst == nil {
		*dst = []string{}
	}
	return nil
}

// GetPolicyByApp 读取应用当前 A2A 安全策略草稿；无记录返回 ErrNotFound。
func (s *Store) GetPolicyByApp(ctx context.Context, appID uuid.UUID) (*Policy, error) {
	row := s.db.QueryRow(ctx, `SELECT `+policyColumns+` FROM api_a2a_policies WHERE application_id = $1`, appID)
	return scanPolicy(row)
}

// SavePolicyDraft 校验并保存 A2A 策略草稿（expected_version 乐观锁 + 同事务写入不可变版本历史）。
func (s *Store) SavePolicyDraft(ctx context.Context, p *Policy, expectedVersion int, reason, updatedBy string) error {
	if errs := ValidatePolicy(p); len(errs) > 0 {
		return &ValidationError{Errors: errs}
	}
	if strings.TrimSpace(reason) == "" {
		return &ValidationError{Errors: []FieldError{{Field: "reason", Message: "变更理由不能为空"}}}
	}
	prefixesJSON, err := json.Marshal(nonNilSlice(p.A2APathPrefixes))
	if err != nil {
		return err
	}
	callersJSON, err := json.Marshal(nonNilSlice(p.AllowedCallerAgents))
	if err != nil {
		return err
	}
	readPatJSON, err := json.Marshal(nonNilSlice(p.ConfidentialReadPatterns))
	if err != nil {
		return err
	}
	egressJSON, err := json.Marshal(nonNilSlice(p.ExternalEgressPatterns))
	if err != nil {
		return err
	}
	snapshotJSON, err := json.Marshal(map[string]interface{}{
		"mode":                       p.Mode,
		"card_discovery_enabled":     p.CardDiscoveryEnabled,
		"a2a_path_prefixes":          nonNilSlice(p.A2APathPrefixes),
		"allowed_caller_agents":      nonNilSlice(p.AllowedCallerAgents),
		"max_delegation_depth":       p.MaxDelegationDepth,
		"enforce_scope_attenuation":  p.EnforceScopeAttenuation,
		"loop_window_seconds":        p.LoopWindowSeconds,
		"max_calls_per_task_window":  p.MaxCallsPerTaskWindow,
		"lethal_trifecta_enabled":    p.LethalTrifectaEnabled,
		"confidential_read_patterns": nonNilSlice(p.ConfidentialReadPatterns),
		"external_egress_patterns":   nonNilSlice(p.ExternalEgressPatterns),
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
INSERT INTO api_a2a_policies (
	application_id, mode, version, card_discovery_enabled, a2a_path_prefixes,
	allowed_caller_agents, max_delegation_depth, enforce_scope_attenuation,
	loop_window_seconds, max_calls_per_task_window, lethal_trifecta_enabled,
	confidential_read_patterns, external_egress_patterns, updated_by
) VALUES ($1,$2,1,$3,$4::jsonb,$5::jsonb,$6,$7,$8,$9,$10,$11::jsonb,$12::jsonb,$13)
RETURNING id, version`,
			p.ApplicationID, p.Mode, p.CardDiscoveryEnabled, string(prefixesJSON),
			string(callersJSON), p.MaxDelegationDepth, p.EnforceScopeAttenuation,
			p.LoopWindowSeconds, p.MaxCallsPerTaskWindow, p.LethalTrifectaEnabled,
			string(readPatJSON), string(egressJSON), updatedBy,
		).Scan(&p.ID, &newVersion)
		if err != nil {
			if isUniqueViolation(err) {
				return ErrConflict
			}
			return err
		}
	} else {
		err = tx.QueryRow(ctx, `
UPDATE api_a2a_policies SET
	mode=$1, card_discovery_enabled=$2, a2a_path_prefixes=$3::jsonb,
	allowed_caller_agents=$4::jsonb, max_delegation_depth=$5,
	enforce_scope_attenuation=$6, loop_window_seconds=$7,
	max_calls_per_task_window=$8, lethal_trifecta_enabled=$9,
	confidential_read_patterns=$10::jsonb, external_egress_patterns=$11::jsonb,
	updated_by=$12, updated_at=now(), version=version+1
WHERE application_id=$13 AND version=$14
RETURNING id, version`,
			p.Mode, p.CardDiscoveryEnabled, string(prefixesJSON),
			string(callersJSON), p.MaxDelegationDepth,
			p.EnforceScopeAttenuation, p.LoopWindowSeconds,
			p.MaxCallsPerTaskWindow, p.LethalTrifectaEnabled,
			string(readPatJSON), string(egressJSON),
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
INSERT INTO api_a2a_policy_versions (
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

// PublishedVersion 读取最近 SUCCESS 访问控制发布快照中本应用的 A2A 策略版本。
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
		APIA2APolicy map[string]struct {
			Version int `json:"version"`
		} `json:"api_a2a_policy"`
	}
	if err := json.Unmarshal(raw, &cfg); err != nil {
		return 0, fmt.Errorf("decode published guard config: %w", err)
	}
	if pol, ok := cfg.APIA2APolicy[appCode]; ok {
		return pol.Version, nil
	}
	return 0, nil
}

// ListForGuard 读取全部应用的 A2A 安全策略并映射为网关冻结契约（实现 guardconfig.A2ALister；key=应用编码）。
func (s *Store) ListForGuard(ctx context.Context) (map[string]*gatewayconfig.GuardA2APolicy, error) {
	rows, err := s.db.Query(ctx, `
SELECT p.application_id, a.code, p.mode, p.version, p.card_discovery_enabled,
	p.a2a_path_prefixes, p.allowed_caller_agents, p.max_delegation_depth,
	p.enforce_scope_attenuation, p.loop_window_seconds, p.max_calls_per_task_window,
	p.lethal_trifecta_enabled, p.confidential_read_patterns, p.external_egress_patterns
FROM api_a2a_policies p
JOIN applications a ON a.id = p.application_id
WHERE a.deleted_at IS NULL
ORDER BY a.code ASC`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	out := map[string]*gatewayconfig.GuardA2APolicy{}
	for rows.Next() {
		var (
			p                                              Policy
			code                                           string
			prefixesRaw, callersRaw, readPatRaw, egressRaw []byte
		)
		if err := rows.Scan(
			&p.ApplicationID, &code, &p.Mode, &p.Version, &p.CardDiscoveryEnabled,
			&prefixesRaw, &callersRaw, &p.MaxDelegationDepth,
			&p.EnforceScopeAttenuation, &p.LoopWindowSeconds, &p.MaxCallsPerTaskWindow,
			&p.LethalTrifectaEnabled, &readPatRaw, &egressRaw,
		); err != nil {
			return nil, err
		}
		if err := decodeStringSlice(prefixesRaw, &p.A2APathPrefixes); err != nil {
			return nil, fmt.Errorf("decode a2a_path_prefixes for %s: %w", code, err)
		}
		if err := decodeStringSlice(callersRaw, &p.AllowedCallerAgents); err != nil {
			return nil, fmt.Errorf("decode allowed_caller_agents for %s: %w", code, err)
		}
		if err := decodeStringSlice(readPatRaw, &p.ConfidentialReadPatterns); err != nil {
			return nil, fmt.Errorf("decode confidential_read_patterns for %s: %w", code, err)
		}
		if err := decodeStringSlice(egressRaw, &p.ExternalEgressPatterns); err != nil {
			return nil, fmt.Errorf("decode external_egress_patterns for %s: %w", code, err)
		}
		out[code] = toGuardPolicy(&p)
	}
	return out, rows.Err()
}

// toGuardPolicy 将领域策略映射为网关 api_a2a_policy 冻结契约（纯函数）。
func toGuardPolicy(p *Policy) *gatewayconfig.GuardA2APolicy {
	return &gatewayconfig.GuardA2APolicy{
		SchemaVersion:            SchemaVersion,
		ApplicationID:            p.ApplicationID.String(),
		Mode:                     p.Mode,
		Version:                  p.Version,
		CardDiscoveryEnabled:     p.CardDiscoveryEnabled,
		A2APathPrefixes:          cloneStrings(p.A2APathPrefixes),
		AllowedCallerAgents:      cloneStrings(p.AllowedCallerAgents),
		MaxDelegationDepth:       p.MaxDelegationDepth,
		EnforceScopeAttenuation:  p.EnforceScopeAttenuation,
		LoopWindowSeconds:        p.LoopWindowSeconds,
		MaxCallsPerTaskWindow:    p.MaxCallsPerTaskWindow,
		LethalTrifectaEnabled:    p.LethalTrifectaEnabled,
		ConfidentialReadPatterns: cloneStrings(p.ConfidentialReadPatterns),
		ExternalEgressPatterns:   cloneStrings(p.ExternalEgressPatterns),
	}
}

// ---------- Agent 物料清单（AgBOM） ----------

const agentSelectColumns = `g.id, g.application_id, COALESCE(a.code, ''), COALESCE(a.name, ''),
	g.agent_name, g.agent_url, g.agent_version, g.status, g.description,
	g.skills, g.allowed_skills, g.auth_schemes,
	g.first_seen_at, g.last_seen_at, g.observed_count, g.created_at, g.updated_at`

func scanAgent(row pgx.Row) (*Agent, error) {
	var (
		ag                                 Agent
		skillsRaw, allowedRaw, schemesRaw  []byte
	)
	err := row.Scan(
		&ag.ID, &ag.ApplicationID, &ag.ApplicationCode, &ag.ApplicationName,
		&ag.AgentName, &ag.AgentURL, &ag.AgentVersion, &ag.Status, &ag.Description,
		&skillsRaw, &allowedRaw, &schemesRaw,
		&ag.FirstSeenAt, &ag.LastSeenAt, &ag.ObservedCount, &ag.CreatedAt, &ag.UpdatedAt,
	)
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return nil, ErrNotFound
		}
		return nil, err
	}
	if err := decodeStringSlice(skillsRaw, &ag.Skills); err != nil {
		return nil, fmt.Errorf("decode skills: %w", err)
	}
	if err := decodeStringSlice(allowedRaw, &ag.AllowedSkills); err != nil {
		return nil, fmt.Errorf("decode allowed_skills: %w", err)
	}
	if err := decodeStringSlice(schemesRaw, &ag.AuthSchemes); err != nil {
		return nil, fmt.Errorf("decode auth_schemes: %w", err)
	}
	return &ag, nil
}

// ListAgents 分页查询 Agent 物料清单（AgBOM）。
func (s *Store) ListAgents(ctx context.Context, f AgentFilter) ([]Agent, int64, error) {
	page, pageSize := normalizePage(f.Page, f.PageSize)
	where, args := buildAgentWhere(f)

	var total int64
	if err := s.db.QueryRow(ctx, `SELECT COUNT(*) FROM api_a2a_agents g `+where, args...).Scan(&total); err != nil {
		return nil, 0, err
	}

	limitIdx := len(args) + 1
	offsetIdx := len(args) + 2
	queryArgs := append(append([]any{}, args...), pageSize, (page-1)*pageSize)
	rows, err := s.db.Query(ctx, `
SELECT `+agentSelectColumns+`
FROM api_a2a_agents g
LEFT JOIN applications a ON a.id = g.application_id
`+where+`
ORDER BY g.last_seen_at DESC, g.created_at DESC, g.id DESC
LIMIT $`+fmt.Sprint(limitIdx)+` OFFSET $`+fmt.Sprint(offsetIdx), queryArgs...)
	if err != nil {
		return nil, 0, err
	}
	defer rows.Close()

	items := []Agent{}
	for rows.Next() {
		item, err := scanAgent(rows)
		if err != nil {
			return nil, 0, err
		}
		items = append(items, *item)
	}
	return items, total, rows.Err()
}

func buildAgentWhere(f AgentFilter) (string, []any) {
	conds := []string{}
	args := []any{}
	if f.ApplicationID != nil {
		args = append(args, *f.ApplicationID)
		conds = append(conds, fmt.Sprintf("g.application_id = $%d", len(args)))
	}
	if f.Status != "" {
		args = append(args, f.Status)
		conds = append(conds, fmt.Sprintf("g.status = $%d", len(args)))
	}
	if kw := strings.TrimSpace(f.Keyword); kw != "" {
		args = append(args, "%"+escapeLike(kw)+"%")
		idx := len(args)
		conds = append(conds, fmt.Sprintf(
			"(g.agent_name ILIKE $%d ESCAPE '\\' OR g.agent_url ILIKE $%d ESCAPE '\\' OR g.description ILIKE $%d ESCAPE '\\' OR g.agent_version ILIKE $%d ESCAPE '\\')",
			idx, idx, idx, idx))
	}
	if len(conds) == 0 {
		return "", args
	}
	return "WHERE " + strings.Join(conds, " AND "), args
}

// GetAgent 按 ID 查询单条 Agent 记录。
func (s *Store) GetAgent(ctx context.Context, id uuid.UUID) (*Agent, error) {
	row := s.db.QueryRow(ctx, `
SELECT `+agentSelectColumns+`
FROM api_a2a_agents g
LEFT JOIN applications a ON a.id = g.application_id
WHERE g.id = $1`, id)
	return scanAgent(row)
}

// CreateAgent 人工登记 Agent（重复 (application_id, agent_name, agent_url) 返回 ErrConflict）。
func (s *Store) CreateAgent(ctx context.Context, ag *Agent) error {
	if errs := ValidateCreateAgent(ag); len(errs) > 0 {
		return &ValidationError{Errors: errs}
	}
	skillsJSON, err := json.Marshal(nonNilSlice(ag.Skills))
	if err != nil {
		return err
	}
	allowedJSON, err := json.Marshal(nonNilSlice(ag.AllowedSkills))
	if err != nil {
		return err
	}
	schemesJSON, err := json.Marshal(nonNilSlice(ag.AuthSchemes))
	if err != nil {
		return err
	}
	var newID uuid.UUID
	err = s.db.QueryRow(ctx, `
INSERT INTO api_a2a_agents (
	application_id, agent_name, agent_url, agent_version, status, description,
	skills, allowed_skills, auth_schemes, observed_count
) VALUES ($1,$2,$3,$4,$5,$6,$7::jsonb,$8::jsonb,$9::jsonb,0)
RETURNING id`,
		ag.ApplicationID, ag.AgentName, ag.AgentURL, ag.AgentVersion, ag.Status, ag.Description,
		string(skillsJSON), string(allowedJSON), string(schemesJSON),
	).Scan(&newID)
	if err != nil {
		if isUniqueViolation(err) {
			return ErrConflict
		}
		return err
	}
	created, err := s.GetAgent(ctx, newID)
	if err != nil {
		return err
	}
	*ag = *created
	return nil
}

// UpdateAgent 审批/编辑 Agent（状态、描述与允许技能集）。
func (s *Store) UpdateAgent(ctx context.Context, id uuid.UUID, status, description string, allowedSkills []string) (*Agent, error) {
	normAllowed := normalizeStrings(allowedSkills)
	if errs := ValidateUpdateAgent(status, description, normAllowed); len(errs) > 0 {
		return nil, &ValidationError{Errors: errs}
	}
	allowedJSON, err := json.Marshal(nonNilSlice(normAllowed))
	if err != nil {
		return nil, err
	}
	tag, err := s.db.Exec(ctx, `
UPDATE api_a2a_agents
SET status=$1, description=$2, allowed_skills=$3::jsonb, updated_at=now()
WHERE id=$4`,
		status, description, string(allowedJSON), id)
	if err != nil {
		return nil, err
	}
	if tag.RowsAffected() == 0 {
		return nil, ErrNotFound
	}
	return s.GetAgent(ctx, id)
}

// DeleteAgent 删除 Agent 资产记录。
func (s *Store) DeleteAgent(ctx context.Context, id uuid.UUID) error {
	tag, err := s.db.Exec(ctx, `DELETE FROM api_a2a_agents WHERE id = $1`, id)
	if err != nil {
		return err
	}
	if tag.RowsAffected() == 0 {
		return ErrNotFound
	}
	return nil
}

// ---------- A2A 安全事件查询 ----------

const eventSelectColumns = `e.id, e.application_id, COALESCE(a.code, ''), COALESCE(a.name, ''),
	e.request_id, e.occurred_at, e.event_type, e.method, e.agent_name,
	e.delegation_depth, e.rule_id, e.action_taken, e.reason, e.client_ip, e.created_at`

func scanEvent(row pgx.Row) (*Event, error) {
	var e Event
	err := row.Scan(
		&e.ID, &e.ApplicationID, &e.ApplicationCode, &e.ApplicationName,
		&e.RequestID, &e.OccurredAt, &e.EventType, &e.Method, &e.AgentName,
		&e.DelegationDepth, &e.RuleID, &e.ActionTaken, &e.Reason, &e.ClientIP, &e.CreatedAt,
	)
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return nil, ErrNotFound
		}
		return nil, err
	}
	return &e, nil
}

// ListEvents 分页查询 A2A 安全事件。
func (s *Store) ListEvents(ctx context.Context, f EventFilter) ([]Event, int64, error) {
	page, pageSize := normalizePage(f.Page, f.PageSize)
	where, args := buildEventWhere(f)

	var total int64
	if err := s.db.QueryRow(ctx, `SELECT COUNT(*) FROM api_a2a_events e `+where, args...).Scan(&total); err != nil {
		return nil, 0, err
	}

	limitIdx := len(args) + 1
	offsetIdx := len(args) + 2
	queryArgs := append(append([]any{}, args...), pageSize, (page-1)*pageSize)
	rows, err := s.db.Query(ctx, `
SELECT `+eventSelectColumns+`
FROM api_a2a_events e
LEFT JOIN applications a ON a.id = e.application_id
`+where+`
ORDER BY e.occurred_at DESC, e.id DESC
LIMIT $`+fmt.Sprint(limitIdx)+` OFFSET $`+fmt.Sprint(offsetIdx), queryArgs...)
	if err != nil {
		return nil, 0, err
	}
	defer rows.Close()

	items := []Event{}
	for rows.Next() {
		item, err := scanEvent(rows)
		if err != nil {
			return nil, 0, err
		}
		items = append(items, *item)
	}
	return items, total, rows.Err()
}

func buildEventWhere(f EventFilter) (string, []any) {
	conds := []string{}
	args := []any{}
	if f.ApplicationID != nil {
		args = append(args, *f.ApplicationID)
		conds = append(conds, fmt.Sprintf("e.application_id = $%d", len(args)))
	}
	if f.EventType != "" {
		args = append(args, f.EventType)
		conds = append(conds, fmt.Sprintf("e.event_type = $%d", len(args)))
	}
	if f.RuleID != "" {
		args = append(args, f.RuleID)
		conds = append(conds, fmt.Sprintf("e.rule_id = $%d", len(args)))
	}
	if len(conds) == 0 {
		return "", args
	}
	return "WHERE " + strings.Join(conds, " AND "), args
}

// ---------- 网关 A2A_* 事件消费（accesscontrolevents.A2AIngester） ----------

// upsertDiscoveredAgentSQL 发现事件回流 AgBOM：
// 冲突时仅更新 last_seen_at / first_seen_at / observed_count+1 / skills / auth_schemes / agent_version，
// 绝不覆盖管理员审批后的 status（APPROVED/BLOCKED）、description 或 allowed_skills！
const upsertDiscoveredAgentSQL = `
INSERT INTO api_a2a_agents (
	application_id, agent_name, agent_url, agent_version, status,
	skills, auth_schemes, first_seen_at, last_seen_at, observed_count
) VALUES ($1, $2, $3, $4, 'DISCOVERED', $5::jsonb, $6::jsonb, $7, $7, 1)
ON CONFLICT (application_id, agent_name, agent_url) DO UPDATE SET
	agent_version  = CASE WHEN EXCLUDED.agent_version <> '' THEN EXCLUDED.agent_version ELSE api_a2a_agents.agent_version END,
	skills         = CASE WHEN jsonb_array_length(EXCLUDED.skills) > 0 THEN EXCLUDED.skills ELSE api_a2a_agents.skills END,
	auth_schemes   = CASE WHEN jsonb_array_length(EXCLUDED.auth_schemes) > 0 THEN EXCLUDED.auth_schemes ELSE api_a2a_agents.auth_schemes END,
	first_seen_at  = LEAST(api_a2a_agents.first_seen_at, EXCLUDED.first_seen_at),
	last_seen_at   = GREATEST(api_a2a_agents.last_seen_at, EXCLUDED.last_seen_at),
	observed_count = api_a2a_agents.observed_count + 1,
	updated_at     = now()`

const insertA2AEventSQL = `
INSERT INTO api_a2a_events (
	application_id, request_id, occurred_at, event_type, method,
	agent_name, delegation_depth, rule_id, action_taken, reason, client_ip
) VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11)`

// IngestEvent 消费网关采集到的 A2A_* 访问控制事件：
//   - A2A_AGENT_CARD_DISCOVERED → UPSERT api_a2a_agents（绝不覆盖 APPROVED/BLOCKED 状态及管理员 description/allowed_skills）；
//   - A2A_OBSERVED / A2A_BLOCKED / A2A_LOOP_KILLED / A2A_LETHAL_TRIFECTA → INSERT api_a2a_events。
func (s *Store) IngestEvent(ctx context.Context, ev *accesscontrolevents.Event) error {
	if s == nil || s.exec == nil || ev == nil {
		return nil
	}
	if ev.ApplicationID == nil || *ev.ApplicationID == uuid.Nil {
		return nil
	}
	appID := *ev.ApplicationID
	occurredAt := ev.OccurredAt.UTC()
	if occurredAt.IsZero() {
		occurredAt = time.Now().UTC()
	}

	detail := extractA2ADetail(ev)
	switch ev.EventType {
	case accesscontrolevents.EventTypeA2AAgentCardDiscovered:
		agentName := trimMax(detailString(detail, "agent_name"), MaxAgBOMAgentNameLen)
		if agentName == "" {
			return nil
		}
		agentURL := trimMax(detailString(detail, "agent_url"), MaxAgentURLLen)
		agentVersion := trimMax(detailString(detail, "agent_version"), MaxAgentVersionLen)
		skills := clampStrings(detailStrings(detail, "skills"), 32, MaxSkillLen)
		authSchemes := clampStrings(detailStrings(detail, "auth_schemes"), 16, MaxAuthSchemeLen)
		skillsJSON, err := json.Marshal(skills)
		if err != nil {
			return err
		}
		schemesJSON, err := json.Marshal(authSchemes)
		if err != nil {
			return err
		}
		_, err = s.exec.Exec(ctx, upsertDiscoveredAgentSQL,
			appID, agentName, agentURL, agentVersion, string(skillsJSON), string(schemesJSON), occurredAt)
		return err

	case accesscontrolevents.EventTypeA2AObserved,
		accesscontrolevents.EventTypeA2ABlocked,
		accesscontrolevents.EventTypeA2ALoopKilled,
		accesscontrolevents.EventTypeA2ALethalTrifecta:
		method := trimMax(detailString(detail, "method"), 128)
		agentName := trimMax(detailString(detail, "agent_name"), MaxAgBOMAgentNameLen)
		delegationDepth := detailInt(detail, "delegation_depth")
		ruleID := trimMax(detailString(detail, "rule_id"), 128)
		actionTaken := trimMax(detailString(detail, "action_taken"), 32)
		if actionTaken == "" {
			actionTaken = trimMax(ev.Action, 32)
		}
		reason := trimMax(detailString(detail, "reason"), 512)
		if reason == "" {
			reason = trimMax(ev.Message, 512)
		}
		_, err := s.exec.Exec(ctx, insertA2AEventSQL,
			appID, trimMax(ev.RequestID, 128), occurredAt, trimMax(ev.EventType, 64), method,
			agentName, delegationDepth, ruleID, actionTaken, reason, trimMax(ev.ClientIP, 64))
		return err

	default:
		return nil
	}
}

func extractA2ADetail(ev *accesscontrolevents.Event) map[string]interface{} {
	if ev == nil || ev.Details == nil {
		return nil
	}
	raw, ok := ev.Details["a2a"]
	if !ok || raw == nil {
		return nil
	}
	m, ok := raw.(map[string]interface{})
	if !ok {
		return nil
	}
	return m
}

func detailString(m map[string]interface{}, key string) string {
	if m == nil {
		return ""
	}
	if s, ok := m[key].(string); ok {
		return strings.TrimSpace(s)
	}
	return ""
}

func detailInt(m map[string]interface{}, key string) int {
	if m == nil {
		return 0
	}
	switch v := m[key].(type) {
	case int:
		return v
	case int64:
		return int(v)
	case float64:
		return int(v)
	case json.Number:
		if n, err := v.Int64(); err == nil {
			return int(n)
		}
	}
	return 0
}

func detailStrings(m map[string]interface{}, key string) []string {
	if m == nil {
		return nil
	}
	switch v := m[key].(type) {
	case []string:
		return v
	case []interface{}:
		out := make([]string, 0, len(v))
		for _, item := range v {
			if s, ok := item.(string); ok {
				out = append(out, s)
			}
		}
		return out
	}
	return nil
}

func clampStrings(in []string, maxItems, maxItemLen int) []string {
	out := make([]string, 0, len(in))
	seen := map[string]bool{}
	for _, s := range in {
		s = trimMax(s, maxItemLen)
		if s == "" || seen[s] {
			continue
		}
		seen[s] = true
		out = append(out, s)
		if len(out) >= maxItems {
			break
		}
	}
	return out
}

func trimMax(s string, n int) string {
	s = strings.TrimSpace(s)
	if len(s) > n {
		return s[:n]
	}
	return s
}

func normalizePage(page, pageSize int) (int, int) {
	if page <= 0 {
		page = 1
	}
	if pageSize <= 0 {
		pageSize = 20
	}
	if pageSize > 200 {
		pageSize = 200
	}
	return page, pageSize
}

func nonNilSlice(in []string) []string {
	if in == nil {
		return []string{}
	}
	return in
}

func cloneStrings(in []string) []string {
	if len(in) == 0 {
		return []string{}
	}
	out := make([]string, len(in))
	copy(out, in)
	return out
}

func escapeLike(s string) string {
	s = strings.ReplaceAll(s, `\`, `\\`)
	s = strings.ReplaceAll(s, `%`, `\%`)
	s = strings.ReplaceAll(s, `_`, `\_`)
	return s
}

func isUniqueViolation(err error) bool {
	var iface interface{ SQLState() string }
	if errors.As(err, &iface) {
		return iface.SQLState() == "23505"
	}
	return false
}

// store.go 客户端供应链安全仓储：client_side_policies、client_side_policy_versions、
// client_script_inventory 与 client_side_violations（迁移 000246）。
// 实现 guardconfig.ClientSideLister 与 accesscontrolevents.ClientSideIngester 接口。
package clientside

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
var ErrNotFound = errors.New("client side resource not found")

// ErrConflict 版本冲突或脚本唯一约束冲突。
var ErrConflict = errors.New("client side resource conflict")

// sqlExecer 最小 SQL 执行接口（*pgxpool.Pool 实现，便于单测注入内存桩验证 IngestEvent SQL 与参数）。
type sqlExecer interface {
	Exec(ctx context.Context, sql string, arguments ...any) (pgconn.CommandTag, error)
}

// Repository 定义处理器所需的仓储接口（*Store 实现，单测可注入内存桩）。
type Repository interface {
	GetPolicyByApp(ctx context.Context, appID uuid.UUID) (*Policy, error)
	SavePolicyDraft(ctx context.Context, p *Policy, expectedVersion int, reason, updatedBy string) error
	PublishedVersion(ctx context.Context, appCode string) (int, error)
	ListScripts(ctx context.Context, f ScriptFilter) ([]Script, int64, error)
	GetScript(ctx context.Context, id uuid.UUID) (*Script, error)
	CreateScript(ctx context.Context, s *Script) error
	UpdateScript(ctx context.Context, id uuid.UUID, sriHash, status, justification, approvedBy string, approvedAt *time.Time) (*Script, error)
	DeleteScript(ctx context.Context, id uuid.UUID) error
	ListViolations(ctx context.Context, f ViolationFilter) ([]Violation, int64, error)
	GetViolation(ctx context.Context, id uuid.UUID) (*Violation, error)
	UpdateViolationStatus(ctx context.Context, id uuid.UUID, status, note, handledBy string, handledAt time.Time) (*Violation, error)
	ExportComplianceData(ctx context.Context, appID *uuid.UUID) ([]Script, []Violation, ViolationSummary, error)
}

// Store 是客户端供应链安全仓储。
type Store struct {
	db   *pgxpool.Pool
	exec sqlExecer
}

// NewStore 创建仓储。
func NewStore(db *pgxpool.Pool) *Store {
	return &Store{db: db, exec: db}
}

// ---------- 应用级客户端供应链安全策略 ----------

const policyColumns = `id, application_id, mode, version, csp_mode, sensitive_paths,
	probe_enabled, strip_unauthorized_scripts, allowed_script_origins,
	allowed_connect_origins, allowed_form_origins, custom_csp_directives,
	updated_by, created_at, updated_at`

func scanPolicy(row pgx.Row) (*Policy, error) {
	var (
		p                                               Policy
		pathsRaw, scriptOrigRaw, connOrigRaw, formOrigRaw []byte
		updatedBy                                       *string
	)
	err := row.Scan(
		&p.ID, &p.ApplicationID, &p.Mode, &p.Version, &p.CSPMode, &pathsRaw,
		&p.ProbeEnabled, &p.StripUnauthorizedScripts, &scriptOrigRaw,
		&connOrigRaw, &formOrigRaw, &p.CustomCSPDirectives,
		&updatedBy, &p.CreatedAt, &p.UpdatedAt,
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
	if err := decodeStringSlice(pathsRaw, &p.SensitivePaths); err != nil {
		return nil, fmt.Errorf("decode sensitive_paths: %w", err)
	}
	if err := decodeStringSlice(scriptOrigRaw, &p.AllowedScriptOrigins); err != nil {
		return nil, fmt.Errorf("decode allowed_script_origins: %w", err)
	}
	if err := decodeStringSlice(connOrigRaw, &p.AllowedConnectOrigins); err != nil {
		return nil, fmt.Errorf("decode allowed_connect_origins: %w", err)
	}
	if err := decodeStringSlice(formOrigRaw, &p.AllowedFormOrigins); err != nil {
		return nil, fmt.Errorf("decode allowed_form_origins: %w", err)
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

// GetPolicyByApp 读取应用当前客户端供应链安全策略草稿；无记录返回 ErrNotFound。
func (s *Store) GetPolicyByApp(ctx context.Context, appID uuid.UUID) (*Policy, error) {
	row := s.db.QueryRow(ctx, `SELECT `+policyColumns+` FROM client_side_policies WHERE application_id = $1`, appID)
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
	pathsJSON, err := json.Marshal(nonNilSlice(p.SensitivePaths))
	if err != nil {
		return err
	}
	scriptOrigJSON, err := json.Marshal(nonNilSlice(p.AllowedScriptOrigins))
	if err != nil {
		return err
	}
	connOrigJSON, err := json.Marshal(nonNilSlice(p.AllowedConnectOrigins))
	if err != nil {
		return err
	}
	formOrigJSON, err := json.Marshal(nonNilSlice(p.AllowedFormOrigins))
	if err != nil {
		return err
	}
	snapshotJSON, err := json.Marshal(map[string]interface{}{
		"mode":                       p.Mode,
		"csp_mode":                   p.CSPMode,
		"sensitive_paths":            nonNilSlice(p.SensitivePaths),
		"probe_enabled":              p.ProbeEnabled,
		"strip_unauthorized_scripts": p.StripUnauthorizedScripts,
		"allowed_script_origins":     nonNilSlice(p.AllowedScriptOrigins),
		"allowed_connect_origins":    nonNilSlice(p.AllowedConnectOrigins),
		"allowed_form_origins":       nonNilSlice(p.AllowedFormOrigins),
		"custom_csp_directives":      p.CustomCSPDirectives,
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
INSERT INTO client_side_policies (
	application_id, mode, version, csp_mode, sensitive_paths,
	probe_enabled, strip_unauthorized_scripts, allowed_script_origins,
	allowed_connect_origins, allowed_form_origins, custom_csp_directives, updated_by
) VALUES ($1,$2,1,$3,$4::jsonb,$5,$6,$7::jsonb,$8::jsonb,$9::jsonb,$10,$11)
RETURNING id, version`,
			p.ApplicationID, p.Mode, p.CSPMode, string(pathsJSON),
			p.ProbeEnabled, p.StripUnauthorizedScripts, string(scriptOrigJSON),
			string(connOrigJSON), string(formOrigJSON), p.CustomCSPDirectives, updatedBy,
		).Scan(&p.ID, &newVersion)
		if err != nil {
			if isUniqueViolation(err) {
				return ErrConflict
			}
			return err
		}
	} else {
		err = tx.QueryRow(ctx, `
UPDATE client_side_policies SET
	mode=$1, csp_mode=$2, sensitive_paths=$3::jsonb,
	probe_enabled=$4, strip_unauthorized_scripts=$5,
	allowed_script_origins=$6::jsonb, allowed_connect_origins=$7::jsonb,
	allowed_form_origins=$8::jsonb, custom_csp_directives=$9,
	updated_by=$10, updated_at=now(), version=version+1
WHERE application_id=$11 AND version=$12
RETURNING id, version`,
			p.Mode, p.CSPMode, string(pathsJSON),
			p.ProbeEnabled, p.StripUnauthorizedScripts,
			string(scriptOrigJSON), string(connOrigJSON),
			string(formOrigJSON), p.CustomCSPDirectives,
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
INSERT INTO client_side_policy_versions (
	application_id, version, mode, csp_mode, policy_snapshot, reason, created_by
) VALUES ($1,$2,$3,$4,$5::jsonb,$6,$7)`,
		p.ApplicationID, newVersion, p.Mode, p.CSPMode, string(snapshotJSON), reason, updatedBy,
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

// PublishedVersion 读取最近 SUCCESS 访问控制发布快照中本应用的客户端供应链安全策略版本。
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
		ClientSidePolicy map[string]struct {
			Version int `json:"version"`
		} `json:"client_side_policy"`
	}
	if err := json.Unmarshal(raw, &cfg); err != nil {
		return 0, fmt.Errorf("decode published guard config: %w", err)
	}
	if pol, ok := cfg.ClientSidePolicy[appCode]; ok {
		return pol.Version, nil
	}
	return 0, nil
}

// ListForGuard 读取全部应用客户端供应链安全策略及已授权/已封禁脚本清单，映射为网关下发冻结契约
// （实现 guardconfig.ClientSideLister 接口；key 为应用编码）。
func (s *Store) ListForGuard(ctx context.Context) (map[string]*gatewayconfig.GuardClientSidePolicy, error) {
	// 1. 读取已授权与已封禁脚本清单（按 app_code + script_url + script_type 稳定排序，确保 api_policy_version 确定性）
	scriptRows, err := s.db.Query(ctx, `
SELECT a.code, s.script_url, s.script_type, s.sri_hash, s.status
FROM client_script_inventory s
JOIN applications a ON a.id = s.application_id
WHERE a.deleted_at IS NULL AND s.status IN ('AUTHORIZED', 'BLOCKED')
ORDER BY a.code ASC, s.script_url ASC, s.script_type ASC`)
	if err != nil {
		return nil, fmt.Errorf("list client scripts for guard: %w", err)
	}
	defer scriptRows.Close()

	scriptsByCode := map[string][]Script{}
	for scriptRows.Next() {
		var (
			code string
			item Script
		)
		if err := scriptRows.Scan(&code, &item.ScriptURL, &item.ScriptType, &item.SRIHash, &item.Status); err != nil {
			return nil, err
		}
		scriptsByCode[code] = append(scriptsByCode[code], item)
	}
	if err := scriptRows.Err(); err != nil {
		return nil, err
	}

	// 2. 读取应用级客户端供应链策略
	rows, err := s.db.Query(ctx, `
SELECT p.application_id, a.code, p.mode, p.version, p.csp_mode, p.sensitive_paths,
	p.probe_enabled, p.strip_unauthorized_scripts, p.allowed_script_origins,
	p.allowed_connect_origins, p.allowed_form_origins, p.custom_csp_directives
FROM client_side_policies p
JOIN applications a ON a.id = p.application_id
WHERE a.deleted_at IS NULL
ORDER BY a.code ASC`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	out := map[string]*gatewayconfig.GuardClientSidePolicy{}
	for rows.Next() {
		var (
			p                                                 Policy
			code                                              string
			pathsRaw, scriptOrigRaw, connOrigRaw, formOrigRaw []byte
		)
		if err := rows.Scan(
			&p.ApplicationID, &code, &p.Mode, &p.Version, &p.CSPMode, &pathsRaw,
			&p.ProbeEnabled, &p.StripUnauthorizedScripts, &scriptOrigRaw,
			&connOrigRaw, &formOrigRaw, &p.CustomCSPDirectives,
		); err != nil {
			return nil, err
		}
		if err := decodeStringSlice(pathsRaw, &p.SensitivePaths); err != nil {
			return nil, fmt.Errorf("decode sensitive_paths for %s: %w", code, err)
		}
		if err := decodeStringSlice(scriptOrigRaw, &p.AllowedScriptOrigins); err != nil {
			return nil, fmt.Errorf("decode allowed_script_origins for %s: %w", code, err)
		}
		if err := decodeStringSlice(connOrigRaw, &p.AllowedConnectOrigins); err != nil {
			return nil, fmt.Errorf("decode allowed_connect_origins for %s: %w", code, err)
		}
		if err := decodeStringSlice(formOrigRaw, &p.AllowedFormOrigins); err != nil {
			return nil, fmt.Errorf("decode allowed_form_origins for %s: %w", code, err)
		}
		out[code] = toGuardPolicy(&p, scriptsByCode[code])
	}
	return out, rows.Err()
}

// toGuardPolicy 将领域策略与脚本台账映射为网关冻结契约（纯函数，仅包含 AUTHORIZED 与 BLOCKED）。
func toGuardPolicy(p *Policy, scripts []Script) *gatewayconfig.GuardClientSidePolicy {
	gp := &gatewayconfig.GuardClientSidePolicy{
		SchemaVersion:            SchemaVersion,
		ApplicationID:            p.ApplicationID.String(),
		Mode:                     p.Mode,
		Version:                  p.Version,
		CSPMode:                  p.CSPMode,
		SensitivePaths:           cloneStrings(p.SensitivePaths),
		ProbeEnabled:             p.ProbeEnabled,
		StripUnauthorizedScripts: p.StripUnauthorizedScripts,
		AllowedScriptOrigins:     cloneStrings(p.AllowedScriptOrigins),
		AllowedConnectOrigins:    cloneStrings(p.AllowedConnectOrigins),
		AllowedFormOrigins:       cloneStrings(p.AllowedFormOrigins),
		CustomCSPDirectives:      p.CustomCSPDirectives,
		AuthorizedScripts:        make([]gatewayconfig.GuardClientSideScript, 0, len(scripts)),
	}
	for _, sc := range scripts {
		if sc.Status != ScriptStatusAuthorized && sc.Status != ScriptStatusBlocked {
			continue
		}
		gp.AuthorizedScripts = append(gp.AuthorizedScripts, gatewayconfig.GuardClientSideScript{
			ScriptURL:  sc.ScriptURL,
			ScriptType: sc.ScriptType,
			SRIHash:    sc.SRIHash,
			Status:     sc.Status,
		})
	}
	return gp
}

// ---------- 脚本资产清单（PCI DSS 4.0 6.4.3） ----------

const scriptSelectColumns = `s.id, s.application_id, COALESCE(a.code, ''), COALESCE(a.name, ''),
	s.script_url, s.script_origin, s.script_type, s.sri_hash, s.observed_sri, s.status,
	s.justification, s.approved_by, s.approved_at, s.sample_page_path,
	s.first_seen_at, s.last_seen_at, s.observed_count, s.created_at, s.updated_at`

func scanScript(row pgx.Row) (*Script, error) {
	var s Script
	err := row.Scan(
		&s.ID, &s.ApplicationID, &s.ApplicationCode, &s.ApplicationName,
		&s.ScriptURL, &s.ScriptOrigin, &s.ScriptType, &s.SRIHash, &s.ObservedSRI, &s.Status,
		&s.Justification, &s.ApprovedBy, &s.ApprovedAt, &s.SamplePagePath,
		&s.FirstSeenAt, &s.LastSeenAt, &s.ObservedCount, &s.CreatedAt, &s.UpdatedAt,
	)
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return nil, ErrNotFound
		}
		return nil, err
	}
	return &s, nil
}

// ListScripts 分页查询脚本资产清单。
func (s *Store) ListScripts(ctx context.Context, f ScriptFilter) ([]Script, int64, error) {
	page, pageSize := normalizePage(f.Page, f.PageSize)
	where, args := buildScriptWhere(f)

	var total int64
	if err := s.db.QueryRow(ctx, `SELECT COUNT(*) FROM client_script_inventory s `+where, args...).Scan(&total); err != nil {
		return nil, 0, err
	}

	limitIdx := len(args) + 1
	offsetIdx := len(args) + 2
	queryArgs := append(append([]any{}, args...), pageSize, (page-1)*pageSize)
	rows, err := s.db.Query(ctx, `
SELECT `+scriptSelectColumns+`
FROM client_script_inventory s
LEFT JOIN applications a ON a.id = s.application_id
`+where+`
ORDER BY s.last_seen_at DESC, s.created_at DESC, s.id DESC
LIMIT $`+fmt.Sprint(limitIdx)+` OFFSET $`+fmt.Sprint(offsetIdx), queryArgs...)
	if err != nil {
		return nil, 0, err
	}
	defer rows.Close()

	items := []Script{}
	for rows.Next() {
		item, err := scanScript(rows)
		if err != nil {
			return nil, 0, err
		}
		items = append(items, *item)
	}
	return items, total, rows.Err()
}

func buildScriptWhere(f ScriptFilter) (string, []any) {
	conds := []string{}
	args := []any{}
	if f.ApplicationID != nil {
		args = append(args, *f.ApplicationID)
		conds = append(conds, fmt.Sprintf("s.application_id = $%d", len(args)))
	}
	if f.Status != "" {
		args = append(args, f.Status)
		conds = append(conds, fmt.Sprintf("s.status = $%d", len(args)))
	}
	if kw := strings.TrimSpace(f.Keyword); kw != "" {
		args = append(args, "%"+escapeLike(kw)+"%")
		idx := len(args)
		conds = append(conds, fmt.Sprintf(
			"(s.script_url ILIKE $%d ESCAPE '\\' OR s.script_origin ILIKE $%d ESCAPE '\\' OR s.justification ILIKE $%d ESCAPE '\\' OR s.sample_page_path ILIKE $%d ESCAPE '\\')",
			idx, idx, idx, idx))
	}
	if len(conds) == 0 {
		return "", args
	}
	return "WHERE " + strings.Join(conds, " AND "), args
}

// GetScript 按 ID 查询单条脚本资产。
func (s *Store) GetScript(ctx context.Context, id uuid.UUID) (*Script, error) {
	row := s.db.QueryRow(ctx, `
SELECT `+scriptSelectColumns+`
FROM client_script_inventory s
LEFT JOIN applications a ON a.id = s.application_id
WHERE s.id = $1`, id)
	return scanScript(row)
}

// CreateScript 新增预授权/封禁/待审脚本资产（重复键返回 ErrConflict）。
func (s *Store) CreateScript(ctx context.Context, sc *Script) error {
	if errs := ValidateCreateScript(sc); len(errs) > 0 {
		return &ValidationError{Errors: errs}
	}
	var newID uuid.UUID
	err := s.db.QueryRow(ctx, `
INSERT INTO client_script_inventory (
	application_id, script_url, script_origin, script_type,
	sri_hash, observed_sri, status, justification,
	approved_by, approved_at, sample_page_path, observed_count
) VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,0)
RETURNING id`,
		sc.ApplicationID, sc.ScriptURL, sc.ScriptOrigin, sc.ScriptType,
		sc.SRIHash, sc.ObservedSRI, sc.Status, sc.Justification,
		sc.ApprovedBy, sc.ApprovedAt, sc.SamplePagePath,
	).Scan(&newID)
	if err != nil {
		if isUniqueViolation(err) {
			return ErrConflict
		}
		return err
	}
	created, err := s.GetScript(ctx, newID)
	if err != nil {
		return err
	}
	*sc = *created
	return nil
}

// UpdateScript 审批或编辑脚本资产（固定 SRI 哈希、状态与 PCI DSS 6.4.3 业务说明）。
func (s *Store) UpdateScript(ctx context.Context, id uuid.UUID, sriHash, status, justification, approvedBy string, approvedAt *time.Time) (*Script, error) {
	if errs := ValidateUpdateScript(sriHash, status, justification); len(errs) > 0 {
		return nil, &ValidationError{Errors: errs}
	}
	tag, err := s.db.Exec(ctx, `
UPDATE client_script_inventory
SET sri_hash=$1, status=$2, justification=$3, approved_by=$4, approved_at=$5, updated_at=now()
WHERE id=$6`,
		sriHash, status, justification, approvedBy, approvedAt, id)
	if err != nil {
		return nil, err
	}
	if tag.RowsAffected() == 0 {
		return nil, ErrNotFound
	}
	return s.GetScript(ctx, id)
}

// DeleteScript 删除脚本资产记录。
func (s *Store) DeleteScript(ctx context.Context, id uuid.UUID) error {
	tag, err := s.db.Exec(ctx, `DELETE FROM client_script_inventory WHERE id = $1`, id)
	if err != nil {
		return err
	}
	if tag.RowsAffected() == 0 {
		return ErrNotFound
	}
	return nil
}

// ---------- 违规与篡改告警（PCI DSS 4.0 11.6.1） ----------

const violationSelectColumns = `v.id, v.application_id, COALESCE(a.code, ''), COALESCE(a.name, ''),
	v.request_id, v.occurred_at, v.violation_type, v.script_url, v.script_origin,
	v.expected_sri, v.observed_sri, v.page_path, v.violated_directive, v.blocked_uri,
	v.action_taken, v.reason, v.client_ip, v.status, v.note, v.handled_by, v.handled_at, v.created_at`

func scanViolation(row pgx.Row) (*Violation, error) {
	var v Violation
	err := row.Scan(
		&v.ID, &v.ApplicationID, &v.ApplicationCode, &v.ApplicationName,
		&v.RequestID, &v.OccurredAt, &v.ViolationType, &v.ScriptURL, &v.ScriptOrigin,
		&v.ExpectedSRI, &v.ObservedSRI, &v.PagePath, &v.ViolatedDirective, &v.BlockedURI,
		&v.ActionTaken, &v.Reason, &v.ClientIP, &v.Status, &v.Note, &v.HandledBy, &v.HandledAt, &v.CreatedAt,
	)
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return nil, ErrNotFound
		}
		return nil, err
	}
	return &v, nil
}

// ListViolations 分页查询客户端安全违规告警。
func (s *Store) ListViolations(ctx context.Context, f ViolationFilter) ([]Violation, int64, error) {
	page, pageSize := normalizePage(f.Page, f.PageSize)
	where, args := buildViolationWhere(f)

	var total int64
	if err := s.db.QueryRow(ctx, `SELECT COUNT(*) FROM client_side_violations v `+where, args...).Scan(&total); err != nil {
		return nil, 0, err
	}

	limitIdx := len(args) + 1
	offsetIdx := len(args) + 2
	queryArgs := append(append([]any{}, args...), pageSize, (page-1)*pageSize)
	rows, err := s.db.Query(ctx, `
SELECT `+violationSelectColumns+`
FROM client_side_violations v
LEFT JOIN applications a ON a.id = v.application_id
`+where+`
ORDER BY v.occurred_at DESC, v.id DESC
LIMIT $`+fmt.Sprint(limitIdx)+` OFFSET $`+fmt.Sprint(offsetIdx), queryArgs...)
	if err != nil {
		return nil, 0, err
	}
	defer rows.Close()

	items := []Violation{}
	for rows.Next() {
		item, err := scanViolation(rows)
		if err != nil {
			return nil, 0, err
		}
		items = append(items, *item)
	}
	return items, total, rows.Err()
}

func buildViolationWhere(f ViolationFilter) (string, []any) {
	conds := []string{}
	args := []any{}
	if f.ApplicationID != nil {
		args = append(args, *f.ApplicationID)
		conds = append(conds, fmt.Sprintf("v.application_id = $%d", len(args)))
	}
	if f.ViolationType != "" {
		args = append(args, f.ViolationType)
		conds = append(conds, fmt.Sprintf("v.violation_type = $%d", len(args)))
	}
	if f.Status != "" {
		args = append(args, f.Status)
		conds = append(conds, fmt.Sprintf("v.status = $%d", len(args)))
	}
	if len(conds) == 0 {
		return "", args
	}
	return "WHERE " + strings.Join(conds, " AND "), args
}

// GetViolation 按 ID 查询单条违规告警。
func (s *Store) GetViolation(ctx context.Context, id uuid.UUID) (*Violation, error) {
	row := s.db.QueryRow(ctx, `
SELECT `+violationSelectColumns+`
FROM client_side_violations v
LEFT JOIN applications a ON a.id = v.application_id
WHERE v.id = $1`, id)
	return scanViolation(row)
}

// UpdateViolationStatus 更新违规告警处置状态与备注。
func (s *Store) UpdateViolationStatus(ctx context.Context, id uuid.UUID, status, note, handledBy string, handledAt time.Time) (*Violation, error) {
	if errs := ValidateViolationStatusUpdate(status, note); len(errs) > 0 {
		return nil, &ValidationError{Errors: errs}
	}
	tag, err := s.db.Exec(ctx, `
UPDATE client_side_violations
SET status=$1, note=$2, handled_by=$3, handled_at=$4
WHERE id=$5`,
		status, note, handledBy, handledAt.UTC(), id)
	if err != nil {
		return nil, err
	}
	if tag.RowsAffected() == 0 {
		return nil, ErrNotFound
	}
	return s.GetViolation(ctx, id)
}

// ExportComplianceData 读取导出 PCI DSS 4.0 6.4.3 & 11.6.1 合规 CSV 所需的脚本台账与违规明细/摘要。
func (s *Store) ExportComplianceData(ctx context.Context, appID *uuid.UUID) ([]Script, []Violation, ViolationSummary, error) {
	scriptWhere, scriptArgs := buildScriptWhere(ScriptFilter{ApplicationID: appID})
	sRows, err := s.db.Query(ctx, `
SELECT `+scriptSelectColumns+`
FROM client_script_inventory s
LEFT JOIN applications a ON a.id = s.application_id
`+scriptWhere+`
ORDER BY COALESCE(a.code, '') ASC, s.status ASC, s.script_url ASC
LIMIT 10000`, scriptArgs...)
	if err != nil {
		return nil, nil, ViolationSummary{}, err
	}
	defer sRows.Close()
	scripts := []Script{}
	for sRows.Next() {
		item, err := scanScript(sRows)
		if err != nil {
			return nil, nil, ViolationSummary{}, err
		}
		scripts = append(scripts, *item)
	}
	if err := sRows.Err(); err != nil {
		return nil, nil, ViolationSummary{}, err
	}

	violWhere, violArgs := buildViolationWhere(ViolationFilter{ApplicationID: appID})
	vRows, err := s.db.Query(ctx, `
SELECT `+violationSelectColumns+`
FROM client_side_violations v
LEFT JOIN applications a ON a.id = v.application_id
`+violWhere+`
ORDER BY v.occurred_at DESC, v.id DESC
LIMIT 10000`, violArgs...)
	if err != nil {
		return nil, nil, ViolationSummary{}, err
	}
	defer vRows.Close()
	violations := []Violation{}
	for vRows.Next() {
		item, err := scanViolation(vRows)
		if err != nil {
			return nil, nil, ViolationSummary{}, err
		}
		violations = append(violations, *item)
	}
	if err := vRows.Err(); err != nil {
		return nil, nil, ViolationSummary{}, err
	}

	var summary ViolationSummary
	err = s.db.QueryRow(ctx, `
SELECT
	COUNT(*),
	COUNT(*) FILTER (WHERE v.status = 'OPEN'),
	COUNT(*) FILTER (WHERE v.status = 'ACKNOWLEDGED'),
	COUNT(*) FILTER (WHERE v.status = 'RESOLVED'),
	COUNT(*) FILTER (WHERE v.status = 'FALSE_POSITIVE'),
	COUNT(*) FILTER (WHERE v.violation_type = 'UNAUTHORIZED_SCRIPT'),
	COUNT(*) FILTER (WHERE v.violation_type = 'SCRIPT_TAMPERED'),
	COUNT(*) FILTER (WHERE v.violation_type = 'CSP_VIOLATION'),
	COUNT(*) FILTER (WHERE v.violation_type = 'PROBE_ALERT')
FROM client_side_violations v `+violWhere, violArgs...).Scan(
		&summary.Total,
		&summary.Open, &summary.Acknowledged, &summary.Resolved, &summary.FalsePositive,
		&summary.UnauthorizedScript, &summary.ScriptTampered, &summary.CSPViolation, &summary.ProbeAlert,
	)
	if err != nil {
		return nil, nil, ViolationSummary{}, err
	}
	return scripts, violations, summary, nil
}

// ---------- 网关 CLIENT_SIDE_* 事件消费（accesscontrolevents.ClientSideIngester） ----------

const upsertObservedScriptSQL = `
INSERT INTO client_script_inventory (
	application_id, script_url, script_origin, script_type,
	sri_hash, observed_sri, status, sample_page_path,
	first_seen_at, last_seen_at, observed_count
) VALUES ($1, $2, $3, $4, '', $5, 'DISCOVERED', $6, $7, $7, 1)
ON CONFLICT (application_id, script_url, script_type) DO UPDATE SET
	script_origin    = CASE WHEN client_script_inventory.script_origin = '' THEN EXCLUDED.script_origin ELSE client_script_inventory.script_origin END,
	observed_sri     = EXCLUDED.observed_sri,
	sample_page_path = CASE WHEN EXCLUDED.sample_page_path <> '' THEN EXCLUDED.sample_page_path ELSE client_script_inventory.sample_page_path END,
	first_seen_at    = LEAST(client_script_inventory.first_seen_at, EXCLUDED.first_seen_at),
	last_seen_at     = GREATEST(client_script_inventory.last_seen_at, EXCLUDED.last_seen_at),
	observed_count   = client_script_inventory.observed_count + 1,
	updated_at       = now()`

const insertViolationSQL = `
INSERT INTO client_side_violations (
	application_id, request_id, occurred_at, violation_type,
	script_url, script_origin, expected_sri, observed_sri,
	page_path, violated_directive, blocked_uri, action_taken,
	reason, client_ip, status
) VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,$14,'OPEN')`

// IngestEvent 消费网关采集到的 CLIENT_SIDE_* 访问控制事件：
//   - CLIENT_SIDE_SCRIPT_OBSERVED → UPSERT client_script_inventory（冲突时仅更新 last_seen_at / observed_sri / observed_count+1，
//     绝不覆盖已审批的 AUTHORIZED/BLOCKED 状态及固定 sri_hash）；
//   - CLIENT_SIDE_UNAUTHORIZED_SCRIPT / SCRIPT_TAMPERED / CSP_VIOLATION / PROBE_ALERT → INSERT client_side_violations，
//     其中 UNAUTHORIZED_SCRIPT 同步按 DISCOVERED UPSERT 脚本清单（若不存在则新增，已存在绝不覆盖 AUTHORIZED/BLOCKED 或 sri_hash）。
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

	detail := extractClientSideDetail(ev)
	scriptURL := trimMax(detail["script_url"], MaxScriptURLLen)
	scriptType := normalizeIngestScriptType(detail["script_type"], scriptURL)
	scriptOrigin := trimMax(detail["script_origin"], MaxOriginLen)
	if scriptOrigin == "" && scriptURL != "" {
		scriptOrigin = ExtractScriptOrigin(scriptURL, scriptType)
	}
	expectedSRI := trimMax(detail["expected_sri"], MaxSRILen)
	observedSRI := trimMax(detail["observed_sri"], MaxSRILen)
	pagePath := trimMax(detail["page_path"], MaxPathLen)
	if pagePath == "" {
		pagePath = trimMax(ev.RequestPath, MaxPathLen)
	}
	violatedDirective := trimMax(detail["violated_directive"], 128)
	blockedURI := trimMax(detail["blocked_uri"], MaxScriptURLLen)
	actionTaken := trimMax(detail["action_taken"], 32)
	if actionTaken == "" {
		actionTaken = trimMax(ev.Action, 32)
	}
	reason := trimMax(detail["reason"], 512)
	if reason == "" {
		reason = trimMax(ev.Message, 512)
	}

	switch ev.EventType {
	case accesscontrolevents.EventTypeClientSideScriptObserved:
		if scriptURL == "" {
			return nil
		}
		_, err := s.exec.Exec(ctx, upsertObservedScriptSQL,
			appID, scriptURL, scriptOrigin, scriptType, observedSRI, pagePath, occurredAt)
		return err

	case accesscontrolevents.EventTypeClientSideUnauthorizedScript,
		accesscontrolevents.EventTypeClientSideScriptTampered,
		accesscontrolevents.EventTypeClientSideCSPViolation,
		accesscontrolevents.EventTypeClientSideProbeAlert:
		vType := mapEventTypeToViolationType(ev.EventType)
		if _, err := s.exec.Exec(ctx, insertViolationSQL,
			appID, trimMax(ev.RequestID, 128), occurredAt, vType,
			scriptURL, scriptOrigin, expectedSRI, observedSRI,
			pagePath, violatedDirective, blockedURI, actionTaken,
			reason, trimMax(ev.ClientIP, 64),
		); err != nil {
			return err
		}
		if ev.EventType == accesscontrolevents.EventTypeClientSideUnauthorizedScript && scriptURL != "" {
			if _, err := s.exec.Exec(ctx, upsertObservedScriptSQL,
				appID, scriptURL, scriptOrigin, scriptType, observedSRI, pagePath, occurredAt); err != nil {
				return err
			}
		}
		return nil
	default:
		return nil
	}
}

func mapEventTypeToViolationType(eventType string) string {
	switch eventType {
	case accesscontrolevents.EventTypeClientSideUnauthorizedScript:
		return ViolationUnauthorizedScript
	case accesscontrolevents.EventTypeClientSideScriptTampered:
		return ViolationScriptTampered
	case accesscontrolevents.EventTypeClientSideCSPViolation:
		return ViolationCSPViolation
	case accesscontrolevents.EventTypeClientSideProbeAlert:
		return ViolationProbeAlert
	default:
		return ""
	}
}

func extractClientSideDetail(ev *accesscontrolevents.Event) map[string]string {
	out := map[string]string{}
	if ev == nil || ev.Details == nil {
		return out
	}
	raw, ok := ev.Details["client_side"]
	if !ok || raw == nil {
		return out
	}
	m, ok := raw.(map[string]interface{})
	if !ok {
		return out
	}
	for k, v := range m {
		if s, ok := v.(string); ok {
			out[k] = strings.TrimSpace(s)
		}
	}
	return out
}

func normalizeIngestScriptType(rawType, scriptURL string) string {
	t := strings.ToUpper(strings.TrimSpace(rawType))
	if t == ScriptTypeExternal || t == ScriptTypeInlineHash {
		return t
	}
	if strings.HasPrefix(scriptURL, "sha256-") || strings.HasPrefix(scriptURL, "sha384-") ||
		strings.HasPrefix(scriptURL, "sha512-") || strings.HasPrefix(scriptURL, "inline:") {
		return ScriptTypeInlineHash
	}
	return ScriptTypeExternal
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

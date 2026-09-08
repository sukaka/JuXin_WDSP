// Package protectionpolicies 提供WAF防护策略管理。
package protectionpolicies

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/jiuzhang-waf/server/internal/gatewayconfig"
)

// 错误
var (
	ErrNotFound     = errors.New("policy not found")
	ErrCodeExists   = errors.New("policy code already exists")
	ErrInUse        = errors.New("policy is in use by applications")
	ErrBuiltin      = errors.New("builtin policy cannot be modified or deleted")
	ErrInvalidInput = errors.New("invalid policy input")
)

// 防护模式
const (
	ModeOff     = "OFF"
	ModeObserve = "OBSERVE"
	ModeProtect = "PROTECT"
)

// Policy 是WAF防护策略。
type Policy struct {
	ID                       uuid.UUID  `json:"id"`
	Code                     string     `json:"code"`
	Name                     string     `json:"name"`
	Description              string     `json:"description"`
	IsBuiltin                bool       `json:"is_builtin"`
	Status                   string     `json:"status"`
	ProtectionMode           string     `json:"protection_mode"`
	ParanoiaLevel            int        `json:"paranoia_level"`
	InboundAnomalyThreshold  int        `json:"inbound_anomaly_threshold"`
	OutboundAnomalyThreshold int        `json:"outbound_anomaly_threshold"`
	RequestBodyAccess        bool       `json:"request_body_access"`
	ResponseBodyAccess       bool       `json:"response_body_access"`
	RequestBodyLimit         int64      `json:"request_body_limit"`
	RequestBodyNoFilesLimit  int64      `json:"request_body_no_files_limit"`
	ResponseBodyLimit        int64      `json:"response_body_limit"`
	UploadFileLimit          int64      `json:"upload_file_limit"`
	JSONParserEnabled        bool       `json:"json_parser_enabled"`
	XMLParserEnabled         bool       `json:"xml_parser_enabled"`
	MultipartParserEnabled   bool       `json:"multipart_parser_enabled"`
	AuditLogEnabled          bool       `json:"audit_log_enabled"`
	AuditLogRelevantStatus   string     `json:"audit_log_relevant_status"`
	AuditLogParts            string     `json:"audit_log_parts"`
	BlockingStatusCode       int        `json:"blocking_status_code"`
	BlockingPageID           string     `json:"blocking_page_id"`
	CreatedBy                *uuid.UUID `json:"created_by,omitempty"`
	CreatedAt                time.Time  `json:"created_at"`
	UpdatedAt                time.Time  `json:"updated_at"`
	Version                  int        `json:"version"`
}

// Store 是策略仓储。
type Store struct {
	db *pgxpool.Pool
}

// NewStore 创建策略仓储。
func NewStore(db *pgxpool.Pool) *Store {
	return &Store{db: db}
}

const policyColumns = `id, code, name, description, is_builtin, status, protection_mode,
paranoia_level, inbound_anomaly_threshold, outbound_anomaly_threshold,
request_body_access, response_body_access, request_body_limit, request_body_no_files_limit,
response_body_limit, upload_file_limit, json_parser_enabled, xml_parser_enabled,
multipart_parser_enabled, audit_log_enabled, audit_log_relevant_status, audit_log_parts,
blocking_status_code, blocking_page_id, created_by, created_at, updated_at, version`

func (s *Store) scanPolicy(row pgx.Row) (*Policy, error) {
	var p Policy
	err := row.Scan(&p.ID, &p.Code, &p.Name, &p.Description, &p.IsBuiltin, &p.Status,
		&p.ProtectionMode, &p.ParanoiaLevel, &p.InboundAnomalyThreshold, &p.OutboundAnomalyThreshold,
		&p.RequestBodyAccess, &p.ResponseBodyAccess, &p.RequestBodyLimit, &p.RequestBodyNoFilesLimit,
		&p.ResponseBodyLimit, &p.UploadFileLimit, &p.JSONParserEnabled, &p.XMLParserEnabled,
		&p.MultipartParserEnabled, &p.AuditLogEnabled, &p.AuditLogRelevantStatus, &p.AuditLogParts,
		&p.BlockingStatusCode, &p.BlockingPageID, &p.CreatedBy, &p.CreatedAt, &p.UpdatedAt, &p.Version)
	if err != nil {
		return nil, err
	}
	return &p, nil
}

// ValidatePolicy 校验策略字段。
func ValidatePolicy(p *Policy) error {
	if p.Code == "" || len(p.Code) > 64 {
		return fmt.Errorf("%w: 策略编码不能为空且不超过64字符", ErrInvalidInput)
	}
	if p.Name == "" || len(p.Name) > 128 {
		return fmt.Errorf("%w: 策略名称不能为空且不超过128字符", ErrInvalidInput)
	}
	if p.ProtectionMode != ModeOff && p.ProtectionMode != ModeObserve && p.ProtectionMode != ModeProtect {
		return fmt.Errorf("%w: 无效的防护模式", ErrInvalidInput)
	}
	if p.ParanoiaLevel < 1 || p.ParanoiaLevel > 4 {
		return fmt.Errorf("%w: 执行等级必须在1至4之间", ErrInvalidInput)
	}
	if p.InboundAnomalyThreshold < 1 || p.InboundAnomalyThreshold > 100 {
		return fmt.Errorf("%w: 入站异常阈值必须在1至100之间", ErrInvalidInput)
	}
	if p.OutboundAnomalyThreshold < 1 || p.OutboundAnomalyThreshold > 100 {
		return fmt.Errorf("%w: 出站异常阈值必须在1至100之间", ErrInvalidInput)
	}
	if p.RequestBodyLimit < 1024 || p.RequestBodyLimit > 1024*1024*1024 {
		return fmt.Errorf("%w: 请求体限制超出合理范围", ErrInvalidInput)
	}
	if p.BlockingStatusCode < 400 || p.BlockingStatusCode > 599 {
		return fmt.Errorf("%w: 阻断状态码必须在400至599之间", ErrInvalidInput)
	}
	return nil
}

// Create 创建策略。
func (s *Store) Create(ctx context.Context, p *Policy) error {
	if err := ValidatePolicy(p); err != nil {
		return err
	}
	err := s.db.QueryRow(ctx, `
INSERT INTO protection_policies (code, name, description, is_builtin, status, protection_mode,
  paranoia_level, inbound_anomaly_threshold, outbound_anomaly_threshold,
  request_body_access, response_body_access, request_body_limit, request_body_no_files_limit,
  response_body_limit, upload_file_limit, json_parser_enabled, xml_parser_enabled,
  multipart_parser_enabled, audit_log_enabled, audit_log_relevant_status, audit_log_parts,
  blocking_status_code, blocking_page_id, created_by)
VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,$14,$15,$16,$17,$18,$19,$20,$21,$22,$23,$24)
RETURNING id, created_at, updated_at, version`,
		p.Code, p.Name, p.Description, p.IsBuiltin, p.Status, p.ProtectionMode,
		p.ParanoiaLevel, p.InboundAnomalyThreshold, p.OutboundAnomalyThreshold,
		p.RequestBodyAccess, p.ResponseBodyAccess, p.RequestBodyLimit, p.RequestBodyNoFilesLimit,
		p.ResponseBodyLimit, p.UploadFileLimit, p.JSONParserEnabled, p.XMLParserEnabled,
		p.MultipartParserEnabled, p.AuditLogEnabled, p.AuditLogRelevantStatus, p.AuditLogParts,
		p.BlockingStatusCode, p.BlockingPageID, p.CreatedBy,
	).Scan(&p.ID, &p.CreatedAt, &p.UpdatedAt, &p.Version)
	if err != nil {
		if strings.Contains(err.Error(), "idx_protection_policies_code") {
			return ErrCodeExists
		}
		return err
	}
	return nil
}

// GetByID 查询策略。
func (s *Store) GetByID(ctx context.Context, id uuid.UUID) (*Policy, error) {
	row := s.db.QueryRow(ctx, `SELECT `+policyColumns+` FROM protection_policies WHERE id = $1 AND deleted_at IS NULL`, id)
	p, err := s.scanPolicy(row)
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return nil, ErrNotFound
		}
		return nil, err
	}
	return p, nil
}

// GetByCode 按编码查询策略。
func (s *Store) GetByCode(ctx context.Context, code string) (*Policy, error) {
	row := s.db.QueryRow(ctx, `SELECT `+policyColumns+` FROM protection_policies WHERE code = $1 AND deleted_at IS NULL`, code)
	p, err := s.scanPolicy(row)
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return nil, ErrNotFound
		}
		return nil, err
	}
	return p, nil
}

// List 分页查询策略。
func (s *Store) List(ctx context.Context, keyword, mode string, page, pageSize int) ([]Policy, int64, error) {
	if page <= 0 {
		page = 1
	}
	if pageSize <= 0 || pageSize > 100 {
		pageSize = 20
	}
	where := "deleted_at IS NULL"
	args := []interface{}{}
	argIdx := 1
	if keyword != "" {
		where += fmt.Sprintf(" AND (code ILIKE $%d OR name ILIKE $%d)", argIdx, argIdx)
		args = append(args, "%"+keyword+"%")
		argIdx++
	}
	if mode != "" {
		where += fmt.Sprintf(" AND protection_mode = $%d", argIdx)
		args = append(args, mode)
		argIdx++
	}
	var total int64
	if err := s.db.QueryRow(ctx, `SELECT count(*) FROM protection_policies WHERE `+where, args...).Scan(&total); err != nil {
		return nil, 0, err
	}
	query := `SELECT ` + policyColumns + ` FROM protection_policies WHERE ` + where +
		fmt.Sprintf(" ORDER BY is_builtin DESC, created_at DESC LIMIT $%d OFFSET $%d", argIdx, argIdx+1)
	args = append(args, pageSize, (page-1)*pageSize)
	rows, err := s.db.Query(ctx, query, args...)
	if err != nil {
		return nil, 0, err
	}
	defer rows.Close()
	var out []Policy
	for rows.Next() {
		var p Policy
		if err := rows.Scan(&p.ID, &p.Code, &p.Name, &p.Description, &p.IsBuiltin, &p.Status,
			&p.ProtectionMode, &p.ParanoiaLevel, &p.InboundAnomalyThreshold, &p.OutboundAnomalyThreshold,
			&p.RequestBodyAccess, &p.ResponseBodyAccess, &p.RequestBodyLimit, &p.RequestBodyNoFilesLimit,
			&p.ResponseBodyLimit, &p.UploadFileLimit, &p.JSONParserEnabled, &p.XMLParserEnabled,
			&p.MultipartParserEnabled, &p.AuditLogEnabled, &p.AuditLogRelevantStatus, &p.AuditLogParts,
			&p.BlockingStatusCode, &p.BlockingPageID, &p.CreatedBy, &p.CreatedAt, &p.UpdatedAt, &p.Version); err != nil {
			return nil, 0, err
		}
		out = append(out, p)
	}
	return out, total, rows.Err()
}

// Update 更新策略（乐观锁，内置策略不可修改）。
func (s *Store) Update(ctx context.Context, p *Policy) error {
	existing, err := s.GetByID(ctx, p.ID)
	if err != nil {
		return err
	}
	if existing.IsBuiltin {
		return ErrBuiltin
	}
	if err := ValidatePolicy(p); err != nil {
		return err
	}
	res, err := s.db.Exec(ctx, `
UPDATE protection_policies SET name=$1, description=$2, status=$3, protection_mode=$4,
  paranoia_level=$5, inbound_anomaly_threshold=$6, outbound_anomaly_threshold=$7,
  request_body_access=$8, response_body_access=$9, request_body_limit=$10,
  request_body_no_files_limit=$11, response_body_limit=$12, upload_file_limit=$13,
  json_parser_enabled=$14, xml_parser_enabled=$15, multipart_parser_enabled=$16,
  audit_log_enabled=$17, audit_log_relevant_status=$18, audit_log_parts=$19,
  blocking_status_code=$20, blocking_page_id=$21, updated_at=now(), version=version+1
WHERE id=$22 AND version=$23 AND deleted_at IS NULL`,
		p.Name, p.Description, p.Status, p.ProtectionMode, p.ParanoiaLevel,
		p.InboundAnomalyThreshold, p.OutboundAnomalyThreshold, p.RequestBodyAccess,
		p.ResponseBodyAccess, p.RequestBodyLimit, p.RequestBodyNoFilesLimit, p.ResponseBodyLimit,
		p.UploadFileLimit, p.JSONParserEnabled, p.XMLParserEnabled, p.MultipartParserEnabled,
		p.AuditLogEnabled, p.AuditLogRelevantStatus, p.AuditLogParts, p.BlockingStatusCode,
		p.BlockingPageID, p.ID, p.Version)
	if err != nil {
		return err
	}
	if res.RowsAffected() == 0 {
		return ErrNotFound
	}
	p.Version++
	return nil
}

// Delete 删除策略（内置/使用中不可删除）。
func (s *Store) Delete(ctx context.Context, id uuid.UUID) error {
	p, err := s.GetByID(ctx, id)
	if err != nil {
		return err
	}
	if p.IsBuiltin {
		return ErrBuiltin
	}
	// 检查是否被应用引用
	var useCount int
	if err := s.db.QueryRow(ctx,
		`SELECT count(*) FROM application_policies WHERE policy_id = $1 AND is_active = TRUE`, id).Scan(&useCount); err != nil {
		return err
	}
	if useCount > 0 {
		return ErrInUse
	}
	res, err := s.db.Exec(ctx,
		`UPDATE protection_policies SET deleted_at=now(), updated_at=now(), version=version+1 WHERE id=$1 AND deleted_at IS NULL`, id)
	if err != nil {
		return err
	}
	if res.RowsAffected() == 0 {
		return ErrNotFound
	}
	return nil
}

// Copy 复制策略。
func (s *Store) Copy(ctx context.Context, id uuid.UUID, operatorID uuid.UUID) (*Policy, error) {
	src, err := s.GetByID(ctx, id)
	if err != nil {
		return nil, err
	}
	newCode := src.Code + "-copy"
	for i := 2; i <= 100; i++ {
		if _, err := s.GetByCode(ctx, newCode); err != nil {
			break
		}
		newCode = fmt.Sprintf("%s-copy%d", src.Code, i)
	}
	np := *src
	np.ID = uuid.Nil
	np.Code = newCode
	np.Name = src.Name + "（副本）"
	np.IsBuiltin = false
	np.CreatedBy = &operatorID
	if err := s.Create(ctx, &np); err != nil {
		return nil, err
	}
	return &np, nil
}

// BindApplication 绑定策略到应用。
func (s *Store) BindApplication(ctx context.Context, appID, policyID, operatorID uuid.UUID) error {
	tx, err := s.db.BeginTx(ctx, pgx.TxOptions{})
	if err != nil {
		return err
	}
	defer func() { _ = tx.Rollback(ctx) }()
	if _, err := tx.Exec(ctx,
		`UPDATE application_policies SET is_active = FALSE, updated_at = now() WHERE application_id = $1`, appID); err != nil {
		return err
	}
	if _, err := tx.Exec(ctx, `
INSERT INTO application_policies (application_id, policy_id, is_active, created_by)
VALUES ($1, $2, TRUE, $3)
ON CONFLICT (application_id, policy_id) DO UPDATE SET is_active = TRUE, updated_at = now()`,
		appID, policyID, operatorID); err != nil {
		return err
	}
	return tx.Commit(ctx)
}

// UnbindApplication 解绑应用策略。
func (s *Store) UnbindApplication(ctx context.Context, appID uuid.UUID) error {
	_, err := s.db.Exec(ctx,
		`DELETE FROM application_policies WHERE application_id = $1`, appID)
	return err
}

// GetApplicationPolicy 查询应用当前活动策略。
// 注意：JOIN 时必须加表别名前缀，避免与 application_policies 的同名列歧义。
func (s *Store) GetApplicationPolicy(ctx context.Context, appID uuid.UUID) (*Policy, error) {
	aliased := joinWithPrefix(policyColumns, "p")
	row := s.db.QueryRow(ctx, `
SELECT `+aliased+` FROM protection_policies p
JOIN application_policies ap ON ap.policy_id = p.id
WHERE ap.application_id = $1 AND ap.is_active = TRUE AND p.deleted_at IS NULL`, appID)
	p, err := s.scanPolicy(row)
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return nil, nil
		}
		return nil, err
	}
	return p, nil
}

// joinWithPrefix 为列清单添加表别名前缀（逗号分隔的列名，去除空白与换行）。
func joinWithPrefix(columns, prefix string) string {
	parts := strings.Split(columns, ",")
	var cols []string
	for _, c := range parts {
		c = strings.TrimSpace(c)
		if c != "" {
			cols = append(cols, prefix+"."+c)
		}
	}
	return strings.Join(cols, ",")
}

// ListApplicationIDs 查询策略绑定的应用。
func (s *Store) ListApplicationIDs(ctx context.Context, policyID uuid.UUID) ([]uuid.UUID, error) {
	rows, err := s.db.Query(ctx,
		`SELECT application_id FROM application_policies WHERE policy_id = $1 AND is_active = TRUE`, policyID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []uuid.UUID
	for rows.Next() {
		var id uuid.UUID
		if err := rows.Scan(&id); err != nil {
			return nil, err
		}
		out = append(out, id)
	}
	return out, rows.Err()
}

// CountUsage 查询策略被引用的应用数。
func (s *Store) CountUsage(ctx context.Context, policyID uuid.UUID) (int, error) {
	var n int
	err := s.db.QueryRow(ctx,
		`SELECT count(*) FROM application_policies WHERE policy_id = $1 AND is_active = TRUE`, policyID).Scan(&n)
	return n, err
}

// GetApplicationPolicyParams 查询应用当前策略参数（供配置生成器使用）。
func (s *Store) GetApplicationPolicyParams(ctx context.Context, appID uuid.UUID) (*gatewayconfig.PolicyParams, error) {
	p, err := s.GetApplicationPolicy(ctx, appID)
	if err != nil {
		return nil, err
	}
	if p == nil {
		return nil, nil
	}
	return &gatewayconfig.PolicyParams{
		PolicyID:          p.ID.String(),
		ProtectionMode:    p.ProtectionMode,
		ParanoiaLevel:     p.ParanoiaLevel,
		InboundThreshold:  p.InboundAnomalyThreshold,
		OutboundThreshold: p.OutboundAnomalyThreshold,
	}, nil
}

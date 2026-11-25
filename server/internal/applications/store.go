// Package applications 提供Web应用、域名、源站的数据管理。
package applications

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/jiuzhang-waf/server/internal/validation"
)

// 错误
var (
	ErrNotFound       = errors.New("application not found")
	ErrCodeExists     = errors.New("application code already exists")
	ErrDomainConflict = errors.New("domain listen conflict")
	ErrInvalidInput   = errors.New("invalid input")
	ErrCannotDelete   = errors.New("application cannot be deleted in current state")
)

// 应用状态
const (
	StatusDraft    = "DRAFT"
	StatusActive   = "ACTIVE"
	StatusDisabled = "DISABLED"
	StatusError    = "ERROR"
	StatusDeleted  = "DELETED"
)

// 防护模式
const (
	ModeOff     = "OFF"
	ModeObserve = "OBSERVE"
	ModeProtect = "PROTECT"
	// ModeBypass 数据透传：跳过全部检测（WAF/访问控制/CC/API动态防护），仅用于排障与应急直通
	ModeBypass = "BYPASS"
)

// validProtectionMode 校验防护模式是否合法（OFF/OBSERVE/PROTECT/BYPASS）。
func validProtectionMode(m string) bool {
	return m == ModeOff || m == ModeObserve || m == ModeProtect || m == ModeBypass
}

// API 准入模式（api_admission_mode，迁移 000166；docs/API_ADMISSION_CONTROL_DESIGN.md §3.1）。
// 与 protection_mode 正交：准入管「这个 API 允不允许存在」，无 BYPASS 取值。
const (
	AdmissionModeOff     = "OFF"
	AdmissionModeObserve = "OBSERVE"
	AdmissionModeProtect = "PROTECT"
)

// validAPIAdmissionMode 校验 API 准入模式是否合法（OFF/OBSERVE/PROTECT）。
func validAPIAdmissionMode(m string) bool {
	return m == AdmissionModeOff || m == AdmissionModeObserve || m == AdmissionModeProtect
}

// 部署模式（docs/NETWORK_MODES_DESIGN.md §4；MIRROR/TRANSPARENT 见 §4.2/§4.3）
const (
	DeployModeReverseProxy = "REVERSE_PROXY"
	DeployModeRouted       = "ROUTED"
	DeployModeMirror       = "MIRROR"
	DeployModeTransparent  = "TRANSPARENT"
)

// validDeploymentMode 校验部署模式是否合法（REVERSE_PROXY/ROUTED/MIRROR/TRANSPARENT）。
func validDeploymentMode(m string) bool {
	return m == DeployModeReverseProxy || m == DeployModeRouted ||
		m == DeployModeMirror || m == DeployModeTransparent
}

// 部署状态
const (
	DeployNotPublished   = "NOT_PUBLISHED"
	DeployPublishing     = "PUBLISHING"
	DeployPublished      = "PUBLISHED"
	DeployPublishFailed  = "PUBLISH_FAILED"
	DeployRollingBack    = "ROLLING_BACK"
	DeployRollbackFailed = "ROLLBACK_FAILED"
)

// 源站健康状态（只读运行态摘要，来自 upstream_health_records 最新探测记录）
const (
	UpstreamHealthHealthy   = "HEALTHY"
	UpstreamHealthUnhealthy = "UNHEALTHY"
	UpstreamHealthUnknown   = "UNKNOWN"
	UpstreamHealthDisabled  = "DISABLED"
)

// Application 是Web应用。
type Application struct {
	ID                uuid.UUID  `json:"id"`
	Code              string     `json:"code"`
	Name              string     `json:"name"`
	Description       string     `json:"description"`
	BusinessOwner     string     `json:"business_owner"`
	TechnicalOwner    string     `json:"technical_owner"`
	Status            string     `json:"status"`
	ProtectionMode    string     `json:"protection_mode"`
	APIAdmissionMode  string     `json:"api_admission_mode"`
	DeploymentMode    string     `json:"deployment_mode"`
	DeploymentStatus  string     `json:"deployment_status"`
	HealthStatus      string     `json:"health_status"`
	CurrentVersionID  *uuid.UUID `json:"current_version_id"`
	LastPublishAt     *time.Time `json:"last_publish_at"`
	LastPublishResult string     `json:"last_publish_result"`
	CreatedBy         *uuid.UUID `json:"created_by,omitempty"`
	CreatedAt         time.Time  `json:"created_at"`
	UpdatedAt         time.Time  `json:"updated_at"`
	Version           int        `json:"version"`
	// AuthzLeaseSeconds per-app 授权快照租约秒数（NG-AZ-02 D5；nil=不启用租约约束，
	// 配置夹紧 15~300——发布链编译进 handler api_authz_lease_seconds 与快照 lease_seconds）
	AuthzLeaseSeconds *int `json:"authz_lease_seconds"`
	// AutoSSL 自动申请/续约 SSL 证书配置与运行态摘要（迁移 000238）
	AutoSSLEnabled         bool       `json:"auto_ssl_enabled"`
	AutoSSLChallengeType   string     `json:"auto_ssl_challenge_type"`
	AutoSSLRenewBeforeDays *int       `json:"auto_ssl_renew_before_days"`
	AutoSSLLastStatus      string     `json:"auto_ssl_last_status"`
	AutoSSLLastError       string     `json:"auto_ssl_last_error"`
	AutoSSLFailCount       int        `json:"auto_ssl_fail_count"`
	AutoSSLNextRetryAt     *time.Time `json:"auto_ssl_next_retry_at"`
	AutoSSLLastAttemptAt   *time.Time `json:"auto_ssl_last_attempt_at"`
}

// PolicySummary 是应用或域名关联的防护策略摘要（只读展示用）。
type PolicySummary struct {
	ID             uuid.UUID `json:"id"`
	Code           string    `json:"code"`
	Name           string    `json:"name"`
	ProtectionMode string    `json:"protection_mode"`
	ParanoiaLevel  int       `json:"paranoia_level"`
}

// Domain 是应用域名。
type Domain struct {
	ID                  uuid.UUID  `json:"id"`
	ApplicationID       uuid.UUID  `json:"application_id"`
	Hostname            string     `json:"hostname"`
	NormalizedHostname  string     `json:"normalized_hostname"`
	DomainType          string     `json:"domain_type"`
	IsPrimary           bool       `json:"is_primary"`
	HTTPEnabled         bool       `json:"http_enabled"`
	HTTPSEnabled        bool       `json:"https_enabled"`
	HTTPPort            *int       `json:"http_port"`
	HTTPSPort           *int       `json:"https_port"`
	RedirectHTTPToHTTPS bool       `json:"redirect_http_to_https"`
	PolicyID            *uuid.UUID `json:"policy_id"`
	PolicyCode          string     `json:"policy_code,omitempty"`
	PolicyName          string     `json:"policy_name,omitempty"`
	PolicyMode          string     `json:"policy_mode,omitempty"`
	Status              string     `json:"status"`
	CreatedAt           time.Time  `json:"created_at"`
	UpdatedAt           time.Time  `json:"updated_at"`
}

// Upstream 是源站。
type Upstream struct {
	ID                         uuid.UUID  `json:"id"`
	ApplicationID              uuid.UUID  `json:"application_id"`
	Name                       string     `json:"name"`
	Scheme                     string     `json:"scheme"`
	Host                       string     `json:"host"`
	NormalizedHost             string     `json:"normalized_host"`
	Port                       int        `json:"port"`
	Weight                     int        `json:"weight"`
	Priority                   int        `json:"priority"`
	Status                     string     `json:"status"`
	HealthCheckEnabled         bool       `json:"health_check_enabled"`
	HealthCheckPath            string     `json:"health_check_path"`
	HealthCheckMethod          string     `json:"health_check_method"`
	HealthCheckIntervalSeconds int        `json:"health_check_interval_seconds"`
	HealthCheckTimeoutSeconds  int        `json:"health_check_timeout_seconds"`
	ExpectedStatusCodes        string     `json:"expected_status_codes"`
	ConnectTimeoutMs           int        `json:"connect_timeout_ms"`
	ResponseHeaderTimeoutMs    int        `json:"response_header_timeout_ms"`
	TLSServerName              string     `json:"tls_server_name"`
	TLSVerify                  bool       `json:"tls_verify"`
	MaxRetries                 int        `json:"max_retries"`
	CreatedBy                  *uuid.UUID `json:"created_by,omitempty"`
	CreatedAt                  time.Time  `json:"created_at"`
	UpdatedAt                  time.Time  `json:"updated_at"`
	Version                    int        `json:"version"`
	// 运行态健康探测摘要（来自 upstream_health_records 最新一条记录，只读展示）
	HealthStatus         string     `json:"health_status"`
	LastHealthCheckAt    *time.Time `json:"last_health_check_at"`
	LastResponseStatus   *int       `json:"last_response_status"`
	LastResponseTimeMs   *int       `json:"last_response_time_ms"`
	LastHealthErrorCode  string     `json:"last_health_error_code"`
	LastHealthError      string     `json:"last_health_error"`
	ConsecutiveSuccesses int        `json:"consecutive_successes"`
	ConsecutiveFailures  int        `json:"consecutive_failures"`
}

// Store 是应用仓储。
type Store struct {
	db *pgxpool.Pool
}

// NewStore 创建应用仓储。
func NewStore(db *pgxpool.Pool) *Store {
	return &Store{db: db}
}

// DB 返回底层连接池（仅用于只读统计查询）。
func (s *Store) DB() *pgxpool.Pool {
	return s.db
}

// ---------- 应用 ----------

const appColumns = `id, code, name, description, business_owner, technical_owner, status,
protection_mode, api_admission_mode, deployment_mode, deployment_status, health_status, current_version_id, last_publish_at,
last_publish_result, created_by, created_at, updated_at, version, authz_lease_seconds,
auto_ssl_enabled, auto_ssl_challenge_type, auto_ssl_renew_before_days, auto_ssl_last_status,
auto_ssl_last_error, auto_ssl_fail_count, auto_ssl_next_retry_at, auto_ssl_last_attempt_at`

func (s *Store) scanApp(row pgx.Row) (*Application, error) {
	var a Application
	err := row.Scan(&a.ID, &a.Code, &a.Name, &a.Description, &a.BusinessOwner, &a.TechnicalOwner,
		&a.Status, &a.ProtectionMode, &a.APIAdmissionMode, &a.DeploymentMode, &a.DeploymentStatus, &a.HealthStatus, &a.CurrentVersionID,
		&a.LastPublishAt, &a.LastPublishResult, &a.CreatedBy, &a.CreatedAt, &a.UpdatedAt, &a.Version, &a.AuthzLeaseSeconds,
		&a.AutoSSLEnabled, &a.AutoSSLChallengeType, &a.AutoSSLRenewBeforeDays, &a.AutoSSLLastStatus,
		&a.AutoSSLLastError, &a.AutoSSLFailCount, &a.AutoSSLNextRetryAt, &a.AutoSSLLastAttemptAt)
	if err != nil {
		return nil, err
	}
	return &a, nil
}

// Create 创建应用。
func (s *Store) Create(ctx context.Context, a *Application) error {
	if err := validation.ValidateAppCode(a.Code); err != nil {
		return err
	}
	if a.Name == "" || len(a.Name) > 128 {
		return fmt.Errorf("应用名称不能为空且不超过128字符")
	}
	if !validProtectionMode(a.ProtectionMode) {
		return fmt.Errorf("无效的防护模式")
	}
	// 空准入模式归一为 OFF（缺省语义；HTTP 层已对非法非空值 400，此处防御性校验兜底）
	if a.APIAdmissionMode == "" {
		a.APIAdmissionMode = AdmissionModeOff
	}
	if !validAPIAdmissionMode(a.APIAdmissionMode) {
		return fmt.Errorf("无效的API准入模式")
	}
	if !validDeploymentMode(a.DeploymentMode) {
		return fmt.Errorf("无效的部署模式")
	}
	err := s.db.QueryRow(ctx, `
INSERT INTO applications (code, name, description, business_owner, technical_owner, status, protection_mode, api_admission_mode, deployment_mode, created_by)
VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10)
RETURNING id, created_at, updated_at, version`,
		a.Code, a.Name, a.Description, a.BusinessOwner, a.TechnicalOwner, a.Status, a.ProtectionMode, a.APIAdmissionMode, a.DeploymentMode, a.CreatedBy,
	).Scan(&a.ID, &a.CreatedAt, &a.UpdatedAt, &a.Version)
	if err != nil {
		if strings.Contains(err.Error(), "idx_applications_code") {
			return ErrCodeExists
		}
		return err
	}
	return nil
}

// GetByID 查询应用。
func (s *Store) GetByID(ctx context.Context, id uuid.UUID) (*Application, error) {
	row := s.db.QueryRow(ctx, `SELECT `+appColumns+` FROM applications WHERE id = $1 AND deleted_at IS NULL`, id)
	a, err := s.scanApp(row)
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return nil, ErrNotFound
		}
		return nil, err
	}
	return a, nil
}

// GetByCode 按编码查询应用。
func (s *Store) GetByCode(ctx context.Context, code string) (*Application, error) {
	row := s.db.QueryRow(ctx, `SELECT `+appColumns+` FROM applications WHERE code = $1 AND deleted_at IS NULL`, code)
	a, err := s.scanApp(row)
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return nil, ErrNotFound
		}
		return nil, err
	}
	return a, nil
}

// Count 应用总数（不含软删除；授权配额强制与授权状态页配额用量展示共用口径）。
func (s *Store) Count(ctx context.Context) (int64, error) {
	var n int64
	err := s.db.QueryRow(ctx, `SELECT count(*) FROM applications WHERE deleted_at IS NULL`).Scan(&n)
	return n, err
}

// ListFilter 是应用列表筛选。
type ListFilter struct {
	Keyword        string
	Status         string
	Mode           string
	DeploymentMode string
	Page           int
	PageSize       int
}

// List 分页查询应用。
func (s *Store) List(ctx context.Context, f ListFilter) ([]Application, int64, error) {
	if f.Page <= 0 {
		f.Page = 1
	}
	if f.PageSize <= 0 || f.PageSize > 100 {
		f.PageSize = 20
	}
	where := "deleted_at IS NULL"
	args := []interface{}{}
	argIdx := 1
	if f.Keyword != "" {
		where += fmt.Sprintf(
			" AND (code ILIKE $%d OR name ILIKE $%d OR EXISTS (SELECT 1 FROM application_domains ad WHERE ad.application_id = applications.id AND (ad.hostname ILIKE $%d OR ad.normalized_hostname ILIKE $%d)))",
			argIdx, argIdx, argIdx, argIdx,
		)
		args = append(args, "%"+f.Keyword+"%")
		argIdx++
	}
	if f.Status != "" {
		where += fmt.Sprintf(" AND status = $%d", argIdx)
		args = append(args, f.Status)
		argIdx++
	}
	if f.Mode != "" {
		where += fmt.Sprintf(" AND protection_mode = $%d", argIdx)
		args = append(args, f.Mode)
		argIdx++
	}
	if f.DeploymentMode != "" {
		where += fmt.Sprintf(" AND deployment_mode = $%d", argIdx)
		args = append(args, f.DeploymentMode)
		argIdx++
	}
	var total int64
	if err := s.db.QueryRow(ctx, `SELECT count(*) FROM applications WHERE `+where, args...).Scan(&total); err != nil {
		return nil, 0, err
	}
	query := `SELECT ` + appColumns + ` FROM applications WHERE ` + where +
		fmt.Sprintf(" ORDER BY created_at DESC LIMIT $%d OFFSET $%d", argIdx, argIdx+1)
	args = append(args, f.PageSize, (f.Page-1)*f.PageSize)
	rows, err := s.db.Query(ctx, query, args...)
	if err != nil {
		return nil, 0, err
	}
	defer rows.Close()
	var out []Application
	for rows.Next() {
		a, err := s.scanApp(rows)
		if err != nil {
			return nil, 0, err
		}
		out = append(out, *a)
	}
	return out, total, rows.Err()
}

// Update 更新应用（乐观锁）。
func (s *Store) Update(ctx context.Context, a *Application) error {
	if a.Name == "" || len(a.Name) > 128 {
		return fmt.Errorf("应用名称不能为空且不超过128字符")
	}
	// 与 Create 同口径校验：非法模式发布后会在 generator modeToRuleEngine 静默回落 DetectionOnly
	if !validProtectionMode(a.ProtectionMode) {
		return fmt.Errorf("无效的防护模式")
	}
	// 与 Create 同口径：空准入模式归一为 OFF（防御性校验兜底，HTTP 层已对非法非空值 400）
	if a.APIAdmissionMode == "" {
		a.APIAdmissionMode = AdmissionModeOff
	}
	if !validAPIAdmissionMode(a.APIAdmissionMode) {
		return fmt.Errorf("无效的API准入模式")
	}
	if !validDeploymentMode(a.DeploymentMode) {
		return fmt.Errorf("无效的部署模式")
	}
	// NG-AZ-02 D5：租约秒数校验（nil=不启用；设置时必须在 15~300——
	// 防操作员把租约压到心跳间隔一半以下造成系统性误报）
	if a.AuthzLeaseSeconds != nil && (*a.AuthzLeaseSeconds < 15 || *a.AuthzLeaseSeconds > 300) {
		return fmt.Errorf("无效的授权租约秒数（须为 15~300 或留空不启用）")
	}
	res, err := s.db.Exec(ctx, `
UPDATE applications SET name=$1, description=$2, business_owner=$3, technical_owner=$4,
  protection_mode=$5, api_admission_mode=$6, deployment_mode=$7, updated_at=now(), version=version+1,
  authz_lease_seconds=$10
WHERE id=$8 AND version=$9 AND deleted_at IS NULL`,
		a.Name, a.Description, a.BusinessOwner, a.TechnicalOwner, a.ProtectionMode, a.APIAdmissionMode, a.DeploymentMode, a.ID, a.Version, a.AuthzLeaseSeconds)
	if err != nil {
		return err
	}
	if res.RowsAffected() == 0 {
		return ErrNotFound
	}
	a.Version++
	return nil
}

// SetStatus 设置应用状态。
func (s *Store) SetStatus(ctx context.Context, id uuid.UUID, status string) error {
	res, err := s.db.Exec(ctx,
		`UPDATE applications SET status=$1, updated_at=now(), version=version+1 WHERE id=$2 AND deleted_at IS NULL`, status, id)
	if err != nil {
		return err
	}
	if res.RowsAffected() == 0 {
		return ErrNotFound
	}
	return nil
}

// SetDeploymentStatus 设置部署状态。
func (s *Store) SetDeploymentStatus(ctx context.Context, id uuid.UUID, deployStatus, publishResult string, versionID *uuid.UUID) error {
	res, err := s.db.Exec(ctx, `
UPDATE applications SET deployment_status=$1, last_publish_result=$2, current_version_id=$3,
  last_publish_at=now(), updated_at=now(), version=version+1
WHERE id=$4 AND deleted_at IS NULL`, deployStatus, publishResult, versionID, id)
	if err != nil {
		return err
	}
	if res.RowsAffected() == 0 {
		return ErrNotFound
	}
	return nil
}

// SoftDelete 逻辑删除应用。
func (s *Store) SoftDelete(ctx context.Context, id uuid.UUID) error {
	res, err := s.db.Exec(ctx,
		`UPDATE applications SET deleted_at=now(), status=$2, updated_at=now(), version=version+1 WHERE id=$1 AND deleted_at IS NULL`, id, StatusDeleted)
	if err != nil {
		return err
	}
	if res.RowsAffected() == 0 {
		return ErrNotFound
	}
	return nil
}

// UpdateAutoSSLConfig 更新站点级自动 SSL 开关与策略配置。
func (s *Store) UpdateAutoSSLConfig(ctx context.Context, appID uuid.UUID, enabled bool, challengeType string, renewBeforeDays *int) error {
	if challengeType == "" {
		challengeType = "HTTP01"
	}
	if challengeType != "HTTP01" {
		return fmt.Errorf("当前仅支持 HTTP01 验证方式")
	}
	if renewBeforeDays != nil && (*renewBeforeDays < 7 || *renewBeforeDays > 60) {
		return fmt.Errorf("提前续约天数须在 7 至 60 天之间")
	}
	res, err := s.db.Exec(ctx, `
UPDATE applications
SET auto_ssl_enabled = $1,
    auto_ssl_challenge_type = $2,
    auto_ssl_renew_before_days = $3,
    auto_ssl_next_retry_at = CASE WHEN $1 THEN NULL ELSE auto_ssl_next_retry_at END,
    auto_ssl_fail_count = CASE WHEN $1 THEN 0 ELSE auto_ssl_fail_count END,
    updated_at = now(),
    version = version + 1
WHERE id = $4 AND deleted_at IS NULL`,
		enabled, challengeType, renewBeforeDays, appID)
	if err != nil {
		return err
	}
	if res.RowsAffected() == 0 {
		return ErrNotFound
	}
	return nil
}

// UpdateAutoSSLRuntimeState 更新站点级自动 SSL 运行态摘要与失败退避时间。
func (s *Store) UpdateAutoSSLRuntimeState(ctx context.Context, appID uuid.UUID, lastStatus, lastError string, failCount int, nextRetryAt, lastAttemptAt *time.Time) error {
	if len(lastError) > 1000 {
		lastError = lastError[:1000]
	}
	res, err := s.db.Exec(ctx, `
UPDATE applications
SET auto_ssl_last_status = $1,
    auto_ssl_last_error = $2,
    auto_ssl_fail_count = $3,
    auto_ssl_next_retry_at = $4,
    auto_ssl_last_attempt_at = $5,
    updated_at = now()
WHERE id = $6 AND deleted_at IS NULL`,
		lastStatus, lastError, failCount, nextRetryAt, lastAttemptAt, appID)
	if err != nil {
		return err
	}
	if res.RowsAffected() == 0 {
		return ErrNotFound
	}
	return nil
}

// ListAutoSSLCandidates 返回全部已启用且开启自动 SSL 的非镜像站点。
func (s *Store) ListAutoSSLCandidates(ctx context.Context) ([]Application, error) {
	rows, err := s.db.Query(ctx, `
SELECT `+appColumns+`
FROM applications
WHERE deleted_at IS NULL
  AND status = $1
  AND auto_ssl_enabled = TRUE
  AND deployment_mode <> $2
ORDER BY created_at ASC`, StatusActive, DeployModeMirror)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []Application
	for rows.Next() {
		a, err := s.scanApp(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, *a)
	}
	return out, rows.Err()
}

// HasAnyAutoSSLEnabled 判断是否存在任一活动且开启自动 SSL 的非镜像站点。
func (s *Store) HasAnyAutoSSLEnabled(ctx context.Context) (bool, error) {
	var exists bool
	err := s.db.QueryRow(ctx, `
SELECT EXISTS (
  SELECT 1 FROM applications
  WHERE deleted_at IS NULL
    AND status = $1
    AND auto_ssl_enabled = TRUE
    AND deployment_mode <> $2
)`, StatusActive, DeployModeMirror).Scan(&exists)
	return exists, err
}

// ---------- 域名 ----------

// validateDomainInput 校验域名主机名、端口范围及至少启用 HTTP/HTTPS 之一（新增与更新共用）。
func validateDomainInput(d *Domain) error {
	normalized, dtype, err := validation.ValidateHostname(d.Hostname)
	if err != nil {
		return err
	}
	d.NormalizedHostname = normalized
	d.DomainType = dtype
	if d.HTTPPort != nil {
		if err := validation.ValidatePort(*d.HTTPPort); err != nil {
			return err
		}
	}
	if d.HTTPSPort != nil {
		if err := validation.ValidatePort(*d.HTTPSPort); err != nil {
			return err
		}
	}
	if !d.HTTPEnabled && !d.HTTPSEnabled {
		return fmt.Errorf("至少启用HTTP或HTTPS之一")
	}
	return nil
}

// GetBoundPolicySummary 查询应用当前绑定的活动防护策略摘要（未绑定返回 nil, nil）。
func (s *Store) GetBoundPolicySummary(ctx context.Context, appID uuid.UUID) (*PolicySummary, error) {
	row := s.db.QueryRow(ctx, `
SELECT p.id, p.code, p.name, p.protection_mode, p.paranoia_level
FROM protection_policies p
JOIN application_policies ap ON ap.policy_id = p.id
WHERE ap.application_id = $1 AND ap.is_active = TRUE AND p.deleted_at IS NULL
LIMIT 1`, appID)
	var ps PolicySummary
	if err := row.Scan(&ps.ID, &ps.Code, &ps.Name, &ps.ProtectionMode, &ps.ParanoiaLevel); err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return nil, nil
		}
		return nil, err
	}
	return &ps, nil
}

// resolveDomainPolicy 校验并解析域名绑定的防护策略（nil=继承应用策略；非空须存在且 ACTIVE）。
func (s *Store) resolveDomainPolicy(ctx context.Context, policyID *uuid.UUID) (code, name, mode string, err error) {
	if policyID == nil {
		return "", "", "", nil
	}
	row := s.db.QueryRow(ctx, `
SELECT code, name, protection_mode
FROM protection_policies
WHERE id = $1 AND deleted_at IS NULL AND status = 'ACTIVE'`, *policyID)
	if err := row.Scan(&code, &name, &mode); err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return "", "", "", fmt.Errorf("%w: 所选防护策略不存在或已停用", ErrInvalidInput)
		}
		return "", "", "", err
	}
	return code, name, mode, nil
}

// AddDomain 添加域名（含校验、策略有效性检查与冲突检测）。
func (s *Store) AddDomain(ctx context.Context, d *Domain) error {
	if err := validateDomainInput(d); err != nil {
		return err
	}
	code, name, mode, err := s.resolveDomainPolicy(ctx, d.PolicyID)
	if err != nil {
		return err
	}
	d.PolicyCode, d.PolicyName, d.PolicyMode = code, name, mode
	// 冲突检测：相同规范化域名+端口+协议（跨应用）
	conflict, err := s.checkDomainConflict(ctx, d, uuid.Nil)
	if err != nil {
		return err
	}
	if conflict != "" {
		return fmt.Errorf("%w: %s", ErrDomainConflict, conflict)
	}
	err = s.db.QueryRow(ctx, `
INSERT INTO application_domains (application_id, hostname, normalized_hostname, domain_type, is_primary,
  http_enabled, https_enabled, http_port, https_port, redirect_http_to_https, policy_id, status)
VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12)
RETURNING id, created_at, updated_at`,
		d.ApplicationID, d.Hostname, d.NormalizedHostname, d.DomainType, d.IsPrimary,
		d.HTTPEnabled, d.HTTPSEnabled, d.HTTPPort, d.HTTPSPort, d.RedirectHTTPToHTTPS, d.PolicyID, d.Status,
	).Scan(&d.ID, &d.CreatedAt, &d.UpdatedAt)
	return err
}

// checkDomainConflict 检测域名监听冲突，返回冲突描述（空表示无冲突）。
// excludeID 排除自身（更新场景；新增传 uuid.Nil，不匹配任何行）。
func (s *Store) checkDomainConflict(ctx context.Context, d *Domain, excludeID uuid.UUID) (string, error) {
	rows, err := s.db.Query(ctx, `
SELECT ad.normalized_hostname, ad.http_port, ad.https_port, ad.http_enabled, ad.https_enabled, a.code
FROM application_domains ad
JOIN applications a ON a.id = ad.application_id
WHERE ad.normalized_hostname = $1 AND ad.id <> $2 AND ad.status = 'ACTIVE' AND a.deleted_at IS NULL AND a.status <> 'DELETED'`,
		d.NormalizedHostname, excludeID)
	if err != nil {
		return "", err
	}
	defer rows.Close()
	for rows.Next() {
		var host string
		var httpPort, httpsPort *int
		var httpEnabled, httpsEnabled bool
		var appCode string
		if err := rows.Scan(&host, &httpPort, &httpsPort, &httpEnabled, &httpsEnabled, &appCode); err != nil {
			return "", err
		}
		// 检查 HTTP 端口冲突
		if d.HTTPEnabled && httpEnabled && d.HTTPPort != nil && httpPort != nil && *d.HTTPPort == *httpPort {
			return fmt.Sprintf("域名 %s 的 HTTP 端口 %d 已被应用 %s 使用", host, *httpPort, appCode), nil
		}
		// 检查 HTTPS 端口冲突
		if d.HTTPSEnabled && httpsEnabled && d.HTTPSPort != nil && httpsPort != nil && *d.HTTPSPort == *httpsPort {
			return fmt.Sprintf("域名 %s 的 HTTPS 端口 %d 已被应用 %s 使用", host, *httpsPort, appCode), nil
		}
	}
	return "", rows.Err()
}

const domainSelectColumns = `ad.id, ad.application_id, ad.hostname, ad.normalized_hostname, ad.domain_type, ad.is_primary,
  ad.http_enabled, ad.https_enabled, ad.http_port, ad.https_port, ad.redirect_http_to_https,
  ad.policy_id, COALESCE(pp.code, ''), COALESCE(pp.name, ''), COALESCE(pp.protection_mode, ''),
  ad.status, ad.created_at, ad.updated_at`

func scanDomainRow(scan func(dest ...any) error) (Domain, error) {
	var d Domain
	err := scan(
		&d.ID, &d.ApplicationID, &d.Hostname, &d.NormalizedHostname, &d.DomainType,
		&d.IsPrimary, &d.HTTPEnabled, &d.HTTPSEnabled, &d.HTTPPort, &d.HTTPSPort,
		&d.RedirectHTTPToHTTPS, &d.PolicyID, &d.PolicyCode, &d.PolicyName, &d.PolicyMode,
		&d.Status, &d.CreatedAt, &d.UpdatedAt,
	)
	return d, err
}

// ListDomains 查询应用域名（附带域名级防护策略摘要）。
func (s *Store) ListDomains(ctx context.Context, appID uuid.UUID) ([]Domain, error) {
	rows, err := s.db.Query(ctx, `
SELECT `+domainSelectColumns+`
FROM application_domains ad
LEFT JOIN protection_policies pp ON pp.id = ad.policy_id AND pp.deleted_at IS NULL
WHERE ad.application_id = $1
ORDER BY ad.is_primary DESC, ad.created_at ASC`, appID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []Domain
	for rows.Next() {
		d, err := scanDomainRow(rows.Scan)
		if err != nil {
			return nil, err
		}
		out = append(out, d)
	}
	return out, rows.Err()
}

// GetDomain 查询单个域名（附带域名级防护策略摘要）。
func (s *Store) GetDomain(ctx context.Context, domainID uuid.UUID) (*Domain, error) {
	row := s.db.QueryRow(ctx, `
SELECT `+domainSelectColumns+`
FROM application_domains ad
LEFT JOIN protection_policies pp ON pp.id = ad.policy_id AND pp.deleted_at IS NULL
WHERE ad.id = $1`, domainID)
	d, err := scanDomainRow(row.Scan)
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return nil, ErrNotFound
		}
		return nil, err
	}
	return &d, nil
}

// UpdateDomain 更新域名（含与 AddDomain 同口径的主机名/端口/协议/策略校验及冲突检测）。
func (s *Store) UpdateDomain(ctx context.Context, d *Domain) error {
	if err := validateDomainInput(d); err != nil {
		return err
	}
	code, name, mode, err := s.resolveDomainPolicy(ctx, d.PolicyID)
	if err != nil {
		return err
	}
	d.PolicyCode, d.PolicyName, d.PolicyMode = code, name, mode
	conflict, err := s.checkDomainConflict(ctx, d, d.ID)
	if err != nil {
		return err
	}
	if conflict != "" {
		return fmt.Errorf("%w: %s", ErrDomainConflict, conflict)
	}
	res, err := s.db.Exec(ctx, `
UPDATE application_domains SET hostname=$1, normalized_hostname=$2, domain_type=$3, is_primary=$4,
  http_enabled=$5, https_enabled=$6, http_port=$7, https_port=$8, redirect_http_to_https=$9,
  policy_id=$10, status=$11, updated_at=now()
WHERE id=$12`,
		d.Hostname, d.NormalizedHostname, d.DomainType, d.IsPrimary, d.HTTPEnabled, d.HTTPSEnabled,
		d.HTTPPort, d.HTTPSPort, d.RedirectHTTPToHTTPS, d.PolicyID, d.Status, d.ID)
	if err != nil {
		return err
	}
	if res.RowsAffected() == 0 {
		return ErrNotFound
	}
	return nil
}

// DeleteDomain 删除域名。
func (s *Store) DeleteDomain(ctx context.Context, domainID uuid.UUID) error {
	res, err := s.db.Exec(ctx, `DELETE FROM application_domains WHERE id = $1`, domainID)
	if err != nil {
		return err
	}
	if res.RowsAffected() == 0 {
		return ErrNotFound
	}
	return nil
}

// CountActiveDomains 统计应用的活动域名数。
func (s *Store) CountActiveDomains(ctx context.Context, appID uuid.UUID) (int, error) {
	var n int
	err := s.db.QueryRow(ctx,
		`SELECT count(*) FROM application_domains WHERE application_id = $1 AND status = 'ACTIVE'`, appID).Scan(&n)
	return n, err
}

// PrimaryDomainsByAppIDs 批量查询每个应用的主活动域名（优先 is_primary，其次最早创建）。
func (s *Store) PrimaryDomainsByAppIDs(ctx context.Context, appIDs []uuid.UUID) (map[uuid.UUID]string, error) {
	out := make(map[uuid.UUID]string, len(appIDs))
	if len(appIDs) == 0 {
		return out, nil
	}
	rows, err := s.db.Query(ctx, `
SELECT DISTINCT ON (application_id) application_id, normalized_hostname
FROM application_domains
WHERE application_id = ANY($1) AND status = 'ACTIVE'
ORDER BY application_id, is_primary DESC, created_at ASC`, appIDs)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	for rows.Next() {
		var appID uuid.UUID
		var host string
		if err := rows.Scan(&appID, &host); err != nil {
			return nil, err
		}
		out[appID] = host
	}
	return out, rows.Err()
}

// ---------- 源站 ----------

func defaultUpstreamHealthStatus(status string, healthCheckEnabled bool) string {
	if !healthCheckEnabled {
		return UpstreamHealthDisabled
	}
	if status != "ACTIVE" {
		return UpstreamHealthUnknown
	}
	return UpstreamHealthUnknown
}

const upstreamSelectWithHealth = `
SELECT u.id, u.application_id, u.name, u.scheme, u.host, u.normalized_host, u.port, u.weight, u.priority, u.status,
  u.health_check_enabled, u.health_check_path, u.health_check_method, u.health_check_interval_seconds,
  u.health_check_timeout_seconds, u.expected_status_codes, u.connect_timeout_ms, u.response_header_timeout_ms,
  u.tls_server_name, u.tls_verify, u.max_retries, u.created_at, u.updated_at, u.version,
  CASE
    WHEN NOT u.health_check_enabled THEN 'DISABLED'
    WHEN u.status <> 'ACTIVE' THEN 'UNKNOWN'
    WHEN h.status IN ('UP', 'HEALTHY') THEN 'HEALTHY'
    WHEN h.status IN ('DOWN', 'UNHEALTHY') THEN 'UNHEALTHY'
    ELSE 'UNKNOWN'
  END AS health_status,
  h.checked_at,
  h.response_status,
  h.response_time_ms,
  COALESCE(h.error_code, ''),
  COALESCE(h.error_message, ''),
  COALESCE(h.consecutive_successes, 0),
  COALESCE(h.consecutive_failures, 0)
FROM upstreams u
LEFT JOIN LATERAL (
  SELECT status, checked_at, response_status, response_time_ms,
         error_code, error_message, consecutive_successes, consecutive_failures
  FROM upstream_health_records
  WHERE upstream_id = u.id
  ORDER BY checked_at DESC
  LIMIT 1
) h ON u.health_check_enabled AND u.status = 'ACTIVE'`

func scanUpstreamWithHealth(scan func(dest ...any) error) (Upstream, error) {
	var u Upstream
	err := scan(
		&u.ID, &u.ApplicationID, &u.Name, &u.Scheme, &u.Host, &u.NormalizedHost,
		&u.Port, &u.Weight, &u.Priority, &u.Status, &u.HealthCheckEnabled, &u.HealthCheckPath,
		&u.HealthCheckMethod, &u.HealthCheckIntervalSeconds, &u.HealthCheckTimeoutSeconds,
		&u.ExpectedStatusCodes, &u.ConnectTimeoutMs, &u.ResponseHeaderTimeoutMs, &u.TLSServerName,
		&u.TLSVerify, &u.MaxRetries, &u.CreatedAt, &u.UpdatedAt, &u.Version,
		&u.HealthStatus, &u.LastHealthCheckAt, &u.LastResponseStatus, &u.LastResponseTimeMs,
		&u.LastHealthErrorCode, &u.LastHealthError, &u.ConsecutiveSuccesses, &u.ConsecutiveFailures,
	)
	return u, err
}

// AddUpstream 添加源站。
func (s *Store) AddUpstream(ctx context.Context, u *Upstream) error {
	if err := validation.IsValidUpstreamHost(u.Host); err != nil {
		return err
	}
	if err := validation.ValidatePort(u.Port); err != nil {
		return err
	}
	if u.Scheme != "http" && u.Scheme != "https" && u.Scheme != "h2c" {
		return fmt.Errorf("源站协议仅支持 http、https 或 h2c")
	}
	if u.Weight < 1 || u.Weight > 100 {
		return fmt.Errorf("源站权重必须在1至100之间")
	}
	u.NormalizedHost = strings.ToLower(strings.TrimSpace(u.Host))
	if u.Name == "" {
		u.Name = u.NormalizedHost
	}
	err := s.db.QueryRow(ctx, `
INSERT INTO upstreams (application_id, name, scheme, host, normalized_host, port, weight, priority, status,
  health_check_enabled, health_check_path, health_check_method, health_check_interval_seconds,
  health_check_timeout_seconds, expected_status_codes, connect_timeout_ms, response_header_timeout_ms,
  tls_server_name, tls_verify, max_retries, created_by)
VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,$14,$15,$16,$17,$18,$19,$20,$21)
RETURNING id, created_at, updated_at, version`,
		u.ApplicationID, u.Name, u.Scheme, u.Host, u.NormalizedHost, u.Port, u.Weight, u.Priority, u.Status,
		u.HealthCheckEnabled, u.HealthCheckPath, u.HealthCheckMethod, u.HealthCheckIntervalSeconds,
		u.HealthCheckTimeoutSeconds, u.ExpectedStatusCodes, u.ConnectTimeoutMs, u.ResponseHeaderTimeoutMs,
		u.TLSServerName, u.TLSVerify, u.MaxRetries, u.CreatedBy,
	).Scan(&u.ID, &u.CreatedAt, &u.UpdatedAt, &u.Version)
	if err == nil {
		u.HealthStatus = defaultUpstreamHealthStatus(u.Status, u.HealthCheckEnabled)
	}
	return err
}

// ListUpstreams 查询应用源站（附带最新一次健康探测摘要）。
func (s *Store) ListUpstreams(ctx context.Context, appID uuid.UUID) ([]Upstream, error) {
	rows, err := s.db.Query(ctx,
		upstreamSelectWithHealth+` WHERE u.application_id = $1 AND u.deleted_at IS NULL ORDER BY u.priority DESC, u.weight DESC, u.created_at ASC`, appID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []Upstream
	for rows.Next() {
		u, err := scanUpstreamWithHealth(rows.Scan)
		if err != nil {
			return nil, err
		}
		out = append(out, u)
	}
	return out, rows.Err()
}

// GetUpstream 查询源站（附带最新一次健康探测摘要）。
func (s *Store) GetUpstream(ctx context.Context, id uuid.UUID) (*Upstream, error) {
	row := s.db.QueryRow(ctx,
		upstreamSelectWithHealth+` WHERE u.id = $1 AND u.deleted_at IS NULL`, id)
	u, err := scanUpstreamWithHealth(row.Scan)
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return nil, ErrNotFound
		}
		return nil, err
	}
	return &u, nil
}

// UpdateUpstream 更新源站（乐观锁）。
func (s *Store) UpdateUpstream(ctx context.Context, u *Upstream) error {
	if err := validation.IsValidUpstreamHost(u.Host); err != nil {
		return err
	}
	if err := validation.ValidatePort(u.Port); err != nil {
		return err
	}
	// 与 AddUpstream 同口径校验协议，防写入任意值进入发布配置
	if u.Scheme != "http" && u.Scheme != "https" && u.Scheme != "h2c" {
		return fmt.Errorf("源站协议仅支持 http、https 或 h2c")
	}
	if u.Weight < 1 || u.Weight > 100 {
		return fmt.Errorf("源站权重必须在1至100之间")
	}
	u.NormalizedHost = strings.ToLower(strings.TrimSpace(u.Host))
	res, err := s.db.Exec(ctx, `
UPDATE upstreams SET name=$1, scheme=$2, host=$3, normalized_host=$4, port=$5, weight=$6, priority=$7,
  status=$8, health_check_enabled=$9, health_check_path=$10, health_check_method=$11,
  health_check_interval_seconds=$12, health_check_timeout_seconds=$13, expected_status_codes=$14,
  connect_timeout_ms=$15, response_header_timeout_ms=$16, tls_server_name=$17, tls_verify=$18,
  max_retries=$19, updated_at=now(), version=version+1
WHERE id=$20 AND version=$21 AND deleted_at IS NULL`,
		u.Name, u.Scheme, u.Host, u.NormalizedHost, u.Port, u.Weight, u.Priority, u.Status,
		u.HealthCheckEnabled, u.HealthCheckPath, u.HealthCheckMethod, u.HealthCheckIntervalSeconds,
		u.HealthCheckTimeoutSeconds, u.ExpectedStatusCodes, u.ConnectTimeoutMs, u.ResponseHeaderTimeoutMs,
		u.TLSServerName, u.TLSVerify, u.MaxRetries, u.ID, u.Version)
	if err != nil {
		return err
	}
	if res.RowsAffected() == 0 {
		return ErrNotFound
	}
	u.Version++
	if !u.HealthCheckEnabled || u.Status != "ACTIVE" {
		u.HealthStatus = defaultUpstreamHealthStatus(u.Status, u.HealthCheckEnabled)
		u.LastHealthCheckAt = nil
		u.LastResponseStatus = nil
		u.LastResponseTimeMs = nil
		u.LastHealthErrorCode = ""
		u.LastHealthError = ""
		u.ConsecutiveSuccesses = 0
		u.ConsecutiveFailures = 0
	}
	return nil
}

// SetUpstreamStatus 设置源站状态。
func (s *Store) SetUpstreamStatus(ctx context.Context, id uuid.UUID, status string) error {
	res, err := s.db.Exec(ctx,
		`UPDATE upstreams SET status=$1, updated_at=now(), version=version+1 WHERE id=$2 AND deleted_at IS NULL`, status, id)
	if err != nil {
		return err
	}
	if res.RowsAffected() == 0 {
		return ErrNotFound
	}
	return nil
}

// DeleteUpstream 删除源站（逻辑删除）。
func (s *Store) DeleteUpstream(ctx context.Context, id uuid.UUID) error {
	res, err := s.db.Exec(ctx,
		`UPDATE upstreams SET deleted_at=now(), updated_at=now(), version=version+1 WHERE id=$1 AND deleted_at IS NULL`, id)
	if err != nil {
		return err
	}
	if res.RowsAffected() == 0 {
		return ErrNotFound
	}
	return nil
}

// CountActiveUpstreams 统计应用的活动源站数。
func (s *Store) CountActiveUpstreams(ctx context.Context, appID uuid.UUID) (int, error) {
	var n int
	err := s.db.QueryRow(ctx,
		`SELECT count(*) FROM upstreams WHERE application_id = $1 AND status = 'ACTIVE' AND deleted_at IS NULL`, appID).Scan(&n)
	return n, err
}

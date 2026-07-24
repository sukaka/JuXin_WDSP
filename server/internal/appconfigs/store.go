// Package appconfigs 应用级 HTTP 头合规与代理配置 + 路径粒度转发（迁移 000026）。
//
// 两张表：
//   - app_header_configs：每应用一对一的头合规与代理配置，全量 upsert + version 乐观锁；
//   - app_path_routes：应用内路径前缀 → 指定源站的路径粒度转发，常规 CRUD + version 乐观锁。
//
// Store 同时实现 gatewayconfig.AppConfigsProvider，供配置发布侧读取生效配置。
package appconfigs

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"regexp"
	"strings"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/jiuzhang-waf/server/internal/gatewayconfig"
)

// 错误
var (
	ErrNotFound        = errors.New("appconfigs: record not found")
	ErrAppNotFound     = errors.New("appconfigs: application not found")
	ErrVersionConflict = errors.New("appconfigs: version conflict")
	ErrRouteConflict   = errors.New("appconfigs: path route already exists")
	ErrInvalid         = errors.New("appconfigs: invalid input")
)

// 取值白名单
var (
	headerActions   = map[string]bool{"keep": true, "hide": true, "replace": true}
	frameOptions    = map[string]bool{"default": true, "inherit": true, "deny": true, "sameorigin": true, "allow_from": true}
	cspModes        = map[string]bool{"off": true, "preset": true, "custom": true}
	ruleMethods     = map[string]bool{"set": true, "add": true, "delete": true}
	upstreamSchemes = map[string]bool{"http": true, "https": true}
	routeStatuses   = map[string]bool{"ENABLED": true, "DISABLED": true}
)

// headerNameRe RFC 7230 token（HTTP 头字段名）。
var headerNameRe = regexp.MustCompile(`^[!#$%&'*+\-.^_` + "`" + `|~0-9A-Za-z]+$`)

// HeaderConfigRecord 头合规配置记录（含乐观锁版本与审计字段）。
type HeaderConfigRecord struct {
	Config    *gatewayconfig.AppHeaderConfig `json:"config"`
	Version   int                            `json:"version"`
	UpdatedBy *uuid.UUID                     `json:"updated_by,omitempty"`
	CreatedAt time.Time                      `json:"created_at"`
	UpdatedAt time.Time                      `json:"updated_at"`
}

// PathRoute 路径粒度转发规则。
type PathRoute struct {
	ID             uuid.UUID  `json:"id"`
	ApplicationID  uuid.UUID  `json:"application_id"`
	PathPrefix     string     `json:"path_prefix"`
	UpstreamScheme string     `json:"upstream_scheme"`
	UpstreamHost   string     `json:"upstream_host"`
	UpstreamPort   int        `json:"upstream_port"`
	StripPrefix    bool       `json:"strip_prefix"`
	Priority       int        `json:"priority"`
	Status         string     `json:"status"`
	Description    string     `json:"description"`
	CreatedBy      *uuid.UUID `json:"created_by,omitempty"`
	CreatedAt      time.Time  `json:"created_at"`
	UpdatedAt      time.Time  `json:"updated_at"`
	Version        int        `json:"version"`
}

// Repository 是 appconfigs 仓储接口（SQL Store 与 MemStore 同语义）。
type Repository interface {
	GetHeaderConfig(ctx context.Context, appID uuid.UUID) (*gatewayconfig.AppHeaderConfig, error)
	GetHeaderConfigRecord(ctx context.Context, appID uuid.UUID) (*HeaderConfigRecord, error)
	UpsertHeaderConfig(ctx context.Context, appID uuid.UUID, cfg *gatewayconfig.AppHeaderConfig, updatedBy uuid.UUID, expectVersion int) (int, error)
	ListEnabledPathRoutes(ctx context.Context, appID uuid.UUID) ([]gatewayconfig.AppPathRoute, error)
	ListPathRoutes(ctx context.Context, appID uuid.UUID, page, pageSize int) ([]PathRoute, int64, error)
	GetPathRoute(ctx context.Context, appID, routeID uuid.UUID) (*PathRoute, error)
	CreatePathRoute(ctx context.Context, r *PathRoute) error
	UpdatePathRoute(ctx context.Context, r *PathRoute) error
	DeletePathRoute(ctx context.Context, appID, routeID uuid.UUID) error
}

// DefaultHeaderConfig 返回未配置时的默认头合规对象（与迁移默认值一致，
// 行为等价于既有静态头版本）。
func DefaultHeaderConfig() *gatewayconfig.AppHeaderConfig {
	return &gatewayconfig.AppHeaderConfig{
		ServerAction:     "keep",
		XAuthorAction:    "keep",
		XPoweredByAction: "keep",
		XFrameOptions:    "default",
		HstsMaxAge:       31536000,
		CspMode:          "off",
	}
}

// Store 是 appconfigs 的 PostgreSQL 仓储。
type Store struct {
	db *pgxpool.Pool
}

// NewStore 创建仓储。
func NewStore(db *pgxpool.Pool) *Store {
	return &Store{db: db}
}

var (
	_ Repository                       = (*Store)(nil)
	_ gatewayconfig.AppConfigsProvider = (*Store)(nil)
)

// headerConfigColumns app_header_configs 全列（顺序与 scan 一致）。
const headerConfigColumns = `application_id, server_action, server_value, x_powered_by_action, x_powered_by_value,
  x_author_action, x_author_value,
  x_frame_options, x_frame_options_url, x_xss_protection, vary_user_agent,
  hsts_enabled, hsts_max_age, csp_mode, csp_value,
  response_buffering, xff_overwrite, host_strip_port, accept_encoding_off, redirect_port_rewrite,
  custom_request_rules, custom_response_rules, updated_by, created_at, updated_at, version`

// GetHeaderConfig 查询应用头合规配置；无记录返回 (nil, nil)（默认静态头行为）。
func (s *Store) GetHeaderConfig(ctx context.Context, appID uuid.UUID) (*gatewayconfig.AppHeaderConfig, error) {
	rec, err := s.GetHeaderConfigRecord(ctx, appID)
	if err != nil || rec == nil {
		return nil, err
	}
	return rec.Config, nil
}

// GetHeaderConfigRecord 查询头合规配置完整记录（含版本）；无记录返回 (nil, nil)。
func (s *Store) GetHeaderConfigRecord(ctx context.Context, appID uuid.UUID) (*HeaderConfigRecord, error) {
	row := s.db.QueryRow(ctx, `SELECT `+headerConfigColumns+` FROM app_header_configs WHERE application_id = $1`, appID)
	rec, err := scanHeaderConfig(row)
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return nil, nil
		}
		return nil, err
	}
	return rec, nil
}

// UpsertHeaderConfig 全量 upsert 头合规配置，version 乐观锁：
// expectVersion=0 表示创建（已存在报 ErrVersionConflict）；>0 表示按版本更新
// （记录不存在或版本不匹配报 ErrVersionConflict）。应用不存在报 ErrAppNotFound（FK）。
// 返回新版本号。
func (s *Store) UpsertHeaderConfig(ctx context.Context, appID uuid.UUID, cfg *gatewayconfig.AppHeaderConfig, updatedBy uuid.UUID, expectVersion int) (int, error) {
	if err := validateHeaderConfig(cfg); err != nil {
		return 0, err
	}
	reqRules, err := json.Marshal(rulesOrEmpty(cfg.CustomRequestRules))
	if err != nil {
		return 0, fmt.Errorf("marshal custom_request_rules: %w", err)
	}
	respRules, err := json.Marshal(rulesOrEmpty(cfg.CustomResponseRules))
	if err != nil {
		return 0, fmt.Errorf("marshal custom_response_rules: %w", err)
	}
	var ub *uuid.UUID
	if updatedBy != uuid.Nil {
		ub = &updatedBy
	}
	if expectVersion > 0 {
		res, err := s.db.Exec(ctx, `
UPDATE app_header_configs SET server_action=$2, server_value=$3, x_powered_by_action=$4, x_powered_by_value=$5,
  x_author_action=$6, x_author_value=$7,
  x_frame_options=$8, x_frame_options_url=$9, x_xss_protection=$10, vary_user_agent=$11,
  hsts_enabled=$12, hsts_max_age=$13, csp_mode=$14, csp_value=$15,
  response_buffering=$16, xff_overwrite=$17, host_strip_port=$18, accept_encoding_off=$19, redirect_port_rewrite=$20,
  custom_request_rules=$21, custom_response_rules=$22, updated_by=$23, updated_at=now(), version=version+1
WHERE application_id=$1 AND version=$24`,
			appID, cfg.ServerAction, cfg.ServerValue, cfg.XPoweredByAction, cfg.XPoweredByValue,
			cfg.XAuthorAction, cfg.XAuthorValue,
			cfg.XFrameOptions, cfg.XFrameOptionsURL, cfg.XXssProtection, cfg.VaryUserAgent,
			cfg.HstsEnabled, cfg.HstsMaxAge, cfg.CspMode, cfg.CspValue,
			cfg.ResponseBuffering, cfg.XffOverwrite, cfg.HostStripPort, cfg.AcceptEncodingOff, cfg.RedirectPortRewrite,
			reqRules, respRules, ub, expectVersion)
		if err != nil {
			return 0, err
		}
		if res.RowsAffected() == 0 {
			// 区分记录不存在与版本不匹配：对客户端均为版本冲突（需先 GET 取最新版本）。
			return 0, ErrVersionConflict
		}
		return expectVersion + 1, nil
	}
	var newVersion int
	err = s.db.QueryRow(ctx, `
INSERT INTO app_header_configs (application_id, server_action, server_value, x_powered_by_action, x_powered_by_value,
  x_author_action, x_author_value,
  x_frame_options, x_frame_options_url, x_xss_protection, vary_user_agent,
  hsts_enabled, hsts_max_age, csp_mode, csp_value,
  response_buffering, xff_overwrite, host_strip_port, accept_encoding_off, redirect_port_rewrite,
  custom_request_rules, custom_response_rules, updated_by)
VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,$14,$15,$16,$17,$18,$19,$20,$21,$22,$23)
RETURNING version`,
		appID, cfg.ServerAction, cfg.ServerValue, cfg.XPoweredByAction, cfg.XPoweredByValue,
		cfg.XAuthorAction, cfg.XAuthorValue,
		cfg.XFrameOptions, cfg.XFrameOptionsURL, cfg.XXssProtection, cfg.VaryUserAgent,
		cfg.HstsEnabled, cfg.HstsMaxAge, cfg.CspMode, cfg.CspValue,
		cfg.ResponseBuffering, cfg.XffOverwrite, cfg.HostStripPort, cfg.AcceptEncodingOff, cfg.RedirectPortRewrite,
		reqRules, respRules, ub).Scan(&newVersion)
	if err != nil {
		var pgErr *pgconn.PgError
		if errors.As(err, &pgErr) {
			switch pgErr.Code {
			case "23503": // FK：应用不存在
				return 0, ErrAppNotFound
			case "23505": // 并发创建：已存在
				return 0, ErrVersionConflict
			}
		}
		return 0, err
	}
	return newVersion, nil
}

// ListEnabledPathRoutes 查询应用 ENABLED 路径转发（发布侧用；
// 排序：priority 升序，同优先级长前缀优先，与网关评估顺序一致）。
func (s *Store) ListEnabledPathRoutes(ctx context.Context, appID uuid.UUID) ([]gatewayconfig.AppPathRoute, error) {
	rows, err := s.db.Query(ctx, `
SELECT path_prefix, upstream_scheme, upstream_host, upstream_port, strip_prefix, priority
FROM app_path_routes
WHERE application_id = $1 AND status = 'ENABLED'
ORDER BY priority ASC, length(path_prefix) DESC, path_prefix ASC`, appID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := []gatewayconfig.AppPathRoute{}
	for rows.Next() {
		var pr gatewayconfig.AppPathRoute
		if err := rows.Scan(&pr.PathPrefix, &pr.UpstreamScheme, &pr.UpstreamHost, &pr.UpstreamPort, &pr.StripPrefix, &pr.Priority); err != nil {
			return nil, err
		}
		out = append(out, pr)
	}
	return out, rows.Err()
}

// ListPathRoutes 分页查询应用路径转发（priority 升序，前缀字典序，确定性）。
func (s *Store) ListPathRoutes(ctx context.Context, appID uuid.UUID, page, pageSize int) ([]PathRoute, int64, error) {
	if page <= 0 {
		page = 1
	}
	if pageSize <= 0 || pageSize > 100 {
		pageSize = 20
	}
	var total int64
	if err := s.db.QueryRow(ctx, `SELECT count(*) FROM app_path_routes WHERE application_id = $1`, appID).Scan(&total); err != nil {
		return nil, 0, err
	}
	rows, err := s.db.Query(ctx, `
SELECT id, application_id, path_prefix, upstream_scheme, upstream_host, upstream_port,
  strip_prefix, priority, status, description, created_by, created_at, updated_at, version
FROM app_path_routes WHERE application_id = $1
ORDER BY priority ASC, path_prefix ASC, created_at ASC
LIMIT $2 OFFSET $3`, appID, pageSize, (page-1)*pageSize)
	if err != nil {
		return nil, 0, err
	}
	defer rows.Close()
	out := []PathRoute{}
	for rows.Next() {
		r, err := scanPathRoute(rows)
		if err != nil {
			return nil, 0, err
		}
		out = append(out, *r)
	}
	return out, total, rows.Err()
}

// GetPathRoute 查询单条路径转发（限定应用）。
func (s *Store) GetPathRoute(ctx context.Context, appID, routeID uuid.UUID) (*PathRoute, error) {
	row := s.db.QueryRow(ctx, `
SELECT id, application_id, path_prefix, upstream_scheme, upstream_host, upstream_port,
  strip_prefix, priority, status, description, created_by, created_at, updated_at, version
FROM app_path_routes WHERE id = $1 AND application_id = $2`, routeID, appID)
	r, err := scanPathRoute(row)
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return nil, ErrNotFound
		}
		return nil, err
	}
	return r, nil
}

// CreatePathRoute 创建路径转发；应用不存在报 ErrAppNotFound（FK），
// 同前缀+源站重复报 ErrRouteConflict（唯一索引）。
func (s *Store) CreatePathRoute(ctx context.Context, r *PathRoute) error {
	if err := validatePathRoute(r); err != nil {
		return err
	}
	err := s.db.QueryRow(ctx, `
INSERT INTO app_path_routes (application_id, path_prefix, upstream_scheme, upstream_host, upstream_port,
  strip_prefix, priority, status, description, created_by)
VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10)
RETURNING id, created_at, updated_at, version`,
		r.ApplicationID, r.PathPrefix, r.UpstreamScheme, r.UpstreamHost, r.UpstreamPort,
		r.StripPrefix, r.Priority, r.Status, r.Description, r.CreatedBy,
	).Scan(&r.ID, &r.CreatedAt, &r.UpdatedAt, &r.Version)
	if err != nil {
		var pgErr *pgconn.PgError
		if errors.As(err, &pgErr) {
			switch pgErr.Code {
			case "23503":
				return ErrAppNotFound
			case "23505":
				return ErrRouteConflict
			}
		}
		return err
	}
	return nil
}

// UpdatePathRoute 全量更新路径转发（version 乐观锁；r.ID/r.ApplicationID 定位记录）。
func (s *Store) UpdatePathRoute(ctx context.Context, r *PathRoute) error {
	if err := validatePathRoute(r); err != nil {
		return err
	}
	res, err := s.db.Exec(ctx, `
UPDATE app_path_routes SET path_prefix=$3, upstream_scheme=$4, upstream_host=$5, upstream_port=$6,
  strip_prefix=$7, priority=$8, status=$9, description=$10, updated_at=now(), version=version+1
WHERE id=$1 AND application_id=$2 AND version=$11`,
		r.ID, r.ApplicationID, r.PathPrefix, r.UpstreamScheme, r.UpstreamHost, r.UpstreamPort,
		r.StripPrefix, r.Priority, r.Status, r.Description, r.Version)
	if err != nil {
		var pgErr *pgconn.PgError
		if errors.As(err, &pgErr) && pgErr.Code == "23505" {
			return ErrRouteConflict
		}
		return err
	}
	if res.RowsAffected() == 0 {
		if _, err := s.GetPathRoute(ctx, r.ApplicationID, r.ID); errors.Is(err, ErrNotFound) {
			return ErrNotFound
		}
		return ErrVersionConflict
	}
	r.Version++
	return nil
}

// DeletePathRoute 删除路径转发（限定应用）。
func (s *Store) DeletePathRoute(ctx context.Context, appID, routeID uuid.UUID) error {
	res, err := s.db.Exec(ctx, `DELETE FROM app_path_routes WHERE id = $1 AND application_id = $2`, routeID, appID)
	if err != nil {
		return err
	}
	if res.RowsAffected() == 0 {
		return ErrNotFound
	}
	return nil
}

// scanHeaderConfig 扫描 app_header_configs 行（列顺序见 headerConfigColumns）。
func scanHeaderConfig(row pgx.Row) (*HeaderConfigRecord, error) {
	rec := &HeaderConfigRecord{Config: &gatewayconfig.AppHeaderConfig{}}
	var appID uuid.UUID
	var reqRules, respRules []byte
	c := rec.Config
	err := row.Scan(&appID, &c.ServerAction, &c.ServerValue, &c.XPoweredByAction, &c.XPoweredByValue,
		&c.XAuthorAction, &c.XAuthorValue,
		&c.XFrameOptions, &c.XFrameOptionsURL, &c.XXssProtection, &c.VaryUserAgent,
		&c.HstsEnabled, &c.HstsMaxAge, &c.CspMode, &c.CspValue,
		&c.ResponseBuffering, &c.XffOverwrite, &c.HostStripPort, &c.AcceptEncodingOff, &c.RedirectPortRewrite,
		&reqRules, &respRules, &rec.UpdatedBy, &rec.CreatedAt, &rec.UpdatedAt, &rec.Version)
	if err != nil {
		return nil, err
	}
	if len(reqRules) > 0 {
		if err := json.Unmarshal(reqRules, &c.CustomRequestRules); err != nil {
			return nil, fmt.Errorf("unmarshal custom_request_rules: %w", err)
		}
	}
	if len(respRules) > 0 {
		if err := json.Unmarshal(respRules, &c.CustomResponseRules); err != nil {
			return nil, fmt.Errorf("unmarshal custom_response_rules: %w", err)
		}
	}
	return rec, nil
}

func scanPathRoute(row pgx.Row) (*PathRoute, error) {
	var r PathRoute
	err := row.Scan(&r.ID, &r.ApplicationID, &r.PathPrefix, &r.UpstreamScheme, &r.UpstreamHost, &r.UpstreamPort,
		&r.StripPrefix, &r.Priority, &r.Status, &r.Description, &r.CreatedBy, &r.CreatedAt, &r.UpdatedAt, &r.Version)
	if err != nil {
		return nil, err
	}
	return &r, nil
}

// validateHeaderConfig 校验头合规配置（写库前调用，非法输入报 ErrInvalid）。
func validateHeaderConfig(cfg *gatewayconfig.AppHeaderConfig) error {
	if cfg == nil {
		return fmt.Errorf("%w: 配置不能为空", ErrInvalid)
	}
	if !headerActions[cfg.ServerAction] {
		return fmt.Errorf("%w: server_action 取值无效（keep/hide/replace）", ErrInvalid)
	}
	if !headerActions[cfg.XPoweredByAction] {
		return fmt.Errorf("%w: x_powered_by_action 取值无效（keep/hide/replace）", ErrInvalid)
	}
	if !headerActions[cfg.XAuthorAction] {
		return fmt.Errorf("%w: x_author_action 取值无效（keep/hide/replace）", ErrInvalid)
	}
	if len(cfg.ServerValue) > 255 || len(cfg.XPoweredByValue) > 255 || len(cfg.XAuthorValue) > 255 {
		return fmt.Errorf("%w: server_value/x_author_value/x_powered_by_value 长度不能超过 255", ErrInvalid)
	}
	if !frameOptions[cfg.XFrameOptions] {
		return fmt.Errorf("%w: x_frame_options 取值无效（default/inherit/deny/sameorigin/allow_from）", ErrInvalid)
	}
	if cfg.XFrameOptions == "allow_from" && strings.TrimSpace(cfg.XFrameOptionsURL) == "" {
		return fmt.Errorf("%w: x_frame_options 为 allow_from 时必须提供 x_frame_options_url", ErrInvalid)
	}
	if len(cfg.XFrameOptionsURL) > 512 {
		return fmt.Errorf("%w: x_frame_options_url 长度不能超过 512", ErrInvalid)
	}
	if cfg.HstsMaxAge <= 0 {
		return fmt.Errorf("%w: hsts_max_age 必须大于 0", ErrInvalid)
	}
	if !cspModes[cfg.CspMode] {
		return fmt.Errorf("%w: csp_mode 取值无效（off/preset/custom）", ErrInvalid)
	}
	if cfg.CspMode == "custom" && strings.TrimSpace(cfg.CspValue) == "" {
		return fmt.Errorf("%w: csp_mode 为 custom 时必须提供 csp_value", ErrInvalid)
	}
	if err := validateHeaderRules("custom_request_rules", cfg.CustomRequestRules); err != nil {
		return err
	}
	if err := validateHeaderRules("custom_response_rules", cfg.CustomResponseRules); err != nil {
		return err
	}
	return nil
}

// validateHeaderRules 校验自定义头修改规则：method ∈ set|add|delete、
// name 必填且为合法 header 名、delete 时 value 必须为空。
func validateHeaderRules(field string, rules []gatewayconfig.HeaderRule) error {
	if len(rules) > 64 {
		return fmt.Errorf("%w: %s 规则数量不能超过 64", ErrInvalid, field)
	}
	for i, rule := range rules {
		name := strings.TrimSpace(rule.Name)
		if name == "" {
			return fmt.Errorf("%w: %s[%d] name 不能为空", ErrInvalid, field, i)
		}
		if len(name) > 255 || !headerNameRe.MatchString(name) {
			return fmt.Errorf("%w: %s[%d] name 不是合法的 HTTP 头字段名", ErrInvalid, field, i)
		}
		if !ruleMethods[rule.Method] {
			return fmt.Errorf("%w: %s[%d] method 取值无效（set/add/delete）", ErrInvalid, field, i)
		}
		if rule.Method == "delete" && rule.Value != "" {
			return fmt.Errorf("%w: %s[%d] method 为 delete 时 value 必须为空", ErrInvalid, field, i)
		}
	}
	return nil
}

// validatePathRoute 校验路径转发规则（写库前调用，非法输入报 ErrInvalid）。
func validatePathRoute(r *PathRoute) error {
	if r == nil {
		return fmt.Errorf("%w: 路径转发不能为空", ErrInvalid)
	}
	prefix := r.PathPrefix
	if prefix == "" || len(prefix) > 512 || !strings.HasPrefix(prefix, "/") {
		return fmt.Errorf("%w: path_prefix 必须以 / 开头且长度不超过 512", ErrInvalid)
	}
	if strings.ContainsAny(prefix, "?#") {
		return fmt.Errorf("%w: path_prefix 不能包含 ? 或 #", ErrInvalid)
	}
	if strings.Contains(prefix, "..") {
		return fmt.Errorf("%w: path_prefix 不能包含 ..", ErrInvalid)
	}
	if strings.TrimSpace(r.UpstreamHost) == "" || len(r.UpstreamHost) > 255 {
		return fmt.Errorf("%w: upstream_host 不能为空且长度不能超过 255", ErrInvalid)
	}
	if r.UpstreamPort < 1 || r.UpstreamPort > 65535 {
		return fmt.Errorf("%w: upstream_port 必须在 1-65535 之间", ErrInvalid)
	}
	if !upstreamSchemes[r.UpstreamScheme] {
		return fmt.Errorf("%w: upstream_scheme 取值无效（http/https）", ErrInvalid)
	}
	if !routeStatuses[r.Status] {
		return fmt.Errorf("%w: status 取值无效（ENABLED/DISABLED）", ErrInvalid)
	}
	if len(r.Description) > 255 {
		return fmt.Errorf("%w: description 长度不能超过 255", ErrInvalid)
	}
	return nil
}

// rulesOrEmpty 保证 JSONB 写入 [] 而非 null。
func rulesOrEmpty(rules []gatewayconfig.HeaderRule) []gatewayconfig.HeaderRule {
	if rules == nil {
		return []gatewayconfig.HeaderRule{}
	}
	return rules
}

// store.go client_identity 体系管理面查询与手工封禁状态迁移。
package securityidentities

import (
	"context"
	"errors"
	"fmt"
	"strings"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgxpool"
)

// ErrNotFound 身份不存在。
var ErrNotFound = errors.New("identity not found")

// normalizeIdentityType keeps records written by the retired MACHINE contract
// readable without exposing that value through the management API.
func normalizeIdentityType(identityType string) string {
	if identityType == "MACHINE" {
		return "UNKNOWN"
	}
	return identityType
}

// 排序字段白名单（防注入；缺省 last_seen_at DESC）。
var validSortFields = map[string]string{
	"last_seen_at":  "last_seen_at",
	"first_seen_at": "first_seen_at",
	"risk_score":    "risk_score",
	"request_count": "request_count",
}

// identityColumns 详情查询列清单（与 scanIdentity 顺序一致）。
const identityColumns = `id, identity_key, identity_type, first_seen_at, last_seen_at, primary_ip,
  identity_confidence, confidence_source, asn, tls_fingerprint, browser_fingerprint, account_id, jwt_subject, api_key_hash, oauth_client_id,
  device_type, risk_score, risk_level, status, request_count,
  blocked_reason, blocked_by, blocked_at, unblocked_by, unblocked_at, created_at, updated_at`

// Store 是 client_identity 体系查询仓储。
type Store struct {
	db *pgxpool.Pool
}

// NewStore 创建仓储。
func NewStore(db *pgxpool.Pool) *Store {
	return &Store{db: db}
}

// List 分页查询身份列表（默认 last_seen_at DESC；ip_count 为 identity_ip_history 子查询聚合）。
func (s *Store) List(ctx context.Context, f ListFilter) ([]ListItem, int64, error) {
	if f.Page <= 0 {
		f.Page = 1
	}
	if f.PageSize <= 0 || f.PageSize > 100 {
		f.PageSize = 20
	}
	// MACHINE is a legacy value retained only for backward-compatible reads. It
	// must not appear in the current management list or affect its pagination.
	where := "identity_type <> 'MACHINE'"
	args := []interface{}{}
	argIdx := 1
	add := func(cond string, v interface{}) {
		where += fmt.Sprintf(" AND "+cond, argIdx)
		args = append(args, v)
		argIdx++
	}
	if f.RiskLevel != "" {
		add("risk_level = $%d", f.RiskLevel)
	}
	if f.IdentityType != "" {
		add("identity_type = $%d", f.IdentityType)
	}
	if f.Keyword != "" {
		where += fmt.Sprintf(" AND (identity_key ILIKE $%d || '%%' OR account_id ILIKE '%%' || $%d || '%%')", argIdx, argIdx)
		args = append(args, f.Keyword)
		argIdx++
	}
	if f.IP != "" {
		add("EXISTS (SELECT 1 FROM identity_ip_history h WHERE h.identity_id = client_identity.id AND h.ip = $%d)", f.IP)
	}
	if f.From != nil {
		add("last_seen_at >= $%d", *f.From)
	}
	if f.To != nil {
		add("last_seen_at <= $%d", *f.To)
	}

	var total int64
	if err := s.db.QueryRow(ctx, `SELECT count(*) FROM client_identity WHERE `+where, args...).Scan(&total); err != nil {
		return nil, 0, err
	}

	sortCol := validSortFields[f.Sort]
	if sortCol == "" {
		sortCol = "last_seen_at"
	}
	order := "DESC"
	if strings.EqualFold(f.Order, "asc") {
		order = "ASC"
	}
	query := `SELECT id, identity_key, identity_type, identity_confidence, risk_score, risk_level, status, primary_ip,
  (SELECT count(*) FROM identity_ip_history h WHERE h.identity_id = client_identity.id) AS ip_count,
  account_id, request_count, first_seen_at, last_seen_at
FROM client_identity WHERE ` + where +
		fmt.Sprintf(" ORDER BY %s %s, id DESC LIMIT $%d OFFSET $%d", sortCol, order, argIdx, argIdx+1)
	args = append(args, f.PageSize, (f.Page-1)*f.PageSize)
	rows, err := s.db.Query(ctx, query, args...)
	if err != nil {
		return nil, 0, err
	}
	defer rows.Close()
	out := make([]ListItem, 0, f.PageSize)
	for rows.Next() {
		var it ListItem
		if err := rows.Scan(&it.ID, &it.IdentityKey, &it.IdentityType, &it.IdentityConfidence, &it.RiskScore, &it.RiskLevel,
			&it.Status, &it.PrimaryIP, &it.IPCount, &it.AccountID, &it.RequestCount,
			&it.FirstSeenAt, &it.LastSeenAt); err != nil {
			return nil, 0, err
		}
		it.IdentityType = normalizeIdentityType(it.IdentityType)
		out = append(out, it)
	}
	return out, total, rows.Err()
}

// GetByID 查询身份全字段。
func (s *Store) GetByID(ctx context.Context, id uuid.UUID) (*Identity, error) {
	return scanIdentity(s.db.QueryRow(ctx, `SELECT `+identityColumns+` FROM client_identity WHERE id = $1`, id))
}

// ListIPHistory 身份 IP 历史（按 last_seen_at DESC 全量）。
func (s *Store) ListIPHistory(ctx context.Context, identityID uuid.UUID) ([]IPHistory, error) {
	rows, err := s.db.Query(ctx, `
SELECT ip, first_seen_at, last_seen_at, request_count
FROM identity_ip_history WHERE identity_id = $1 ORDER BY last_seen_at DESC NULLS LAST`, identityID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := []IPHistory{}
	for rows.Next() {
		var h IPHistory
		if err := rows.Scan(&h.IP, &h.FirstSeenAt, &h.LastSeenAt, &h.RequestCount); err != nil {
			return nil, err
		}
		out = append(out, h)
	}
	return out, rows.Err()
}

// ListCredentials 身份凭据指纹列表（类型 + 哈希 + 首末次观测）。
func (s *Store) ListCredentials(ctx context.Context, identityID uuid.UUID) ([]CredentialItem, error) {
	rows, err := s.db.Query(ctx, `
SELECT credential_type, credential_hash, first_seen_at, last_seen_at
FROM identity_credential WHERE identity_id = $1 ORDER BY last_seen_at DESC NULLS LAST`, identityID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := []CredentialItem{}
	for rows.Next() {
		var c CredentialItem
		if err := rows.Scan(&c.CredentialType, &c.CredentialHash, &c.FirstSeenAt, &c.LastSeenAt); err != nil {
			return nil, err
		}
		out = append(out, c)
	}
	return out, rows.Err()
}

// ListRecentEvents 身份最近信号事件（详情接口内嵌，最近 limit 条）。
func (s *Store) ListRecentEvents(ctx context.Context, identityID uuid.UUID, limit int) ([]BehaviorEvent, error) {
	if limit <= 0 || limit > 100 {
		limit = 20
	}
	events, _, err := s.queryEvents(ctx, identityID, EventFilter{Page: 1, PageSize: limit})
	return events, err
}

// ListEvents 身份信号事件分页（occurred_at DESC）。
func (s *Store) ListEvents(ctx context.Context, identityID uuid.UUID, f EventFilter) ([]BehaviorEvent, int64, error) {
	return s.queryEvents(ctx, identityID, f)
}

// eventColumns 事件查询列清单（与 scanEvents 顺序一致；迁移契约中 reason/request_id 等
// 为可空列带默认值，COALESCE 兜底直接 SQL 写入的 NULL 行）。
const eventColumns = `id, occurred_at, event_kind, rule_code, rule_version, signal, risk_score_delta,
  mode, COALESCE(reason,''), metadata, COALESCE(request_id,''), COALESCE(client_ip,''), COALESCE(method,''),
  COALESCE(path,''), COALESCE(app_id,''), COALESCE(domain,''), COALESCE(gateway_node,''),
  COALESCE(identity_confidence,0), COALESCE(identity_evidence,'[]'::jsonb)`

func (s *Store) queryEvents(ctx context.Context, identityID uuid.UUID, f EventFilter) ([]BehaviorEvent, int64, error) {
	if f.Page <= 0 {
		f.Page = 1
	}
	if f.PageSize <= 0 || f.PageSize > 100 {
		f.PageSize = 20
	}
	where := "identity_id = $1"
	args := []interface{}{identityID}
	argIdx := 2
	if f.Signal != "" {
		where += fmt.Sprintf(" AND signal = $%d", argIdx)
		args = append(args, f.Signal)
		argIdx++
	}
	if f.From != nil {
		where += fmt.Sprintf(" AND occurred_at >= $%d", argIdx)
		args = append(args, *f.From)
		argIdx++
	}
	if f.To != nil {
		where += fmt.Sprintf(" AND occurred_at <= $%d", argIdx)
		args = append(args, *f.To)
		argIdx++
	}
	var total int64
	if err := s.db.QueryRow(ctx, `SELECT count(*) FROM identity_behavior_events WHERE `+where, args...).Scan(&total); err != nil {
		return nil, 0, err
	}
	query := `SELECT ` + eventColumns + ` FROM identity_behavior_events WHERE ` + where +
		fmt.Sprintf(" ORDER BY occurred_at DESC, id DESC LIMIT $%d OFFSET $%d", argIdx, argIdx+1)
	args = append(args, f.PageSize, (f.Page-1)*f.PageSize)
	rows, err := s.db.Query(ctx, query, args...)
	if err != nil {
		return nil, 0, err
	}
	defer rows.Close()
	out := make([]BehaviorEvent, 0, f.PageSize)
	for rows.Next() {
		var ev BehaviorEvent
		if err := rows.Scan(&ev.ID, &ev.OccurredAt, &ev.EventKind, &ev.RuleCode, &ev.RuleVersion, &ev.Signal,
			&ev.RiskScoreDelta, &ev.Mode, &ev.Reason, &ev.Metadata, &ev.RequestID, &ev.ClientIP,
			&ev.Method, &ev.Path, &ev.AppID, &ev.Domain, &ev.GatewayNode, &ev.IdentityConfidence, &ev.IdentityEvidence); err != nil {
			return nil, 0, err
		}
		out = append(out, ev)
	}
	return out, total, rows.Err()
}

// statColumns 行为窗口统计查询列清单。
const statColumns = `window_type, window_start, request_count, unique_uri_count, new_uri_count,
  status_401_count, status_403_count, status_404_count, status_405_count, status_500_count,
  auth_fail_count, parameter_mutation_count, sensitive_path_hits, account_enum_count, object_enum_count`

// ListBehavior 身份行为窗口统计时间序列（window_start ASC 便于趋势图；window 缺省全部窗口）。
func (s *Store) ListBehavior(ctx context.Context, identityID uuid.UUID, f BehaviorFilter) ([]BehaviorStat, int64, error) {
	if f.Page <= 0 {
		f.Page = 1
	}
	if f.PageSize <= 0 || f.PageSize > 200 {
		f.PageSize = 50
	}
	where := "identity_id = $1"
	args := []interface{}{identityID}
	argIdx := 2
	if f.Window != "" {
		where += fmt.Sprintf(" AND window_type = $%d", argIdx)
		args = append(args, f.Window)
		argIdx++
	}
	where += fmt.Sprintf(" AND window_start >= $%d AND window_start <= $%d", argIdx, argIdx+1)
	args = append(args, f.From, f.To)
	argIdx += 2

	var total int64
	if err := s.db.QueryRow(ctx, `SELECT count(*) FROM behavior_statistics WHERE `+where, args...).Scan(&total); err != nil {
		return nil, 0, err
	}
	query := `SELECT ` + statColumns + ` FROM behavior_statistics WHERE ` + where +
		fmt.Sprintf(" ORDER BY window_start ASC, window_type ASC LIMIT $%d OFFSET $%d", argIdx, argIdx+1)
	args = append(args, f.PageSize, (f.Page-1)*f.PageSize)
	rows, err := s.db.Query(ctx, query, args...)
	if err != nil {
		return nil, 0, err
	}
	defer rows.Close()
	out := make([]BehaviorStat, 0, f.PageSize)
	for rows.Next() {
		var st BehaviorStat
		if err := rows.Scan(&st.WindowType, &st.WindowStart, &st.RequestCount, &st.UniqueURICount, &st.NewURICount,
			&st.Status401Count, &st.Status403Count, &st.Status404Count, &st.Status405Count, &st.Status500Count,
			&st.AuthFailCount, &st.ParameterMutationCount, &st.SensitivePathHits, &st.AccountEnumCount, &st.ObjectEnumCount); err != nil {
			return nil, 0, err
		}
		out = append(out, st)
	}
	return out, total, rows.Err()
}

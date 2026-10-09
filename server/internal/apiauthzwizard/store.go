// store.go 向导数据 PostgreSQL 仓储：readiness/影响评估的事实采集（对象模型行、
// 有效 OWNER 关系、OPEN 冲突、应用租约）与确认单生命周期写入。
// 节点 ACK 事实复用 apiauthzacks（ack_state 五态已在该包派生——本包不重复实现）。
package apiauthzwizard

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
)

// DBTX 最小数据库句柄（*pgxpool.Pool 与 pgx.Tx 均满足——ConsumeConfirmToken
// 在 apisecurity PATCH 的切换事务内以 pgx.Tx 调用）。
type DBTX interface {
	Exec(ctx context.Context, sql string, args ...any) (pgconn.CommandTag, error)
	Query(ctx context.Context, sql string, args ...any) (pgx.Rows, error)
	QueryRow(ctx context.Context, sql string, args ...any) pgx.Row
}

// Store 向导仓储。
type Store struct {
	db *pgxpool.Pool
}

// NewStore 创建。
func NewStore(db *pgxpool.Pool) *Store { return &Store{db: db} }

// DB 返回底层池（app 装配 ACK store 复用同池）。
func (s *Store) DB() *pgxpool.Pool { return s.db }

// ObjectModelRow 对象模型行（readiness 派生与影响评估的事实源）。
type ObjectModelRow struct {
	ID                uuid.UUID `json:"id"`
	EndpointID        uuid.UUID `json:"endpoint_id"`
	EndpointKey       string    `json:"endpoint_key"`
	ObjectSegment     string    `json:"object_segment"`
	ObjectType        string    `json:"object_type"` // 编译同口径（path:<pos> 前段/query:<名>）
	ApplicationID     uuid.UUID `json:"application_id"`
	Publishable       bool      `json:"publishable"`
	RequiredRelation  string    `json:"required_relation"`
	OwnerExclusive    bool      `json:"owner_exclusive"`
	Enforcement       string    `json:"enforcement"`
	EndpointConfirmed bool      `json:"endpoint_confirmed"`
}

// objectTypeOf 编译同口径对象类型（guardconfig.compileObjectSegment 的服务端翻译：
// path:<pos> 取 normalized_path 第 pos 段的前一非占位段，query:<名> 即参数名；
// 翻译不出（段序越界/非占位缺失）回退为参数名——冲突/关系判定按键宁可窄不可宽）。
func objectTypeOf(pathTemplate, segment string) string {
	if strings.HasPrefix(segment, "query:") {
		return strings.TrimSpace(strings.TrimPrefix(segment, "query:"))
	}
	if !strings.HasPrefix(segment, "path:") {
		return ""
	}
	parts := strings.Split(strings.Trim(pathTemplate, "/"), "/")
	pos := 0
	if _, err := fmt.Sscanf(strings.TrimPrefix(segment, "path:"), "%d", &pos); err != nil {
		return ""
	}
	if pos <= 0 || pos >= len(parts) {
		return ""
	}
	name := strings.TrimSuffix(strings.TrimPrefix(parts[pos], "{"), "}")
	if name == parts[pos] || name == "" {
		return ""
	}
	if !strings.ContainsAny(parts[pos-1], "{}") {
		return parts[pos-1]
	}
	return name
}

const listObjectModelRowsSQL = `
SELECT m.id, m.endpoint_id, COALESCE(e.endpoint_key, ''), m.object_segment,
       COALESCE(e.normalized_path, ''), COALESCE(e.application_id, m.endpoint_id),
       m.publishable, COALESCE(m.required_relation, ''), m.owner_exclusive, m.enforcement,
       (e.asset_status = 'CONFIRMED')
FROM api_object_models m
LEFT JOIN api_endpoints e ON e.id = m.endpoint_id`

// scanObjectModelRow 行扫描（application_id 直取 api_endpoints 列——对象模型无应用列）。
func scanObjectModelRow(row pgx.Row) (ObjectModelRow, error) {
	var r ObjectModelRow
	var pathTemplate string
	err := row.Scan(&r.ID, &r.EndpointID, &r.EndpointKey, &r.ObjectSegment,
		&pathTemplate, &r.ApplicationID,
		&r.Publishable, &r.RequiredRelation, &r.OwnerExclusive, &r.Enforcement,
		&r.EndpointConfirmed)
	r.ObjectType = objectTypeOf(pathTemplate, r.ObjectSegment)
	return r, err
}

// ListObjectModelRows 对象模型行查询（endpoint_id 可空=按应用全量；application_id 必填）。
func (s *Store) ListObjectModelRows(ctx context.Context, applicationID, endpointID uuid.UUID) ([]ObjectModelRow, error) {
	cond := " WHERE e.application_id = $1"
	args := []any{applicationID}
	if endpointID != uuid.Nil {
		args = append(args, endpointID)
		cond += fmt.Sprintf(" AND m.endpoint_id = $%d", len(args))
	}
	rows, err := s.db.Query(ctx, listObjectModelRowsSQL+cond+" ORDER BY e.endpoint_key, m.object_segment", args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := []ObjectModelRow{}
	for rows.Next() {
		r, err := scanObjectModelRow(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, r)
	}
	return out, rows.Err()
}

// GetObjectModelRow 按对象模型行 ID 取行（PATCH token 绑定核对用）。
func (s *Store) GetObjectModelRow(ctx context.Context, id uuid.UUID) (ObjectModelRow, error) {
	r, err := scanObjectModelRow(s.db.QueryRow(ctx, listObjectModelRowsSQL+" WHERE m.id = $1", id))
	if errors.Is(err, pgx.ErrNoRows) {
		return ObjectModelRow{}, ErrNotFound
	}
	return r, err
}

// ErrNotFound 行不存在哨兵。
var ErrNotFound = errors.New("apiauthzwizard: not found")

// HasEffectiveOwnerRelation 该应用+对象类型存在有效 OWNER 关系
// （CONFIRMED 且 valid_from 已生效、valid_until 未过期——与发布编译 WHERE 同口径）。
func (s *Store) HasEffectiveOwnerRelation(ctx context.Context, applicationID uuid.UUID, objectType string, now time.Time) (bool, error) {
	if objectType == "" {
		return false, nil
	}
	var exists bool
	err := s.db.QueryRow(ctx, `SELECT EXISTS(
	SELECT 1 FROM api_object_relations
	WHERE application_id=$1 AND object_type=$2 AND status='CONFIRMED' AND relation='OWNER'
	  AND valid_from <= $3 AND (valid_until IS NULL OR valid_until > $3))`,
		applicationID, objectType, now).Scan(&exists)
	return exists, err
}

// HasOpenConflict 该应用+对象类型存在 OPEN 冲突。
func (s *Store) HasOpenConflict(ctx context.Context, applicationID uuid.UUID, objectType string) (bool, error) {
	if objectType == "" {
		return false, nil
	}
	var exists bool
	err := s.db.QueryRow(ctx, `SELECT EXISTS(
	SELECT 1 FROM api_authority_conflicts WHERE application_id=$1 AND object_type=$2 AND status='OPEN')`,
		applicationID, objectType).Scan(&exists)
	return exists, err
}

// AppLeaseSeconds 应用授权租约秒数（NULL/≤0 = 未配置）。
func (s *Store) AppLeaseSeconds(ctx context.Context, applicationID uuid.UUID) (int, error) {
	var sec *int
	err := s.db.QueryRow(ctx, `SELECT authz_lease_seconds FROM applications WHERE id=$1 AND deleted_at IS NULL`, applicationID).Scan(&sec)
	if errors.Is(err, pgx.ErrNoRows) {
		return 0, ErrNotFound
	}
	if err != nil || sec == nil {
		return 0, err
	}
	return *sec, nil
}

// ---------- 确认单（§1.4 生命周期：签发→签署→消费） ----------

// Confirmation 确认单行（查询出参）。
type Confirmation struct {
	ID               uuid.UUID  `json:"id"`
	ConfirmToken     uuid.UUID  `json:"confirm_token"`
	ApplicationID    uuid.UUID  `json:"application_id"`
	EndpointID       uuid.UUID  `json:"endpoint_id"`
	EndpointKey      string     `json:"endpoint_key"`
	ObjectSegment    string     `json:"object_segment"`
	WindowDays       int        `json:"window_days"`
	ImpactSnapshot   []byte     `json:"impact_snapshot"`
	ConfirmText      string     `json:"confirm_text"`
	EnforcementOwner string     `json:"enforcement_owner"`
	EvidenceSource   string     `json:"evidence_source"`
	OnUnknown        string     `json:"on_unknown"`
	ConfirmedByName  string     `json:"confirmed_by_name"`
	CreatedAt        time.Time  `json:"created_at"`
	TokenExpiresAt   time.Time  `json:"token_expires_at"`
	SignedAt         *time.Time `json:"signed_at"`
	ConsumedAt       *time.Time `json:"consumed_at"`
	ConsumedAuditID  string     `json:"consumed_audit_id"`
}

// confirmTokenTTL 一次性签署令牌 TTL（§1.4 冻结：签发后 15 分钟）。
const confirmTokenTTL = 15 * time.Minute

// IssueConfirmation 签发确认单（影响评估 manage 调用内；返回令牌与到期时刻）。
func (s *Store) IssueConfirmation(ctx context.Context, applicationID, endpointID uuid.UUID, objectSegment string, windowDays int, impactSnapshot []byte, now time.Time) (uuid.UUID, time.Time, error) {
	token := uuid.New()
	expires := now.Add(confirmTokenTTL)
	_, err := s.db.Exec(ctx, `INSERT INTO api_authz_enforcement_confirmations
	(confirm_token, application_id, endpoint_id, object_segment, window_days, impact_snapshot, token_expires_at)
	VALUES ($1,$2,$3,$4,$5,$6::jsonb,$7)`,
		token, applicationID, endpointID, objectSegment, windowDays, impactSnapshot, expires)
	return token, expires, err
}

const confirmationCols = `c.id, c.confirm_token, c.application_id, c.endpoint_id,
	COALESCE(e.endpoint_key,''), c.object_segment, c.window_days, c.impact_snapshot, c.confirm_text,
	c.enforcement_owner, c.evidence_source, c.on_unknown, c.confirmed_by_name,
	c.created_at, c.token_expires_at, c.signed_at, c.consumed_at, c.consumed_audit_id`

func scanConfirmation(row pgx.Row) (Confirmation, error) {
	var c Confirmation
	err := row.Scan(&c.ID, &c.ConfirmToken, &c.ApplicationID, &c.EndpointID,
		&c.EndpointKey, &c.ObjectSegment, &c.WindowDays, &c.ImpactSnapshot, &c.ConfirmText,
		&c.EnforcementOwner, &c.EvidenceSource, &c.OnUnknown, &c.ConfirmedByName,
		&c.CreatedAt, &c.TokenExpiresAt, &c.SignedAt, &c.ConsumedAt, &c.ConsumedAuditID)
	return c, err
}

// ListConfirmations 确认单分页查询（application_id/endpoint_id 过滤，created_at 倒序）。
func (s *Store) ListConfirmations(ctx context.Context, applicationID, endpointID uuid.UUID, page, pageSize int) ([]Confirmation, int64, error) {
	if page <= 0 {
		page = 1
	}
	if pageSize <= 0 {
		pageSize = 20
	}
	where, args := []string{}, []any{}
	if applicationID != uuid.Nil {
		args = append(args, applicationID)
		where = append(where, fmt.Sprintf("c.application_id = $%d", len(args)))
	}
	if endpointID != uuid.Nil {
		args = append(args, endpointID)
		where = append(where, fmt.Sprintf("c.endpoint_id = $%d", len(args)))
	}
	cond := ""
	if len(where) > 0 {
		cond = " WHERE " + strings.Join(where, " AND ")
	}
	join := " FROM api_authz_enforcement_confirmations c LEFT JOIN api_endpoints e ON e.id = c.endpoint_id"
	var total int64
	if err := s.db.QueryRow(ctx, "SELECT count(*)"+join+cond, args...).Scan(&total); err != nil {
		return nil, 0, err
	}
	args = append(args, pageSize, (page-1)*pageSize)
	rows, err := s.db.Query(ctx, `SELECT `+confirmationCols+join+cond+
		fmt.Sprintf(" ORDER BY c.created_at DESC, c.id LIMIT $%d OFFSET $%d", len(args)-1, len(args)), args...)
	if err != nil {
		return nil, 0, err
	}
	defer rows.Close()
	out := []Confirmation{}
	for rows.Next() {
		c, err := scanConfirmation(rows)
		if err != nil {
			return nil, 0, err
		}
		out = append(out, c)
	}
	return out, total, rows.Err()
}

// SignConfirmation 签署确认单（按 confirm_token 列查找更新——向导/前端只持有令牌；
// signed_at + 四要素 + 确认文案回填；不存在/未消费/未过期/未签署四类违规精确区分——
// ErrNotFound / ErrConsumed / ErrExpired / ErrAlreadySigned）。
func (s *Store) SignConfirmation(ctx context.Context, token uuid.UUID, owner, evidenceSource, onUnknown, confirmText string, signedBy uuid.UUID, signedByName string, now time.Time) (*Confirmation, error) {
	ct, err := s.db.Exec(ctx, `UPDATE api_authz_enforcement_confirmations
	SET signed_at=$2, confirmed_by=$3, confirmed_by_name=$4,
	    enforcement_owner=$5, evidence_source=$6, on_unknown=$7, confirm_text=$8
	WHERE confirm_token=$1 AND consumed_at IS NULL AND signed_at IS NULL AND token_expires_at > $2`,
		token, now, signedBy, signedByName, owner, evidenceSource, onUnknown, confirmText)
	if err != nil {
		return nil, err
	}
	if ct.RowsAffected() == 0 {
		// 区分失败类别（精确消息：不存在/已签署/已消费/已过期）
		var consumedAt, signedAt *time.Time
		var expires time.Time
		err := s.db.QueryRow(ctx, `SELECT consumed_at, signed_at, token_expires_at FROM api_authz_enforcement_confirmations WHERE confirm_token=$1`, token).
			Scan(&consumedAt, &signedAt, &expires)
		if errors.Is(err, pgx.ErrNoRows) {
			return nil, ErrNotFound
		}
		if err != nil {
			return nil, err
		}
		switch {
		case consumedAt != nil:
			return nil, ErrConsumed
		case signedAt != nil:
			return nil, ErrAlreadySigned
		default:
			return nil, ErrExpired
		}
	}
	c, err := scanConfirmation(s.db.QueryRow(ctx, `SELECT `+confirmationCols+`
	FROM api_authz_enforcement_confirmations c LEFT JOIN api_endpoints e ON e.id = c.endpoint_id WHERE c.confirm_token=$1`, token))
	if err != nil {
		return nil, err
	}
	return &c, nil
}

// 生命周期哨兵（精确消息区分；PATCH 与 sign 共用）。
var (
	ErrConsumed       = errors.New("confirmation already consumed")
	ErrExpired        = errors.New("confirmation token expired")
	ErrAlreadySigned  = errors.New("confirmation already signed")
	ErrNotSigned      = errors.New("confirmation not signed")
	ErrTokenMismatch  = errors.New("confirmation endpoint binding mismatch")
	ErrInvalidTokenID = errors.New("confirmation token not found")
)

// ConsumeConfirmToken PATCH enforcement=PROTECT 同事务消费（§1.4/D4）：
// 校验（存在/未消费/未过期/端点×对象段绑定/已签署，五类精确区分）→ 置
// consumed_at + consumed_audit_id（request_id，审计按 request_id 反查溯源）。
// db 为 PATCH 切换事务句柄（pgx.Tx）；任一校验失败返回哨兵错误由调用方整体回滚
// ——不留半切换状态。
func ConsumeConfirmToken(ctx context.Context, db DBTX, token, endpointID uuid.UUID, objectSegment, requestID string, now time.Time) error {
	var (
		endpoint             uuid.UUID
		segment              string
		consumedAt, signedAt *time.Time
		expires              time.Time
	)
	err := db.QueryRow(ctx, `SELECT endpoint_id, object_segment, consumed_at, signed_at, token_expires_at
	FROM api_authz_enforcement_confirmations WHERE confirm_token=$1 FOR UPDATE`, token).
		Scan(&endpoint, &segment, &consumedAt, &signedAt, &expires)
	if errors.Is(err, pgx.ErrNoRows) {
		return ErrInvalidTokenID
	}
	if err != nil {
		return fmt.Errorf("load confirmation token: %w", err)
	}
	switch {
	case consumedAt != nil:
		return ErrConsumed
	case !expires.After(now):
		return ErrExpired
	case endpoint != endpointID || segment != objectSegment:
		return ErrTokenMismatch
	case signedAt == nil:
		return ErrNotSigned
	}
	ct, err := db.Exec(ctx, `UPDATE api_authz_enforcement_confirmations
	SET consumed_at=$2, consumed_audit_id=$3 WHERE confirm_token=$1 AND consumed_at IS NULL`,
		token, now, requestID)
	if err != nil {
		return fmt.Errorf("consume confirmation token: %w", err)
	}
	if ct.RowsAffected() == 0 {
		return ErrConsumed
	}
	return nil
}

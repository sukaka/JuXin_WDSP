// Package temporaryblocks 提供临时封禁管理：数据库记录 + Valkey 封禁键同步。
//
// Valkey 封禁键协议（与网关 jiuzhang_guard/temporaryblock 模块约定，禁止改动）：
//   - 哈希键：jiuzhang:guard:tempblocks
//   - field：BlockFieldKey(ip, appID)，长度前缀编码的 sha256 前 32 位十六进制
//   - value：JSON {"id","client_ip","application_id","expires_at","reason","auto"}
package temporaryblocks

import (
	"context"
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"net/netip"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/jiuzhang-waf/server/internal/accessrules"
	"github.com/jiuzhang-waf/server/internal/cache"
)

// HashKey 是 Valkey 封禁哈希键（与网关约定一致）。
const HashKey = "jiuzhang:guard:tempblocks"

// 封禁状态
const (
	StatusActive           = "ACTIVE"
	StatusExpired          = "EXPIRED"
	StatusManuallyReleased = "MANUALLY_RELEASED"
	StatusCancelled        = "CANCELLED"
)

// 解除类型
const (
	ReleaseTypeAutoExpire = "AUTO_EXPIRE"
	ReleaseTypeManual     = "MANUAL"
	ReleaseTypeConverted  = "CONVERTED"
)

// 触发类型
const (
	TriggerCCAuto = "CC_AUTO"
	TriggerManual = "MANUAL"
)

// 错误
var (
	ErrNotFound           = errors.New("temporary block not found")
	ErrNotActive          = errors.New("temporary block is not active")
	ErrInvalidExpiry      = errors.New("invalid block expiry time")
	ErrConvertUnsupported = errors.New("permanent rule creator not configured")
)

// PermanentRuleCreator 由 accessrules.Store 实现（构造注入，可为 nil，
// nil 时 ConvertToPermanent 返回 ErrConvertUnsupported）。
type PermanentRuleCreator interface {
	Create(ctx context.Context, in accessrules.CreateInput, createdBy uuid.UUID) (*accessrules.Rule, error)
}

// BlockFieldKey 计算封禁哈希 field：对 ip 和 appID 两个部分，
// 每部分先写 4 字节大端长度再写字节，整体 sha256，hex 取前 32 字符。
// appID 为空串表示全局。与网关 counters.HashParts(ip, appID) 严格一致。
func BlockFieldKey(ip, appID string) string {
	h := sha256.New()
	for _, part := range []string{ip, appID} {
		b := []byte(part)
		var lb [4]byte
		binary.BigEndian.PutUint32(lb[:], uint32(len(b)))
		h.Write(lb[:])
		h.Write(b)
	}
	return hex.EncodeToString(h.Sum(nil))[:32]
}

// Block 是临时封禁记录。
type Block struct {
	ID              uuid.UUID  `json:"id"`
	ClientIP        string     `json:"client_ip"`
	ApplicationID   *uuid.UUID `json:"application_id"` // NULL = 全局
	TriggerType     string     `json:"trigger_type"`
	TriggerPolicyID *uuid.UUID `json:"trigger_policy_id"`
	TriggerEventIDs []string   `json:"trigger_event_ids"`
	BlockStartedAt  time.Time  `json:"block_started_at"`
	BlockExpiresAt  time.Time  `json:"block_expires_at"`
	Status          string     `json:"status"`
	HitCount        int64      `json:"hit_count"`
	ReleaseType     string     `json:"release_type,omitempty"`
	ReleasedBy      *uuid.UUID `json:"released_by"`
	ReleasedAt      *time.Time `json:"released_at"`
	CreatedAt       time.Time  `json:"created_at"`
}

// appKey 返回封禁键用的 appID（空 = 全局）。
func (b *Block) appKey() string {
	if b.ApplicationID == nil {
		return ""
	}
	return b.ApplicationID.String()
}

// cacheValue 是写入 Valkey 的封禁值（与网关 temporaryblock.Block JSON 结构一致）。
type cacheValue struct {
	ID            string    `json:"id"`
	ClientIP      string    `json:"client_ip"`
	ApplicationID string    `json:"application_id"`
	ExpiresAt     time.Time `json:"expires_at"`
	Reason        string    `json:"reason,omitempty"`
	Auto          bool      `json:"auto"`
}

// ValidateNewExpiry 校验新的到期时间：必须晚于 now。
func ValidateNewExpiry(newExpiresAt, now time.Time) error {
	if newExpiresAt.IsZero() || !newExpiresAt.After(now) {
		return fmt.Errorf("%w: 到期时间必须晚于当前时间", ErrInvalidExpiry)
	}
	return nil
}

// Store 是临时封禁仓储。
type Store struct {
	db          *pgxpool.Pool
	cache       *cache.Client // 可为 nil（nil 时跳过 Valkey 同步）
	ruleCreator PermanentRuleCreator
}

// NewStore 创建临时封禁仓储。creators 为可选的永久规则创建器（构造注入）。
func NewStore(db *pgxpool.Pool, cacheClient *cache.Client, creators ...PermanentRuleCreator) *Store {
	s := &Store{db: db, cache: cacheClient}
	if len(creators) > 0 {
		s.ruleCreator = creators[0]
	}
	return s
}

// SetPermanentRuleCreator 设置永久规则创建器（应用装配时使用）。
func (s *Store) SetPermanentRuleCreator(c PermanentRuleCreator) {
	s.ruleCreator = c
}

// ListFilter 是封禁查询筛选。
type ListFilter struct {
	Status        string
	ClientIP      string
	ApplicationID *uuid.UUID
	Page          int
	PageSize      int
}

// List 分页查询封禁。
func (s *Store) List(ctx context.Context, f ListFilter) ([]Block, int64, error) {
	if f.Page <= 0 {
		f.Page = 1
	}
	if f.PageSize <= 0 || f.PageSize > 100 {
		f.PageSize = 20
	}
	where := "1=1"
	args := []interface{}{}
	argIdx := 1
	add := func(cond string, v interface{}) {
		where += fmt.Sprintf(" AND "+cond, argIdx)
		args = append(args, v)
		argIdx++
	}
	if f.Status != "" {
		add("status = $%d", f.Status)
	}
	if f.ClientIP != "" {
		add("client_ip = $%d", f.ClientIP)
	}
	if f.ApplicationID != nil {
		add("application_id = $%d", *f.ApplicationID)
	}

	var total int64
	if err := s.db.QueryRow(ctx, `SELECT count(*) FROM temporary_blocks WHERE `+where, args...).Scan(&total); err != nil {
		return nil, 0, err
	}
	query := `
SELECT id, client_ip, application_id, trigger_type, trigger_policy_id, trigger_event_ids,
  block_started_at, block_expires_at, status, hit_count, release_type, released_by, released_at, created_at
FROM temporary_blocks WHERE ` + where + fmt.Sprintf(" ORDER BY created_at DESC LIMIT $%d OFFSET $%d", argIdx, argIdx+1)
	args = append(args, f.PageSize, (f.Page-1)*f.PageSize)
	rows, err := s.db.Query(ctx, query, args...)
	if err != nil {
		return nil, 0, err
	}
	defer rows.Close()
	var out []Block
	for rows.Next() {
		b, err := scanBlock(rows)
		if err != nil {
			return nil, 0, err
		}
		out = append(out, *b)
	}
	return out, total, rows.Err()
}

// GetByID 查询封禁详情。
func (s *Store) GetByID(ctx context.Context, id uuid.UUID) (*Block, error) {
	row := s.db.QueryRow(ctx, `
SELECT id, client_ip, application_id, trigger_type, trigger_policy_id, trigger_event_ids,
  block_started_at, block_expires_at, status, hit_count, release_type, released_by, released_at, created_at
FROM temporary_blocks WHERE id = $1`, id)
	return scanBlock(row)
}

func scanBlock(row pgx.Row) (*Block, error) {
	var b Block
	var cip *netip.Addr
	var eventIDs []byte
	var releaseType *string
	err := row.Scan(&b.ID, &cip, &b.ApplicationID, &b.TriggerType, &b.TriggerPolicyID, &eventIDs,
		&b.BlockStartedAt, &b.BlockExpiresAt, &b.Status, &b.HitCount, &releaseType,
		&b.ReleasedBy, &b.ReleasedAt, &b.CreatedAt)
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return nil, ErrNotFound
		}
		return nil, err
	}
	if cip != nil {
		b.ClientIP = cip.String()
	}
	if releaseType != nil {
		b.ReleaseType = *releaseType
	}
	if len(eventIDs) > 0 {
		if err := json.Unmarshal(eventIDs, &b.TriggerEventIDs); err != nil {
			return nil, fmt.Errorf("parse trigger_event_ids: %w", err)
		}
	}
	return &b, nil
}

// Release 人工解封：DB 置 MANUALLY_RELEASED + Valkey HDel。
func (s *Store) Release(ctx context.Context, id, releasedBy uuid.UUID) error {
	b, err := s.GetByID(ctx, id)
	if err != nil {
		return err
	}
	if b.Status != StatusActive {
		return ErrNotActive
	}
	res, err := s.db.Exec(ctx, `
UPDATE temporary_blocks SET status=$1, release_type=$2, released_by=$3, released_at=now()
WHERE id=$4 AND status=$5`,
		StatusManuallyReleased, ReleaseTypeManual, releasedBy, id, StatusActive)
	if err != nil {
		return err
	}
	if res.RowsAffected() == 0 {
		return ErrNotActive
	}
	return s.cacheDel(ctx, b)
}

// Extend 延长封禁：DB 更新到期时间 + Valkey 更新 JSON。
func (s *Store) Extend(ctx context.Context, id uuid.UUID, newExpiresAt time.Time) error {
	if err := ValidateNewExpiry(newExpiresAt, time.Now()); err != nil {
		return err
	}
	b, err := s.GetByID(ctx, id)
	if err != nil {
		return err
	}
	if b.Status != StatusActive {
		return ErrNotActive
	}
	if !newExpiresAt.After(b.BlockExpiresAt) {
		return fmt.Errorf("%w: 新到期时间必须晚于当前到期时间", ErrInvalidExpiry)
	}
	res, err := s.db.Exec(ctx,
		`UPDATE temporary_blocks SET block_expires_at=$1 WHERE id=$2 AND status=$3`,
		newExpiresAt, id, StatusActive)
	if err != nil {
		return err
	}
	if res.RowsAffected() == 0 {
		return ErrNotActive
	}
	b.BlockExpiresAt = newExpiresAt
	return s.cachePut(ctx, b, "")
}

// ConvertToPermanent 把封禁转为永久 DENY 规则：
// 创建永久规则后置 CANCELLED(release_type=CONVERTED) + Valkey HDel。
func (s *Store) ConvertToPermanent(ctx context.Context, id, createdBy uuid.UUID) (*accessrules.Rule, error) {
	if s.ruleCreator == nil {
		return nil, ErrConvertUnsupported
	}
	b, err := s.GetByID(ctx, id)
	if err != nil {
		return nil, err
	}
	if b.Status != StatusActive {
		return nil, ErrNotActive
	}
	in := accessrules.CreateInput{
		Name:         fmt.Sprintf("临时封禁转永久-%s", b.ClientIP),
		RuleType:     accessrules.RuleTypeDeny,
		ScopeType:    accessrules.ScopeGlobal,
		Address:      b.ClientIP,
		Priority:     100,
		ValidityType: accessrules.ValidityPermanent,
		Reason:       fmt.Sprintf("由临时封禁 %s 转换（触发类型 %s）", b.ID, b.TriggerType),
		SourceType:   accessrules.SourceAutoBlock,
	}
	if b.ApplicationID != nil {
		in.ScopeType = accessrules.ScopeApplication
		in.ApplicationID = b.ApplicationID
	}
	for _, eid := range b.TriggerEventIDs {
		if parsed, err := uuid.Parse(eid); err == nil {
			in.SourceEventID = &parsed
			break
		}
	}
	rule, err := s.ruleCreator.Create(ctx, in, createdBy)
	if err != nil {
		return nil, fmt.Errorf("create permanent rule: %w", err)
	}
	res, err := s.db.Exec(ctx, `
UPDATE temporary_blocks SET status=$1, release_type=$2, released_by=$3, released_at=now()
WHERE id=$4 AND status=$5`,
		StatusCancelled, ReleaseTypeConverted, createdBy, id, StatusActive)
	if err != nil {
		return nil, err
	}
	if res.RowsAffected() == 0 {
		return nil, ErrNotActive
	}
	if err := s.cacheDel(ctx, b); err != nil {
		return rule, err
	}
	return rule, nil
}

// UpsertFromEvent 供采集器调用：CC_AUTO 来源封禁入库。
// 幂等：同 client_ip+application_id 已存在 ACTIVE 记录则更新 expires（取较大者）且 hit_count+1。
func (s *Store) UpsertFromEvent(ctx context.Context, b *Block) error {
	if b.ClientIP == "" {
		return fmt.Errorf("client_ip is required")
	}
	if _, err := netip.ParseAddr(b.ClientIP); err != nil {
		return fmt.Errorf("invalid client_ip: %w", err)
	}
	if b.BlockExpiresAt.IsZero() {
		return fmt.Errorf("block_expires_at is required")
	}
	if b.TriggerType == "" {
		b.TriggerType = TriggerCCAuto
	}

	var existingID uuid.UUID
	err := s.db.QueryRow(ctx, `
SELECT id FROM temporary_blocks
WHERE client_ip = $1 AND application_id IS NOT DISTINCT FROM $2 AND status = $3
ORDER BY block_expires_at DESC LIMIT 1`,
		b.ClientIP, b.ApplicationID, StatusActive).Scan(&existingID)
	if err != nil && !errors.Is(err, pgx.ErrNoRows) {
		return err
	}
	if err == nil {
		// 已存在 ACTIVE：更新到期时间（取较大者）+ 命中数 +1
		_, err = s.db.Exec(ctx, `
UPDATE temporary_blocks SET block_expires_at = GREATEST(block_expires_at, $1), hit_count = hit_count + 1
WHERE id = $2`, b.BlockExpiresAt, existingID)
		if err != nil {
			return err
		}
		b.ID = existingID
		b.Status = StatusActive
		return nil
	}

	eventIDs, err := json.Marshal(b.TriggerEventIDs)
	if err != nil {
		return fmt.Errorf("marshal trigger_event_ids: %w", err)
	}
	err = s.db.QueryRow(ctx, `
INSERT INTO temporary_blocks (client_ip, application_id, trigger_type, trigger_policy_id,
  trigger_event_ids, block_expires_at, status)
VALUES ($1,$2,$3,$4,$5,$6,$7)
RETURNING id, block_started_at, created_at`,
		b.ClientIP, b.ApplicationID, b.TriggerType, b.TriggerPolicyID,
		string(eventIDs), b.BlockExpiresAt, StatusActive,
	).Scan(&b.ID, &b.BlockStartedAt, &b.CreatedAt)
	if err != nil {
		return err
	}
	b.Status = StatusActive
	return nil
}

// MarkExpired 把到期 ACTIVE 批量置 EXPIRED(release_type=AUTO_EXPIRE)，返回更新数量。
// 由定时任务/采集周期调用。
func (s *Store) MarkExpired(ctx context.Context, now time.Time) (int, error) {
	blocks, err := s.MarkExpiredReturning(ctx, now)
	return len(blocks), err
}

// MarkExpiredReturning 到期标记并返回被过期的记录（供写入 CC_TEMP_BLOCK_EXPIRED 事件）。
// DB 置 EXPIRED 后同步 HDel Valkey 封禁 field（与 Release/ConvertToPermanent 同口径），
// 否则 jiuzhang:guard:tempblocks 哈希只增不减。逐条清理并聚合错误：
// 部分 HDel 失败不影响其余条目，记录随错误一并返回，由调用方继续补写事件后上抛。
func (s *Store) MarkExpiredReturning(ctx context.Context, now time.Time) ([]Block, error) {
	rows, err := s.db.Query(ctx, `
UPDATE temporary_blocks SET status=$1, release_type=$2, released_at=$3
WHERE status=$4 AND block_expires_at <= $3
RETURNING id, host(client_ip), application_id, block_expires_at, trigger_type`,
		StatusExpired, ReleaseTypeAutoExpire, now, StatusActive)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []Block
	for rows.Next() {
		var b Block
		var appID *uuid.UUID
		var cip string
		if err := rows.Scan(&b.ID, &cip, &appID, &b.BlockExpiresAt, &b.TriggerType); err != nil {
			return nil, err
		}
		b.ClientIP = cip
		b.ApplicationID = appID
		b.Status = StatusExpired
		b.ReleaseType = ReleaseTypeAutoExpire
		out = append(out, b)
	}
	if err := rows.Err(); err != nil {
		return nil, err
	}
	var delErrs []error
	for i := range out {
		if err := s.cacheDel(ctx, &out[i]); err != nil {
			delErrs = append(delErrs, fmt.Errorf("hdel expired tempblock %s: %w", out[i].ID, err))
		}
	}
	return out, errors.Join(delErrs...)
}

// cachePut 写入/更新 Valkey 封禁值。reason 为空时保留已有 reason。
func (s *Store) cachePut(ctx context.Context, b *Block, reason string) error {
	if s.cache == nil {
		return nil
	}
	field := BlockFieldKey(b.ClientIP, b.appKey())
	// 保留已有 reason（DB 不存 reason，延长时不能丢）
	if reason == "" {
		if old, err := s.cache.Redis().HGet(ctx, HashKey, field).Result(); err == nil {
			var cv cacheValue
			if json.Unmarshal([]byte(old), &cv) == nil {
				reason = cv.Reason
			}
		}
	}
	data, err := json.Marshal(cacheValue{
		ID:            b.ID.String(),
		ClientIP:      b.ClientIP,
		ApplicationID: b.appKey(),
		ExpiresAt:     b.BlockExpiresAt.UTC(),
		Reason:        reason,
		Auto:          b.TriggerType == TriggerCCAuto,
	})
	if err != nil {
		return err
	}
	if err := s.cache.Redis().HSet(ctx, HashKey, field, string(data)).Err(); err != nil {
		return fmt.Errorf("valkey hset tempblock: %w", err)
	}
	return nil
}

// cacheDel 删除 Valkey 封禁值。
func (s *Store) cacheDel(ctx context.Context, b *Block) error {
	if s.cache == nil {
		return nil
	}
	if err := s.cache.Redis().HDel(ctx, HashKey, BlockFieldKey(b.ClientIP, b.appKey())).Err(); err != nil {
		return fmt.Errorf("valkey hdel tempblock: %w", err)
	}
	return nil
}

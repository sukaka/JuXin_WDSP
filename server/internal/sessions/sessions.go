// Package sessions 提供服务端会话管理。
// 浏览器仅保存随机会话标识 Cookie，会话状态存 Valkey；
// PostgreSQL login_sessions 保存审计摘要（不含原始 Session ID）。
package sessions

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/jiuzhang-waf/server/internal/cache"
	"github.com/jiuzhang-waf/server/internal/security"
	"github.com/redis/go-redis/v9"
)

// 会话错误
var (
	ErrSessionNotFound = errors.New("session not found")
	ErrSessionExpired  = errors.New("session expired")
	ErrSessionRevoked  = errors.New("session revoked")
)

const sessionKeyPrefix = "jiuzhang:session:"

// Session 是服务端会话。
type Session struct {
	ID             string    `json:"id"`
	UserID         uuid.UUID `json:"user_id"`
	Username       string    `json:"username"`
	Roles          []string  `json:"roles"`
	Permissions    []string  `json:"permissions"`
	PermissionVer  int64     `json:"permission_version"`
	CreatedAt      time.Time `json:"created_at"`
	LastSeenAt     time.Time `json:"last_seen_at"`
	AbsoluteExpiry time.Time `json:"absolute_expiry"`
	SourceIP       string    `json:"source_ip"`
	UserAgent      string    `json:"user_agent"`
	MustChangePwd  bool      `json:"must_change_password"`
}

// Policy 是会话策略。
type Policy struct {
	IdleTimeout     time.Duration // 空闲超时
	AbsoluteTimeout time.Duration // 绝对超时
	MaxPerUser      int           // 单用户最大会话数
	AllowMulti      bool          // 是否允许多会话
}

// Service 是会话服务。
type Service struct {
	cache *cache.Client
	db    *pgxpool.Pool
}

// NewService 创建会话服务。
func NewService(c *cache.Client, db *pgxpool.Pool) *Service {
	return &Service{cache: c, db: db}
}

// HashSessionID 计算会话 ID 的哈希（用于持久化，不保存原始 ID）。
func HashSessionID(id string) string {
	sum := sha256.Sum256([]byte("jiuzhang-session:" + id))
	return hex.EncodeToString(sum[:])
}

// Create 创建新会话。
func (s *Service) Create(ctx context.Context, userID uuid.UUID, username string, roles, permissions []string, sourceIP, userAgent string, mustChangePwd bool, policy Policy) (*Session, error) {
	// 单用户会话数控制
	if !policy.AllowMulti {
		if err := s.RevokeAllForUser(ctx, userID, "new_login_single_session"); err != nil {
			return nil, err
		}
	} else if policy.MaxPerUser > 0 {
		if err := s.enforceMaxSessions(ctx, userID, policy.MaxPerUser); err != nil {
			return nil, err
		}
	}

	id, err := security.NewRandomToken(32)
	if err != nil {
		return nil, err
	}
	now := time.Now().UTC()
	sess := &Session{
		ID:             id,
		UserID:         userID,
		Username:       username,
		Roles:          roles,
		Permissions:    permissions,
		CreatedAt:      now,
		LastSeenAt:     now,
		AbsoluteExpiry: now.Add(policy.AbsoluteTimeout),
		SourceIP:       sourceIP,
		UserAgent:      truncateUA(userAgent),
		MustChangePwd:  mustChangePwd,
	}
	if err := s.save(ctx, sess, policy.IdleTimeout); err != nil {
		return nil, err
	}
	// 审计摘要持久化
	_, err = s.db.Exec(ctx, `
INSERT INTO login_sessions (user_id, session_hash, source_ip, user_agent_summary, expires_at)
VALUES ($1, $2, $3, $4, $5)`,
		userID, HashSessionID(id), nullableIP(sourceIP), truncateUA(userAgent), sess.AbsoluteExpiry)
	if err != nil {
		cleanupErr := s.deleteCachedSession(ctx, sess)
		return nil, errors.Join(fmt.Errorf("persist session summary: %w", err), cleanupErr)
	}
	return sess, nil
}

// Get 获取会话并刷新空闲超时。
func (s *Service) Get(ctx context.Context, id string, policy Policy) (*Session, error) {
	sess, err := s.load(ctx, id)
	if err != nil {
		return nil, err
	}
	now := time.Now().UTC()
	if now.After(sess.AbsoluteExpiry) {
		return nil, errors.Join(ErrSessionExpired, s.Revoke(ctx, id, "absolute_expired"))
	}
	// 刷新空闲超时
	sess.LastSeenAt = now
	if err := s.save(ctx, sess, policy.IdleTimeout); err != nil {
		return nil, err
	}
	if _, err := s.db.Exec(ctx,
		`UPDATE login_sessions SET last_seen_at = now() WHERE session_hash = $1`, HashSessionID(id)); err != nil {
		return nil, fmt.Errorf("update session last seen: %w", err)
	}
	return sess, nil
}

// GetNoRefresh 获取会话但不刷新空闲超时（内部使用）。
func (s *Service) GetNoRefresh(ctx context.Context, id string) (*Session, error) {
	return s.load(ctx, id)
}

// RefreshPermissions 更新会话中的权限（角色变更后调用）。
func (s *Service) RefreshPermissions(ctx context.Context, id string, roles, permissions []string) error {
	sess, err := s.load(ctx, id)
	if err != nil {
		return err
	}
	sess.Roles = roles
	sess.Permissions = permissions
	return s.cache.Set(ctx, sessionKeyPrefix+id, mustMarshal(sess), remainingTTL(sess))
}

// Revoke 注销会话。
func (s *Service) Revoke(ctx context.Context, id, reason string) error {
	sess, _ := s.load(ctx, id)
	var errs []error
	if _, err := s.db.Exec(ctx,
		`UPDATE login_sessions SET revoked_at = now(), revoke_reason = $2 WHERE session_hash = $1 AND revoked_at IS NULL`,
		HashSessionID(id), reason); err != nil {
		errs = append(errs, fmt.Errorf("persist session revocation: %w", err))
	}
	if err := s.cache.Del(ctx, sessionKeyPrefix+id); err != nil {
		errs = append(errs, fmt.Errorf("delete cached session: %w", err))
	}
	if sess != nil {
		if err := s.cache.Redis().SRem(ctx, userSessionIndexKey(sess.UserID), id).Err(); err != nil {
			errs = append(errs, fmt.Errorf("remove cached session index: %w", err))
		}
	}
	return errors.Join(errs...)
}

// RevokeAllForUser 注销指定用户全部会话。
func (s *Service) RevokeAllForUser(ctx context.Context, userID uuid.UUID, reason string) error {
	var errs []error
	if _, err := s.db.Exec(ctx,
		`UPDATE login_sessions SET revoked_at = now(), revoke_reason = $2 WHERE user_id = $1 AND revoked_at IS NULL`,
		userID, reason); err != nil {
		errs = append(errs, fmt.Errorf("persist user session revocations: %w", err))
	}

	// Valkey 按用户索引删除
	idxKey := userSessionIndexKey(userID)
	members, err := s.cache.Redis().SMembers(ctx, idxKey).Result()
	if err != nil && err != redis.Nil {
		errs = append(errs, fmt.Errorf("list cached user sessions: %w", err))
	} else {
		for _, id := range members {
			if err := s.cache.Del(ctx, sessionKeyPrefix+id); err != nil {
				errs = append(errs, fmt.Errorf("delete cached session %s: %w", HashSessionID(id), err))
			}
		}
	}
	if err := s.cache.Del(ctx, idxKey); err != nil {
		errs = append(errs, fmt.Errorf("delete cached user session index: %w", err))
	}
	return errors.Join(errs...)
}

// ListForUser 返回用户的会话摘要（DB 中的审计记录）。
func (s *Service) ListForUser(ctx context.Context, userID uuid.UUID, limit int) ([]Summary, error) {
	if limit <= 0 || limit > 100 {
		limit = 20
	}
	rows, err := s.db.Query(ctx, `
SELECT id, session_hash, source_ip, user_agent_summary, created_at, last_seen_at, expires_at, revoked_at, revoke_reason
FROM login_sessions
WHERE user_id = $1
ORDER BY created_at DESC
LIMIT $2`, userID, limit)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []Summary
	for rows.Next() {
		var su Summary
		var revokedAt *time.Time
		var reason *string
		if err := rows.Scan(&su.ID, &su.SessionHash, &su.SourceIP, &su.UserAgent,
			&su.CreatedAt, &su.LastSeenAt, &su.ExpiresAt, &revokedAt, &reason); err != nil {
			return nil, err
		}
		su.RevokedAt = revokedAt
		if reason != nil {
			su.RevokeReason = *reason
		}
		out = append(out, su)
	}
	return out, rows.Err()
}

// RevokeOtherForUser 注销用户除 currentID 外的全部会话。
func (s *Service) RevokeOtherForUser(ctx context.Context, userID uuid.UUID, currentID, reason string) error {
	var errs []error
	if _, err := s.db.Exec(ctx,
		`UPDATE login_sessions SET revoked_at = now(), revoke_reason = $3
		 WHERE user_id = $1 AND session_hash <> $2 AND revoked_at IS NULL`,
		userID, HashSessionID(currentID), reason); err != nil {
		errs = append(errs, fmt.Errorf("persist other session revocations: %w", err))
	}

	idxKey := userSessionIndexKey(userID)
	members, err := s.cache.Redis().SMembers(ctx, idxKey).Result()
	if err != nil && err != redis.Nil {
		errs = append(errs, fmt.Errorf("list cached user sessions: %w", err))
	} else {
		for _, id := range members {
			if id == currentID {
				continue
			}
			if err := s.cache.Del(ctx, sessionKeyPrefix+id); err != nil {
				errs = append(errs, fmt.Errorf("delete cached session %s: %w", HashSessionID(id), err))
			}
			if err := s.cache.Redis().SRem(ctx, idxKey, id).Err(); err != nil {
				errs = append(errs, fmt.Errorf("remove cached session index %s: %w", HashSessionID(id), err))
			}
		}
	}
	return errors.Join(errs...)
}

// FindSessionIDByHash 通过摘要反查 Valkey 中的会话 ID（用于管理员强制下线）。
func (s *Service) FindSessionIDByHash(ctx context.Context, userID uuid.UUID, sessionHash string) (string, error) {
	idxKey := userSessionIndexKey(userID)
	members, err := s.cache.Redis().SMembers(ctx, idxKey).Result()
	if err != nil {
		return "", err
	}
	for _, id := range members {
		if HashSessionID(id) == sessionHash {
			return id, nil
		}
	}
	return "", ErrSessionNotFound
}

// OwnsSession 校验摘要是否属于用户且会话存活。
func (s *Service) OwnsSession(ctx context.Context, userID uuid.UUID, sessionHash string) bool {
	id, err := s.FindSessionIDByHash(ctx, userID, sessionHash)
	if err != nil {
		return false
	}
	_, err = s.load(ctx, id)
	return err == nil
}

func (s *Service) load(ctx context.Context, id string) (*Session, error) {
	data, err := s.cache.Get(ctx, sessionKeyPrefix+id)
	if err != nil {
		if err == redis.Nil {
			return nil, ErrSessionNotFound
		}
		return nil, err
	}
	var sess Session
	if err := json.Unmarshal([]byte(data), &sess); err != nil {
		return nil, fmt.Errorf("corrupt session: %w", err)
	}
	return &sess, nil
}

func (s *Service) save(ctx context.Context, sess *Session, idleTimeout time.Duration) error {
	ttl := remainingTTL(sess)
	if ttl <= 0 {
		return ErrSessionExpired
	}
	if idleTimeout > 0 && idleTimeout < ttl {
		ttl = idleTimeout
	}
	if err := s.cache.Set(ctx, sessionKeyPrefix+sess.ID, mustMarshal(sess), ttl); err != nil {
		return err
	}
	// 用户会话索引
	idxKey := userSessionIndexKey(sess.UserID)
	if err := s.cache.Redis().SAdd(ctx, idxKey, sess.ID).Err(); err != nil {
		return errors.Join(err, s.cache.Del(ctx, sessionKeyPrefix+sess.ID))
	}
	if err := s.cache.Expire(ctx, idxKey, 30*24*time.Hour); err != nil {
		return errors.Join(err, s.deleteCachedSession(ctx, sess))
	}
	return nil
}

func (s *Service) deleteCachedSession(ctx context.Context, sess *Session) error {
	return errors.Join(
		s.cache.Del(ctx, sessionKeyPrefix+sess.ID),
		s.cache.Redis().SRem(ctx, userSessionIndexKey(sess.UserID), sess.ID).Err(),
	)
}

func (s *Service) enforceMaxSessions(ctx context.Context, userID uuid.UUID, max int) error {
	idxKey := userSessionIndexKey(userID)
	members, err := s.cache.Redis().SMembers(ctx, idxKey).Result()
	if err != nil && err != redis.Nil {
		return err
	}
	// 清理死会话
	alive := members[:0]
	for _, id := range members {
		if _, err := s.load(ctx, id); err == nil {
			alive = append(alive, id)
		} else {
			if err := s.cache.Redis().SRem(ctx, idxKey, id).Err(); err != nil {
				return err
			}
		}
	}
	// 超限时淘汰最旧会话
	if len(alive) >= max {
		oldest := ""
		var oldestTime time.Time
		for _, id := range alive {
			sess, err := s.load(ctx, id)
			if err != nil {
				continue
			}
			if oldest == "" || sess.CreatedAt.Before(oldestTime) {
				oldest = id
				oldestTime = sess.CreatedAt
			}
		}
		if oldest != "" {
			if err := s.Revoke(ctx, oldest, "max_sessions_evicted"); err != nil {
				return err
			}
		}
	}
	return nil
}

func remainingTTL(sess *Session) time.Duration {
	return time.Until(sess.AbsoluteExpiry)
}

func mustMarshal(sess *Session) string {
	b, _ := json.Marshal(sess)
	return string(b)
}

func userSessionIndexKey(userID uuid.UUID) string {
	return "jiuzhang:user_sessions:" + userID.String()
}

func nullableIP(ip string) interface{} {
	if ip == "" {
		return nil
	}
	return ip
}

func truncateUA(ua string) string {
	if len(ua) > 500 {
		return ua[:500]
	}
	return ua
}

// Summary 是会话审计摘要。
type Summary struct {
	ID           uuid.UUID  `json:"id"`
	SessionHash  string     `json:"session_hash"`
	SourceIP     string     `json:"source_ip"`
	UserAgent    string     `json:"user_agent_summary"`
	CreatedAt    time.Time  `json:"created_at"`
	LastSeenAt   time.Time  `json:"last_seen_at"`
	ExpiresAt    time.Time  `json:"expires_at"`
	RevokedAt    *time.Time `json:"revoked_at"`
	RevokeReason string     `json:"revoke_reason"`
}

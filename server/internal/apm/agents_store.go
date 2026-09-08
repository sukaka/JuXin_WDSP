// agents_store.go APM Agent 控制面仓储（迁移 000089 五表）。
// 纪律：所有 SQL 参数化；Agent 注册（EnrollAgent）为单事务——令牌锁定校验/消费、
// 服务认领、顶替存量、登记新 Agent 与策略解析一次提交，任一步失败整体回滚；
// 策略版本递增 / 撤销与轮换同样在事务内完成（策略版本经 pg_advisory_xact_lock 串行化
// 取 max+1，(scope, version) 唯一约束兜底）；证书撤销按指纹列表，认证路径必查。
package apm

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"strconv"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
)

// 控制面仓储错误（handler 按 errors.Is 映射状态码）。
var (
	// ErrTokenInvalid 令牌无效/已使用/已过期（统一口径，不区分原因——防令牌枚举）。
	ErrTokenInvalid = errors.New("注册令牌无效、已使用或已过期")
	// ErrAgentNotFound Agent 不存在（HTTP 404）。
	ErrAgentNotFound = errors.New("agent not found")
	// ErrAgentAlreadyRevoked Agent 已处于 REVOKED 终态（HTTP 409）。
	ErrAgentAlreadyRevoked = errors.New("agent already revoked")
	// ErrPolicyNotFound 作用域下暂无策略版本（HTTP 404）。
	ErrPolicyNotFound = errors.New("policy not found")
	// ErrServiceClaimConflict 服务已被其他应用认领（HTTP 409；防跨应用认领劫持）。
	ErrServiceClaimConflict = errors.New("service claimed by another application")
	// ErrCertFingerprintMismatch 轮换时出示的证书不是该 Agent 当前生效证书（HTTP 409）。
	ErrCertFingerprintMismatch = errors.New("certificate fingerprint mismatch")
	// ErrTokenLanguageNotAllowed 注册令牌语言白名单不含请求语言（HTTP 400；
	// 先于令牌消费校验——语言不符不烧毁令牌）。
	ErrTokenLanguageNotAllowed = errors.New("注册令牌不允许该语言")
)

// AgentsFilter Agent 列表查询条件（Status 为展示态过滤，含派生态 OFFLINE；
// Page/PageSize 已由 handler 夹紧）。
type AgentsFilter struct {
	Status        string
	Language      string
	Keyword       string
	ApplicationID *uuid.UUID
	Page          int
	PageSize      int
}

// AgentRepository 控制面存取抽象（管理面与 Agent 面共用；单测以 fake 注入）。
type AgentRepository interface {
	// 管理面
	ApplicationExists(ctx context.Context, id uuid.UUID) (bool, error)
	CreateEnrollmentToken(ctx context.Context, row *EnrollmentTokenRow, tokenHash string) error
	ListAgents(ctx context.Context, f AgentsFilter, offlineAfter time.Duration, now time.Time) ([]AgentRow, int64, error)
	GetAgent(ctx context.Context, id uuid.UUID) (*AgentRow, error)
	RevokeAgent(ctx context.Context, id uuid.UUID, reason string, now time.Time) (*AgentRow, error)
	LatestPolicy(ctx context.Context, scope string) (*PolicyRow, error)
	CreatePolicyVersion(ctx context.Context, scope string, policy map[string]interface{}, signature, keyID string,
		issuedAt, expiresAt time.Time, expectedVersion *int64, createdBy *uuid.UUID) (*PolicyRow, error)

	// Agent 面
	EnrollAgent(ctx context.Context, params *EnrollAgentParams, resolvePolicy PolicyResolver) (*EnrollAgentResult, error)
	AgentByCertFingerprint(ctx context.Context, fingerprint string) (*AgentRow, error)
	IsFingerprintRevoked(ctx context.Context, fingerprint string) (bool, error)
	RecordHeartbeat(ctx context.Context, agentID uuid.UUID, agentVersion, sdkVersion string, nodeInfo NodeInfo, now time.Time) error
	RotateAgentCert(ctx context.Context, agentID uuid.UUID, oldFingerprint, newFingerprint string, notAfter, now time.Time) error
}

// PolicyStore 策略读取/发布最小面（注册事务内以 txPolicyStore 实现与登记最终态同提交；
// 事务外由 *AgentStore / fake 实现——二者共用 AgentRepository 既有方法集）。
type PolicyStore interface {
	LatestPolicy(ctx context.Context, scope string) (*PolicyRow, error)
	CreatePolicyVersion(ctx context.Context, scope string, policy map[string]interface{}, signature, keyID string,
		issuedAt, expiresAt time.Time, expectedVersion *int64, createdBy *uuid.UUID) (*PolicyRow, error)
}

// PolicyResolver 在给定策略存取面上解析 Agent 生效策略（应用级优先 → 全局基线，
// 可含全局基线惰性创建；实现见 AgentAPIHandler.resolvePolicyForAgent）。
type PolicyResolver func(ctx context.Context, store PolicyStore, applicationID *uuid.UUID) (*PolicyRow, error)

// EnrollAgentParams EnrollAgent 入参（证书已在事务外签发：Agent 携带指纹/到期时间等登记字段，
// ServiceID 由事务内服务认领结果回填）。
type EnrollAgentParams struct {
	TokenHash   string
	Language    string
	ServiceName string
	Agent       *AgentRow
	Now         time.Time
}

// EnrollAgentResult EnrollAgent 提交结果（Service 为认领后权威归属；Policy 为生效签名策略；
// Superseded 为本次顶替的存量 Agent 数）。
type EnrollAgentResult struct {
	Token      *EnrollmentTokenRow
	Service    *AgentServiceRow
	Agent      *AgentRow
	Policy     *PolicyRow
	Superseded int
}

// AgentStore Agent 控制面仓储。
type AgentStore struct {
	db *pgxpool.Pool
}

// NewAgentStore 创建控制面仓储。
func NewAgentStore(db *pgxpool.Pool) *AgentStore { return &AgentStore{db: db} }

// ---------- 管理面 ----------

// ApplicationExists 应用存在且未软删除（令牌绑定时校验；apm_services 关联同样过滤软删）。
func (s *AgentStore) ApplicationExists(ctx context.Context, id uuid.UUID) (bool, error) {
	var exists bool
	err := s.db.QueryRow(ctx,
		`SELECT EXISTS(SELECT 1 FROM applications WHERE id = $1 AND deleted_at IS NULL)`, id).Scan(&exists)
	return exists, err
}

// CreateEnrollmentToken 落库一次性令牌（仅 SHA-256 摘要，原文不入库）。
func (s *AgentStore) CreateEnrollmentToken(ctx context.Context, row *EnrollmentTokenRow, tokenHash string) error {
	langs, _ := json.Marshal(row.AllowedLanguages)
	return s.db.QueryRow(ctx, `
INSERT INTO apm_enrollment_tokens
  (token_hash, application_id, environment, allowed_languages, expires_at, note, created_by)
VALUES ($1, $2, $3, $4::jsonb, $5, $6, $7)
RETURNING id, created_at`,
		tokenHash, row.ApplicationID, row.Environment, langs, row.ExpiresAt, row.Note, row.CreatedBy,
	).Scan(&row.ID, &row.CreatedAt)
}

// ListAgents Agent 列表（展示态在 SQL 内按心跳超时推导，过滤/分页均按展示态口径）。
func (s *AgentStore) ListAgents(ctx context.Context, f AgentsFilter, offlineAfter time.Duration, now time.Time) ([]AgentRow, int64, error) {
	offlineBefore := now.UTC().Add(-offlineAfter)
	rows, err := s.db.Query(ctx, `
WITH view AS (
  SELECT a.id, a.service_id, s.service_name, s.environment, s.application_id,
         a.instance_id, a.language, a.agent_version, a.sdk_version,
         a.status AS stored_status,
         CASE WHEN a.status = 'REVOKED' THEN 'REVOKED'
              WHEN COALESCE(a.last_heartbeat_at, a.registered_at) < $1 THEN 'OFFLINE'
              ELSE a.status END AS status,
         a.cert_fingerprint, a.cert_not_after, a.last_heartbeat_at, a.node_info,
         a.registered_at, a.revoked_at, a.revoke_reason
  FROM apm_agents a
  JOIN apm_services s ON s.id = a.service_id
)
SELECT *, count(*) OVER () AS total FROM view
WHERE ($2::text = '' OR status = $2)
  AND ($3::text = '' OR language = $3)
  AND ($4::text = '' OR service_name ILIKE '%' || $4 || '%' OR instance_id ILIKE '%' || $4 || '%')
  AND ($5::uuid IS NULL OR application_id = $5)
ORDER BY last_heartbeat_at DESC NULLS LAST, registered_at DESC
LIMIT $6 OFFSET $7`,
		offlineBefore, f.Status, f.Language, f.Keyword, f.ApplicationID,
		f.PageSize, (f.Page-1)*f.PageSize)
	if err != nil {
		return nil, 0, err
	}
	defer rows.Close()
	list := []AgentRow{}
	var total int64
	for rows.Next() {
		a, t, err := scanAgentRow(rows)
		if err != nil {
			return nil, 0, err
		}
		total = t
		list = append(list, *a)
	}
	return list, total, rows.Err()
}

// agentScanner 兼容 pgx.Row / pgx.Rows 的扫描目标。
type agentScanner interface {
	Scan(dest ...interface{}) error
}

// scanAgentRow 扫描 view 形态行（末列含 count(*) OVER () 时带出 total；无则传 nil）。
func scanAgentRow(row agentScanner) (*AgentRow, int64, error) {
	return scanAgentRowWithTotal(row, true)
}

func scanAgentRowWithTotal(row agentScanner, withTotal bool) (*AgentRow, int64, error) {
	var a AgentRow
	var nodeInfo []byte
	dest := []interface{}{
		&a.ID, &a.ServiceID, &a.ServiceName, &a.Environment, &a.ApplicationID,
		&a.InstanceID, &a.Language, &a.AgentVersion, &a.SdkVersion,
		&a.StoredStatus, &a.Status,
		&a.CertFingerprint, &a.CertNotAfter, &a.LastHeartbeatAt, &nodeInfo,
		&a.RegisteredAt, &a.RevokedAt, &a.RevokeReason,
	}
	var total int64
	if withTotal {
		dest = append(dest, &total)
	}
	if err := row.Scan(dest...); err != nil {
		return nil, 0, err
	}
	decodedNodeInfo, err := decodeNodeInfo(nodeInfo)
	if err != nil {
		return nil, 0, err
	}
	a.NodeInfo = decodedNodeInfo
	return &a, total, nil
}

// decodeNodeInfo 将数据库中的节点信息归一化为展示用字符串。
// 旧版本或外部 Agent 可能写入数字、布尔值或嵌套 JSON；这些值不应导致整个 Agent 列表失败。
func decodeNodeInfo(data []byte) (NodeInfo, error) {
	trimmed := bytes.TrimSpace(data)
	if len(trimmed) == 0 || bytes.Equal(trimmed, []byte("null")) {
		return NodeInfo{}, nil
	}

	var raw map[string]json.RawMessage
	if err := json.Unmarshal(trimmed, &raw); err != nil {
		return nil, fmt.Errorf("decode node_info: %w", err)
	}

	info := make(NodeInfo, len(raw))
	for key, value := range raw {
		value = bytes.TrimSpace(value)
		var str string
		if err := json.Unmarshal(value, &str); err == nil {
			info[key] = str
			continue
		}
		var number json.Number
		if err := json.Unmarshal(value, &number); err == nil {
			info[key] = number.String()
			continue
		}
		var boolean bool
		if err := json.Unmarshal(value, &boolean); err == nil {
			info[key] = strconv.FormatBool(boolean)
			continue
		}
		// 对象和数组仅用于展示，保留其紧凑 JSON 表示，避免历史数据阻断列表查询。
		var compact bytes.Buffer
		if err := json.Compact(&compact, value); err == nil {
			info[key] = compact.String()
		} else {
			info[key] = string(value)
		}
	}
	return info, nil
}

// GetAgent 按 ID 取 Agent（撤销前加载；展示态不在此推导——撤销只看存态）。
func (s *AgentStore) GetAgent(ctx context.Context, id uuid.UUID) (*AgentRow, error) {
	row := s.db.QueryRow(ctx, `
SELECT a.id, a.service_id, s.service_name, s.environment, s.application_id,
       a.instance_id, a.language, a.agent_version, a.sdk_version,
       a.status, a.status,
       a.cert_fingerprint, a.cert_not_after, a.last_heartbeat_at, a.node_info,
       a.registered_at, a.revoked_at, a.revoke_reason
FROM apm_agents a JOIN apm_services s ON s.id = a.service_id
WHERE a.id = $1`, id)
	a, _, err := scanAgentRowWithTotal(row, false)
	if errors.Is(err, pgx.ErrNoRows) {
		return nil, ErrAgentNotFound
	}
	return a, err
}

// RevokeAgent 撤销 Agent（事务：状态 → REVOKED 终态 + 当前证书指纹入撤销列表）。
func (s *AgentStore) RevokeAgent(ctx context.Context, id uuid.UUID, reason string, now time.Time) (*AgentRow, error) {
	tx, err := s.db.Begin(ctx)
	if err != nil {
		return nil, err
	}
	defer tx.Rollback(ctx)
	var fp string
	var status string
	var serviceName, instanceID string
	err = tx.QueryRow(ctx, `
SELECT a.cert_fingerprint, a.status, s.service_name, a.instance_id
FROM apm_agents a JOIN apm_services s ON s.id = a.service_id
WHERE a.id = $1 FOR UPDATE OF a`, id).Scan(&fp, &status, &serviceName, &instanceID)
	if errors.Is(err, pgx.ErrNoRows) {
		return nil, ErrAgentNotFound
	}
	if err != nil {
		return nil, err
	}
	if status == AgentStatusRevoked {
		return nil, ErrAgentAlreadyRevoked
	}
	if _, err := tx.Exec(ctx, `
UPDATE apm_agents SET status = $2, revoked_at = $3, revoke_reason = $4
WHERE id = $1`, id, AgentStatusRevoked, now.UTC(), reason); err != nil {
		return nil, err
	}
	if _, err := tx.Exec(ctx, `
INSERT INTO apm_agent_cert_revocations (cert_fingerprint, agent_id, revoked_at, reason)
VALUES ($1, $2, $3, 'revoked')`, fp, id, now.UTC()); err != nil {
		return nil, err
	}
	if err := tx.Commit(ctx); err != nil {
		return nil, err
	}
	return s.GetAgent(ctx, id)
}

// dbRower 兼容 *pgxpool.Pool 与 pgx.Tx 的单行查询面（注册事务内复用同一 SQL）。
type dbRower interface {
	QueryRow(ctx context.Context, sql string, args ...interface{}) pgx.Row
}

// LatestPolicy 取作用域最新版本（无版本 → ErrPolicyNotFound）。
func (s *AgentStore) LatestPolicy(ctx context.Context, scope string) (*PolicyRow, error) {
	return latestPolicy(ctx, s.db, scope)
}

// latestPolicy 取作用域最新版本（调用方决定执行面：池或事务）。
func latestPolicy(ctx context.Context, q dbRower, scope string) (*PolicyRow, error) {
	row := q.QueryRow(ctx, `
SELECT id, scope, version, policy, signature, key_id, issued_at, expires_at, created_by
FROM apm_agent_policies WHERE scope = $1 ORDER BY version DESC LIMIT 1`, scope)
	return scanPolicyRow(row)
}

// scanPolicyRow 扫描策略行（policy jsonb → map）。
func scanPolicyRow(row pgx.Row) (*PolicyRow, error) {
	var p PolicyRow
	var policy []byte
	err := row.Scan(&p.ID, &p.Scope, &p.Version, &policy, &p.Signature, &p.KeyID,
		&p.IssuedAt, &p.ExpiresAt, &p.CreatedBy)
	if errors.Is(err, pgx.ErrNoRows) {
		return nil, ErrPolicyNotFound
	}
	if err != nil {
		return nil, err
	}
	if err := json.Unmarshal(policy, &p.Policy); err != nil {
		return nil, fmt.Errorf("decode policy: %w", err)
	}
	return &p, nil
}

// CreatePolicyVersion 新增策略版本（独立事务，供管理面/事务外调用；
// 注册事务内请经 txPolicyStore 复用同一事务）。
func (s *AgentStore) CreatePolicyVersion(ctx context.Context, scope string, policy map[string]interface{},
	signature, keyID string, issuedAt, expiresAt time.Time, expectedVersion *int64, createdBy *uuid.UUID) (*PolicyRow, error) {
	tx, err := s.db.Begin(ctx)
	if err != nil {
		return nil, err
	}
	defer tx.Rollback(ctx)
	p, err := createPolicyVersion(ctx, tx, scope, policy, signature, keyID, issuedAt, expiresAt, expectedVersion, createdBy)
	if err != nil {
		return nil, err
	}
	if err := tx.Commit(ctx); err != nil {
		return nil, err
	}
	return p, nil
}

// createPolicyVersion 策略版本插入（事务 + 作用域咨询锁串行化：版本恒为 max+1，
// 单调递增由唯一约束兜底；expectedVersion 非空时做乐观并发校验——读取后他人
// 已发新版则冲突拒绝，防丢失更新）。调用方负责事务边界。
func createPolicyVersion(ctx context.Context, tx pgx.Tx, scope string, policy map[string]interface{},
	signature, keyID string, issuedAt, expiresAt time.Time, expectedVersion *int64, createdBy *uuid.UUID) (*PolicyRow, error) {
	policyJSON, err := json.Marshal(policy)
	if err != nil {
		return nil, fmt.Errorf("encode policy: %w", err)
	}
	if _, err := tx.Exec(ctx, `SELECT pg_advisory_xact_lock(hashtext($1))`, scope); err != nil {
		return nil, err
	}
	var maxVersion int64
	err = tx.QueryRow(ctx,
		`SELECT COALESCE(MAX(version), 0) FROM apm_agent_policies WHERE scope = $1`, scope).Scan(&maxVersion)
	if err != nil {
		return nil, err
	}
	if expectedVersion != nil && *expectedVersion != maxVersion {
		return nil, ErrPolicyVersionConflict
	}
	row := tx.QueryRow(ctx, `
INSERT INTO apm_agent_policies (scope, version, policy, signature, key_id, issued_at, expires_at, created_by)
VALUES ($1, $2, $3::jsonb, $4, $5, $6, $7, $8)
RETURNING id, scope, version, policy, signature, key_id, issued_at, expires_at, created_by`,
		scope, maxVersion+1, policyJSON, signature, keyID, issuedAt.UTC(), expiresAt.UTC(), createdBy)
	return scanPolicyRow(row)
}

// txPolicyStore 注册事务内的策略存取面：策略读取与全局基线惰性创建与
// 令牌消费/登记最终态同一事务提交，策略步骤失败则注册整体回滚。
type txPolicyStore struct{ tx pgx.Tx }

func (t txPolicyStore) LatestPolicy(ctx context.Context, scope string) (*PolicyRow, error) {
	return latestPolicy(ctx, t.tx, scope)
}

func (t txPolicyStore) CreatePolicyVersion(ctx context.Context, scope string, policy map[string]interface{},
	signature, keyID string, issuedAt, expiresAt time.Time, expectedVersion *int64, createdBy *uuid.UUID) (*PolicyRow, error) {
	return createPolicyVersion(ctx, t.tx, scope, policy, signature, keyID, issuedAt, expiresAt, expectedVersion, createdBy)
}

// ---------- Agent 面 ----------

// EnrollAgent Agent 注册单事务（BUG-01 修复：原注册链为多次独立 DB 操作，
// 中途失败留下"令牌已用但 Agent 未注册"/"旧 Agent 已顶替但新 Agent 不存在"中间态）。
// 事务内语义链：
//  1. 锁定令牌行（FOR UPDATE）并校验未用未过期（统一 ErrTokenInvalid，防令牌枚举）；
//  2. 语言白名单校验（先于消费——语言不符不烧毁令牌）；
//  3. 消费令牌（同事务置 used_at/used_by_agent_id，提交前对并发不可见）；
//  4. 服务映射登记/认领（已被其他应用认领 → ErrServiceClaimConflict）；
//  5. 解析生效策略（含全局基线惰性创建——读取/创建均在本事务，失败整体回滚）；
//  6. 顶替同服务同实例存量（REVOKED + 当前证书指纹入撤销列表）；
//  7. 登记新 Agent（CONNECTED_BASELINE）；
//  8. 一次提交。任一步失败全部回滚，数据库不存在中间态。
func (s *AgentStore) EnrollAgent(ctx context.Context, params *EnrollAgentParams, resolvePolicy PolicyResolver) (*EnrollAgentResult, error) {
	now := params.Now.UTC()
	tx, err := s.db.Begin(ctx)
	if err != nil {
		return nil, err
	}
	defer tx.Rollback(ctx)

	token, err := lockEnrollmentToken(ctx, tx, params.TokenHash, now)
	if err != nil {
		return nil, err
	}
	if !token.LanguageAllowed(params.Language) {
		return nil, ErrTokenLanguageNotAllowed
	}
	if _, err := tx.Exec(ctx,
		`UPDATE apm_enrollment_tokens SET used_at = $2, used_by_agent_id = $3 WHERE id = $1`,
		token.ID, now, params.Agent.ID); err != nil {
		return nil, err
	}
	token.UsedAt = &now
	token.UsedByAgentID = &params.Agent.ID

	svc, err := upsertServiceForEnrollment(ctx, tx, params.ServiceName, token.Environment, token.ApplicationID, now)
	if err != nil {
		return nil, err
	}
	policy, err := resolvePolicy(ctx, txPolicyStore{tx: tx}, svc.ApplicationID)
	if err != nil {
		return nil, err
	}
	superseded, err := supersedeInstanceAgents(ctx, tx, svc.ID, params.Agent.InstanceID, "superseded by re-enrollment", now)
	if err != nil {
		return nil, err
	}
	agent := *params.Agent
	agent.ServiceID = svc.ID
	if err := insertAgent(ctx, tx, &agent); err != nil {
		return nil, err
	}
	if err := tx.Commit(ctx); err != nil {
		return nil, err
	}
	return &EnrollAgentResult{Token: token, Service: svc, Agent: &agent, Policy: policy, Superseded: superseded}, nil
}

// lockEnrollmentToken 锁定并校验一次性令牌（EnrollAgent 第 1 步；统一返回
// ErrTokenInvalid 不区分不存在/已用/过期，防令牌枚举）。
func lockEnrollmentToken(ctx context.Context, tx pgx.Tx, tokenHash string, now time.Time) (*EnrollmentTokenRow, error) {
	row := tx.QueryRow(ctx, `
SELECT id, application_id, environment, allowed_languages, expires_at, used_at, used_by_agent_id, note, created_by, created_at
FROM apm_enrollment_tokens WHERE token_hash = $1 FOR UPDATE`, tokenHash)
	t, err := scanTokenRow(row)
	if errors.Is(err, pgx.ErrNoRows) {
		return nil, ErrTokenInvalid
	}
	if err != nil {
		return nil, err
	}
	if t.UsedAt != nil || !t.ExpiresAt.After(now) {
		return nil, ErrTokenInvalid
	}
	return t, nil
}

// scanTokenRow 扫描令牌行（allowed_languages jsonb → []string）。
func scanTokenRow(row pgx.Row) (*EnrollmentTokenRow, error) {
	var t EnrollmentTokenRow
	var langs []byte
	err := row.Scan(&t.ID, &t.ApplicationID, &t.Environment, &langs, &t.ExpiresAt,
		&t.UsedAt, &t.UsedByAgentID, &t.Note, &t.CreatedBy, &t.CreatedAt)
	if err != nil {
		return nil, err
	}
	t.AllowedLanguages = []string{}
	if len(langs) > 0 {
		if err := json.Unmarshal(langs, &t.AllowedLanguages); err != nil {
			return nil, fmt.Errorf("decode allowed_languages: %w", err)
		}
	}
	return &t, nil
}

// upsertServiceForEnrollment 登记/认领服务映射（事务内 SELECT ... FOR UPDATE：
// 已被其他应用认领 → ErrServiceClaimConflict；未认领且令牌绑定应用 → 认领；
// 其余情形仅刷新 last_seen_at）。调用方负责事务边界（EnrollAgent 第 4 步）。
func upsertServiceForEnrollment(ctx context.Context, tx pgx.Tx, serviceName, environment string, applicationID *uuid.UUID, now time.Time) (*AgentServiceRow, error) {
	var svc AgentServiceRow
	err := tx.QueryRow(ctx, `
INSERT INTO apm_services (service_name, environment, application_id, claim_status, first_seen_at, last_seen_at)
VALUES ($1, $2, $3, CASE WHEN $3::uuid IS NULL THEN 'UNCLAIMED' ELSE 'CLAIMED' END, $4, $4)
ON CONFLICT (service_name, environment) DO NOTHING
RETURNING id, service_name, environment, application_id, claim_status, first_seen_at, last_seen_at`,
		serviceName, environment, applicationID, now.UTC(),
	).Scan(&svc.ID, &svc.ServiceName, &svc.Environment, &svc.ApplicationID, &svc.ClaimStatus, &svc.FirstSeenAt, &svc.LastSeenAt)
	if errors.Is(err, pgx.ErrNoRows) {
		// 已存在：锁定后按认领口径合并
		err = tx.QueryRow(ctx, `
SELECT id, service_name, environment, application_id, claim_status, first_seen_at, last_seen_at
FROM apm_services WHERE service_name = $1 AND environment = $2 FOR UPDATE`,
			serviceName, environment,
		).Scan(&svc.ID, &svc.ServiceName, &svc.Environment, &svc.ApplicationID, &svc.ClaimStatus, &svc.FirstSeenAt, &svc.LastSeenAt)
		if err != nil {
			return nil, err
		}
		switch {
		case svc.ApplicationID != nil && applicationID != nil && *svc.ApplicationID != *applicationID:
			return nil, ErrServiceClaimConflict
		case svc.ApplicationID == nil && applicationID != nil:
			// 未认领 → 令牌绑定应用认领
			if err := tx.QueryRow(ctx, `
UPDATE apm_services SET application_id = $2, claim_status = 'CLAIMED', last_seen_at = $3, updated_at = $3
WHERE id = $1
RETURNING application_id, claim_status, last_seen_at`,
				svc.ID, applicationID, now.UTC(),
			).Scan(&svc.ApplicationID, &svc.ClaimStatus, &svc.LastSeenAt); err != nil {
				return nil, err
			}
		default:
			if _, err := tx.Exec(ctx,
				`UPDATE apm_services SET last_seen_at = $2, updated_at = $2 WHERE id = $1`,
				svc.ID, now.UTC()); err != nil {
				return nil, err
			}
		}
	} else if err != nil {
		return nil, err
	}
	return &svc, nil
}

// supersedeInstanceAgents 重新注册顶替：同服务同实例的存量非终态 Agent 全部置
// REVOKED（reason=superseded）并把当前证书指纹入撤销列表；返回顶替数量。
// 调用方负责事务边界（EnrollAgent 第 6 步——与新 Agent 登记同事务提交）。
func supersedeInstanceAgents(ctx context.Context, tx pgx.Tx, serviceID uuid.UUID, instanceID, reason string, now time.Time) (int, error) {
	var n int
	err := tx.QueryRow(ctx, `
WITH doomed AS (
  SELECT id, cert_fingerprint FROM apm_agents
  WHERE service_id = $1 AND instance_id = $2 AND status <> 'REVOKED'
), rev AS (
  UPDATE apm_agents a SET status = 'REVOKED', revoked_at = $4, revoke_reason = $3
  FROM doomed d WHERE a.id = d.id
), ins AS (
  INSERT INTO apm_agent_cert_revocations (cert_fingerprint, agent_id, revoked_at, reason)
  SELECT cert_fingerprint, id, $4, 'superseded' FROM doomed
)
SELECT count(*) FROM doomed`,
		serviceID, instanceID, reason, now.UTC()).Scan(&n)
	if err != nil {
		return 0, err
	}
	return n, nil
}

// insertAgent 登记新 Agent（注册成功即 CONNECTED_BASELINE——注册事务完成即完成握手，
// ENROLLING 预留给后续多步注册形态）。调用方负责事务边界（EnrollAgent 第 7 步）。
func insertAgent(ctx context.Context, tx pgx.Tx, row *AgentRow) error {
	nodeInfo, _ := json.Marshal(row.NodeInfo)
	return tx.QueryRow(ctx, `
INSERT INTO apm_agents
  (id, service_id, instance_id, language, agent_version, sdk_version, status,
   cert_fingerprint, cert_not_after, node_info, registered_at)
VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10::jsonb, $11)
RETURNING registered_at`,
		row.ID, row.ServiceID, row.InstanceID, row.Language, row.AgentVersion, row.SdkVersion,
		AgentStatusConnectedBaseline, row.CertFingerprint, row.CertNotAfter, nodeInfo, row.RegisteredAt,
	).Scan(&row.RegisteredAt)
}

// AgentByCertFingerprint 按当前证书指纹反查登记行（PoP 认证身份来源：
// 指纹命中即证明证书由本 CA 签发且为登记在册身份）。
func (s *AgentStore) AgentByCertFingerprint(ctx context.Context, fingerprint string) (*AgentRow, error) {
	row := s.db.QueryRow(ctx, `
SELECT a.id, a.service_id, s.service_name, s.environment, s.application_id,
       a.instance_id, a.language, a.agent_version, a.sdk_version,
       a.status, a.status,
       a.cert_fingerprint, a.cert_not_after, a.last_heartbeat_at, a.node_info,
       a.registered_at, a.revoked_at, a.revoke_reason
FROM apm_agents a JOIN apm_services s ON s.id = a.service_id
WHERE a.cert_fingerprint = $1`, fingerprint)
	a, _, err := scanAgentRowWithTotal(row, false)
	if errors.Is(err, pgx.ErrNoRows) {
		return nil, ErrAgentNotFound
	}
	return a, err
}

// IsFingerprintRevoked 查询证书指纹是否在撤销列表（认证路径必查）。
func (s *AgentStore) IsFingerprintRevoked(ctx context.Context, fingerprint string) (bool, error) {
	var revoked bool
	err := s.db.QueryRow(ctx,
		`SELECT EXISTS(SELECT 1 FROM apm_agent_cert_revocations WHERE cert_fingerprint = $1)`,
		fingerprint).Scan(&revoked)
	return revoked, err
}

// RecordHeartbeat 刷新心跳（单语句 CTE 同事务语义更新服务 last_seen_at；
// 版本/节点信息仅在请求显式携带时覆盖；ENROLLING 残留行首心跳补进到
// CONNECTED_BASELINE——状态机 §8.3 合法迁移）。
func (s *AgentStore) RecordHeartbeat(ctx context.Context, agentID uuid.UUID, agentVersion, sdkVersion string, nodeInfo NodeInfo, now time.Time) error {
	var nodeInfoJSON []byte
	if nodeInfo != nil {
		nodeInfoJSON, _ = json.Marshal(nodeInfo)
	}
	res, err := s.db.Exec(ctx, `
WITH upd AS (
  UPDATE apm_agents SET
    last_heartbeat_at = $2,
    agent_version = CASE WHEN $3 <> '' THEN $3 ELSE agent_version END,
    sdk_version   = CASE WHEN $4 <> '' THEN $4 ELSE sdk_version END,
    node_info     = CASE WHEN $5::jsonb IS NOT NULL THEN $5 ELSE node_info END,
    status        = CASE WHEN status = 'ENROLLING' THEN 'CONNECTED_BASELINE' ELSE status END
  WHERE id = $1
  RETURNING service_id
)
UPDATE apm_services s SET last_seen_at = $2, updated_at = $2 FROM upd WHERE s.id = upd.service_id`,
		agentID, now.UTC(), agentVersion, sdkVersion, nodeInfoJSON)
	if err != nil {
		return err
	}
	if res.RowsAffected() == 0 {
		return ErrAgentNotFound
	}
	return nil
}

// RotateAgentCert 证书轮换（事务：出示证书须为当前生效证书；旧指纹入撤销列表
// reason=rotated；登记行切换到新指纹/新到期时间）。
func (s *AgentStore) RotateAgentCert(ctx context.Context, agentID uuid.UUID, oldFingerprint, newFingerprint string, notAfter, now time.Time) error {
	tx, err := s.db.Begin(ctx)
	if err != nil {
		return err
	}
	defer tx.Rollback(ctx)
	var currentFP, status string
	err = tx.QueryRow(ctx,
		`SELECT cert_fingerprint, status FROM apm_agents WHERE id = $1 FOR UPDATE`, agentID,
	).Scan(&currentFP, &status)
	if errors.Is(err, pgx.ErrNoRows) {
		return ErrAgentNotFound
	}
	if err != nil {
		return err
	}
	if currentFP != oldFingerprint {
		return ErrCertFingerprintMismatch
	}
	if status == AgentStatusRevoked {
		return ErrAgentAlreadyRevoked
	}
	if _, err := tx.Exec(ctx, `
INSERT INTO apm_agent_cert_revocations (cert_fingerprint, agent_id, revoked_at, reason)
VALUES ($1, $2, $3, 'rotated')`, oldFingerprint, agentID, now.UTC()); err != nil {
		return err
	}
	if _, err := tx.Exec(ctx, `
UPDATE apm_agents SET cert_fingerprint = $2, cert_not_after = $3 WHERE id = $1`,
		agentID, newFingerprint, notAfter.UTC()); err != nil {
		return err
	}
	return tx.Commit(ctx)
}

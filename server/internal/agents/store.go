// store.go 流量采集 Agent PostgreSQL 仓储：注册事务 / Bearer 反查 / 心跳与指标 /
// 配置拉取与 ACK / FLOW 批量入库 / RAW 计数 / 管理端 CRUD 与绑定。
//
// 关键口径：
//   - last_metrics 为「Agent 心跳 metrics 快照 + 服务端 RAW 累计计数」混合视图：
//     心跳/指标写入时保留 raw_frames_received/raw_bytes_received 两个服务端键不被覆盖，
//     RAW 通道经 AddRawCounters 原子累加（jsonb 合并，幂等性由 Agent 重传语义承担——
//     Phase 1 计数仅作容量观测，契约 §3.5 明确不入库）；
//   - status 永不落库（契约 §5 查询时派生），SQL 内派生表达式与 DeriveStatus 同口径
//     （窗口常量 OfflineAfterSeconds 为唯一事实源，经 make_interval 传参）；
//   - config_version 在策略更新/绑定/解绑时 +1（契约 §4：version 变化驱动 Agent 拉取）。
package agents

import (
	"context"
	"errors"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
	"github.com/jackc/pgx/v5/pgxpool"
)

// 仓储错误（handler 映射 HTTP 状态码）。
var (
	// ErrTokenInvalid 注册令牌无效/过期/已用/已撤销（契约 §3.1 → 401）。
	ErrTokenInvalid = errors.New("enrollment token invalid")
	// ErrAgentNotFound Agent 不存在。
	ErrAgentNotFound = errors.New("agent not found")
	// ErrPolicyNotFound 策略不存在。
	ErrPolicyNotFound = errors.New("agent policy not found")
	// ErrPolicyNameConflict 策略名冲突。
	ErrPolicyNameConflict = errors.New("agent policy name conflict")
	// ErrPolicyBound 策略仍被绑定，禁止删除（先解绑）。
	ErrPolicyBound = errors.New("agent policy still bound")
	// ErrNoBinding Agent 当前无生效绑定（解绑 404）。
	ErrNoBinding = errors.New("agent has no policy binding")
	// ErrPolicyVersionNotFound 策略历史版本不存在（回滚 404）。
	ErrPolicyVersionNotFound = errors.New("agent policy version not found")
	// ErrTokenNotFound 令牌不存在。
	ErrTokenNotFound = errors.New("enrollment token not found")
	// ErrTokenState 令牌已使用/已撤销，不可再撤销（409）。
	ErrTokenState = errors.New("enrollment token already used or revoked")
	// ErrCertFingerprintMismatch 出示证书非当前生效证书（轮换 409——契约 §9 同 APM 先例）。
	ErrCertFingerprintMismatch = errors.New("agent cert fingerprint mismatch")
)

// EnrollInput 注册输入（凭据明文由 handler 生成，本层只收摘要；
// CertFingerprint/CertNotAfter 为 Phase 2-B 可选——Agent 携带 CSR 注册时回填，nil 落 NULL）。
type EnrollInput struct {
	AgentID         uuid.UUID
	TokenHash       string
	CredentialHash  string
	Hostname        string
	IP              string
	OS              string
	Kernel          string
	Arch            string
	Version         string
	Interfaces      []InterfaceInfo
	CertFingerprint *string
	CertNotAfter    *time.Time
	// HTTPEventSchemas 能力协商生效集（v2 契约 §3；nil → 库默认 {1}）。
	HTTPEventSchemas      []int16
	APIObservationSchemas []int16
	Now                   time.Time
}

// RotateCertInput 证书轮换输入（Phase 2-B §9：旧指纹入撤销表 24h 宽限，当前指纹/到期换新）。
type RotateCertInput struct {
	AgentID        uuid.UUID
	OldFingerprint string    // 出示（当前生效）证书指纹；与库中当前指纹不一致 → ErrCertFingerprintMismatch
	OldNotBefore   time.Time // 旧证书生效起点（revocations.not_before）
	PublicKeyHash  string    // CSR 公钥 SHA-256；与旧指纹共同构成幂等键
	NewFingerprint string
	NewNotAfter    time.Time
	GraceUntil     time.Time // 旧指纹宽限截止（now+24h）
	Now            time.Time
	AgentCertPEM   string // 已签发身份，和状态推进在同一事务持久化
	CACertPEM      string
}

// RotateCertResult 是轮换响应的持久化副本。响应丢失后的同请求重试直接返回它。
type RotateCertResult struct {
	AgentCertPEM  string
	CACertPEM     string
	CertExpiresAt time.Time
}

// AgentFilter 管理端列表过滤（status 为派生状态过滤；q 匹配 hostname/ip/agent_id）。
type AgentFilter struct {
	Status string
	Q      string
	Page   PageParams
}

// MachineRepository 机器端点仓储（*Store 实现；machine handler 面向接口便于测试注入）。
type MachineRepository interface {
	// Enroll 注册事务：原子消费令牌（未用/未撤/未过期）→ 创建 Agent → 落网卡清单；
	// 任一步失败整体回滚（令牌不被烧毁）。
	Enroll(ctx context.Context, in EnrollInput) (*Agent, error)
	// AgentByCredentialHash Bearer 反查（摘要唯一）。
	AgentByCredentialHash(ctx context.Context, hash string) (*Agent, error)
	// RecordHeartbeat 心跳：last_seen/last_status/last_metrics（保留 RAW 累计键）+
	// last_clock_offset_ms（clockOffsetMS 为 nil 时保留原值——Agent 未上报有效 timestamp）；
	// schemas 为 v2 契约 §3 能力协商生效集（nil 保持原值——心跳未声明 capabilities）；
	// 返回当前 config_version 供响应携带。metrics 为 nil 时仅刷新活性与状态。
	RecordHeartbeat(ctx context.Context, agentID uuid.UUID, status string, metrics []byte, clockOffsetMS *int64, schemas []int16, now time.Time) (int64, error)
	// RecordMetrics 指标快照（契约 §3.2 /metrics，与心跳同处理逻辑，不动 last_status）。
	RecordMetrics(ctx context.Context, agentID uuid.UUID, metrics []byte, now time.Time) error
	// AgentConfig 配置拉取：config_version + 绑定策略（无绑定 policy 为 nil）。
	AgentConfig(ctx context.Context, agentID uuid.UUID) (int64, *Policy, error)
	// AckConfig 配置 ACK：APPLIED 回填 applied_config_version（FAILED 不回填）。
	AckConfig(ctx context.Context, agentID uuid.UUID, version int64, applied bool) error
	// InsertFlowEvents FLOW 事件批量入库（整批失败整体报错，Agent 转本地缓存——契约 §3.4）。
	InsertFlowEvents(ctx context.Context, agentID uuid.UUID, events []FlowEvent) error
	// InsertHTTPEvents HTTP 事件批量入库（整批失败整体报错——Phase 3 契约 §3：
	// 入库失败整体 500，Agent 落本地缓存补传）。
	InsertHTTPEvents(ctx context.Context, agentID uuid.UUID, records []HTTPRecord) error
	// InsertHTTPEventsV2 v2 批次入库（v2 契约 §4：单事务逐条 ON CONFLICT 幂等去重——
	// 重复确认但不重复入库；返回新入库记录的输入下标与重复条数；失败整批回滚）。
	InsertHTTPEventsV2(ctx context.Context, agentID uuid.UUID, records []HTTPRecordV2, ingestionTS time.Time) (acceptedIdx []int, duplicates int, err error)
	// UpsertHTTPAssetSource 资产来源关系持久化（v2 契约 §5；多来源各自成行，
	// 首次/末次观测与关联状态可查询，不覆盖既有资产所有权）。
	UpsertHTTPAssetSource(ctx context.Context, in HTTPAssetSourceInput) error
	// AddRawCounters RAW 通道计数累加（last_metrics.raw_frames_received/raw_bytes_received）。
	AddRawCounters(ctx context.Context, agentID uuid.UUID, frames, bytes int64) error
	// AgentByID 按路径 agent_id 反查（PoP 认证身份解析——Phase 2-B §8）。
	AgentByID(ctx context.Context, agentID uuid.UUID) (*Agent, error)
	// CertFingerprintUsable 证书指纹可用性（契约 §10：== agents 当前指纹，
	// 或存在于 revocations 且 grace_until > now——宽限中；立即撤销 grace_until=NULL 不可用）。
	CertFingerprintUsable(ctx context.Context, agentID uuid.UUID, fingerprint string, now time.Time) (bool, error)
	// RotateAgentCert 证书轮换（契约 §9）：同一 agent+旧指纹+CSR 公钥重试返回已签发身份；
	// 首次请求将响应和状态推进在同一事务提交，避免响应丢失后无法恢复。
	RotateAgentCert(ctx context.Context, in RotateCertInput) (*RotateCertResult, error)
	// ActiveCaptureOverrides 未过期定向采集规则全量（Phase 4 契约 §2.4 config 下发）。
	ActiveCaptureOverrides(ctx context.Context, agentID uuid.UUID, now time.Time) ([]CaptureOverride, error)
}

// AdminRepository 管理端点仓储（*Store 实现；admin handler 面向接口便于测试注入）。
type AdminRepository interface {
	CreateEnrollmentToken(ctx context.Context, tokenHash, label string, expiresAt time.Time, createdBy string) (*EnrollmentToken, error)
	ListEnrollmentTokens(ctx context.Context) ([]EnrollmentToken, error)
	RevokeEnrollmentToken(ctx context.Context, id uuid.UUID, now time.Time) error
	Summary(ctx context.Context) (Summary, error)
	ListAgents(ctx context.Context, f AgentFilter) ([]Agent, int64, error)
	GetAgent(ctx context.Context, agentID uuid.UUID) (*AgentDetail, error)
	SetAgentDisabled(ctx context.Context, agentID uuid.UUID, disabled bool) error
	DeleteAgent(ctx context.Context, agentID uuid.UUID) error
	ListFlowEvents(ctx context.Context, agentID uuid.UUID, p PageParams) ([]FlowEventRow, int64, error)
	// ListHTTPEvents HTTP 事件分页（host/method 过滤，ts 倒序；不含 headers/body——Phase 3 契约 §6）。
	ListHTTPEvents(ctx context.Context, agentID uuid.UUID, f HTTPEventFilter) ([]HTTPEventRow, int64, error)
	// GetHTTPEvent HTTP 事件单条全量（含 headers/body；不属于该 Agent → ErrHTTPEventNotFound）。
	GetHTTPEvent(ctx context.Context, agentID uuid.UUID, id int64) (*HTTPEventRow, error)
	// ListHTTPAssetSources 资产来源关系分页（v2 契约 §5；state 精确过滤，last_seen_at 倒序）。
	ListHTTPAssetSources(ctx context.Context, agentID uuid.UUID, f HTTPAssetSourceFilter) ([]HTTPAssetSourceRow, int64, error)
	CreatePolicy(ctx context.Context, name string, config []byte, createdBy string) (*Policy, error)
	ListPolicies(ctx context.Context) ([]Policy, error)
	GetPolicy(ctx context.Context, id uuid.UUID) (*Policy, error)
	// UpdatePolicy 修改策略（version+1）、快照新版本到 agent_policy_versions，
	// 并把所有绑定该策略的 Agent config_version+1（同一事务）。
	UpdatePolicy(ctx context.Context, id uuid.UUID, name string, config []byte, actor string) (*Policy, error)
	DeletePolicy(ctx context.Context, id uuid.UUID) error
	// ListPolicyVersions 策略历史版本列表（version 倒序；策略不存在 → ErrPolicyNotFound）。
	ListPolicyVersions(ctx context.Context, policyID uuid.UUID) ([]PolicyVersion, error)
	// RollbackPolicy 以历史版本 config 生成新版本（version+1，同事务快照），
	// 并把绑定该策略的 Agent config_version+1（设计 §68.14 回滚语义）；
	// 版本不存在 → ErrPolicyVersionNotFound。
	RollbackPolicy(ctx context.Context, id uuid.UUID, version int, actor string) (*Policy, error)
	// BindPolicy 绑定/换绑（每 Agent 唯一生效绑定；绑定后 config_version+1，同一事务）。
	BindPolicy(ctx context.Context, agentID, policyID uuid.UUID, boundBy string) error
	// UnbindPolicy 解绑（config_version+1，同一事务；无绑定返回 ErrNoBinding）。
	UnbindPolicy(ctx context.Context, agentID uuid.UUID) error
	// ListCaptureOverrides 定向采集规则列表（含已过期，管理端标注 inactive——Phase 4 契约 §2.3）。
	ListCaptureOverrides(ctx context.Context, agentID uuid.UUID) ([]CaptureOverride, error)
	// CreateCaptureOverride 创建定向采集规则（同事务 config_version+1；契约 §2.3）。
	CreateCaptureOverride(ctx context.Context, in CaptureOverrideInput) (*CaptureOverride, error)
	// DeleteCaptureOverride 删除定向采集规则（同事务 config_version+1；返回被删行供审计；
	// 不存在/不属于该 Agent → ErrCaptureOverrideNotFound）。
	DeleteCaptureOverride(ctx context.Context, agentID, overrideID uuid.UUID, now time.Time) (*CaptureOverride, error)
}

// Repository 组合接口（*Store 断言用）。
type Repository interface {
	MachineRepository
	AdminRepository
}

// Store 流量采集 Agent PostgreSQL 仓储。
type Store struct {
	db *pgxpool.Pool
}

// NewStore 创建。
func NewStore(db *pgxpool.Pool) *Store { return &Store{db: db} }

var _ Repository = (*Store)(nil)

// ---------- 机器端 ----------

// Enroll 注册事务（令牌原子消费与 Agent 创建同生共死）。
func (s *Store) Enroll(ctx context.Context, in EnrollInput) (*Agent, error) {
	tx, err := s.db.Begin(ctx)
	if err != nil {
		return nil, err
	}
	defer tx.Rollback(ctx)

	var tokenID uuid.UUID
	err = tx.QueryRow(ctx, `
UPDATE agent_enrollment_tokens
SET used_at = $2, used_by_agent_id = $3
WHERE token_hash = $1 AND used_at IS NULL AND revoked_at IS NULL AND expires_at > $2
RETURNING id`, in.TokenHash, in.Now.UTC(), in.AgentID).Scan(&tokenID)
	if errors.Is(err, pgx.ErrNoRows) {
		return nil, ErrTokenInvalid
	}
	if err != nil {
		return nil, err
	}
	schemas := in.HTTPEventSchemas
	if len(schemas) == 0 {
		schemas = []int16{1}
	}
	if _, err := tx.Exec(ctx, `
INSERT INTO agents
(agent_id, hostname, ip, os, kernel, arch, version, credential_hash, enrollment_token_id,
 agent_cert_fingerprint, agent_cert_not_after, http_event_schemas, api_observation_schemas, created_at, updated_at)
VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,$14,$14)`,
		in.AgentID, in.Hostname, in.IP, in.OS, in.Kernel, in.Arch, in.Version,
		in.CredentialHash, tokenID, in.CertFingerprint, in.CertNotAfter, schemas, in.APIObservationSchemas, in.Now.UTC()); err != nil {
		return nil, err
	}
	for _, ifc := range in.Interfaces {
		if _, err := tx.Exec(ctx, `
INSERT INTO agent_interfaces (agent_id, name, mac, ipv4, ipv6, mtu, speed_mbps)
VALUES ($1,$2,$3,$4,$5,$6,$7)`,
			in.AgentID, ifc.Name, ifc.MAC, ifc.IPv4, ifc.IPv6, ifc.MTU, ifc.SpeedMbps); err != nil {
			return nil, err
		}
	}
	if err := tx.Commit(ctx); err != nil {
		return nil, err
	}
	return &Agent{
		AgentID: in.AgentID, Hostname: in.Hostname, IP: in.IP, OS: in.OS,
		Kernel: in.Kernel, Arch: in.Arch, Version: in.Version,
		LastMetrics: []byte(`{}`), CreatedAt: in.Now.UTC(),
		HTTPEventSchemas: int16SliceToInt(schemas), APIObservationSchemas: int16SliceToInt(in.APIObservationSchemas),
	}, nil
}

const agentCols = `agent_id, hostname, ip, os, kernel, arch, version, credential_hash,
	disabled, enrollment_token_id, last_seen, last_status, last_metrics,
	config_version, applied_config_version, last_clock_offset_ms, created_at,
	agent_cert_fingerprint, agent_cert_not_after, http_event_schemas, api_observation_schemas`

type rowScanner interface {
	Scan(dest ...interface{}) error
}

func scanAgent(row rowScanner, a *Agent) error {
	var schemas, apiSchemas []int16
	err := row.Scan(&a.AgentID, &a.Hostname, &a.IP, &a.OS, &a.Kernel, &a.Arch, &a.Version,
		&a.CredentialHash, &a.Disabled, &a.EnrollmentTokenID, &a.LastSeen, &a.LastStatus,
		&a.LastMetrics, &a.ConfigVersion, &a.AppliedConfigVersion, &a.ClockOffsetMS, &a.CreatedAt,
		&a.CertFingerprint, &a.CertNotAfter, &schemas, &apiSchemas)
	if err != nil {
		return err
	}
	a.HTTPEventSchemas = int16SliceToInt(schemas)
	a.APIObservationSchemas = int16SliceToInt(apiSchemas)
	return nil
}

func int16SliceToInt(values []int16) []int {
	out := make([]int, 0, len(values))
	for _, value := range values {
		out = append(out, int(value))
	}
	return out
}

// AgentByCredentialHash Bearer 反查（摘要 UNIQUE；未登记 → ErrAgentNotFound）。
func (s *Store) AgentByCredentialHash(ctx context.Context, hash string) (*Agent, error) {
	row := s.db.QueryRow(ctx, `SELECT `+agentCols+` FROM agents WHERE credential_hash=$1`, hash)
	var a Agent
	if err := scanAgent(row, &a); err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return nil, ErrAgentNotFound
		}
		return nil, err
	}
	return &a, nil
}

// rawKeepExpr 心跳/指标写入时保留服务端 RAW 累计键的 jsonb 片段。
const rawKeepExpr = `jsonb_build_object(
	'raw_frames_received', COALESCE((last_metrics->>'raw_frames_received')::bigint, 0),
	'raw_bytes_received',  COALESCE((last_metrics->>'raw_bytes_received')::bigint, 0))`

// RecordHeartbeat 心跳落活性/自报状态/metrics 快照（RAW 累计键不被 Agent 快照覆盖）+
// 时钟偏移（clockOffsetMS 为 nil——Agent 未上报有效 timestamp——保留原值不清空）+
// 能力协商生效集（schemas 为 nil——心跳未声明 capabilities——保留原值，v2 契约 §3）。
func (s *Store) RecordHeartbeat(ctx context.Context, agentID uuid.UUID, status string, metrics []byte, clockOffsetMS *int64, schemas []int16, now time.Time) (int64, error) {
	var cfgVersion int64
	err := s.db.QueryRow(ctx, `
UPDATE agents SET
  last_seen = $2,
  last_status = $3,
  last_metrics = CASE WHEN $4::jsonb IS NULL THEN last_metrics
                      ELSE $4::jsonb || `+rawKeepExpr+` END,
  last_clock_offset_ms = CASE WHEN $5::bigint IS NULL THEN last_clock_offset_ms
                              ELSE $5 END,
  http_event_schemas = CASE WHEN $6::smallint[] IS NULL THEN http_event_schemas
                            ELSE $6 END,
  updated_at = $2
WHERE agent_id = $1
RETURNING config_version`,
		agentID, now.UTC(), status, nullableJSON(metrics), clockOffsetMS, nullableInt16Slice(schemas)).Scan(&cfgVersion)
	if errors.Is(err, pgx.ErrNoRows) {
		return 0, ErrAgentNotFound
	}
	return cfgVersion, err
}

// nullableInt16Slice nil 切片传 NULL（心跳未声明 capabilities 时保持库中原值）。
func nullableInt16Slice(v []int16) interface{} {
	if v == nil {
		return nil
	}
	return v
}

// RecordMetrics 指标快照（与心跳同处理逻辑；不动 last_status）。
func (s *Store) RecordMetrics(ctx context.Context, agentID uuid.UUID, metrics []byte, now time.Time) error {
	res, err := s.db.Exec(ctx, `
UPDATE agents SET
  last_seen = $2,
  last_metrics = $3::jsonb || `+rawKeepExpr+`,
  updated_at = $2
WHERE agent_id = $1`, agentID, now.UTC(), metrics)
	if err != nil {
		return err
	}
	if res.RowsAffected() == 0 {
		return ErrAgentNotFound
	}
	return nil
}

// nullableJSON 空 metrics 传 NULL（心跳可不带 metrics 仅刷新活性）。
func nullableJSON(metrics []byte) interface{} {
	if len(metrics) == 0 {
		return nil
	}
	return metrics
}

// AgentConfig 配置拉取（LEFT JOIN 绑定与策略；无绑定 policy=nil）。
func (s *Store) AgentConfig(ctx context.Context, agentID uuid.UUID) (int64, *Policy, error) {
	var cfgVersion int64
	var pid *uuid.UUID
	var pname *string
	var pconfig []byte
	var pversion *int
	err := s.db.QueryRow(ctx, `
SELECT a.config_version, p.id, p.name, p.config, p.version
FROM agents a
LEFT JOIN agent_policy_bindings b ON b.agent_id = a.agent_id
LEFT JOIN agent_policies p ON p.id = b.policy_id
WHERE a.agent_id = $1`, agentID).Scan(&cfgVersion, &pid, &pname, &pconfig, &pversion)
	if errors.Is(err, pgx.ErrNoRows) {
		return 0, nil, ErrAgentNotFound
	}
	if err != nil {
		return 0, nil, err
	}
	if pid == nil {
		return cfgVersion, nil, nil
	}
	return cfgVersion, &Policy{ID: *pid, Name: *pname, Config: pconfig, Version: *pversion}, nil
}

// AckConfig 配置 ACK 回填（仅 APPLIED 推进 applied_config_version）。
func (s *Store) AckConfig(ctx context.Context, agentID uuid.UUID, version int64, applied bool) error {
	if !applied {
		return nil
	}
	res, err := s.db.Exec(ctx, `
UPDATE agents SET applied_config_version=$2, updated_at=now() WHERE agent_id=$1`, agentID, version)
	if err != nil {
		return err
	}
	if res.RowsAffected() == 0 {
		return ErrAgentNotFound
	}
	return nil
}

// flowEventCols CopyFrom 列序（id/created_at 由库默认生成）。
var flowEventCols = []string{
	"agent_id", "ts", "event_type", "flow_id", "src_ip", "src_port", "dst_ip", "dst_port",
	"protocol", "direction", "bytes_in", "bytes_out", "packets_in", "packets_out",
	"tls_visibility", "http_method", "http_host", "http_uri", "http_status",
	"k8s",
}

// InsertFlowEvents FLOW 事件批量入库（CopyFrom 单轮整批；失败整体报错——契约 §3.4）。
func (s *Store) InsertFlowEvents(ctx context.Context, agentID uuid.UUID, events []FlowEvent) error {
	rows := make([][]interface{}, 0, len(events))
	for i := range events {
		e := &events[i]
		rows = append(rows, []interface{}{
			agentID, time.Unix(e.Timestamp, 0).UTC(), e.EventType, e.FlowID,
			e.SrcIP, e.SrcPort, e.DstIP, e.DstPort, e.Protocol, e.Direction,
			e.BytesIn, e.BytesOut, e.PacketsIn, e.PacketsOut,
			e.TLSVisibility, e.HTTPMethod, e.HTTPHost, e.HTTPURI, e.HTTPStatus,
			marshalK8sMetadata(e.K8s),
		})
	}
	_, err := s.db.CopyFrom(ctx, pgx.Identifier{"agent_flow_events"}, flowEventCols, pgx.CopyFromRows(rows))
	return err
}

// AddRawCounters RAW 通道计数原子累加（契约 §3.5：计数后丢弃，不入库）。
func (s *Store) AddRawCounters(ctx context.Context, agentID uuid.UUID, frames, bytes int64) error {
	res, err := s.db.Exec(ctx, `
UPDATE agents SET last_metrics = last_metrics || jsonb_build_object(
	'raw_frames_received', COALESCE((last_metrics->>'raw_frames_received')::bigint, 0) + $2,
	'raw_bytes_received',  COALESCE((last_metrics->>'raw_bytes_received')::bigint, 0) + $3)
WHERE agent_id = $1`, agentID, frames, bytes)
	if err != nil {
		return err
	}
	if res.RowsAffected() == 0 {
		return ErrAgentNotFound
	}
	return nil
}

// AgentByID 按路径 agent_id 反查（PoP 认证身份解析；未登记 → ErrAgentNotFound）。
func (s *Store) AgentByID(ctx context.Context, agentID uuid.UUID) (*Agent, error) {
	row := s.db.QueryRow(ctx, `SELECT `+agentCols+` FROM agents WHERE agent_id=$1`, agentID)
	var a Agent
	if err := scanAgent(row, &a); err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return nil, ErrAgentNotFound
		}
		return nil, err
	}
	return &a, nil
}

// CertFingerprintUsable 证书指纹可用性（契约 §10 语义：当前指纹直接可用；
// 撤销表中仅 grace_until > now 的宽限行可用，grace_until IS NULL 为立即撤销）。
func (s *Store) CertFingerprintUsable(ctx context.Context, agentID uuid.UUID, fingerprint string, now time.Time) (bool, error) {
	var ok bool
	err := s.db.QueryRow(ctx, `
SELECT EXISTS(SELECT 1 FROM agents WHERE agent_id=$1 AND agent_cert_fingerprint=$2)
    OR EXISTS(SELECT 1 FROM agent_cert_revocations
              WHERE agent_id=$1 AND fingerprint=$2 AND grace_until IS NOT NULL AND grace_until > $3)`,
		agentID, fingerprint, now.UTC()).Scan(&ok)
	return ok, err
}

// RotateAgentCert 证书轮换（契约 §9）：行锁校验出示指纹==当前指纹 → 旧指纹入撤销表
// （grace_until=now+24h 宽限，not_before 取旧证书生效起点）→ 当前指纹/到期换新；同一事务。
// 已提交的相同 agent+旧指纹+CSR 公钥请求在状态校验前重放，避免响应丢失后重复签发/推进。
func (s *Store) RotateAgentCert(ctx context.Context, in RotateCertInput) (*RotateCertResult, error) {
	tx, err := s.db.Begin(ctx)
	if err != nil {
		return nil, err
	}
	defer tx.Rollback(ctx)
	var current *string
	err = tx.QueryRow(ctx,
		`SELECT agent_cert_fingerprint FROM agents WHERE agent_id=$1 FOR UPDATE`, in.AgentID).Scan(&current)
	if errors.Is(err, pgx.ErrNoRows) {
		return nil, ErrAgentNotFound
	}
	if err != nil {
		return nil, err
	}
	var replay RotateCertResult
	err = tx.QueryRow(ctx, `
SELECT agent_cert_pem, ca_cert_pem, new_not_after
FROM agent_cert_rotations
WHERE agent_id=$1 AND old_fingerprint=$2 AND public_key_sha256=$3`,
		in.AgentID, in.OldFingerprint, in.PublicKeyHash).Scan(&replay.AgentCertPEM, &replay.CACertPEM, &replay.CertExpiresAt)
	if err == nil {
		return &replay, nil
	}
	if !errors.Is(err, pgx.ErrNoRows) {
		return nil, err
	}
	if current == nil || *current != in.OldFingerprint {
		return nil, ErrCertFingerprintMismatch
	}
	if _, err := tx.Exec(ctx, `
INSERT INTO agent_cert_revocations (agent_id, fingerprint, revoked_at, not_before, grace_until, reason)
VALUES ($1,$2,$3,$4,$5,'rotate')`,
		in.AgentID, in.OldFingerprint, in.Now.UTC(), in.OldNotBefore.UTC(), in.GraceUntil.UTC()); err != nil {
		return nil, err
	}
	if _, err := tx.Exec(ctx, `
UPDATE agents SET agent_cert_fingerprint=$2, agent_cert_not_after=$3, updated_at=$4
WHERE agent_id=$1`, in.AgentID, in.NewFingerprint, in.NewNotAfter.UTC(), in.Now.UTC()); err != nil {
		return nil, err
	}
	if _, err := tx.Exec(ctx, `
INSERT INTO agent_cert_rotations
 (agent_id, old_fingerprint, public_key_sha256, new_fingerprint, agent_cert_pem, ca_cert_pem,
  old_not_before, grace_until, new_not_after, created_at)
VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10)`,
		in.AgentID, in.OldFingerprint, in.PublicKeyHash, in.NewFingerprint, in.AgentCertPEM, in.CACertPEM,
		in.OldNotBefore.UTC(), in.GraceUntil.UTC(), in.NewNotAfter.UTC(), in.Now.UTC()); err != nil {
		return nil, err
	}
	if err := tx.Commit(ctx); err != nil {
		return nil, err
	}
	return &RotateCertResult{AgentCertPEM: in.AgentCertPEM, CACertPEM: in.CACertPEM, CertExpiresAt: in.NewNotAfter}, nil
}

// ---------- 管理端：注册令牌 ----------

// CreateEnrollmentToken 签发令牌（只存摘要；明文由 handler 生成并仅本次返回）。
func (s *Store) CreateEnrollmentToken(ctx context.Context, tokenHash, label string, expiresAt time.Time, createdBy string) (*EnrollmentToken, error) {
	row := s.db.QueryRow(ctx, `
INSERT INTO agent_enrollment_tokens (token_hash, label, expires_at, created_by)
VALUES ($1,$2,$3,$4)
RETURNING id, label, expires_at, used_at, used_by_agent_id, revoked_at, created_by, created_at`,
		tokenHash, label, expiresAt.UTC(), createdBy)
	return scanToken(row)
}

// ListEnrollmentTokens 令牌列表（不含摘要更不含明文；created_at 倒序）。
func (s *Store) ListEnrollmentTokens(ctx context.Context) ([]EnrollmentToken, error) {
	rows, err := s.db.Query(ctx, `
SELECT id, label, expires_at, used_at, used_by_agent_id, revoked_at, created_by, created_at
FROM agent_enrollment_tokens ORDER BY created_at DESC`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := []EnrollmentToken{}
	for rows.Next() {
		t, err := scanToken(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, *t)
	}
	return out, rows.Err()
}

func scanToken(row rowScanner) (*EnrollmentToken, error) {
	var t EnrollmentToken
	if err := row.Scan(&t.ID, &t.Label, &t.ExpiresAt, &t.UsedAt, &t.UsedByAgentID,
		&t.RevokedAt, &t.CreatedBy, &t.CreatedAt); err != nil {
		return nil, err
	}
	return &t, nil
}

// RevokeEnrollmentToken 撤销（仅未使用且未撤销的令牌可撤销；已用/已撤 → ErrTokenState 409）。
func (s *Store) RevokeEnrollmentToken(ctx context.Context, id uuid.UUID, now time.Time) error {
	res, err := s.db.Exec(ctx, `
UPDATE agent_enrollment_tokens SET revoked_at=$2
WHERE id=$1 AND used_at IS NULL AND revoked_at IS NULL`, id, now.UTC())
	if err != nil {
		return err
	}
	if res.RowsAffected() > 0 {
		return nil
	}
	var usedAt, revokedAt *time.Time
	err = s.db.QueryRow(ctx, `SELECT used_at, revoked_at FROM agent_enrollment_tokens WHERE id=$1`, id).
		Scan(&usedAt, &revokedAt)
	if errors.Is(err, pgx.ErrNoRows) {
		return ErrTokenNotFound
	}
	if err != nil {
		return err
	}
	return ErrTokenState
}

// ---------- 管理端：Agent 查询 ----------

// derivedStatusSQL 派生状态 SQL 表达式（与 DeriveStatus 同口径；$1 = 离线窗口秒数）。
const derivedStatusSQL = `CASE WHEN disabled THEN 'DISABLED'
	WHEN last_seen IS NULL OR last_seen < now() - make_interval(secs => $1) THEN 'OFFLINE'
	WHEN last_status IN ('ONLINE','DEGRADED','ERROR') THEN last_status
	ELSE 'ONLINE' END`

// Summary 状态汇总（契约 §4）。degraded 桶含 DEGRADED 与 ERROR 自报状态
// （契约响应键无 error 桶，ERROR 如实归入 degraded 一档，保持五键合计=total）。
func (s *Store) Summary(ctx context.Context) (Summary, error) {
	var sum Summary
	err := s.db.QueryRow(ctx, `
SELECT count(*),
       count(*) FILTER (WHERE disabled),
       count(*) FILTER (WHERE NOT disabled AND (last_seen IS NULL OR last_seen < now() - make_interval(secs => $1))),
       count(*) FILTER (WHERE NOT disabled AND last_seen IS NOT NULL
                        AND last_seen >= now() - make_interval(secs => $1)
                        AND COALESCE(NULLIF(last_status, ''), 'ONLINE') = 'ONLINE'),
       count(*) FILTER (WHERE NOT disabled AND last_seen IS NOT NULL
                        AND last_seen >= now() - make_interval(secs => $1)
                        AND last_status IN ('DEGRADED','ERROR'))
FROM agents`, OfflineAfterSeconds).
		Scan(&sum.Total, &sum.Disabled, &sum.Offline, &sum.Online, &sum.Degraded)
	return sum, err
}

// policyLimitCols 健康评分输入提取（绑定策略 config 中的自我保护/缓存上限；
// 无绑定或缺省键 → 0，评分公式按默认阈值或跳过对应档位——health.go）。
const policyLimitCols = `
	COALESCE((p.config->'limits'->>'cpu_percent')::float8, 0),
	COALESCE((p.config->'limits'->>'memory_mb')::float8, 0),
	COALESCE((p.config->'buffer'->>'max_size_mb')::float8, 0)`

// policyLimitJoin 绑定策略 LEFT JOIN（agentRef 为调用方表别名如 "v"/"a"；
// 每 Agent 至多一条生效绑定，不放大行数）。
func policyLimitJoin(agentRef string) string {
	return `
	LEFT JOIN agent_policy_bindings pb ON pb.agent_id = ` + agentRef + `.agent_id
	LEFT JOIN agent_policies p ON p.id = pb.policy_id`
}

// ListAgents 分页列表（status 为派生状态过滤；q 匹配 hostname/ip/agent_id；created_at 倒序）。
func (s *Store) ListAgents(ctx context.Context, f AgentFilter) ([]Agent, int64, error) {
	rows, err := s.db.Query(ctx, `
WITH view AS (
  SELECT agent_id, hostname, ip, os, kernel, arch, version, disabled,
         last_seen, last_status, last_metrics, config_version, applied_config_version,
         last_clock_offset_ms, created_at,
         `+derivedStatusSQL+` AS status
  FROM agents
)
SELECT v.agent_id, v.hostname, v.ip, v.os, v.kernel, v.arch, v.version, v.disabled, v.status,
       v.last_seen, v.last_status, v.last_metrics, v.config_version, v.applied_config_version,
       v.last_clock_offset_ms, v.created_at,
       `+policyLimitCols+`,
       count(*) OVER () AS total
FROM view v`+policyLimitJoin("v")+`
WHERE ($2::text = '' OR v.status = $2)
  AND ($3::text = '' OR v.hostname ILIKE '%'||$3||'%' OR v.ip ILIKE '%'||$3||'%' OR v.agent_id::text = $3)
ORDER BY v.created_at DESC
LIMIT $4 OFFSET $5`,
		OfflineAfterSeconds, f.Status, f.Q, f.Page.PageSize, f.Page.Offset())
	if err != nil {
		return nil, 0, err
	}
	defer rows.Close()
	out := []Agent{}
	var total int64
	for rows.Next() {
		var a Agent
		if err := rows.Scan(&a.AgentID, &a.Hostname, &a.IP, &a.OS, &a.Kernel, &a.Arch, &a.Version,
			&a.Disabled, &a.Status, &a.LastSeen, &a.LastStatus, &a.LastMetrics,
			&a.ConfigVersion, &a.AppliedConfigVersion, &a.ClockOffsetMS, &a.CreatedAt,
			&a.cpuLimitPercent, &a.memoryLimitMB, &a.bufferLimitMB, &total); err != nil {
			return nil, 0, err
		}
		out = append(out, a)
	}
	return out, total, rows.Err()
}

// GetAgent 详情（基础字段 + interfaces + policy_binding + 当前证书指纹/到期——
// Phase 2-B §11 详情增量，无证书为 NULL；000133 起含 http_event_schemas 能力协商生效集——
// 任务书 P1-03 §4.3 管理端「需升级」判定依据字段；不存在 → ErrAgentNotFound）。
func (s *Store) GetAgent(ctx context.Context, agentID uuid.UUID) (*AgentDetail, error) {
	row := s.db.QueryRow(ctx, `
SELECT a.agent_id, a.hostname, a.ip, a.os, a.kernel, a.arch, a.version, a.disabled,
       a.last_seen, a.last_status, a.last_metrics, a.config_version, a.applied_config_version,
       a.last_clock_offset_ms, a.created_at, a.agent_cert_fingerprint, a.agent_cert_not_after,
       a.http_event_schemas,
       `+policyLimitCols+`
FROM agents a`+policyLimitJoin("a")+`
WHERE a.agent_id=$1`, agentID)
	var d AgentDetail
	var schemas []int16
	if err := row.Scan(&d.AgentID, &d.Hostname, &d.IP, &d.OS, &d.Kernel, &d.Arch, &d.Version,
		&d.Disabled, &d.LastSeen, &d.LastStatus, &d.LastMetrics,
		&d.ConfigVersion, &d.AppliedConfigVersion, &d.ClockOffsetMS, &d.CreatedAt,
		&d.CertFingerprint, &d.CertNotAfter, &schemas,
		&d.cpuLimitPercent, &d.memoryLimitMB, &d.bufferLimitMB); err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return nil, ErrAgentNotFound
		}
		return nil, err
	}
	// 能力集归一：库列 NOT NULL DEFAULT '{1}'；空集兜底 {1}（仅 v1——旧 Agent 语义）。
	d.HTTPEventSchemas = make([]int, 0, len(schemas))
	for _, v := range schemas {
		d.HTTPEventSchemas = append(d.HTTPEventSchemas, int(v))
	}
	if len(d.HTTPEventSchemas) == 0 {
		d.HTTPEventSchemas = []int{1}
	}
	ifRows, err := s.db.Query(ctx, `
SELECT name, mac, ipv4, ipv6, mtu, speed_mbps
FROM agent_interfaces WHERE agent_id=$1 ORDER BY name`, agentID)
	if err != nil {
		return nil, err
	}
	defer ifRows.Close()
	d.Interfaces = []InterfaceInfo{}
	for ifRows.Next() {
		var ifc InterfaceInfo
		if err := ifRows.Scan(&ifc.Name, &ifc.MAC, &ifc.IPv4, &ifc.IPv6, &ifc.MTU, &ifc.SpeedMbps); err != nil {
			return nil, err
		}
		d.Interfaces = append(d.Interfaces, ifc)
	}
	if err := ifRows.Err(); err != nil {
		return nil, err
	}
	var b PolicyBinding
	err = s.db.QueryRow(ctx, `
SELECT p.id, p.name, p.version, b.bound_by, b.updated_at
FROM agent_policy_bindings b JOIN agent_policies p ON p.id = b.policy_id
WHERE b.agent_id=$1`, agentID).
		Scan(&b.PolicyID, &b.PolicyName, &b.PolicyVersion, &b.BoundBy, &b.BoundAt)
	switch {
	case errors.Is(err, pgx.ErrNoRows):
		d.PolicyBinding = nil
	case err != nil:
		return nil, err
	default:
		d.PolicyBinding = &b
	}
	return &d, nil
}

// SetAgentDisabled 禁用/启用（desired_state 经心跳下发；契约 §4）。
// 吊销即禁用（Phase 2-B §11）：禁用时把当前证书指纹写入撤销表（grace_until=NULL，
// 立即撤销）并清空当前指纹/到期——同一事务；启用不回滚撤销（证书吊销为终态，
// Agent 需重新注册或后续轮换流程恢复证书）。
func (s *Store) SetAgentDisabled(ctx context.Context, agentID uuid.UUID, disabled bool) error {
	tx, err := s.db.Begin(ctx)
	if err != nil {
		return err
	}
	defer tx.Rollback(ctx)
	res, err := tx.Exec(ctx, `
UPDATE agents SET disabled=$2, updated_at=now() WHERE agent_id=$1`, agentID, disabled)
	if err != nil {
		return err
	}
	if res.RowsAffected() == 0 {
		return ErrAgentNotFound
	}
	if disabled {
		if _, err := tx.Exec(ctx, `
INSERT INTO agent_cert_revocations (agent_id, fingerprint, revoked_at, reason)
SELECT agent_id, agent_cert_fingerprint, now(), 'agent disabled'
FROM agents WHERE agent_id=$1 AND agent_cert_fingerprint IS NOT NULL`, agentID); err != nil {
			return err
		}
		if _, err := tx.Exec(ctx, `
UPDATE agents SET agent_cert_fingerprint=NULL, agent_cert_not_after=NULL
WHERE agent_id=$1 AND agent_cert_fingerprint IS NOT NULL`, agentID); err != nil {
			return err
		}
	}
	return tx.Commit(ctx)
}

// DeleteAgent 删除 Agent（credential 随行吊销；网卡/绑定/流量事件 ON DELETE CASCADE；
// 操作审计不受影响——契约 §4 删除语义）。
// 契约 §11：删除前把当前证书指纹写入撤销表（grace_until=NULL，立即撤销）；
// 该撤销行随 Agent 删除被 CASCADE 清理（Agent 行不存在证书亦无法再认证，语义等价），
// 持久溯源由 delete 操作审计承担。
func (s *Store) DeleteAgent(ctx context.Context, agentID uuid.UUID) error {
	tx, err := s.db.Begin(ctx)
	if err != nil {
		return err
	}
	defer tx.Rollback(ctx)
	if _, err := tx.Exec(ctx, `
INSERT INTO agent_cert_revocations (agent_id, fingerprint, revoked_at, reason)
SELECT agent_id, agent_cert_fingerprint, now(), 'agent deleted'
FROM agents WHERE agent_id=$1 AND agent_cert_fingerprint IS NOT NULL`, agentID); err != nil {
		return err
	}
	res, err := tx.Exec(ctx, `DELETE FROM agents WHERE agent_id=$1`, agentID)
	if err != nil {
		return err
	}
	if res.RowsAffected() == 0 {
		return ErrAgentNotFound
	}
	return tx.Commit(ctx)
}

// ListFlowEvents 流量事件分页（ts 倒序——契约 §4）。
func (s *Store) ListFlowEvents(ctx context.Context, agentID uuid.UUID, p PageParams) ([]FlowEventRow, int64, error) {
	rows, err := s.db.Query(ctx, `
SELECT id, agent_id, ts, event_type, flow_id, src_ip, src_port, dst_ip, dst_port,
       protocol, direction, bytes_in, bytes_out, packets_in, packets_out,
	       tls_visibility, http_method, http_host, http_uri, http_status, k8s,
       count(*) OVER () AS total
FROM agent_flow_events
WHERE agent_id=$1
ORDER BY ts DESC, id DESC
LIMIT $2 OFFSET $3`, agentID, p.PageSize, p.Offset())
	if err != nil {
		return nil, 0, err
	}
	defer rows.Close()
	out := []FlowEventRow{}
	var total int64
	for rows.Next() {
		var e FlowEventRow
		if err := rows.Scan(&e.ID, &e.AgentID, &e.Ts, &e.EventType, &e.FlowID,
			&e.SrcIP, &e.SrcPort, &e.DstIP, &e.DstPort, &e.Protocol, &e.Direction,
			&e.BytesIn, &e.BytesOut, &e.PacketsIn, &e.PacketsOut,
			&e.TLSVisibility, &e.HTTPMethod, &e.HTTPHost, &e.HTTPURI, &e.HTTPStatus, &e.K8s, &total); err != nil {
			return nil, 0, err
		}
		out = append(out, e)
	}
	return out, total, rows.Err()
}

// ---------- 管理端：策略 ----------

// CreatePolicy 创建策略（name UNIQUE 冲突 → ErrPolicyNameConflict）；
// 同一事务快照 v1 到 agent_policy_versions（设计 §68.13 版本化）。
func (s *Store) CreatePolicy(ctx context.Context, name string, config []byte, createdBy string) (*Policy, error) {
	tx, err := s.db.Begin(ctx)
	if err != nil {
		return nil, err
	}
	defer tx.Rollback(ctx)
	row := tx.QueryRow(ctx, `
INSERT INTO agent_policies (name, config, created_by) VALUES ($1,$2,$3)
RETURNING id, name, config, version, created_by, created_at, updated_at`, name, config, createdBy)
	p, err := scanPolicy(row)
	if isUniqueViolation(err) {
		return nil, ErrPolicyNameConflict
	}
	if err != nil {
		return nil, err
	}
	if err := snapshotPolicyVersion(ctx, tx, p, createdBy); err != nil {
		return nil, err
	}
	if err := tx.Commit(ctx); err != nil {
		return nil, err
	}
	return p, nil
}

// snapshotPolicyVersion 同事务快照当前策略版本（(policy_id,version) 唯一兜底防重）。
func snapshotPolicyVersion(ctx context.Context, tx pgx.Tx, p *Policy, actor string) error {
	_, err := tx.Exec(ctx, `
INSERT INTO agent_policy_versions (policy_id, version, config, created_by)
VALUES ($1,$2,$3,$4)
ON CONFLICT (policy_id, version) DO NOTHING`, p.ID, p.Version, p.Config, actor)
	return err
}

// ListPolicies 策略列表（name 升序；策略基数小，不分页）。
func (s *Store) ListPolicies(ctx context.Context) ([]Policy, error) {
	rows, err := s.db.Query(ctx, `
SELECT id, name, config, version, created_by, created_at, updated_at
FROM agent_policies ORDER BY name`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := []Policy{}
	for rows.Next() {
		p, err := scanPolicy(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, *p)
	}
	return out, rows.Err()
}

// GetPolicy 按 ID 取策略。
func (s *Store) GetPolicy(ctx context.Context, id uuid.UUID) (*Policy, error) {
	row := s.db.QueryRow(ctx, `
SELECT id, name, config, version, created_by, created_at, updated_at
FROM agent_policies WHERE id=$1`, id)
	p, err := scanPolicy(row)
	if errors.Is(err, pgx.ErrNoRows) {
		return nil, ErrPolicyNotFound
	}
	return p, err
}

func scanPolicy(row rowScanner) (*Policy, error) {
	var p Policy
	if err := row.Scan(&p.ID, &p.Name, &p.Config, &p.Version, &p.CreatedBy, &p.CreatedAt, &p.UpdatedAt); err != nil {
		return nil, err
	}
	return &p, nil
}

// UpdatePolicy 修改策略（version+1）、同事务快照新版本，
// 并把绑定该策略的全部 Agent config_version+1（同一事务）。
func (s *Store) UpdatePolicy(ctx context.Context, id uuid.UUID, name string, config []byte, actor string) (*Policy, error) {
	tx, err := s.db.Begin(ctx)
	if err != nil {
		return nil, err
	}
	defer tx.Rollback(ctx)
	row := tx.QueryRow(ctx, `
UPDATE agent_policies SET name=$2, config=$3, version=version+1, updated_at=now()
WHERE id=$1
RETURNING id, name, config, version, created_by, created_at, updated_at`, id, name, config)
	p, err := scanPolicy(row)
	if errors.Is(err, pgx.ErrNoRows) {
		return nil, ErrPolicyNotFound
	}
	if isUniqueViolation(err) {
		return nil, ErrPolicyNameConflict
	}
	if err != nil {
		return nil, err
	}
	if err := snapshotPolicyVersion(ctx, tx, p, actor); err != nil {
		return nil, err
	}
	if _, err := tx.Exec(ctx, `
UPDATE agents SET config_version=config_version+1, updated_at=now()
WHERE agent_id IN (SELECT agent_id FROM agent_policy_bindings WHERE policy_id=$1)`, id); err != nil {
		return nil, err
	}
	if err := tx.Commit(ctx); err != nil {
		return nil, err
	}
	return p, nil
}

// ListPolicyVersions 策略历史版本列表（version 倒序；策略不存在 → ErrPolicyNotFound）。
func (s *Store) ListPolicyVersions(ctx context.Context, policyID uuid.UUID) ([]PolicyVersion, error) {
	var exists bool
	if err := s.db.QueryRow(ctx,
		`SELECT EXISTS(SELECT 1 FROM agent_policies WHERE id=$1)`, policyID).Scan(&exists); err != nil {
		return nil, err
	}
	if !exists {
		return nil, ErrPolicyNotFound
	}
	rows, err := s.db.Query(ctx, `
SELECT policy_id, version, config, created_by, created_at
FROM agent_policy_versions WHERE policy_id=$1 ORDER BY version DESC`, policyID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := []PolicyVersion{}
	for rows.Next() {
		var v PolicyVersion
		if err := rows.Scan(&v.PolicyID, &v.Version, &v.Config, &v.CreatedBy, &v.CreatedAt); err != nil {
			return nil, err
		}
		out = append(out, v)
	}
	return out, rows.Err()
}

// RollbackPolicy 以历史版本 config 生成新版本（设计 §68.14）：
// 锁策略行 → 取目标历史版本 config（不存在 → ErrPolicyVersionNotFound）→
// version+1 落新 config → 同事务快照 → 绑定 Agent config_version+1。
// 回滚不还原 name（name 生命周期独立于 config 版本演进）。
func (s *Store) RollbackPolicy(ctx context.Context, id uuid.UUID, version int, actor string) (*Policy, error) {
	tx, err := s.db.Begin(ctx)
	if err != nil {
		return nil, err
	}
	defer tx.Rollback(ctx)
	var current int
	err = tx.QueryRow(ctx,
		`SELECT version FROM agent_policies WHERE id=$1 FOR UPDATE`, id).Scan(&current)
	if errors.Is(err, pgx.ErrNoRows) {
		return nil, ErrPolicyNotFound
	}
	if err != nil {
		return nil, err
	}
	var config []byte
	err = tx.QueryRow(ctx,
		`SELECT config FROM agent_policy_versions WHERE policy_id=$1 AND version=$2`,
		id, version).Scan(&config)
	if errors.Is(err, pgx.ErrNoRows) {
		return nil, ErrPolicyVersionNotFound
	}
	if err != nil {
		return nil, err
	}
	row := tx.QueryRow(ctx, `
UPDATE agent_policies SET config=$2, version=version+1, updated_at=now()
WHERE id=$1
RETURNING id, name, config, version, created_by, created_at, updated_at`, id, config)
	p, err := scanPolicy(row)
	if err != nil {
		return nil, err
	}
	if err := snapshotPolicyVersion(ctx, tx, p, actor); err != nil {
		return nil, err
	}
	if _, err := tx.Exec(ctx, `
UPDATE agents SET config_version=config_version+1, updated_at=now()
WHERE agent_id IN (SELECT agent_id FROM agent_policy_bindings WHERE policy_id=$1)`, id); err != nil {
		return nil, err
	}
	if err := tx.Commit(ctx); err != nil {
		return nil, err
	}
	return p, nil
}

// DeletePolicy 删除策略（仍被绑定 → ErrPolicyBound 409，先解绑）。
func (s *Store) DeletePolicy(ctx context.Context, id uuid.UUID) error {
	var bound int64
	if err := s.db.QueryRow(ctx,
		`SELECT count(*) FROM agent_policy_bindings WHERE policy_id=$1`, id).Scan(&bound); err != nil {
		return err
	}
	if bound > 0 {
		return ErrPolicyBound
	}
	res, err := s.db.Exec(ctx, `DELETE FROM agent_policies WHERE id=$1`, id)
	if err != nil {
		return err
	}
	if res.RowsAffected() == 0 {
		return ErrPolicyNotFound
	}
	return nil
}

// BindPolicy 绑定/换绑（agent_id UNIQUE upsert；config_version+1 同事务）。
func (s *Store) BindPolicy(ctx context.Context, agentID, policyID uuid.UUID, boundBy string) error {
	tx, err := s.db.Begin(ctx)
	if err != nil {
		return err
	}
	defer tx.Rollback(ctx)
	var exists bool
	if err := tx.QueryRow(ctx, `SELECT EXISTS(SELECT 1 FROM agents WHERE agent_id=$1)`, agentID).
		Scan(&exists); err != nil {
		return err
	}
	if !exists {
		return ErrAgentNotFound
	}
	if err := tx.QueryRow(ctx, `SELECT EXISTS(SELECT 1 FROM agent_policies WHERE id=$1)`, policyID).
		Scan(&exists); err != nil {
		return err
	}
	if !exists {
		return ErrPolicyNotFound
	}
	if _, err := tx.Exec(ctx, `
INSERT INTO agent_policy_bindings (agent_id, policy_id, bound_by)
VALUES ($1,$2,$3)
ON CONFLICT (agent_id) DO UPDATE SET
  policy_id=EXCLUDED.policy_id, bound_by=EXCLUDED.bound_by, updated_at=now()`,
		agentID, policyID, boundBy); err != nil {
		return err
	}
	if _, err := tx.Exec(ctx, `
UPDATE agents SET config_version=config_version+1, updated_at=now() WHERE agent_id=$1`, agentID); err != nil {
		return err
	}
	return tx.Commit(ctx)
}

// UnbindPolicy 解绑（config_version+1 同事务；无绑定 → ErrNoBinding）。
func (s *Store) UnbindPolicy(ctx context.Context, agentID uuid.UUID) error {
	tx, err := s.db.Begin(ctx)
	if err != nil {
		return err
	}
	defer tx.Rollback(ctx)
	res, err := tx.Exec(ctx, `DELETE FROM agent_policy_bindings WHERE agent_id=$1`, agentID)
	if err != nil {
		return err
	}
	if res.RowsAffected() == 0 {
		var exists bool
		if err := tx.QueryRow(ctx, `SELECT EXISTS(SELECT 1 FROM agents WHERE agent_id=$1)`, agentID).
			Scan(&exists); err != nil {
			return err
		}
		if !exists {
			return ErrAgentNotFound
		}
		return ErrNoBinding
	}
	if _, err := tx.Exec(ctx, `
UPDATE agents SET config_version=config_version+1, updated_at=now() WHERE agent_id=$1`, agentID); err != nil {
		return err
	}
	return tx.Commit(ctx)
}

// isUniqueViolation 唯一约束冲突（PostgreSQL 23505）。
func isUniqueViolation(err error) bool {
	var pgErr *pgconn.PgError
	return errors.As(err, &pgErr) && pgErr.Code == "23505"
}

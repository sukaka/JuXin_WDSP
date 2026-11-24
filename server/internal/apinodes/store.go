// store.go 节点版本视图 PostgreSQL 仓储：事件聚合 / 节点 upsert / 心跳落活性 / 列表 / 状态刷新。
// 聚合口径（如实说明）：每轮对 api_runtime_events 全量分组重算（该表仅落
// 含检测明细或动作非 ALLOW 的「可记录」事件，量级可控），upsert 为绝对值
// 覆盖——采集重放/重复 sweep 不产生叠加，幂等安全；若未来事件表膨胀，
// 游标化增量是后续优化，不改变视图语义。
// W17-HB 起节点活性/版本还有第二写入方：网关心跳（RecordHeartbeat，见 UpsertNode
// 注释的合并不回退口径）——无业务流量时段节点状态不再失真（SILENT 误判修复）。
package apinodes

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"math"
	"strings"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/jiuzhang-waf/server/internal/apiruntime"
	"github.com/jiuzhang-waf/server/internal/gatewayconfig"
)

// ErrNodeNotFound 节点不存在（GetNode / 同步登记编辑 / 删除）。
var ErrNodeNotFound = errors.New("api gateway node not found")

// ErrNodeNameExists 节点名已存在（CreateNode 冲突）。
var ErrNodeNameExists = errors.New("api gateway node name already exists")

// ErrNodeInHAGroup 节点仍被主备高可用组引用，禁止删除。
var ErrNodeInHAGroup = errors.New("api gateway node is referenced by an ha group")

// Repository 节点视图仓储接口（*Store 实现；sweeper/handler 面向接口，便于测试注入）。
type Repository interface {
	// AggregateEvents 按 gateway_node 分组聚合事件表（仅含已上报节点名的行）
	AggregateEvents(ctx context.Context) ([]NodeAggregate, error)
	// UpsertNode 按 node_name upsert 节点行（聚合绝对值口径 + 与心跳写入合并不回退，
	// status 由调用方以合并后有效活性判定随写入刷新）
	UpsertNode(ctx context.Context, agg NodeAggregate, status string, now time.Time) error
	// RecordHeartbeat 节点心跳落活性视图（W17-HB；node_name 合并 upsert，幂等）。
	// NG-AZ-02 起携带授权 ACK 字段的心跳同事务追加 upsert api_node_authz_acks。
	RecordHeartbeat(ctx context.Context, hb apiruntime.Heartbeat) error
	// ListNodes 全量节点列表（node_name 升序；节点基数小，不分页）
	ListNodes(ctx context.Context) ([]Node, error)
	// UpdateNodeStatus 刷新单节点状态（状态未变化时不触行）
	UpdateNodeStatus(ctx context.Context, nodeName, status string, now time.Time) error
	// GetNode 按 ID 查询节点（W18-SYNC 同步登记编辑/审计 before 用；不存在返回 ErrNodeNotFound）
	GetNode(ctx context.Context, id uuid.UUID) (*Node, error)
	// GetNodeByName 按节点名查询节点（不存在返回 ErrNodeNotFound）
	GetNodeByName(ctx context.Context, nodeName string) (*Node, error)
	// CreateNode 手动登记新网关节点（节点名重复返回 ErrNodeNameExists）
	CreateNode(ctx context.Context, in CreateNodeInput) (*Node, error)
	// DeleteNode 删除网关节点（若被 ha_group_members 引用返回 ErrNodeInHAGroup）
	DeleteNode(ctx context.Context, id uuid.UUID) error
	// UpdateSyncRegistration 更新节点同步登记（向后兼容旧签名，仅改 admin_addr 与 sync_enabled）
	UpdateSyncRegistration(ctx context.Context, id uuid.UUID, adminAddr string, syncEnabled bool) error
	// UpdateNodeRegistration 更新节点完整同步登记（admin_addr / sync_agent_addr / 可选 sync_secret_ciphertext / sync_enabled）
	UpdateNodeRegistration(ctx context.Context, id uuid.UUID, upd SyncRegistrationUpdate) error
	// ListSyncTargets 全量同步目标（sync_enabled 且 admin_addr 或 sync_agent_addr 非空，
	// gatewayconfig 发布扇出逐节点推送用）
	ListSyncTargets(ctx context.Context) ([]gatewayconfig.SyncTarget, error)
	// RecordSyncResult 回填单节点同步结果（W18-SYNC；last_sync_* + 本次版本）
	RecordSyncResult(ctx context.Context, nodeID uuid.UUID, result, errMsg string, versionID uuid.UUID) error
}

// Store 节点版本视图 PostgreSQL 仓储。
type Store struct {
	db *pgxpool.Pool
}

// NewStore 创建。
func NewStore(db *pgxpool.Pool) *Store { return &Store{db: db} }

var _ Repository = (*Store)(nil)

// AggregateEvents 按 gateway_node 分组聚合：
// max(occurred_at)/min(occurred_at)/count + 最新非空 policy_version/model_version
// （按 occurred_at 倒序取首个非空值；全程未上报回退空串 = 未上报）。
// gateway_node 为 NULL/空串的行（存量数据、旧版网关、采集未接线）不参与聚合。
func (s *Store) AggregateEvents(ctx context.Context) ([]NodeAggregate, error) {
	rows, err := s.db.Query(ctx, `
SELECT gateway_node,
       min(occurred_at),
       max(occurred_at),
       count(*),
       COALESCE((array_agg(policy_version ORDER BY occurred_at DESC)
                 FILTER (WHERE policy_version IS NOT NULL AND policy_version <> ''))[1], ''),
       COALESCE((array_agg(model_version ORDER BY occurred_at DESC)
                 FILTER (WHERE model_version IS NOT NULL AND model_version <> ''))[1], '')
FROM api_runtime_events
WHERE gateway_node IS NOT NULL AND gateway_node <> ''
GROUP BY gateway_node`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := []NodeAggregate{}
	for rows.Next() {
		var a NodeAggregate
		if err := rows.Scan(&a.NodeName, &a.FirstSeenAt, &a.LastSeenAt, &a.EventCount,
			&a.LastPolicyVersion, &a.LastModelVersion); err != nil {
			return nil, err
		}
		out = append(out, a)
	}
	return out, rows.Err()
}

// UpsertNode 按 node_name upsert。W17-HB 起为「聚合绝对值 + 与心跳写入合并不回退」
// 混合口径（与 RecordHeartbeat 共存，两个写入方互不把对方的活性/版本写回旧值）：
//   - first_seen_at 取历史最小、last_seen_at 取最大——心跳可能已把活性推进到事件表
//     max(occurred_at) 之后（无流量时段），覆盖式写回会让活性回退、节点状态在
//     清扫周期间振荡；
//   - last_policy_version 在聚合数据不旧于现存活性（EXCLUDED.last_seen_at >= 现存
//     last_seen_at）且非空时覆盖——两个写入方的时间新近性裁决：心跳把活性推进到
//     事件表 max(occurred_at) 之后时（无流量时段），历史业务聚合不把心跳上报版本
//     写回旧值（任务书 §201「版本以心跳上报为准」）；并列（纯业务节点聚合重算/
//     版本订正/乱序补采同刻到达）时聚合覆盖，保证订正与回填如实传播；更新的业务
//     事件到达时正常接管（同网关两数据源同配置，天然一致）；聚合「最新非空」口径
//     本身不产生空值覆盖，空值守卫仅防御混合来源边界；
//   - last_model_version 绝对值覆盖（聚合是其唯一写入方——心跳只报模型版本摘要数，
//     不逐端点上报；绝对值口径保留业务事件维护的最新非空版本，订正即时生效）；
//   - event_count 仍为绝对值覆盖（事件表全量重算，天然幂等；心跳不入事件表不计数）。
func (s *Store) UpsertNode(ctx context.Context, agg NodeAggregate, status string, now time.Time) error {
	_, err := s.db.Exec(ctx, `
INSERT INTO api_gateway_nodes
(node_name, first_seen_at, last_seen_at, last_policy_version, last_model_version, event_count, status, created_at, updated_at)
VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$8)
ON CONFLICT (node_name) DO UPDATE SET
  first_seen_at       = LEAST(api_gateway_nodes.first_seen_at, EXCLUDED.first_seen_at),
  last_seen_at        = GREATEST(api_gateway_nodes.last_seen_at, EXCLUDED.last_seen_at),
  last_policy_version = CASE WHEN EXCLUDED.last_seen_at >= api_gateway_nodes.last_seen_at
                             AND EXCLUDED.last_policy_version <> ''
                        THEN EXCLUDED.last_policy_version
                        ELSE api_gateway_nodes.last_policy_version END,
  last_model_version  = EXCLUDED.last_model_version,
  event_count         = EXCLUDED.event_count,
  status              = EXCLUDED.status,
  updated_at          = EXCLUDED.updated_at`,
		agg.NodeName, agg.FirstSeenAt, agg.LastSeenAt,
		agg.LastPolicyVersion, agg.LastModelVersion, agg.EventCount, status, now)
	return err
}

// RecordHeartbeat 节点心跳落活性视图（W17-HB）：node_name 合并 upsert——
// first_seen_at 取历史最小、last_seen_at 取最大（不回退）；策略版本非空即覆盖
// （心跳是版本的最高优先级来源：它反映节点当下加载的配置，业务事件版本可能是
// 流量低谷前的旧值）；last_model_version 不动（心跳只报模型版本摘要数，逐端点
// 版本仍由业务事件聚合维护）；event_count 不动（仅统计业务事件，由 Sweeper 聚合维护）。
// 幂等：同一拍重复上报/采集重放仅刷新相同值；status 以来库时钟对心跳时间现算，
// 与 Sweeper 周期重算同一 StatusFor 口径。
//
// NG-AZ-02 D6 起扩展为同事务两表 upsert：心跳携带授权 ACK 字段（HasAuthzAck）时
// 同事务 upsert api_node_authz_acks——
//   - last_ack_at 取管理面收拍时刻（now，非节点自报时间——节点时钟可漂移，D8）；
//   - clock_skew_seconds = now − hb.OccurredAt（心跳时间戳即节点时钟直接读数，
//     可为负：节点时钟超前）；漂移判定（|skew|>上限 → CLOCK_SKEW）在查询侧派生，
//     本表只落实测值；
//   - 两表同一 pgx.Tx：任一失败整体回滚，不产生「活性已推进但 ACK 丢失」的半拍
//     （错误逐拍上抛，采集侧记日志、下一周期心跳自愈）；
//   - 未携带授权字段（旧版网关/未启用授权快照）只写节点表——不伪造零值 ACK 行，
//     ACK 视图如实 NEVER_ACKED。
func (s *Store) RecordHeartbeat(ctx context.Context, hb apiruntime.Heartbeat) error {
	if hb.NodeName == "" {
		return fmt.Errorf("heartbeat node name required")
	}
	now := time.Now().UTC()
	tx, err := s.db.Begin(ctx)
	if err != nil {
		return err
	}
	defer func() { _ = tx.Rollback(ctx) }()
	_, err = tx.Exec(ctx, `
INSERT INTO api_gateway_nodes
(node_name, first_seen_at, last_seen_at, last_policy_version, last_model_version, event_count, status, created_at, updated_at)
VALUES ($1,$2,$2,$3,'',0,$4,$5,$5)
ON CONFLICT (node_name) DO UPDATE SET
  first_seen_at       = LEAST(api_gateway_nodes.first_seen_at, EXCLUDED.first_seen_at),
  last_seen_at        = GREATEST(api_gateway_nodes.last_seen_at, EXCLUDED.last_seen_at),
  last_policy_version = CASE WHEN EXCLUDED.last_policy_version <> ''
                        THEN EXCLUDED.last_policy_version
                        ELSE api_gateway_nodes.last_policy_version END,
  status              = EXCLUDED.status,
  updated_at          = EXCLUDED.updated_at`,
		hb.NodeName, hb.OccurredAt, hb.PolicyVersion, StatusFor(now, hb.OccurredAt), now)
	if err != nil {
		return err
	}
	if hb.HasAuthzAck() {
		if err := upsertAuthzAck(ctx, tx, hb, now); err != nil {
			return err
		}
	}
	return tx.Commit(ctx)
}

// upsertAuthzAck 授权 ACK 行 upsert（RecordHeartbeat 事务内调用；水位缺失落 NULL
// 不伪造零向量——查询侧按「缺失即零水位」口径参与比较）。
func upsertAuthzAck(ctx context.Context, tx pgx.Tx, hb apiruntime.Heartbeat, now time.Time) error {
	var watermarkJSON []byte
	if hb.AuthzWatermark != nil {
		b, err := json.Marshal(hb.AuthzWatermark)
		if err != nil {
			return fmt.Errorf("marshal authz watermark of node %s: %w", hb.NodeName, err)
		}
		watermarkJSON = b
	}
	var leaseSeconds *int32
	if hb.AuthzLeaseSeconds != nil {
		// 列型 integer（int4）：超范围值拒绝落库（int32() 直接转换会静默回绕，
		// 整拍心跳随事务回滚、错误上抛由采集侧记日志，下一周期心跳自愈）。
		if *hb.AuthzLeaseSeconds > math.MaxInt32 || *hb.AuthzLeaseSeconds < math.MinInt32 {
			return fmt.Errorf("authz lease seconds of node %s out of int4 range: %d", hb.NodeName, *hb.AuthzLeaseSeconds)
		}
		v := int32(*hb.AuthzLeaseSeconds)
		leaseSeconds = &v
	}
	// 时钟漂移实测（D8）：管理面收拍时刻 − 心跳产生时刻（节点时钟读数），可为负。
	skewSeconds := int64(now.Sub(hb.OccurredAt) / time.Second)
	_, err := tx.Exec(ctx, `
INSERT INTO api_node_authz_acks
(node_name, last_ack_at, authz_policy_version, authz_watermark, authz_snapshot_expires_at,
 authz_applied_at, authz_lease_seconds, clock_skew_seconds, updated_at)
VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$2)
ON CONFLICT (node_name) DO UPDATE SET
  last_ack_at              = EXCLUDED.last_ack_at,
  authz_policy_version     = EXCLUDED.authz_policy_version,
  authz_watermark          = EXCLUDED.authz_watermark,
  authz_snapshot_expires_at = EXCLUDED.authz_snapshot_expires_at,
  authz_applied_at         = EXCLUDED.authz_applied_at,
  authz_lease_seconds      = EXCLUDED.authz_lease_seconds,
  clock_skew_seconds       = EXCLUDED.clock_skew_seconds,
  updated_at               = EXCLUDED.updated_at`,
		hb.NodeName, now, hb.AuthzPolicyVersion, watermarkJSON, hb.AuthzSnapshotExpiresAt,
		hb.AuthzAppliedAt, leaseSeconds, skewSeconds)
	return err
}

// nodeCols 列表查询列（含 W18-SYNC 同步登记与 000236 协同代理/遥测状态列；永不查出密文，只返回 has_sync_secret 布尔）。
const nodeCols = `id, node_name, first_seen_at, last_seen_at, last_policy_version,
	last_model_version, event_count, status,
	admin_addr, sync_enabled, last_sync_at, last_sync_result, last_sync_error, last_sync_version_id,
	sync_agent_addr, (sync_secret_ciphertext <> ''), reported_version,
	ha_vip_status, ha_vip_status_at, network_status, network_status_at,
	created_at, updated_at`

const nodeCredCols = `id, node_name, admin_addr, sync_agent_addr, sync_secret_ciphertext, sync_enabled,
	reported_version, ha_vip_status, ha_vip_status_at, network_status, network_status_at`

// ListNodes 全量节点列表（node_name 升序）。
func (s *Store) ListNodes(ctx context.Context) ([]Node, error) {
	rows, err := s.db.Query(ctx, `SELECT `+nodeCols+` FROM api_gateway_nodes ORDER BY node_name`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := []Node{}
	for rows.Next() {
		var n Node
		if err := scanNode(rows, &n); err != nil {
			return nil, err
		}
		out = append(out, n)
	}
	return out, rows.Err()
}

// GetNode 按 ID 查询节点（同步登记编辑/审计 before 用）。
func (s *Store) GetNode(ctx context.Context, id uuid.UUID) (*Node, error) {
	row := s.db.QueryRow(ctx, `SELECT `+nodeCols+` FROM api_gateway_nodes WHERE id=$1`, id)
	var n Node
	if err := scanNode(row, &n); err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return nil, ErrNodeNotFound
		}
		return nil, err
	}
	return &n, nil
}

// GetNodeByName 按节点名查询节点。
func (s *Store) GetNodeByName(ctx context.Context, nodeName string) (*Node, error) {
	row := s.db.QueryRow(ctx, `SELECT `+nodeCols+` FROM api_gateway_nodes WHERE node_name=$1`, strings.TrimSpace(nodeName))
	var n Node
	if err := scanNode(row, &n); err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return nil, ErrNodeNotFound
		}
		return nil, err
	}
	return &n, nil
}

// CreateNode 手动登记新网关节点（初始状态 SILENT、last_seen_at 置 Unix 纪元，
// 直到首次心跳或 hasyncd 遥测推进活性；节点名冲突返回 ErrNodeNameExists）。
func (s *Store) CreateNode(ctx context.Context, in CreateNodeInput) (*Node, error) {
	nodeName := strings.TrimSpace(in.NodeName)
	if nodeName == "" {
		return nil, fmt.Errorf("node_name required")
	}
	now := time.Now().UTC()
	neverSeen := time.Unix(0, 0).UTC()
	row := s.db.QueryRow(ctx, `
INSERT INTO api_gateway_nodes
(node_name, first_seen_at, last_seen_at, last_policy_version, last_model_version, event_count, status,
 admin_addr, sync_agent_addr, sync_secret_ciphertext, sync_enabled, created_at, updated_at)
VALUES ($1, $2, $3, '', '', 0, $4, $5, $6, $7, $8, $2, $2)
RETURNING `+nodeCols,
		nodeName, now, neverSeen, StatusSilent,
		strings.TrimSpace(in.AdminAddr), strings.TrimSpace(in.SyncAgentAddr), in.SyncSecretCiphertext, in.SyncEnabled)
	var n Node
	if err := scanNode(row, &n); err != nil {
		var pgErr *pgconn.PgError
		if errors.As(err, &pgErr) && pgErr.Code == "23505" {
			return nil, ErrNodeNameExists
		}
		return nil, err
	}
	return &n, nil
}

// DeleteNode 删除网关节点（事务内校验 ha_group_members 引用，存在引用返回 ErrNodeInHAGroup）。
func (s *Store) DeleteNode(ctx context.Context, id uuid.UUID) error {
	tx, err := s.db.Begin(ctx)
	if err != nil {
		return err
	}
	defer func() { _ = tx.Rollback(ctx) }()

	var inGroup bool
	if err := tx.QueryRow(ctx, `SELECT EXISTS(SELECT 1 FROM ha_group_members WHERE node_id = $1)`, id).Scan(&inGroup); err != nil {
		return err
	}
	if inGroup {
		return ErrNodeInHAGroup
	}
	tag, err := tx.Exec(ctx, `DELETE FROM api_gateway_nodes WHERE id = $1`, id)
	if err != nil {
		var pgErr *pgconn.PgError
		if errors.As(err, &pgErr) && pgErr.Code == "23503" {
			return ErrNodeInHAGroup
		}
		return err
	}
	if tag.RowsAffected() == 0 {
		return ErrNodeNotFound
	}
	return tx.Commit(ctx)
}

// scanNode 按 nodeCols 列序扫描单行（pgx.Row 与 pgx.Rows 共用）。
func scanNode(row pgx.Row, n *Node) error {
	var haRaw, netRaw []byte
	err := row.Scan(&n.ID, &n.NodeName, &n.FirstSeenAt, &n.LastSeenAt,
		&n.LastPolicyVersion, &n.LastModelVersion, &n.EventCount, &n.Status,
		&n.AdminAddr, &n.SyncEnabled, &n.LastSyncAt, &n.LastSyncResult,
		&n.LastSyncError, &n.LastSyncVersionID,
		&n.SyncAgentAddr, &n.HasSyncSecret, &n.ReportedVersion,
		&haRaw, &n.HaVipStatusAt, &netRaw, &n.NetworkStatusAt,
		&n.CreatedAt, &n.UpdatedAt)
	if err != nil {
		return err
	}
	if len(haRaw) > 0 {
		n.HaVipStatus = json.RawMessage(haRaw)
	} else {
		n.HaVipStatus = nil
	}
	if len(netRaw) > 0 {
		n.NetworkStatus = json.RawMessage(netRaw)
	} else {
		n.NetworkStatus = nil
	}
	return nil
}

func scanNodeCredentials(row pgx.Row, c *NodeSyncCredentials) error {
	var haRaw, netRaw []byte
	err := row.Scan(&c.NodeID, &c.NodeName, &c.AdminAddr, &c.SyncAgentAddr, &c.SyncSecretCiphertext, &c.SyncEnabled,
		&c.ReportedVersion, &haRaw, &c.HaVipStatusAt, &netRaw, &c.NetworkStatusAt)
	if err != nil {
		return err
	}
	if len(haRaw) > 0 {
		c.HaVipStatus = json.RawMessage(haRaw)
	} else {
		c.HaVipStatus = nil
	}
	if len(netRaw) > 0 {
		c.NetworkStatus = json.RawMessage(netRaw)
	} else {
		c.NetworkStatus = nil
	}
	return nil
}

// GetNodeSyncCredentials 按 ID 获取节点协同凭据与状态快照（内部 nodesync 专用）。
func (s *Store) GetNodeSyncCredentials(ctx context.Context, id uuid.UUID) (*NodeSyncCredentials, error) {
	row := s.db.QueryRow(ctx, `SELECT `+nodeCredCols+` FROM api_gateway_nodes WHERE id=$1`, id)
	var c NodeSyncCredentials
	if err := scanNodeCredentials(row, &c); err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return nil, ErrNodeNotFound
		}
		return nil, err
	}
	return &c, nil
}

// GetNodeSyncCredentialsByName 按节点名获取节点协同凭据与状态快照（内部 nodesync 专用）。
func (s *Store) GetNodeSyncCredentialsByName(ctx context.Context, nodeName string) (*NodeSyncCredentials, error) {
	row := s.db.QueryRow(ctx, `SELECT `+nodeCredCols+` FROM api_gateway_nodes WHERE node_name=$1`, strings.TrimSpace(nodeName))
	var c NodeSyncCredentials
	if err := scanNodeCredentials(row, &c); err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return nil, ErrNodeNotFound
		}
		return nil, err
	}
	return &c, nil
}

// ListNodesWithSyncAgent 返回所有配置了 sync_agent_addr 的节点凭据（供 TelemetrySweeper 周期轮询）。
func (s *Store) ListNodesWithSyncAgent(ctx context.Context) ([]NodeSyncCredentials, error) {
	rows, err := s.db.Query(ctx, `SELECT `+nodeCredCols+` FROM api_gateway_nodes WHERE sync_agent_addr <> '' ORDER BY node_name`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := []NodeSyncCredentials{}
	for rows.Next() {
		var c NodeSyncCredentials
		if err := scanNodeCredentials(rows, &c); err != nil {
			return nil, err
		}
		out = append(out, c)
	}
	return out, rows.Err()
}

// ListNodeCredentialsByNames 批量按节点名查询凭据与状态快照（HA 汇聚/多节点检查用）。
func (s *Store) ListNodeCredentialsByNames(ctx context.Context, nodeNames []string) ([]NodeSyncCredentials, error) {
	if len(nodeNames) == 0 {
		return []NodeSyncCredentials{}, nil
	}
	rows, err := s.db.Query(ctx, `SELECT `+nodeCredCols+` FROM api_gateway_nodes WHERE node_name = ANY($1) ORDER BY node_name`, nodeNames)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := []NodeSyncCredentials{}
	for rows.Next() {
		var c NodeSyncCredentials
		if err := scanNodeCredentials(rows, &c); err != nil {
			return nil, err
		}
		out = append(out, c)
	}
	return out, rows.Err()
}

// UpdateNodeTelemetry 持久化节点协同代理遥测快照（GET /v1/status 周期拉取回填）。
// last_seen_at 遵循合并不回退口径；ha_vip_status / network_status 按最新一次成功响应整体覆写（无文件时落 NULL 避免残留过期快照）。
func (s *Store) UpdateNodeTelemetry(ctx context.Context, upd NodeTelemetryUpdate) error {
	nodeName := strings.TrimSpace(upd.NodeName)
	if nodeName == "" {
		return fmt.Errorf("telemetry node name required")
	}
	now := time.Now().UTC()
	lastSeen := upd.LastSeenAt.UTC()
	if lastSeen.IsZero() {
		lastSeen = now
	}
	var haRaw []byte
	if len(upd.HaVipStatus) > 0 {
		haRaw = []byte(upd.HaVipStatus)
	}
	var netRaw []byte
	if len(upd.NetworkStatus) > 0 {
		netRaw = []byte(upd.NetworkStatus)
	}
	status := StatusFor(now, lastSeen)
	res, err := s.db.Exec(ctx, `
UPDATE api_gateway_nodes
SET last_seen_at        = GREATEST(last_seen_at, $2),
    status              = CASE WHEN $2 >= last_seen_at THEN $3 ELSE status END,
    last_policy_version = CASE WHEN $4 <> '' THEN $4 ELSE last_policy_version END,
    reported_version    = CASE WHEN $5 <> '' THEN $5 ELSE reported_version END,
    ha_vip_status       = $6,
    ha_vip_status_at    = $7,
    network_status      = $8,
    network_status_at   = $9,
    updated_at          = $10
WHERE node_name = $1`,
		nodeName, lastSeen, status,
		strings.TrimSpace(upd.PolicyVersion), strings.TrimSpace(upd.ReportedVersion),
		haRaw, upd.HaVipStatusAt, netRaw, upd.NetworkStatusAt, now)
	if err != nil {
		return err
	}
	return ensureNodeUpdate(res)
}

// UpdateSyncRegistration 更新节点同步登记（admin_addr 已在 handler 层校验；
// last_sync_* 历史列不清空——如实保留上一次同步事实）。
func (s *Store) UpdateSyncRegistration(ctx context.Context, id uuid.UUID, adminAddr string, syncEnabled bool) error {
	res, err := s.db.Exec(ctx, `
UPDATE api_gateway_nodes SET admin_addr=$2, sync_enabled=$3, updated_at=now() WHERE id=$1`,
		id, adminAddr, syncEnabled)
	if err != nil {
		return err
	}
	if res.RowsAffected() == 0 {
		return ErrNodeNotFound
	}
	return nil
}

// UpdateNodeRegistration 更新节点完整同步登记（admin_addr / sync_agent_addr / 可选 sync_secret_ciphertext / sync_enabled）。
func (s *Store) UpdateNodeRegistration(ctx context.Context, id uuid.UUID, upd SyncRegistrationUpdate) error {
	var res pgconn.CommandTag
	var err error
	if upd.SyncSecretCiphertext == nil {
		res, err = s.db.Exec(ctx, `
UPDATE api_gateway_nodes
SET admin_addr=$2, sync_agent_addr=$3, sync_enabled=$4, updated_at=now()
WHERE id=$1`,
			id, upd.AdminAddr, upd.SyncAgentAddr, upd.SyncEnabled)
	} else {
		res, err = s.db.Exec(ctx, `
UPDATE api_gateway_nodes
SET admin_addr=$2, sync_agent_addr=$3, sync_secret_ciphertext=$4, sync_enabled=$5, updated_at=now()
WHERE id=$1`,
			id, upd.AdminAddr, upd.SyncAgentAddr, *upd.SyncSecretCiphertext, upd.SyncEnabled)
	}
	if err != nil {
		return err
	}
	return ensureNodeUpdate(res)
}

// ListSyncTargets 全量同步目标（sync_enabled 且已登记 admin_addr 或 sync_agent_addr；node_name 升序）。
func (s *Store) ListSyncTargets(ctx context.Context) ([]gatewayconfig.SyncTarget, error) {
	rows, err := s.db.Query(ctx, `
SELECT id, node_name, admin_addr, sync_agent_addr FROM api_gateway_nodes
WHERE sync_enabled = TRUE AND (admin_addr <> '' OR sync_agent_addr <> '') ORDER BY node_name`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := []gatewayconfig.SyncTarget{}
	for rows.Next() {
		var t gatewayconfig.SyncTarget
		if err := rows.Scan(&t.NodeID, &t.NodeName, &t.AdminAddr, &t.SyncAgentAddr); err != nil {
			return nil, err
		}
		out = append(out, t)
	}
	return out, rows.Err()
}

// ListFailedSyncTargets 返回指定配置版本最近一次同步失败或哈希不一致的节点。
// 仅选择当前仍启用且登记了管理地址或协同代理地址的节点，供发布恢复入口定向重试；没有记录该版本
// 的节点不在结果中，避免把尚未参与该版本发布的节点误当作失败节点。
func (s *Store) ListFailedSyncTargets(ctx context.Context, versionID uuid.UUID) ([]gatewayconfig.SyncTarget, error) {
	rows, err := s.db.Query(ctx, `
SELECT id, node_name, admin_addr, sync_agent_addr FROM api_gateway_nodes
WHERE sync_enabled = TRUE AND (admin_addr <> '' OR sync_agent_addr <> '')
  AND last_sync_version_id = $1
  AND last_sync_result IN ($2, $3)
ORDER BY node_name`, versionID, gatewayconfig.NodeSyncFailed, gatewayconfig.NodeSyncHashMismatch)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := []gatewayconfig.SyncTarget{}
	for rows.Next() {
		var t gatewayconfig.SyncTarget
		if err := rows.Scan(&t.NodeID, &t.NodeName, &t.AdminAddr, &t.SyncAgentAddr); err != nil {
			return nil, err
		}
		out = append(out, t)
	}
	return out, rows.Err()
}

// RecordSyncResult 回填单节点同步结果（last_sync_* + 本次版本；versionID 为
// 同步尝试的配置版本，成功与失败均如实记录）。
func (s *Store) RecordSyncResult(ctx context.Context, nodeID uuid.UUID, result, errMsg string, versionID uuid.UUID) error {
	res, err := s.db.Exec(ctx, `
UPDATE api_gateway_nodes
SET last_sync_at=now(), last_sync_result=$2, last_sync_error=$3, last_sync_version_id=$4, updated_at=now()
WHERE id=$1`, nodeID, result, errMsg, versionID)
	if err != nil {
		return err
	}
	return ensureNodeUpdate(res)
}

func ensureNodeUpdate(tag pgconn.CommandTag) error {
	if tag.RowsAffected() == 0 {
		return ErrNodeNotFound
	}
	return nil
}

// UpdateNodeStatus 刷新单节点状态（WHERE status<>$2 避免无变化触行）。
func (s *Store) UpdateNodeStatus(ctx context.Context, nodeName, status string, now time.Time) error {
	_, err := s.db.Exec(ctx, `
UPDATE api_gateway_nodes SET status=$2, updated_at=$3 WHERE node_name=$1 AND status<>$2`,
		nodeName, status, now)
	return err
}

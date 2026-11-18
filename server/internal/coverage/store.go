// store.go 执行覆盖观测摄入仓储（NG-COV-01/02 server 侧；迁移 000168 契约）。
// 与 identityevents 采集器同一断点纪律：全部写方法接收 Querier（采集器 flush 批次
// 传入同一个 pgx.Tx，整批一次 COMMIT；失败整体回滚、断点不前移，下轮重放由
// UPSERT/WHERE NOT EXISTS 幂等兜底）。
//
// 三张表分工：
//   - coverage_observations：请求级明细（采集器确定性 1/N 采样留存；request_id+
//     detector+phase 幂等，重放不产生重复行）；
//   - coverage_minute_agg：Aggregator 分钟桶 UPSERT（维度键唯一约束，计数按增量累加）；
//   - coverage_counter_snapshots：摄入管线节点级阶段计数快照（append-only，
//     每次 flush 一组，丢弃事实本身入聚合展示——契约「丢弃不得静默」）。
//
// 安全不变量（ADR-2）：观测永不进入攻击评分链路，本包不提供任何评分/动作语义。
package coverage

import (
	"context"
	"fmt"
	"time"
	"unicode/utf8"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
	"github.com/jackc/pgx/v5/pgxpool"

	gwcov "github.com/jiuzhang-waf/gateway/dynamic_security/coverage"
)

// Querier 采集批次事务/连接池共用的最小查询接口（与 identityevents 同型）。
type Querier interface {
	Exec(ctx context.Context, sql string, args ...interface{}) (pgconn.CommandTag, error)
	QueryRow(ctx context.Context, sql string, args ...interface{}) pgx.Row
	Query(ctx context.Context, sql string, args ...interface{}) (pgx.Rows, error)
}

// Store 是执行覆盖摄入仓储。
type Store struct {
	db *pgxpool.Pool
}

// NewStore 创建仓储。
func NewStore(db *pgxpool.Pool) *Store {
	return &Store{db: db}
}

// 列宽上限（迁移 000168 varchar 宽度；超长 rune 安全截断，列定义即口径）。
const (
	colRequestID     = 64
	colApplicationID = 64
	colEndpointKey   = 560
	colDetector      = 96
	colPhase         = 16
	colStatus        = 16
	colReasonCode    = 48
	colNARuleID      = 96
	colPolicyVersion = 64
	colNodeID        = 96
	colStage         = 48
)

// truncateRunes 按字符数截断（rune 安全），与列宽对齐（同 apiruntime.truncateRunes）。
func truncateRunes(s string, n int) string {
	if utf8.RuneCountInString(s) <= n {
		return s
	}
	return string([]rune(s)[:n])
}

// InsertObservations 明细批量入库（采样后的请求级观测）。
// 幂等：request_id+detector+phase 已存在则跳过（WHERE NOT EXISTS），重放不产生重复行。
// 明细 INSERT 后整批一次 COMMIT，不逐行提交。
func (s *Store) InsertObservations(ctx context.Context, q Querier, batch []gwcov.Observation) error {
	for _, o := range batch {
		if _, err := q.Exec(ctx, `
INSERT INTO coverage_observations (request_id, application_id, endpoint_key, detector, phase, status,
  reason_code, na_rule_id, scope_bytes, scope_messages, scope_direction,
  bytes_examined, truncated, policy_version, node_id, occurred_at)
SELECT $1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,$14,$15,$16
WHERE NOT EXISTS (
  SELECT 1 FROM coverage_observations
  WHERE request_id = $1::varchar AND detector = $4::varchar AND phase = $5::varchar
)`,
			truncateRunes(o.RequestID, colRequestID),
			truncateRunes(o.ApplicationID, colApplicationID),
			truncateRunes(o.EndpointKey, colEndpointKey),
			truncateRunes(o.Detector, colDetector),
			truncateRunes(string(o.Phase), colPhase),
			truncateRunes(string(o.Status), colStatus),
			truncateRunes(string(o.ReasonCode), colReasonCode),
			truncateRunes(o.NARuleID, colNARuleID),
			o.Scope.Bytes, o.Scope.Messages, truncateRunes(o.Scope.Direction, colPhase),
			o.BytesExamined, o.Truncated,
			truncateRunes(o.PolicyVersion, colPolicyVersion),
			truncateRunes(o.NodeID, colNodeID),
			o.OccurredAt.UTC()); err != nil {
			return fmt.Errorf("insert coverage_observation (request_id=%s detector=%s): %w", o.RequestID, o.Detector, err)
		}
	}
	return nil
}

// StageCount 摄入管线阶段计数（stage 命名空间 cov_ingest.*，见 collector）。
type StageCount struct {
	Stage string
	Count uint64
}

// InsertCounterSnapshot 节点级阶段计数快照入库（每次 flush 一组，append-only 留痕）。
func (s *Store) InsertCounterSnapshot(ctx context.Context, q Querier, nodeID string, counts []StageCount, capturedAt time.Time) error {
	for _, c := range counts {
		if _, err := q.Exec(ctx, `
INSERT INTO coverage_counter_snapshots (node_id, stage, count, captured_at)
VALUES ($1,$2,$3,$4)`,
			truncateRunes(nodeID, colNodeID), truncateRunes(c.Stage, colStage),
			int64(c.Count), capturedAt.UTC()); err != nil {
			return fmt.Errorf("insert coverage_counter_snapshot (stage=%s): %w", c.Stage, err)
		}
	}
	return nil
}

// AggRow 聚合落库行：维度键 + 五态计数增量 + other 归拢标记（采集器 flush 构造）。
type AggRow struct {
	Key     DimKey
	Bucket  Bucket
	IsOther bool
}

// UpsertMinuteAgg 聚合分钟桶落库：维度键唯一约束冲突时按增量累加五态计数
// （同一进程重启/多采集器重放安全：Aggregator 输出的是「自上次 flush 以来的增量」，
// 计数列累加；is_other 取并集——曾归拢过 other 即保持标记）。
func (s *Store) UpsertMinuteAgg(ctx context.Context, q Querier, aggs []AggRow) error {
	for _, a := range aggs {
		if _, err := q.Exec(ctx, `
INSERT INTO coverage_minute_agg (application_id, endpoint_key, detector, phase, policy_version, node_id, minute,
  full_count, partial_count, skipped_count, error_count, na_count, is_other)
VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13)
ON CONFLICT ON CONSTRAINT coverage_minute_agg_dim DO UPDATE SET
  full_count    = coverage_minute_agg.full_count + EXCLUDED.full_count,
  partial_count = coverage_minute_agg.partial_count + EXCLUDED.partial_count,
  skipped_count = coverage_minute_agg.skipped_count + EXCLUDED.skipped_count,
  error_count   = coverage_minute_agg.error_count + EXCLUDED.error_count,
  na_count      = coverage_minute_agg.na_count + EXCLUDED.na_count,
  is_other      = coverage_minute_agg.is_other OR EXCLUDED.is_other,
  updated_at    = now()`,
			truncateRunes(a.Key.ApplicationID, colApplicationID),
			truncateRunes(a.Key.EndpointKey, colEndpointKey),
			truncateRunes(a.Key.Detector, colDetector),
			truncateRunes(a.Key.Phase, colPhase),
			truncateRunes(a.Key.PolicyVersion, colPolicyVersion),
			truncateRunes(a.Key.NodeID, colNodeID),
			a.Key.Minute.UTC(),
			int64(a.Bucket.Full), int64(a.Bucket.Partial), int64(a.Bucket.Skipped),
			int64(a.Bucket.Error), int64(a.Bucket.NotApplicable), a.IsOther); err != nil {
			return fmt.Errorf("upsert coverage_minute_agg (detector=%s minute=%s): %w", a.Key.Detector, a.Key.Minute, err)
		}
	}
	return nil
}

// AggQuery 聚合查询条件（零值为不过滤；分钟窗闭开区间 [from, to)）。
type AggQuery struct {
	ApplicationID string
	EndpointKey   string
	Detector      string
	NodeID        string
	From          time.Time
	To            time.Time
	Limit         int
}

// QueryAgg 按维度键 + 时间窗查询分钟聚合（E 口径比率在查询侧计算：
// E=full+partial+skipped+error；E=0 时 NoApplicableTraffic=true，绝不显示 100%）。
func (s *Store) QueryAgg(ctx context.Context, q Querier, aq AggQuery) ([]Metrics, error) {
	if aq.Limit <= 0 || aq.Limit > 1000 {
		aq.Limit = 500
	}
	rows, err := q.Query(ctx, `
SELECT application_id, endpoint_key, detector, phase, policy_version, node_id, minute,
       full_count, partial_count, skipped_count, error_count, na_count
FROM coverage_minute_agg
WHERE ($1 = '' OR application_id = $1)
  AND ($2 = '' OR endpoint_key = $2)
  AND ($3 = '' OR detector = $3)
  AND ($4 = '' OR node_id = $4)
  AND minute >= $5 AND minute < $6
ORDER BY minute DESC, application_id, endpoint_key, detector
LIMIT $7`,
		aq.ApplicationID, aq.EndpointKey, aq.Detector, aq.NodeID,
		aq.From.UTC(), aq.To.UTC(), aq.Limit)
	if err != nil {
		return nil, fmt.Errorf("query coverage_minute_agg: %w", err)
	}
	defer rows.Close()
	var out []Metrics
	for rows.Next() {
		var m Metrics
		var full, partial, skipped, errCount, na int64
		if err := rows.Scan(&m.ApplicationID, &m.EndpointKey, &m.Detector, &m.Phase,
			&m.PolicyVersion, &m.NodeID, &m.Minute,
			&full, &partial, &skipped, &errCount, &na); err != nil {
			return nil, fmt.Errorf("scan coverage_minute_agg: %w", err)
		}
		m.Bucket = Bucket{
			Full:          uint64(full),
			Partial:       uint64(partial),
			Skipped:       uint64(skipped),
			Error:         uint64(errCount),
			NotApplicable: uint64(na),
		}
		m.E = m.Bucket.E()
		if m.E == 0 {
			m.NoApplicableTraffic = true
		} else {
			m.FullRate = float64(m.Bucket.Full) / float64(m.E)
			m.EffectiveRate = float64(m.Bucket.Full+m.Bucket.Partial) / float64(m.E)
		}
		out = append(out, m)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("iterate coverage_minute_agg: %w", err)
	}
	return out, nil
}

// QueryAggView 聚合查询（连接池直连；handler 查询侧入口，采集批次仍走 tx 版 QueryAgg）。
func (s *Store) QueryAggView(ctx context.Context, aq AggQuery) ([]Metrics, error) {
	return s.QueryAgg(ctx, s.db, aq)
}

// NodeStageSnapshot 单节点最新一份阶段计数（窗口内 captured_at 最大的一组）。
type NodeStageSnapshot struct {
	NodeID     string           `json:"node_id"`
	CapturedAt time.Time        `json:"captured_at"`
	Counts     map[string]int64 `json:"-"` // stage → count（map 供组装，序列化由 handler 保序输出）
}

// LatestStageCounts 取窗口内每个节点最新一份阶段计数（stageSet 过滤阶段集合——
// guard 链路阶段与 cov_ingest 摄入遥测共用本表但 captured_at 不同源，须按阶段集
// 分别取「最新一份」；返回按 node_id 排序，节点无快照不出现）。
func (s *Store) LatestStageCounts(ctx context.Context, stageSet []string, nodeID string, from, to time.Time) ([]NodeStageSnapshot, error) {
	if len(stageSet) == 0 {
		return nil, nil
	}
	rows, err := s.db.Query(ctx, `
SELECT node_id, stage, count, captured_at
FROM coverage_counter_snapshots
WHERE stage = ANY($1)
  AND captured_at >= $2 AND captured_at < $3
  AND ($4 = '' OR node_id = $4)
  AND (node_id, captured_at) IN (
    SELECT node_id, MAX(captured_at)
    FROM coverage_counter_snapshots
    WHERE stage = ANY($1)
      AND captured_at >= $2 AND captured_at < $3
      AND ($4 = '' OR node_id = $4)
    GROUP BY node_id
  )
ORDER BY node_id, stage`,
		stageSet, from.UTC(), to.UTC(), nodeID)
	if err != nil {
		return nil, fmt.Errorf("query latest stage counts: %w", err)
	}
	defer rows.Close()
	byNode := map[string]*NodeStageSnapshot{}
	var order []string
	for rows.Next() {
		var nodeID2, stage string
		var count int64
		var capturedAt time.Time
		if err := rows.Scan(&nodeID2, &stage, &count, &capturedAt); err != nil {
			return nil, fmt.Errorf("scan latest stage counts: %w", err)
		}
		snap, ok := byNode[nodeID2]
		if !ok {
			snap = &NodeStageSnapshot{NodeID: nodeID2, CapturedAt: capturedAt, Counts: map[string]int64{}}
			byNode[nodeID2] = snap
			order = append(order, nodeID2)
		}
		snap.Counts[stage] = count
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("iterate latest stage counts: %w", err)
	}
	out := make([]NodeStageSnapshot, 0, len(order))
	for _, n := range order {
		out = append(out, *byNode[n])
	}
	return out, nil
}

// InsertParseFailure 解析失败入队（event_parse_failures 通用表，与其他采集器共用；
// best-effort——队列写入失败仅由调用方记日志，不阻断采集）。
func (s *Store) InsertParseFailure(ctx context.Context, collectorID, rawLine, reason string) error {
	if len(rawLine) > 4096 {
		rawLine = rawLine[:4096]
	}
	_, err := s.db.Exec(ctx,
		`INSERT INTO event_parse_failures (collector_id, raw_line, error_reason) VALUES ($1, $2, $3)`,
		collectorID, rawLine, reason)
	return err
}

// call_edges.go API 调用边生产方（WDSP P1-09/P1-10 调用图谱/拓扑）：
// api_runtime_events → 派生 from_endpoint→to_endpoint 调用边，upsert api_call_edges。
//
// 派生规则：同一 identity_fingerprint 的事件按时间升序排列，相邻两次调用间隔
// 不超过 CallEdgeSessionWindow（默认 10 分钟）即构成一条「连续调用序列」上的边，
// 边观测时间取 to 事件的时刻；间隔超窗序列截断、自环（from==to，重复调用同一端点
// 不产生拓扑信息，节点 hit_count 已表达）不成边。
//
// 匿名纪律（docs/API_MICRO_MODELS.md §2.2 边界规则的延伸）：匿名事件
// identity_fingerprint 为空串，全部匿名调用者共享同一「身份」，source 指纹维度
// 不可信，拼出的边是跨真实用户的伪拓扑，故匿名事件在 SQL 层整体排除、不参与
// 派生（也不打断已识别身份的序列——匿名调用是另一行为主体）。
// 端点未解析（endpoint_key 未匹配 api_endpoints）的事件是序列截断点：
// 其前后不强行连边（A→未知→B 不能断言 A→B），与 behavior.go 一样跳过并计数告警。
//
// 水位纪律（与 apidata/apiauthz sweep 同模式，但水位落点不同）：本表无独立的
// 状态列，水位取 aggregation_jobs 中最近一次 SUCCESS 的 CALL_EDGES 记录的
// window_end，只处理其后的新事件；水位推进（aggregation_jobs 行）与边 upsert
// 同事务提交，崩溃重跑不重复计数（幂等）。为让跨批次相邻事件正确成边，事件查询
// 向前回看一个会话窗口（watermark-window），派生时仅计入 to 时刻严格晚于水位
// 的边（回看部分只作配对上下文，不重复计数）。单次最多处理 callEdgeBatchSize 条
// 事件（防长事务），打满时 HasMore=true 提示调用方继续调度。
// 已知边界：事件迟到且 occurred_at 早于水位时不再重扫（采集器 2s 轮询，概率极低），
// 与 apidata sweep 的「与水位同刻」边界同类。
//
// upsert 方式：000067 起 api_call_edges 有 (caller, source, target) 自然键唯一索引
// （uq_api_call_edges_caller_source_target，NULLS NOT DISTINCT），单条
// INSERT ... ON CONFLICT DO UPDATE 即原子 upsert，并发安全由唯一索引兜底，
// 不再依赖 pg_advisory_xact_lock 序列化（W11-GRAPH 移除）。
//
// identity_count 口径（近似下界）：精确统计「多少身份走过这条边」需要边观测携带
// 身份哈希集合，成本太高；取而代之用「首见身份」近似——自然键首次插入（新身份
// 指纹首次出现在该边）计 1，ON CONFLICT 命中（同身份重复经过）只累加 call_count、
// 不动 identity_count。deriveCallEdges 已按 (caller, source, target) 合并批内增量，
// 单批同键只 upsert 一次（批内 distinct 由合并保证）。因身份指纹可能折叠/碰撞，
// 该口径是 distinct 身份数的近似下界。
// 空表/无事件安全返回零值结果。
package aggregations

import (
	"context"
	"fmt"
	"log/slog"
	"sort"
	"time"

	"github.com/google/uuid"
)

// CallEdgeSessionWindow 同一身份连续调用序列的最大间隔（超过则序列截断、不成边）。
const CallEdgeSessionWindow = 10 * time.Minute

// callEdgeBatchSize 单次派生事件批大小（防长事务）。
const callEdgeBatchSize = 5000

// CallEdgeResult 一次边派生的结果统计。
type CallEdgeResult struct {
	EventsScanned     int        `json:"events_scanned"`      // 扫描到的非匿名事件数
	EdgesUpserted     int        `json:"edges_upserted"`      // upsert 边数（去重后边键数，观测次数累计进 call_count）
	SkippedNoEndpoint int        `json:"skipped_no_endpoint"` // endpoint_key 未匹配资产而成为截断点的事件数
	HasMore           bool       `json:"has_more"`            // 本批打满，可能还有余量
	Watermark         *time.Time `json:"watermark"`           // 本次推进到的水位（最大事件时间）
}

// callEdgeEvent 参与边派生的最小事件字段集。
type callEdgeEvent struct {
	Identity   string    // 身份指纹（匿名空串 — SQL 层已排除，纯逻辑层防御性跳过）
	EndpointID uuid.UUID // 已解析的 api_endpoints.id；uuid.Nil = 未解析（序列截断点）
	OccurredAt time.Time // 事件发生时间
}

// callEdgeDelta 一次派生产出的边增量（同批同边键合并）。
type callEdgeDelta struct {
	Caller    string
	SourceID  uuid.UUID
	TargetID  uuid.UUID
	Count     int64
	FirstSeen time.Time // 本批最早边观测时刻（to 事件时刻）
	LastSeen  time.Time // 本批最晚边观测时刻
}

// deriveCallEdges 纯逻辑：事件序列 → 边增量（输出按 caller+source+target 排序，结果确定）。
// 仅计入 to 时刻严格晚于 watermark 的边（水位前的边已由上一轮计入）；watermark 为 nil
// 时全量派生（首轮回填）。事件无需调用方排序（内部按身份+时间稳定排序，同刻事件保持
// 输入顺序，与 SQL ORDER BY occurred_at, id 的稳定性一致）。
func deriveCallEdges(events []callEdgeEvent, window time.Duration, watermark *time.Time) []callEdgeDelta {
	sorted := make([]callEdgeEvent, len(events))
	copy(sorted, events)
	sort.SliceStable(sorted, func(i, j int) bool {
		if sorted[i].Identity != sorted[j].Identity {
			return sorted[i].Identity < sorted[j].Identity
		}
		return sorted[i].OccurredAt.Before(sorted[j].OccurredAt)
	})

	type edgeKey struct {
		caller         string
		source, target uuid.UUID
	}
	merged := map[edgeKey]*callEdgeDelta{}
	var prev *callEdgeEvent // 当前身份的序列尾部（已解析事件）；nil = 序列未开始/已截断
	for i := range sorted {
		ev := &sorted[i]
		if ev.Identity == "" {
			continue // 匿名防御（正常路径 SQL 已排除）
		}
		if prev != nil && prev.Identity != ev.Identity {
			prev = nil // 身份切换，重新起算
		}
		if ev.EndpointID == uuid.Nil {
			prev = nil // 未解析端点：序列截断（A→未知→B 不断言 A→B）
			continue
		}
		if prev != nil && ev.EndpointID != prev.EndpointID &&
			ev.OccurredAt.Sub(prev.OccurredAt) <= window &&
			(watermark == nil || ev.OccurredAt.After(*watermark)) {
			k := edgeKey{ev.Identity, prev.EndpointID, ev.EndpointID}
			d := merged[k]
			if d == nil {
				d = &callEdgeDelta{Caller: ev.Identity, SourceID: prev.EndpointID, TargetID: ev.EndpointID,
					FirstSeen: ev.OccurredAt, LastSeen: ev.OccurredAt}
				merged[k] = d
			}
			d.Count++
			if ev.OccurredAt.Before(d.FirstSeen) {
				d.FirstSeen = ev.OccurredAt
			}
			if ev.OccurredAt.After(d.LastSeen) {
				d.LastSeen = ev.OccurredAt
			}
		}
		prev = ev // 间隔超窗不成边，但当前事件成为新序列尾部
	}

	out := make([]callEdgeDelta, 0, len(merged))
	for _, d := range merged {
		out = append(out, *d)
	}
	sort.Slice(out, func(i, j int) bool {
		if out[i].Caller != out[j].Caller {
			return out[i].Caller < out[j].Caller
		}
		if out[i].SourceID != out[j].SourceID {
			return out[i].SourceID.String() < out[j].SourceID.String()
		}
		return out[i].TargetID.String() < out[j].TargetID.String()
	})
	return out
}

// RunCallEdges 执行一次调用边派生：水位增量扫描 api_runtime_events，upsert
// api_call_edges。执行结果记 aggregation_jobs（CALL_EDGES，与边 upsert 同事务），
// 失败不静默（记录 FAILED 后返回错误）。
func (j *Jobs) RunCallEdges(ctx context.Context) (*CallEdgeResult, error) {
	res, err := j.sweepCallEdges(ctx)
	if err != nil {
		// 失败时扫描窗口可能未知（水位读取即失败），FAILED 记录退化为执行时刻
		failedAt := time.Now().UTC()
		_ = j.store.recordJob(ctx, "CALL_EDGES", failedAt, failedAt, "FAILED", 0, err.Error())
		return res, err
	}
	return res, nil
}

// sweepCallEdges 水位增量派生主体。返回写入边数与统计；空表/无新事件安全返回零值。
func (j *Jobs) sweepCallEdges(ctx context.Context) (*CallEdgeResult, error) {
	res := &CallEdgeResult{}
	db := j.store.db

	// 水位：最近一次 SUCCESS 的 CALL_EDGES 记录的 window_end（无 → 首轮全量回填）。
	// 查询下界向前回看一个会话窗口，让跨批次相邻事件正确成边；
	// 派生时仅计入 to 时刻 > 水位的边（回看部分只作配对上下文）。
	var wm *time.Time
	if err := db.QueryRow(ctx, `
SELECT max(window_end) FROM aggregation_jobs
WHERE job_type = 'CALL_EDGES' AND status = 'SUCCESS'`).Scan(&wm); err != nil {
		return nil, fmt.Errorf("call edge watermark: %w", err)
	}
	var scanFrom *time.Time
	if wm != nil {
		from := wm.Add(-CallEdgeSessionWindow)
		scanFrom = &from
	}

	rows, err := db.Query(ctx, `
SELECT ev.identity_fingerprint, e.id, ev.occurred_at
FROM api_runtime_events ev
LEFT JOIN api_endpoints e ON e.endpoint_key = ev.endpoint_key
WHERE ev.identity_fingerprint <> ''
  AND ($1::timestamptz IS NULL OR ev.occurred_at > $1)
ORDER BY ev.occurred_at ASC, ev.id ASC
LIMIT $2`, scanFrom, callEdgeBatchSize)
	if err != nil {
		return res, fmt.Errorf("call edge query: %w", err)
	}
	events := []callEdgeEvent{}
	for rows.Next() {
		var ev callEdgeEvent
		var endpointID *uuid.UUID
		if err := rows.Scan(&ev.Identity, &endpointID, &ev.OccurredAt); err != nil {
			rows.Close()
			return res, fmt.Errorf("call edge scan: %w", err)
		}
		if endpointID == nil {
			res.SkippedNoEndpoint++ // 端点已删除或发现尚未落库：序列截断点
		} else {
			ev.EndpointID = *endpointID
		}
		events = append(events, ev)
	}
	rows.Close()
	if err := rows.Err(); err != nil {
		return res, fmt.Errorf("call edge iterate: %w", err)
	}
	res.EventsScanned = len(events)
	if len(events) == 0 {
		// 空表/无新事件安全。首轮（无水位）不写任务记录——水位保持 NULL，
		// 下轮仍全量回填（采集器补传的历史事件不会被误跳过）；已有水位的
		// 空扫记一条原地 SUCCESS（rows=0），执行轨迹与其余周期作业一致。
		if wm != nil {
			if err := j.store.recordJob(ctx, "CALL_EDGES", *wm, *wm, "SUCCESS", 0, ""); err != nil {
				return res, fmt.Errorf("call edge record noop job: %w", err)
			}
		}
		return res, nil
	}
	res.HasMore = len(events) >= callEdgeBatchSize
	if res.SkippedNoEndpoint > 0 {
		slog.Warn("call edges: events unresolved (endpoint missing)",
			"skipped", res.SkippedNoEndpoint, "watermark", wm)
	}

	deltas := deriveCallEdges(events, CallEdgeSessionWindow, wm)
	// 新水位 = 本批扫描到的最大事件时间（不论是否产边；与同刻余量边界见文件头注释）
	newWM := events[len(events)-1].OccurredAt
	res.Watermark = &newWM

	tx, err := db.Begin(ctx)
	if err != nil {
		return res, err
	}
	defer func() { _ = tx.Rollback(ctx) }()
	// 000067 唯一索引兜底：单条 INSERT ... ON CONFLICT 原子 upsert，
	// 无需 advisory lock 序列化并发写入方（锁已于 W11-GRAPH 移除）。
	// identity_count 近似口径：INSERT 携带 1（新身份指纹首见该边）；
	// 冲突（同身份重复经过）只累加 call_count、不动 identity_count（近似下界，
	// 见文件头注释）。
	for _, d := range deltas {
		if _, err := tx.Exec(ctx, `
INSERT INTO api_call_edges (caller_fingerprint, source_endpoint_id, target_endpoint_id, call_count, first_seen_at, last_seen_at, identity_count)
VALUES ($1, $2, $3, $4, $5, $6, 1)
ON CONFLICT (caller_fingerprint, source_endpoint_id, target_endpoint_id) DO UPDATE
SET call_count = api_call_edges.call_count + EXCLUDED.call_count,
    first_seen_at = LEAST(api_call_edges.first_seen_at, EXCLUDED.first_seen_at),
    last_seen_at = GREATEST(api_call_edges.last_seen_at, EXCLUDED.last_seen_at)`,
			d.Caller, d.SourceID, d.TargetID, d.Count, d.FirstSeen, d.LastSeen); err != nil {
			return res, fmt.Errorf("call edge upsert: %w", err)
		}
		res.EdgesUpserted++
	}
	// 水位推进与边 upsert 同事务提交（崩溃重跑不重复计数）；
	// window_start 取上一水位（首轮取本批最早事件时间，仅作记录语义）
	windowStart := newWM
	if wm != nil {
		windowStart = *wm
	} else if len(events) > 0 {
		windowStart = events[0].OccurredAt
	}
	if _, err := tx.Exec(ctx, `
INSERT INTO aggregation_jobs (job_type, window_start, window_end, status, error, rows_written, finished_at)
VALUES ('CALL_EDGES', $1, $2, 'SUCCESS', '', $3, now())`,
		windowStart, newWM, res.EdgesUpserted); err != nil {
		return res, fmt.Errorf("call edge record job: %w", err)
	}
	if err := tx.Commit(ctx); err != nil {
		return res, err
	}
	return res, nil
}

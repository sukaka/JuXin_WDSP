// behavior.go API 行为基线画像离线聚合（WDSP 三微模型第二批，访问微模型「访问时间」维度；
// docs/API_MICRO_MODELS.md §四第 6 项、docs/API_BEHAVIOR_ANALYSIS.md §六）。
//
// 定位：管理面离线画像，让行为基线在管理面可见；网关侧实时滑窗仍是进程内存，两者互不依赖。
// 数据源 api_runtime_events（采集口径：含检测明细或动作非 ALLOW 的 API 请求，见
// apiruntime/collector.go notable()；request_count 因此是「值得关注请求」量级而非全量流量——
// 全量请求量在 access_logs，但访问日志无 endpoint_key/身份维度，路径归一化只在网关侧，
// 服务端不复刻，故不混入）。身份口径遵守 §2.2 边界规则：身份只由凭据派生，
// 匿名事件身份为空串，只汇入端点级聚合行，不产身份级行。
//
// 幂等纪律与分钟/小时聚合一致：每次从源表按回看窗口重算，UPSERT 覆盖式写入，
// 不依赖上一行状态，可安全重跑。
package aggregations

import (
	"context"
	"encoding/json"
	"fmt"
	"log/slog"
	"sort"
	"strconv"
	"time"

	"github.com/google/uuid"
)

// BehaviorProfileWindowSeconds 画像速率基线窗口秒数（与 api_behavior_profiles.window_seconds
// 默认值一致）。request_count/avg_rate/status_code_dist 描述该回看窗口。
const BehaviorProfileWindowSeconds = 3600

// behaviorProfileHourLookback 时段分布回看时长。单速率窗口（1h）只覆盖 1-2 个小时桶，
// 「该身份平时哪些时段调用」的时段基线需要完整日周期，故 hour_dist 固定按 24h 回看重算。
const behaviorProfileHourLookback = 24 * time.Hour

// behaviorEvent 聚合输入：一条运行时事件参与画像的最小字段集。
type behaviorEvent struct {
	EndpointID string    // api_endpoints.id（已解析；未解析的事件不进画像）
	Identity   string    // 身份指纹，匿名空串
	OccurredAt time.Time // 事件发生时间
	Status     int       // 响应状态码，0 = 网关未采集到
}

// behaviorProfile 聚合输出：api_behavior_profiles 一行（endpoint × identity × window）。
type behaviorProfile struct {
	EndpointID   string
	Identity     string // 空串 = 端点级聚合
	RequestCount int64
	AvgRate      float64
	StatusDist   map[string]int64
	HourDist     map[string]int64
}

// statusCodeClass 状态码分桶：与分钟聚合同一套 2xx/4xx/5xx 口径（accesslog.go statusClass）；
// 状态码未知（0，网关未采集到）归 unknown，不冒充成功类。
func statusCodeClass(status int) string {
	if status <= 0 {
		return "unknown"
	}
	return statusClass(status)
}

// aggregateBehaviorEvents 纯逻辑：事件列表 → 画像行（输出按 endpoint+identity 排序，结果确定）。
// 每个非匿名身份产一行身份级画像；全部事件（含匿名）汇总产一行端点级画像（Identity=""）。
// rateStart ≤ t < windowEnd 内的事件计入 request_count/avg_rate/status_code_dist；
// 全部传入事件计入 hour_dist（调用方保证传入范围即时段回看窗口）。
func aggregateBehaviorEvents(events []behaviorEvent, rateStart, windowEnd time.Time, windowSeconds int) []*behaviorProfile {
	type key struct{ ep, identity string }
	byKey := map[key]*behaviorProfile{}
	get := func(ep, identity string) *behaviorProfile {
		k := key{ep, identity}
		p := byKey[k]
		if p == nil {
			p = &behaviorProfile{
				EndpointID: ep, Identity: identity,
				StatusDist: map[string]int64{}, HourDist: map[string]int64{},
			}
			byKey[k] = p
		}
		return p
	}
	add := func(ep, identity string, ev behaviorEvent) {
		p := get(ep, identity)
		p.HourDist[strconv.Itoa(ev.OccurredAt.UTC().Hour())]++
		if !ev.OccurredAt.Before(rateStart) && ev.OccurredAt.Before(windowEnd) {
			p.RequestCount++
			p.StatusDist[statusCodeClass(ev.Status)]++
		}
	}
	for _, ev := range events {
		if ev.EndpointID == "" {
			continue
		}
		if ev.Identity != "" {
			add(ev.EndpointID, ev.Identity, ev)
		}
		add(ev.EndpointID, "", ev)
	}
	out := make([]*behaviorProfile, 0, len(byKey))
	for _, p := range byKey {
		if windowSeconds > 0 {
			p.AvgRate = float64(p.RequestCount) / float64(windowSeconds)
		}
		out = append(out, p)
	}
	sort.Slice(out, func(i, j int) bool {
		if out[i].EndpointID != out[j].EndpointID {
			return out[i].EndpointID < out[j].EndpointID
		}
		return out[i].Identity < out[j].Identity
	})
	return out
}

// RunBehaviorProfiles 执行一次行为画像聚合：回看窗口从 api_runtime_events 重算并 UPSERT
// api_behavior_profiles。执行结果记 aggregation_jobs（BEHAVIOR），失败不静默。
func (j *Jobs) RunBehaviorProfiles(ctx context.Context, now time.Time) error {
	windowEnd := now.UTC()
	rateStart := windowEnd.Add(-BehaviorProfileWindowSeconds * time.Second)
	hourStart := windowEnd.Add(-behaviorProfileHourLookback)
	n, err := j.aggregateBehaviorProfiles(ctx, hourStart, rateStart, windowEnd)
	if err != nil {
		_ = j.store.recordJob(ctx, "BEHAVIOR", hourStart, windowEnd, "FAILED", n, err.Error())
		return err
	}
	return j.store.recordJob(ctx, "BEHAVIOR", hourStart, windowEnd, "SUCCESS", n, "")
}

// aggregateBehaviorProfiles 拉取回看窗口事件（LEFT JOIN 解析 endpoint_id；未匹配端点的
// 事件跳过并计数告警，不静默丢弃），纯逻辑聚合后覆盖式 UPSERT。返回写入行数。
func (j *Jobs) aggregateBehaviorProfiles(ctx context.Context, hourStart, rateStart, windowEnd time.Time) (int, error) {
	rows, err := j.store.db.Query(ctx, `
SELECT e.id, ev.identity_fingerprint, ev.occurred_at, ev.response_status
FROM api_runtime_events ev
LEFT JOIN api_endpoints e ON e.endpoint_key = ev.endpoint_key
WHERE ev.occurred_at >= $1 AND ev.occurred_at < $2`, hourStart, windowEnd)
	if err != nil {
		return 0, fmt.Errorf("query runtime events: %w", err)
	}
	var events []behaviorEvent
	skipped := 0
	for rows.Next() {
		var endpointID *uuid.UUID
		var ev behaviorEvent
		if err := rows.Scan(&endpointID, &ev.Identity, &ev.OccurredAt, &ev.Status); err != nil {
			rows.Close()
			return 0, fmt.Errorf("scan runtime event: %w", err)
		}
		if endpointID == nil {
			skipped++ // 端点已删除或发现尚未落库：无法归属 endpoint_id（FK），不计入画像
			continue
		}
		ev.EndpointID = endpointID.String()
		events = append(events, ev)
	}
	rows.Close()
	if err := rows.Err(); err != nil {
		return 0, fmt.Errorf("iterate runtime events: %w", err)
	}
	if skipped > 0 {
		slog.Warn("behavior profile: events skipped (endpoint unresolved)",
			"skipped", skipped, "window_start", hourStart, "window_end", windowEnd)
	}

	profiles := aggregateBehaviorEvents(events, rateStart, windowEnd, BehaviorProfileWindowSeconds)
	if len(profiles) == 0 {
		return 0, nil
	}
	tx, err := j.store.db.Begin(ctx)
	if err != nil {
		return 0, err
	}
	defer func() { _ = tx.Rollback(ctx) }()
	n := 0
	for _, p := range profiles {
		statusDist, _ := json.Marshal(p.StatusDist)
		hourDist, _ := json.Marshal(p.HourDist)
		// EndpointID 由扫描的 uuid 而来，写库前还原为 uuid.UUID 传参（避免 text→uuid 类型歧义）
		endpointID, err := uuid.Parse(p.EndpointID)
		if err != nil {
			return n, fmt.Errorf("parse endpoint id %q: %w", p.EndpointID, err)
		}
		if _, err := tx.Exec(ctx, `
INSERT INTO api_behavior_profiles (endpoint_id, identity_fingerprint, window_seconds, request_count, avg_rate, status_code_dist, hour_dist, updated_at)
VALUES ($1, $2, $3, $4, $5, $6, $7, now())
ON CONFLICT (endpoint_id, identity_fingerprint, window_seconds) DO UPDATE SET
  request_count = EXCLUDED.request_count, avg_rate = EXCLUDED.avg_rate,
  status_code_dist = EXCLUDED.status_code_dist, hour_dist = EXCLUDED.hour_dist,
  updated_at = now()`,
			endpointID, p.Identity, BehaviorProfileWindowSeconds,
			p.RequestCount, p.AvgRate, statusDist, hourDist); err != nil {
			return n, fmt.Errorf("upsert behavior profile: %w", err)
		}
		n++
	}
	return n, tx.Commit(ctx)
}

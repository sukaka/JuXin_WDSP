// api_collector.go API 专项指标采集器（阶段8 / 补全任务书 §158 口径）。
//
// 周期从 DB 聚合 21 项 API 专项指标为「当前值」快照（gauge 语义；速率/耗时类为
// float gauge，见 APISnapshot.Floats），经 Snapshot()/Render() 输出（Render 为
// Prometheus 文本 exposition）。
// 采集调度遵循 runtimehealth.Collector 既有模式：Run 启动即采一轮 + ticker 周期，
// 单轮单源失败只记录错误并保留该源旧值，不影响其他指标源与后续轮次（不静默吞错：
// 错误累计进 CollectErrors 并随 Render 的 api_metrics_collect_errors_total 暴露）。
//
// 与阶段6 指标管道（aggregations → metric_*_aggregates）的关系：聚合表按时间桶
// 计数、供范围求和（SumRange），承载「当前总量」型 gauge 会因按桶求和重复计数，
// 故本采集器采用内存快照 + 文本输出，不写聚合表。
//
// 成本说明：mask_response_total / findings / samples 等指标为全表 count，源表
// （api_runtime_events 等）当前无留存清理、随时间增长；默认 1 分钟采集周期下
// 代价可接受，表量大后应改为增量聚合（超出本分片范围）。
package metrics

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"
)

// DefaultAPICollectInterval 默认采集周期（对齐阶段6 分钟聚合粒度；全表计数不宜高频）。
const DefaultAPICollectInterval = time.Minute

// apiQueryTimeout 单源聚合查询超时（与 runtimehealth 探针同量级，避免拖住采集轮）。
const apiQueryTimeout = 10 * time.Second

// apiAssetsNewWindow 「新端点」窗口（api_assets_new）：近 24 小时首次发现。
const apiAssetsNewWindow = 24 * time.Hour

// apiDiscoveryRateWindow 「每秒识别量」统计窗口：近 60s 新识别端点数 / 窗口秒数。
const apiDiscoveryRateWindow = time.Minute

// apiLearningLatencyWindow 学习延迟统计窗口：近 24h 完成（COMPLETED）的学习任务。
const apiLearningLatencyWindow = 24 * time.Hour

// APISnapshot 一轮 API 专项指标快照（UTC；Values/Floats 键为本包指标名枚举）。
type APISnapshot struct {
	CollectedAt   time.Time          `json:"collected_at"`
	Values        map[string]int64   `json:"values"`
	Floats        map[string]float64 `json:"floats,omitempty"` // 速率/耗时类 float gauge
	CollectErrors int                `json:"collect_errors"`   // 累计采集错误次数
	LastError     string             `json:"last_error,omitempty"`
	// StrongFlow 强流程 per-app 指标行集（NG-FLOW-04 §1.9；无强流程实例为 nil——
	// 渲染整段省略，观测面零变化 NG-T-C01）
	StrongFlow []StrongFlowAppMetrics `json:"strong_flow,omitempty"`
}

// APICollector API 专项指标采集器（周期 DB 聚合 + 内存快照）。
type APICollector struct {
	db  *pgxpool.Pool
	now func() time.Time // 时钟（测试注入）

	mu          sync.RWMutex
	values      map[string]int64
	floats      map[string]float64
	strongFlow  []StrongFlowAppMetrics
	collectedAt time.Time
	collectErrs int
	lastError   string
}

// NewAPICollector 创建采集器。
func NewAPICollector(db *pgxpool.Pool) *APICollector {
	return &APICollector{
		db:     db,
		now:    func() time.Time { return time.Now().UTC() },
		values: map[string]int64{},
		floats: map[string]float64{},
	}
}

// Run 周期采集直到 ctx 取消（启动时立即采集一轮）。
func (c *APICollector) Run(ctx context.Context, interval time.Duration) {
	if interval <= 0 {
		interval = DefaultAPICollectInterval
	}
	ticker := time.NewTicker(interval)
	defer ticker.Stop()
	slog.Info("api metrics collector started", "interval", interval)
	c.collectSafe(ctx)
	for {
		select {
		case <-ctx.Done():
			slog.Info("api metrics collector stopped")
			return
		case <-ticker.C:
			c.collectSafe(ctx)
		}
	}
}

// collectSafe 采集一轮；失败仅记日志，不中断调度。
func (c *APICollector) collectSafe(ctx context.Context) {
	if err := c.CollectOnce(ctx); err != nil {
		slog.Error("api metrics collect error", "error", err)
	}
}

// CollectOnce 执行一轮采集：逐源聚合，单源失败保留该源上一轮值（gauge 缺新值
// 不代表归零）并累计错误，返回聚合错误（无错误返回 nil）。
func (c *APICollector) CollectOnce(ctx context.Context) error {
	c.mu.RLock()
	values := make(map[string]int64, len(c.values)+len(apiMetricDocs))
	for k, v := range c.values {
		values[k] = v
	}
	floats := make(map[string]float64, len(c.floats)+len(apiFloatMetricDocs))
	for k, v := range c.floats {
		floats[k] = v
	}
	strongFlow := append([]StrongFlowAppMetrics(nil), c.strongFlow...)
	c.mu.RUnlock()

	var errs []error
	fail := func(source string, err error) {
		errs = append(errs, fmt.Errorf("%s: %w", source, err))
	}

	// 1. API 资产（api_endpoints）：合并单次扫描总数、近 24h 新发现、ZOMBIE 资产与近 60s 识别速率
	var assetsTotal, assetsNew, zombieTotal, discovered int64
	now := c.now()
	qCtx, cancel := context.WithTimeout(ctx, apiQueryTimeout)
	err := c.db.QueryRow(qCtx, `
SELECT count(*),
       count(*) FILTER (WHERE first_seen_at >= $1),
       count(*) FILTER (WHERE asset_status = 'ZOMBIE'),
       count(*) FILTER (WHERE first_seen_at >= $2)
FROM api_endpoints WHERE is_api = TRUE`,
		now.Add(-apiAssetsNewWindow), now.Add(-apiDiscoveryRateWindow)).Scan(
		&assetsTotal, &assetsNew, &zombieTotal, &discovered)
	cancel()
	if err != nil {
		fail("api_endpoints", err)
	} else {
		values[APIAssetsTotal] = assetsTotal
		values[APIAssetsNew] = assetsNew
		values[APIZombieTotal] = zombieTotal
		floats[APIDiscoveryPerSecond] = DiscoveryPerSecond(discovered, apiDiscoveryRateWindow)
	}

	// 2. 学习任务（api_learning_jobs）：运行中任务数
	var runningJobs int64
	qCtx, cancel = context.WithTimeout(ctx, apiQueryTimeout)
	err = c.db.QueryRow(qCtx,
		`SELECT count(*) FROM api_learning_jobs WHERE status = 'RUNNING'`).Scan(&runningJobs)
	cancel()
	if err != nil {
		fail("api_learning_jobs", err)
	} else {
		values[APILearningJobs] = runningJobs
	}

	// 3. 学习样本（api_learning_samples）：累计样本数与被排除数
	var samples, excluded int64
	qCtx, cancel = context.WithTimeout(ctx, apiQueryTimeout)
	err = c.db.QueryRow(qCtx, `
SELECT count(*), count(*) FILTER (WHERE accepted = FALSE)
FROM api_learning_samples`).Scan(&samples, &excluded)
	cancel()
	if err != nil {
		fail("api_learning_samples", err)
	} else {
		values[APILearningSamples] = samples
		values[APILearningExcluded] = excluded
	}

	// 4. 模型版本（api_model_versions）：候选与已确认状态计数
	qCtx, cancel = context.WithTimeout(ctx, apiQueryTimeout)
	versionCounts, err := c.queryCounts(qCtx,
		`SELECT status, count(*) FROM api_model_versions GROUP BY status`)
	cancel()
	if err != nil {
		fail("api_model_versions", err)
	} else {
		candidates, confirmed := AggregateModelVersions(versionCounts)
		values[APICandidatesCreated] = candidates
		values[APIModelsConfirmed] = confirmed
	}

	// 5. 运行时策略（api_runtime_policies）：编译总数与失败数
	qCtx, cancel = context.WithTimeout(ctx, apiQueryTimeout)
	policyCounts, err := c.queryCounts(qCtx,
		`SELECT status, count(*) FROM api_runtime_policies GROUP BY status`)
	cancel()
	if err != nil {
		fail("api_runtime_policies", err)
	} else {
		total, failed := AggregateRuntimePolicies(policyCounts)
		values[RuntimeCompileTotal] = total
		values[RuntimeCompileError] = failed
	}

	// 6. 风险发现（api_runtime_findings）：按 finding_type 前缀分五组
	qCtx, cancel = context.WithTimeout(ctx, apiQueryTimeout)
	findingCounts, err := c.queryCounts(qCtx,
		`SELECT finding_type, count(*) FROM api_runtime_findings GROUP BY finding_type`)
	cancel()
	if err != nil {
		fail("api_runtime_findings", err)
	} else {
		for name, n := range AggregateFindingsByGroup(findingCounts) {
			values[name] = n
		}
	}

	// 7. 响应脱敏（api_runtime_events）：MASK_RESPONSE 决策累计
	var maskTotal int64
	qCtx, cancel = context.WithTimeout(ctx, apiQueryTimeout)
	err = c.db.QueryRow(qCtx,
		`SELECT count(*) FROM api_runtime_events WHERE final_action = 'MASK_RESPONSE'`).Scan(&maskTotal)
	cancel()
	if err != nil {
		fail("api_runtime_events", err)
	} else {
		values[MaskResponseTotal] = maskTotal
	}

	// 8. Shadow 数（api_runtime_findings）：未关闭的 SHADOW 发现
	// （状态词表见迁移 000042；口径同 reports.findingOpenStatuses）
	var shadowTotal int64
	qCtx, cancel = context.WithTimeout(ctx, apiQueryTimeout)
	err = c.db.QueryRow(qCtx, `
SELECT count(*) FROM api_runtime_findings
WHERE finding_type = 'SHADOW' AND status IN ('NEW','CONFIRMED','IN_PROGRESS')`).Scan(&shadowTotal)
	cancel()
	if err != nil {
		fail("api_shadow_findings", err)
	} else {
		values[APIShadowTotal] = shadowTotal
	}

	// （原 9. api_endpoints ZOMBIE 与识别速率已并入步骤 1 单次扫描，减少大表重复扫描）

	// 10. 学习延迟（api_learning_jobs）：近 24h COMPLETED 任务平均时长（秒）；
	// 窗口内无完成任务时为 0（无样本即无延迟读数，不外推旧值口径——旧值随快照保留纪律
	// 仅适用于采集失败；采集成功但无样本时 0 是真实当前值）
	var learnLatency float64
	qCtx, cancel = context.WithTimeout(ctx, apiQueryTimeout)
	err = c.db.QueryRow(qCtx, `
SELECT COALESCE(avg(EXTRACT(EPOCH FROM (stopped_at - started_at))), 0)
FROM api_learning_jobs
WHERE status = 'COMPLETED' AND stopped_at IS NOT NULL AND stopped_at >= $1`,
		c.now().Add(-apiLearningLatencyWindow)).Scan(&learnLatency)
	cancel()
	if err != nil {
		fail("api_learning_latency", err)
	} else {
		floats[APILearningLatencySeconds] = learnLatency
	}

	// 11. 图谱边（api_call_edges）：调用边全表计数
	var edgeTotal int64
	qCtx, cancel = context.WithTimeout(ctx, apiQueryTimeout)
	err = c.db.QueryRow(qCtx, `SELECT count(*) FROM api_call_edges`).Scan(&edgeTotal)
	cancel()
	if err != nil {
		fail("api_call_edges", err)
	} else {
		values[APIGraphEdgesTotal] = edgeTotal
	}

	// 12. AI Tool 调用量（ai_tool_calls）：全表计数
	var aiToolCalls int64
	qCtx, cancel = context.WithTimeout(ctx, apiQueryTimeout)
	err = c.db.QueryRow(qCtx, `SELECT count(*) FROM ai_tool_calls`).Scan(&aiToolCalls)
	cancel()
	if err != nil {
		fail("ai_tool_calls", err)
	} else {
		values[AIToolCallsTotal] = aiToolCalls
	}

	// 13. 强流程运行指标（NG-FLOW-04 §1.9；api_strong_flow_instances/step_events
	// 迁移 000177 表——缺表/查询失败单源失败保留上一轮行集，不拖垮其他源）：
	// per-app 五态分桶 + INDETERMINATE 积压与滞留时延 + 近 24h RESERVE 冲突率
	sfRows, sfErr := c.collectStrongFlow(ctx)
	if sfErr != nil {
		fail("strong_flow", sfErr)
	} else {
		strongFlow = sfRows
	}

	c.mu.Lock()
	c.values = values
	c.floats = floats
	c.strongFlow = strongFlow
	c.collectedAt = c.now()
	c.collectErrs += len(errs)
	if len(errs) > 0 {
		c.lastError = errors.Join(errs...).Error()
	} else {
		c.lastError = ""
	}
	c.mu.Unlock()
	return errors.Join(errs...)
}

// collectStrongFlow 强流程指标三路聚合（NG-FLOW-04 §1.9；迁移 000177 表缺表即
// 单源失败——与既有源同纪律，不静默吞错）：
//  1. 实例计数按五态分桶（per-app）；
//  2. INDETERMINATE 积压与滞留时延（采集时刻 - updated_at 的 avg/max）；
//  3. 近 24h step_events RESERVE 动作冲突率（result∈CONFLICT,REJECTED）。
func (c *APICollector) collectStrongFlow(ctx context.Context) ([]StrongFlowAppMetrics, error) {
	qCtx, cancel := context.WithTimeout(ctx, apiQueryTimeout)
	defer cancel()
	var instances []strongFlowInstanceRow
	rows, err := c.db.Query(qCtx, `SELECT application_id, status, count(*)
		FROM api_strong_flow_instances GROUP BY application_id, status`)
	if err != nil {
		return nil, fmt.Errorf("instances: %w", err)
	}
	defer rows.Close()
	for rows.Next() {
		var r strongFlowInstanceRow
		if err := rows.Scan(&r.AppID, &r.Status, &r.N); err != nil {
			return nil, err
		}
		instances = append(instances, r)
	}
	if err := rows.Err(); err != nil {
		return nil, err
	}
	var indet []strongFlowIndeterminateRow
	rows2, err := c.db.Query(qCtx, `SELECT application_id, count(*),
		COALESCE(avg(EXTRACT(EPOCH FROM (now() - updated_at))), 0),
		COALESCE(max(EXTRACT(EPOCH FROM (now() - updated_at))), 0)
		FROM api_strong_flow_instances WHERE status='INDETERMINATE' GROUP BY application_id`)
	if err != nil {
		return nil, fmt.Errorf("indeterminate: %w", err)
	}
	defer rows2.Close()
	for rows2.Next() {
		var r strongFlowIndeterminateRow
		if err := rows2.Scan(&r.AppID, &r.N, &r.AvgSec, &r.MaxSec); err != nil {
			return nil, err
		}
		indet = append(indet, r)
	}
	if err := rows2.Err(); err != nil {
		return nil, err
	}
	var reserve []strongFlowReserveRow
	rows3, err := c.db.Query(qCtx, `SELECT i.application_id,
		count(*) FILTER (WHERE e.action='RESERVE'),
		count(*) FILTER (WHERE e.action='RESERVE' AND e.result IN ('CONFLICT','REJECTED'))
		FROM api_strong_flow_step_events e
		JOIN api_strong_flow_instances i ON i.id = e.instance_id
		WHERE e.occurred_at >= now() - interval '24 hours'
		GROUP BY i.application_id`)
	if err != nil {
		return nil, fmt.Errorf("reserve: %w", err)
	}
	defer rows3.Close()
	for rows3.Next() {
		var r strongFlowReserveRow
		if err := rows3.Scan(&r.AppID, &r.Total, &r.Conflicts); err != nil {
			return nil, err
		}
		reserve = append(reserve, r)
	}
	if err := rows3.Err(); err != nil {
		return nil, err
	}
	return BuildStrongFlowMetrics(instances, indet, reserve), nil
}

// queryCounts 执行「键, count(*)」两列聚合查询。
func (c *APICollector) queryCounts(ctx context.Context, sql string) (map[string]int64, error) {
	rows, err := c.db.Query(ctx, sql)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := map[string]int64{}
	for rows.Next() {
		var key string
		var n int64
		if err := rows.Scan(&key, &n); err != nil {
			return nil, err
		}
		out[key] = n
	}
	return out, rows.Err()
}

// Snapshot 返回最新快照（Values/Floats/StrongFlow 为拷贝，调用方可安全持有）。
func (c *APICollector) Snapshot() APISnapshot {
	c.mu.RLock()
	defer c.mu.RUnlock()
	values := make(map[string]int64, len(c.values))
	for k, v := range c.values {
		values[k] = v
	}
	floats := make(map[string]float64, len(c.floats))
	for k, v := range c.floats {
		floats[k] = v
	}
	return APISnapshot{
		CollectedAt:   c.collectedAt,
		Values:        values,
		Floats:        floats,
		CollectErrors: c.collectErrs,
		LastError:     c.lastError,
		StrongFlow:    append([]StrongFlowAppMetrics(nil), c.strongFlow...),
	}
}

// Render 输出最新快照的 Prometheus 文本 exposition。
func (c *APICollector) Render() string {
	return RenderAPISnapshot(c.Snapshot())
}

// apiMetricDocs 指标输出顺序与 HELP 文案（固定顺序；指标名只允许本包枚举）。
var apiMetricDocs = []struct {
	name string
	help string
}{
	{APIAssetsTotal, "API 端点资产总数（数据源 api_endpoints，is_api=TRUE）"},
	{APIAssetsNew, "近 24 小时新发现 API 端点数（数据源 api_endpoints.first_seen_at）"},
	{APILearningJobs, "运行中学习任务数（数据源 api_learning_jobs，status=RUNNING）"},
	{APILearningSamples, "累计学习样本数（数据源 api_learning_samples）"},
	{APILearningExcluded, "累计被排除学习样本数（数据源 api_learning_samples，accepted=FALSE）"},
	{APICandidatesCreated, "当前候选模型版本数（数据源 api_model_versions，status=CANDIDATE/IN_REVIEW）"},
	{APIModelsConfirmed, "当前已确认（正式）模型版本数（数据源 api_model_versions，status=FORMAL）"},
	{RuntimeCompileTotal, "运行时策略编译产物总数（数据源 api_runtime_policies）"},
	{RuntimeCompileError, "编译/发布失败的运行时策略数（数据源 api_runtime_policies，status=FAILED）"},
	{SchemaFindings, "Schema 类风险发现数（数据源 api_runtime_findings，finding_type 前缀 SCHEMA_/API_SCHEMA）"},
	{AuthFindings, "认证类风险发现数（数据源 api_runtime_findings，finding_type 前缀 AUTH_/AUTHENTICATION）"},
	{AuthzFindings, "越权类风险发现数（数据源 api_runtime_findings，finding_type 前缀 BOLA/BFLA/AUTHZ_）"},
	{SensitiveFindings, "敏感数据类风险发现数（数据源 api_runtime_findings，finding_type 前缀 SENSITIVE_）"},
	{BehaviorFindings, "行为类风险发现数（数据源 api_runtime_findings，finding_type 前缀 BEHAVIOR）"},
	{MaskResponseTotal, "响应脱敏决策累计数（数据源 api_runtime_events，final_action=MASK_RESPONSE）"},
	{APIShadowTotal, "未关闭 Shadow 发现数（数据源 api_runtime_findings，finding_type=SHADOW 且 NEW/CONFIRMED/IN_PROGRESS）"},
	{APIZombieTotal, "Zombie 端点数（数据源 api_endpoints，asset_status=ZOMBIE 且 is_api=TRUE）"},
	{APIGraphEdgesTotal, "API 图谱调用边总数（数据源 api_call_edges）"},
	{AIToolCallsTotal, "AI Tool 调用累计数（数据源 ai_tool_calls）"},
}

// apiFloatMetricDocs float gauge 输出顺序与 HELP 文案（固定顺序；指标名只允许本包枚举）。
var apiFloatMetricDocs = []struct {
	name string
	help string
}{
	{APIDiscoveryPerSecond, "每秒 API 识别量（数据源 api_endpoints.first_seen_at，近 60s 新识别数/60）"},
	{APILearningLatencySeconds, "学习延迟秒数（数据源 api_learning_jobs，近 24h COMPLETED 任务平均时长）"},
}

// RenderAPISnapshot 渲染快照为 Prometheus 文本 exposition（纯函数，便于测试与装配复用）。
// 21 项专项指标恒输出（无值取 0，保证抓取方时序连续）；附带采集器自指标
// api_metrics_collect_errors_total / api_metrics_last_collect_timestamp_seconds。
func RenderAPISnapshot(s APISnapshot) string {
	var b strings.Builder
	for _, d := range apiMetricDocs {
		b.WriteString("# HELP " + d.name + " " + d.help + "\n")
		b.WriteString("# TYPE " + d.name + " gauge\n")
		fmt.Fprintf(&b, "%s %d\n", d.name, s.Values[d.name])
	}
	for _, d := range apiFloatMetricDocs {
		b.WriteString("# HELP " + d.name + " " + d.help + "\n")
		b.WriteString("# TYPE " + d.name + " gauge\n")
		fmt.Fprintf(&b, "%s %s\n", d.name, strconv.FormatFloat(s.Floats[d.name], 'f', -1, 64))
	}
	b.WriteString("# HELP api_metrics_collect_errors_total API 专项指标采集累计错误次数\n")
	b.WriteString("# TYPE api_metrics_collect_errors_total counter\n")
	fmt.Fprintf(&b, "api_metrics_collect_errors_total %d\n", s.CollectErrors)
	b.WriteString("# HELP api_metrics_last_collect_timestamp_seconds API 专项指标最近一轮采集时间（Unix 秒）\n")
	b.WriteString("# TYPE api_metrics_last_collect_timestamp_seconds gauge\n")
	fmt.Fprintf(&b, "api_metrics_last_collect_timestamp_seconds %d\n", s.CollectedAt.Unix())
	b.WriteString(RenderStrongFlowSection(s.StrongFlow))
	return b.String()
}

// ---------- 聚合纯函数（造数可测） ----------

// DiscoveryPerSecond 窗口内新识别端点数 → 每秒识别量（非正窗口防御性返回 0）。
func DiscoveryPerSecond(discovered int64, window time.Duration) float64 {
	if window <= 0 {
		return 0
	}
	return float64(discovered) / window.Seconds()
}

// FindingGroup 运行时发现分组（finding_type → 指标维度）。
// 前缀口径与生产方 apiruntime/findings.go 的 findingTypeOf 映射一致：
// rule_id 大写下划线化（schema.* → SCHEMA_*、auth.* → AUTH_*、sensitive.* →
// SENSITIVE_*、behavior.* → BEHAVIOR*），rule_id 缺失时以 detector 名兜底
// （api_schema → API_SCHEMA、authentication → AUTHENTICATION）；越权类取
// 任务书词表 BOLA/BFLA 前缀并预留 AUTHZ_。不属于五组（SHADOW/ZOMBIE/DEPRECATED/
// WAF_* 等生命周期与 WAF 类型）返回空串，不计入本批指标。
func FindingGroup(findingType string) string {
	ft := strings.ToUpper(findingType)
	switch {
	case strings.HasPrefix(ft, "SCHEMA_"), strings.HasPrefix(ft, "API_SCHEMA"):
		return "schema"
	case strings.HasPrefix(ft, "AUTH_"), strings.HasPrefix(ft, "AUTHENTICATION"):
		return "auth"
	case strings.HasPrefix(ft, "BOLA"), strings.HasPrefix(ft, "BFLA"), strings.HasPrefix(ft, "AUTHZ_"):
		return "authz"
	case strings.HasPrefix(ft, "SENSITIVE_"):
		return "sensitive"
	case strings.HasPrefix(ft, "BEHAVIOR"):
		return "behavior"
	}
	return ""
}

// AggregateFindingsByGroup 按 FindingGroup 汇总 finding_type 行数计数（counts 为 type→行数）。
func AggregateFindingsByGroup(counts map[string]int64) map[string]int64 {
	out := map[string]int64{
		SchemaFindings: 0, AuthFindings: 0, AuthzFindings: 0,
		SensitiveFindings: 0, BehaviorFindings: 0,
	}
	for ft, n := range counts {
		switch FindingGroup(ft) {
		case "schema":
			out[SchemaFindings] += n
		case "auth":
			out[AuthFindings] += n
		case "authz":
			out[AuthzFindings] += n
		case "sensitive":
			out[SensitiveFindings] += n
		case "behavior":
			out[BehaviorFindings] += n
		}
	}
	return out
}

// AggregateModelVersions 模型版本状态计数 → 候选/已确认。
// 候选 = CANDIDATE + IN_REVIEW（未确认在途）；已确认 = FORMAL（当前正式版本）。
// 状态机见 apimodels/store.go：SUPERSEDED/ARCHIVED 曾正式但已退出或归档，
// REJECTED 已拒绝，均不计入「当前已确认」口径。
func AggregateModelVersions(counts map[string]int64) (candidates, confirmed int64) {
	for st, n := range counts {
		switch strings.ToUpper(st) {
		case "CANDIDATE", "IN_REVIEW":
			candidates += n
		case "FORMAL":
			confirmed += n
		}
	}
	return candidates, confirmed
}

// AggregateRuntimePolicies 运行时策略状态计数 → 编译总数/失败数。
// 每行即一次编译产物（状态机见迁移 000037），FAILED 为编译/发布失败。
func AggregateRuntimePolicies(counts map[string]int64) (total, failed int64) {
	for st, n := range counts {
		total += n
		if strings.EqualFold(st, "FAILED") {
			failed += n
		}
	}
	return total, failed
}

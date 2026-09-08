// chstore_metrics.go APM 阶段3 第二批：运行时指标查询（metrics 信号）。
//
// 数据源：deployment/apm/clickhouse/003_metrics.sql 的 apm.otel_metrics_gauge /
// otel_metrics_sum / otel_metrics_histogram（对齐 contrib v0.154.0 clickhouse exporter
// 默认表结构与默认表名；summary/exp_histogram 本期不查询——Go/Java 等运行时埋点
// 不落这两类表）。
//
// 口径（如实标注，设计 §10.3"不同语言不能强行统一不存在的指标"）：
//   - 实例 = (ServiceName, ResourceAttributes['service.instance.id'])，
//     Agent 未上报 service.instance.id 时为空串，如实返回；
//   - 指标集按上报原样返回（不硬编码 Go/Java 清单），每实例按指标名升序取前 20 个；
//   - latest_value：同名多属性序列各自取窗口内最新值后求和
//     （go.memory.used 拆 go.memory.type=other/stack 两序列，合计即总用量）；
//   - points：按窗口等分降采样（桶宽 = ceil(窗口秒数/200)，≤201 桶），桶内单序列
//     取均值、同名多序列再按桶求和；直方图（go.schedule.duration 等）先按
//     Sum/Count 折算单点均值再降采样，description 附折算说明；
//   - description 尾部附来源（instrumentation scope）与折算口径说明。
//
// 纪律同 chstore.go：全部参数化（桶宽为本文件计算值的整数插值，非用户输入）、
// 强制限窗（≤24h，handler 侧 parseSearchWindow）、withCHSettings max_execution_time、
// CH 未配置/失败一律降级空数据（data_source=agentless + note），绝不 500。
package apm

import (
	"context"
	"math"
	"strconv"
	"strings"
	"time"
)

const (
	// maxRuntimeInstances 单次返回实例上限（+1 行探测截断，note 如实标注）。
	maxRuntimeInstances = 20
	// maxRuntimeMetricsPerInstance 每实例指标上限（按指标名升序截取，确定性口径）。
	maxRuntimeMetricsPerInstance = 20
	// maxRuntimePoints 每指标降采样点上限（桶宽由窗口等分保证 ≤201 桶，LIMIT BY 兜底）。
	maxRuntimePoints = 200
	// runtimeCatalogRowsLimit 目录查询行数兜底（实例×指标×序列，正常远小于此）。
	runtimeCatalogRowsLimit = 5000
	// runtimePointRowsLimit 点查询总行数兜底。
	runtimePointRowsLimit = 100000
)

// runtimeNormalNote 正常返回口径说明（data_source=otel 时携带）。
const runtimeNormalNote = "运行时指标按实例上报原样返回，不同语言 Agent 指标集不强行统一" +
	"（description 含来源 scope 与折算口径）；同名多序列按时间桶求和合并，直方图按 Sum/Count 折算均值；" +
	"points 已按窗口等分降采样（每指标 ≤200 点、每实例 ≤20 个指标）"

// runtimeBucketSeconds 降采样桶宽（秒）：窗口等分为 ≤200 桶，最小 1 秒。
func runtimeBucketSeconds(window time.Duration) int64 {
	sec := int64(math.Ceil(window.Seconds() / maxRuntimePoints))
	if sec < 1 {
		sec = 1
	}
	return sec
}

// ---------- 查询构造 ----------

// runtimeUnion runtime 指标三类表并集子查询（统一列形：histogram 行 Value 为
// Sum/Count 折算均值；source 列标识来源表，组装 description 用）。
// services/metricNames 非空时追加 IN 过滤（点查询阶段收窄到已选实例服务与指标）。
// 参数顺序：基础过滤三分支各绑定一遍，services/metricNames 过滤随分支各自追加。
func runtimeUnion(f RuntimeFilter, services, metricNames []string) (string, []any) {
	where := []string{"TimeUnix >= ?", "TimeUnix < ?"}
	args := []any{f.Start, f.End}
	if f.Service != "" {
		where = append(where, "ServiceName = ?")
		args = append(args, f.Service)
	}
	if f.InstanceID != "" {
		where = append(where, "ResourceAttributes['service.instance.id'] = ?")
		args = append(args, f.InstanceID)
	}
	if len(services) > 0 {
		where = append(where, "ServiceName IN (?)")
		args = append(args, services)
	}
	if len(metricNames) > 0 {
		where = append(where, "MetricName IN (?)")
		args = append(args, metricNames)
	}
	w := strings.Join(where, " AND ")
	// Sum/Count 为列名（与聚合函数同形），反引号引用避免解析歧义
	q := `SELECT ServiceName, ResourceAttributes['service.instance.id'] AS instance_id,
    MetricName, MetricUnit, MetricDescription, ScopeName, Attributes, TimeUnix, Value, 'gauge' AS source
  FROM apm.otel_metrics_gauge WHERE ` + w + `
  UNION ALL
  SELECT ServiceName, ResourceAttributes['service.instance.id'] AS instance_id,
    MetricName, MetricUnit, MetricDescription, ScopeName, Attributes, TimeUnix, Value, 'sum' AS source
  FROM apm.otel_metrics_sum WHERE ` + w + `
  UNION ALL
  SELECT ServiceName, ResourceAttributes['service.instance.id'] AS instance_id,
    MetricName, MetricUnit, MetricDescription, ScopeName, Attributes, TimeUnix,
    if(` + "`Count`" + ` > 0, ` + "`Sum`" + ` / toFloat64(` + "`Count`" + `), 0) AS Value, 'histogram' AS source
  FROM apm.otel_metrics_histogram WHERE ` + w
	all := make([]any, 0, len(args)*3)
	for i := 0; i < 3; i++ {
		all = append(all, args...)
	}
	return q, all
}

// buildRuntimeInstancesQuery 窗口内实例发现（去重 + 排序，+1 行探测截断）。
func buildRuntimeInstancesQuery(f RuntimeFilter) (string, []any) {
	union, args := runtimeUnion(f, nil, nil)
	return `SELECT DISTINCT ServiceName, instance_id
FROM (
` + union + `
)
ORDER BY ServiceName ASC, instance_id ASC
LIMIT ` + strconv.Itoa(maxRuntimeInstances+1), args
}

// buildRuntimeCatalogQuery 指标目录 + latest_value：内层按（实例×指标×属性序列）
// 取窗口内最新值，外层按（实例×指标）合并（多序列求和，口径见文件头注释）。
func buildRuntimeCatalogQuery(f RuntimeFilter) (string, []any) {
	union, args := runtimeUnion(f, nil, nil)
	return `SELECT ServiceName, instance_id, MetricName,
  anyLast(unit) AS unit, anyLast(descr) AS descr, anyLast(scope) AS scope, anyLast(source) AS source,
  sum(series_latest) AS latest_value
FROM (
  SELECT ServiceName, instance_id, MetricName, MetricUnit AS unit, MetricDescription AS descr,
    ScopeName AS scope, source, Attributes,
    argMax(Value, TimeUnix) AS series_latest
  FROM (
` + union + `
  )
  GROUP BY ServiceName, instance_id, MetricName, unit, descr, scope, source, Attributes
)
GROUP BY ServiceName, instance_id, MetricName
ORDER BY ServiceName ASC, instance_id ASC, MetricName ASC
LIMIT ` + strconv.Itoa(runtimeCatalogRowsLimit), args
}

// buildRuntimePointsQuery 降采样点序列：内层按（实例×指标×属性序列×桶）取均值，
// 外层按（实例×指标×桶）求和合并多序列。桶宽为 Go 侧计算的整数插值（非用户输入）；
// LIMIT BY 兜底每指标 ≤201 桶，全局 LIMIT 兜底总行数。
func buildRuntimePointsQuery(f RuntimeFilter, services, metricNames []string, bucketSec int64) (string, []any) {
	union, args := runtimeUnion(f, services, metricNames)
	return `SELECT ServiceName, instance_id, MetricName, bucket, sum(v) AS value
FROM (
  SELECT ServiceName, instance_id, MetricName, Attributes,
    toStartOfInterval(TimeUnix, toIntervalSecond(` + strconv.FormatInt(bucketSec, 10) + `)) AS bucket,
    avg(Value) AS v
  FROM (
` + union + `
  )
  GROUP BY ServiceName, instance_id, MetricName, Attributes, bucket
)
GROUP BY ServiceName, instance_id, MetricName, bucket
ORDER BY bucket ASC
LIMIT ` + strconv.Itoa(maxRuntimePoints+1) + ` BY ServiceName, instance_id, MetricName
LIMIT ` + strconv.Itoa(runtimePointRowsLimit), args
}

// ---------- 组装 ----------

// runtimeInstKey 实例键（服务名 + 实例 ID）。
type runtimeInstKey struct {
	service  string
	instance string
}

// runtimeDescription 组装 description：上报描述 + 来源 scope + 折算口径说明。
func runtimeDescription(descr, scope, source string) string {
	var suffix []string
	if scope != "" {
		suffix = append(suffix, "来源 scope: "+scope)
	}
	if source == "histogram" {
		suffix = append(suffix, "直方图按 Sum/Count 折算均值")
	}
	if len(suffix) == 0 {
		return descr
	}
	if descr == "" {
		return strings.Join(suffix, "；")
	}
	return descr + "（" + strings.Join(suffix, "；") + "）"
}

// degradedRuntime CH 未配置/不可用时的降级响应（空实例 + agentless + 提示，不 500）。
func degradedRuntime(message string) *RuntimeData {
	return &RuntimeData{DataSource: dataSourceAgentless, Instances: []RuntimeInstance{}, Note: message}
}

// ListRuntimeMetrics 运行时指标查询（CH 数据面；未配置/故障降级为空数据不报错）。
// 三阶段：实例发现（上限 20 + 截断探测）→ 指标目录与 latest_value（每实例 ≤20 个指标）
// → 降采样点序列（每指标 ≤200 点）。任一阶段失败整体降级为 agentless 空数据。
func (s *Store) ListRuntimeMetrics(ctx context.Context, f RuntimeFilter) (*RuntimeData, error) {
	ch := s.conn(ctx)
	if ch == nil {
		return degradedRuntime("APM_CLICKHOUSE_DSN 未配置：OTel 数据面未接入，运行时指标不可用"), nil
	}
	note := runtimeNormalNote

	// ---- 阶段1：实例发现 ----
	instSQL, instArgs := buildRuntimeInstancesQuery(f)
	instRows, err := ch.Query(withCHSettings(ctx), instSQL, instArgs...)
	if err != nil {
		slogWarnCH("runtime instances", err)
		return degradedRuntime(chDegradedMessage), nil
	}
	keys := []runtimeInstKey{}
	truncated := false
	for instRows.Next() {
		if len(keys) >= maxRuntimeInstances {
			// 第 maxRuntimeInstances+1 行仅作截断探测，不再扫描下放
			truncated = true
			break
		}
		var k runtimeInstKey
		if err := instRows.Scan(&k.service, &k.instance); err != nil {
			instRows.Close()
			slogWarnCH("runtime instances scan", err)
			return degradedRuntime(chDegradedMessage), nil
		}
		keys = append(keys, k)
	}
	if err := instRows.Err(); err != nil {
		instRows.Close()
		slogWarnCH("runtime instances iterate", err)
		return degradedRuntime(chDegradedMessage), nil
	}
	instRows.Close()
	if truncated {
		note += "；实例数已达上限 " + strconv.Itoa(maxRuntimeInstances) +
			"，请用 service/instance_id 参数缩小范围"
	}
	out := &RuntimeData{DataSource: dataSourceOTel, Instances: []RuntimeInstance{}, Note: note}
	if len(keys) == 0 {
		return out, nil
	}
	instIndex := map[runtimeInstKey]int{}
	for _, k := range keys {
		instIndex[k] = len(out.Instances)
		out.Instances = append(out.Instances, RuntimeInstance{
			InstanceID: k.instance, ServiceName: k.service, Metrics: []RuntimeMetric{},
		})
	}

	// ---- 阶段2：指标目录 + latest_value（每实例按名升序取前 20 个） ----
	catSQL, catArgs := buildRuntimeCatalogQuery(f)
	catRows, err := ch.Query(withCHSettings(ctx), catSQL, catArgs...)
	if err != nil {
		slogWarnCH("runtime catalog", err)
		return degradedRuntime(chDegradedMessage), nil
	}
	// metricIndex 记录（实例, 指标名）→ 实例内 metrics 下标，供点序列回填
	metricIndex := map[runtimeInstKey]map[string]int{}
	for catRows.Next() {
		var k runtimeInstKey
		var name, unit, descr, scope, source string
		var latest float64
		if err := catRows.Scan(&k.service, &k.instance, &name, &unit, &descr, &scope, &source, &latest); err != nil {
			catRows.Close()
			slogWarnCH("runtime catalog scan", err)
			return degradedRuntime(chDegradedMessage), nil
		}
		ii, ok := instIndex[k]
		if !ok || len(out.Instances[ii].Metrics) >= maxRuntimeMetricsPerInstance {
			continue // 未选实例（不会发生，目录与发现同窗同过滤）或已达指标上限
		}
		if metricIndex[k] == nil {
			metricIndex[k] = map[string]int{}
		}
		metricIndex[k][name] = len(out.Instances[ii].Metrics)
		out.Instances[ii].Metrics = append(out.Instances[ii].Metrics, RuntimeMetric{
			Name:        name,
			Unit:        unit,
			Description: runtimeDescription(descr, scope, source),
			LatestValue: round3(latest),
			Points:      []RuntimePoint{},
		})
	}
	if err := catRows.Err(); err != nil {
		catRows.Close()
		slogWarnCH("runtime catalog iterate", err)
		return degradedRuntime(chDegradedMessage), nil
	}
	catRows.Close()

	// ---- 阶段3：降采样点序列（收窄到已选服务与指标名，实例对在 Go 侧精确匹配） ----
	serviceSet := map[string]bool{}
	nameSet := map[string]bool{}
	for _, k := range keys {
		if len(metricIndex[k]) > 0 {
			serviceSet[k.service] = true
			for name := range metricIndex[k] {
				nameSet[name] = true
			}
		}
	}
	if len(nameSet) == 0 {
		return out, nil
	}
	services := make([]string, 0, len(serviceSet))
	for svc := range serviceSet {
		services = append(services, svc)
	}
	names := make([]string, 0, len(nameSet))
	for n := range nameSet {
		names = append(names, n)
	}
	ptSQL, ptArgs := buildRuntimePointsQuery(f, services, names, runtimeBucketSeconds(f.End.Sub(f.Start)))
	ptRows, err := ch.Query(withCHSettings(ctx), ptSQL, ptArgs...)
	if err != nil {
		slogWarnCH("runtime points", err)
		return degradedRuntime(chDegradedMessage), nil
	}
	defer ptRows.Close()
	for ptRows.Next() {
		var k runtimeInstKey
		var name string
		var bucket time.Time
		var v float64
		if err := ptRows.Scan(&k.service, &k.instance, &name, &bucket, &v); err != nil {
			slogWarnCH("runtime points scan", err)
			return degradedRuntime(chDegradedMessage), nil
		}
		// 服务×指标 IN 过滤的叉积可能带出未选实例对（多服务多实例交叉），仅回填已选
		ii, ok := instIndex[k]
		if !ok {
			continue
		}
		mi, ok := metricIndex[k][name]
		if !ok {
			continue
		}
		pts := out.Instances[ii].Metrics[mi].Points
		if len(pts) >= maxRuntimePoints {
			continue // LIMIT BY 兜底之外的防御（正常不会触发）
		}
		out.Instances[ii].Metrics[mi].Points = append(pts, RuntimePoint{Ts: bucket.UTC(), Value: round3(v)})
	}
	if err := ptRows.Err(); err != nil {
		slogWarnCH("runtime points iterate", err)
		return degradedRuntime(chDegradedMessage), nil
	}
	return out, nil
}

// round3 浮点统一保留 3 位小数（与 roundMS 同口径；运行时指标单位各异，
// 毫秒/字节/计数均适用，避免浮点长尾污染响应）。
func round3(v float64) float64 { return math.Round(v*1000) / 1000 }

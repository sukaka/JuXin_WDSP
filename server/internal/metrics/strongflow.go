// strongflow.go 强流程运行指标（NG-FLOW-04 §1.9/D9：实例计数按状态、INDETERMINATE
// 率与积压、对账时延、reserve 冲突率）——内嵌既有 api-security/metrics 端点
// （Prometheus 文本 exposition 同形态，零新端点；权限随端点 api_runtime.read 零新增）。
//
// 形态与口径（冻结注释）：
//   - per-app labeled 序列（application_id 标签；与端点内既有 21 项全局无 label
//     gauge 并存——强流程实例天然按应用归属，聚合全局会抹平单应用积压信号）；
//   - 五态分桶每应用恒输出五序列（无该状态补 0，与全局「无值取 0」时序连续
//     纪律一致）；无任何强流程实例时整段省略（无强流程活动即零输出——NG-T-C01
//     观测面零变化，Prometheus absent 语义，不输出全 0 序列冒充「有定义零实例」）；
//   - 对账时延口径（可实现口径选定并注释）：INDETERMINATE 实例当前积压滞留时长
//     （采集时刻 - updated_at）的 avg 与 max 双序列——avg 对长积压敏感、max 暴露
//     最坏滞留；p50 不选（积压样本通常个位数，分位数读数噪声大且 avg/max 已覆盖
//     运营关注面）；无 INDETERMINATE 实例时 0（无积压即无滞留，0 是真实当前值）；
//   - reserve 冲突率口径：近 24h step_events 中 action=RESERVE 且
//     result∈(CONFLICT,REJECTED) 占全部 RESERVE 动作比；窗口无 RESERVE 样本
//     时 0（无样本即无冲突读数，不外推——同 APILearningLatencySeconds 口径纪律）。
//   - 成本说明：三查询均为 per-app GROUP BY（实例表按主键维度小表；step_events
//     近 24h 窗口过滤，与既有全表 count 指标同量纲可接受——表量大后改增量聚合）。
package metrics

import (
	"fmt"
	"sort"
	"strconv"
	"strings"
)

// formatGaugeFloat float gauge 文本格式化（与 RenderAPISnapshot float 序列同形）。
func formatGaugeFloat(f float64) string { return strconv.FormatFloat(f, 'f', -1, 64) }

// 强流程指标名（本包枚举，render 顺序固定；labels 见 RenderStrongFlowSection）。
const (
	StrongFlowInstances            = "strong_flow_instances"                     // {application_id,status} 五态分桶
	StrongFlowIndeterminateBacklog = "strong_flow_indeterminate_backlog"         // {application_id} INDETERMINATE 当前积压
	StrongFlowIndeterminateRatio   = "strong_flow_indeterminate_ratio"           // {application_id} 占实例比（float）
	StrongFlowIndeterminateAgeAvg  = "strong_flow_indeterminate_age_avg_seconds" // {application_id} 积压滞留均值秒
	StrongFlowIndeterminateAgeMax  = "strong_flow_indeterminate_age_max_seconds" // {application_id} 积压滞留最大秒
	StrongFlowReserveConflictRatio = "strong_flow_reserve_conflict_ratio"        // {application_id} 近 24h RESERVE 冲突占比（float）
)

// strongFlowStatuses 实例五态（分桶恒输出序；与迁移 000177 CHECK 词表一致）。
var strongFlowStatuses = []string{"ACTIVE", "CONFIRMED", "INDETERMINATE", "CANCELLED", "FAILED"}

// strongFlowReserveConflictWindow reserve 冲突率统计窗口（近 24h）。
const strongFlowReserveConflictWindow = "24 hours"

// StrongFlowAppMetrics 单应用强流程指标行（采集快照元素；StableOrder 稳定排序）。
type StrongFlowAppMetrics struct {
	ApplicationID string
	// InstancesByStatus 实例计数按五态分桶（五键恒在，缺省 0）
	InstancesByStatus map[string]int64
	// IndeterminateBacklog INDETERMINATE 当前积压数
	IndeterminateBacklog int64
	// IndeterminateRatio INDETERMINATE 占实例比（0..1；实例总数 0 时 0——
	// 无实例应用本就不在行集内，此防御仅覆盖聚合竞态）
	IndeterminateRatio float64
	// IndeterminateAgeAvgSeconds / IndeterminateAgeMaxSeconds 对账时延
	// （INDETERMINATE 实例采集时刻 - updated_at 滞留时长 avg/max；无积压=0）
	IndeterminateAgeAvgSeconds float64
	IndeterminateAgeMaxSeconds float64
	// ReserveTotal24h / ReserveConflict24h 近 24h RESERVE 动作总数与
	// 冲突数（result∈CONFLICT,REJECTED）
	ReserveTotal24h    int64
	ReserveConflict24h int64
	// ReserveConflictRatio 冲突占比（无样本=0 不外推）
	ReserveConflictRatio float64
}

// strongFlowInstanceRow 实例分桶查询行（application_id, status, n）。
type strongFlowInstanceRow struct {
	AppID  string
	Status string
	N      int64
}

// strongFlowIndeterminateRow INDETERMINATE 积压查询行（application_id, n, avgSec, maxSec）。
type strongFlowIndeterminateRow struct {
	AppID  string
	N      int64
	AvgSec float64
	MaxSec float64
}

// strongFlowReserveRow reserve 冲突率查询行（application_id, total, conflicts）。
type strongFlowReserveRow struct {
	AppID     string
	Total     int64
	Conflicts int64
}

// BuildStrongFlowMetrics 三路查询行集 → per-app 指标行集（application_id 升序稳定
// 排序——同内容恒得同序列化，抓取方 diff 可核对）。纯函数（造数可测）。
func BuildStrongFlowMetrics(instances []strongFlowInstanceRow, indet []strongFlowIndeterminateRow, reserve []strongFlowReserveRow) []StrongFlowAppMetrics {
	byApp := map[string]*StrongFlowAppMetrics{}
	at := func(appID string) *StrongFlowAppMetrics {
		m, ok := byApp[appID]
		if !ok {
			m = &StrongFlowAppMetrics{ApplicationID: appID, InstancesByStatus: map[string]int64{}}
			for _, st := range strongFlowStatuses {
				m.InstancesByStatus[st] = 0
			}
			byApp[appID] = m
		}
		return m
	}
	for _, r := range instances {
		m := at(r.AppID)
		if _, ok := m.InstancesByStatus[r.Status]; ok {
			m.InstancesByStatus[r.Status] += r.N
		}
		// 词表外状态（未来扩展未同步）不计入分桶——不静默吞错由 DB CHECK 兜底，
		// 此处只承载已知五态
	}
	for _, r := range indet {
		m := at(r.AppID)
		m.IndeterminateBacklog = r.N
		m.IndeterminateAgeAvgSeconds = r.AvgSec
		m.IndeterminateAgeMaxSeconds = r.MaxSec
	}
	for _, r := range reserve {
		m := at(r.AppID)
		m.ReserveTotal24h = r.Total
		m.ReserveConflict24h = r.Conflicts
	}
	out := make([]StrongFlowAppMetrics, 0, len(byApp))
	for _, m := range byApp {
		var total int64
		for _, st := range strongFlowStatuses {
			total += m.InstancesByStatus[st]
		}
		if total > 0 {
			m.IndeterminateRatio = float64(m.IndeterminateBacklog) / float64(total)
		}
		if m.ReserveTotal24h > 0 {
			m.ReserveConflictRatio = float64(m.ReserveConflict24h) / float64(m.ReserveTotal24h)
		}
		out = append(out, *m)
	}
	sort.Slice(out, func(a, b int) bool { return out[a].ApplicationID < out[b].ApplicationID })
	return out
}

// RenderStrongFlowSection 渲染强流程指标段（纯函数）。rows 为空 → 整段省略
// （无强流程活动即零输出——不输出全 0 序列冒充「有定义零实例」；HELP/TYPE 头同省）。
func RenderStrongFlowSection(rows []StrongFlowAppMetrics) string {
	if len(rows) == 0 {
		return ""
	}
	var b strings.Builder
	b.WriteString("# HELP " + StrongFlowInstances + " 强流程实例计数按五态分桶（数据源 api_strong_flow_instances；labels application_id/status）\n")
	b.WriteString("# TYPE " + StrongFlowInstances + " gauge\n")
	for _, m := range rows {
		for _, st := range strongFlowStatuses {
			fmt.Fprintf(&b, "%s{application_id=%q,status=%q} %d\n",
				StrongFlowInstances, m.ApplicationID, st, m.InstancesByStatus[st])
		}
	}
	b.WriteString("# HELP " + StrongFlowIndeterminateBacklog + " 强流程 INDETERMINATE 实例当前积压数（未知待对账，不显示安全通过）\n")
	b.WriteString("# TYPE " + StrongFlowIndeterminateBacklog + " gauge\n")
	for _, m := range rows {
		fmt.Fprintf(&b, "%s{application_id=%q} %d\n", StrongFlowIndeterminateBacklog, m.ApplicationID, m.IndeterminateBacklog)
	}
	b.WriteString("# HELP " + StrongFlowIndeterminateRatio + " 强流程 INDETERMINATE 实例占全部实例比（0..1）\n")
	b.WriteString("# TYPE " + StrongFlowIndeterminateRatio + " gauge\n")
	for _, m := range rows {
		fmt.Fprintf(&b, "%s{application_id=%q} %s\n", StrongFlowIndeterminateRatio, m.ApplicationID, formatGaugeFloat(m.IndeterminateRatio))
	}
	b.WriteString("# HELP " + StrongFlowIndeterminateAgeAvg + " 强流程 INDETERMINATE 实例积压滞留时长均值（秒；采集时刻 - updated_at）\n")
	b.WriteString("# TYPE " + StrongFlowIndeterminateAgeAvg + " gauge\n")
	for _, m := range rows {
		fmt.Fprintf(&b, "%s{application_id=%q} %s\n", StrongFlowIndeterminateAgeAvg, m.ApplicationID, formatGaugeFloat(m.IndeterminateAgeAvgSeconds))
	}
	b.WriteString("# HELP " + StrongFlowIndeterminateAgeMax + " 强流程 INDETERMINATE 实例积压滞留时长最大值（秒；采集时刻 - updated_at）\n")
	b.WriteString("# TYPE " + StrongFlowIndeterminateAgeMax + " gauge\n")
	for _, m := range rows {
		fmt.Fprintf(&b, "%s{application_id=%q} %s\n", StrongFlowIndeterminateAgeMax, m.ApplicationID, formatGaugeFloat(m.IndeterminateAgeMaxSeconds))
	}
	b.WriteString("# HELP " + StrongFlowReserveConflictRatio + " 强流程近 24h RESERVE 动作冲突占比（result∈CONFLICT,REJECTED；窗口无样本=0 不外推）\n")
	b.WriteString("# TYPE " + StrongFlowReserveConflictRatio + " gauge\n")
	for _, m := range rows {
		fmt.Fprintf(&b, "%s{application_id=%q} %s\n", StrongFlowReserveConflictRatio, m.ApplicationID, formatGaugeFloat(m.ReserveConflictRatio))
	}
	return b.String()
}

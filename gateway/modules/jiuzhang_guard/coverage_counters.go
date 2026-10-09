// coverage_counters.go 请求出入口最小计数（NG-COV-01 guard 段）：
// 节点级阶段归因计数器，支撑「上游已拒绝 / 到达 API 管线 / 到达源站」三分区分
// （RD_PLAN §5.1：仅在 API 管线内打点无法覆盖前两者，需在请求入口/出口最小计数接线）。
//
// 纪律：只计数、不改变任何处理顺序与响应语义；原子自增为纳秒级，无热路径分配。
package jiuzhang_guard

import (
	"net/http"
	"sync"
	"sync/atomic"

	"github.com/caddyserver/caddy/v2/modules/caddyhttp"
)

// CovStage 计数阶段（标签冻结：进入聚合后不得改名，新增只准追加）。
type CovStage string

const (
	// 入口总量
	StageTotal CovStage = "total"
	// 上游拒绝（请求被 guard 上游环节终止，未到达 API 管线）
	StageManualBan    CovStage = "rejected_manual_ban"    // 人工临时封禁
	StageIPBlacklist  CovStage = "rejected_ip_blacklist"  // IP 黑名单
	StageAutoBan      CovStage = "rejected_auto_ban"      // 自动临时封禁
	StageL7ACL        CovStage = "rejected_l7_acl"        // L7 访问控制阻断
	StageCC           CovStage = "rejected_cc"            // CC 频率限制
	StageLicenseQuota CovStage = "rejected_license_quota" // 授权配额全局限速
	StageBotIntercept CovStage = "intercepted_bot"        // Bot 挑战/协议命名空间拦截
	StageWAFIntercept CovStage = "intercepted_waf"        // Coraza/WAF 中断（未到达源站）
	// 到达面
	StageAPIPipelineReached CovStage = "reached_api_pipeline" // 到达 API 动态防护管线
	StageProxied            CovStage = "reached_upstream"     // 实际反向代理到源站（链路完成、未被 WAF 中断）
)

// covStageOrder 阶段稳定顺序（快照/导出按此序，保对账可 diff）。
var covStageOrder = []CovStage{
	StageTotal,
	StageManualBan,
	StageIPBlacklist,
	StageAutoBan,
	StageL7ACL,
	StageCC,
	StageLicenseQuota,
	StageBotIntercept,
	StageWAFIntercept,
	StageAPIPipelineReached,
	StageProxied,
}

// CovStageCount 单阶段计数。
type CovStageCount struct {
	Stage CovStage `json:"stage"`
	Count uint64   `json:"count"`
}

// CovCounters 阶段计数注册表（节点级单例）。
type CovCounters struct {
	mu      sync.RWMutex // 仅用于 Snapshot/Reset 与 map 结构一致性
	buckets map[CovStage]*atomic.Uint64
}

// NewCovCounters 创建注册表（预建全部阶段桶，保证快照键集稳定）。
func NewCovCounters() *CovCounters {
	c := &CovCounters{buckets: map[CovStage]*atomic.Uint64{}}
	for _, s := range covStageOrder {
		c.buckets[s] = &atomic.Uint64{}
	}
	return c
}

// Inc 阶段计数 +1（未知阶段忽略——标签冻结纪律下不应出现）。
func (c *CovCounters) Inc(s CovStage) {
	c.mu.RLock()
	b, ok := c.buckets[s]
	c.mu.RUnlock()
	if !ok {
		return
	}
	b.Add(1)
}

// Snapshot 按稳定顺序返回全部阶段计数（含零值）。
func (c *CovCounters) Snapshot() []CovStageCount {
	out := make([]CovStageCount, 0, len(covStageOrder))
	for _, s := range covStageOrder {
		c.mu.RLock()
		v := c.buckets[s].Load()
		c.mu.RUnlock()
		out = append(out, CovStageCount{Stage: s, Count: v})
	}
	return out
}

// Reset 清零（仅测试用）。
func (c *CovCounters) Reset() {
	for _, s := range covStageOrder {
		c.mu.RLock()
		c.buckets[s].Store(0)
		c.mu.RUnlock()
	}
}

// DefaultCovCounters 节点级默认注册表（装配/摄入层读取 Snapshot 周期汇总）。
var DefaultCovCounters = NewCovCounters()

// proxyAndCount 执行下游链并按结果归因计数（契约 ExecutionOutcome.forwarded_to_origin 语义）：
// 链路完成（err==nil）计 reached_upstream；Coraza/WAF 中断计 intercepted_waf；
// 其他错误不另计——既不把 WAF 拦截夸大成源站到达，也不把非 WAF 故障误标为攻击。
func proxyAndCount(w http.ResponseWriter, r *http.Request, next caddyhttp.Handler) error {
	err := next.ServeHTTP(w, r)
	switch {
	case err == nil:
		DefaultCovCounters.Inc(StageProxied)
	default:
		if _, _, ok := corazaInterruption(err); ok {
			DefaultCovCounters.Inc(StageWAFIntercept)
		}
	}
	return err
}

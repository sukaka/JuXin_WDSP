package detectors

import (
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"

	dsctx "github.com/jiuzhang-waf/gateway/dynamic_security/context"
	"github.com/jiuzhang-waf/gateway/dynamic_security/normalizer"
	"github.com/jiuzhang-waf/gateway/dynamic_security/parser"
)

// 阶段8 任务书 §36 API 维度限流可行子集：小时/日配额（定窗累计+跨窗重置）、
// 对象维度限速（复用任务书 §7 object_identifiers 提取口径，路径位置参数 + 请求体
// 主键字段的值哈希入键）、批量/分页大小上限信号。OBSERVE/PROTECT 语义与
// CheckAPIWriteRate 一致：
// RATE_LIMIT 类只 AddMatch 不定案，PROTECT 由决策引擎映射 429，OBSERVE 只记录。
//
// 配置面说明：发布通道已下发配额/对象/批量/分页五键（system_settings gateway_runtime 组
// api_quota_per_hour/api_quota_per_day/object_rate_per_minute/max_page_size/max_batch_size，
// 迁移 000152 种子）；语义「配置未到 = 不启用」不变（pipeline.Config 对应字段 >0 才调用
// 本文件检测器，不走默认值冒充已配置）；检测器保留 ≤0 走默认值约定供直接调用方使用。
// GraphQL 深度/复杂度、租户/设备等维度超出现有配置面与解析产物，未硬造（缺口见任务交接报告）。
//
// 计数有界：各追踪器均 LRU 定容（10000 键）；配额为定窗（自然小时/UTC 自然日），
// 跨窗即重置不保留历史样本。存储注入（Valkey）未覆盖本文件追踪器——StoreOverrides
// 结构在 store.go，扩展该结构属另一工作面，进程内单节点限制同 windowTracker。

const (
	// DefaultAPIQuotaPerHour 身份+端点每小时配额默认值（≤0 时启用；对齐写限速 60/分钟折算）。
	DefaultAPIQuotaPerHour = 3600
	// DefaultAPIQuotaPerDay 身份+端点每日配额默认值（≤0 时启用）。
	DefaultAPIQuotaPerDay = 50000
	// DefaultObjectRatePerMinute 同身份对同对象每分钟上限默认值（≤0 时启用）。
	DefaultObjectRatePerMinute = 120
	// DefaultMaxPageSize 分页大小上限默认值（≤0 时启用）。
	DefaultMaxPageSize = 200
	// DefaultMaxBatchSize 批量数量上限默认值（≤0 时启用）。
	DefaultMaxBatchSize = 100

	quotaMaxKeys      = 10000
	objectRateMaxKeys = 10000
)

// fixedWindowEntry 单键定窗状态：窗口起点 + 计数。
type fixedWindowEntry struct {
	windowStart time.Time
	count       int
}

// fixedWindowTracker 定窗计数器（配额用）：窗口对齐到 window 的自然边界
// （time.Truncate 语义，UTC；24h 即 UTC 自然日），跨窗即重置，不保留历史样本。
type fixedWindowTracker struct {
	mu      sync.Mutex
	window  time.Duration
	entries *lru // key → *fixedWindowEntry
	now     func() time.Time
}

func newFixedWindowTracker(window time.Duration, capacity int, now func() time.Time) *fixedWindowTracker {
	if now == nil {
		now = time.Now
	}
	return &fixedWindowTracker{window: window, entries: newLRU(capacity), now: now}
}

// add 记录一次命中，返回当前窗口计数；跨窗重置为 1。
func (t *fixedWindowTracker) add(key string) int {
	t.mu.Lock()
	defer t.mu.Unlock()
	cur := t.now().UTC().Truncate(t.window)
	var e *fixedWindowEntry
	if v, ok := t.entries.get(key); ok {
		e = v.(*fixedWindowEntry)
	} else {
		e = &fixedWindowEntry{windowStart: cur}
		t.entries.set(key, e)
	}
	if !e.windowStart.Equal(cur) {
		e.windowStart = cur
		e.count = 0
	}
	e.count++
	return e.count
}

// 包级默认追踪器（单节点限制同 windowTracker；配置重载不重置，进程重启清零）。
var (
	defaultHourlyQuotaTracker = newFixedWindowTracker(time.Hour, quotaMaxKeys, nil)
	defaultDailyQuotaTracker  = newFixedWindowTracker(24*time.Hour, quotaMaxKeys, nil)
	defaultObjectRateTracker  = newWindowTracker(objectRateMaxKeys, nil)
)

// CheckAPIHourlyQuota 身份+端点小时配额：定窗累计超 limit → API_HOURLY_QUOTA
// （RATE_LIMIT 类；只 AddMatch，不定案）。limit ≤ 0 用 DefaultAPIQuotaPerHour。
// 适用流量范围（全部 API / 仅写方法）由调用方装配决定，与 CheckAPIWriteRate 同约定。
func CheckAPIHourlyQuota(ctx *dsctx.RequestContext, identity, endpointKey string, limit int) {
	if ctx == nil || identity == "" || endpointKey == "" {
		return
	}
	if limit <= 0 {
		limit = DefaultAPIQuotaPerHour
	}
	count := defaultHourlyQuotaTracker.add(identity + "|" + endpointKey)
	if count <= limit {
		return
	}
	ctx.AddMatch(dsctx.DetectorMatch{
		Detector: "api_ratelimit",
		RuleID:   "ratelimit.api_hourly_quota",
		Category: "RATE_LIMIT",
		Severity: "HIGH",
		Message:  "api hourly quota exceeded",
		Evidence: map[string]string{
			"window_count": strconv.Itoa(count),
			"limit":        strconv.Itoa(limit),
			"window":       "1h",
		},
		ScoreDelta: 30,
	})
}

// CheckAPIDailyQuota 身份+端点日配额（UTC 自然日定窗）：超 limit → API_DAILY_QUOTA
// （RATE_LIMIT 类；只 AddMatch，不定案）。limit ≤ 0 用 DefaultAPIQuotaPerDay。
func CheckAPIDailyQuota(ctx *dsctx.RequestContext, identity, endpointKey string, limit int) {
	if ctx == nil || identity == "" || endpointKey == "" {
		return
	}
	if limit <= 0 {
		limit = DefaultAPIQuotaPerDay
	}
	count := defaultDailyQuotaTracker.add(identity + "|" + endpointKey)
	if count <= limit {
		return
	}
	ctx.AddMatch(dsctx.DetectorMatch{
		Detector: "api_ratelimit",
		RuleID:   "ratelimit.api_daily_quota",
		Category: "RATE_LIMIT",
		Severity: "HIGH",
		Message:  "api daily quota exceeded",
		Evidence: map[string]string{
			"window_count": strconv.Itoa(count),
			"limit":        strconv.Itoa(limit),
			"window":       "1d",
		},
		ScoreDelta: 30,
	})
}

// CheckObjectRate 对象维度限速：同一身份对同一对象标识 1 分钟滑窗计数超 limit →
// OBJECT_RATE（RATE_LIMIT 类）。对象标识优先消费 ctx 已落的 object_identifiers
// （任务书 §7 统一提取产物，pipeline 在检测段前写入，避免重复 HMAC 提取）；ctx 未落
// 时按入参解析产物现场提取（parser.ExtractObjectIdentifiers：归一化路径位置参数 +
// 请求体主键字段，两口径同源同盐）。ValueHash 直接入计数键，原始值不进本函数、
// 永不入证据；证据仅含结构维度（来源/占位符名/字段路径）。limit ≤ 0 用
// DefaultObjectRatePerMinute（pipeline 装配语义为 >0 才调用，见 pipeline.Config）。
func CheckObjectRate(ctx *dsctx.RequestContext, p *parser.Parsed, identity, endpointKey, salt string, limit int) {
	if ctx == nil || p == nil || identity == "" {
		return
	}
	if limit <= 0 {
		limit = DefaultObjectRatePerMinute
	}
	ids := ctx.CopyObjectIdentifiers()
	if len(ids) == 0 {
		ids = parser.ExtractObjectIdentifiers(p, salt)
	}
	if len(ids) == 0 {
		return
	}
	ek := endpointKey
	if ek == "" {
		ek = normalizer.EndpointKey(p.Method, p.RawPath)
	}
	for _, id := range ids {
		key := identity + "|" + ek + "|" + id.Source + ":" + id.Param + "|" + id.ValueHash
		count, _ := defaultObjectRateTracker.add(key)
		if count <= limit {
			continue
		}
		ctx.AddMatch(dsctx.DetectorMatch{
			Detector: "api_ratelimit",
			RuleID:   "ratelimit.object_rate",
			Category: "RATE_LIMIT",
			Severity: "HIGH",
			Message:  "per-object access rate exceeded",
			Evidence: map[string]string{
				"window_count": strconv.Itoa(count),
				"limit":        strconv.Itoa(limit),
				"window":       "1m",
				"source":       id.Source,
				"param":        id.Param,
			},
			ScoreDelta: 30,
		})
	}
}

// pageSizeParamNames 分页大小参数词表（与 parser.Query 键精确匹配，大小写敏感）。
var pageSizeParamNames = []string{
	"limit", "page_size", "pagesize", "per_page", "perpage",
	"size", "max_results", "maxresults", "top",
}

// CheckPaginationSize 分页大小上限信号：Query 分页参数（词表见 pageSizeParamNames）
// 解析为正整数且超 maxPageSize → PAGE_SIZE_EXCEEDED（RATE_LIMIT 类，MEDIUM）。
// 非数字值不判（形态问题由解析/约束层负责）；maxPageSize ≤ 0 用 DefaultMaxPageSize。
func CheckPaginationSize(ctx *dsctx.RequestContext, p *parser.Parsed, maxPageSize int) {
	if ctx == nil || p == nil || len(p.Query) == 0 {
		return
	}
	if maxPageSize <= 0 {
		maxPageSize = DefaultMaxPageSize
	}
	for _, name := range pageSizeParamNames {
		val, ok := p.Query[name]
		if !ok {
			continue
		}
		n, err := strconv.Atoi(strings.TrimSpace(val))
		if err != nil || n <= maxPageSize {
			continue
		}
		ctx.AddMatch(dsctx.DetectorMatch{
			Detector: "api_ratelimit",
			RuleID:   "ratelimit.page_size_exceeded",
			Category: "RATE_LIMIT",
			Severity: "MEDIUM",
			Message:  "pagination size exceeded",
			Evidence: map[string]string{
				"param": name,
				"value": strconv.Itoa(n),
				"limit": strconv.Itoa(maxPageSize),
			},
			ScoreDelta: 15,
		})
	}
}

// CheckBatchSize 批量数量上限信号：Query 参数值为逗号分隔列表（如 ids=1,2,3,...）
// 且元素数超 maxBatch → BATCH_SIZE_EXCEEDED（RATE_LIMIT 类）。maxBatch ≤ 0 用
// DefaultMaxBatchSize。元素数经 strings.Count 精确统计，参数值长度受解析层配额约束。
// BODY 侧批量（顶层 JSON 数组长度）不在本子集：parser walkJSON 只走首元素不留存
// 数组长度，无法阈值化，属解析产物缺口（见任务交接报告）。
func CheckBatchSize(ctx *dsctx.RequestContext, p *parser.Parsed, maxBatch int) {
	if ctx == nil || p == nil || len(p.Query) == 0 {
		return
	}
	if maxBatch <= 0 {
		maxBatch = DefaultMaxBatchSize
	}
	names := make([]string, 0, len(p.Query))
	for name := range p.Query {
		names = append(names, name)
	}
	// 确定性遍历序（map 迭代序随机）
	sort.Strings(names)
	for _, name := range names {
		val := p.Query[name]
		if !strings.Contains(val, ",") {
			continue
		}
		items := strings.Count(val, ",") + 1
		if items <= maxBatch {
			continue
		}
		ctx.AddMatch(dsctx.DetectorMatch{
			Detector: "api_ratelimit",
			RuleID:   "ratelimit.batch_size_exceeded",
			Category: "RATE_LIMIT",
			Severity: "HIGH",
			Message:  "batch size exceeded",
			Evidence: map[string]string{
				"param": name,
				"items": strconv.Itoa(items),
				"limit": strconv.Itoa(maxBatch),
			},
			ScoreDelta: 30,
		})
	}
}

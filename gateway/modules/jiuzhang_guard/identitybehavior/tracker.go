package identitybehavior

import (
	"net/url"
	"regexp"
	"sort"
	"strings"
	"time"
)

// Window 统计窗口（1m/5m/30m/24h，数组维度即 NumWindows）。
type Window int

const (
	Window1m Window = iota
	Window5m
	Window30m
	Window24h
	NumWindows // 窗口数（Snapshot.Windows 数组维度）
)

var windowDurations = [NumWindows]time.Duration{
	time.Minute, 5 * time.Minute, 30 * time.Minute, 24 * time.Hour,
}

var windowNames = [NumWindows]string{"1m", "5m", "30m", "24h"}

// Name 窗口名（事件 JSON 键 / 信号 window 字段）。
func (w Window) Name() string { return windowNames[w] }

// Duration 窗口时长（桶对齐与估值权重用）。
func (w Window) Duration() time.Duration { return windowDurations[w] }

// WindowCounts 单窗口计数快照。
// 计数为双桶轮转估值（current + previous×(1-elapsed/window)，浮点）；
// UniqueURICount 为 HLL（Valkey）/精确集合（内存）整数估计；
// AttackHitCount 为 WAF 攻击命中预留位，本阶段恒 0（不写入事件 JSON）。
// 例外：Snapshot.CompletedWindow 各字段为上一桶原始整数计数（非加权估值）。
type WindowCounts struct {
	WindowStart            time.Time // 当前桶起点（窗口对齐）
	RequestCount           float64
	UniqueURICount         int64
	NewURICount            float64
	Status401Count         float64
	Status403Count         float64
	Status404Count         float64
	Status405Count         float64
	Status500Count         float64
	AuthFailCount          float64 // 认证失败数（语义 = status_401_count；上游 401 视为认证失败）
	ParameterMutationCount float64 // 参数变异数（(identity,uri) 新参数签名出现次数）
	SensitivePathHits      float64
	AccountEnumCount       int64   // 当前窗口去重账号标识数（仅保存摘要）
	ObjectEnumCount        int64   // 当前窗口去重对象标识数（仅保存摘要）
	AttackHitCount         float64 // 预留恒 0
}

// Snapshot Observe 原子返回：各窗口计数快照 + 1m 完成桶回放 + (identity,uri) 维度即时结果。
type Snapshot struct {
	Windows [NumWindows]WindowCounts
	// CompletedWindow 1m 上一已完成桶的原始整数计数（桶起点 = 当前 1m 桶起点-1m；
	// 首桶或跨多桶空闲后无双桶数据，计数全 0）。供轮转触发快照回放完成桶：server 端按
	// (identity,window_type,window_start) UPSERT 覆盖语义天然去重。仅 1m——当前仅
	// 1m 轮转触发消费，其余窗口不回放。
	CompletedWindow    WindowCounts
	DistinctMethods    int   // 当前 (identity,uri) 30m 内 distinct method 数
	ParamSigNew        bool  // 当前 (identity,uri) 参数签名是否新（30m 内首次出现）
	IdentityConfidence uint8 // 本次身份解析置信度；用于枚举规则最低可信门槛
}

// ObserveInput 单次请求观测输入（URI 为路径、不含 query）。
type ObserveInput struct {
	IdentityKey    string
	Method         string
	URI            string
	Status         int    // 响应状态码（0 = 未采集到，仅计 request_count）
	ParamSignature string // 参数签名（空 = 本次无参数，不参与 HLL/变异计数）
	SensitivePath  bool   // 本次请求命中敏感路径前缀
	AccountKey     string // 账号标识摘要；空值不参与账号枚举统计
	ObjectKey      string // 对象标识摘要；空值不参与对象枚举统计
	At             time.Time
}

// Store 行为滑窗统计存储（Valkey / 进程内存实现；实现内 fail-open，Observe 不返回错误，
// error 返回值仅为防御性兜底）。
type Store interface {
	// Observe 原子记账并返回各窗口计数快照 + unique/new 计数 + (identity,uri)
	// distinct method 数与参数签名新旧。单 round-trip（Valkey）/ 单锁临界区（内存）。
	Observe(in ObserveInput) (*Snapshot, error)
	// Close 释放资源（内存实现为 no-op；Valkey 实现不关闭共享连接——连接归共享引擎所有）。
	Close() error
}

// ---------- 参数签名 ----------

// reUUID UUID 字面量（值类别判定）。
var reUUID = regexp.MustCompile(`^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}$`)

// 参数签名上界（防超大 query 撑爆内存与键空间）。
const (
	maxSigPairs = 64
	maxSigName  = 64
	maxSigLen   = 1024
)

// ParamSignature 参数签名：排序后「参数名=值类别」对（值类别：数字=n、空=empty、
// uuid=uuid、其余 s:<长度桶 1-8/9-64/65-256/257+>）。同参数多值逐值成对；无名值/空名
// 归一为 ""。签名不含参数原值（去敏），仅用于新旧判定。
func ParamSignature(query url.Values) string {
	if len(query) == 0 {
		return ""
	}
	pairs := make([]string, 0, len(query))
	for name, vals := range query {
		if len(name) > maxSigName {
			name = name[:maxSigName]
		}
		if len(vals) == 0 {
			pairs = append(pairs, name+"=empty")
			continue
		}
		for _, v := range vals {
			pairs = append(pairs, name+"="+valueClass(v))
		}
	}
	sort.Strings(pairs)
	if len(pairs) > maxSigPairs {
		pairs = pairs[:maxSigPairs]
	}
	sig := strings.Join(pairs, "&")
	if len(sig) > maxSigLen {
		sig = sig[:maxSigLen]
	}
	return sig
}

// valueClass 参数值类别（数字=n、空=empty、uuid=uuid、其余按长度桶）。
func valueClass(v string) string {
	if v == "" {
		return "empty"
	}
	if isDigits(v) {
		return "n"
	}
	if reUUID.MatchString(v) {
		return "uuid"
	}
	switch n := len(v); {
	case n <= 8:
		return "s:1-8"
	case n <= 64:
		return "s:9-64"
	case n <= 256:
		return "s:65-256"
	default:
		return "s:257+"
	}
}

func isDigits(v string) bool {
	for i := 0; i < len(v); i++ {
		if v[i] < '0' || v[i] > '9' {
			return false
		}
	}
	return len(v) > 0
}

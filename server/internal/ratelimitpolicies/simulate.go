package ratelimitpolicies

import (
	"math"
	"time"
)

// simInterval 模拟请求间隔（固定 10ms，保证结果可复现）。
const simInterval = 10 * time.Millisecond

// defaultSimIP 缺省模拟客户端IP（TEST-NET-3 文档保留地址，非真实地址）。
const defaultSimIP = "203.0.113.10"

// SimInput 是策略模拟输入。
type SimInput struct {
	Requests  int      // 模拟请求总数（1~10000）
	ClientIPs []string // 模拟客户端IP列表（最多10个，轮询使用；为空时用 defaultSimIP）
	URI       string   // 模拟请求URI（缺省 "/"）
}

// SimResult 是策略模拟结果。
type SimResult struct {
	Algorithm         string `json:"algorithm"`
	Dimension         string `json:"dimension"`
	DimensionNote     string `json:"dimension_note"`
	Requests          int    `json:"requests"`
	Allowed           int    `json:"allowed"`
	Rejected          int    `json:"rejected"`
	FirstRejectAt     int    `json:"first_reject_at"` // 第几个请求被首次拒绝（1起），0 表示无拒绝
	RetryAfterSeconds int    `json:"retry_after_seconds"`
}

// bucketState 令牌桶状态（模拟时间轴）。
type bucketState struct {
	tokens float64
	last   time.Duration
}

// windowState 双固定窗口状态（模拟时间轴）。
type windowState struct {
	currStart time.Duration
	curr      int64
	prev      int64
}

// Simulate 干跑模拟限速判定，不产生真实请求、不触达网关。
// 算法语义与网关 jiuzhang_guard/ratelimit 内存后端一致：
//   - TOKEN_BUCKET：容量 burst（0→limit），按 limit/window 匀速补充，初始满桶；
//   - SLIDING_WINDOW：当前窗口计数 + 上一窗口计数×(1-已过去比例)。
//
// 请求按 10ms 间隔注入，多个 client_ips 轮询使用。纯函数，可独立单测。
func Simulate(p *Policy, in SimInput) SimResult {
	res := SimResult{
		Algorithm:     p.Algorithm,
		Dimension:     p.Dimension,
		DimensionNote: dimensionNote(p.Dimension),
		Requests:      in.Requests,
	}
	if in.Requests <= 0 {
		return res
	}
	// 防御：非法阈值视为全部拒绝（写入侧已校验，此处仅为不静默放行）
	if p.RequestsLimit <= 0 || p.WindowSeconds <= 0 {
		res.Rejected = in.Requests
		res.FirstRejectAt = 1
		res.RetryAfterSeconds = 1
		return res
	}

	ips := in.ClientIPs
	if len(ips) == 0 {
		ips = []string{defaultSimIP}
	}
	uri := in.URI
	if uri == "" {
		uri = "/"
	}

	buckets := map[string]*bucketState{}
	windows := map[string]*windowState{}
	capacity := float64(p.EffectiveBurst())
	rate := float64(p.RequestsLimit) / float64(p.WindowSeconds) // 令牌/秒
	window := time.Duration(p.WindowSeconds) * time.Second

	for i := 0; i < in.Requests; i++ {
		t := time.Duration(i) * simInterval
		key := dimensionKey(p, ips[i%len(ips)], uri)

		var allowed bool
		var retry time.Duration
		switch p.Algorithm {
		case AlgorithmSlidingWindow:
			allowed, retry = allowSlidingWindow(windows, key, t, int64(p.RequestsLimit), window)
		default: // TOKEN_BUCKET
			allowed, retry = allowTokenBucket(buckets, key, t, capacity, rate)
		}

		if allowed {
			res.Allowed++
		} else {
			res.Rejected++
			if res.FirstRejectAt == 0 {
				res.FirstRejectAt = i + 1
				res.RetryAfterSeconds = int(math.Ceil(retry.Seconds()))
				if res.RetryAfterSeconds < 1 {
					res.RetryAfterSeconds = 1
				}
			}
		}
	}
	return res
}

// allowTokenBucket 令牌桶判定（与网关内存后端同语义）。
func allowTokenBucket(states map[string]*bucketState, key string, t time.Duration, capacity, rate float64) (bool, time.Duration) {
	b, ok := states[key]
	if !ok {
		b = &bucketState{tokens: capacity, last: t}
		states[key] = b
	}
	b.tokens += (t - b.last).Seconds() * rate
	if b.tokens > capacity {
		b.tokens = capacity
	}
	b.last = t
	if b.tokens >= 1 {
		b.tokens--
		return true, 0
	}
	return false, time.Duration((1-b.tokens)/rate*1000) * time.Millisecond
}

// allowSlidingWindow 双固定窗口加权判定（与网关内存后端同语义）。
func allowSlidingWindow(states map[string]*windowState, key string, t time.Duration, limit int64, window time.Duration) (bool, time.Duration) {
	w, ok := states[key]
	if !ok {
		w = &windowState{currStart: t}
		states[key] = w
	}
	elapsed := t - w.currStart
	if elapsed >= 2*window {
		w.prev, w.curr, w.currStart = 0, 0, t
		elapsed = 0
	} else if elapsed >= window {
		w.prev, w.curr = w.curr, 0
		w.currStart += window
		elapsed = t - w.currStart
	}
	weight := 1 - elapsed.Seconds()/window.Seconds()
	estimate := w.curr + int64(float64(w.prev)*weight)
	if estimate < limit {
		w.curr++
		return true, 0
	}
	return false, window - elapsed
}

// dimensionKey 构建统计维度键。
func dimensionKey(p *Policy, ip, uri string) string {
	app := "global"
	if p.ApplicationID != nil {
		app = p.ApplicationID.String()
	}
	switch p.Dimension {
	case DimensionApplication:
		return "app:" + app
	case DimensionClientIPAndURI:
		return "ip:" + ip + "|uri:" + uri
	case DimensionClientIPAndApplication:
		return "ip:" + ip + "|app:" + app
	default: // CLIENT_IP
		return "ip:" + ip
	}
}

// dimensionNote 返回维度键的人类可读说明。
func dimensionNote(dimension string) string {
	switch dimension {
	case DimensionApplication:
		return "按 APPLICATION 计数：同一应用的全部请求共享一个计数器"
	case DimensionClientIPAndURI:
		return "按 CLIENT_IP_AND_URI 计数：每个客户端 IP 与 URI 的组合独立计数"
	case DimensionClientIPAndApplication:
		return "按 CLIENT_IP_AND_APPLICATION 计数：每个客户端 IP 与应用的组合独立计数"
	default:
		return "按 CLIENT_IP 计数：每个客户端 IP 独立计数"
	}
}

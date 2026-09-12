// debug_cccounter.go 阶段5 §十七 发布后流量冒烟 CC 精确计数探针：网关调试回显端点。
//
// 保留命名空间 /_wdsp/debug/v1/（与 Bot 命名空间同一保留纪律）：
//   - 仅 debug_cc_counter=true 时本模块拦截该前缀（缺省 false = 零行为变化，
//     与 Bot 命名空间「首次 OFF 且保留已解除不抢占业务路径」同口径：未启用时
//     该前缀照常落入业务链路）；启用后前缀内全部请求本地处理，结构上绝不
//     反向代理（安全底线）；
//   - cc-counter 端点只允许本机/内网连接源（回环/RFC1918/ULA，按 TCP 连接对端
//     res.ConnectionIP 判定，XFF 等代理头不可伪造）；其余来源一律 404 墓碑，
//     不暴露端点存在性；
//   - 端点在 serveGuard 真实 IP 识别之后、CC 限速之前挂接（module.go 步骤 1.6）：
//     回显请求本身不进入 CC 计数（探针自污染防控），也不进入 JWT/身份观测步骤；
//   - 响应只含计数与窗口数字（found/count/limit/window_seconds），不回显
//     计数键材料与客户端 IP；
//   - GET 之外方法 405（Allow: GET）；未知子路径本地 404 墓碑
//     （Cache-Control: no-store，正文 "404 not found"，与 Bot 命名空间同形态）。
package jiuzhang_guard

import (
	"encoding/json"
	"net/http"
	"net/netip"
	"strings"
	"time"

	"github.com/jiuzhang-waf/gateway/modules/jiuzhang_guard/clientip"
	"github.com/jiuzhang-waf/gateway/modules/jiuzhang_guard/ratelimit"
)

const (
	// debugReservedNamespace 调试保留命名空间前缀。
	debugReservedNamespace = "/_wdsp/debug/v1/"
	// debugCCCounterPath CC 计数回显端点固定路径。
	debugCCCounterPath = "/_wdsp/debug/v1/cc-counter"
)

// debugConnIPAllowed 端点来源门禁：仅本机/内网连接源（回环 + RFC1918/ULA）。
// 判定用 TCP 连接对端（res.ConnectionIP），代理头声明不影响。
func debugConnIPAllowed(ip netip.Addr) bool {
	return ip.IsLoopback() || ip.IsPrivate()
}

// serveDebugNamespace 调试保留命名空间本地处理；全部结局只写本地响应，
// 永不调用 next（调用方已按开关与前缀门控）。
func (g *Guard) serveDebugNamespace(w http.ResponseWriter, r *http.Request, res clientip.Result) error {
	dispo := DispositionFrom(r.Context())
	w.Header().Set("Cache-Control", "no-store")

	writeTombstone := func(reason string) {
		dispo.RecordTerminal(ExecutorNone, DisActionNone, http.StatusNotFound, true, []string{reason}, nil)
		w.Header().Set("Content-Type", "text/plain; charset=utf-8")
		w.WriteHeader(http.StatusNotFound)
		_, _ = w.Write([]byte("404 not found"))
	}
	writeJSON := func(status int, reason string, v interface{}) {
		dispo.RecordTerminal(ExecutorNone, DisActionNone, status, true, []string{reason}, nil)
		w.Header().Set("Content-Type", "application/json; charset=utf-8")
		w.WriteHeader(status)
		body, err := json.Marshal(v)
		if err != nil {
			g.logger.Warn("debug cc-counter response marshal failed")
			return
		}
		_, _ = w.Write(body)
	}

	// 非本机/内网连接源：404 墓碑（不暴露端点存在性）
	if !debugConnIPAllowed(res.ConnectionIP) {
		writeTombstone("DEBUG_NAMESPACE_DENIED")
		return nil
	}
	if r.URL.Path != debugCCCounterPath {
		writeTombstone("DEBUG_UNKNOWN_SUBPATH")
		return nil
	}
	if r.Method != http.MethodGet {
		dispo.RecordTerminal(ExecutorNone, DisActionNone, http.StatusMethodNotAllowed, true, []string{"DEBUG_METHOD_NOT_ALLOWED"}, nil)
		w.Header().Set("Allow", http.MethodGet)
		w.Header().Set("Content-Type", "text/plain; charset=utf-8")
		w.WriteHeader(http.StatusMethodNotAllowed)
		_, _ = w.Write([]byte("405 method not allowed"))
		return nil
	}

	q := r.URL.Query()
	policyID := strings.TrimSpace(q.Get("policy_id"))
	if policyID == "" {
		writeJSON(http.StatusBadRequest, "DEBUG_MISSING_PARAM", map[string]string{"error": "MISSING_POLICY_ID"})
		return nil
	}
	var p *compiledPolicy
	for _, pol := range g.policies {
		if pol.cfg.ID == policyID {
			p = pol
			break
		}
	}
	if p == nil {
		writeJSON(http.StatusNotFound, "DEBUG_POLICY_NOT_FOUND", map[string]string{"error": "POLICY_NOT_FOUND"})
		return nil
	}
	// 维度含客户端 IP 时需显式传入探针来源 IP；APPLICATION 维度键与 IP 无关
	var ip netip.Addr
	if p.cfg.Dimension != "APPLICATION" {
		var err error
		ip, err = netip.ParseAddr(strings.TrimSpace(q.Get("ip")))
		if err != nil {
			writeJSON(http.StatusBadRequest, "DEBUG_INVALID_PARAM", map[string]string{"error": "INVALID_IP"})
			return nil
		}
	}
	if g.engine == nil || g.engine.limiter == nil {
		writeJSON(http.StatusServiceUnavailable, "DEBUG_ENGINE_UNAVAILABLE", map[string]string{"error": "ENGINE_UNAVAILABLE"})
		return nil
	}
	key := p.cfg.ID + ":" + p.dimensionKey(ip, g.AppID)
	count, found, err := g.engine.limiter.Peek(r.Context(), key,
		ratelimit.Algorithm(p.cfg.Algorithm), p.cfg.RequestsLimit,
		time.Duration(p.cfg.WindowSeconds)*time.Second, p.cfg.BurstCapacity)
	if err != nil {
		g.logger.Warn("debug cc-counter peek failed")
		writeJSON(http.StatusServiceUnavailable, "DEBUG_ENGINE_ERROR", map[string]string{"error": "ENGINE_UNAVAILABLE"})
		return nil
	}
	writeJSON(http.StatusOK, "DEBUG_CC_COUNTER", map[string]interface{}{
		"policy_id":      p.cfg.ID,
		"dimension":      p.cfg.Dimension,
		"algorithm":      p.cfg.Algorithm,
		"found":          found,
		"count":          count,
		"limit":          p.cfg.RequestsLimit,
		"window_seconds": p.cfg.WindowSeconds,
	})
	return nil
}

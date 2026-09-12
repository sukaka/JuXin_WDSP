// gate.go APM 运行期总开关门控（系统设置界面热生效，无需重启）。
//
// 关闭时统一 503 JSON 降级，响应报文与原 APM_ENABLED=false 启动期 stub 完全一致
// （WAF 核心防护不受影响）。管理面路由由装配层经 gatedAuthz 把 gate 挂在 authz 链内，
// 保持原 stub 的认证/CSRF 前置行为（匿名 POST 先被 CSRF 拦 403 而非直接 503）；
// Agent 机器端点由 MachineGate 按开关在"无会话直通"与"authz + 503 stub"间切换。
package apm

import (
	"net/http"

	"github.com/jiuzhang-waf/server/internal/response"
)

// gateDisabledMessage APM 关闭降级文案（与原启动期 stub 完全一致，不得改动报文）。
const gateDisabledMessage = "APM 业务性能监控已关闭（APM_ENABLED=false），WAF 核心防护不受影响"

// writeGateDisabled 写出 APM 关闭统一 503 降级响应。
func writeGateDisabled(w http.ResponseWriter, r *http.Request) {
	response.Error(w, r, http.StatusServiceUnavailable, response.CodeServiceUnavailable, gateDisabledMessage)
}

// NewGate 管理面开关门控：开启时透传 next，关闭时 503 降级。
func NewGate(rc *RuntimeConfig, next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if rc.Enabled(r.Context()) {
			next.ServeHTTP(w, r)
			return
		}
		writeGateDisabled(w, r)
	})
}

// NewMachineGate Agent 机器端点开关切换：开启时直通 next（无会话/CSRF 面，
// 令牌/PoP 自认证）；关闭时走 authz + 503 stub（与原 APM_ENABLED=false 形态一致）。
func NewMachineGate(rc *RuntimeConfig, next http.Handler, authz func(http.Handler) http.Handler) http.Handler {
	disabled := authz(http.HandlerFunc(writeGateDisabled))
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if rc.Enabled(r.Context()) {
			next.ServeHTTP(w, r)
			return
		}
		disabled.ServeHTTP(w, r)
	})
}

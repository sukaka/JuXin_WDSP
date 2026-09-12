// Coraza 合流（WDSP / 阶段8，P0-08）：不 fork coraza-caddy 前提下的最诚实归因方案。
//
// 调查结论（coraza-caddy v2.5.0 源码，xcaddy 构建期经 Dockerfile CORAZA_CADDY_VERSION 锁定）：
//   - coraza-caddy 不导出任何阻断回调/指令 hook：唯一中断信号是未导出哨兵错误
//     errInterruptionTriggered（"interruption triggered"），包装为 caddyhttp.HandlerError
//     {StatusCode: 中断码（deny 缺省 403）, ID: Coraza 事务 ID} 沿中间件链返回；
//   - 请求相位（phase 1/2）阻断：Coraza 自身不写响应，仅返回上述错误（下游捕获 writer 状态码为 0）；
//   - 响应体相位（phase 4）阻断：错误照常返回，且中断状态码已先行写入下游 writer（头已清空）；
//   - 响应头相位（phase 3）阻断：仅写"清空头 + 中断状态码 + 空体"，返回 nil 错误——
//     与源站自返 403 无法可靠区分，为避免误归因不做识别（见下方局限）；
//   - replacer 变量 http.transaction_id 每请求都设置，只是关联线索而非阻断信号；
//     WithErrorCallback 为规则命中日志回调，模块外部不可注入。
//
// 方案：统一管线判定非阻断的流量在响应捕获路径检查下游返回错误——错误链命中
// "interruption triggered" 即归因 Coraza 阻断：补记 detector="waf" 的 BLOCK 类 Finding
// （证据注明 attribution=downstream_intercept 与不确定性来源），事件 final_action 按实记 BLOCK
// （阻断已在下游真实发生，此处是事实记录而非引擎决策），response_status 取中断码。
// 中断码口径修正：coraza-caddy 仅 deny 动作携带真实中断码（缺省 403）；drop 等其他中断
// 动作回退默认码（请求相位 200、响应相位上游状态码），非真实拒绝码——统一按 403 记录，
// 原始值留证据 coraza_raw_status（drop 的连接语义是直接断开，记 200 会把 BLOCK 误标为成功响应）。
//
// 局限（如实声明）：
//   - 归因依赖未导出哨兵消息串，与 coraza-caddy v2.5.0 耦合；升级 CORAZA_CADDY_VERSION 必须复核；
//   - 无法取得命中规则明细（规则 ID/分值仍在 Coraza 审计日志，经 request_id 事后关联不变）；
//   - 非 deny 中断动作（drop 等）的真实中断码不可得（错误链只带 coraza-caddy 回退默认码），按 403 口径记录；
//   - phase 3（响应头相位）中断不归因：无错误返回，特征与源站 403 不可区分；
//   - 非 API 流量事件维持响应前输出（G1 语义），事后 Coraza 阻断不回填该事件。
package jiuzhang_guard

import (
	"errors"
	"net/http"
	"strconv"

	"github.com/caddyserver/caddy/v2/modules/caddyhttp"
	dsctx "github.com/jiuzhang-waf/gateway/dynamic_security/context"
)

// corazaInterruptionMessage coraza-caddy v2.5.0 未导出哨兵错误 errInterruptionTriggered 的消息串
// （coraza.go / interceptor.go 两处中断返回点的唯一可识别特征；升级 coraza-caddy 必须复核）。
const corazaInterruptionMessage = "interruption triggered"

// corazaInterruption 从下游返回错误识别 Coraza 阻断中断。
// 命中返回 Coraza 事务 ID 与中断状态码；其他错误（反代 502、guard 自身错误等）一律不命中。
func corazaInterruption(err error) (txID string, status int, ok bool) {
	if err == nil {
		return "", 0, false
	}
	var he caddyhttp.HandlerError
	if !errors.As(err, &he) {
		return "", 0, false
	}
	if he.Err == nil || he.Err.Error() != corazaInterruptionMessage {
		return "", 0, false
	}
	return he.ID, he.StatusCode, true
}

// attributeWAFIntercept Coraza 合流归因：统一管线未判阻断（非 BLOCK/RATE_LIMIT/TEMP_BLOCK），
// 但下游 coraza-caddy 返回中断错误 → 补记 waf 明细并按实记录 final_action=BLOCK。
// 返回是否发生归因。guard 自身阻断（handled 提前返回）不会到达本路径，双重检查仅防未来重构误接。
func attributeWAFIntercept(resCtx *dsctx.RequestContext, finalAction dsctx.FinalAction, err error) (dsctx.FinalAction, int, bool) {
	txID, status, ok := corazaInterruption(err)
	if !ok {
		return finalAction, 0, false
	}
	switch finalAction {
	case dsctx.ActionBlock, dsctx.ActionRateLimit, dsctx.ActionTempBlock:
		// 统一引擎已判阻断（理论上不会走到下游）：不重复归因
		return finalAction, 0, false
	}
	if resCtx == nil {
		return finalAction, 0, false
	}
	// 中断码口径修正（coraza-caddy v2.5.0 obtainStatusCodeFromInterruptionOrDefault）：
	// 仅 deny 动作携带真实中断码（缺省 403）；drop 等其他中断动作回退默认码——
	// 请求相位为 200、响应相位为上游状态码——均非真实拒绝码（drop 的连接语义是直接断开，
	// 记 200 会把 BLOCK 事件误标为成功响应）。非 4xx/5xx 一律按 403 记录，原始值留证据。
	rawStatus := status
	if status < 400 || status > 599 {
		status = http.StatusForbidden
	}
	evidence := map[string]string{
		"attribution":  "downstream_intercept",
		"uncertainty":  "message_matched_no_rule_detail",
		"coraza_tx_id": txID,
		"status_code":  strconv.Itoa(status),
	}
	if rawStatus != status {
		evidence["coraza_raw_status"] = strconv.Itoa(rawStatus)
	}
	resCtx.AddMatch(dsctx.DetectorMatch{
		Detector:   "waf",
		RuleID:     "waf.downstream_intercept",
		Category:   "BLOCK",
		Severity:   "HIGH",
		Confidence: 0.9, // 消息特征归因（无规则明细），高于 waf 默认 0.8 但不为 1
		Message:    "request blocked by downstream WAF (coraza interruption)",
		Evidence:   evidence,
		ScoreDelta: 50,
	})
	// 阻断已在下游真实执行：按实记录 BLOCK（事实记录，非引擎决策路径；OBSERVE 模式同样按实记录）
	resCtx.SetFinalAction(dsctx.ActionBlock)
	return dsctx.ActionBlock, status, true
}

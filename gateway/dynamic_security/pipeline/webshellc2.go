// webshellc2.go 加密 WebShell C&C 会话行为检测的管线挂点（BAS 覆盖基线：冰蝎/哥斯拉/蚁剑
// AES 加密通信重放缺口；检测器本体与统计口径见 detectors/webshellc2.go 头部注释）。
//
// 双入口接线纪律：
//   - 请求相位入口 ObserveWebShellC2Request 必须由挂点侧在读体处调用（parser 之后 r.Body
//     已消费，体统计样本仅读体处可得；样本仅请求内存活，不落证据、不入事件）；
//   - 响应收束入口由 ProcessResponse 统一调用（checkWebShellC2Response），评估产出的
//     webshell.c2_suspected 恒为 OBSERVE（ScoreDelta 20 < 50 定案线），绝不参与定案阻断；
//   - 两侧均不挂 api.IsAPI 分类门槛——WebShell 端点通常非 API 分类，分类漏判不应关掉观测
//     （响应相位本身仅 API 流量到达：非 API 路径无响应捕获，属挂点侧既有结构约束）；
//   - 挂点侧未供给原请求/身份时零行为；样本门槛（≥5）由检测器自身把关，无会话形态零开销。
package pipeline

import (
	"net/http"

	dsctx "github.com/jiuzhang-waf/gateway/dynamic_security/context"
	"github.com/jiuzhang-waf/gateway/dynamic_security/detectors"
	"github.com/jiuzhang-waf/gateway/dynamic_security/normalizer"
)

// ObserveWebShellC2Request 请求相位 webshell C2 会话观测（挂点侧在读体处调用）：
// 身份（TrackingKey：凭据指纹优先、无凭据回退 IP）与端点键（与 Process 内部同一
// 归一化算法）由本函数统一取值，挂点侧只需供给体样本（nil = 本请求无体统计，
// 仍参与长度/头画像累计）。只记账，绝不产检测明细。
func ObserveWebShellC2Request(r *http.Request, identitySalt string, bodySample []byte) {
	ObserveWebShellC2RequestWithStores(r, identitySalt, bodySample, nil)
}

// ObserveWebShellC2RequestWithStores 将当前 Guard 的存储选择显式传入请求相位会话记账。
func ObserveWebShellC2RequestWithStores(r *http.Request, identitySalt string, bodySample []byte, stores *detectors.StoreOverrides) {
	if r == nil || r.Method != http.MethodPost {
		return // 非 POST 不参与（与检测器内部同一门槛；提前返回省去身份指纹计算）
	}
	detectors.ObserveWebShellC2RequestWithStores(r, detectors.TrackingKey(r, identitySalt), webShellC2SessionURI(r), bodySample, stores)
}

// webShellC2SessionURI 会话维度 URI：与 Process 端点键同源的归一化路径
// （请求/响应两侧同一取值口径，会话统计才能对齐——不得改用 gRPC 的全保留端点键）。
func webShellC2SessionURI(r *http.Request) string {
	return normalizer.EndpointKey(r.Method, r.URL.Path)
}

// checkWebShellC2Response 响应收束评估（ProcessResponse 挂点）：请求相位已记账的会话
// 在此累计响应侧统计并评估四组弱特征（≥3 组命中产 webshell.c2_suspected OBSERVE/MEDIUM，
// 绝不单独定案）。cfg.Request/cfg.Identity 缺失时零行为；样本取自响应捕获体
// （截断前缀同样可用于统计；流式无缓冲为 nil，仅长度参与累计）。
func checkWebShellC2Response(ctx *dsctx.RequestContext, in ResponseInput, cfg ResponseConfig) {
	if cfg.Request == nil || cfg.Identity == "" || cfg.Request.Method != http.MethodPost {
		return
	}
	detectors.CheckWebShellC2Response(ctx, cfg.Request, cfg.Identity, webShellC2SessionURI(cfg.Request), in.Body, in.BodySize)
}

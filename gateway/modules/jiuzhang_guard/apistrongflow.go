// apistrongflow.go 强流程响应回程挂点（NG-FLOW-03）：响应记录器（包装
// ResponseWriter 先例——apiresponse/identitybehavior 同款）+ 收口调用。
//
// 读取纪律：
//   - 仅对命中强流程绑定且请求相位已成功预留（flowguard.Reservation 存在）的
//     请求包装记录器；无预留零包装零行为（NG-T-C01）；
//   - 体样本仅当步骤配置了 body 判定式（JSONPath 等值/GraphQL errors）才采集，
//     有界 ≤64KB——超限置 truncated 直通外发（判定按不命中 UNKNOWN 如实处理）；
//   - 记录器只读不改：状态行/头/体逐字节透传，fail-open 不影响响应本身；
//   - 采样的是源站原始字节（挂点在脱敏/水印/签名改写之前）——业务成功判定
//     面向源站事实，不面向交付产物。
package jiuzhang_guard

import (
	"bufio"
	"bytes"
	"fmt"
	"net"
	"net/http"
	"time"

	dsctx "github.com/jiuzhang-waf/gateway/dynamic_security/context"
	"github.com/jiuzhang-waf/gateway/dynamic_security/detectors/flowguard"
)

// maxStrongFlowBodySample 强流程响应体采样上限（64KB 冻结读取纪律）。
const maxStrongFlowBodySample = 64 << 10

// strongFlowResponseRecorder 强流程响应记录器（透传 + 状态码采集 + 有界体采样；
// 并发模型与请求处理一致：单请求单 goroutine 顺序写）。
type strongFlowResponseRecorder struct {
	base        http.ResponseWriter
	captureBody bool // 步骤配置了 body 判定式才为 true（status-codes-only 零体开销）

	status    int
	body      bytes.Buffer
	truncated bool // 体超 64KB 上限（直通外发不截断，判定按超限 UNKNOWN 处理）
	hijacked  bool
}

// wrapStrongFlowResponse 命中成功预留时包装记录器；无预留/无运行时返回原 writer
// （零行为 NG-T-C01）。返回（使用的 writer, 记录器或 nil）。
func (g *Guard) wrapStrongFlowResponse(w http.ResponseWriter, rc *dsctx.RequestContext) (http.ResponseWriter, *strongFlowResponseRecorder) {
	if g.strongFlowRuntime == nil || rc == nil {
		return w, nil
	}
	res := flowguard.ReservationFromContext(rc)
	if res == nil {
		return w, nil
	}
	captureBody := res.SuccessRule != nil &&
		(res.SuccessRule.BodyJSONPathEquals != nil || res.SuccessRule.GraphQLErrorsEmpty)
	rec := &strongFlowResponseRecorder{base: w, captureBody: captureBody}
	return rec, rec
}

// finalizeStrongFlow 响应回程收口（下游返回后调用，先于事件输出——动作条目
// 随主事件 strong_flow 数组一并落盘）。无记录器 = 未包装 = 零行为。
func (g *Guard) finalizeStrongFlow(rc *dsctx.RequestContext, rec *strongFlowResponseRecorder, downstreamErr bool) {
	if rec == nil || g.strongFlowRuntime == nil || rc == nil {
		return
	}
	status := rec.status
	if status == 0 && !downstreamErr {
		status = http.StatusOK // 与 net/http 一致：Write 隐式 200
	}
	facts := flowguard.ResponseFacts{
		Status:        status,
		BodyTruncated: rec.truncated,
		DownstreamErr: downstreamErr || rec.hijacked,
	}
	if rec.captureBody && !rec.truncated {
		facts.Body = rec.body.Bytes()
	}
	g.strongFlowRuntime.FinalizeResponse(rc, facts, time.Now().UTC())
}

// Header 透传底层头表。
func (r *strongFlowResponseRecorder) Header() http.Header { return r.base.Header() }

// WriteHeader 采集状态码并透传（1xx  provisional 逐条透传不采集，与
// apiResponseCapture 同一口径；重复 WriteHeader 忽略）。
func (r *strongFlowResponseRecorder) WriteHeader(code int) {
	if code >= 100 && code < 200 && code != http.StatusSwitchingProtocols {
		if r.status == 0 {
			r.base.WriteHeader(code)
		}
		return
	}
	if r.status != 0 {
		return
	}
	r.status = code
	r.base.WriteHeader(code)
}

// Write 透传全部字节；仅 captureBody 时在上限内采样（超限置 truncated 后
// 纯透传——原响应一字节不少，判定按超限 UNKNOWN 如实处理）。
func (r *strongFlowResponseRecorder) Write(p []byte) (int, error) {
	if r.status == 0 {
		r.WriteHeader(http.StatusOK)
	}
	if r.captureBody && !r.truncated {
		remain := maxStrongFlowBodySample - r.body.Len()
		if len(p) <= remain {
			r.body.Write(p)
		} else {
			if remain > 0 {
				r.body.Write(p[:remain])
			}
			r.truncated = true
		}
	}
	return r.base.Write(p)
}

// Flush 透传底层 Flusher。
func (r *strongFlowResponseRecorder) Flush() {
	if r.status == 0 {
		r.WriteHeader(http.StatusOK)
	}
	if f, ok := r.base.(http.Flusher); ok {
		f.Flush()
	}
}

// Unwrap 返回底层 writer（http.ResponseController 依赖）。
func (r *strongFlowResponseRecorder) Unwrap() http.ResponseWriter { return r.base }

// Hijack 透传连接劫持（升级后响应脱离记录——收口按 downstreamErr 处理，
// 网关未获得源站执行证据，F04 UNKNOWN 如实）。
func (r *strongFlowResponseRecorder) Hijack() (net.Conn, *bufio.ReadWriter, error) {
	r.hijacked = true
	h, ok := r.base.(http.Hijacker)
	if !ok {
		return nil, nil, fmt.Errorf("underlying writer does not support hijacking")
	}
	return h.Hijack()
}

// pipeline_webshellc2_test.go 加密 WebShell C&C 会话行为检测管线挂点贯通（BAS 覆盖基线）：
// 请求相位入口（ObserveWebShellC2Request，挂点侧读体处供给样本）只记账不产明细；
// 响应收束入口（ProcessResponse → checkWebShellC2Response）累计响应侧统计并评估——
// 四组弱特征 ≥3 命中产 webshell.c2_suspected（OBSERVE，绝不单独定案阻断）；
// 弱特征不足（常规轮询画像）与挂点侧未供给原请求/身份（未接线）时零产出。
package pipeline

import (
	"encoding/base64"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	dsctx "github.com/jiuzhang-waf/gateway/dynamic_security/context"
	"github.com/jiuzhang-waf/gateway/dynamic_security/detectors"
)

// c2PipeBlob 确定性高熵 base64 串（模拟 AES 密文的 base64 形态；n 取 256 倍数时字节
// 分布均匀、熵约 6.0 bits/byte；仅测试数据生成，非安全用途）。
func c2PipeBlob(n int) string {
	buf := make([]byte, n)
	for i := range buf {
		buf[i] = byte(i)
	}
	return base64.StdEncoding.EncodeToString(buf)
}

// c2PipePost 构造带固定 UA 的 POST 请求（httptest 自动设置 ContentLength 与 RemoteAddr）。
func c2PipePost(t *testing.T, uri, body string) *http.Request {
	t.Helper()
	r := httptest.NewRequest(http.MethodPost, "http://h"+uri, strings.NewReader(body))
	r.Header.Set("User-Agent", "Mozilla/5.0 (Windows NT 10.0; Win64; x64)")
	return r
}

// c2PipeRound 驱动一次「请求相位观测 + 响应收束评估」会话往返（两入口均经管线挂点面）。
func c2PipeRound(t *testing.T, uri, reqBody string, resp []byte, wireIdentity bool) (*dsctx.RequestContext, dsctx.FinalAction) {
	t.Helper()
	r := c2PipePost(t, uri, reqBody)
	// 请求相位入口（挂点侧读体处供给样本；空盐 = 未加盐口径）：只记账
	ObserveWebShellC2Request(r, "", []byte(reqBody))
	cfg := ResponseConfig{Mode: "PROTECT"}
	if wireIdentity {
		cfg.Request = r
		cfg.Identity = detectors.TrackingKey(r, "")
	}
	ctx := dsctx.New("pipe-c2", dsctx.DefaultParseLimits())
	act, err := ProcessResponse(ctx, ResponseInput{
		Status: 200, ContentType: "text/plain", Body: resp, BodySize: int64(len(resp)),
	}, cfg)
	if err != nil {
		t.Fatal(err)
	}
	return ctx, act
}

// 产出路径：四组弱特征全满足的会话经两入口驱动，第 5 个样本起产 webshell.c2_suspected；
// PROTECT 模式下也只落到 OBSERVE（绝不单独定案阻断）。
func TestPipelineWebShellC2SuspectedSessionFires(t *testing.T) {
	const uri = "/upload/c2pipe_shell.jsp"
	body := c2PipeBlob(512)         // 定长、高熵、全 base64 字符集
	resp := []byte(c2PipeBlob(256)) // 定长、高熵、无 HTML 标签
	var last *dsctx.RequestContext
	for i := 1; i <= 6; i++ {
		ctx, act := c2PipeRound(t, uri, body, resp, true)
		if act == dsctx.ActionBlock {
			t.Fatalf("webshell c2 signal must never block: %s", act)
		}
		if i < 5 && hasRule(&Result{Context: ctx}, "webshell.c2_suspected") {
			t.Fatalf("round %d below min samples must not fire: %+v", i, ctx.CopyMatches())
		}
		last = ctx
	}
	if !hasRule(&Result{Context: last}, "webshell.c2_suspected") {
		t.Fatalf("full c2 profile must fire, got %+v", last.CopyMatches())
	}
	for _, m := range last.CopyMatches() {
		if m.RuleID != "webshell.c2_suspected" {
			continue
		}
		if m.Detector != "webshell" || m.Category != "OBSERVE" || m.ScoreDelta != 20 {
			t.Fatalf("signal must stay OBSERVE and below finalize line: %+v", m)
		}
		if m.Evidence["signals"] != "body_profile,size_stability,header_profile,response_profile" {
			t.Fatalf("all four signal groups expected: %+v", m.Evidence)
		}
	}
}

// 不产出路径（误报纪律）：常规 API 轮询画像（定长明文 JSON 请求/响应、无 Cookie/Referer、
// UA 恒定）只命中 size_stability+header_profile 两组弱特征，达不到 3 项门槛。
func TestPipelineWebShellC2BenignSessionNoFire(t *testing.T) {
	const uri = "/api/v1/c2pipe_metrics"
	body := `{"window":"1m","metrics":["cpu","mem","disk"],"labels":["host","region"]}`
	resp := []byte(`{"cpu":0.42,"mem":0.71,"disk":0.33,"host":"edge-01"}`)
	for i := 0; i < 8; i++ {
		ctx, _ := c2PipeRound(t, uri, body, resp, true)
		if hasRule(&Result{Context: ctx}, "webshell.c2_suspected") {
			t.Fatalf("only 2 weak signals must not fire: %+v", ctx.CopyMatches())
		}
	}
}

// 不产出路径（未接线零行为）：请求相位照常记账，但响应收束处挂点侧未供给原请求/身份
// （ResponseConfig.Request/Identity 缺省），会话形态再典型也零产出。
func TestPipelineWebShellC2UnwiredZeroBehavior(t *testing.T) {
	const uri = "/upload/c2pipe_unwired.jsp"
	body := c2PipeBlob(512)
	resp := []byte(c2PipeBlob(256))
	for i := 0; i < 8; i++ {
		ctx, _ := c2PipeRound(t, uri, body, resp, false)
		if hasRule(&Result{Context: ctx}, "webshell.c2_suspected") {
			t.Fatalf("unwired response config must be zero-behavior: %+v", ctx.CopyMatches())
		}
	}
}

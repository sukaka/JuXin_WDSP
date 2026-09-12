package pipeline

import (
	"math"
	"strings"
	"testing"

	dsctx "github.com/jiuzhang-waf/gateway/dynamic_security/context"
	"github.com/jiuzhang-waf/gateway/dynamic_security/decision"
)

// §7.2 响应体采样比例：测试用小解析上限（64B）以便构造超大响应。
func sampleRatioLimits(ratio float64) dsctx.ParseLimits {
	l := dsctx.DefaultParseLimits()
	l.MaxBodyParseBytes = 64
	l.ResponseSampleRatio = ratio
	return l
}

func runSampledResponse(t *testing.T, body string, ratio float64, truncated, streamed bool) *dsctx.ResponseContext {
	t.Helper()
	limits := sampleRatioLimits(ratio)
	ctx := dsctx.New("rid-sample", limits)
	_, err := ProcessResponse(ctx, ResponseInput{
		Status:      200,
		ContentType: "application/json",
		Body:        []byte(body),
		BodySize:    int64(len(body)),
		Truncated:   truncated,
		Streamed:    streamed,
	}, ResponseConfig{Mode: decision.ModeProtect, Limits: limits})
	if err != nil {
		t.Fatalf("process: %v", err)
	}
	rc := ctx.GetResponse()
	if rc == nil {
		t.Fatal("response ctx nil")
	}
	return rc
}

// 默认值：DefaultParseLimits 采样比例=1（全量解析，保持现行为）。
func TestDefaultParseLimits_ResponseSampleRatio(t *testing.T) {
	if got := dsctx.DefaultParseLimits().ResponseSampleRatio; got != 1 {
		t.Fatalf("default ResponseSampleRatio = %v, want 1", got)
	}
}

// 比例 0 = 不解析响应体：IsJSON/ParsedBody/Observation 全空（与非 JSON 同口径），
// 体哈希与错误签名不受影响。
func TestProcessResponse_SampleRatioZeroSkipsParse(t *testing.T) {
	rc := runSampledResponse(t, `{"user":{"phone":"13800138000"}}`, 0, false, false)
	if rc.IsJSON || rc.ParsedBody != nil || rc.Observation != nil {
		t.Fatalf("ratio=0 must skip parse: %+v", rc)
	}
	if rc.BodyHash == "" {
		t.Fatal("body hash must still be recorded")
	}
	if len(rc.SensitiveFields) != 0 {
		t.Fatalf("no sensitive findings without parse: %+v", rc.SensitiveFields)
	}

	// 错误签名不依赖 JSON 解析，比例 0 不回退
	limits := sampleRatioLimits(0)
	ctx := dsctx.New("rid-sample-err", limits)
	if _, err := ProcessResponse(ctx, ResponseInput{
		Status:      500,
		ContentType: "application/json",
		Body:        []byte(`{"error":"stack trace: panic at server.go:42"}`),
		BodySize:    48,
	}, ResponseConfig{Mode: decision.ModeProtect, Limits: limits}); err != nil {
		t.Fatalf("process: %v", err)
	}
	if rc := ctx.GetResponse(); len(rc.ErrorSignatures) == 0 {
		t.Fatal("error signatures must not be gated by sample ratio")
	}
}

// 比例 1 = 全量解析：超大响应（>MaxBodyParseBytes）仍完整解析（保持现行为）。
func TestProcessResponse_SampleRatioOneParsesOversized(t *testing.T) {
	body := `{"key":"` + strings.Repeat("x", 200) + `"}`
	rc := runSampledResponse(t, body, 1, false, false)
	if !rc.IsJSON || rc.ParsedBody["key"] != "string" {
		t.Fatalf("ratio=1 must fully parse oversized body: %+v", rc)
	}
}

// (0,1) 超大响应确定性前缀采样：ceil(ratio×MaxBodyParseBytes) 字节前缀。
// 前缀恰为完整 JSON 值（尾部空白被解码器忽略）→ 按采样内容正确解析。
func TestProcessResponse_SampleRatioPartialPrefixParsed(t *testing.T) {
	// 体长 107 > 64；ratio 0.5 → 前缀 32B = {"a":1} + 25 空格 → 完整值可解
	body := `{"a":1}` + strings.Repeat(" ", 100)
	rc := runSampledResponse(t, body, 0.5, false, false)
	if !rc.IsJSON || rc.ParsedBody["a"] != "number" {
		t.Fatalf("sampled prefix must parse: %+v", rc)
	}
	if rc.Observation == nil || rc.Observation.Fields["a"] != "number" {
		t.Fatalf("observation must reflect sampled parse: %+v", rc.Observation)
	}
}

// (0,1) 超大响应前缀截断在 JSON 中间 → 前缀非完整 JSON，按不可解析处理
// （不产出部分 schema，与请求侧截断体同一纪律）。
func TestProcessResponse_SampleRatioPartialPrefixUnparseable(t *testing.T) {
	body := `{"key":"` + strings.Repeat("x", 200) + `"}` // 前缀 32B 落在字符串中间
	rc := runSampledResponse(t, body, 0.5, false, false)
	if rc.IsJSON || rc.ParsedBody != nil {
		t.Fatalf("truncated-mid-json prefix must be treated as unparseable: %+v", rc)
	}
}

// (0,1) 不超大响应不受采样比例影响：体长 ≤ MaxBodyParseBytes 全量解析。
func TestProcessResponse_SampleRatioSmallBodyUnaffected(t *testing.T) {
	rc := runSampledResponse(t, `{"a":1,"b":"x"}`, 0.25, false, false)
	if !rc.IsJSON || rc.ParsedBody["a"] != "number" || rc.ParsedBody["b"] != "string" {
		t.Fatalf("small body must fully parse regardless of ratio: %+v", rc)
	}
}

// 非法比例（<0 / >1 / NaN）归一为 1：超大响应全量解析。
func TestProcessResponse_SampleRatioInvalidNormalized(t *testing.T) {
	body := `{"key":"` + strings.Repeat("x", 200) + `"}`
	for _, ratio := range []float64{-0.5, 1.5, math.NaN()} {
		rc := runSampledResponse(t, body, ratio, false, false)
		if !rc.IsJSON || rc.ParsedBody["key"] != "string" {
			t.Fatalf("invalid ratio %v must normalize to full parse: %+v", ratio, rc)
		}
	}
}

// 与既有捕获侧行为的组合不回退：截断/流式/非 JSON 在任意采样比例下仍跳过解析。
func TestProcessResponse_SampleRatioCombinesWithCaptureFlags(t *testing.T) {
	body := `{"a":1}`
	if rc := runSampledResponse(t, body, 0.5, true, false); rc.IsJSON {
		t.Fatal("truncated capture must stay unparseable at any ratio")
	}
	if rc := runSampledResponse(t, body, 0.5, false, true); rc.IsJSON {
		t.Fatal("streamed response must stay unparseable at any ratio")
	}
	limits := sampleRatioLimits(0.5)
	ctx := dsctx.New("rid-sample-bin", limits)
	if _, err := ProcessResponse(ctx, ResponseInput{
		Status:      200,
		ContentType: "application/octet-stream",
		Body:        []byte{0x01, 0x02, 0x03},
		BodySize:    3,
	}, ResponseConfig{Mode: decision.ModeProtect, Limits: limits}); err != nil {
		t.Fatalf("process: %v", err)
	}
	if rc := ctx.GetResponse(); rc.IsJSON {
		t.Fatal("non-JSON response must stay unparseable at any ratio")
	}
}

// grpcguard_test.go grpcguard 判定形态矩阵/缺描述符红线/执行双闸/错误→状态码
// 映射/streaming 降级/压缩分支/覆盖五态与 coverage_v1 键。
package grpcguard

import (
	"strconv"
	"testing"

	"github.com/jiuzhang-waf/gateway/dynamic_security/classifier"
	dsctx "github.com/jiuzhang-waf/gateway/dynamic_security/context"
	"github.com/jiuzhang-waf/gateway/dynamic_security/coverage"
	"github.com/jiuzhang-waf/gateway/dynamic_security/parser"
)

// evalCase 评估输入夹具。
type evalCase struct {
	method      string
	contentType string
	headers     map[string]string
	body        []byte
	cfg         *Config
	appID       string
	engineProtect bool
}

func runEval(t *testing.T, ec evalCase) (*dsctx.RequestContext, *coverage.Observation) {
	t.Helper()
	if ec.method == "" {
		ec.method = "POST"
	}
	if ec.contentType == "" {
		ec.contentType = "application/grpc"
	}
	if ec.headers == nil {
		ec.headers = map[string]string{}
	}
	if ec.cfg == nil {
		ec.cfg = testConfig(t, true, nil)
	}
	ctx := dsctx.New("req-gg-1", dsctx.DefaultParseLimits())
	p := &parser.Parsed{Method: ec.method, RawPath: "/echo.EchoService/Echo", ContentType: ec.contentType, Headers: ec.headers}
	grpcRes := classifier.GRPCResult{IsGRPC: true, Service: "echo.EchoService", Method: "Echo"}
	cov := Evaluate(ctx, p, grpcRes, ec.body, ec.cfg, ec.appID, ec.engineProtect)
	return ctx, cov
}

func validUnaryBody(t *testing.T) []byte {
	reg := testEchoRegistry(t)
	return testFrame(false, testEchoMessage(t, reg, nil))
}

func matchByRule(ctx *dsctx.RequestContext, ruleID string) *dsctx.DetectorMatch {
	for _, m := range ctx.CopyMatches() {
		if m.RuleID == ruleID {
			mm := m
			return &mm
		}
	}
	return nil
}

// TestDecisionForms 判定形态矩阵（D1：content-type 变体/非 POST）。
func TestDecisionForms(t *testing.T) {
	body := validUnaryBody(t)
	cases := []struct {
		name       string
		method     string
		ct         string
		wantStatus coverage.Status
		wantReason coverage.ReasonCode
		wantSkip   string
	}{
		{"裸 proto 类型", "POST", "application/grpc", coverage.StatusFull, "", ""},
		{"+proto 变体", "POST", "application/grpc+proto", coverage.StatusFull, "", ""},
		{"+json 变体不深检", "POST", "application/grpc+json", coverage.StatusSkipped, coverage.ReasonNonProtoCodec, skipNonProtoCodec},
		{"+custom 变体按非 proto", "POST", "application/grpc+custom", coverage.StatusSkipped, coverage.ReasonNonProtoCodec, skipNonProtoCodec},
		{"非 POST 非候选", "GET", "application/grpc", coverage.StatusSkipped, coverage.ReasonNotGRPC, skipNonGRPC},
		{"带参数 proto", "POST", "application/grpc; charset=utf-8", coverage.StatusFull, "", ""},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			ctx, cov := runEval(t, evalCase{method: tc.method, contentType: tc.ct, body: body})
			if cov == nil || cov.Status != tc.wantStatus {
				t.Fatalf("status = %+v，应 %s", cov, tc.wantStatus)
			}
			if cov.ReasonCode != tc.wantReason {
				t.Fatalf("reason = %q，应 %q", cov.ReasonCode, tc.wantReason)
			}
			m := matchByRule(ctx, "grpc.coverage_v1")
			if m == nil {
				t.Fatal("候选请求恒有 grpc.coverage_v1 记录")
			}
			if tc.wantSkip != "" && m.Evidence["skip_reason"] != tc.wantSkip {
				t.Fatalf("skip_reason = %q，应 %q", m.Evidence["skip_reason"], tc.wantSkip)
			}
		})
	}
}

// TestNoDescriptorRedline 缺描述符红线（D3：SKIPPED(no_descriptor)，PROTECT 不误断）。
func TestNoDescriptorRedline(t *testing.T) {
	body := validUnaryBody(t)
	t.Run("全局无描述符", func(t *testing.T) {
		ctx, cov := runEval(t, evalCase{body: body, cfg: &Config{}, engineProtect: true})
		if cov.Status != coverage.StatusSkipped || cov.ReasonCode != coverage.ReasonNoDescriptor {
			t.Fatalf("应 no_descriptor: %+v", cov)
		}
		for _, m := range ctx.CopyMatches() {
			if m.Category == "BLOCK" {
				t.Fatalf("缺描述符 PROTECT 不误断: %+v", m)
			}
		}
	})
	t.Run("绑定应用未绑定服务", func(t *testing.T) {
		cfg := testConfig(t, true, map[string]map[string]Binding{
			"app-1": {"other.OtherService": {DescriptorName: "echo-set", Mode: ModeProtect}},
		})
		ctx, cov := runEval(t, evalCase{body: body, cfg: cfg, appID: "app-1", engineProtect: true})
		if cov.Status != coverage.StatusSkipped || cov.ReasonCode != coverage.ReasonNoDescriptor {
			t.Fatalf("绑定应用未绑定服务应 no_descriptor: %+v", cov)
		}
		for _, m := range ctx.CopyMatches() {
			if m.Category == "BLOCK" {
				t.Fatal("不误断红线")
			}
		}
	})
	t.Run("绑定引用未知集", func(t *testing.T) {
		cfg := testConfig(t, true, map[string]map[string]Binding{
			"app-1": {"echo.EchoService": {DescriptorName: "ghost-set", Mode: ModeProtect}},
		})
		ctx, cov := runEval(t, evalCase{body: body, cfg: cfg, appID: "app-1", engineProtect: true})
		if cov.Status != coverage.StatusSkipped || cov.ReasonCode != coverage.ReasonNoDescriptor {
			t.Fatalf("未知集应 no_descriptor: %+v", cov)
		}
		for _, m := range ctx.CopyMatches() {
			if m.Category == "BLOCK" {
				t.Fatal("不误断红线")
			}
		}
	})
	t.Run("空绑定全局可见", func(t *testing.T) {
		ctx, cov := runEval(t, evalCase{body: body, cfg: testConfig(t, true, nil), appID: "app-x"})
		if cov.Status != coverage.StatusFull {
			t.Fatalf("空绑定应走全局注册表 FULL: %+v", cov)
		}
		m := matchByRule(ctx, "grpc.coverage_v1")
		if m.Evidence["descriptor"] != "echo-set" || m.Evidence["descriptor_hash"] != "deadbeef" {
			t.Fatalf("覆盖读数 = %+v", m.Evidence)
		}
	})
}

// TestViolationDoubleGate 结构违规双闸（绑定 mode × 引擎 mode）。
func TestViolationDoubleGate(t *testing.T) {
	reg := testEchoRegistry(t)
	body := testFrame(false, testEchoMessage(t, reg, testSetTags(MaxRepeatedElements+1)))
	boundProtect := testConfig(t, false, map[string]map[string]Binding{
		"app-1": {"echo.EchoService": {DescriptorName: "echo-set", Mode: ModeProtect}},
	})
	boundObserve := testConfig(t, false, map[string]map[string]Binding{
		"app-1": {"echo.EchoService": {DescriptorName: "echo-set", Mode: ModeObserve}},
	})
	cases := []struct {
		name         string
		cfg          *Config
		engineProtect bool
		wantCategory string
	}{
		{"双闸全真 BLOCK", boundProtect, true, "BLOCK"},
		{"绑定 OBSERVE+引擎 PROTECT 只记录", boundObserve, true, "OBSERVE"},
		{"绑定 PROTECT+引擎 OBSERVE 不实断", boundProtect, false, "OBSERVE"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			ctx, cov := runEval(t, evalCase{body: body, cfg: tc.cfg, appID: "app-1", engineProtect: tc.engineProtect})
			m := matchByRule(ctx, "grpc.field_violation")
			if m == nil {
				t.Fatal("应产 field_violation")
			}
			if m.Category != tc.wantCategory {
				t.Fatalf("category = %q，应 %q", m.Category, tc.wantCategory)
			}
			if m.Evidence["grpc_status"] != strconv.Itoa(StatusPermissionDenied) {
				t.Fatalf("grpc_status = %q", m.Evidence["grpc_status"])
			}
			if m.Evidence["rule"] != "repeated_exceeded" || m.Evidence["read"] == "" || m.Evidence["path"] != "tags" {
				t.Fatalf("证据 = %+v", m.Evidence)
			}
			// 深检完成=FULL（违规是判定结果不是覆盖缺失）
			if cov.Status != coverage.StatusFull {
				t.Fatalf("status = %s", cov.Status)
			}
		})
	}
}

// TestStreamingDegraded streaming 识别降级（D1/R05：不冒充深检不报告通过）。
func TestStreamingDegraded(t *testing.T) {
	reg := testEchoRegistry(t)
	// 首条消息即含结构违规——但 streaming 降级先于深检，不产违规判定
	body := append(testFrame(false, testEchoMessage(t, reg, testSetTags(MaxRepeatedElements+1))),
		testFrame(false, testEchoMessage(t, reg, nil))...)
	cfg := testConfig(t, false, map[string]map[string]Binding{
		"app-1": {"echo.EchoService": {DescriptorName: "echo-set", Mode: ModeProtect}},
	})
	ctx, cov := runEval(t, evalCase{body: body, cfg: cfg, appID: "app-1", engineProtect: true})
	if cov.Status != coverage.StatusSkipped || cov.ReasonCode != coverage.ReasonStreamingDegraded {
		t.Fatalf("应 streaming_degraded: %+v", cov)
	}
	m := matchByRule(ctx, "grpc.streaming_observed")
	if m == nil || m.Category != "OBSERVE" || m.Evidence["direction"] != "request" {
		t.Fatalf("观测 = %+v", m)
	}
	if matchByRule(ctx, "grpc.field_violation") != nil {
		t.Fatal("降级不执行深检——不得产违规判定（不冒充部分通过）")
	}
	for _, mm := range ctx.CopyMatches() {
		if mm.Category == "BLOCK" {
			t.Fatal("降级不实断")
		}
	}
}

// TestCompressionBranches 压缩分支（D5：解压深检/显式关闭/损坏/预算）。
func TestCompressionBranches(t *testing.T) {
	reg := testEchoRegistry(t)
	msg := testEchoMessage(t, reg, nil)
	var gzBody []byte
	{
		var buf []byte
		w := gzipNewWriterForTest(&buf)
		_, _ = w.Write(msg)
		_ = w.Close()
		gzBody = testFrame(true, buf)
	}
	t.Run("gzip 解压深检 FULL", func(t *testing.T) {
		ctx, cov := runEval(t, evalCase{body: gzBody})
		if cov.Status != coverage.StatusFull {
			t.Fatalf("status = %s", cov.Status)
		}
		m := matchByRule(ctx, "grpc.coverage_v1")
		if m.Evidence["compression"] != "gzip" || m.Evidence["decompressed_bytes"] == "" {
			t.Fatalf("覆盖读数 = %+v", m.Evidence)
		}
	})
	t.Run("显式关闭不进入解压", func(t *testing.T) {
		cfg := testConfig(t, true, nil)
		off := false
		cfg.AllowCompression = &off
		_, cov := runEval(t, evalCase{body: gzBody, cfg: cfg})
		if cov.Status != coverage.StatusSkipped || cov.ReasonCode != coverage.ReasonDisabled {
			t.Fatalf("显式 false 应 SKIPPED(compression_disabled): %+v", cov)
		}
	})
	t.Run("nil 默认 true（G1 D5）", func(t *testing.T) {
		cfg := testConfig(t, true, nil)
		if !cfg.AllowGzip() {
			t.Fatal("nil 应默认允许")
		}
	})
	t.Run("gzip 流损坏 decode_error 不实断", func(t *testing.T) {
		bad := testFrame(true, []byte{0x1f, 0x8b, 0x00, 0x01})
		cfg := testConfig(t, false, map[string]map[string]Binding{
			"app-1": {"echo.EchoService": {DescriptorName: "echo-set", Mode: ModeProtect}},
		})
		ctx, cov := runEval(t, evalCase{body: bad, cfg: cfg, appID: "app-1", engineProtect: true})
		if matchByRule(ctx, "grpc.decode_error") == nil {
			t.Fatal("应 decode_error")
		}
		if cov.Status != coverage.StatusPartial {
			t.Fatalf("应 PARTIAL: %s", cov.Status)
		}
		for _, m := range ctx.CopyMatches() {
			if m.Category == "BLOCK" {
				t.Fatal("坏消息不升级实断（UNKNOWN 红线）")
			}
		}
	})
}

// TestUnsupportedEncoding 未知压缩算法（UNIMPLEMENTED(12)：PROTECT 双闸/OBSERVE 记录）。
func TestUnsupportedEncoding(t *testing.T) {
	reg := testEchoRegistry(t)
	body := testFrame(true, testEchoMessage(t, reg, nil)) // 压缩标志位但内容不解码——本用例只到编码闸
	hdr := map[string]string{"grpc-encoding": "snappy"}
	boundProtect := testConfig(t, false, map[string]map[string]Binding{
		"app-1": {"echo.EchoService": {DescriptorName: "echo-set", Mode: ModeProtect}},
	})
	ctx, _ := runEval(t, evalCase{body: body, headers: hdr, cfg: boundProtect, appID: "app-1", engineProtect: true})
	m := matchByRule(ctx, "grpc.unsupported_encoding")
	if m == nil || m.Category != "BLOCK" || m.Evidence["grpc_status"] != "12" || m.Evidence["encoding"] != "snappy" {
		t.Fatalf("PROTECT 明细 = %+v", m)
	}
	ctx2, _ := runEval(t, evalCase{body: body, headers: hdr, cfg: boundProtect, appID: "app-1", engineProtect: false})
	m2 := matchByRule(ctx2, "grpc.unsupported_encoding")
	if m2 == nil || m2.Category != "OBSERVE" {
		t.Fatalf("OBSERVE 记录转发不动: %+v", m2)
	}
}

// TestMalformedAndBudgetMapping 格式/预算错误→RESOURCE_EXHAUSTED(8) 映射与分类分离。
func TestMalformedAndBudgetMapping(t *testing.T) {
	boundProtect := testConfig(t, false, map[string]map[string]Binding{
		"app-1": {"echo.EchoService": {DescriptorName: "echo-set", Mode: ModeProtect}},
	})
	t.Run("保留位非零→畸形 8", func(t *testing.T) {
		body := []byte{0xFF, 0, 0, 0, 0}
		ctx, cov := runEval(t, evalCase{body: body, cfg: boundProtect, appID: "app-1", engineProtect: true})
		m := matchByRule(ctx, "grpcguard.malformed_frame")
		if m == nil || m.Category != "BLOCK" || m.Evidence["grpc_status"] != "8" || m.Evidence["kind"] != "reserved_flag_bits" {
			t.Fatalf("明细 = %+v", m)
		}
		if cov.Status != coverage.StatusPartial {
			t.Fatalf("应 PARTIAL: %s", cov.Status)
		}
	})
	t.Run("声明超单消息→预算 8", func(t *testing.T) {
		body := []byte{0, 0, 0x50, 0, 0} // 声明 5MiB > 4MiB 默认
		ctx, _ := runEval(t, evalCase{body: body, cfg: boundProtect, appID: "app-1", engineProtect: true})
		m := matchByRule(ctx, "grpcguard.budget_exceeded")
		if m == nil || m.Evidence["grpc_status"] != "8" || m.Evidence["kind"] != "message_bytes" {
			t.Fatalf("明细 = %+v", m)
		}
	})
	t.Run("截断头→格式类不误入预算", func(t *testing.T) {
		ctx, _ := runEval(t, evalCase{body: []byte{0, 0}, cfg: boundProtect, appID: "app-1", engineProtect: true})
		m := matchByRule(ctx, "grpcguard.malformed_frame")
		if m == nil || m.Evidence["kind"] != "truncated_header" {
			t.Fatalf("明细 = %+v", m)
		}
	})
	t.Run("压缩预算→compression_budget_exceeded 8", func(t *testing.T) {
		// 全零 200KB → gzip ~200B 倍率超 100×
		bomb := gzipCompressForTest(make([]byte, 200<<10))
		cfg := boundProtect
		ctx, _ := runEval(t, evalCase{body: testFrame(true, bomb), cfg: cfg, appID: "app-1", engineProtect: true})
		m := matchByRule(ctx, "grpc.compression_budget_exceeded")
		if m == nil || m.Category != "BLOCK" || m.Evidence["grpc_status"] != "8" {
			t.Fatalf("明细 = %+v", m)
		}
	})
}

// TestZeroMessagePartial 零消息 PARTIAL 如实（不定案）。
func TestZeroMessagePartial(t *testing.T) {
	_, cov := runEval(t, evalCase{body: nil})
	if cov.Status != coverage.StatusPartial {
		t.Fatalf("应 PARTIAL: %s", cov.Status)
	}
	_, cov2 := runEval(t, evalCase{body: []byte{}})
	if cov2.Status != coverage.StatusPartial {
		t.Fatalf("空体应 PARTIAL: %s", cov2.Status)
	}
}

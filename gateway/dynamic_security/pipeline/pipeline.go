// Package pipeline 统一防护管线：一次解析 → 分类 → 检测器写 Matches → 统一决策。
// API 动态防护关闭时 Process 直接跳过 API 检测，由调用方继续既有 WAF 路径。
package pipeline

import (
	"net/http"

	"github.com/jiuzhang-waf/gateway/dynamic_security/classifier"
	dsctx "github.com/jiuzhang-waf/gateway/dynamic_security/context"
	"github.com/jiuzhang-waf/gateway/dynamic_security/decision"
	"github.com/jiuzhang-waf/gateway/dynamic_security/detectors"
	"github.com/jiuzhang-waf/gateway/dynamic_security/normalizer"
	"github.com/jiuzhang-waf/gateway/dynamic_security/parser"
)

// Config 管线配置。
type Config struct {
	Enabled bool // API_DYNAMIC_PROTECTION_ENABLED
	Mode    decision.Mode
	Limits  dsctx.ParseLimits
	// FormalSchema 可选：字段名 → 期望类型（冻结模型）；nil 表示不跑偏离
	FormalSchema map[string]string
}

// Result 管线输出。
type Result struct {
	Context    *dsctx.RequestContext
	Parsed     *parser.Parsed
	API        classifier.Result
	EndpointKey string
	FinalAction dsctx.FinalAction
	Skipped    bool // API 管线关闭
}

// Process 执行统一管线。enabled=false 时返回 Skipped=true，不设置 final action（由遗留 WAF 负责）。
func Process(r *http.Request, cfg Config, externalMatches []dsctx.DetectorMatch) (*Result, error) {
	if !cfg.Enabled {
		return &Result{Skipped: true}, nil
	}
	limits := cfg.Limits
	if limits.MaxBodyParseBytes <= 0 {
		limits = dsctx.DefaultParseLimits()
	}
	reqID := ""
	if r != nil {
		reqID = r.Header.Get("X-Request-Id")
		if reqID == "" {
			reqID = r.Header.Get("X-Jiuzhang-Request-ID")
		}
	}
	ctx := dsctx.New(reqID, limits)
	parsed, err := parser.ParseRequest(r, ctx)
	if err != nil {
		return nil, err
	}
	// external (WAF/guard) matches only recorded — never finalize here
	for _, m := range externalMatches {
		ctx.AddMatch(m)
	}
	api := classifier.Classify(parsed)
	ctx.APIConfidence = api.Confidence
	if api.IsAPI {
		ctx.SetExtension("api.is_api", true)
		ctx.SetExtension("api.signals", api.Signals)
	}
	ek := normalizer.EndpointKey(parsed.Method, parsed.RawPath)
	ctx.SetExtension("api.endpoint_key", ek)

	// schema deviation against formal model
	if cfg.FormalSchema != nil && parsed != nil {
		detectors.CheckSchemaDeviation(ctx, parsed.JSONFields, cfg.FormalSchema)
	}
	// identity fingerprint (presence only)
	if parsed != nil {
		detectors.CheckIdentitySignals(ctx, parsed)
	}

	mode := cfg.Mode
	if mode == "" {
		mode = decision.ModeProtect
	}
	act := decision.Decide(ctx, decision.Input{Mode: mode})
	return &Result{
		Context:     ctx,
		Parsed:      parsed,
		API:         api,
		EndpointKey: ek,
		FinalAction: act,
	}, nil
}

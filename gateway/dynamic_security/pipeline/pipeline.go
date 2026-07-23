// Package pipeline 统一防护管线：一次解析 → 分类 → 检测器写 Matches → 统一决策。
// API 动态防护关闭时 Process 直接跳过 API 检测，由调用方继续既有 WAF 路径。
package pipeline

import (
	"fmt"
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
	// KnownEndpoints 已知端点基线（endpoint_key → asset_status，发布通道下发）；nil 关闭生命周期检测
	KnownEndpoints map[string]string
	// APIWriteRatePerMinute 写方法 API 每分钟限速（≤0 用 detectors.DefaultAPIWriteRatePerMinute）
	APIWriteRatePerMinute int
	// SensitivePatterns 敏感字段名模式（nil 用内置默认表；编译失败返回错误）
	SensitivePatterns []detectors.SensitivePattern
}

// Result 管线输出。
type Result struct {
	Context     *dsctx.RequestContext
	Parsed      *parser.Parsed
	API         classifier.Result
	EndpointKey string
	FinalAction dsctx.FinalAction
	Skipped     bool // API 管线关闭
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

	// 追加检测器（只 AddMatch，统一由 decision 定案）
	identity := detectors.IdentityKey(r)
	if parsed != nil {
		// 认证有效性（scheme/格式/弱凭据；凭据值不入证据）
		detectors.CheckAuthentication(ctx, r, api.IsAPI)
		// 敏感字段名（自定义模式编译失败为配置错误，不静默吞错）
		patterns, err := detectors.CompileSensitivePatterns(cfg.SensitivePatterns)
		if err != nil {
			return nil, fmt.Errorf("compile sensitive patterns: %w", err)
		}
		detectors.CheckSensitiveData(ctx, parsed, patterns)
		// 对象级访问辅助（BOLA/BFLA 前置信号）
		detectors.CheckResourceAccess(ctx, parsed, identity)
		if api.IsAPI {
			// 生命周期（依赖 endpoint_key；仅 API 流量，静态路径不参与基线比对）
			detectors.CheckLifecycle(ctx, ek, cfg.KnownEndpoints)
			// 写方法 API 限速信号
			if detectors.IsWriteMethod(parsed.Method) {
				detectors.CheckAPIWriteRate(ctx, identity, ek, cfg.APIWriteRatePerMinute)
			}
		}
		// 行为基线（identity+endpoint 进程内滑窗）
		detectors.CheckBehavior(ctx, identity, ek)
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

// Package identitybehavior 身份引擎 + 行为检测 + 侦察检测（WDSP AI 自动化渗透防护增强 阶段1，网关侧）。
//
// 设计纪律（与 guard 既有组件一致）：
//   - 配置缺省 = 零行为变化：identity_behavior 段不下发或 enabled=false 时引擎不装配，
//     请求链路无 wrapper、无文件、无计数；
//   - 本阶段全部信号仅 OBSERVE：不拦截任何请求，mode 非 OBSERVE 值装配期 Warn 并按 OBSERVE 处理；
//   - 任何组件故障 fail-open：存储 Valkey 故障回退进程内存（zap Warn 节流 1/min），
//     End 内 panic recover + zap Error，事件写入失败仅告警——请求永不因本包失败而失败；
//   - 身份/键材料一律 HMAC 指纹（detectors.Fingerprint，盐 = identity_salt），凭据明文不出函数作用域；
//   - 未验签 JWT claims 仅作关联用途，永不用于授权判定。
package identitybehavior

import (
	"fmt"
	"net/netip"
	"strings"

	"go.uber.org/zap"
)

// ModeObserve 观测模式（本阶段唯一有效模式：信号只记录不拦截）。
const ModeObserve = "OBSERVE"

// RuleVersion 侦察规则集版本（随规则语义变更递增，事件原样记录供溯源）。
const RuleVersion = "1.0.0"

// Params 发布通道下发原文（identity_behavior 段；json tag 为跨分片契约，不得改动）。
// 阈值字段为指针：nil = 引擎默认值兜底；显式 0 = 该规则关闭。
type Params struct {
	Enabled       bool   `json:"enabled"`
	Mode          string `json:"mode,omitempty"` // OBSERVE|PROTECT（预留；非 OBSERVE 值按 OBSERVE 处理并 Warn）
	PolicyVersion string `json:"policy_version,omitempty"`

	URIEnumUniqueThreshold   *int64   `json:"uri_enum_unique_threshold,omitempty"`    // 默认 50
	URIEnumNewRatioThreshold *float64 `json:"uri_enum_new_ratio_threshold,omitempty"` // 默认 0.8
	NotFoundRatioThreshold   *float64 `json:"not_found_ratio_threshold,omitempty"`    // 默认 0.7
	NotFoundMinRequests      *int64   `json:"not_found_min_requests,omitempty"`       // 默认 30
	MethodEnumThreshold      *int64   `json:"method_enum_threshold,omitempty"`        // 默认 4
	ParamMutationThreshold   *int64   `json:"param_mutation_threshold,omitempty"`     // 默认 30
	AuthFailThreshold        *int64   `json:"auth_fail_threshold,omitempty"`          // 默认 10
	LowSlowSensitiveMinHits  *int64   `json:"low_slow_sensitive_min_hits,omitempty"`  // 默认 10
	AccountEnumThreshold     *int64   `json:"account_enum_threshold,omitempty"`       // 默认 20
	ObjectEnumThreshold      *int64   `json:"object_enum_threshold,omitempty"`        // 默认 20
	AccountIdentifierFields  []string `json:"account_identifier_fields,omitempty"`    // 查询字段来源
	ObjectIdentifierFields   []string `json:"object_identifier_fields,omitempty"`     // 查询字段来源

	// SensitivePaths 敏感路径前缀（nil = 引擎默认表；显式空列表 = 无敏感路径）。
	SensitivePaths []string `json:"sensitive_paths,omitempty"`
	// Scores 信号分值覆盖（key = Signal 名；缺省用内置默认；显式 0 = 该规则关闭）。
	Scores map[string]int `json:"scores,omitempty"`

	WhitelistIPs []string `json:"whitelist_ips,omitempty"` // CIDR 或裸 IP；命中完全跳过身份行为观测
	WhitelistUAs []string `json:"whitelist_uas,omitempty"` // UA 子串（小写匹配）
}

// 引擎默认阈值（发布通道未显式下发时生效）。
const (
	defaultURIEnumUnique   int64   = 50
	defaultURIEnumNewRatio float64 = 0.8
	defaultNotFoundRatio   float64 = 0.7
	defaultNotFoundMinReq  int64   = 30
	defaultMethodEnum      int64   = 4
	defaultParamMutation   int64   = 30
	defaultAuthFail        int64   = 10
	defaultLowSlowMinHits  int64   = 10
	defaultAccountEnum     int64   = 20
	defaultObjectEnum      int64   = 20
)

var defaultAccountIdentifierFields = []string{"account", "account_id", "username", "user_id", "email"}
var defaultObjectIdentifierFields = []string{"object_id", "resource_id", "record_id"}

// defaultSensitivePaths 默认敏感路径前缀表（小写；前缀匹配）。
var defaultSensitivePaths = []string{
	"/.git", "/.env", "/swagger", "/openapi.json", "/v3/api-docs",
	"/actuator", "/metrics", "/debug", "/admin", "/graphql",
	"/server-status", "/config",
}

// defaultScores 内置默认分值（key = Signal 名）。
var defaultScores = map[string]int{
	SignalURIEnumeration:      15,
	SignalNotFoundEnumeration: 10,
	SignalSensitivePathProbe:  15,
	SignalMethodEnumeration:   10,
	SignalParameterMutation:   20,
	SignalAuthFailProbe:       15,
	SignalLowSlowRecon:        15,
	SignalHeadless:            10,
	SignalAccountEnumeration:  20,
	SignalObjectEnumeration:   20,
}

// Config 编译后的身份行为配置（Provision 产物，请求路径只读）。
type Config struct {
	Enabled       bool
	Mode          string // 恒 OBSERVE（本阶段）
	PolicyVersion string

	URIEnumUniqueThreshold   int64   // 0 = 规则关闭
	URIEnumNewRatioThreshold float64 // 0 = 规则关闭
	NotFoundRatioThreshold   float64 // 0 = 规则关闭
	NotFoundMinRequests      int64   // 0 = 规则关闭
	MethodEnumThreshold      int64   // 0 = 规则关闭
	ParamMutationThreshold   int64   // 0 = 规则关闭
	AuthFailThreshold        int64   // 0 = 规则关闭
	LowSlowSensitiveMinHits  int64   // 0 = 规则关闭
	AccountEnumThreshold     int64   // 0 = 规则关闭
	ObjectEnumThreshold      int64   // 0 = 规则关闭
	AccountIdentifierFields  []string
	ObjectIdentifierFields   []string

	// SensitivePaths 敏感路径前缀（已归一小写；空 = 无敏感路径，RECON-PATH-001 零行为）。
	SensitivePaths []string
	// Scores 信号分值（默认表 + 下发覆盖；0 = 规则关闭）。
	Scores map[string]int

	whitelistIPs []netip.Prefix
	whitelistUAs []string // 已归一小写
}

// maxPatternLen 单条敏感路径/UA 模式长度上限（防超大配置）。
const maxPatternLen = 256

// ValidateParams 装配期校验（比率 0-1、阈值非负、分值非负、白名单地址可解析）。
// p 为 nil 或未启用同样校验（配置显式下发即应合法）；校验失败为配置错误显式返回，不静默吞错。
func ValidateParams(p *Params) error {
	if p == nil {
		return nil
	}
	ratios := []struct {
		name string
		v    *float64
	}{
		{"uri_enum_new_ratio_threshold", p.URIEnumNewRatioThreshold},
		{"not_found_ratio_threshold", p.NotFoundRatioThreshold},
	}
	for _, r := range ratios {
		if r.v != nil && (*r.v < 0 || *r.v > 1) {
			return fmt.Errorf("%s must be between 0 and 1, got %v", r.name, *r.v)
		}
	}
	thresholds := []struct {
		name string
		v    *int64
	}{
		{"uri_enum_unique_threshold", p.URIEnumUniqueThreshold},
		{"not_found_min_requests", p.NotFoundMinRequests},
		{"method_enum_threshold", p.MethodEnumThreshold},
		{"param_mutation_threshold", p.ParamMutationThreshold},
		{"auth_fail_threshold", p.AuthFailThreshold},
		{"low_slow_sensitive_min_hits", p.LowSlowSensitiveMinHits},
		{"account_enum_threshold", p.AccountEnumThreshold},
		{"object_enum_threshold", p.ObjectEnumThreshold},
	}
	for _, t := range thresholds {
		if t.v != nil && *t.v < 0 {
			return fmt.Errorf("%s must be >= 0, got %d", t.name, *t.v)
		}
	}
	for sig, s := range p.Scores {
		if s < 0 {
			return fmt.Errorf("scores[%q] must be >= 0, got %d", sig, s)
		}
	}
	for i, sp := range p.SensitivePaths {
		if strings.TrimSpace(sp) == "" || len(sp) > maxPatternLen {
			return fmt.Errorf("sensitive_paths[%d]: bad pattern (empty or > %d chars)", i, maxPatternLen)
		}
	}
	for _, c := range p.WhitelistIPs {
		if _, err := parseCIDR(c); err != nil {
			return fmt.Errorf("whitelist_ips: %w", err)
		}
	}
	for i, u := range p.WhitelistUAs {
		if strings.TrimSpace(u) == "" || len(u) > maxPatternLen {
			return fmt.Errorf("whitelist_uas[%d]: bad pattern (empty or > %d chars)", i, maxPatternLen)
		}
	}
	return nil
}

// Compile 编译发布参数为运行时配置：p 为 nil 或 enabled=false 返回 (nil, nil)（零行为变化）；
// 阈值 nil 用默认值兜底、显式 0 = 规则关闭；mode 非 OBSERVE 值 Warn 并按 OBSERVE 处理（本阶段不拦截）；
// 配置非法返回错误（装配层 fail-open：记 Error 并关闭本功能，不影响其他功能）。
func Compile(p *Params, logger *zap.Logger) (*Config, error) {
	if p == nil || !p.Enabled {
		return nil, nil
	}
	if err := ValidateParams(p); err != nil {
		return nil, err
	}
	if p.Mode != "" && p.Mode != ModeObserve && logger != nil {
		logger.Warn("identity_behavior: mode 非 OBSERVE，本阶段按 OBSERVE 处理（信号不拦截）",
			zap.String("mode", p.Mode))
	}
	c := &Config{
		Enabled:                  true,
		Mode:                     ModeObserve,
		PolicyVersion:            p.PolicyVersion,
		URIEnumUniqueThreshold:   intOr(p.URIEnumUniqueThreshold, defaultURIEnumUnique),
		URIEnumNewRatioThreshold: floatOr(p.URIEnumNewRatioThreshold, defaultURIEnumNewRatio),
		NotFoundRatioThreshold:   floatOr(p.NotFoundRatioThreshold, defaultNotFoundRatio),
		NotFoundMinRequests:      intOr(p.NotFoundMinRequests, defaultNotFoundMinReq),
		MethodEnumThreshold:      intOr(p.MethodEnumThreshold, defaultMethodEnum),
		ParamMutationThreshold:   intOr(p.ParamMutationThreshold, defaultParamMutation),
		AuthFailThreshold:        intOr(p.AuthFailThreshold, defaultAuthFail),
		LowSlowSensitiveMinHits:  intOr(p.LowSlowSensitiveMinHits, defaultLowSlowMinHits),
		AccountEnumThreshold:     intOr(p.AccountEnumThreshold, defaultAccountEnum),
		ObjectEnumThreshold:      intOr(p.ObjectEnumThreshold, defaultObjectEnum),
		Scores:                   make(map[string]int, len(defaultScores)+len(p.Scores)),
	}
	if p.AccountIdentifierFields == nil {
		c.AccountIdentifierFields = append([]string(nil), defaultAccountIdentifierFields...)
	} else {
		c.AccountIdentifierFields = normalizeIdentifierFields(p.AccountIdentifierFields)
	}
	if p.ObjectIdentifierFields == nil {
		c.ObjectIdentifierFields = append([]string(nil), defaultObjectIdentifierFields...)
	} else {
		c.ObjectIdentifierFields = normalizeIdentifierFields(p.ObjectIdentifierFields)
	}
	for k, v := range defaultScores {
		c.Scores[k] = v
	}
	for k, v := range p.Scores {
		c.Scores[k] = v // 显式覆盖（含 0 = 关闭）
	}
	if p.SensitivePaths == nil {
		c.SensitivePaths = append([]string(nil), defaultSensitivePaths...)
	} else {
		c.SensitivePaths = make([]string, 0, len(p.SensitivePaths))
		for _, sp := range p.SensitivePaths {
			c.SensitivePaths = append(c.SensitivePaths, strings.ToLower(strings.TrimSpace(sp)))
		}
	}
	for _, raw := range p.WhitelistIPs {
		pfx, err := parseCIDR(raw)
		if err != nil {
			return nil, fmt.Errorf("whitelist_ips: %w", err)
		}
		c.whitelistIPs = append(c.whitelistIPs, pfx)
	}
	for _, u := range p.WhitelistUAs {
		c.whitelistUAs = append(c.whitelistUAs, strings.ToLower(strings.TrimSpace(u)))
	}
	return c, nil
}

func normalizeIdentifierFields(fields []string) []string {
	out := make([]string, 0, len(fields))
	seen := make(map[string]struct{}, len(fields))
	for _, field := range fields {
		field = strings.ToLower(strings.TrimSpace(field))
		if field == "" || len(field) > maxPatternLen {
			continue
		}
		if _, ok := seen[field]; ok {
			continue
		}
		seen[field] = struct{}{}
		out = append(out, field)
	}
	return out
}

// intOr / floatOr 指针阈值兜底（nil = 默认值；显式 0 保留 = 规则关闭）。
func intOr(v *int64, def int64) int64 {
	if v == nil {
		return def
	}
	return *v
}

func floatOr(v *float64, def float64) float64 {
	if v == nil {
		return def
	}
	return *v
}

// parseCIDR 解析 CIDR 或裸 IP（裸 IP 归一为全位前缀）。
func parseCIDR(s string) (netip.Prefix, error) {
	s = strings.TrimSpace(s)
	if p, err := netip.ParsePrefix(s); err == nil {
		return p, nil
	}
	a, err := netip.ParseAddr(s)
	if err != nil {
		return netip.Prefix{}, fmt.Errorf("invalid address %q", s)
	}
	return netip.PrefixFrom(a, a.BitLen()), nil
}

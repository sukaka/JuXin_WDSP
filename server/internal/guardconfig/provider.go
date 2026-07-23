// Package guardconfig 阶段5访问控制/CC 配置组装：
// 从可信代理/保护地址/黑白名单/CC策略仓储读取生效数据，
// 组装为下发网关的 GuardConfig，并管理版本快照。
package guardconfig

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"sort"
	"time"

	"github.com/google/uuid"
	"github.com/jiuzhang-waf/server/internal/accesscontrolversions"
	"github.com/jiuzhang-waf/server/internal/accessrules"
	"github.com/jiuzhang-waf/server/internal/apimodels"
	"github.com/jiuzhang-waf/server/internal/gatewayconfig"
	"github.com/jiuzhang-waf/server/internal/protectedaddresses"
	"github.com/jiuzhang-waf/server/internal/ratelimitpolicies"
	"github.com/jiuzhang-waf/server/internal/trustedproxies"
)

// Provider 是阶段5配置组装器（实现 gatewayconfig.GuardProvider）。
type Provider struct {
	proxies   *trustedproxies.Store
	protected *protectedaddresses.Store
	rules     *accessrules.Store
	policies  *ratelimitpolicies.Store
	versions  *accesscontrolversions.Store
	apiModels *apimodels.Store // 阶段8：冻结模型下发（nil 时跳过）

	valkeyAddr     string
	valkeyPassword string
	valkeyDB       int
	eventsLog      string // 网关容器内事件日志路径
	gatewayNode    string
	maxProxyChain  int
	maxCounterKeys int
	failOpen       bool

	// 阶段8 / WDSP：API 动态防护下发配置
	apiEnabled   bool
	apiMode      string
	apiEventsLog string // 网关容器内 API 事件日志路径
}

// Config 是组装器配置。
type Config struct {
	ValkeyAddress  string
	ValkeyPassword string
	ValkeyDB       int
	EventsLog      string // 网关容器内路径（如 /var/log/caddy/guard-events.log）
	GatewayNode    string
	MaxProxyChain  int  // 默认 16
	MaxCounterKeys int  // 默认 100000
	FailOpen       bool // 计数引擎故障策略
	// 阶段8 / WDSP：APIDynamicProtection 为 false 时下发 JSON 与纯 WAF 完全一致
	APIDynamicProtection bool
	APIProtectionMode    string // OFF | OBSERVE | PROTECT（启用时缺省 OBSERVE）
	APIEventsLog         string // 网关容器内路径（如 /var/log/caddy/api-runtime-events.log）
}

// NewProvider 创建组装器。
func NewProvider(
	proxies *trustedproxies.Store,
	protected *protectedaddresses.Store,
	rules *accessrules.Store,
	policies *ratelimitpolicies.Store,
	versions *accesscontrolversions.Store,
	cfg Config,
) *Provider {
	if cfg.MaxProxyChain <= 0 {
		cfg.MaxProxyChain = 16
	}
	if cfg.MaxCounterKeys <= 0 {
		cfg.MaxCounterKeys = 100000
	}
	if cfg.EventsLog == "" {
		cfg.EventsLog = "/var/log/caddy/guard-events.log"
	}
	return &Provider{
		proxies: proxies, protected: protected, rules: rules, policies: policies, versions: versions,
		valkeyAddr: cfg.ValkeyAddress, valkeyPassword: cfg.ValkeyPassword, valkeyDB: cfg.ValkeyDB,
		eventsLog: cfg.EventsLog, gatewayNode: cfg.GatewayNode,
		maxProxyChain: cfg.MaxProxyChain, maxCounterKeys: cfg.MaxCounterKeys, failOpen: cfg.FailOpen,
		apiEnabled: cfg.APIDynamicProtection, apiMode: cfg.APIProtectionMode, apiEventsLog: cfg.APIEventsLog,
	}
}

// SetAPIModels 注入模型版本仓储（阶段8：冻结正式模型随发布下发网关；nil 表示不下发）。
func (p *Provider) SetAPIModels(m *apimodels.Store) { p.apiModels = m }

// BuildGuardConfig 从数据库读取生效配置并组装。
func (p *Provider) BuildGuardConfig(ctx context.Context) (*gatewayconfig.GuardConfig, error) {
	cfg := &gatewayconfig.GuardConfig{
		TrustedProxies:     []gatewayconfig.GuardProxy{},
		MaxProxyChain:      p.maxProxyChain,
		ProtectedAddresses: []string{},
		GlobalAllow:        []gatewayconfig.GuardRule{},
		GlobalDeny:         []gatewayconfig.GuardRule{},
		GlobalPolicies:     []gatewayconfig.GuardPolicy{},
		AppRules:           map[string]*gatewayconfig.GuardAppRules{},
		CounterBackend:     "valkey",
		MaxCounterKeys:     p.maxCounterKeys,
		FailOpen:           p.failOpen,
		EventsLog:          p.eventsLog,
		GatewayNode:        p.gatewayNode,
	}
	if p.valkeyAddr != "" {
		cfg.Valkey = &gatewayconfig.GuardValkey{
			Address:  p.valkeyAddr,
			Password: p.valkeyPassword,
			DB:       p.valkeyDB,
		}
	} else {
		cfg.CounterBackend = "memory"
	}

	// 可信代理（启用；NODE 级仅本节点）
	proxies, err := p.proxies.ListEnabled(ctx)
	if err != nil {
		return nil, fmt.Errorf("list trusted proxies: %w", err)
	}
	for _, tp := range proxies {
		if tp.Scope == "NODE" && tp.NodeName != p.gatewayNode {
			continue
		}
		cfg.TrustedProxies = append(cfg.TrustedProxies, gatewayconfig.GuardProxy{
			Name:             tp.Name,
			CIDR:             tp.CIDR,
			HeaderType:       tp.HeaderType,
			CustomHeaderName: tp.CustomHeaderName,
			Priority:         tp.Priority,
		})
	}
	sort.Slice(cfg.TrustedProxies, func(i, j int) bool { return cfg.TrustedProxies[i].Priority < cfg.TrustedProxies[j].Priority })

	// 保护地址（启用）
	protected, err := p.protected.List(ctx, "")
	if err != nil {
		return nil, fmt.Errorf("list protected addresses: %w", err)
	}
	for _, pa := range protected {
		addr := pa.Address
		if addr == "" {
			addr = pa.CIDR
		}
		if addr != "" {
			cfg.ProtectedAddresses = append(cfg.ProtectedAddresses, addr)
		}
	}
	sort.Strings(cfg.ProtectedAddresses)

	// 黑白名单（ACTIVE）
	rules, _, err := p.rules.List(ctx, accessrules.ListFilter{Status: "ACTIVE", Page: 1, PageSize: 100000})
	if err != nil {
		return nil, fmt.Errorf("list access rules: %w", err)
	}
	appIDs := map[uuid.UUID]bool{}
	for _, r := range rules {
		if r.ApplicationID != nil {
			appIDs[*r.ApplicationID] = true
		}
	}
	idList := make([]uuid.UUID, 0, len(appIDs))
	for id := range appIDs {
		idList = append(idList, id)
	}
	appCodes, err := p.rules.ApplicationCodes(ctx, idList)
	if err != nil {
		return nil, fmt.Errorf("resolve application codes: %w", err)
	}
	appRules := map[string]*gatewayconfig.GuardAppRules{}
	for _, r := range rules {
		gr := gatewayconfig.GuardRule{
			ID:             r.ID.String(),
			Address:        r.Address,
			Priority:       r.Priority,
			EffectiveFrom:  formatTime(r.EffectiveFrom),
			EffectiveUntil: formatTime(r.EffectiveUntil),
		}
		switch {
		case r.ScopeType == "GLOBAL" && r.RuleType == "ALLOW":
			cfg.GlobalAllow = append(cfg.GlobalAllow, gr)
		case r.ScopeType == "GLOBAL":
			cfg.GlobalDeny = append(cfg.GlobalDeny, gr)
		default: // APPLICATION
			code := appCodes[*r.ApplicationID]
			ar := appRules[code]
			if ar == nil {
				ar = &gatewayconfig.GuardAppRules{
					Allow: []gatewayconfig.GuardRule{}, Deny: []gatewayconfig.GuardRule{}, Policies: []gatewayconfig.GuardPolicy{},
				}
				appRules[code] = ar
			}
			if r.RuleType == "ALLOW" {
				ar.Allow = append(ar.Allow, gr)
			} else {
				ar.Deny = append(ar.Deny, gr)
			}
		}
	}

	// CC 策略（ACTIVE）
	policies, _, err := p.policies.List(ctx, ratelimitpolicies.ListFilter{Status: "ACTIVE", Page: 1, PageSize: 10000})
	if err != nil {
		return nil, fmt.Errorf("list rate limit policies: %w", err)
	}
	polAppIDs := map[uuid.UUID]bool{}
	for _, pl := range policies {
		if pl.ApplicationID != nil {
			polAppIDs[*pl.ApplicationID] = true
		}
	}
	polIDList := make([]uuid.UUID, 0, len(polAppIDs))
	for id := range polAppIDs {
		polIDList = append(polIDList, id)
	}
	polAppCodes, err := p.rules.ApplicationCodes(ctx, polIDList)
	if err != nil {
		return nil, fmt.Errorf("resolve policy application codes: %w", err)
	}
	for _, pl := range policies {
		gp := gatewayconfig.GuardPolicy{
			ID:                   pl.ID.String(),
			Name:                 pl.Name,
			Dimension:            pl.Dimension,
			Algorithm:            pl.Algorithm,
			URIMatchType:         pl.URIMatchType,
			URIPattern:           pl.URIPattern,
			RequestsLimit:        int64(pl.RequestsLimit),
			WindowSeconds:        pl.WindowSeconds,
			BurstCapacity:        int64(pl.BurstCapacity),
			Action:               pl.Action,
			BlockDurationSeconds: pl.BlockDurationSeconds,
			ObserveOnly:          pl.ObserveOnly,
			Priority:             pl.Priority,
			EffectiveFrom:        formatTime(pl.EffectiveFrom),
			EffectiveUntil:       formatTime(pl.EffectiveUntil),
		}
		if pl.ScopeType == "GLOBAL" {
			cfg.GlobalPolicies = append(cfg.GlobalPolicies, gp)
			continue
		}
		code := polAppCodes[*pl.ApplicationID]
		ar := appRules[code]
		if ar == nil {
			ar = &gatewayconfig.GuardAppRules{
				Allow: []gatewayconfig.GuardRule{}, Deny: []gatewayconfig.GuardRule{}, Policies: []gatewayconfig.GuardPolicy{},
			}
			appRules[code] = ar
		}
		ar.Policies = append(ar.Policies, gp)
	}
	cfg.AppRules = appRules

	// 阶段8 / WDSP：API 动态防护开关与冻结模型（仅开启时注入；关闭时 GuardConfig 与纯 WAF 一致）
	if p.apiEnabled {
		cfg.APIDynamicProtection = true
		cfg.APIProtectionMode = p.apiMode
		cfg.APIEventsLog = p.apiEventsLog
		if p.apiModels != nil {
			schemas, err := p.apiModels.ListFormalSchemas(ctx)
			if err != nil {
				return nil, fmt.Errorf("list formal api schemas: %w", err)
			}
			if len(schemas) > 0 {
				cfg.APIFormalSchemas = schemas
			}
		}
	}
	return cfg, nil
}

// RedactGuardConfig 返回脱敏副本（版本历史/API 不落明文密码）。
func RedactGuardConfig(cfg *gatewayconfig.GuardConfig) *gatewayconfig.GuardConfig {
	if cfg == nil {
		return nil
	}
	cp := *cfg
	if cfg.Valkey != nil {
		v := *cfg.Valkey
		if v.Password != "" {
			v.Password = "***"
		}
		cp.Valkey = &v
	}
	// 深拷贝 AppRules map，避免调用方修改影响快照
	if cfg.AppRules != nil {
		cp.AppRules = make(map[string]*gatewayconfig.GuardAppRules, len(cfg.AppRules))
		for k, ar := range cfg.AppRules {
			if ar == nil {
				cp.AppRules[k] = nil
				continue
			}
			arCopy := *ar
			cp.AppRules[k] = &arCopy
		}
	}
	return &cp
}

// InjectRuntimeSecrets 将当前运行时 Valkey 凭据注入历史配置（回滚用，不信任快照中的密码）。
func (p *Provider) InjectRuntimeSecrets(cfg *gatewayconfig.GuardConfig) {
	if cfg == nil {
		return
	}
	if p.valkeyAddr == "" {
		cfg.Valkey = nil
		if cfg.CounterBackend == "valkey" {
			cfg.CounterBackend = "memory"
		}
		return
	}
	if cfg.Valkey == nil {
		cfg.Valkey = &gatewayconfig.GuardValkey{}
	}
	cfg.Valkey.Address = p.valkeyAddr
	cfg.Valkey.Password = p.valkeyPassword
	cfg.Valkey.DB = p.valkeyDB
	if cfg.CounterBackend == "" {
		cfg.CounterBackend = "valkey"
	}
}

// SaveVersionSnapshot 保存访问控制配置版本快照（PENDING，发布结果由 MarkVersionResult 回填）。
// 快照中的 Valkey 密码已脱敏，回滚时由 InjectRuntimeSecrets 重新注入。
func (p *Provider) SaveVersionSnapshot(ctx context.Context, cfg *gatewayconfig.GuardConfig, taskID, createdBy uuid.UUID) (uuid.UUID, error) {
	data, err := json.Marshal(RedactGuardConfig(cfg))
	if err != nil {
		return uuid.Nil, err
	}
	sum := sha256.Sum256(data)
	var prevID *uuid.UUID
	if latest, err := p.versions.GetLatest(ctx); err == nil && latest != nil {
		prevID = &latest.ID
	}
	summary := fmt.Sprintf("可信代理%d 保护地址%d 全局白%d 全局黑%d 应用规则组%d 全局CC%d",
		len(cfg.TrustedProxies), len(cfg.ProtectedAddresses), len(cfg.GlobalAllow), len(cfg.GlobalDeny),
		len(cfg.AppRules), len(cfg.GlobalPolicies))
	v, err := p.versions.Create(ctx, accesscontrolversions.CreateInput{
		Config:            data,
		ConfigHash:        hex.EncodeToString(sum[:]),
		ChangeSummary:     summary,
		PreviousVersionID: prevID,
		PublishTaskID:     &taskID,
		CreatedBy:         &createdBy,
	})
	if err != nil {
		return uuid.Nil, err
	}
	return v.ID, nil
}

// MarkVersionResult 回填版本发布结果。
func (p *Provider) MarkVersionResult(ctx context.Context, id uuid.UUID, result string) error {
	return p.versions.SetResult(ctx, id, result)
}

// GetVersionConfig 读取历史版本的 Guard 配置快照（回滚用），并注入当前运行时密钥。
func (p *Provider) GetVersionConfig(ctx context.Context, versionID uuid.UUID) (*gatewayconfig.GuardConfig, error) {
	v, err := p.versions.GetByID(ctx, versionID)
	if err != nil {
		return nil, err
	}
	var cfg gatewayconfig.GuardConfig
	if err := json.Unmarshal(v.Config, &cfg); err != nil {
		return nil, fmt.Errorf("decode version config: %w", err)
	}
	p.InjectRuntimeSecrets(&cfg)
	return &cfg, nil
}

// formatTime RFC3339 格式化（nil → 空串）。
func formatTime(t *time.Time) string {
	if t == nil {
		return ""
	}
	return t.UTC().Format(time.RFC3339)
}

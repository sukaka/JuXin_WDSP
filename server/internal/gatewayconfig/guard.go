// guard.go 阶段5访问控制/CC防护配置：类型定义与向 Caddy JSON 注入 jiuzhang_guard 处理器。
// 配置结构与 gateway/modules/jiuzhang_guard 的 JSON 约定一一对应。
package gatewayconfig

// GuardProxy 可信代理（下发网关）。
type GuardProxy struct {
	Name             string `json:"name"`
	CIDR             string `json:"cidr"`
	HeaderType       string `json:"header_type"`
	CustomHeaderName string `json:"custom_header_name,omitempty"`
	Priority         int    `json:"priority"`
}

// GuardRule IP 访问控制规则（下发网关）。
type GuardRule struct {
	ID             string `json:"id"`
	Address        string `json:"address"`
	Priority       int    `json:"priority"`
	EffectiveFrom  string `json:"effective_from,omitempty"`
	EffectiveUntil string `json:"effective_until,omitempty"`
}

// GuardPolicy CC 防护策略（下发网关）。
type GuardPolicy struct {
	ID                   string `json:"id"`
	Name                 string `json:"name"`
	Scope                string `json:"scope,omitempty"` // GLOBAL | APPLICATION
	Dimension            string `json:"dimension"`
	Algorithm            string `json:"algorithm"`
	URIMatchType         string `json:"uri_match_type"`
	URIPattern           string `json:"uri_pattern,omitempty"`
	RequestsLimit        int64  `json:"requests_limit"`
	WindowSeconds        int    `json:"window_seconds"`
	BurstCapacity        int64  `json:"burst_capacity,omitempty"`
	Action               string `json:"action"`
	BlockDurationSeconds int    `json:"block_duration_seconds,omitempty"`
	ObserveOnly          bool   `json:"observe_only,omitempty"`
	Priority             int    `json:"priority"`
	EffectiveFrom        string `json:"effective_from,omitempty"`
	EffectiveUntil       string `json:"effective_until,omitempty"`
}

// GuardValkey Valkey 连接（下发网关）。
type GuardValkey struct {
	Address  string `json:"address"`
	Username string `json:"username,omitempty"`
	Password string `json:"password,omitempty"`
	DB       int    `json:"db"`
}

// GuardAccessLog 全量访问日志采集配置（下发网关，对应 gateway jiuzhang_guard access_log 段）。
type GuardAccessLog struct {
	Enabled                bool   `json:"enabled"`
	CaptureRequestHeaders  bool   `json:"capture_request_headers"`
	CaptureRequestBody     bool   `json:"capture_request_body"`
	CaptureResponseHeaders bool   `json:"capture_response_headers"`
	CaptureResponseBody    bool   `json:"capture_response_body"`
	BodyLimitKB            int    `json:"body_limit_kb"`
	LogPath                string `json:"log_path"`
}

// GuardAppRules 单应用视角的规则与策略。
type GuardAppRules struct {
	Allow    []GuardRule   `json:"allow"`
	Deny     []GuardRule   `json:"deny"`
	Policies []GuardPolicy `json:"policies"`
}

// GuardConfig 阶段5访问控制/CC 全量配置（全局 + 按应用）。
// 该结构整体序列化后同时作为 access_control_versions 的快照。
type GuardConfig struct {
	TrustedProxies     []GuardProxy              `json:"trusted_proxies"`
	MaxProxyChain      int                       `json:"max_proxy_chain"`
	ProtectedAddresses []string                  `json:"protected_addresses"`
	GlobalAllow        []GuardRule               `json:"global_allow"`
	GlobalDeny         []GuardRule               `json:"global_deny"`
	GlobalPolicies     []GuardPolicy             `json:"global_policies"`
	AppRules           map[string]*GuardAppRules `json:"app_rules"` // key: 应用编码
	Valkey             *GuardValkey              `json:"valkey,omitempty"`
	CounterBackend     string                    `json:"counter_backend"`
	MaxCounterKeys     int                       `json:"max_counter_keys"`
	FailOpen           bool                      `json:"fail_open"`
	EventsLog          string                    `json:"events_log"`
	GatewayNode        string                    `json:"gateway_node"`
	// 阶段8 / WDSP：API 动态防护（默认关闭，关闭时下发 JSON 与纯 WAF 完全一致）
	APIDynamicProtection bool   `json:"api_dynamic_protection,omitempty"`
	APIProtectionMode    string `json:"api_protection_mode,omitempty"` // OFF | OBSERVE | PROTECT
	APIEventsLog         string `json:"api_events_log,omitempty"`
	// APIFormalSchemas 冻结正式模型（endpoint_key → 字段名 → 期望类型），经发布通道下发网关
	APIFormalSchemas map[string]map[string]string `json:"api_formal_schemas,omitempty"`
	// APIKnownEndpoints 已知 API 端点基线（endpoint_key → asset_status），经发布通道下发网关
	APIKnownEndpoints map[string]string `json:"api_known_endpoints,omitempty"`
	// AccessLog 全量访问日志（二期；nil 或 enabled=false 时网关零行为变化）
	AccessLog *GuardAccessLog `json:"access_log,omitempty"`
}

// buildGuardHandler 构建单应用路由的 jiuzhang_guard 处理器 JSON。
func buildGuardHandler(g *GuardConfig, app AppData) mapT {
	h := mapT{
		"handler":             "jiuzhang_guard",
		"app_id":              app.AppID,
		"app_code":            app.Code,
		"trusted_proxies":     g.TrustedProxies,
		"max_proxy_chain":     g.MaxProxyChain,
		"protected_addresses": g.ProtectedAddresses,
		"global_allow":        g.GlobalAllow,
		"global_deny":         g.GlobalDeny,
		"counter_backend":     g.CounterBackend,
		"max_counter_keys":    g.MaxCounterKeys,
		"fail_open":           g.FailOpen,
		"events_log":          g.EventsLog,
		"gateway_node":        g.GatewayNode,
	}
	appAllow := []GuardRule{}
	appDeny := []GuardRule{}
	policies := make([]GuardPolicy, 0, len(g.GlobalPolicies)+8)
	for _, p := range g.GlobalPolicies {
		cp := p
		if cp.Scope == "" {
			cp.Scope = "GLOBAL"
		}
		policies = append(policies, cp)
	}
	if ar, ok := g.AppRules[app.Code]; ok && ar != nil {
		appAllow = ar.Allow
		appDeny = ar.Deny
		for _, p := range ar.Policies {
			cp := p
			if cp.Scope == "" {
				cp.Scope = "APPLICATION"
			}
			policies = append(policies, cp)
		}
	}
	h["app_allow"] = appAllow
	h["app_deny"] = appDeny
	h["rate_limits"] = policies
	if g.Valkey != nil {
		h["valkey"] = g.Valkey
	}
	// 全量访问日志（二期）：非 nil 时注入（网关按 enabled 决定是否采集）
	if g.AccessLog != nil {
		h["access_log"] = g.AccessLog
	}
	// 阶段8：仅在 WDSP 开启时注入 API 动态防护配置（关闭时 JSON 与纯 WAF 一致）
	if g.APIDynamicProtection {
		h["api_dynamic_protection"] = true
		if g.APIProtectionMode != "" {
			h["api_protection_mode"] = g.APIProtectionMode
		}
		if g.APIEventsLog != "" {
			h["api_events_log"] = g.APIEventsLog
		}
		if len(g.APIFormalSchemas) > 0 {
			h["api_formal_schemas"] = g.APIFormalSchemas
		}
		if len(g.APIKnownEndpoints) > 0 {
			h["api_known_endpoints"] = g.APIKnownEndpoints
		}
	}
	return h
}

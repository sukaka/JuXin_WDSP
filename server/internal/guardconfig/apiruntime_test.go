// apiruntime_test.go 发布通道扩展单测（P0-03/04/18/21，纯函数 + fake，不依赖数据库）：
// gateway_runtime 设置写入/缺省/非法值、api_policy_version 稳定性、脱敏规则缺失容忍。
package guardconfig

import (
	"context"
	"errors"
	"testing"

	"github.com/jiuzhang-waf/server/internal/gatewayconfig"
)

// TestApplyGatewayRuntimeSettings 合法键全量写入；缺省键不下发；空串视同缺省；未知键忽略。
func TestApplyGatewayRuntimeSettings(t *testing.T) {
	cfg := &gatewayconfig.GuardConfig{}
	err := applyGatewayRuntimeSettings(cfg, map[string]string{
		"behavior_store":                "valkey",
		"behavior_store_ttl_seconds":    "720",
		"identity_salt":                 "s3cret",
		"credential_ip_spread_limit":    "5",
		"credential_concurrency_limit":  "10",
		"api_write_rate_per_minute":     "120",
		"api_quota_per_hour":            "3600",
		"api_quota_per_day":             "50000",
		"object_rate_per_minute":        "60",
		"max_page_size":                 "500",
		"max_batch_size":                "200",
		"unknown_future_key":            "ignored", // 未识别键忽略（前向兼容）
		"behavior_store_empty_fallback": "",
	})
	if err != nil {
		t.Fatal(err)
	}
	if cfg.BehaviorStore != "valkey" || cfg.BehaviorStoreTTLSeconds != 720 ||
		cfg.IdentitySalt != "s3cret" || cfg.CredentialIPSpreadLimit != 5 ||
		cfg.CredentialConcurrencyLimit != 10 || cfg.APIWriteRatePerMinute != 120 ||
		cfg.APIQuotaPerHour != 3600 || cfg.APIQuotaPerDay != 50000 ||
		cfg.ObjectRatePerMinute != 60 || cfg.APIMaxPageSize != 500 || cfg.APIMaxBatchSize != 200 {
		t.Fatalf("cfg = %+v", cfg)
	}

	// 缺省（map 无键/空串值）：全部保持零值 → 发布不下发，网关默认兜底
	empty := &gatewayconfig.GuardConfig{}
	if err := applyGatewayRuntimeSettings(empty, map[string]string{"identity_salt": "  "}); err != nil {
		t.Fatal(err)
	}
	if empty.BehaviorStore != "" || empty.IdentitySalt != "" || empty.BehaviorStoreTTLSeconds != 0 ||
		empty.CredentialIPSpreadLimit != 0 || empty.CredentialConcurrencyLimit != 0 || empty.APIWriteRatePerMinute != 0 ||
		empty.APIQuotaPerHour != 0 || empty.APIQuotaPerDay != 0 || empty.ObjectRatePerMinute != 0 ||
		empty.APIMaxPageSize != 0 || empty.APIMaxBatchSize != 0 {
		t.Fatalf("empty settings must leave zero values: %+v", empty)
	}

	// behavior_store 大小写归一
	normalized := &gatewayconfig.GuardConfig{}
	if err := applyGatewayRuntimeSettings(normalized, map[string]string{"behavior_store": " Memory "}); err != nil {
		t.Fatal(err)
	}
	if normalized.BehaviorStore != "memory" {
		t.Fatalf("behavior_store normalize = %q", normalized.BehaviorStore)
	}
}

// TestApplyGatewayRuntimeSettingsTicketKey TLS 会话票据密钥：支持 1~2 个逗号分隔 64 位 hex
// （小写归一，首键写入 TLSSessionTicketKey 向后兼容，全量写入 TLSSessionTicketKeys），
// 超 2 键/重复/空段/长度不足/非 hex 如实报错（中止发布，与组内其他键同一纪律）。
func TestApplyGatewayRuntimeSettingsTicketKey(t *testing.T) {
	const key1 = "0123456789ABCDEF0123456789ABCDEF0123456789ABCDEF0123456789ABCDEF"
	const key1Lower = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"
	const key2 = "FEDCBA9876543210FEDCBA9876543210FEDCBA9876543210FEDCBA9876543210"
	const key2Lower = "fedcba9876543210fedcba9876543210fedcba9876543210fedcba9876543210"
	const key3 = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"

	cfg := &gatewayconfig.GuardConfig{}
	if err := applyGatewayRuntimeSettings(cfg, map[string]string{"tls_session_ticket_key": key1}); err != nil {
		t.Fatalf("合法单键应通过: %v", err)
	}
	if cfg.TLSSessionTicketKey != key1Lower {
		t.Fatalf("单键未小写归一: %q", cfg.TLSSessionTicketKey)
	}
	if len(cfg.TLSSessionTicketKeys) != 1 || cfg.TLSSessionTicketKeys[0] != key1Lower {
		t.Fatalf("单键 TLSSessionTicketKeys = %v", cfg.TLSSessionTicketKeys)
	}

	// 双键平滑轮换（逗号分隔，允许空白）
	cfg2 := &gatewayconfig.GuardConfig{}
	if err := applyGatewayRuntimeSettings(cfg2, map[string]string{"tls_session_ticket_key": key2 + " , " + key1}); err != nil {
		t.Fatalf("合法双键应通过: %v", err)
	}
	if cfg2.TLSSessionTicketKey != key2Lower {
		t.Fatalf("双键首键 TLSSessionTicketKey = %q, want %q", cfg2.TLSSessionTicketKey, key2Lower)
	}
	if len(cfg2.TLSSessionTicketKeys) != 2 || cfg2.TLSSessionTicketKeys[0] != key2Lower || cfg2.TLSSessionTicketKeys[1] != key1Lower {
		t.Fatalf("双键 TLSSessionTicketKeys = %v", cfg2.TLSSessionTicketKeys)
	}

	// 脱敏双键占位 "***,***" 视同取不到，不写入也不报错
	cfgRedacted := &gatewayconfig.GuardConfig{}
	if err := applyGatewayRuntimeSettings(cfgRedacted, map[string]string{"tls_session_ticket_key": "***,***"}); err != nil {
		t.Fatalf("脱敏双键占位不应报错: %v", err)
	}
	if cfgRedacted.TLSSessionTicketKey != "" || len(cfgRedacted.TLSSessionTicketKeys) != 0 {
		t.Fatalf("脱敏双键占位不得写入: %+v", cfgRedacted)
	}

	for name, bad := range map[string]string{
		"长度不足":   "abcd",
		"非 hex":  "zz3456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef",
		"超过2个密钥": key1 + "," + key2 + "," + key3,
		"重复密钥":   key1 + "," + key1Lower,
		"尾部多余逗号": key1 + ",",
		"前导多余逗号": "," + key1,
		"第二键非法":  key1 + ",nothex",
	} {
		if err := applyGatewayRuntimeSettings(&gatewayconfig.GuardConfig{}, map[string]string{"tls_session_ticket_key": bad}); err == nil {
			t.Errorf("%s: %q must fail", name, bad)
		}
	}
}

// TestApplyGatewayRuntimeSettingsInvalid 非法取值如实报错（枚举外词汇/非数字/负数）。
func TestApplyGatewayRuntimeSettingsInvalid(t *testing.T) {
	cases := map[string]map[string]string{
		"非法枚举":    {"behavior_store": "redis"},
		"非数字":     {"behavior_store_ttl_seconds": "abc"},
		"负数":      {"credential_ip_spread_limit": "-1"},
		"浮点":      {"api_write_rate_per_minute": "1.5"},
		"配额负数":    {"api_quota_per_hour": "-10"},
		"日配额非数字":  {"api_quota_per_day": "many"},
		"对象限速浮点":  {"object_rate_per_minute": "2.5"},
		"分页上限负数":  {"max_page_size": "-1"},
		"批量上限非数字": {"max_batch_size": "abc"},
	}
	for name, kv := range cases {
		if err := applyGatewayRuntimeSettings(&gatewayconfig.GuardConfig{}, kv); err == nil {
			t.Errorf("%s: %v must fail", name, kv)
		}
	}
}

// TestComputeAPIPolicyVersion 版本戳：内容不变（含 map 乱序）恒同；内容变更即变；
// 已下发未进哈希的段（防护模式/已知端点/模型版本/事件日志/非密钥运行时键）变更即变；
// 密钥三段与 identity_salt 不参与（变更不动戳）。
func TestComputeAPIPolicyVersion(t *testing.T) {
	base := func() *gatewayconfig.GuardConfig {
		return &gatewayconfig.GuardConfig{
			APIFormalSchemas: map[string]map[string]string{"POST /v1/orders": {"amount": "number", "note": "string"}},
			APIParameterConstraints: map[string][]gatewayconfig.GuardParamConstraint{
				"POST /v1/orders": {{Location: "QUERY", Name: "page", Path: "page", BaseType: "number", Required: true}},
			},
			APIMaskRules:           []gatewayconfig.GuardMaskRule{{EndpointKey: "POST /v1/orders", FieldPath: "buyer.phone", DataType: "PHONE", Algorithm: "MASK"}},
			APISensitiveValueRules: []gatewayconfig.GuardSensitiveValueRule{{DataType: "phone", Regex: `^1[3-9]\d{9}$`, Locations: []string{"query", "json"}, Level: "SENSITIVE"}},
		}
	}
	v1 := computeAPIPolicyVersion(base())
	// 同内容不同 map 插入序 → 同版本戳
	scrambled := base()
	scrambled.APIFormalSchemas = map[string]map[string]string{"POST /v1/orders": {"note": "string", "amount": "number"}}
	if v2 := computeAPIPolicyVersion(scrambled); v2 != v1 {
		t.Fatalf("same content must yield same version: %s != %s", v2, v1)
	}
	if len(v1) != 64 {
		t.Fatalf("version must be sha256 hex: %s", v1)
	}
	// 既有规则段：内容变更 → 新版本戳
	c := base()
	c.APIFormalSchemas = nil
	if v := computeAPIPolicyVersion(c); v == v1 {
		t.Fatal("schema removal must change version")
	}
	c = base()
	c.APIMaskRules = nil
	if v := computeAPIPolicyVersion(c); v == v1 {
		t.Fatal("mask rule removal must change version")
	}
	c = base()
	c.APISensitiveValueRules = nil
	if v := computeAPIPolicyVersion(c); v == v1 {
		t.Fatal("sensitive value rule removal must change version")
	}
	// 响应结构基线纳入版本戳（W9-GW）：内容变更即变
	c = base()
	c.APIResponseBaselines = []gatewayconfig.GuardResponseBaseline{{
		EndpointKey: "POST /v1/orders", StatusCode: 200, Fields: map[string]string{"amount": "number"},
	}}
	if v := computeAPIPolicyVersion(c); v == v1 {
		t.Fatal("response baselines must be part of policy version")
	}
	// 已确认参数条件关系纳入版本戳（W11-REL）：确认/撤回即变，供「发布内容与实际生效」比对
	c = base()
	c.APIParameterRelations = []gatewayconfig.GuardParamRelation{{
		EndpointKey:  "POST /v1/orders",
		RelationType: "REQUIRES",
		ParamA:       gatewayconfig.GuardParamRef{Location: "QUERY", Path: "page", Name: "page"},
		ParamB:       gatewayconfig.GuardParamRef{Location: "QUERY", Path: "page_size", Name: "page_size"},
	}}
	if v := computeAPIPolicyVersion(c); v == v1 {
		t.Fatal("parameter relations must be part of policy version")
	}
	// 文件合规规则纳入版本戳（W13-GW / P2-03）：启停/变更即变
	c = base()
	c.APIFileComplianceRules = []gatewayconfig.GuardFileComplianceRule{{
		Direction: "UPLOAD", Match: "EXT", Value: "exe", Action: "BLOCK", Reason: "可执行文件",
	}}
	if v := computeAPIPolicyVersion(c); v == v1 {
		t.Fatal("file compliance rules must be part of policy version")
	}
	// gRPC 描述符集纳入版本戳（W14-DESC / P2-05）：变更即变
	c = base()
	c.APIGRPCDescriptors = []gatewayconfig.GuardGRPCDescriptor{{Name: "orders", ContentBase64: "CgVoZWxsbw=="}}
	if v := computeAPIPolicyVersion(c); v == v1 {
		t.Fatal("grpc descriptors must be part of policy version")
	}
	// 已下发未进哈希段补齐（对齐 guard.go 下发面）：逐项变更即变
	segments := map[string]func(c *gatewayconfig.GuardConfig){
		"api_protection_mode": func(c *gatewayconfig.GuardConfig) { c.APIProtectionMode = "PROTECT" },
		"api_events_log":      func(c *gatewayconfig.GuardConfig) { c.APIEventsLog = "/var/log/caddy/api.log" },
		"api_known_endpoints": func(c *gatewayconfig.GuardConfig) {
			c.APIKnownEndpoints = map[string]string{"POST /v1/orders": "CONFIRMED"}
		},
		"api_formal_model_versions": func(c *gatewayconfig.GuardConfig) {
			c.APIFormalModelVersions = map[string]string{"POST /v1/orders": "v3"}
		},
		"behavior_store":                 func(c *gatewayconfig.GuardConfig) { c.BehaviorStore = "valkey" },
		"credential_ip_spread_limit":     func(c *gatewayconfig.GuardConfig) { c.CredentialIPSpreadLimit = 5 },
		"credential_concurrency_limit":   func(c *gatewayconfig.GuardConfig) { c.CredentialConcurrencyLimit = 10 },
		"api_write_rate_per_minute":      func(c *gatewayconfig.GuardConfig) { c.APIWriteRatePerMinute = 120 },
		"api_quota_per_hour":             func(c *gatewayconfig.GuardConfig) { c.APIQuotaPerHour = 3600 },
		"api_quota_per_day":              func(c *gatewayconfig.GuardConfig) { c.APIQuotaPerDay = 50000 },
		"object_rate_per_minute":         func(c *gatewayconfig.GuardConfig) { c.ObjectRatePerMinute = 60 },
		"max_page_size":                  func(c *gatewayconfig.GuardConfig) { c.APIMaxPageSize = 500 },
		"max_batch_size":                 func(c *gatewayconfig.GuardConfig) { c.APIMaxBatchSize = 200 },
		"api_response_fail_policy":       func(c *gatewayconfig.GuardConfig) { c.APIResponseFailPolicy = "FAIL_CLOSED" },
		"api_response_capture_max_bytes": func(c *gatewayconfig.GuardConfig) { c.APIResponseCaptureMaxBytes = 4096 },
		"api_llm_allowed_models":         func(c *gatewayconfig.GuardConfig) { c.APILLMAllowedModels = []string{"gpt-x"} },
		"api_llm_security_policies": func(c *gatewayconfig.GuardConfig) {
			c.APILLMSecurityPolicies = []gatewayconfig.GuardLLMSecurityPolicy{{ID: "policy-1", Version: 1, Mode: "OBSERVE"}}
		},
		"api_file_watermark": func(c *gatewayconfig.GuardConfig) {
			c.APIFileWatermark = &gatewayconfig.GuardFileWatermark{Enabled: true, TextTemplate: "t"}
		},
		"api_grpc_max_frame_bytes":   func(c *gatewayconfig.GuardConfig) { c.APIGRPCMaxFrameBytes = 1024 },
		"api_grpc_allow_compression": func(c *gatewayconfig.GuardConfig) { c.APIGRPCAllowCompression = true },
	}
	for name, mutate := range segments {
		c := base()
		mutate(c)
		if v := computeAPIPolicyVersion(c); v == v1 {
			t.Errorf("%s must be part of policy version", name)
		}
	}
	// 密钥三段与 identity_salt 为秘密材料，不参与版本戳（变更不动戳）
	secrets := map[string]func(c *gatewayconfig.GuardConfig){
		"tls_session_ticket_key": func(c *gatewayconfig.GuardConfig) {
			c.TLSSessionTicketKey = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"
			c.TLSSessionTicketKeys = []string{
				"0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef",
				"fedcba9876543210fedcba9876543210fedcba9876543210fedcba9876543210",
			}
		},
		"identity_salt": func(c *gatewayconfig.GuardConfig) { c.IdentitySalt = "s3cret" },
		"api_scan_verification": func(c *gatewayconfig.GuardConfig) {
			c.APIScanVerification = &gatewayconfig.GuardScanVerification{KeyHex: "ab"}
		},
		"api_file_signature": func(c *gatewayconfig.GuardConfig) {
			c.APIFileSignature = &gatewayconfig.GuardFileSignature{Enabled: true, KID: "k1", KeyHex: "cd"}
		},
	}
	for name, mutate := range secrets {
		c := base()
		mutate(c)
		if v := computeAPIPolicyVersion(c); v != v1 {
			t.Errorf("secret %s must not be part of policy version", name)
		}
	}
}

// TestApplyGatewayRuntimeSettingsRedactPlaceholder 当前设置值为脱敏占位符（"***"）的键
// 视同取不到：不写入（防 "***" 被发布到网关，如 tls_session_ticket_key 非 hex 致 /load 拒绝）。
func TestApplyGatewayRuntimeSettingsRedactPlaceholder(t *testing.T) {
	cfg := &gatewayconfig.GuardConfig{}
	if err := applyGatewayRuntimeSettings(cfg, map[string]string{
		"tls_session_ticket_key": "***",
		"identity_salt":          "***",
		"behavior_store":         "valkey",
	}); err != nil {
		t.Fatal(err)
	}
	if cfg.TLSSessionTicketKey != "" || cfg.IdentitySalt != "" {
		t.Fatalf("redact placeholder must not be written: %+v", cfg)
	}
	if cfg.BehaviorStore != "valkey" {
		t.Fatalf("normal key must still apply: %+v", cfg)
	}
}

// fakeMaskLister 内存版脱敏规则读取（可注入错误路径）。
type fakeMaskLister struct {
	rules []gatewayconfig.GuardMaskRule
	err   error
}

func (f *fakeMaskLister) ListEnabledMaskRules(ctx context.Context) ([]gatewayconfig.GuardMaskRule, error) {
	_ = ctx
	return f.rules, f.err
}

// TestLoadAPIMaskRulesTolerance 脱敏规则：未注入 nil；查询失败（如 000040 表未建立）Warn 跳过返回 nil；
// 空规则不下发；正常读取透传。
func TestLoadAPIMaskRulesTolerance(t *testing.T) {
	// 未注入
	p := &Provider{}
	if got := p.loadAPIMaskRules(context.Background()); got != nil {
		t.Fatalf("nil lister must yield nil: %v", got)
	}
	// 查询失败（表不存在）→ 容忍跳过
	p = &Provider{maskRules: &fakeMaskLister{err: errors.New(`relation "api_masking_rules" does not exist`)}}
	if got := p.loadAPIMaskRules(context.Background()); got != nil {
		t.Fatalf("missing table must be tolerated: %v", got)
	}
	// 空规则 → 不下发
	p = &Provider{maskRules: &fakeMaskLister{rules: []gatewayconfig.GuardMaskRule{}}}
	if got := p.loadAPIMaskRules(context.Background()); got != nil {
		t.Fatalf("empty rules must yield nil: %v", got)
	}
	// 正常读取
	want := []gatewayconfig.GuardMaskRule{{EndpointKey: "POST /v1/orders", FieldPath: "buyer.phone", DataType: "PHONE", Algorithm: "MASK", Params: map[string]any{"keep_head": float64(3)}}}
	p = &Provider{maskRules: &fakeMaskLister{rules: want}}
	got := p.loadAPIMaskRules(context.Background())
	if len(got) != 1 || got[0].EndpointKey != want[0].EndpointKey || got[0].Params["keep_head"] != float64(3) {
		t.Fatalf("rules = %+v", got)
	}
}

// TestApplyGatewayRuntimeLoaderError 设置读取失败如实返回（发布侧中止，不静默回退）。
func TestApplyGatewayRuntimeLoaderError(t *testing.T) {
	p := &Provider{runtimeSettingsLoader: func(ctx context.Context) (map[string]string, error) {
		return nil, errors.New("db down")
	}}
	if err := p.applyGatewayRuntime(context.Background(), &gatewayconfig.GuardConfig{}); err == nil {
		t.Fatal("loader error must propagate")
	}
	// 未注入 loader：零行为变化
	p = &Provider{}
	if err := p.applyGatewayRuntime(context.Background(), &gatewayconfig.GuardConfig{}); err != nil {
		t.Fatal(err)
	}
}

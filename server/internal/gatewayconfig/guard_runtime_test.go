// guard_runtime_test.go 发布通道新键下发（P0-03/04/18/21）与规范化配置哈希单测。
package gatewayconfig

import (
	"encoding/json"
	"strings"
	"testing"
)

// TestBuildGuardHandlerRuntimeKeys gateway_runtime 设置/版本戳/脱敏规则仅 WDSP 开启且有值时注入；
// 关闭或零值时 JSON 不出现对应键（与既有下发面最小纪律一致；json tag 为跨分片契约）。
func TestBuildGuardHandlerRuntimeKeys(t *testing.T) {
	newCfg := func() *GuardConfig {
		g := testGuardConfig()
		g.APIDynamicProtection = true
		g.APIProtectionMode = "OBSERVE"
		g.APIPolicyVersion = "abc123"
		g.BehaviorStore = "valkey"
		g.BehaviorStoreTTLSeconds = 720
		g.IdentitySalt = "s3cret"
		g.CredentialIPSpreadLimit = 5
		g.CredentialConcurrencyLimit = 10
		g.APIWriteRatePerMinute = 120
		g.APIQuotaPerHour = 3600
		g.APIQuotaPerDay = 50000
		g.ObjectRatePerMinute = 60
		g.APIMaxPageSize = 500
		g.APIMaxBatchSize = 200
		g.APIMaskRules = []GuardMaskRule{{
			EndpointKey: "POST /v1/orders", FieldPath: "buyer.phone", DataType: "PHONE",
			Algorithm: "MASK", Params: map[string]any{"keep_head": 3},
		}}
		g.APISensitiveValueRules = []GuardSensitiveValueRule{{
			DataType: "phone", Regex: `^1[3-9]\d{9}$`, Locations: []string{"query", "json"}, Level: "SENSITIVE",
		}}
		return g
	}
	app := AppData{AppID: "app-1", Code: "shop"}

	// 开启：全部新键注入且 json tag 与契约一致
	raw, err := json.Marshal(buildGuardHandler(newCfg(), app, 0))
	if err != nil {
		t.Fatal(err)
	}
	j := string(raw)
	for _, want := range []string{
		`"api_policy_version":"abc123"`,
		`"behavior_store":"valkey"`,
		`"behavior_store_ttl_seconds":720`,
		`"identity_salt":"s3cret"`,
		`"credential_ip_spread_limit":5`,
		`"credential_concurrency_limit":10`,
		`"api_write_rate_per_minute":120`,
		`"api_quota_per_hour":3600`,
		`"api_quota_per_day":50000`,
		`"object_rate_per_minute":60`,
		`"max_page_size":500`,
		`"max_batch_size":200`,
		`"api_mask_rules"`, `"endpoint_key":"POST /v1/orders"`, `"field_path":"buyer.phone"`,
		`"data_type":"PHONE"`, `"algorithm":"MASK"`, `"params":{"keep_head":3}`,
		`"api_sensitive_value_rules"`, `"data_type":"phone"`, `"regex":"^1[3-9]\\d{9}$"`,
		`"locations":["query","json"]`, `"level":"SENSITIVE"`,
	} {
		if !strings.Contains(j, want) {
			t.Errorf("handler json missing %s: %s", want, j)
		}
	}

	// WDSP 关闭：新键一律不注入
	off := newCfg()
	off.APIDynamicProtection = false
	raw, _ = json.Marshal(buildGuardHandler(off, app, 0))
	j = string(raw)
	for _, key := range []string{
		"api_policy_version", "behavior_store", "behavior_store_ttl_seconds", "identity_salt",
		"credential_ip_spread_limit", "credential_concurrency_limit", "api_write_rate_per_minute", "api_mask_rules",
		"api_sensitive_value_rules",
		"api_quota_per_hour", "api_quota_per_day", "object_rate_per_minute", "max_page_size", "max_batch_size",
	} {
		if strings.Contains(j, `"`+key+`"`) {
			t.Errorf("%s must not be injected when api dynamic protection disabled", key)
		}
	}

	// 开启但零值：缺省键不下发（网关内置默认值兜底）
	empty := testGuardConfig()
	empty.APIDynamicProtection = true
	raw, _ = json.Marshal(buildGuardHandler(empty, app, 0))
	j = string(raw)
	for _, key := range []string{
		"api_policy_version", "behavior_store", "behavior_store_ttl_seconds", "identity_salt",
		"credential_ip_spread_limit", "credential_concurrency_limit", "api_write_rate_per_minute", "api_mask_rules",
		"api_sensitive_value_rules",
		"api_quota_per_hour", "api_quota_per_day", "object_rate_per_minute", "max_page_size", "max_batch_size",
	} {
		if strings.Contains(j, `"`+key+`"`) {
			t.Errorf("%s must be omitted when zero value", key)
		}
	}
}

// TestBuildGuardHandlerTraceKeys W3C trace 开关（APM 底座能力）：true 时显式下发且不受
// WDSP 门控影响；false/缺省时下发 JSON 无对应键（网关内置默认兜底，与历史版本逐字节一致）。
func TestBuildGuardHandlerTraceKeys(t *testing.T) {
	app := AppData{AppID: "app-1", Code: "shop"}

	// 缺省：不出现 trace 键（WDSP 开/关两态均断言）
	for _, wdsp := range []bool{false, true} {
		g := testGuardConfig()
		g.APIDynamicProtection = wdsp
		raw, err := json.Marshal(buildGuardHandler(g, app, 0))
		if err != nil {
			t.Fatal(err)
		}
		j := string(raw)
		for _, key := range []string{"trace_trust_external", "trace_inject_upstream"} {
			if strings.Contains(j, `"`+key+`"`) {
				t.Errorf("%s must be omitted when false (wdsp=%v): %s", key, wdsp, j)
			}
		}
	}

	// 开启：true 显式下发；底座能力不受 WDSP 门控（WDSP 关闭同样下发）
	for _, wdsp := range []bool{false, true} {
		g := testGuardConfig()
		g.APIDynamicProtection = wdsp
		g.TraceTrustExternal = true
		g.TraceInjectUpstream = true
		raw, err := json.Marshal(buildGuardHandler(g, app, 0))
		if err != nil {
			t.Fatal(err)
		}
		j := string(raw)
		for _, want := range []string{`"trace_trust_external":true`, `"trace_inject_upstream":true`} {
			if !strings.Contains(j, want) {
				t.Errorf("handler json missing %s (wdsp=%v): %s", want, wdsp, j)
			}
		}
	}
}

// TestCanonicalConfigHash 规范化哈希：键序/空白差异容忍（语义一致 → 哈希一致）；
// 内容真实不同 → 哈希不同；非法 JSON 报错。
func TestCanonicalConfigHash(t *testing.T) {
	a := `{"apps":{"http":{"servers":{"srv":{}}}},"admin":{"listen":"unix /run/caddy.sock"}}`
	// 同语义、键序不同 + 多余空白
	b := "{\n  \"admin\": {\"listen\": \"unix /run/caddy.sock\"},\n  \"apps\": {\"http\": {\"servers\": {\"srv\": {}}}}\n}"
	ha, err := CanonicalConfigHash(a)
	if err != nil {
		t.Fatal(err)
	}
	hb, err := CanonicalConfigHash(b)
	if err != nil {
		t.Fatal(err)
	}
	if ha != hb {
		t.Fatalf("canonical hash must ignore key order/whitespace: %s != %s", ha, hb)
	}
	// 内容不同 → 哈希不同
	hc, err := CanonicalConfigHash(`{"apps":{"http":{"servers":{"srv2":{}}}}}`)
	if err != nil {
		t.Fatal(err)
	}
	if hc == ha {
		t.Fatal("different content must yield different hash")
	}
	// 非法 JSON → 报错
	if _, err := CanonicalConfigHash("not-json"); err == nil {
		t.Fatal("invalid json must fail")
	}
}

package settings

import (
	"encoding/json"
	"strings"
	"testing"
)

// TestValidateValueRange 数值类安全策略取值范围回归（审查 LOW-S13）：
// 0/负数不得写入（如 max_failed_attempts=0 会关闭账号锁定、min_length=0 放行弱口令）。
func TestValidateValueRange(t *testing.T) {
	cases := []struct {
		name      string
		group     string
		key       string
		valueType string
		value     string
		wantErr   bool
	}{
		{"min_length 合法", "password", "min_length", "integer", "12", false},
		{"min_length 下限", "password", "min_length", "integer", "8", false},
		{"min_length 过低", "password", "min_length", "integer", "4", true},
		{"min_length 零", "password", "min_length", "integer", "0", true},
		{"min_length 负数", "password", "min_length", "integer", "-1", true},
		{"max_failed_attempts 零（关闭锁定）", "login", "max_failed_attempts", "integer", "0", true},
		{"max_failed_attempts 合法", "login", "max_failed_attempts", "integer", "5", false},
		{"lock_minutes 负数", "login", "lock_minutes", "integer", "-5", true},
		{"expire_days 零合法（不过期）", "password", "expire_days", "integer", "0", false},
		{"expire_days 负数", "password", "expire_days", "integer", "-1", true},
		{"idle_timeout 合法", "session", "idle_timeout_minutes", "integer", "30", false},
		{"idle_timeout 零", "session", "idle_timeout_minutes", "integer", "0", true},
		{"未列入范围的键不校验", "display", "system_name", "integer", "-99", false},
		{"非 integer 类型不校验", "password", "min_length", "string", `"0"`, false},
		{"范围键非法 JSON", "password", "min_length", "integer", `"x"`, true},
	}
	for _, c := range cases {
		err := validateValueRange(c.group, c.key, c.valueType, json.RawMessage(c.value))
		if (err != nil) != c.wantErr {
			t.Errorf("%s: validateValueRange err = %v, wantErr = %v", c.name, err, c.wantErr)
		}
	}
}

// TestValidateStringLen 字符串类设置长度上限回归（阶段5 §5.1 自定义阻断页面）：
// 超上限拒绝保存（400）；未列入清单的字符串键不校验；空串（缺省=内置默认）合法。
func TestValidateStringLen(t *testing.T) {
	longBody := `"` + strings.Repeat("p", 4097) + `"`
	maxBody := `"` + strings.Repeat("p", 4096) + `"`
	cases := []struct {
		name      string
		group     string
		key       string
		valueType string
		value     string
		wantErr   bool
	}{
		{"html_body 上限内", "block_response", "html_body", "string", maxBody, false},
		{"html_body 超上限", "block_response", "html_body", "string", longBody, true},
		{"html_body 空串（内置默认）", "block_response", "html_body", "string", `""`, false},
		{"html_title 超上限", "block_response", "html_title", "string", `"` + strings.Repeat("a", 129) + `"`, true},
		{"未列入清单的字符串键不校验", "display", "system_name", "string", longBody, false},
		{"非 string 类型不校验", "block_response", "html_body", "integer", "999999", false},
	}
	for _, c := range cases {
		err := validateStringLen(c.group, c.key, c.valueType, json.RawMessage(c.value))
		if (err != nil) != c.wantErr {
			t.Errorf("%s: validateStringLen err = %v, wantErr = %v", c.name, err, c.wantErr)
		}
	}
	// 白名单登记：四键均可经设置接口修改
	for _, key := range []string{"html_title", "html_body", "json_code", "json_message"} {
		if !AllowedSettingKeys["block_response:"+key] {
			t.Errorf("block_response:%s 未登记 AllowedSettingKeys", key)
		}
	}
}

// TestIsSensitiveSetting 敏感设置判定回归（审查 MED-14）：秘密材料键即使 DB 行
// is_sensitive=false（清单生效前写入的历史行）也按敏感处理（List 脱敏/审计脱敏）。
func TestIsSensitiveSetting(t *testing.T) {
	cases := []struct {
		group        string
		key          string
		rowSensitive bool
		want         bool
	}{
		{"gateway_runtime", "identity_salt", false, true},
		{"gateway_runtime", "tls_session_ticket_key", false, true},
		{"gateway_runtime", "api_file_signature_key", false, true},
		{"api_scan", "signing_key", false, true},
		{"apm_agent", "ca_material", false, true},
		{"traffic_agent_ca", "ca_material", false, true},
		{"password", "min_length", false, false},
		{"gateway_runtime", "api_file_signature_kid", false, false}, // kid 非秘密（随 token 明文嵌入文件）
		{"display", "system_name", true, true},                      // DB 行标记优先保留
	}
	for _, c := range cases {
		if got := isSensitiveSetting(c.group, c.key, c.rowSensitive); got != c.want {
			t.Errorf("%s:%s rowSensitive=%v: got %v, want %v", c.group, c.key, c.rowSensitive, got, c.want)
		}
	}
}

// TestAPIRateLimitKeysAllowed 阶段8 §36 限流下发面：gateway_runtime 组五个阈值键
// （种子见迁移 000152）均可经设置接口修改；阈值非秘密材料，不按敏感处理。
func TestAPIRateLimitKeysAllowed(t *testing.T) {
	for _, key := range []string{
		"api_quota_per_hour", "api_quota_per_day", "object_rate_per_minute",
		"max_page_size", "max_batch_size",
	} {
		if !AllowedSettingKeys["gateway_runtime:"+key] {
			t.Errorf("gateway_runtime:%s 未登记 AllowedSettingKeys", key)
		}
		if isSensitiveSetting("gateway_runtime", key, false) {
			t.Errorf("gateway_runtime:%s 不应按敏感设置处理", key)
		}
	}
}

func TestCredentialRatePerMinuteSetting(t *testing.T) {
	const key = "gateway_runtime:credential_rate_per_minute"
	if !AllowedSettingKeys[key] {
		t.Fatalf("%s 未登记 AllowedSettingKeys", key)
	}
	if isSensitiveSetting("gateway_runtime", "credential_rate_per_minute", false) {
		t.Fatal("credential rate must not be sensitive")
	}
	for _, tc := range []struct {
		name    string
		value   string
		wantErr bool
	}{
		{name: "空串", value: `""`},
		{name: "空白", value: `" \t "`},
		{name: "零", value: `"0"`},
		{name: "正数", value: `"120"`},
		{name: "带空白正数", value: `" 60 "`},
		{name: "负数", value: `"-1"`, wantErr: true},
		{name: "非数字", value: `"many"`, wantErr: true},
		{name: "浮点", value: `"1.5"`, wantErr: true},
		{name: "指数", value: `"1e2"`, wantErr: true},
		{name: "JSON 数值", value: `60`, wantErr: true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			value := json.RawMessage(tc.value)
			err := validateValueType("string", value)
			if err == nil {
				err = validateValueRange("gateway_runtime", "credential_rate_per_minute", "string", value)
			}
			if (err != nil) != tc.wantErr {
				t.Fatalf("validation error = %v, wantErr %v", err, tc.wantErr)
			}
		})
	}
}

// TestNetworkServerSettings 节点 DNS/NTP 服务器设置（迁移 000162 种子）回归：
// 两键均可经设置接口修改；逗号分隔主机列表校验（去空白去空项、每项合法 IP 或
// 主机名、≤4 项、总长 ≤255）；空串合法（= 继承宿主机现状不下发）。
func TestNetworkServerSettings(t *testing.T) {
	for _, key := range []string{"ntp_servers", "dns_servers"} {
		if !AllowedSettingKeys["network:"+key] {
			t.Errorf("network:%s 未登记 AllowedSettingKeys", key)
		}
		if settingStringMaxLen["network:"+key] != 255 {
			t.Errorf("network:%s 未登记 255 字节长度上限", key)
		}
	}
	cases := []struct {
		name    string
		key     string
		value   string
		wantErr bool
	}{
		{"单个 IP", "dns_servers", `"223.5.5.5"`, false},
		{"单个主机名", "ntp_servers", `"pool.ntp.org"`, false},
		{"IPv6 字面量", "dns_servers", `"2001:4860:4860::8888"`, false},
		{"多个含空白与空项", "dns_servers", `" 223.5.5.5, ,8.8.8.8 ,"`, false},
		{"恰好 4 项", "ntp_servers", `"a.pool.org, b.pool.org, 1.1.1.1, ntp.aliyun.com"`, false},
		{"空串（继承宿主机）", "dns_servers", `""`, false},
		{"全空白（视同空）", "dns_servers", `"   "`, false},
		{"5 项超上限", "dns_servers", `"1.1.1.1,2.2.2.2,3.3.3.3,4.4.4.4,5.5.5.5"`, true},
		{"含 shell 元字符", "dns_servers", `"8.8.8.8; rm -rf /"`, true},
		{"含空格的主机名", "ntp_servers", `"pool. ntp.org"`, true},
		{"非法字符下划线开头", "dns_servers", `"_dmarc.example.com"`, true},
		{"含斜杠（CIDR 不允许）", "dns_servers", `"8.8.8.8/24"`, true},
		{"值非字符串", "ntp_servers", `123`, true},
	}
	for _, c := range cases {
		err := validateServerList("network", c.key, "string", json.RawMessage(c.value))
		if (err != nil) != c.wantErr {
			t.Errorf("%s: validateServerList err = %v, wantErr = %v", c.name, err, c.wantErr)
		}
	}
	// 未列入清单的键与非 string 类型不校验
	if err := validateServerList("display", "system_name", "string", json.RawMessage(`"a;b"`)); err != nil {
		t.Errorf("未列入清单的键不应校验: %v", err)
	}
	if err := validateServerList("network", "dns_servers", "integer", json.RawMessage(`"a;b"`)); err != nil {
		t.Errorf("非 string 类型不应校验: %v", err)
	}
}

// TestExposureEngineSettings WDSP 暴露面判定引擎设置（迁移 000190 种子）回归：
// 五键均登记白名单且非敏感；数值键区间校验；partner_egress_cidrs CIDR 列表校验；
// public_dns_servers 走主机列表校验（与 network 组同口径）。
func TestExposureEngineSettings(t *testing.T) {
	for _, key := range []string{
		"observation_days", "partner_egress_cidrs", "public_dns_servers", "min_requests", "min_days",
	} {
		if !AllowedSettingKeys["exposure_engine:"+key] {
			t.Errorf("exposure_engine:%s 未登记 AllowedSettingKeys", key)
		}
		if isSensitiveSetting("exposure_engine", key, false) {
			t.Errorf("exposure_engine:%s 不应按敏感设置处理", key)
		}
	}
	// 数值区间
	for _, c := range []struct {
		key     string
		value   string
		wantErr bool
	}{
		{"observation_days", "7", false},
		{"observation_days", "0", true},
		{"observation_days", "31", true},
		{"min_requests", "50", false},
		{"min_requests", "0", true},
		{"min_days", "2", false},
		{"min_days", "-1", true},
	} {
		err := validateValueRange("exposure_engine", c.key, "integer", json.RawMessage(c.value))
		if (err != nil) != c.wantErr {
			t.Errorf("%s=%s: validateValueRange err = %v, wantErr = %v", c.key, c.value, err, c.wantErr)
		}
	}
	// CIDR 列表
	for _, c := range []struct {
		name    string
		value   string
		wantErr bool
	}{
		{"单个 CIDR", `"203.0.113.0/24"`, false},
		{"多个含空白与空项", `" 203.0.113.0/24, ,2001:db8::/32 ,"`, false},
		{"空串（不启用）", `""`, false},
		{"裸 IP 非法（须带前缀）", `"203.0.113.1"`, true},
		{"非法前缀长度", `"10.0.0.0/33"`, true},
		{"非 CIDR 字符串", `"abc"`, true},
		{"值非字符串", `123`, true},
	} {
		err := validateCIDRList("exposure_engine", "partner_egress_cidrs", "string", json.RawMessage(c.value))
		if (err != nil) != c.wantErr {
			t.Errorf("%s: validateCIDRList err = %v, wantErr = %v", c.name, err, c.wantErr)
		}
	}
	// 超项数上限
	tooMany := make([]string, 0, 33)
	for i := 0; i < 33; i++ {
		tooMany = append(tooMany, "10.0.0.0/8")
	}
	if err := validateCIDRList("exposure_engine", "partner_egress_cidrs", "string",
		json.RawMessage(`"`+strings.Join(tooMany, ",")+`"`)); err == nil {
		t.Error("33 项 CIDR 应超上限报错")
	}
	// public_dns_servers 走主机列表校验（CIDR 不允许）
	if err := validateServerList("exposure_engine", "public_dns_servers", "string",
		json.RawMessage(`"223.5.5.5, 8.8.8.8"`)); err != nil {
		t.Errorf("public_dns_servers 合法列表不应报错: %v", err)
	}
	if err := validateServerList("exposure_engine", "public_dns_servers", "string",
		json.RawMessage(`"8.8.8.8/24"`)); err == nil {
		t.Error("public_dns_servers 含 CIDR 应报错")
	}
}

func TestScalarString(t *testing.T) {
	cases := []struct {
		raw     string
		want    string
		wantErr bool
	}{
		{`"abc"`, "abc", false},
		{`true`, "true", false},
		{`false`, "false", false},
		{`42`, "42", false},
		{`3.5`, "3.5", false},
		{`{"a":1}`, "", true},
		{`[1,2]`, "", true},
		{`null`, "", false}, // json.Unmarshal null→string 得空串不报错，视同空值
	}
	for _, c := range cases {
		got, err := scalarString(json.RawMessage(c.raw))
		if c.wantErr {
			if err == nil {
				t.Fatalf("scalarString(%s) 应报错", c.raw)
			}
			continue
		}
		if err != nil || got != c.want {
			t.Fatalf("scalarString(%s) = %q, %v；期望 %q", c.raw, got, err, c.want)
		}
	}
}

func TestValidateTproxyPassthroughAllowlist(t *testing.T) {
	if !AllowedSettingKeys["network:tproxy_passthrough_allowlist"] {
		t.Fatal("network:tproxy_passthrough_allowlist must be in AllowedSettingKeys")
	}
	valid := []string{
		`""`,
		`"partner.example.com"`,
		`"partner.example.com, *.other.example.com"`,
		`"a.example.com\n*.b.example.com"`,
		`"[\"a.example.com\",\"*.b.example.com\"]"`,
	}
	for _, v := range valid {
		if err := validateTproxyPassthroughAllowlist("network", "tproxy_passthrough_allowlist", "string", json.RawMessage(v)); err != nil {
			t.Errorf("validateTproxyPassthroughAllowlist(%s) unexpected error: %v", v, err)
		}
	}
	invalid := []string{
		`"*"`,
		`"*.com"`,
		`"*.*.example.com"`,
		`"bad host.com"`,
		`"[not-json"`,
	}
	for _, v := range invalid {
		if err := validateTproxyPassthroughAllowlist("network", "tproxy_passthrough_allowlist", "string", json.RawMessage(v)); err == nil {
			t.Errorf("validateTproxyPassthroughAllowlist(%s) should fail", v)
		}
	}
}

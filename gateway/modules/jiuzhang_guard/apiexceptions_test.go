// API 受限例外纯函数测试（WDSP P0-04；EXC-01/05/08/10/11 网关侧覆盖：
// 解析严格性 fail-closed、范围逐维度 AND 翻折、时间半开区间边界、
// 可信 IP 成员判定与 XFF 伪造无关性、规则引用展开溯源）。
package jiuzhang_guard

import (
	"encoding/json"
	"strings"
	"testing"
)

// baseAPIExceptionJSON 全维度配置齐备的单条例外（各用例在其上逐维度翻折）。
func baseAPIExceptionJSON() map[string]any {
	return map[string]any{
		"schema_version":  1,
		"exception_id":    "exc-uuid-1",
		"version":         2,
		"domain":          "api.example.com",
		"uri_prefix":      "/api/orders",
		"methods":         []string{"POST"},
		"source_ips":      []string{"10.0.0.0/8", "192.168.1.7"},
		"effective_from":  int64(1000),
		"effective_until": int64(2000),
		"rule_refs": []map[string]any{
			{"detector_id": "api_schema", "rule_id": "schema.extra_field", "model_version": "mv-1"},
			{"detector_id": "api_parser", "rule_id": "parser.multi_value"},
		},
	}
}

func mustParseAPIExceptions(t *testing.T, sec map[string]any) map[string][]APIException {
	t.Helper()
	raw, err := json.Marshal(sec)
	if err != nil {
		t.Fatal(err)
	}
	out, err := ParseAPIExceptionsSection(raw)
	if err != nil {
		t.Fatalf("parse failed: %v", err)
	}
	return out
}

// 合法段完整解码：key=应用编码，字段逐字对应，methods 标准化大写。
func TestParseAPIExceptionsSectionValid(t *testing.T) {
	sec := map[string]any{"shop": []any{baseAPIExceptionJSON()}}
	out := mustParseAPIExceptions(t, sec)
	list := out["shop"]
	if len(list) != 1 {
		t.Fatalf("list len=%d", len(list))
	}
	exc := list[0]
	if exc.SchemaVersion != 1 || exc.ExceptionID != "exc-uuid-1" || exc.Version != 2 {
		t.Fatalf("identity fields: %+v", exc)
	}
	if exc.Domain != "api.example.com" || exc.URIPrefix != "/api/orders" || exc.URIExact != "" {
		t.Fatalf("scope fields: %+v", exc)
	}
	if len(exc.RuleRefs) != 2 || exc.RuleRefs[0].DetectorID != "api_schema" ||
		exc.RuleRefs[0].RuleID != "schema.extra_field" || exc.RuleRefs[0].ModelVersion != "mv-1" {
		t.Fatalf("rule refs: %+v", exc.RuleRefs)
	}
	if exc.EffectiveFrom == nil || *exc.EffectiveFrom != 1000 || exc.EffectiveUntil == nil || *exc.EffectiveUntil != 2000 {
		t.Fatalf("time bounds: %+v", exc)
	}

	// methods 小写输入就地标准化为大写（纵深防御，发布侧已标准化）
	lower := baseAPIExceptionJSON()
	lower["methods"] = []string{"post"}
	out = mustParseAPIExceptions(t, map[string]any{"shop": []any{lower}})
	if out["shop"][0].Methods[0] != "POST" {
		t.Fatalf("methods must normalize to upper case, got %q", out["shop"][0].Methods[0])
	}
}

// 解析严格性（fail-closed）：任一违反基线约束即整段拒绝加载。
func TestParseAPIExceptionsSectionStrict(t *testing.T) {
	mutate := func(fn func(e map[string]any)) map[string]any {
		e := baseAPIExceptionJSON()
		fn(e)
		return map[string]any{"shop": []any{e}}
	}
	cases := []struct {
		name    string
		raw     string         // 非空时直接作为输入（覆盖结构级问题）
		section map[string]any // 否则用变异后的条目
	}{
		{name: "unknown field", raw: `{"shop":[{"schema_version":1,"exception_id":"e","version":1,"uri_exact":"/a","methods":["GET"],"rule_refs":[{"detector_id":"api_schema","rule_id":"r"}],"action":"ALLOW_ALL"}]}`},
		{name: "unknown nested field", raw: `{"shop":[{"schema_version":1,"exception_id":"e","version":1,"uri_exact":"/a","methods":["GET"],"rule_refs":[{"detector_id":"api_schema","rule_id":"r","note":"x"}]}]}`},
		{name: "trailing content", raw: `{"shop":[]} {"extra":1}`},
		{name: "not an object", raw: `[{"schema_version":1}]`},
		{name: "schema_version 2", section: mutate(func(e map[string]any) { e["schema_version"] = 2 })},
		{name: "schema_version missing", section: mutate(func(e map[string]any) { delete(e, "schema_version") })},
		{name: "exception_id empty", section: mutate(func(e map[string]any) { e["exception_id"] = "" })},
		{name: "methods empty", section: mutate(func(e map[string]any) { e["methods"] = []string{} })},
		{name: "methods missing", section: mutate(func(e map[string]any) { delete(e, "methods") })},
		{name: "methods blank entry", section: mutate(func(e map[string]any) { e["methods"] = []string{" "} })},
		{name: "both uri_exact and uri_prefix", section: mutate(func(e map[string]any) { e["uri_exact"] = "/api/orders" })},
		{name: "neither uri dimension", section: mutate(func(e map[string]any) { delete(e, "uri_prefix") })},
		{name: "prefix without leading slash", section: mutate(func(e map[string]any) { e["uri_prefix"] = "api/orders" })},
		{name: "rule_refs empty", section: mutate(func(e map[string]any) { e["rule_refs"] = []any{} })},
		// EXC-11：注册表外 detector 一律拒绝（waf/jwt/cc 等不可经 API 例外豁免）
		{name: "EXC-11 detector waf rejected", section: mutate(func(e map[string]any) {
			e["rule_refs"] = []map[string]any{{"detector_id": "waf", "rule_id": "942100"}}
		})},
		{name: "EXC-11 detector jwt rejected", section: mutate(func(e map[string]any) {
			e["rule_refs"] = []map[string]any{{"detector_id": "jwt", "rule_id": "jwt.expired"}}
		})},
		{name: "EXC-11 detector unknown rejected", section: mutate(func(e map[string]any) {
			e["rule_refs"] = []map[string]any{{"detector_id": "api_behavior", "rule_id": "x"}}
		})},
		{name: "rule_id empty", section: mutate(func(e map[string]any) {
			e["rule_refs"] = []map[string]any{{"detector_id": "api_schema", "rule_id": ""}}
		})},
		{name: "source_ips invalid", section: mutate(func(e map[string]any) { e["source_ips"] = []string{"999.1.2.3"} })},
		{name: "source_ips garbage", section: mutate(func(e map[string]any) { e["source_ips"] = []string{"not-an-ip"} })},
		{name: "from after until", section: mutate(func(e map[string]any) {
			e["effective_from"] = int64(3000)
			e["effective_until"] = int64(2000)
		})},
		{name: "from equals until", section: mutate(func(e map[string]any) {
			e["effective_from"] = int64(2000)
			e["effective_until"] = int64(2000)
		})},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			raw := tc.raw
			if raw == "" {
				b, err := json.Marshal(tc.section)
				if err != nil {
					t.Fatal(err)
				}
				raw = string(b)
			}
			out, err := ParseAPIExceptionsSection(json.RawMessage(raw))
			if err == nil {
				t.Fatalf("must reject (fail-closed), got %+v", out)
			}
		})
	}
}

// 范围逐维度翻折（EXC-01 AND 语义）：基线全匹配适用；每维度单独不满足即不适用。
func TestFilterAPIExceptionsScopeANDPerDimension(t *testing.T) {
	out := mustParseAPIExceptions(t, map[string]any{"shop": []any{baseAPIExceptionJSON()}})
	list := out["shop"]

	// 基线：全部维度满足 → 适用，展开为规则引用级 ExceptionRef（携带 ID/Version 溯源）
	refs := FilterAPIExceptions(list, "api.example.com", "/api/orders", "POST", "10.1.2.3", 1500)
	if len(refs) != 2 {
		t.Fatalf("baseline must apply with 2 rule refs, got %+v", refs)
	}
	if refs[0].ExceptionID != "exc-uuid-1" || refs[0].Version != 2 ||
		refs[0].DetectorID != "api_schema" || refs[0].RuleID != "schema.extra_field" || refs[0].ModelVersion != "mv-1" {
		t.Fatalf("ref[0] expansion wrong: %+v", refs[0])
	}
	if refs[1].ExceptionID != "exc-uuid-1" || refs[1].Version != 2 ||
		refs[1].DetectorID != "api_parser" || refs[1].RuleID != "parser.multi_value" || refs[1].ModelVersion != "" {
		t.Fatalf("ref[1] expansion wrong: %+v", refs[1])
	}

	flips := []struct {
		name                           string
		domain, path, method, clientIP string
		now                            int64
	}{
		{"domain mismatch", "other.example.com", "/api/orders", "POST", "10.1.2.3", 1500},
		{"path outside prefix", "api.example.com", "/api/users", "POST", "10.1.2.3", 1500},
		{"method not member", "api.example.com", "/api/orders", "GET", "10.1.2.3", 1500},
		{"ip outside set", "api.example.com", "/api/orders", "POST", "8.8.8.8", 1500},
		{"before effective_from", "api.example.com", "/api/orders", "POST", "10.1.2.3", 999},
		{"at effective_until", "api.example.com", "/api/orders", "POST", "10.1.2.3", 2000},
	}
	for _, tc := range flips {
		t.Run(tc.name, func(t *testing.T) {
			if refs := FilterAPIExceptions(list, tc.domain, tc.path, tc.method, tc.clientIP, tc.now); refs != nil {
				t.Fatalf("single dimension unsatisfied must make exception inapplicable, got %+v", refs)
			}
		})
	}
}

// domain 维度：大小写不敏感、请求侧容忍 :端口（含 [v6]:port）；不同域名不匹配。
func TestFilterAPIExceptionsDomainMatching(t *testing.T) {
	sec := map[string]any{"shop": []any{map[string]any{
		"schema_version": 1, "exception_id": "e1", "version": 1,
		"domain": "API.Example.COM", "uri_exact": "/a", "methods": []string{"GET"},
		"rule_refs": []map[string]any{{"detector_id": "api_schema", "rule_id": "r1"}},
	}}}
	list := mustParseAPIExceptions(t, sec)["shop"]

	match := []string{"api.example.com", "API.EXAMPLE.COM", "api.example.com:8443", "Api.Example.Com:443"}
	for _, d := range match {
		if FilterAPIExceptions(list, d, "/a", "GET", "", 0) == nil {
			t.Fatalf("domain %q must match", d)
		}
	}
	noMatch := []string{"example.com", "api.example.com.evil.com", "api.example.comx:443"}
	for _, d := range noMatch {
		if refs := FilterAPIExceptions(list, d, "/a", "GET", "", 0); refs != nil {
			t.Fatalf("domain %q must not match, got %+v", d, refs)
		}
	}

	// 未配置 domain = 不限域名
	sec2 := map[string]any{"shop": []any{map[string]any{
		"schema_version": 1, "exception_id": "e2", "version": 1,
		"uri_exact": "/a", "methods": []string{"GET"},
		"rule_refs": []map[string]any{{"detector_id": "api_schema", "rule_id": "r1"}},
	}}}
	list2 := mustParseAPIExceptions(t, sec2)["shop"]
	if FilterAPIExceptions(list2, "anything.example.org", "/a", "GET", "", 0) == nil {
		t.Fatal("empty configured domain must not constrain")
	}
}

// path 维度：精确等值；按段前缀 ^prefix(?:/|$)——命中自身与子路径，不命中段外相似前缀。
func TestFilterAPIExceptionsPathMatching(t *testing.T) {
	mk := func(exact, prefix string) []APIException {
		e := map[string]any{
			"schema_version": 1, "exception_id": "e1", "version": 1,
			"methods":   []string{"GET"},
			"rule_refs": []map[string]any{{"detector_id": "api_schema", "rule_id": "r1"}},
		}
		if exact != "" {
			e["uri_exact"] = exact
		}
		if prefix != "" {
			e["uri_prefix"] = prefix
		}
		return mustParseAPIExceptions(t, map[string]any{"shop": []any{e}})["shop"]
	}

	exact := mk("/api/orders", "")
	if FilterAPIExceptions(exact, "", "/api/orders", "GET", "", 0) == nil {
		t.Fatal("uri_exact self must match")
	}
	for _, p := range []string{"/api/orders/", "/api/orders/1", "/api/Orders", "/api/orders?x=1"} {
		if refs := FilterAPIExceptions(exact, "", p, "GET", "", 0); refs != nil {
			t.Fatalf("uri_exact must not match %q, got %+v", p, refs)
		}
	}

	prefix := mk("", "/api/orders")
	for _, p := range []string{"/api/orders", "/api/orders/", "/api/orders/1/2"} {
		if FilterAPIExceptions(prefix, "", p, "GET", "", 0) == nil {
			t.Fatalf("uri_prefix must match %q", p)
		}
	}
	for _, p := range []string{"/api/ordersx", "/api/orders2", "/api", "/API/orders"} {
		if refs := FilterAPIExceptions(prefix, "", p, "GET", "", 0); refs != nil {
			t.Fatalf("uri_prefix must not match %q (segment boundary), got %+v", p, refs)
		}
	}
}

// method 维度：大写集合成员；请求方法大小写不敏感归一后判定。
func TestFilterAPIExceptionsMethodMatching(t *testing.T) {
	sec := map[string]any{"shop": []any{map[string]any{
		"schema_version": 1, "exception_id": "e1", "version": 1,
		"uri_exact": "/a", "methods": []string{"GET", "POST"},
		"rule_refs": []map[string]any{{"detector_id": "api_schema", "rule_id": "r1"}},
	}}}
	list := mustParseAPIExceptions(t, sec)["shop"]
	for _, m := range []string{"GET", "POST", "post", "Post"} {
		if FilterAPIExceptions(list, "", "/a", m, "", 0) == nil {
			t.Fatalf("method %q must match", m)
		}
	}
	for _, m := range []string{"DELETE", "PUT", ""} {
		if refs := FilterAPIExceptions(list, "", "/a", m, "", 0); refs != nil {
			t.Fatalf("method %q must not match, got %+v", m, refs)
		}
	}
}

// clientIP 维度：精确 IP 与 CIDR（含 IPv6）；非法/空字符串不匹配任何带 source_ips
// 的例外（XFF 伪造无关性——入参即可信值，伪造字符串直接不命中，不放大范围）。
func TestFilterAPIExceptionsSourceIPMatching(t *testing.T) {
	sec := map[string]any{"shop": []any{map[string]any{
		"schema_version": 1, "exception_id": "e1", "version": 1,
		"uri_exact": "/a", "methods": []string{"GET"},
		"source_ips": []string{"10.0.0.0/8", "192.168.1.7", "2001:db8::/32"},
		"rule_refs":  []map[string]any{{"detector_id": "api_schema", "rule_id": "r1"}},
	}}}
	list := mustParseAPIExceptions(t, sec)["shop"]

	match := []string{"10.255.0.1", "192.168.1.7", "2001:db8::1", "::ffff:10.1.2.3"}
	for _, ip := range match {
		if FilterAPIExceptions(list, "", "/a", "GET", ip, 0) == nil {
			t.Fatalf("clientIP %q must match", ip)
		}
	}
	// 伪造/非法字符串（典型 XFF 注入形态）一律不匹配带 source_ips 的例外
	noMatch := []string{"8.8.8.8", "192.168.1.8", "2001:db9::1", "", "not-an-ip",
		"10.1.2.3, 1.2.3.4", "10.1.2.3;DROP", "999.999.1.1"}
	for _, ip := range noMatch {
		if refs := FilterAPIExceptions(list, "", "/a", "GET", ip, 0); refs != nil {
			t.Fatalf("clientIP %q must not match, got %+v", ip, refs)
		}
	}

	// 未配置 source_ips = 不限来源（非法入参字符串亦不产生差异）
	sec2 := map[string]any{"shop": []any{map[string]any{
		"schema_version": 1, "exception_id": "e2", "version": 1,
		"uri_exact": "/a", "methods": []string{"GET"},
		"rule_refs": []map[string]any{{"detector_id": "api_schema", "rule_id": "r1"}},
	}}}
	list2 := mustParseAPIExceptions(t, sec2)["shop"]
	if FilterAPIExceptions(list2, "", "/a", "GET", "garbage", 0) == nil {
		t.Fatal("no source_ips configured must not constrain")
	}
}

// 时间维度：半开区间 [from, until)——起前/恰终不适用，起点/终前适用；nil 端不限。
func TestFilterAPIExceptionsTimeHalfOpen(t *testing.T) {
	mk := func(from, until *int64) []APIException {
		e := map[string]any{
			"schema_version": 1, "exception_id": "e1", "version": 1,
			"uri_exact": "/a", "methods": []string{"GET"},
			"rule_refs": []map[string]any{{"detector_id": "api_schema", "rule_id": "r1"}},
		}
		if from != nil {
			e["effective_from"] = *from
		}
		if until != nil {
			e["effective_until"] = *until
		}
		return mustParseAPIExceptions(t, map[string]any{"shop": []any{e}})["shop"]
	}
	i64 := func(v int64) *int64 { return &v }

	bounded := mk(i64(1000), i64(2000))
	cases := []struct {
		now  int64
		want bool
	}{
		{999, false},  // 起前
		{1000, true},  // 起点（包含）
		{1999, true},  // 终前
		{2000, false}, // 恰终（不包含）
		{2001, false}, // 终后
	}
	for _, tc := range cases {
		got := FilterAPIExceptions(bounded, "", "/a", "GET", "", tc.now) != nil
		if got != tc.want {
			t.Fatalf("now=%d: applicable=%v, want %v", tc.now, got, tc.want)
		}
	}

	if FilterAPIExceptions(mk(nil, i64(2000)), "", "/a", "GET", "", 0) == nil {
		t.Fatal("nil from must be unbounded below")
	}
	if FilterAPIExceptions(mk(i64(1000), nil), "", "/a", "GET", "", 1<<40) == nil {
		t.Fatal("nil until must be unbounded above")
	}
	if FilterAPIExceptions(mk(nil, nil), "", "/a", "GET", "", 123456) == nil {
		t.Fatal("no time fields must not constrain")
	}
}

// 多例外展开：list 顺序保持（决策侧先入例外优先）；均不适用时返回 nil。
func TestFilterAPIExceptionsMultipleOrdering(t *testing.T) {
	sec := map[string]any{"shop": []any{
		map[string]any{
			"schema_version": 1, "exception_id": "exc-a", "version": 1,
			"uri_prefix": "/api", "methods": []string{"POST"},
			"rule_refs": []map[string]any{{"detector_id": "api_schema", "rule_id": "r1"}},
		},
		map[string]any{
			"schema_version": 1, "exception_id": "exc-b", "version": 5,
			"uri_exact": "/api/orders", "methods": []string{"POST"},
			"rule_refs": []map[string]any{
				{"detector_id": "api_schema", "rule_id": "r2"},
				{"detector_id": "api_parser", "rule_id": "r3"},
			},
		},
	}}
	list := mustParseAPIExceptions(t, sec)["shop"]

	refs := FilterAPIExceptions(list, "", "/api/orders", "POST", "", 0)
	if len(refs) != 3 {
		t.Fatalf("both exceptions apply, refs=%+v", refs)
	}
	if refs[0].ExceptionID != "exc-a" || refs[1].ExceptionID != "exc-b" || refs[2].ExceptionID != "exc-b" {
		t.Fatalf("list order must be preserved (first-match priority upstream), refs=%+v", refs)
	}
	if refs[2].Version != 5 || refs[2].RuleID != "r3" {
		t.Fatalf("ref expansion wrong: %+v", refs[2])
	}

	// 仅 exc-b 的路径适用
	refs = FilterAPIExceptions(list, "", "/api/other", "POST", "", 0)
	if len(refs) != 1 || refs[0].ExceptionID != "exc-a" {
		t.Fatalf("only prefix exception applies, refs=%+v", refs)
	}

	if refs := FilterAPIExceptions(list, "", "/api/orders", "DELETE", "", 0); refs != nil {
		t.Fatalf("none applicable must return nil, got %+v", refs)
	}
	if refs := FilterAPIExceptions(nil, "", "/api/orders", "POST", "", 0); refs != nil {
		t.Fatalf("empty list must return nil, got %+v", refs)
	}
}

// 解析错误信息须可定位（应用编码/下标/exception_id），供装配 fail-closed 时排障。
func TestParseAPIExceptionsSectionErrorContext(t *testing.T) {
	sec := map[string]any{"shop-api": []any{
		baseAPIExceptionJSON(),
		func() map[string]any {
			e := baseAPIExceptionJSON()
			e["exception_id"] = "bad-one"
			e["methods"] = []string{}
			return e
		}(),
	}}
	raw, err := json.Marshal(sec)
	if err != nil {
		t.Fatal(err)
	}
	_, err = ParseAPIExceptionsSection(raw)
	if err == nil {
		t.Fatal("must reject")
	}
	msg := err.Error()
	if !strings.Contains(msg, "shop-api") || !strings.Contains(msg, "bad-one") {
		t.Fatalf("error must carry app code and exception_id for triage: %v", err)
	}
}

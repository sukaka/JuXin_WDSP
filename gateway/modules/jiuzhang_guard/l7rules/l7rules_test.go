package l7rules

import (
	"fmt"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"strings"
	"testing"
)

// mustCompile 编译配置并要求零拒绝。
func mustCompile(t *testing.T, cfg *Config) *Engine {
	t.Helper()
	eng, errs := Compile(cfg)
	if len(errs) > 0 {
		t.Fatalf("compile rejected: %+v", errs)
	}
	return eng
}

// newReq 构造测试请求（path 可带 query）。
func newReq(t *testing.T, method, target string) *http.Request {
	t.Helper()
	return httptest.NewRequest(method, "http://example.com"+target, nil)
}

var testIP = netip.MustParseAddr("192.168.1.5")

// allowRule 便捷构造：单条件 allow 规则。
func allowRule(id string, priority int, conds ...ConditionJSON) RuleJSON {
	return RuleJSON{ID: id, Name: id, Priority: priority, Enabled: true, Conditions: conds, Action: "allow"}
}

func evalOnce(t *testing.T, eng *Engine, r *http.Request, ip string) (Decision, bool) {
	t.Helper()
	return eng.Eval(r, netip.MustParseAddr(ip))
}

// ---------- 各 type × op 匹配矩阵 ----------

func TestURIConditions(t *testing.T) {
	cases := []struct {
		name   string
		cond   ConditionJSON
		target string
		want   bool
	}{
		{"eq命中", ConditionJSON{Type: "uri", Op: "eq", Value: "/admin"}, "/admin", true},
		{"eq不命中", ConditionJSON{Type: "uri", Op: "eq", Value: "/admin"}, "/admin/", false},
		{"eq大小写敏感", ConditionJSON{Type: "uri", Op: "eq", Value: "/Admin"}, "/admin", false},
		{"ne命中", ConditionJSON{Type: "uri", Op: "ne", Value: "/admin"}, "/user", true},
		{"ne不命中", ConditionJSON{Type: "uri", Op: "ne", Value: "/admin"}, "/admin", false},
		{"prefix命中", ConditionJSON{Type: "uri", Op: "prefix", Value: "/admin"}, "/admin/users", true},
		{"prefix边界", ConditionJSON{Type: "uri", Op: "prefix", Value: "/admin"}, "/administrator", true}, // 纯字符串前缀，/administrator 命中 /admin
		{"prefix不命中", ConditionJSON{Type: "uri", Op: "prefix", Value: "/admin"}, "/user", false},
		{"contains命中", ConditionJSON{Type: "uri", Op: "contains", Value: "adm"}, "/x/admin/y", true},
		{"contains不命中", ConditionJSON{Type: "uri", Op: "contains", Value: "adm"}, "/user", false},
		{"regex命中", ConditionJSON{Type: "uri", Op: "regex", Value: `^/api/v\d+/users$`}, "/api/v2/users", true},
		{"regex不命中", ConditionJSON{Type: "uri", Op: "regex", Value: `^/api/v\d+/users$`}, "/api/v2/orders", false},
		{"in命中", ConditionJSON{Type: "uri", Op: "in", Values: []string{"/a", "/b"}}, "/b", true},
		{"in不命中", ConditionJSON{Type: "uri", Op: "in", Values: []string{"/a", "/b"}}, "/c", false},
		{"空路径归一为根", ConditionJSON{Type: "uri", Op: "eq", Value: "/"}, "", true},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			eng := mustCompile(t, &Config{Rules: []RuleJSON{allowRule("r1", 1, tc.cond)}})
			target := tc.target
			if target == "" {
				target = "/"
			}
			r := newReq(t, "GET", target)
			if target != tc.target {
				r.URL.Path = "" // 显式构造空路径
			}
			_, got := evalOnce(t, eng, r, "192.168.1.5")
			if got != tc.want {
				t.Fatalf("want %v, got %v", tc.want, got)
			}
		})
	}
}

func TestMethodCondition(t *testing.T) {
	eng := mustCompile(t, &Config{Rules: []RuleJSON{
		allowRule("r1", 1, ConditionJSON{Type: "method", Values: []string{"GET", "post"}}),
	}})
	// 配置小写 post 归一为大写；请求方法统一大写比较（大小写不敏感）
	for _, m := range []string{"GET", "POST"} {
		if _, ok := evalOnce(t, eng, newReq(t, m, "/x"), "192.168.1.5"); !ok {
			t.Fatalf("method %s should match", m)
		}
	}
	if _, ok := evalOnce(t, eng, newReq(t, "PUT", "/x"), "192.168.1.5"); ok {
		t.Fatal("PUT should not match")
	}
}

func TestHeaderConditions(t *testing.T) {
	cases := []struct {
		name    string
		cond    ConditionJSON
		headers map[string]string
		want    bool
	}{
		{"eq命中", ConditionJSON{Type: "header", Name: "X-Env", Op: "eq", Value: "prod"}, map[string]string{"X-Env": "prod"}, true},
		{"eq值大小写敏感", ConditionJSON{Type: "header", Name: "X-Env", Op: "eq", Value: "Prod"}, map[string]string{"X-Env": "prod"}, false},
		{"名大小写不敏感", ConditionJSON{Type: "header", Name: "x-env", Op: "eq", Value: "prod"}, map[string]string{"X-Env": "prod"}, true},
		{"ne命中", ConditionJSON{Type: "header", Name: "X-Env", Op: "ne", Value: "prod"}, map[string]string{"X-Env": "test"}, true},
		{"ne缺头不命中", ConditionJSON{Type: "header", Name: "X-Env", Op: "ne", Value: "prod"}, nil, false},
		{"eq缺头不命中", ConditionJSON{Type: "header", Name: "X-Env", Op: "eq", Value: "prod"}, nil, false},
		{"prefix命中", ConditionJSON{Type: "header", Name: "User-Agent", Op: "prefix", Value: "curl"}, map[string]string{"User-Agent": "curl/8.0"}, true},
		{"contains命中", ConditionJSON{Type: "header", Name: "User-Agent", Op: "contains", Value: "bot"}, map[string]string{"User-Agent": "my-bot/1.0"}, true},
		{"regex命中", ConditionJSON{Type: "header", Name: "X-Req", Op: "regex", Value: `^\d{4}$`}, map[string]string{"X-Req": "1234"}, true},
		{"exists命中", ConditionJSON{Type: "header", Name: "X-Token", Op: "exists"}, map[string]string{"X-Token": ""}, true},
		{"exists不命中", ConditionJSON{Type: "header", Name: "X-Token", Op: "exists"}, nil, false},
		{"not_exists命中", ConditionJSON{Type: "header", Name: "X-Token", Op: "not_exists"}, nil, true},
		{"not_exists不命中", ConditionJSON{Type: "header", Name: "X-Token", Op: "not_exists"}, map[string]string{"X-Token": "v"}, false},
		{"in命中", ConditionJSON{Type: "header", Name: "X-Env", Op: "in", Values: []string{"prod", "staging"}}, map[string]string{"X-Env": "staging"}, true},
		{"in缺头不命中", ConditionJSON{Type: "header", Name: "X-Env", Op: "in", Values: []string{"prod"}}, nil, false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			eng := mustCompile(t, &Config{Rules: []RuleJSON{allowRule("r1", 1, tc.cond)}})
			r := newReq(t, "GET", "/x")
			for k, v := range tc.headers {
				r.Header.Set(k, v)
			}
			_, got := evalOnce(t, eng, r, "192.168.1.5")
			if got != tc.want {
				t.Fatalf("want %v, got %v", tc.want, got)
			}
		})
	}
}

func TestCookieConditions(t *testing.T) {
	cases := []struct {
		name   string
		cond   ConditionJSON
		cookie string // Cookie 头原始值
		want   bool
	}{
		{"exists命中", ConditionJSON{Type: "cookie", Name: "session", Op: "exists"}, "session=abc", true},
		{"exists不命中", ConditionJSON{Type: "cookie", Name: "session", Op: "exists"}, "other=abc", false},
		{"not_exists命中", ConditionJSON{Type: "cookie", Name: "session", Op: "not_exists"}, "", true},
		{"eq命中", ConditionJSON{Type: "cookie", Name: "session", Op: "eq", Value: "abc"}, "session=abc", true},
		{"eq名大小写敏感", ConditionJSON{Type: "cookie", Name: "Session", Op: "eq", Value: "abc"}, "session=abc", false},
		{"ne缺cookie不命中", ConditionJSON{Type: "cookie", Name: "session", Op: "ne", Value: "abc"}, "", false},
		{"多cookie取目标", ConditionJSON{Type: "cookie", Name: "b", Op: "eq", Value: "2"}, "a=1; b=2; c=3", true},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			eng := mustCompile(t, &Config{Rules: []RuleJSON{allowRule("r1", 1, tc.cond)}})
			r := newReq(t, "GET", "/x")
			if tc.cookie != "" {
				r.Header.Set("Cookie", tc.cookie)
			}
			_, got := evalOnce(t, eng, r, "192.168.1.5")
			if got != tc.want {
				t.Fatalf("want %v, got %v", tc.want, got)
			}
		})
	}
}

func TestQueryConditions(t *testing.T) {
	cases := []struct {
		name   string
		cond   ConditionJSON
		target string
		want   bool
	}{
		{"eq命中", ConditionJSON{Type: "query", Name: "debug", Op: "eq", Value: "1"}, "/x?debug=1", true},
		{"eq不命中", ConditionJSON{Type: "query", Name: "debug", Op: "eq", Value: "1"}, "/x?debug=0", false},
		{"ne命中", ConditionJSON{Type: "query", Name: "debug", Op: "ne", Value: "1"}, "/x?debug=0", true},
		{"ne缺参不命中", ConditionJSON{Type: "query", Name: "debug", Op: "ne", Value: "1"}, "/x", false},
		{"exists命中", ConditionJSON{Type: "query", Name: "debug", Op: "exists"}, "/x?debug", true},
		{"exists不命中", ConditionJSON{Type: "query", Name: "debug", Op: "exists"}, "/x?a=1", false},
		{"not_exists命中", ConditionJSON{Type: "query", Name: "debug", Op: "not_exists"}, "/x?a=1", true},
		{"名大小写敏感", ConditionJSON{Type: "query", Name: "Debug", Op: "exists"}, "/x?debug=1", false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			eng := mustCompile(t, &Config{Rules: []RuleJSON{allowRule("r1", 1, tc.cond)}})
			_, got := evalOnce(t, eng, newReq(t, "GET", tc.target), "192.168.1.5")
			if got != tc.want {
				t.Fatalf("want %v, got %v", tc.want, got)
			}
		})
	}
}

func TestClientIPCondition(t *testing.T) {
	eng := mustCompile(t, &Config{Rules: []RuleJSON{
		allowRule("r1", 1, ConditionJSON{Type: "client_ip", Values: []string{"10.0.0.0/8", "192.168.1.5", "2001:db8::/32"}}),
	}})
	for ip, want := range map[string]bool{
		"192.168.1.5":     true,  // 单 IP 精确
		"10.9.8.7":        true,  // CIDR
		"192.168.1.6":     false, // 同段不同地址
		"172.16.0.1":      false,
		"2001:db8::1":     true, // IPv6 CIDR
		"2001:db9::1":     false,
		"::ffff:10.1.2.3": true, // IPv4 映射 IPv6 归一后命中 CIDR
	} {
		if _, got := evalOnce(t, eng, newReq(t, "GET", "/x"), ip); got != want {
			t.Fatalf("ip %s: want %v, got %v", ip, want, got)
		}
	}
}

// ---------- 多条件 AND / 优先级 / disabled ----------

func TestMultiConditionAND(t *testing.T) {
	eng := mustCompile(t, &Config{Rules: []RuleJSON{
		allowRule("r1", 1,
			ConditionJSON{Type: "uri", Op: "prefix", Value: "/admin"},
			ConditionJSON{Type: "method", Values: []string{"GET", "POST"}},
			ConditionJSON{Type: "header", Name: "X-Env", Op: "eq", Value: "prod"},
			ConditionJSON{Type: "cookie", Name: "session", Op: "exists"},
			ConditionJSON{Type: "query", Name: "debug", Op: "ne", Value: "1"},
			ConditionJSON{Type: "client_ip", Values: []string{"10.0.0.0/8"}},
		),
	}})
	full := func() *http.Request {
		r := newReq(t, "GET", "/admin/panel?debug=0")
		r.Header.Set("X-Env", "prod")
		r.Header.Set("Cookie", "session=abc")
		return r
	}
	if _, ok := evalOnce(t, eng, full(), "10.1.2.3"); !ok {
		t.Fatal("全条件满足应命中")
	}
	// 任一条件不满足即不命中
	bad := []struct {
		name string
		mut  func(r *http.Request)
		ip   string
	}{
		{"uri不符", func(r *http.Request) { r.URL.Path = "/user" }, "10.1.2.3"},
		{"method不符", func(r *http.Request) { r.Method = "DELETE" }, "10.1.2.3"},
		{"header不符", func(r *http.Request) { r.Header.Set("X-Env", "test") }, "10.1.2.3"},
		{"cookie缺失", func(r *http.Request) { r.Header.Del("Cookie") }, "10.1.2.3"},
		{"query不符", func(r *http.Request) { r.URL.RawQuery = "debug=1" }, "10.1.2.3"},
		{"ip不符", func(r *http.Request) {}, "172.16.0.1"},
	}
	for _, b := range bad {
		r := full()
		b.mut(r)
		if _, ok := evalOnce(t, eng, r, b.ip); ok {
			t.Fatalf("%s：不应命中", b.name)
		}
	}
}

func TestPriorityFirstMatch(t *testing.T) {
	mk := func(id string, prio int, action string) RuleJSON {
		return RuleJSON{
			ID: id, Name: id, Priority: prio, Enabled: true,
			Conditions: []ConditionJSON{{Type: "uri", Op: "prefix", Value: "/admin"}},
			Action:     action,
		}
	}
	// 配置顺序与优先级相反：priority 小者先评估且首中即停
	eng := mustCompile(t, &Config{Rules: []RuleJSON{
		mk("block-low-prio-number-wins", 200, "block"),
		mk("allow-first", 100, "allow"),
	}})
	dec, ok := evalOnce(t, eng, newReq(t, "GET", "/admin/x"), "192.168.1.5")
	if !ok || dec.RuleID != "allow-first" || dec.Action != ActionAllow {
		t.Fatalf("priority 100 应先命中: %+v ok=%v", dec, ok)
	}

	// 同优先级：保持下发顺序（稳定排序）
	eng2 := mustCompile(t, &Config{Rules: []RuleJSON{
		mk("first-in-order", 100, "block"),
		mk("second-in-order", 100, "allow"),
	}})
	dec, ok = evalOnce(t, eng2, newReq(t, "GET", "/admin/x"), "192.168.1.5")
	if !ok || dec.RuleID != "first-in-order" {
		t.Fatalf("同优先级应保持下发顺序: %+v ok=%v", dec, ok)
	}
}

func TestDisabledRuleSkipped(t *testing.T) {
	r := allowRule("r1", 1, ConditionJSON{Type: "uri", Op: "prefix", Value: "/admin"})
	r.Enabled = false
	eng := mustCompile(t, &Config{Rules: []RuleJSON{r}})
	if _, ok := evalOnce(t, eng, newReq(t, "GET", "/admin"), "192.168.1.5"); ok {
		t.Fatal("disabled 规则必须跳过")
	}
}

func TestNoMatchFallsThrough(t *testing.T) {
	if _, ok := evalOnce(t, mustCompile(t, &Config{}), newReq(t, "GET", "/x"), "192.168.1.5"); ok {
		t.Fatal("空规则集不应命中")
	}
	var nilEngine *Engine
	if _, ok := nilEngine.Eval(newReq(t, "GET", "/x"), testIP); ok {
		t.Fatal("nil engine 不应命中")
	}
	if _, ok := mustCompile(t, nil).Eval(newReq(t, "GET", "/x"), testIP); ok {
		t.Fatal("nil config 不应命中")
	}
}

// ---------- 编译拒绝矩阵 ----------

func TestCompileRejections(t *testing.T) {
	validConds := []ConditionJSON{{Type: "uri", Op: "prefix", Value: "/a"}}
	cases := []struct {
		name string
		rule RuleJSON
	}{
		{"空ID", RuleJSON{Name: "x", Priority: 1, Enabled: true, Conditions: validConds, Action: "allow"}},
		{"空条件", RuleJSON{ID: "r", Priority: 1, Enabled: true, Action: "allow"}},
		{"条件超限", RuleJSON{ID: "r", Priority: 1, Enabled: true, Action: "allow", Conditions: func() []ConditionJSON {
			out := make([]ConditionJSON, 11)
			for i := range out {
				out[i] = ConditionJSON{Type: "uri", Op: "prefix", Value: "/a"}
			}
			return out
		}()}},
		{"未知类型", RuleJSON{ID: "r", Priority: 1, Enabled: true, Action: "allow", Conditions: []ConditionJSON{{Type: "body", Op: "eq", Value: "x"}}}},
		{"未知op", RuleJSON{ID: "r", Priority: 1, Enabled: true, Action: "allow", Conditions: []ConditionJSON{{Type: "uri", Op: "glob", Value: "x"}}}},
		{"uri不支持exists", RuleJSON{ID: "r", Priority: 1, Enabled: true, Action: "allow", Conditions: []ConditionJSON{{Type: "uri", Op: "exists"}}}},
		{"坏正则", RuleJSON{ID: "r", Priority: 1, Enabled: true, Action: "allow", Conditions: []ConditionJSON{{Type: "uri", Op: "regex", Value: "([a-z"}}}},
		{"正则超长", RuleJSON{ID: "r", Priority: 1, Enabled: true, Action: "allow", Conditions: []ConditionJSON{{Type: "uri", Op: "regex", Value: strings.Repeat("a", 513)}}}},
		{"header名非法", RuleJSON{ID: "r", Priority: 1, Enabled: true, Action: "allow", Conditions: []ConditionJSON{{Type: "header", Name: "X Bad", Op: "exists"}}}},
		{"header缺名", RuleJSON{ID: "r", Priority: 1, Enabled: true, Action: "allow", Conditions: []ConditionJSON{{Type: "header", Op: "exists"}}}},
		{"query名空白", RuleJSON{ID: "r", Priority: 1, Enabled: true, Action: "allow", Conditions: []ConditionJSON{{Type: "query", Name: "a b", Op: "exists"}}}},
		{"method缺values", RuleJSON{ID: "r", Priority: 1, Enabled: true, Action: "allow", Conditions: []ConditionJSON{{Type: "method"}}}},
		{"method错用op", RuleJSON{ID: "r", Priority: 1, Enabled: true, Action: "allow", Conditions: []ConditionJSON{{Type: "method", Op: "eq", Value: "GET"}}}},
		{"method非法值", RuleJSON{ID: "r", Priority: 1, Enabled: true, Action: "allow", Conditions: []ConditionJSON{{Type: "method", Values: []string{"G E T"}}}}},
		{"ip坏值", RuleJSON{ID: "r", Priority: 1, Enabled: true, Action: "allow", Conditions: []ConditionJSON{{Type: "client_ip", Values: []string{"999.1.2.3"}}}}},
		{"ip域名拒绝", RuleJSON{ID: "r", Priority: 1, Enabled: true, Action: "allow", Conditions: []ConditionJSON{{Type: "client_ip", Values: []string{"example.com"}}}}},
		{"未知动作", RuleJSON{ID: "r", Priority: 1, Enabled: true, Conditions: validConds, Action: "drop"}},
		{"block状态码越界", RuleJSON{ID: "r", Priority: 1, Enabled: true, Conditions: validConds, Action: "block", ActionConfig: ActionConfigJSON{Status: 302}}},
		{"redirect缺URL", RuleJSON{ID: "r", Priority: 1, Enabled: true, Conditions: validConds, Action: "redirect"}},
		{"redirect非http", RuleJSON{ID: "r", Priority: 1, Enabled: true, Conditions: validConds, Action: "redirect", ActionConfig: ActionConfigJSON{RedirectURL: "javascript:alert(1)"}}},
		{"redirect相对路径", RuleJSON{ID: "r", Priority: 1, Enabled: true, Conditions: validConds, Action: "redirect", ActionConfig: ActionConfigJSON{RedirectURL: "/login"}}},
		{"redirect状态码非法", RuleJSON{ID: "r", Priority: 1, Enabled: true, Conditions: validConds, Action: "redirect", ActionConfig: ActionConfigJSON{RedirectURL: "https://a.com/", RedirectStatus: 303}}},
		{"custom超限", RuleJSON{ID: "r", Priority: 1, Enabled: true, Conditions: validConds, Action: "custom_page", ActionConfig: ActionConfigJSON{Body: strings.Repeat("x", 64*1024+1)}}},
		{"custom坏contenttype", RuleJSON{ID: "r", Priority: 1, Enabled: true, Conditions: validConds, Action: "custom_page", ActionConfig: ActionConfigJSON{ContentType: "not a type"}}},
		{"custom状态码越界", RuleJSON{ID: "r", Priority: 1, Enabled: true, Conditions: validConds, Action: "custom_page", ActionConfig: ActionConfigJSON{Status: 100}}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			eng, errs := Compile(&Config{Rules: []RuleJSON{tc.rule}})
			if len(errs) != 1 {
				t.Fatalf("应整条拒绝: errs=%+v", errs)
			}
			if eng.RulesCount() != 0 {
				t.Fatal("被拒绝的规则不得进入引擎")
			}
		})
	}
}

func TestCompilePartialRejection(t *testing.T) {
	good := allowRule("good", 1, ConditionJSON{Type: "uri", Op: "prefix", Value: "/ok"})
	bad := RuleJSON{
		ID: "bad", Priority: 2, Enabled: true, Action: "redirect",
		Conditions:   []ConditionJSON{{Type: "uri", Op: "prefix", Value: "/bad"}},
		ActionConfig: ActionConfigJSON{RedirectURL: "ftp://evil/x"},
	}
	eng, errs := Compile(&Config{Rules: []RuleJSON{good, bad}})
	if len(errs) != 1 || errs[0].RuleID != "bad" {
		t.Fatalf("应仅拒绝 bad: %+v", errs)
	}
	if eng.RulesCount() != 1 {
		t.Fatal("good 应正常加载")
	}
	if _, ok := evalOnce(t, eng, newReq(t, "GET", "/ok/x"), "192.168.1.5"); !ok {
		t.Fatal("good 规则应可命中")
	}
}

func TestRulesCountLimit(t *testing.T) {
	rules := make([]RuleJSON, maxRules+5)
	for i := range rules {
		rules[i] = allowRule(fmt.Sprintf("r%d", i), 1, ConditionJSON{Type: "uri", Op: "prefix", Value: "/a"})
	}
	eng, errs := Compile(&Config{Rules: rules})
	if len(errs) != 1 {
		t.Fatalf("超限应记录一条整体拒绝: %+v", errs)
	}
	if eng.RulesCount() != maxRules {
		t.Fatalf("应截断至上限 %d, 实际 %d", maxRules, eng.RulesCount())
	}
}

// ---------- 动作配置默认值 ----------

func TestActionConfigDefaults(t *testing.T) {
	conds := []ConditionJSON{{Type: "uri", Op: "prefix", Value: "/a"}}
	eng := mustCompile(t, &Config{Rules: []RuleJSON{
		{ID: "b", Priority: 1, Enabled: true, Conditions: conds, Action: "block"},
	}})
	dec, ok := evalOnce(t, eng, newReq(t, "GET", "/a"), "192.168.1.5")
	if !ok || dec.Action != ActionBlock {
		t.Fatal("block 应命中")
	}
	if dec.Config.Status != 403 || dec.Config.Message != "访问被拦截" {
		t.Fatalf("block 默认值: %+v", dec.Config)
	}

	eng = mustCompile(t, &Config{Rules: []RuleJSON{
		{ID: "r", Priority: 1, Enabled: true, Conditions: conds, Action: "redirect",
			ActionConfig: ActionConfigJSON{RedirectURL: "https://example.com/login"}},
	}})
	dec, _ = evalOnce(t, eng, newReq(t, "GET", "/a"), "192.168.1.5")
	if dec.Config.RedirectStatus != 302 || dec.Config.RedirectURL != "https://example.com/login" {
		t.Fatalf("redirect 默认值: %+v", dec.Config)
	}

	eng = mustCompile(t, &Config{Rules: []RuleJSON{
		{ID: "c", Priority: 1, Enabled: true, Conditions: conds, Action: "custom_page",
			ActionConfig: ActionConfigJSON{Body: "<h1>维护中</h1>"}},
	}})
	dec, _ = evalOnce(t, eng, newReq(t, "GET", "/a"), "192.168.1.5")
	if dec.Config.Status != 200 || dec.Config.ContentType != "text/html; charset=utf-8" || dec.Config.Body != "<h1>维护中</h1>" {
		t.Fatalf("custom_page 默认值: %+v", dec.Config)
	}
}

// TestDecisionCarriesRuleMeta 决策携带规则 ID 与名称（事件归因用）。
func TestDecisionCarriesRuleMeta(t *testing.T) {
	eng := mustCompile(t, &Config{Rules: []RuleJSON{
		{ID: "uuid-1", Name: "管理后台拦截", Priority: 1, Enabled: true,
			Conditions: []ConditionJSON{{Type: "uri", Op: "prefix", Value: "/admin"}}, Action: "block"},
	}})
	dec, ok := evalOnce(t, eng, newReq(t, "GET", "/admin"), "192.168.1.5")
	if !ok || dec.RuleID != "uuid-1" || dec.RuleName != "管理后台拦截" {
		t.Fatalf("决策元数据: %+v ok=%v", dec, ok)
	}
}

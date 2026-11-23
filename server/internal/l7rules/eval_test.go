package l7rules

import (
	"testing"
	"time"

	"github.com/google/uuid"
)

// mkRule 构造一条已规范化的规则（单条件，block 动作）。
func mkRule(name string, priority int, createdAt time.Time, cond Condition) Rule {
	return Rule{
		ID:         uuid.New(),
		Name:       name,
		Priority:   priority,
		Enabled:    true,
		Conditions: []Condition{cond},
		Action:     ActionBlock,
		ActionConfig: ActionConfig{
			Status: 403, RedirectStatus: 302, ContentType: "text/html; charset=utf-8",
		},
		CreatedAt: createdAt,
	}
}

func baseInput() Input {
	return Input{
		URI:      "/admin/login",
		Method:   "GET",
		Headers:  map[string]string{"X-Env": "prod"},
		Cookies:  map[string]string{"session": "abc"},
		Query:    map[string]string{"debug": "0"},
		ClientIP: "10.1.2.3",
	}
}

// evalSingle 用单条规则评估，返回是否命中。
func evalSingle(t *testing.T, cond Condition, in Input) bool {
	t.Helper()
	ev, err := NewEvaluator([]Rule{mkRule("r", 100, time.Now(), cond)})
	if err != nil {
		t.Fatalf("编译失败: %v", err)
	}
	return ev.Eval(in).Matched
}

func TestEval_URIOps(t *testing.T) {
	in := baseInput()
	cases := []struct {
		name string
		cond Condition
		want bool
	}{
		{"eq命中", Condition{Type: "uri", Op: "eq", Value: "/admin/login"}, true},
		{"eq不命中", Condition{Type: "uri", Op: "eq", Value: "/admin"}, false},
		{"ne命中", Condition{Type: "uri", Op: "ne", Value: "/admin"}, true},
		{"prefix命中", Condition{Type: "uri", Op: "prefix", Value: "/admin"}, true},
		{"prefix不命中", Condition{Type: "uri", Op: "prefix", Value: "/user"}, false},
		{"contains命中", Condition{Type: "uri", Op: "contains", Value: "login"}, true},
		{"regex命中", Condition{Type: "uri", Op: "regex", Value: "^/admin/[a-z]+$"}, true},
		{"regex不命中", Condition{Type: "uri", Op: "regex", Value: "^/api/"}, false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := evalSingle(t, tc.cond, in); got != tc.want {
				t.Fatalf("got=%v want=%v", got, tc.want)
			}
		})
	}
	// URI 带 query：仅路径部分参与匹配
	inWithQuery := in
	inWithQuery.URI = "/admin/login?a=1"
	if !evalSingle(t, Condition{Type: "uri", Op: "eq", Value: "/admin/login"}, inWithQuery) {
		t.Fatal("带 query 的 URI 应按路径部分匹配")
	}
}

func TestEval_MethodAndClientIP(t *testing.T) {
	in := baseInput()
	// method：values 集合；输入小写转大写
	if !evalSingle(t, Condition{Type: "method", Values: []string{"GET", "POST"}}, in) {
		t.Fatal("method 应命中")
	}
	inLower := in
	inLower.Method = "get"
	if !evalSingle(t, Condition{Type: "method", Values: []string{"GET"}}, inLower) {
		t.Fatal("method 大小写不敏感")
	}
	if evalSingle(t, Condition{Type: "method", Values: []string{"POST"}}, in) {
		t.Fatal("method 不应命中")
	}
	// client_ip：单 IP / CIDR / v6
	if !evalSingle(t, Condition{Type: "client_ip", Values: []string{"10.1.2.3"}}, in) {
		t.Fatal("client_ip 单 IP 应命中")
	}
	if !evalSingle(t, Condition{Type: "client_ip", Values: []string{"10.0.0.0/8"}}, in) {
		t.Fatal("client_ip CIDR 应命中")
	}
	if evalSingle(t, Condition{Type: "client_ip", Values: []string{"192.168.0.0/16"}}, in) {
		t.Fatal("client_ip 不应命中")
	}
	in6 := in
	in6.ClientIP = "2001:db8::1"
	if !evalSingle(t, Condition{Type: "client_ip", Values: []string{"2001:db8::/32"}}, in6) {
		t.Fatal("client_ip IPv6 CIDR 应命中")
	}
	// 无 client_ip：条件不命中
	inNone := in
	inNone.ClientIP = ""
	if evalSingle(t, Condition{Type: "client_ip", Values: []string{"0.0.0.0/0"}}, inNone) {
		t.Fatal("无来源IP时 client_ip 条件不应命中")
	}
}

func TestEval_NamedConditions(t *testing.T) {
	in := baseInput()
	cases := []struct {
		name string
		cond Condition
		want bool
	}{
		{"header eq命中", Condition{Type: "header", Name: "X-Env", Op: "eq", Value: "prod"}, true},
		{"header名大小写不敏感", Condition{Type: "header", Name: "x-env", Op: "eq", Value: "prod"}, true},
		{"header eq值不等", Condition{Type: "header", Name: "X-Env", Op: "eq", Value: "Prod"}, false},
		{"header exists命中", Condition{Type: "header", Name: "X-Env", Op: "exists"}, true},
		{"header not_exists不命中", Condition{Type: "header", Name: "X-Env", Op: "not_exists"}, false},
		{"header缺失exists不命中", Condition{Type: "header", Name: "X-Other", Op: "exists"}, false},
		{"header缺失ne不命中", Condition{Type: "header", Name: "X-Other", Op: "ne", Value: "x"}, false},
		{"header缺失not_exists命中", Condition{Type: "header", Name: "X-Other", Op: "not_exists"}, true},
		{"cookie exists命中", Condition{Type: "cookie", Name: "session", Op: "exists"}, true},
		{"cookie名大小写敏感", Condition{Type: "cookie", Name: "Session", Op: "exists"}, false},
		{"query ne命中", Condition{Type: "query", Name: "debug", Op: "ne", Value: "1"}, true},
		{"query ne不命中", Condition{Type: "query", Name: "debug", Op: "ne", Value: "0"}, false},
		{"query regex命中", Condition{Type: "query", Name: "debug", Op: "regex", Value: "^[0-9]$"}, true},
		{"query缺失eq不命中", Condition{Type: "query", Name: "other", Op: "eq", Value: "1"}, false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := evalSingle(t, tc.cond, in); got != tc.want {
				t.Fatalf("got=%v want=%v", got, tc.want)
			}
		})
	}
}

func TestEval_MultiConditionAND(t *testing.T) {
	now := time.Now()
	rule := mkRule("组合", 100, now, Condition{Type: "uri", Op: "prefix", Value: "/admin"})
	rule.Conditions = append(rule.Conditions, Condition{Type: "method", Values: []string{"POST"}})
	ev, err := NewEvaluator([]Rule{rule})
	if err != nil {
		t.Fatal(err)
	}
	in := baseInput() // GET → 不命中
	if ev.Eval(in).Matched {
		t.Fatal("多条件 AND：一假应全假")
	}
	in.Method = "POST"
	if !ev.Eval(in).Matched {
		t.Fatal("多条件 AND：全真应命中")
	}
}

func TestEval_FirstMatchByPriority(t *testing.T) {
	now := time.Now()
	low := mkRule("低优先级", 200, now, Condition{Type: "uri", Op: "prefix", Value: "/"})
	high := mkRule("高优先级", 100, now.Add(time.Second), Condition{Type: "uri", Op: "prefix", Value: "/"})
	// 乱序传入，评估器内部排序
	ev, err := NewEvaluator([]Rule{low, high})
	if err != nil {
		t.Fatal(err)
	}
	res := ev.Eval(baseInput())
	if !res.Matched || res.Rule.Name != "高优先级" {
		t.Fatalf("首中即停应取优先级数值小者: %+v", res)
	}
	if res.Rule.Action != ActionBlock {
		t.Fatalf("命中动作异常: %s", res.Rule.Action)
	}
}

func TestEval_SamePriorityStableByCreatedAt(t *testing.T) {
	now := time.Now()
	older := mkRule("先建", 100, now, Condition{Type: "uri", Op: "prefix", Value: "/"})
	newer := mkRule("后建", 100, now.Add(time.Minute), Condition{Type: "uri", Op: "prefix", Value: "/"})
	ev, err := NewEvaluator([]Rule{newer, older})
	if err != nil {
		t.Fatal(err)
	}
	if res := ev.Eval(baseInput()); res.Rule == nil || res.Rule.Name != "先建" {
		t.Fatalf("同优先级应按 created_at 升序稳定排序: %+v", res.Rule)
	}
}

func TestEval_DisabledSkipped(t *testing.T) {
	rule := mkRule("停用", 100, time.Now(), Condition{Type: "uri", Op: "prefix", Value: "/"})
	rule.Enabled = false
	ev, err := NewEvaluator([]Rule{rule})
	if err != nil {
		t.Fatal(err)
	}
	res := ev.Eval(baseInput())
	if res.Matched {
		t.Fatal("停用规则应跳过")
	}
	if res.Reason != "不命中任何规则，将继续后续检查" {
		t.Fatalf("未命中 reason 异常: %s", res.Reason)
	}
}

func TestEval_EmptyAndCompileError(t *testing.T) {
	ev, err := NewEvaluator(nil)
	if err != nil {
		t.Fatal(err)
	}
	if ev.Eval(baseInput()).Matched {
		t.Fatal("空规则集不应命中")
	}
	// 脏数据防御：正则/CIDR 编译失败整条规则拒绝（NewEvaluator 报错）
	bad := mkRule("脏正则", 100, time.Now(), Condition{Type: "uri", Op: "regex", Value: "([bad"})
	if _, err := NewEvaluator([]Rule{bad}); err == nil {
		t.Fatal("脏正则应导致编译错误")
	}
	badCIDR := mkRule("脏CIDR", 100, time.Now(), Condition{Type: "client_ip", Values: []string{"10.0.0.0/33"}})
	if _, err := NewEvaluator([]Rule{badCIDR}); err == nil {
		t.Fatal("脏CIDR应导致编译错误")
	}
}

func TestEval_HostAndRedirectPreview(t *testing.T) {
	rule := Rule{
		ID:       uuid.New(),
		Name:     "裸域跳转www",
		Priority: 10,
		Enabled:  true,
		Conditions: []Condition{
			{Type: CondTypeHost, Op: OpEq, Value: "jxdr.cn"},
		},
		Action: ActionRedirect,
		ActionConfig: ActionConfig{
			Status:            403,
			RedirectURL:       "https://www.jxdr.cn",
			RedirectStatus:    301,
			PreservePathQuery: true,
			ContentType:       "text/html; charset=utf-8",
		},
		CreatedAt: time.Now(),
	}
	ev, err := NewEvaluator([]Rule{rule})
	if err != nil {
		t.Fatal(err)
	}

	// 兼容大小写和可选端口，保留路径和查询参数
	for _, host := range []string{"jxdr.cn", "JXDR.CN", "JxDr.Cn:443", "jxdr.cn:80", "jxdr.cn."} {
		res := ev.Eval(Input{URI: "/news?id=1", Host: host, Method: "GET"})
		if !res.Matched {
			t.Fatalf("host=%q 应命中", host)
		}
		if res.RedirectStatus != 301 || res.RedirectLocation != "https://www.jxdr.cn/news?id=1" {
			t.Fatalf("host=%q 重定向预览异常: status=%d loc=%q", host, res.RedirectStatus, res.RedirectLocation)
		}
	}

	// 未传 Host 字段时回退 Headers["Host"]，且 Query map 合并进跳转预览
	resHdr := ev.Eval(Input{
		URI:     "/news",
		Method:  "GET",
		Headers: map[string]string{"Host": "JXDR.CN:8443"},
		Query:   map[string]string{"id": "1"},
	})
	if !resHdr.Matched || resHdr.RedirectLocation != "https://www.jxdr.cn/news?id=1" {
		t.Fatalf("Headers Host 回退与 Query 预览异常: %+v", resHdr)
	}

	// www.jxdr.cn 不命中裸域规则
	if ev.Eval(Input{URI: "/news?id=1", Host: "www.jxdr.cn", Method: "GET"}).Matched {
		t.Fatal("www.jxdr.cn 不应命中 jxdr.cn 精确规则")
	}

	// 空 Host 不命中 ne
	if evalSingle(t, Condition{Type: CondTypeHost, Op: OpNe, Value: "jxdr.cn"}, Input{URI: "/"}) {
		t.Fatal("空 Host 不应命中 ne")
	}

	// host regex 大小写不敏感
	if !evalSingle(t, Condition{Type: CondTypeHost, Op: OpRegex, Value: `^(www\.)?JXDR\.CN$`}, Input{URI: "/", Host: "jxdr.cn:443"}) {
		t.Fatal("host regex 应兼容大小写与端口")
	}

	// 关闭 preserve_path_query 时原样返回目标地址
	if got := BuildRedirectLocation("https://www.jxdr.cn", false, "/news?id=1", nil); got != "https://www.jxdr.cn" {
		t.Fatalf("未开启保留时应原样返回: %q", got)
	}
	if got := BuildRedirectLocation("https://www.jxdr.cn/", true, "/news?id=1", nil); got != "https://www.jxdr.cn/news?id=1" {
		t.Fatalf("目标带尾斜杠不应出现双斜杠: %q", got)
	}
}

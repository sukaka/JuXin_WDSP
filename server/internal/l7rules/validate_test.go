package l7rules

import (
	"errors"
	"strings"
	"testing"
)

// validInput 返回一条合法输入（六种条件全覆盖 + block 动作），各用例在其上变异。
func validInput() RuleInput {
	return RuleInput{
		Name:     "管理后台保护",
		Priority: 100,
		Enabled:  true,
		Conditions: []Condition{
			{Type: "uri", Op: "prefix", Value: "/admin"},
			{Type: "method", Values: []string{"GET", "POST"}},
			{Type: "header", Name: "X-Env", Op: "eq", Value: "prod"},
			{Type: "cookie", Name: "session", Op: "exists"},
			{Type: "query", Name: "debug", Op: "ne", Value: "1"},
			{Type: "client_ip", Values: []string{"10.0.0.0/8", "192.168.1.5"}},
		},
		Action:       ActionBlock,
		ActionConfig: ActionConfig{Status: 403, Message: "访问被拦截"},
	}
}

func TestValidateInput_Valid(t *testing.T) {
	in := validInput()
	if err := ValidateInput(&in); err != nil {
		t.Fatalf("合法输入被拒绝了: %v", err)
	}
	// 规范化检查：method 大写、client_ip CIDR 掩码化、values 型条件 op 清空
	if in.Conditions[1].Values[0] != "GET" || in.Conditions[1].Op != "" {
		t.Fatalf("method 条件规范化异常: %+v", in.Conditions[1])
	}
	if in.Conditions[5].Values[0] != "10.0.0.0/8" {
		t.Fatalf("CIDR 规范化异常: %s", in.Conditions[5].Values[0])
	}
	// 默认值填充（六键全量）
	if in.ActionConfig.RedirectStatus != 302 || in.ActionConfig.ContentType != "text/html; charset=utf-8" {
		t.Fatalf("action_config 默认值未填充: %+v", in.ActionConfig)
	}
}

func TestValidateInput_NameAndPriority(t *testing.T) {
	cases := []struct {
		name   string
		mutate func(in *RuleInput)
	}{
		{"名称为空", func(in *RuleInput) { in.Name = "  " }},
		{"名称超长", func(in *RuleInput) { in.Name = strings.Repeat("规", 201) }},
		{"优先级超上限", func(in *RuleInput) { in.Priority = 1000001 }},
		{"优先级超下限", func(in *RuleInput) { in.Priority = -1000001 }},
		{"条件为空", func(in *RuleInput) { in.Conditions = nil }},
		{"条件超10条", func(in *RuleInput) {
			in.Conditions = nil
			for i := 0; i < 11; i++ {
				in.Conditions = append(in.Conditions, Condition{Type: "uri", Op: "prefix", Value: "/a"})
			}
		}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			in := validInput()
			tc.mutate(&in)
			if err := ValidateInput(&in); !errors.Is(err, ErrInvalidInput) {
				t.Fatalf("应返回 ErrInvalidInput，实际: %v", err)
			}
		})
	}
	// 优先级缺省 0 → 100
	in := validInput()
	in.Priority = 0
	if err := ValidateInput(&in); err != nil || in.Priority != 100 {
		t.Fatalf("优先级缺省应为 100: %d, err=%v", in.Priority, err)
	}
}

func TestValidateInput_Conditions(t *testing.T) {
	cases := []struct {
		name string
		cond Condition
		ok   bool
	}{
		{"未知类型", Condition{Type: "body", Op: "eq", Value: "x"}, false},
		// uri
		{"uri合法regex", Condition{Type: "uri", Op: "regex", Value: "^/api/v[0-9]+/"}, true},
		{"uri缺op", Condition{Type: "uri", Value: "/a"}, false},
		{"uri用in拒绝", Condition{Type: "uri", Op: "in", Value: "/a"}, false},
		{"uri值不带斜杠", Condition{Type: "uri", Op: "prefix", Value: "admin"}, false},
		{"uri正则不可编译", Condition{Type: "uri", Op: "regex", Value: "([unclosed"}, false},
		{"uri正则超长", Condition{Type: "uri", Op: "regex", Value: strings.Repeat("a", 513)}, false},
		{"uri带name拒绝", Condition{Type: "uri", Name: "x", Op: "eq", Value: "/a"}, false},
		{"uri值含控制字符", Condition{Type: "uri", Op: "eq", Value: "/a\r\nInjected: 1"}, false},
		// host
		{"host合法裸域", Condition{Type: "host", Op: "eq", Value: "jxdr.cn"}, true},
		{"host大写与尾点归一", Condition{Type: "host", Op: "eq", Value: "JXDR.CN."}, true},
		{"host合法IPv6", Condition{Type: "host", Op: "eq", Value: "[::1]"}, true},
		{"host合法prefix", Condition{Type: "host", Op: "prefix", Value: "API."}, true},
		{"host合法contains", Condition{Type: "host", Op: "contains", Value: "jxdr.cn"}, true},
		{"host合法regex", Condition{Type: "host", Op: "regex", Value: `^(www\.)?jxdr\.cn$`}, true},
		{"host带端口拒绝", Condition{Type: "host", Op: "eq", Value: "jxdr.cn:443"}, false},
		{"hostIPv6带端口拒绝", Condition{Type: "host", Op: "eq", Value: "[::1]:443"}, false},
		{"host带协议拒绝", Condition{Type: "host", Op: "eq", Value: "https://jxdr.cn"}, false},
		{"host带路径拒绝", Condition{Type: "host", Op: "eq", Value: "jxdr.cn/news"}, false},
		{"host带空白拒绝", Condition{Type: "host", Op: "eq", Value: "jxdr.cn evil"}, false},
		{"host带name拒绝", Condition{Type: "host", Name: "Host", Op: "eq", Value: "jxdr.cn"}, false},
		{"host用exists拒绝", Condition{Type: "host", Op: "exists"}, false},
		{"host用values拒绝", Condition{Type: "host", Op: "eq", Value: "jxdr.cn", Values: []string{"jxdr.cn"}}, false},
		{"host正则不可编译", Condition{Type: "host", Op: "regex", Value: "([bad"}, false},
		// method
		{"method合法小写归一", Condition{Type: "method", Values: []string{"get"}}, true},
		{"method空values", Condition{Type: "method"}, false},
		{"method非法方法", Condition{Type: "method", Values: []string{"HACK"}}, false},
		{"method带name拒绝", Condition{Type: "method", Name: "m", Values: []string{"GET"}}, false},
		{"method带op=eq拒绝", Condition{Type: "method", Op: "eq", Values: []string{"GET"}}, false},
		{"method带op=in容忍", Condition{Type: "method", Op: "in", Values: []string{"GET"}}, true},
		// header
		{"header合法contains", Condition{Type: "header", Name: "User-Agent", Op: "contains", Value: "bot"}, true},
		{"header名称空", Condition{Type: "header", Op: "eq", Value: "x"}, false},
		{"header名称非法字符", Condition{Type: "header", Name: "X Bad", Op: "eq", Value: "x"}, false},
		{"header exists带value拒绝", Condition{Type: "header", Name: "X-A", Op: "exists", Value: "1"}, false},
		{"header not_exists合法", Condition{Type: "header", Name: "X-A", Op: "not_exists"}, true},
		{"header ne缺value拒绝", Condition{Type: "header", Name: "X-A", Op: "ne"}, false},
		{"header用in拒绝", Condition{Type: "header", Name: "X-A", Op: "in", Value: "x"}, false},
		{"header带values拒绝", Condition{Type: "header", Name: "X-A", Op: "eq", Values: []string{"x"}}, false},
		// cookie/query
		{"cookie exists合法", Condition{Type: "cookie", Name: "session", Op: "exists"}, true},
		{"query regex合法", Condition{Type: "query", Name: "q", Op: "regex", Value: "^[0-9]+$"}, true},
		{"query名称控制字符", Condition{Type: "query", Name: "a\nb", Op: "eq", Value: "x"}, false},
		// client_ip
		{"client_ip合法", Condition{Type: "client_ip", Values: []string{"::1", "2001:db8::/32"}}, true},
		{"client_ip空values", Condition{Type: "client_ip"}, false},
		{"client_ip非法地址", Condition{Type: "client_ip", Values: []string{"999.1.1.1"}}, false},
		{"client_ip带域名拒绝", Condition{Type: "client_ip", Values: []string{"example.com"}}, false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			in := validInput()
			in.Conditions = []Condition{tc.cond}
			err := ValidateInput(&in)
			if tc.ok && err != nil {
				t.Fatalf("应通过，实际错误: %v", err)
			}
			if !tc.ok && !errors.Is(err, ErrInvalidInput) {
				t.Fatalf("应返回 ErrInvalidInput，实际: %v", err)
			}
		})
	}
}

func TestValidateInput_ClientIPNormalization(t *testing.T) {
	in := validInput()
	in.Conditions = []Condition{{Type: "client_ip", Values: []string{"10.0.0.9/8", "::ffff:192.168.1.5"}}}
	if err := ValidateInput(&in); err != nil {
		t.Fatal(err)
	}
	// CIDR 掩码化 + v4映射v6归一
	if in.Conditions[0].Values[0] != "10.0.0.0/8" || in.Conditions[0].Values[1] != "192.168.1.5" {
		t.Fatalf("client_ip 规范化异常: %v", in.Conditions[0].Values)
	}
}

func TestValidateInput_HostNormalizationAndPreservePathQuery(t *testing.T) {
	in := validInput()
	in.Conditions = []Condition{
		{Type: CondTypeHost, Op: OpEq, Value: "  JXDR.CN.  "},
		{Type: CondTypeHost, Op: OpPrefix, Value: "API."},
	}
	in.Action = ActionRedirect
	in.ActionConfig = ActionConfig{
		RedirectURL:       "https://www.jxdr.cn",
		RedirectStatus:    301,
		PreservePathQuery: true,
	}
	if err := ValidateInput(&in); err != nil {
		t.Fatalf("合法 host + redirect 输入被拒绝: %v", err)
	}
	if in.Conditions[0].Value != "jxdr.cn" || in.Conditions[1].Value != "api." {
		t.Fatalf("host 规范化异常: %+v", in.Conditions)
	}
	if !in.ActionConfig.PreservePathQuery {
		t.Fatal("redirect 动作应保留 preserve_path_query=true")
	}

	// 非 redirect 动作清理 preserve_path_query，避免切换动作残留脏数据
	inBlock := validInput()
	inBlock.Action = ActionBlock
	inBlock.ActionConfig.PreservePathQuery = true
	if err := ValidateInput(&inBlock); err != nil {
		t.Fatal(err)
	}
	if inBlock.ActionConfig.PreservePathQuery {
		t.Fatal("非 redirect 动作应清理 preserve_path_query")
	}
}

func TestValidateInput_Actions(t *testing.T) {
	cases := []struct {
		name   string
		action string
		cfg    ActionConfig
		ok     bool
		check  func(t *testing.T, cfg ActionConfig)
	}{
		{"未知动作", "drop", ActionConfig{}, false, nil},
		{"block默认403", "block", ActionConfig{Message: "x"}, true, func(t *testing.T, cfg ActionConfig) {
			if cfg.Status != 403 {
				t.Fatalf("block 缺省状态码应为 403: %d", cfg.Status)
			}
		}},
		{"block状态码200拒绝", "block", ActionConfig{Status: 200}, false, nil},
		{"block状态码599", "block", ActionConfig{Status: 599}, true, nil},
		{"block文案超长", "block", ActionConfig{Message: strings.Repeat("文", 1025)}, false, nil},
		{"allow合法", "allow", ActionConfig{}, true, nil},
		{"redirect合法301", "redirect", ActionConfig{RedirectURL: "https://example.com/new", RedirectStatus: 301}, true, nil},
		{"redirect缺URL", "redirect", ActionConfig{}, false, nil},
		{"redirect非http(s)", "redirect", ActionConfig{RedirectURL: "javascript:alert(1)"}, false, nil},
		{"redirect缺scheme", "redirect", ActionConfig{RedirectURL: "//example.com/x"}, false, nil},
		{"redirect无主机", "redirect", ActionConfig{RedirectURL: "https:///x"}, false, nil},
		{"redirect含CRLF", "redirect", ActionConfig{RedirectURL: "https://example.com/\r\nx"}, false, nil},
		{"redirect状态码303拒绝", "redirect", ActionConfig{RedirectURL: "https://example.com/x", RedirectStatus: 303}, false, nil},
		{"custom_page合法", "custom_page", ActionConfig{Status: 403, Body: "<h1>禁止访问</h1>"}, true, nil},
		{"custom_page缺body拒绝", "custom_page", ActionConfig{Status: 200}, false, nil},
		{"custom_page默认200", "custom_page", ActionConfig{Body: "x"}, true, func(t *testing.T, cfg ActionConfig) {
			if cfg.Status != 200 {
				t.Fatalf("custom_page 缺省状态码应为 200: %d", cfg.Status)
			}
		}},
		{"custom_page状态码100拒绝", "custom_page", ActionConfig{Status: 100, Body: "x"}, false, nil},
		{"custom_page正文64KB边界", "custom_page", ActionConfig{Body: strings.Repeat("a", 64*1024)}, true, nil},
		{"custom_page正文超64KB", "custom_page", ActionConfig{Body: strings.Repeat("a", 64*1024+1)}, false, nil},
		{"content_type含CRLF拒绝", "custom_page", ActionConfig{Body: "x", ContentType: "text/html\r\nX: 1"}, false, nil},
		{"content_type无斜杠拒绝", "custom_page", ActionConfig{Body: "x", ContentType: "texthtml"}, false, nil},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			in := validInput()
			in.Action = tc.action
			in.ActionConfig = tc.cfg
			err := ValidateInput(&in)
			if tc.ok && err != nil {
				t.Fatalf("应通过，实际错误: %v", err)
			}
			if !tc.ok && !errors.Is(err, ErrInvalidInput) {
				t.Fatalf("应返回 ErrInvalidInput，实际: %v", err)
			}
			if tc.ok && tc.check != nil {
				tc.check(t, in.ActionConfig)
			}
		})
	}
}

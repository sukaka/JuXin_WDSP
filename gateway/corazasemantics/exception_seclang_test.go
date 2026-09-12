// Package corazasemantics 以仓库锁定的 Coraza v3.7.0 实测 P0-04 例外 SecLang
// 模板的真实引擎语义（S4_DESIGN_BASELINE.md §5）：条件 AND 链、ctl 仅全链匹配后
// 执行、REQUEST_FILENAME 不含 query、TIME_EPOCH 半开区间运行时生效/失效、
// 目标级排除不影响同规则其他目标、例外命中经 tag 可审计。
// 不加载 CRS；用一条合成 SQLi 检测规则（id 942100）站在 CRS 位置。
package corazasemantics

import (
	"fmt"
	"strings"
	"testing"
	"time"

	"github.com/corazawaf/coraza/v3"
)

const detectRule = `SecRule ARGS "@detectSQLi" "id:942100,phase:2,deny,status:403,msg:'SQLi found',tag:'attack-sqli'"`

// exceptionRule 按冻结模板生成（两规则标记法，见 S4_DESIGN_BASELINE.md §5：
// Coraza 3.7.0 对「自身已匹配」的规则立即执行非中断动作（internal/corazawaf/rule.go
// 原文注释 "We run non-disruptive actions even if there is no chain match"），
// 链首直挂 ctl 会在后续链环失败时仍摘除规则——故条件链只 setvar 打标（末环携带，
// 末环只在全链匹配时求值），ctl 由独立的 TX 标记规则执行）。
func exceptionRule(chain []string, ctl string) string {
	const markerID, effectID = 8000001, 8000002
	head := fmt.Sprintf(`SecRule REQUEST_HEADERS:Host "@rx (?i)^example\.com(?::\d+)?$" "id:%d,phase:1,pass,nolog,chain"`, markerID)
	var b strings.Builder
	b.WriteString(head)
	b.WriteString("\n")
	for i, c := range chain {
		b.WriteString("    ")
		b.WriteString(c)
		if i < len(chain)-1 {
			b.WriteString(` "chain"`)
		} else {
			fmt.Fprintf(&b, ` "setvar:tx.jz_exc_%d=1"`, markerID)
		}
		b.WriteString("\n")
	}
	fmt.Fprintf(&b, `SecRule TX:jz_exc_%d "@eq 1" "id:%d,phase:1,pass,log,tag:'jiuzhang-exception',tag:'exc:11111111-2222-3333-4444-555555555555',tag:'excv:2',%s"`, markerID, effectID, ctl)
	b.WriteString("\n")
	return b.String()
}

func fullChain(from, until int64) []string {
	return []string{
		`SecRule REQUEST_FILENAME "@streq /api/orders"`,
		`SecRule REQUEST_METHOD "@pm POST"`,
		`SecRule REMOTE_ADDR "@ipMatch 10.0.0.0/8,192.168.1.7"`,
		`SecRule REQUEST_HEADERS:Content-Type "@rx ^application/x-www-form-urlencoded(?:[;]|$)"`,
		fmt.Sprintf(`SecRule TIME_EPOCH "@ge %d"`, from),
		fmt.Sprintf(`SecRule TIME_EPOCH "@lt %d"`, until),
	}
}

const ctlRemoveTarget = `ctl:ruleRemoveTargetById=942100;ARGS:comment`

type txInput struct {
	host, uri, method, ip, ct, body string
}

type txResult struct {
	interrupted bool
	matched9421 bool
	excLogged   bool
	excTags     []string
}

func runTx(t *testing.T, waf coraza.WAF, in txInput) txResult {
	t.Helper()
	tx := waf.NewTransaction()
	defer tx.ProcessLogging()
	tx.ProcessConnection(in.ip, 51234, "10.10.0.1", 8080)
	tx.ProcessURI(in.uri, in.method, "HTTP/1.1")
	tx.AddRequestHeader("Host", in.host)
	tx.SetServerName(strings.Split(in.host, ":")[0])
	if in.ct != "" {
		tx.AddRequestHeader("Content-Type", in.ct)
	}
	tx.ProcessRequestHeaders()
	var interrupted bool
	if _, _, err := tx.WriteRequestBody([]byte(in.body)); err == nil {
		if it, err := tx.ProcessRequestBody(); err == nil && it != nil {
			interrupted = true
		}
	}
	out := txResult{interrupted: interrupted}
	for _, mr := range tx.MatchedRules() {
		if mr.Rule().ID() == 942100 {
			out.matched9421 = true
		}
		if mr.Rule().ID() == 8000002 {
			out.excLogged = true
			for _, tag := range mr.Rule().Tags() {
				if strings.HasPrefix(tag, "exc") {
					out.excTags = append(out.excTags, tag)
				}
			}
		}
	}
	return out
}

func newWAF(t *testing.T, extra string) coraza.WAF {
	t.Helper()
	waf, err := coraza.NewWAF(coraza.NewWAFConfig().WithDirectives(
		"SecRuleEngine On\nSecRequestBodyAccess On\n" + extra + "\n" + detectRule))
	if err != nil {
		t.Fatalf("build waf: %v", err)
	}
	return waf
}

func baseInput() txInput {
	return txInput{
		host: "example.com", uri: "/api/orders", method: "POST",
		ip: "10.1.2.3", ct: "application/x-www-form-urlencoded", body: "comment=' OR 1=1--",
	}
}

// EXC-01 语义：全条件成立时例外生效；逐维翻折即恢复防护。
func TestExceptionChainSemantics(t *testing.T) {
	now := time.Now().Unix()
	rule := exceptionRule(fullChain(now-60, now+3600), ctlRemoveTarget)

	cases := []struct {
		name string
		mut  func(*txInput)
		// ruleOverride 非空时替换默认例外链（如 Content-Type 维度需要
		// 「例外配 json、请求仍 urlencoded」才能既让链失败又让正文可解析）
		ruleOverride string
		// 例外应生效 = 942100 被排除（无中断且无 942100 命中）
		wantExcepted bool
	}{
		{"全条件匹配", nil, "", true},
		{"Host 带端口仍匹配", func(in *txInput) { in.host = "example.com:8443" }, "", true},
		{"Host 大小写不敏感", func(in *txInput) { in.host = "Example.COM" }, "", true},
		{"Host 不匹配", func(in *txInput) { in.host = "evil.com" }, "", false},
		{"路径不匹配", func(in *txInput) { in.uri = "/api/other" }, "", false},
		{"方法不匹配", func(in *txInput) { in.method = "GET" }, "", false},
		{"来源 IP 出 CIDR", func(in *txInput) { in.ip = "172.16.0.1" }, "", false},
		{"来源 IP 精确匹配", func(in *txInput) { in.ip = "192.168.1.7" }, "", true},
		{"Content-Type 带参数仍匹配", func(in *txInput) { in.ct = "application/x-www-form-urlencoded; charset=utf-8" }, "", true},
		{"Content-Type 不匹配", nil,
			exceptionRule([]string{
				`SecRule REQUEST_FILENAME "@streq /api/orders"`,
				`SecRule REQUEST_METHOD "@pm POST"`,
				`SecRule REMOTE_ADDR "@ipMatch 10.0.0.0/8,192.168.1.7"`,
				`SecRule REQUEST_HEADERS:Content-Type "@rx ^application/json(?:[;]|$)"`,
				fmt.Sprintf(`SecRule TIME_EPOCH "@ge %d"`, now-60),
				fmt.Sprintf(`SecRule TIME_EPOCH "@lt %d"`, now+3600),
			}, ctlRemoveTarget), false},
		{"URI 带 query 仍按路径匹配", func(in *txInput) { in.uri = "/api/orders?debug=1" }, "", true},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			ruleForCase := rule
			if tc.ruleOverride != "" {
				ruleForCase = tc.ruleOverride
			}
			waf := newWAF(t, ruleForCase)
			in := baseInput()
			if tc.mut != nil {
				tc.mut(&in)
			}
			got := runTx(t, waf, in)
			excepted := !got.interrupted && !got.matched9421
			if excepted != tc.wantExcepted {
				t.Fatalf("excepted=%v want=%v (interrupted=%v matched9421=%v)",
					excepted, tc.wantExcepted, got.interrupted, got.matched9421)
			}
			if tc.wantExcepted && !got.excLogged {
				t.Fatalf("例外命中应产生可审计的例外规则匹配记录")
			}
		})
	}
}

// EXC-02 语义：目标级排除只摘除指定目标，同规则其他目标继续防护。
func TestExceptionTargetScoping(t *testing.T) {
	now := time.Now().Unix()
	waf := newWAF(t, exceptionRule(fullChain(now-60, now+3600), ctlRemoveTarget))

	in := baseInput()
	in.body = "note=' OR 1=1--" // 非豁免目标字段
	if got := runTx(t, waf, in); !got.interrupted || !got.matched9421 {
		t.Fatalf("非豁免目标仍应被 942100 拦截: %+v", got)
	}

	in = baseInput() // comment 为豁免目标
	if got := runTx(t, waf, in); got.interrupted || got.matched9421 {
		t.Fatalf("豁免目标不应再触发 942100: %+v", got)
	}
}

// EXC-03 语义：规则级排除只移除指定规则，其他规则继续拦截。
func TestExceptionRuleScoping(t *testing.T) {
	now := time.Now().Unix()
	directives := "SecRuleEngine On\nSecRequestBodyAccess On\n" +
		exceptionRule(fullChain(now-60, now+3600), `ctl:ruleRemoveById=942100`) + "\n" +
		`SecRule ARGS "@detectXSS" "id:941100,phase:2,deny,status:403,msg:'XSS found'"` + "\n" +
		`SecRule ARGS "@detectSQLi" "id:942100,phase:2,deny,status:403,msg:'SQLi found'"`
	waf, err := coraza.NewWAF(coraza.NewWAFConfig().WithDirectives(directives))
	if err != nil {
		t.Fatalf("build waf: %v", err)
	}
	in := baseInput()
	in.body = "comment=<script>alert(1)</script>"
	got := runTx(t, waf, in)
	if !got.interrupted {
		t.Fatalf("942100 已豁免但 941100 应继续拦截 XSS: %+v", got)
	}
	if got.matched9421 {
		t.Fatalf("942100 应已被 ruleRemoveById 移除: %+v", got)
	}
}

// EXC-05 语义：TIME_EPOCH 运行时半开区间——过期/未来生效均不生效，区间内生效；
// 到期无需重新发布。
func TestExceptionTimeWindow(t *testing.T) {
	now := time.Now().Unix()
	cases := []struct {
		name         string
		from, until  int64
		wantExcepted bool
	}{
		{"有效期内", now - 60, now + 3600, true},
		{"已过期（不重新发布也恢复防护）", now - 3600, now - 60, false},
		{"未来生效（发布带下发但运行时未生效）", now + 3600, now + 7200, false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			waf := newWAF(t, exceptionRule(fullChain(tc.from, tc.until), ctlRemoveTarget))
			got := runTx(t, waf, baseInput())
			excepted := !got.interrupted && !got.matched9421
			if excepted != tc.wantExcepted {
				t.Fatalf("excepted=%v want=%v", excepted, tc.wantExcepted)
			}
		})
	}
}

// 前缀按路径段边界：/api 匹配 /api/orders，不匹配 /apiserver。
func TestExceptionPrefixSegmentBoundary(t *testing.T) {
	now := time.Now().Unix()
	chain := []string{
		`SecRule REQUEST_FILENAME "@rx ^/api(?:/|$)"`,
		fmt.Sprintf(`SecRule TIME_EPOCH "@ge %d"`, now-60),
		fmt.Sprintf(`SecRule TIME_EPOCH "@lt %d"`, now+3600),
	}
	waf := newWAF(t, exceptionRule(chain, `ctl:ruleRemoveById=942100`))

	in := baseInput()
	in.uri = "/api/orders"
	if got := runTx(t, waf, in); got.interrupted || got.matched9421 {
		t.Fatalf("段内路径应被例外覆盖: %+v", got)
	}
	in.uri = "/apiserver"
	if got := runTx(t, waf, in); !got.interrupted || !got.matched9421 {
		t.Fatalf("相似前缀非段边界不应被例外覆盖: %+v", got)
	}
	in.uri = "/api" // 段自身亦匹配（(?:/|$) 的 $ 分支）
	if got := runTx(t, waf, in); got.interrupted || got.matched9421 {
		t.Fatalf("前缀自身应被例外覆盖: %+v", got)
	}
}

// 例外命中标签：exc:<uuid>/excv:<version> 随匹配记录可读（事件反查锚点）。
func TestExceptionTagsVisible(t *testing.T) {
	now := time.Now().Unix()
	waf := newWAF(t, exceptionRule(fullChain(now-60, now+3600), ctlRemoveTarget))
	got := runTx(t, waf, baseInput())
	if !got.excLogged {
		t.Fatalf("例外规则应出现在匹配记录中")
	}
	joined := strings.Join(got.excTags, ",")
	if !strings.Contains(joined, "exc:11111111-2222-3333-4444-555555555555") ||
		!strings.Contains(joined, "excv:2") {
		t.Fatalf("缺少 exc/excv 反查标签: %v", got.excTags)
	}
}

// 回归钉版：模板绝不产生整请求 DetectionOnly（§2.2 线索 3 的语义层防线）。
func TestNoDetectionOnlyInTemplate(t *testing.T) {
	rule := exceptionRule(fullChain(0, 1), ctlRemoveTarget) + "\n" + detectRule
	if strings.Contains(rule, "ruleEngine=DetectionOnly") {
		t.Fatalf("例外模板不得生成 ctl:ruleEngine=DetectionOnly")
	}
}

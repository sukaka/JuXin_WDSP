package corazasemantics

import (
	"fmt"
	"sort"
	"strings"
	"testing"

	"github.com/corazawaf/coraza/v3"
)

// crsDirectives 按 server/internal/gatewayconfig/generator.go buildWAFDirectivesWithPolicy
// 的指令栈 1:1 复刻（本地相对路径替代容器 /etc/caddy/rules 前缀），加载真实
// OWASP CRS（VERSION 见 ../rules/crs/VERSION.txt）与 contrib/jiuzhang 规则包。
// extra 在 CRS 主规则之前注入附加指令（与生成器例外注入点一致）。
func crsDirectives(extra string) string {
	return `SecRuleEngine On
Include ../rules/coraza.conf
SecAuditEngine RelevantOnly
SecAuditLogParts ABIJDEFHZ
SecAuditLog /tmp/coraza-semantics-audit.log
SecAction "id:900001,phase:1,pass,nolog,setvar:tx.blocking_paranoia_level=1,setvar:tx.inbound_anomaly_score_threshold=5,setvar:tx.outbound_anomaly_score_threshold=4"
Include ../rules/crs/crs-setup.conf
Include ../rules/crs/plugins/*/plugins/*-config.conf
Include ../rules/crs/plugins/*/plugins/*-before.conf
Include ../rules/exclusions/before-crs.conf
` + extra + `Include ../rules/crs/rules/*.conf
Include ../rules/contrib/*/*.conf
Include ../rules/crs/plugins/*/plugins/*-after.conf
Include ../rules/exclusions/after-crs.conf
Include ../rules/jiuzhang/jiuzhang-custom.conf
Include ../rules/jiuzhang/post-contrib-blocking.conf
`
}

// smokeSQLIURI 与 test/e2e/exception-p0-smoke.sh 的 $SQLI 同载荷（URL 编码形态），
// POST 无 Body、curl UA——与冒烟 A1 请求形态一致（920180/1000712 等环境类
// warning/notice 命中依赖此形态，仅作背景，低于异常阈值不参与达阈）。
const smokeSQLIURI = "/echo?comment=1%20UNION%20SELECT%20username,password%20FROM%20users--&name=ok"

// smokeExc1RuleIDs 冒烟例外 exc1 的冻结覆盖集（同步：test/e2e/exception-p0-smoke.sh
// exc1 rule_ids）：CRS SQLi 四条 + contrib 高危规则 1001209（UNION SELECT 变体，
// critical）。1001209 位于 CRS 之后求值——基线请求在 949110 即中断、轮不到它，
// 只摘除 CRS 四条才会显形（残余 critical 单独达阈，由 post-contrib-blocking
// 阻断）。本覆盖集为不动点：全部摘除后请求放行。
var smokeExc1RuleIDs = []int{942100, 942190, 942270, 942360, 1001209}

func removeCommentTargets(ids []int) string {
	var ctl strings.Builder
	ctl.WriteString(`SecAction "id:8001000,phase:1,pass,nolog`)
	for _, id := range ids {
		fmt.Fprintf(&ctl, ",ctl:ruleRemoveTargetById=%d;ARGS:comment", id)
	}
	ctl.WriteString("\"\n")
	return ctl.String()
}

func runSmokeTx(t *testing.T, waf coraza.WAF, uri string) (interrupted bool, criticalHits []int) {
	t.Helper()
	tx := waf.NewTransaction()
	defer tx.ProcessLogging()
	tx.ProcessConnection("192.0.2.60", 51234, "10.10.0.1", 8080)
	tx.ProcessURI(uri, "POST", "HTTP/1.1")
	tx.AddRequestHeader("Host", "exc-smoke.local")
	tx.AddRequestHeader("User-Agent", "curl/8.7.1")
	tx.SetServerName("exc-smoke.local")
	tx.ProcessRequestHeaders()
	if _, _, err := tx.WriteRequestBody(nil); err == nil {
		if it, err := tx.ProcessRequestBody(); err == nil && it != nil {
			interrupted = true
		}
	}
	seen := map[int]bool{}
	for _, mr := range tx.MatchedRules() {
		r := mr.Rule()
		// severity critical/error 的计分命中（达阈阻断的来源）；排除 949xxx
		// 阻断评估族（其命中是结果而非原因）。contrib 自建规则不带 attack-*
		// tag，不得按 tag 过滤。
		if r.Severity().String() != "critical" && r.Severity().String() != "error" {
			continue
		}
		if r.ID() >= 949000 && r.ID() < 950000 {
			continue
		}
		if !seen[r.ID()] {
			seen[r.ID()] = true
			criticalHits = append(criticalHits, r.ID())
		}
	}
	sort.Ints(criticalHits)
	return interrupted, criticalHits
}

func buildSmokeWAF(t *testing.T, removeIDs []int) coraza.WAF {
	t.Helper()
	extra := ""
	if len(removeIDs) > 0 {
		extra = removeCommentTargets(removeIDs)
	}
	waf, err := coraza.NewWAF(coraza.NewWAFConfig().WithDirectives(crsDirectives(extra)))
	if err != nil {
		t.Fatalf("build CRS waf: %v", err)
	}
	return waf
}

// TestSmokePayloadCoverageSet 钉死冒烟例外的规则覆盖集（EXC-01 语义前提）：
// CRS/contrib 升级导致载荷命中集变化时此处显式失败，提示同步冒烟例外配置。
func TestSmokePayloadCoverageSet(t *testing.T) {
	// 1. 基线：无摘除 → 阻断（冒烟对照组前提）
	interrupted, base := runSmokeTx(t, buildSmokeWAF(t, nil), smokeSQLIURI)
	if !interrupted {
		t.Fatal("无例外时载荷未被阻断（规则栈基线失效）")
	}
	t.Logf("基线 critical 命中（949110 前的 CRS 段）: %v", base)

	// 2. 回归钉：只摘除 CRS 四条 → 仍被阻断，且残余 critical 含 1001209
	//    （contrib 段显形；漏配 1001209 曾致一轮真实网关冒烟 EXC-01 失败）
	crsOnly := []int{942100, 942190, 942270, 942360}
	interrupted, residual := runSmokeTx(t, buildSmokeWAF(t, crsOnly), smokeSQLIURI)
	if !interrupted {
		t.Error("只摘除 CRS 四条后未阻断（1001209 已不再覆盖该载荷？覆盖集可收缩）")
	}
	var has1001209 bool
	for _, id := range residual {
		if id == 1001209 {
			has1001209 = true
		}
	}
	if !has1001209 {
		t.Errorf("残余 critical 命中 %v 不含 1001209（contrib 覆盖假设失效）", residual)
	}

	// 3. 充分性：全量摘除 → 放行（EXC-01 引擎级证明）
	interrupted, residual = runSmokeTx(t, buildSmokeWAF(t, smokeExc1RuleIDs), smokeSQLIURI)
	if interrupted {
		t.Errorf("全量摘除后仍被阻断（残余 critical: %v）；覆盖集需扩", residual)
	}

	// 4. EXC-02 目标级语义：同载荷落在未摘除的 name 字段 → 仍阻断
	nameURI := "/echo?comment=ok&name=1%20UNION%20SELECT%20username,password%20FROM%20users--"
	interrupted, _ = runSmokeTx(t, buildSmokeWAF(t, smokeExc1RuleIDs), nameURI)
	if !interrupted {
		t.Error("name 字段载荷未被阻断（摘除过宽，EXC-02 语义破坏）")
	}
}

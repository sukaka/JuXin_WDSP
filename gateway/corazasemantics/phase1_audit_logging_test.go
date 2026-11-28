package corazasemantics

import (
	"bytes"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/corazawaf/coraza/v3"
	"github.com/jiuzhang-waf/gateway/internal/eventparser"
)

// buildAuditWAF 复用生产规则栈（crs-setup.conf 含 phase 1~5 SecDefaultAction），
// 将审计日志写入隔离临时文件，验证 Coraza 真实落盘的 messages 内容。
func buildAuditWAF(t *testing.T) (coraza.WAF, string) {
	t.Helper()
	auditPath := filepath.Join(t.TempDir(), "coraza-audit.log")
	directives := strings.Replace(
		crsDirectives(""),
		"SecAuditLog /tmp/coraza-semantics-audit.log",
		"SecAuditLog "+auditPath,
		1,
	)
	waf, err := coraza.NewWAF(coraza.NewWAFConfig().WithDirectives(directives))
	if err != nil {
		t.Fatalf("build CRS waf: %v", err)
	}
	return waf, auditPath
}

func runAuditRequest(t *testing.T, waf coraza.WAF, uri, ua string, originStatus int) (interrupted bool) {
	t.Helper()
	tx := waf.NewTransaction()
	defer tx.ProcessLogging()
	tx.ProcessConnection("45.148.10.119", 51234, "10.10.0.1", 443)
	tx.ProcessURI(uri, "GET", "HTTP/1.1")
	tx.AddRequestHeader("Host", "www.jxdr.cn")
	tx.AddRequestHeader("User-Agent", ua)
	tx.AddRequestHeader("Accept", "*/*")
	tx.SetServerName("www.jxdr.cn")
	if it := tx.ProcessRequestHeaders(); it != nil {
		return true
	}
	if _, _, err := tx.WriteRequestBody(nil); err == nil {
		if it, err := tx.ProcessRequestBody(); err == nil && it != nil {
			return true
		}
	}
	if originStatus > 0 {
		tx.ProcessResponseHeaders(originStatus, "HTTP/1.1")
	}
	return false
}

func matchRuleIDSet(evt *eventparser.StandardEvent) map[string]bool {
	out := make(map[string]bool, len(evt.Security.Matches))
	for _, m := range evt.Security.Matches {
		out[m.RuleID] = true
	}
	return out
}

// TestPhase1BlockRulesWrittenToAuditLog 回归：
// crs-setup.conf 必须包含 phase 1~5 SecDefaultAction "log,auditlog,pass"，确保
// phase:1 仅写 block 的 CRS/CUSTOM_PACK 计分规则（930130/920440/913100/1000506/
// 1000805/1001920 等）真实写入审计日志 messages，不再出现仅剩 9000102 导致攻击
// 类型退化为「其他」、异常评分为 0 的现象；同时 980170（noauditlog）不得污染日志。
func TestPhase1BlockRulesWrittenToAuditLog(t *testing.T) {
	const chromeUA = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 Chrome/120.0.0.0 Safari/537.36"

	t.Run("/backend/.env 完整记录 930130/1000506/9000102 且解析出 LFI 与总分", func(t *testing.T) {
		waf, auditPath := buildAuditWAF(t)
		if !runAuditRequest(t, waf, "/backend/.env", chromeUA, 404) {
			t.Fatal("GET /backend/.env 应被阶段 1 阻断")
		}
		raw, err := os.ReadFile(auditPath)
		if err != nil {
			t.Fatalf("read audit log: %v", err)
		}
		evt, err := eventparser.ParseLine(bytes.TrimSpace(raw), "gw-test", eventparser.ApplicationRef{Domain: "www.jxdr.cn"})
		if err != nil {
			t.Fatalf("ParseLine: %v", err)
		}
		ids := matchRuleIDSet(evt)
		for _, want := range []string{"930130", "1000506", "9000102"} {
			if !ids[want] {
				t.Errorf("audit messages 缺少规则 %s，实际命中：%v", want, ids)
			}
		}
		if ids["980170"] {
			t.Errorf("980170 (noauditlog) 不得进入审计日志 messages：%v", ids)
		}
		if evt.Security.AttackType != "LOCAL_FILE_INCLUSION" {
			t.Errorf("attack_type = %q, want LOCAL_FILE_INCLUSION", evt.Security.AttackType)
		}
		if evt.Security.AnomalyScore < 10 {
			t.Errorf("anomaly_score = %d, want >= 10", evt.Security.AnomalyScore)
		}
	})

	t.Run("/.env.bak 完整记录 920440/930130/1000506 及扫描器探测规则与总分", func(t *testing.T) {
		waf, auditPath := buildAuditWAF(t)
		if !runAuditRequest(t, waf, "/.env.bak", chromeUA, 404) {
			t.Fatal("GET /.env.bak 应被阶段 1 阻断")
		}
		raw, err := os.ReadFile(auditPath)
		if err != nil {
			t.Fatalf("read audit log: %v", err)
		}
		evt, err := eventparser.ParseLine(bytes.TrimSpace(raw), "gw-test", eventparser.ApplicationRef{Domain: "www.jxdr.cn"})
		if err != nil {
			t.Fatalf("ParseLine: %v", err)
		}
		ids := matchRuleIDSet(evt)
		for _, want := range []string{"920440", "930130", "1000506", "1000221", "1000222", "9000102"} {
			if !ids[want] {
				t.Errorf("audit messages 缺少规则 %s，实际命中：%v", want, ids)
			}
		}
		if evt.Security.AnomalyScore < 18 {
			t.Errorf("anomaly_score = %d, want >= 18", evt.Security.AnomalyScore)
		}
	})

	t.Run("/xmlrpc.php 与 /wp-login.php 404 观察事件记录 1000805/1001920 而非仅 1000718", func(t *testing.T) {
		for _, tc := range []struct {
			uri    string
			ruleID string
		}{
			{"/xmlrpc.php", "1000805"},
			{"/wp-login.php", "1001920"},
		} {
			waf, auditPath := buildAuditWAF(t)
			if runAuditRequest(t, waf, tc.uri, chromeUA, 404) {
				t.Fatalf("GET %s 单条 WARNING 不应达阈阻断", tc.uri)
			}
			raw, err := os.ReadFile(auditPath)
			if err != nil {
				t.Fatalf("read audit log for %s: %v", tc.uri, err)
			}
			evt, err := eventparser.ParseLine(bytes.TrimSpace(raw), "gw-test", eventparser.ApplicationRef{Domain: "www.jxdr.cn"})
			if err != nil {
				t.Fatalf("ParseLine(%s): %v", tc.uri, err)
			}
			ids := matchRuleIDSet(evt)
			if !ids[tc.ruleID] {
				t.Errorf("%s audit messages 缺少规则 %s，实际：%v", tc.uri, tc.ruleID, ids)
			}
			if evt.Security.AttackType != "DATA_DISCLOSURE" {
				t.Errorf("%s attack_type = %q, want DATA_DISCLOSURE", tc.uri, evt.Security.AttackType)
			}
		}
	})

	t.Run("正常浏览器访问 /favicon.ico 200 不阻断且不产生审计记录", func(t *testing.T) {
		waf, auditPath := buildAuditWAF(t)
		if runAuditRequest(t, waf, "/favicon.ico", chromeUA, 200) {
			t.Fatal("正常浏览器访问 /favicon.ico 不得被阻断")
		}
		if raw, err := os.ReadFile(auditPath); err == nil && len(bytes.TrimSpace(raw)) > 0 {
			t.Errorf("正常浏览器访问 /favicon.ico 不应产生审计日志，实际：%s", string(raw))
		}
	})

	t.Run("扫描器 UA 访问 /favicon.ico 记录 CRS 913100 并识别为 SCANNER", func(t *testing.T) {
		waf, auditPath := buildAuditWAF(t)
		if !runAuditRequest(t, waf, "/favicon.ico", "arachni/1.0", 200) {
			t.Fatal("扫描器 UA 访问 /favicon.ico 应被阻断")
		}
		raw, err := os.ReadFile(auditPath)
		if err != nil {
			t.Fatalf("read audit log: %v", err)
		}
		evt, err := eventparser.ParseLine(bytes.TrimSpace(raw), "gw-test", eventparser.ApplicationRef{Domain: "www.jxdr.cn"})
		if err != nil {
			t.Fatalf("ParseLine: %v", err)
		}
		ids := matchRuleIDSet(evt)
		if !ids["913100"] || !ids["9000102"] {
			t.Errorf("期望记录 913100 与 9000102，实际：%v", ids)
		}
		if evt.Security.AttackType != "SCANNER" {
			t.Errorf("attack_type = %q, want SCANNER", evt.Security.AttackType)
		}
		if evt.Security.AnomalyScore < 5 {
			t.Errorf("anomaly_score = %d, want >= 5", evt.Security.AnomalyScore)
		}
	})
}

// TestDuplicateSecDefaultActionRejectedByCoraza 回归：
// Coraza v3.7.0 禁止同一 phase 重复声明 SecDefaultAction。由于 crs-setup.conf
// 已声明 phase 1~5 默认动作，配置生成器不得再次内联 SecDefaultAction，否则网关
// /load 阶段编译 waf 处理器直接返回 400。
func TestDuplicateSecDefaultActionRejectedByCoraza(t *testing.T) {
	dup := strings.Replace(
		crsDirectives(""),
		"Include ../rules/crs/crs-setup.conf",
		"SecDefaultAction \"phase:1,log,auditlog,pass\"\nInclude ../rules/crs/crs-setup.conf",
		1,
	)
	_, err := coraza.NewWAF(coraza.NewWAFConfig().WithDirectives(dup))
	if err == nil {
		t.Fatal("expected duplicate SecDefaultAction to fail Coraza parsing")
	}
	if !strings.Contains(err.Error(), "SecDefaultAction already defined for this phase") {
		t.Fatalf("unexpected Coraza error: %v", err)
	}
}

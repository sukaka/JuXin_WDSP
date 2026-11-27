package systemalerts

import (
	"strings"
	"testing"
	"time"

	"github.com/google/uuid"
)

// TestCSVCellFormulaInjection CSV 导出防公式注入。
func TestCSVCellFormulaInjection(t *testing.T) {
	cases := []struct {
		name  string
		input string
		want  string
	}{
		{"普通文本", "网关不可用", "网关不可用"},
		{"等号公式", "=cmd|'/c calc'!A1", "'=cmd|'/c calc'!A1"},
		{"加号公式", "+1+2", "'+1+2"},
		{"减号公式", "-2+3", "'-2+3"},
		{"at 公式", "@SUM(1)", "'@SUM(1)"},
		{"制表符公式", "\t=1", "'\t=1"},
		{"回车公式", "\r=1", "' =1"},
		{"换行剥离", "line1\nline2\r", "line1 line2 "},
		{"含逗号引用", "a,b", `"a,b"`},
		{"含引号转义", `say "hi"`, `"say ""hi"""`},
		{"空串", "", ""},
	}
	for _, c := range cases {
		if got := csvCell(c.input); got != c.want {
			t.Errorf("%s: csvCell(%q) = %q，期望 %q", c.name, c.input, got, c.want)
		}
	}
	// 注入后的单元格必须以单引号开头
	for _, payload := range []string{"=1+1", "+1", "-1", "@x", "\t1", "\r=1"} {
		if !strings.HasPrefix(csvCell(payload), "'") {
			t.Errorf("payload %q 未加防护前缀", payload)
		}
	}
}

func TestRenderExportCSV(t *testing.T) {
	now := time.Date(2026, 11, 24, 11, 0, 0, 0, time.UTC)
	resolved := now.Add(5 * time.Minute)
	resolveManual := ResolveManual
	resolveRecovered := ResolveRecovered
	id1 := uuid.MustParse("11111111-1111-1111-1111-111111111111")
	id2 := uuid.MustParse("22222222-2222-2222-2222-222222222222")
	id3 := uuid.MustParse("33333333-3333-3333-3333-333333333333")

	list := []Alert{
		{
			ID:              id1,
			AlertType:       TypeGatewayDown,
			Severity:        SeverityCritical,
			Component:       "GATEWAY",
			Title:           "网关不可用",
			Message:         "心跳超时,已重试",
			Status:          StatusResolved,
			OccurrenceCount: 3,
			FirstSeenAt:     now,
			LastSeenAt:      now,
			ResolvedAt:      &resolved,
			ResolveType:     &resolveManual,
		},
		{
			ID:              id2,
			AlertType:       TypeVulnIntelNew,
			Severity:        SeverityHigh,
			Component:       "vuln_intel:php",
			Title:           "=HYPERLINK(\"http://x\")",
			Message:         "发现新漏洞",
			Status:          StatusOpen,
			OccurrenceCount: 1,
			FirstSeenAt:     now,
			LastSeenAt:      now,
		},
		{
			ID:              id3,
			AlertType:       "FUTURE_ALERT",
			Severity:        "CUSTOM_SEV",
			Component:       "shop/GET /v1/orders",
			Title:           "自定义告警",
			Message:         "ok",
			Status:          "CUSTOM_STATUS",
			OccurrenceCount: 2,
			FirstSeenAt:     now,
			LastSeenAt:      now,
			ResolvedAt:      &resolved,
			ResolveType:     &resolveRecovered,
		},
	}

	out := renderExportCSV(list)
	wantHeader := "\xef\xbb\xbf告警 ID,告警类型,严重级别,组件,标题,详情,状态,发生次数,首次发生时间,最近发生时间,解决时间,解决方式\n"
	if !strings.HasPrefix(out, wantHeader) {
		t.Fatalf("missing UTF-8 BOM or Chinese header: %q", out[:min(len(out), 120)])
	}
	lines := strings.Split(strings.TrimSuffix(out, "\n"), "\n")
	if len(lines) != 4 {
		t.Fatalf("line count=%d want 4", len(lines))
	}
	wantRow1 := `11111111-1111-1111-1111-111111111111,网关不可用,严重,防护网关,网关不可用,"心跳超时,已重试",已解决,3,2026-11-24T11:00:00Z,2026-11-24T11:00:00Z,2026-11-24T11:05:00Z,人工解决`
	if lines[1] != wantRow1 {
		t.Fatalf("row1 mismatch:\n got: %s\nwant: %s", lines[1], wantRow1)
	}
	if !strings.Contains(lines[2], `,漏洞情报,高危,漏洞情报:php,"'=HYPERLINK(""http://x"")",发现新漏洞,未处理,1,`) ||
		!strings.HasSuffix(lines[2], "2026-11-24T11:00:00Z,,") {
		t.Fatalf("row2 mismatch: %s", lines[2])
	}
	if !strings.Contains(lines[3], `,FUTURE_ALERT,CUSTOM_SEV,shop/GET /v1/orders,自定义告警,ok,CUSTOM_STATUS,2,`) ||
		!strings.HasSuffix(lines[3], ",2026-11-24T11:05:00Z,自动恢复") {
		t.Fatalf("row3 fallback mismatch: %s", lines[3])
	}

	// 验证 rules.go 注册的全部告警类型均存在中文映射（防新增漏配）
	for _, typ := range AllTypes() {
		got := exportAlertTypeLabel(typ)
		if got == typ {
			t.Errorf("registered alert_type %q missing Chinese label", typ)
		}
	}
	for raw, want := range map[string]string{
		"GATEWAY": "防护网关", "CORAZA": "WAF 引擎", "GUARD": "访问控制模块", "API": "管理 API",
		"POSTGRES": "数据库", "VALKEY": "缓存服务", "EVENT_COLLECTOR": "事件采集器",
		"UPSTREAM": "源站", "CERTIFICATE": "证书", "DISK": "磁盘",
		"API_SECURITY": "API 安全采集", "APM_CLICKHOUSE": "APM 时序存储",
		"waf": "WAF 防护", "cc": "CC 防护", "clickhouse": "ClickHouse 时序存储",
		"API_ENDPOINT_DISCOVERY": "API 端点发现",
		"vuln_intel:nginx":       "漏洞情报:nginx",
	} {
		if got := exportAlertComponentLabel(raw); got != want {
			t.Errorf("exportAlertComponentLabel(%q) = %q, want %q", raw, got, want)
		}
	}
}

// TestMarkFlapping 抖动标记幂等。
func TestMarkFlapping(t *testing.T) {
	msg := markFlapping("磁盘空间不足")
	if !strings.Contains(msg, "抖动") {
		t.Errorf("标记后应含\"抖动\"，实际 %q", msg)
	}
	if again := markFlapping(msg); again != msg {
		t.Errorf("重复标记应幂等，实际 %q", again)
	}
}

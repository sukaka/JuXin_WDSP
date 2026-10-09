package threatintel

import (
	"fmt"
	"strings"
	"testing"
)

func TestParseText_Basic(t *testing.T) {
	content := `# Feodo 样例注释行
192.0.2.10
  198.51.100.20
	203.0.113.30

# 又一行注释
192.0.2.10   `
	res := ParseText(content)
	if res.ErrorTotal != 0 {
		t.Fatalf("unexpected errors: %+v", res.Errors)
	}
	if len(res.Entries) != 3 {
		t.Fatalf("entries=%d, want 3 (dedupe): %+v", len(res.Entries), res.Entries)
	}
	want := []string{"192.0.2.10", "198.51.100.20", "203.0.113.30"}
	for i, w := range want {
		if res.Entries[i].IP != w {
			t.Errorf("entry[%d].IP=%s, want %s", i, res.Entries[i].IP, w)
		}
	}
	// 行号按源内容从 1 计
	if res.Entries[0].Line != 2 || res.Entries[1].Line != 3 || res.Entries[2].Line != 4 {
		t.Errorf("line numbers wrong: %+v", res.Entries)
	}
}

func TestParseText_StripPort(t *testing.T) {
	res := ParseText("192.0.2.1:8080\n203.0.113.5:443")
	if res.ErrorTotal != 0 {
		t.Fatalf("unexpected errors: %+v", res.Errors)
	}
	if len(res.Entries) != 2 || res.Entries[0].IP != "192.0.2.1" || res.Entries[1].IP != "203.0.113.5" {
		t.Fatalf("port strip failed: %+v", res.Entries)
	}
}

func TestParseText_RejectInvalid(t *testing.T) {
	content := strings.Join([]string{
		"2001:db8::1",      // IPv6
		"::ffff:192.0.2.1", // 4 映射 6
		"192.0.2.0/24",     // CIDR
		"example.com",      // 域名
		"192.168.1",        // 残缺
		"192.0.2.256",      // 越界
		"0.0.0.0",          // 未指定地址
		"192.0.2.1:abc",    // 非法端口
		"192.0.2.1:0",      // 端口越界
		"192.0.2.1:70000",  // 端口越界
		"http://192.0.2.1", // 协议前缀
		"192.0.2.*",        // 通配符
		" 192.0.2.1 extra", // 多余内容
		"0192.0.2.1",       // 前导零（netip 严格拒绝）
	}, "\n")
	res := ParseText(content)
	if len(res.Entries) != 0 {
		t.Fatalf("entries should be empty: %+v", res.Entries)
	}
	if res.ErrorTotal != 14 {
		t.Fatalf("ErrorTotal=%d, want 14: %+v", res.ErrorTotal, res.Errors)
	}
	// 行号与内容保留
	if res.Errors[0].Line != 1 || res.Errors[0].Content != "2001:db8::1" {
		t.Errorf("first error wrong: %+v", res.Errors[0])
	}
	for _, e := range res.Errors {
		if e.Error == "" {
			t.Errorf("error message empty: %+v", e)
		}
	}
}

func TestParseText_ErrorDetailCap50(t *testing.T) {
	var lines []string
	for i := 1; i <= 60; i++ {
		lines = append(lines, fmt.Sprintf("bad-line-%d", i))
	}
	res := ParseText(strings.Join(lines, "\n"))
	if res.ErrorTotal != 60 {
		t.Fatalf("ErrorTotal=%d, want 60", res.ErrorTotal)
	}
	if len(res.Errors) != MaxRowErrors {
		t.Fatalf("error details=%d, want %d", len(res.Errors), MaxRowErrors)
	}
	if res.Errors[MaxRowErrors-1].Line != 50 {
		t.Errorf("last detail line=%d, want 50", res.Errors[MaxRowErrors-1].Line)
	}
}

func TestParseText_MaxEntries(t *testing.T) {
	var lines []string
	for i := 0; i < MaxEntries+10; i++ {
		lines = append(lines, fmt.Sprintf("198.51.%d.%d", i/250, i%250+1))
	}
	res := ParseText(strings.Join(lines, "\n"))
	if len(res.Entries) > MaxEntries {
		t.Fatalf("entries=%d exceeds cap %d", len(res.Entries), MaxEntries)
	}
	if !res.Truncated {
		t.Error("Truncated should be true when input exceeds cap")
	}
}

func TestParseText_ExactlyCapNotTruncated(t *testing.T) {
	// 恰好收满上限不算截断（构造 MaxEntries 个互不相同的合法 IP）
	var lines []string
	for i := 0; i < MaxEntries; i++ {
		lines = append(lines, fmt.Sprintf("198.51.%d.%d", i/250, i%250+1))
	}
	res := ParseText(strings.Join(lines, "\n"))
	if len(res.Entries) != MaxEntries {
		t.Fatalf("entries=%d, want %d", len(res.Entries), MaxEntries)
	}
	if res.Truncated {
		t.Error("exactly at cap must not be marked truncated")
	}
}

// 实测 Feodo 快照样本（2026-10-02 抓取，表头：first_seen_utc,dst_ip,dst_port,c2_status,last_online,malware）。
const feodoSample = `################################################################
# abuse.ch Feodo Tracker Botnet C2 IP Blocklist (CSV)          #
# Last updated: 2026-03-04 14:28:39 UTC                        #
################################################################
#
"first_seen_utc","dst_ip","dst_port","c2_status","last_online","malware"
"2022-06-04 21:24:53","192.0.2.11","8080","offline","2026-03-07","Emotet"
"2025-12-30 13:56:31","198.51.100.22","443","online","2026-03-12","QakBot"
"2026-01-13 21:41:15","203.0.113.33","443","offline","2026-03-01","QakBot"
`

func TestParseCSV_FeodoReal(t *testing.T) {
	res, err := ParseCSV(feodoSample)
	if err != nil {
		t.Fatalf("ParseCSV: %v", err)
	}
	if res.ErrorTotal != 0 {
		t.Fatalf("unexpected errors: %+v", res.Errors)
	}
	if len(res.Entries) != 3 {
		t.Fatalf("entries=%d, want 3", len(res.Entries))
	}
	if res.Entries[0].IP != "192.0.2.11" || res.Entries[0].Family != "Emotet" {
		t.Errorf("entry0 wrong: %+v", res.Entries[0])
	}
	if res.Entries[2].Family != "QakBot" {
		t.Errorf("entry2 family=%s, want QakBot", res.Entries[2].Family)
	}
}

func TestParseCSV_HeaderAdaptive(t *testing.T) {
	// 列序不同 + 候选列名变体（c2_family / ip）
	content := "# comment\n" +
		"c2_family,ip,note\n" +
		"Emotet,192.0.2.44,x\n" +
		",198.51.100.55,no-family\n"
	res, err := ParseCSV(content)
	if err != nil {
		t.Fatalf("ParseCSV: %v", err)
	}
	if len(res.Entries) != 2 {
		t.Fatalf("entries=%d, want 2: %+v", len(res.Entries), res.Entries)
	}
	if res.Entries[0].Family != "Emotet" || res.Entries[1].Family != "" {
		t.Errorf("family mapping wrong: %+v", res.Entries)
	}
}

func TestParseCSV_BadRowsSkipped(t *testing.T) {
	content := "dst_ip,malware\n" +
		"192.0.2.1,Emotet\n" +
		"not-an-ip,Bad\n" +
		"2001:db8::99,Bad6\n" +
		"203.0.113.9,QakBot\n"
	res, err := ParseCSV(content)
	if err != nil {
		t.Fatalf("ParseCSV: %v", err)
	}
	if len(res.Entries) != 2 || res.ErrorTotal != 2 {
		t.Fatalf("entries=%d errors=%d, want 2/2", len(res.Entries), res.ErrorTotal)
	}
	if res.Errors[0].Line != 3 || res.Errors[1].Line != 4 {
		t.Errorf("error lines wrong: %+v", res.Errors)
	}
}

func TestParseCSV_MissingIPColumn(t *testing.T) {
	_, err := ParseCSV("foo,bar\n1,2\n")
	if err == nil || !strings.Contains(err.Error(), "缺少 IP 列") {
		t.Fatalf("want structural error, got %v", err)
	}
}

func TestParseCSV_EmptyHeader(t *testing.T) {
	if _, err := ParseCSV(""); err == nil {
		t.Fatal("want error for empty content")
	}
}

func TestParseCSV_CRLF(t *testing.T) {
	content := "dst_ip,malware\r\n192.0.2.7,Emotet\r\n"
	res, err := ParseCSV(content)
	if err != nil {
		t.Fatalf("ParseCSV: %v", err)
	}
	if len(res.Entries) != 1 || res.Entries[0].IP != "192.0.2.7" {
		t.Fatalf("CRLF parse wrong: %+v", res.Entries)
	}
}

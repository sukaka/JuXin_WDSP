package apisecurity

import (
	"context"
	"encoding/json"
	"testing"

	"github.com/google/uuid"
)

func TestLocalizeFindingTitle(t *testing.T) {
	cases := []struct {
		name        string
		findingType string
		title       string
		detail      string
		want        string
	}{
		{
			name:        "CRS SQLi rule by finding_type",
			findingType: "WAF_942100",
			title:       "SQL Injection Attack Detected via libinjection",
			want:        "通过 libinjection 检测到 SQL 注入攻击",
		},
		{
			name:        "CRS anomaly score preserves dynamic total score",
			findingType: "WAF_949110",
			title:       "Inbound Anomaly Score Exceeded (Total Score: 5)",
			want:        "入站异常评分超限（总分：5）",
		},
		{
			name:        "extended custom pack rule by finding_type",
			findingType: "WAF_1000001",
			title:       "Log4Shell JNDI lookup attempt",
			want:        "Log4Shell JNDI 注入攻击尝试（CVE-2021-44228）",
		},
		{
			name:        "crawler template rule",
			findingType: "WAF_1002999",
			title:       "Scanner fingerprint: crawler UA (zgrab)",
			want:        "扫描器指纹：爬虫 UA（zgrab）",
		},
		{
			name:        "coraza parser core rule",
			findingType: "WAF_200002",
			title:       "Failed to parse request body.",
			want:        "请求体解析失败",
		},
		{
			name:        "empty msg fell back to WAF_id slug",
			findingType: "WAF_920350",
			title:       "WAF_920350",
			want:        "Host 头为数字 IP 地址",
		},
		{
			name:        "waf downstream intercept",
			findingType: "WAF_DOWNSTREAM_INTERCEPT",
			title:       "request blocked by downstream WAF (coraza interruption)",
			want:        "请求已被下游 WAF 引擎阻断",
		},
		{
			name:        "rule id extracted from detail json",
			findingType: "CUSTOM_TYPE",
			title:       "XSS Attack Detected via libinjection",
			detail:      `{"detector":"waf","rule_id":"941100"}`,
			want:        "通过 libinjection 检测到 XSS 攻击",
		},
		{
			name:        "already chinese preserved",
			findingType: "WAF_942100",
			title:       "自定义中文拦截提示",
			want:        "自定义中文拦截提示",
		},
		{
			name:        "non-waf finding unchanged",
			findingType: "SHADOW",
			title:       "endpoint not in known baseline (shadow candidate)",
			want:        "endpoint not in known baseline (shadow candidate)",
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got := localizeFindingTitle(tc.findingType, tc.title, json.RawMessage(tc.detail))
			if got != tc.want {
				t.Fatalf("localizeFindingTitle(%q, %q, %s) = %q, want %q",
					tc.findingType, tc.title, tc.detail, got, tc.want)
			}
		})
	}
}

func TestRiskMemStoreGetFindingLocalizesWAFTitle(t *testing.T) {
	id := uuid.New()
	mem := NewRiskMemStore()
	mem.SeedFinding(&RiskFinding{
		ID:          id,
		FindingType: "WAF_1000015",
		Severity:    "CRITICAL",
		Status:      RiskStatusNew,
		Title:       "ThinkPHP invokefunction RCE",
	})
	got, err := mem.GetFinding(context.Background(), id)
	if err != nil {
		t.Fatalf("GetFinding: %v", err)
	}
	want := "ThinkPHP invokefunction 路径远程代码执行（CVE-2018-20062）"
	if got.Title != want {
		t.Fatalf("GetFinding.Title = %q, want %q", got.Title, want)
	}
}

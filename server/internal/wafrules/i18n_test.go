package wafrules

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"testing"
	"unicode/utf8"

	"github.com/google/uuid"
	"github.com/jiuzhang-waf/server/internal/authz"
)

const repoCRSDir = "../../../gateway/rules/crs/rules"

// TestAllGatewayRulesHaveChineseLocalization 解析仓库内全部规则目录（OWASP CRS +
// CRS 插件 + 第三方排除包 + 自建扩展包 + 九章内置），断言 100% 规则均解析为有效 UTF-8 中文名。
func TestAllGatewayRulesHaveChineseLocalization(t *testing.T) {
	sources := BuildSyncSources(repoCRSDir)
	seenSources := map[string]bool{}
	totalRules := 0

	for _, sd := range sources {
		seenSources[sd.Source] = true
		files, err := filepath.Glob(filepath.Join(sd.Dir, "*.conf"))
		if err != nil {
			t.Fatalf("glob %s: %v", sd.Dir, err)
		}
		for _, f := range files {
			base := filepath.Base(f)
			if strings.HasSuffix(base, ".example") || strings.Contains(base, "EXCLUSION") {
				continue
			}
			rules, failed, err := ParseCRSFile(f, sd.Source)
			if err != nil {
				t.Fatalf("ParseCRSFile(%s): %v", f, err)
			}
			if len(failed) > 0 {
				t.Fatalf("parse failures in %s: %v", base, failed)
			}
			for _, r := range rules {
				totalRules++
				if r.Name == "" || r.Message == "" {
					t.Errorf("rule %d (%s/%s) empty name/message", r.RuleID, sd.Source, base)
				}
				if !utf8.ValidString(r.Name) || !utf8.ValidString(r.Message) {
					t.Errorf("rule %d (%s/%s) invalid UTF-8: %q", r.RuleID, sd.Source, base, r.Name)
				}
				if !HasCJK(r.Name) {
					t.Errorf("rule %d (%s/%s) not localized to Chinese: %q", r.RuleID, sd.Source, base, r.Name)
				}
			}
		}
	}

	for _, wantSrc := range []string{SourceCRS, SourceCRSPlugin, SourceThirdParty, SourceCustomPack, SourceJiuzhang} {
		if !seenSources[wantSrc] {
			t.Errorf("expected source %s in BuildSyncSources, got %v", wantSrc, seenSources)
		}
	}
	if totalRules < 3400 {
		t.Fatalf("total parsed rules = %d, want >= 3400", totalRules)
	}
	t.Logf("verified Chinese localization for %d rules across %d source dirs", totalRules, len(sources))
}

func TestLocalizeMatchMessageDynamicScore(t *testing.T) {
	cases := []struct {
		ruleID int
		raw    string
		want   string
	}{
		{
			943120,
			"Possible Session Fixation Attack: SessionID Parameter Name with No Referer",
			"疑似会话固定攻击：SessionID 参数无 Referer",
		},
		{
			949110,
			"Inbound Anomaly Score Exceeded (Total Score: 5)",
			"入站异常评分超限（总分：5）",
		},
		{
			949111,
			"Inbound Anomaly Score Exceeded in phase 1 (Total Score: 8)",
			"入站异常评分超限（阶段 1，总分：8）",
		},
		{
			959100,
			"Outbound Anomaly Score Exceeded (Total Score: 4)",
			"出站异常评分超限（总分：4）",
		},
		{
			959101,
			"Outbound Anomaly Score Exceeded in phase 3 (Total Score: 6)",
			"出站异常评分超限（阶段 3，总分：6）",
		},
		{
			1002999,
			"Scanner fingerprint: crawler UA (zgrab)",
			"扫描器指纹：爬虫 UA（zgrab）",
		},
		{
			1010062,
			"AI crawler UA: GPTBot",
			"AI 爬虫 UA：GPTBot",
		},
		{
			1010201,
			"Search engine bot UA claim: Googlebot",
			"搜索引擎爬虫 UA 声明：Googlebot",
		},
		{
			7100001,
			"自定义规则命中",
			"自定义规则命中",
		},
	}
	for _, tc := range cases {
		if got := LocalizeMatchMessage(tc.ruleID, tc.raw); got != tc.want {
			t.Errorf("LocalizeMatchMessage(%d, %q) = %q, want %q", tc.ruleID, tc.raw, got, tc.want)
		}
	}
}

func TestSyncFromSourcesEmptyCRSDirReturnsError(t *testing.T) {
	svc := NewSyncService(nil)
	emptyDir := t.TempDir()
	_, err := svc.SyncFromSources(context.Background(), "4.28.0", []SourceDir{
		{Dir: emptyDir, Source: SourceCRS},
	})
	if !errors.Is(err, ErrCRSDirEmpty) {
		t.Fatalf("SyncFromSources(empty CRS dir) err = %v, want ErrCRSDirEmpty", err)
	}
}

func TestTruncateUTF8Safe(t *testing.T) {
	s := strings.Repeat("中文规则", 80) // 320 runes, 960 bytes
	got := truncate(s, 200)
	if !utf8.ValidString(got) {
		t.Fatal("truncated Chinese string is not valid UTF-8")
	}
	if len([]rune(got)) != 200 {
		t.Fatalf("rune length = %d, want 200", len([]rune(got)))
	}
}

func TestHandlerSyncEmptyCRSDirReturns503(t *testing.T) {
	h := NewHandler(nil, nil, t.TempDir(), "4.28.0")
	req := httptest.NewRequest(http.MethodPost, "/api/v1/waf-rules/sync", nil)
	ctx := authz.WithPrincipal(req.Context(), &authz.Principal{
		UserID:   uuid.New(),
		Username: "sec_admin",
	})
	rec := httptest.NewRecorder()
	h.Sync(rec, req.WithContext(ctx))
	if rec.Code != http.StatusServiceUnavailable {
		t.Fatalf("status = %d, want 503; body=%s", rec.Code, rec.Body.String())
	}
	if !strings.Contains(rec.Body.String(), "未找到可用 CRS 规则文件") {
		t.Fatalf("expected actionable Chinese error message, got: %s", rec.Body.String())
	}
}

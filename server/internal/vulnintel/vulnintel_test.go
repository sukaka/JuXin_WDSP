package vulnintel

import (
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/jiuzhang-waf/server/internal/authz"
)

// TestValidateCVE CVE 编号形态校验与归一化。
func TestValidateCVE(t *testing.T) {
	if got := NormalizeCVE("  cve-2024-1234 "); got != "CVE-2024-1234" {
		t.Errorf("NormalizeCVE = %q", got)
	}
	for _, ok := range []string{"CVE-2024-1234", "CVE-1999-0067", "CVE-2026-1234567"} {
		if err := ValidateCVE(ok); err != nil {
			t.Errorf("ValidateCVE(%s) 应通过: %v", ok, err)
		}
	}
	for _, bad := range []string{"", "cve-2024-1234-x", "CVE-24-1", "CVE-2024-1", "CNNVD-2024-001", "CVE-2024-12345678"} {
		if err := ValidateCVE(bad); !errors.Is(err, ErrInvalidInput) {
			t.Errorf("ValidateCVE(%q) 应返回 ErrInvalidInput, got %v", bad, err)
		}
	}
}

// TestValidateTechName 技术名词表校验（小写 1-64）。
func TestValidateTechName(t *testing.T) {
	for _, ok := range []string{"php", "nodejs", "openjdk-17", "go1.24", "a", "c++", ".net-core-v2"} {
		// .net-core-v2 首字符为 '.' 不合法，单独断言
		if ok == ".net-core-v2" {
			continue
		}
		if err := ValidateTechName(ok); err != nil {
			t.Errorf("ValidateTechName(%s) 应通过: %v", ok, err)
		}
	}
	for _, bad := range []string{"", "PHP", "-php", ".php", "php;DROP", "php xml", strings.Repeat("a", 65)} {
		if err := ValidateTechName(bad); !errors.Is(err, ErrInvalidInput) {
			t.Errorf("ValidateTechName(%q) 应返回 ErrInvalidInput, got %v", bad, err)
		}
	}
}

// TestSeverityFromScore 级别派生边界。
func TestSeverityFromScore(t *testing.T) {
	cases := []struct {
		score float64
		want  string
	}{
		{10.0, SeverityCritical}, {9.0, SeverityCritical},
		{8.9, SeverityHigh}, {7.0, SeverityHigh},
		{6.9, SeverityMedium}, {4.0, SeverityMedium},
		{3.9, SeverityLow}, {0.1, SeverityLow},
		{0.0, SeverityNone},
	}
	for _, c := range cases {
		if got := SeverityFromScore(c.score); got != c.want {
			t.Errorf("SeverityFromScore(%v) = %s, want %s", c.score, got, c.want)
		}
	}
	if !SeverityGte(SeverityCritical, SeverityHigh) || SeverityGte(SeverityMedium, SeverityHigh) {
		t.Error("SeverityGte 门槛判定错误")
	}
	if SeverityGte(SeverityNone, SeverityLow) {
		t.Error("NONE 不应达到任何门槛")
	}
}

// TestValidateAdvisory 导入校验：归一化（大写 CVE、去重 tech/ref）、必填与上限。
func TestValidateAdvisory(t *testing.T) {
	base := func() *Advisory {
		return &Advisory{
			CVEID:      "cve-2024-0001",
			Summary:    "A flaw in PHP allows ...",
			Severity:   "high",
			TechTags:   []string{"PHP", "php"},
			References: []string{"https://example.com/a", "https://example.com/a", " "},
			Source:     SourceManual,
		}
	}
	a := base()
	if err := ValidateAdvisory(a); err != nil {
		t.Fatalf("ValidateAdvisory: %v", err)
	}
	if a.CVEID != "CVE-2024-0001" {
		t.Errorf("cve_id 未归一化: %q", a.CVEID)
	}
	if a.Severity != "HIGH" {
		t.Errorf("severity 未归一化为大写: %q", a.Severity)
	}
	if len(a.TechTags) != 1 || a.TechTags[0] != "php" {
		t.Errorf("tech_tags 去重归一失败: %v", a.TechTags)
	}
	if len(a.References) != 1 {
		t.Errorf("references 去重/去空失败: %v", a.References)
	}
	if a.Title != "CVE-2024-0001" {
		t.Errorf("空 title 应回落 cve_id: %q", a.Title)
	}

	// 空 tech_tags 拒绝
	b := base()
	b.TechTags = nil
	if err := ValidateAdvisory(b); !errors.Is(err, ErrInvalidInput) {
		t.Errorf("空 tech_tags 应拒绝: %v", err)
	}
	// 非法 severity
	c := base()
	c.Severity = "SEVERE"
	if err := ValidateAdvisory(c); !errors.Is(err, ErrInvalidInput) {
		t.Errorf("非法 severity 应拒绝: %v", err)
	}
	// cvss 越界
	d := base()
	v := 11.0
	d.CVSSScore = &v
	if err := ValidateAdvisory(d); !errors.Is(err, ErrInvalidInput) {
		t.Errorf("cvss 越界应拒绝: %v", err)
	}
	// 非法 source
	e := base()
	e.Source = "CNNVD"
	if err := ValidateAdvisory(e); !errors.Is(err, ErrInvalidInput) {
		t.Errorf("非法 source 应拒绝: %v", err)
	}
	// last_modified 早于 published
	f := base()
	t1 := time.Date(2024, 5, 1, 0, 0, 0, 0, time.UTC)
	t2 := time.Date(2024, 4, 1, 0, 0, 0, 0, time.UTC)
	f.PublishedAt = &t1
	f.LastModifiedAt = &t2
	if err := ValidateAdvisory(f); !errors.Is(err, ErrInvalidInput) {
		t.Errorf("时间倒置应拒绝: %v", err)
	}
	// 超长 title
	g := base()
	g.Title = strings.Repeat("t", MaxTitleLen+1)
	if err := ValidateAdvisory(g); !errors.Is(err, ErrInvalidInput) {
		t.Errorf("超长 title 应拒绝: %v", err)
	}
}

// TestExtractTechTags 确定性技术提取：描述 php 关键词 / CPE php:php / 均不命中。
func TestExtractTechTags(t *testing.T) {
	if tags := ExtractTechTags("A remote code execution in PHP 8.1", nil); len(tags) != 1 || tags[0] != "php" {
		t.Errorf("描述命中 php: %v", tags)
	}
	if tags := ExtractTechTags("Buffer overflow", []string{"cpe:2.3:a:php:php:8.1.0:*:*:*:*:*:*:*"}); len(tags) != 1 || tags[0] != "php" {
		t.Errorf("CPE 命中 php: %v", tags)
	}
	if tags := ExtractTechTags("Buffer overflow in OpenSSL", []string{"cpe:2.3:a:openssl:openssl:*:*:*:*:*:*:*:*"}); len(tags) != 0 {
		t.Errorf("均不命中应为空: %v", tags)
	}
}

// TestParseWatchTechs 订阅技术栈解析（去空白/去重/保序/小写化）。
func TestParseWatchTechs(t *testing.T) {
	got := ParseWatchTechs(" php ,, PHP ,nodejs,php")
	if len(got) != 2 || got[0] != "php" || got[1] != "nodejs" {
		t.Errorf("ParseWatchTechs = %v", got)
	}
	if got := ParseWatchTechs(""); len(got) != 0 {
		t.Errorf("空串应为空列表: %v", got)
	}
	if JoinWatchTechs([]string{"php", "nodejs"}) != "php,nodejs" {
		t.Error("JoinWatchTechs 序列化错误")
	}
}

// TestValidateSubscription 订阅设置校验。
func TestValidateSubscription(t *testing.T) {
	sub := &Subscription{WatchTechs: []string{" PHP ", "php", "nodejs"}, MinSeverity: "high"}
	if err := ValidateSubscription(sub); err != nil {
		t.Fatalf("ValidateSubscription: %v", err)
	}
	if len(sub.WatchTechs) != 2 || sub.WatchTechs[0] != "php" {
		t.Errorf("watch_techs 归一失败: %v", sub.WatchTechs)
	}
	if sub.MinSeverity != SeverityHigh {
		t.Errorf("min_severity 未大写化: %q", sub.MinSeverity)
	}
	for _, bad := range []*Subscription{
		{WatchTechs: nil, MinSeverity: "HIGH"},
		{WatchTechs: []string{"php"}, MinSeverity: "NONE"},
		{WatchTechs: []string{"php"}, MinSeverity: "P0"},
		{WatchTechs: []string{"bad tech!"}, MinSeverity: "HIGH"},
	} {
		if err := ValidateSubscription(bad); !errors.Is(err, ErrInvalidInput) {
			t.Errorf("%+v 应拒绝: %v", bad, err)
		}
	}
	many := make([]string, maxWatchTechs+1)
	for i := range many {
		many[i] = strings.Repeat("x", 1) + strings.Repeat("0", i%10) + "t"
	}
	if err := ValidateSubscription(&Subscription{WatchTechs: many, MinSeverity: "LOW"}); !errors.Is(err, ErrInvalidInput) {
		t.Errorf("watch_techs 超上限应拒绝: %v", err)
	}
}

// TestMF1ReferenceURLSchemeValidation 验证参考链接仅允许 http:// 与 https:// 协议。
func TestMF1ReferenceURLSchemeValidation(t *testing.T) {
	allowed := []string{
		"https://nvd.nist.gov/vuln/detail/CVE-2024-0001",
		"http://example.com/advisory?id=1#top",
		"HTTPS://EXAMPLE.COM/path",
	}
	for _, u := range allowed {
		a := &Advisory{
			CVEID:      "CVE-2024-1111",
			Severity:   SeverityHigh,
			TechTags:   []string{"php"},
			References: []string{u},
			Source:     SourceManual,
		}
		if err := ValidateAdvisory(a); err != nil {
			t.Errorf("ValidateAdvisory(%q) unexpected error: %v", u, err)
		}
	}

	rejected := []string{
		"javascript:alert(1)",
		"JAVASCRIPT:alert(1)",
		"data:text/html,<script>alert(1)</script>",
		"vbscript:msgbox(1)",
		"file:///etc/passwd",
		"ftp://example.com/patch.tar.gz",
		"//example.com/protocol-relative",
		"example.com/no-scheme",
		"https:///missing-host",
		"https://example.com/bad\r\nheader",
		"https://example.com/null\x00byte",
	}
	for _, u := range rejected {
		a := &Advisory{
			CVEID:      "CVE-2024-1111",
			Severity:   SeverityHigh,
			TechTags:   []string{"php"},
			References: []string{u},
			Source:     SourceManual,
		}
		if err := ValidateAdvisory(a); !errors.Is(err, ErrInvalidInput) {
			t.Errorf("ValidateAdvisory(%q) = %v, want ErrInvalidInput", u, err)
		}
	}
}

type deadlineResponseRecorder struct {
	*httptest.ResponseRecorder
	deadlineSet bool
	deadline    time.Time
}

func (d *deadlineResponseRecorder) SetWriteDeadline(t time.Time) error {
	d.deadlineSet = true
	d.deadline = t
	return nil
}

// TestMS12SyncExtendsWriteDeadline 验证手动同步通过 ResponseController 放宽 HTTP 写超时。
func TestMS12SyncExtendsWriteDeadline(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"resultsPerPage":0,"startIndex":0,"totalResults":0,"vulnerabilities":[]}`))
	}))
	defer srv.Close()

	store := newMemSyncStore()
	syncer := newTestSyncer(store, srv.URL, time.Now().UTC())
	h := NewHandler(nil, syncer, nil, nil, nil, nil)

	rec := &deadlineResponseRecorder{ResponseRecorder: httptest.NewRecorder()}
	req := httptest.NewRequest(http.MethodPost, "/api/v1/vuln-intel/sync", nil)
	req = req.WithContext(authz.WithPrincipal(req.Context(), &authz.Principal{
		UserID:   uuid.New(),
		Username: "admin",
	}))
	before := time.Now()
	h.Sync(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("Sync status = %d body = %s, want 200", rec.Code, rec.Body.String())
	}
	if !rec.deadlineSet {
		t.Fatal("Sync did not call ResponseController.SetWriteDeadline")
	}
	if rec.deadline.Before(before.Add(manualSyncTimeout)) {
		t.Fatalf("write deadline %v is shorter than manualSyncTimeout (%v)", rec.deadline.Sub(before), manualSyncTimeout)
	}
}

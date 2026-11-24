package loginlogs

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"strings"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/jiuzhang-waf/server/internal/authz"
)

type fakeRows struct {
	entries []Entry
	idx     int
}

func (r *fakeRows) Next() bool {
	if r.idx >= len(r.entries) {
		return false
	}
	r.idx++
	return true
}

func (r *fakeRows) Scan(dest ...interface{}) error {
	e := r.entries[r.idx-1]
	*dest[0].(*uuid.UUID) = e.ID
	*dest[1].(*time.Time) = e.OccurredAt
	*dest[2].(*string) = e.Username
	*dest[3].(**uuid.UUID) = e.UserID
	if e.SourceIP != "" {
		addr := netip.MustParseAddr(e.SourceIP)
		*dest[4].(**netip.Addr) = &addr
	} else {
		*dest[4].(**netip.Addr) = nil
	}
	if e.ConnectionIP != "" {
		addr := netip.MustParseAddr(e.ConnectionIP)
		*dest[5].(**netip.Addr) = &addr
	} else {
		*dest[5].(**netip.Addr) = nil
	}
	*dest[6].(*string) = e.UserAgent
	*dest[7].(*string) = e.EventType
	*dest[8].(*string) = e.Result
	*dest[9].(*string) = e.FailureCode
	*dest[10].(*string) = e.RequestID
	return nil
}

func (r *fakeRows) Err() error { return nil }
func (r *fakeRows) Close()     {}

type fakeStore struct {
	entries   []Entry
	lastLimit int
}

func (f *fakeStore) Exec(_ context.Context, _ string, _ ...interface{}) error {
	return nil
}

func (f *fakeStore) Count(_ context.Context, _ string, _ ...interface{}) (int64, error) {
	return int64(len(f.entries)), nil
}

func (f *fakeStore) Query(_ context.Context, _ string, args ...interface{}) (logRowScanner, error) {
	limit := len(f.entries)
	offset := 0
	if len(args) >= 2 {
		if l, ok := args[len(args)-2].(int); ok {
			limit = l
			f.lastLimit = l
		}
		if o, ok := args[len(args)-1].(int); ok {
			offset = o
		}
	}
	if offset >= len(f.entries) {
		return &fakeRows{entries: nil}, nil
	}
	end := offset + limit
	if end > len(f.entries) {
		end = len(f.entries)
	}
	return &fakeRows{entries: f.entries[offset:end]}, nil
}

func makeFakeEntries(n int) []Entry {
	out := make([]Entry, 0, n)
	base := time.Date(2026, 11, 1, 0, 0, 0, 0, time.UTC)
	for i := 0; i < n; i++ {
		out = append(out, Entry{
			ID:           uuid.New(),
			OccurredAt:   base.Add(time.Duration(i) * time.Second),
			Username:     fmt.Sprintf("user-%03d", i),
			SourceIP:     "192.0.2.10",
			ConnectionIP: "192.0.2.10",
			EventType:    EventLoginSuccess,
			Result:       ResultSuccess,
			RequestID:    fmt.Sprintf("req-%03d", i),
		})
	}
	return out
}

func TestExportSupportsMoreThan100RowsUpTo10000WhileListClamps(t *testing.T) {
	st := &fakeStore{entries: makeFakeEntries(150)}
	svc := &Service{store: st}

	// List clamps >100 to 20
	listEntries, total, err := svc.List(context.Background(), ListFilter{Page: 1, PageSize: 10000})
	if err != nil {
		t.Fatalf("List: %v", err)
	}
	if total != 150 {
		t.Fatalf("List total = %d, want 150", total)
	}
	if st.lastLimit != 20 || len(listEntries) != 20 {
		t.Fatalf("List limit=%d len=%d, want 20", st.lastLimit, len(listEntries))
	}

	// List allows up to 100
	list100, _, err := svc.List(context.Background(), ListFilter{Page: 1, PageSize: 100})
	if err != nil {
		t.Fatalf("List(100): %v", err)
	}
	if st.lastLimit != 100 || len(list100) != 100 {
		t.Fatalf("List(100) limit=%d len=%d, want 100", st.lastLimit, len(list100))
	}

	// Export allows up to 10000 rows without clamping to 20
	csv, err := svc.Export(context.Background(), ListFilter{})
	if err != nil {
		t.Fatalf("Export: %v", err)
	}
	if st.lastLimit != 10000 {
		t.Fatalf("Export limit = %d, want 10000", st.lastLimit)
	}
	lines := strings.Split(strings.TrimSpace(csv), "\n")
	if len(lines) != 151 { // 1 header + 150 rows
		t.Fatalf("Export CSV lines = %d, want 151", len(lines))
	}
	wantHeader := csvUTF8BOM + "发生时间,用户名,来源 IP,事件类型,结果,失败原因,请求 ID"
	if lines[0] != wantHeader {
		t.Fatalf("Export CSV header = %q, want %q", lines[0], wantHeader)
	}
	if !strings.Contains(lines[1], ",登录成功,成功,") {
		t.Fatalf("Export CSV row should localize enums, got: %q", lines[1])
	}
}

func TestRenderExportCSVChineseHeadersAndValues(t *testing.T) {
	ts := time.Date(2026, 11, 24, 12, 0, 0, 0, time.UTC)

	// 覆盖全部 11 项事件类型
	eventCases := []struct {
		code string
		want string
	}{
		{EventLoginSuccess, "登录成功"},
		{EventLoginFailure, "登录失败"},
		{EventLoginTOTPChallenge, "双因子挑战（TOTP）"},
		{EventCaptchaFailure, "验证码错误"},
		{EventAccountLocked, "账号锁定"},
		{EventLogout, "登出"},
		{EventForceLogout, "强制下线"},
		{EventSessionExpired, "会话过期"},
		{EventPasswordChange, "修改密码"},
		{EventPasswordReset, "重置密码"},
		{EventFirstChangePwd, "首次改密"},
		{"CUSTOM_UNKNOWN_EVENT", "CUSTOM_UNKNOWN_EVENT"},
		{"", ""},
	}
	for _, tc := range eventCases {
		if got := formatLabelUpper(tc.code, loginEventTypeLabels); got != tc.want {
			t.Errorf("event_type %q = %q, want %q", tc.code, got, tc.want)
		}
	}

	// 覆盖全部 11 项失败码
	failureCases := []struct {
		code string
		want string
	}{
		{"CAPTCHA_REQUIRED", "需要验证码"},
		{"CAPTCHA_INVALID", "验证码错误"},
		{"BAD_CREDENTIALS", "用户名或密码错误"},
		{"ACCOUNT_DISABLED", "账号已停用"},
		{"ACCOUNT_LOCKED", "账号已锁定"},
		{"MAX_FAILED_ATTEMPTS", "失败次数超限"},
		{"PASSWORD_EXPIRED", "密码已过期"},
		{"TOTP_CHALLENGE_INVALID", "双因子挑战无效或过期"},
		{"TOTP_CHALLENGE_EXPIRED", "双因子挑战已过期"},
		{"TOTP_CHALLENGE_ORIGIN_MISMATCH", "双因子挑战来源不匹配"},
		{"TOTP_INVALID", "动态令牌或恢复码错误"},
		{"UNKNOWN_CODE", "UNKNOWN_CODE"},
		{"", ""},
	}
	for _, tc := range failureCases {
		if got := formatLabelUpper(tc.code, loginFailureCodeLabels); got != tc.want {
			t.Errorf("failure_code %q = %q, want %q", tc.code, got, tc.want)
		}
	}

	out := renderExportCSV([]Entry{
		{
			OccurredAt:  ts,
			Username:    "admin",
			SourceIP:    "192.0.2.10",
			EventType:   EventLoginFailure,
			Result:      ResultFailure,
			FailureCode: "BAD_CREDENTIALS",
			RequestID:   "req-1",
		},
		{
			OccurredAt:  ts,
			Username:    "=CMD()",
			SourceIP:    "192.0.2.11",
			EventType:   EventLoginTOTPChallenge,
			Result:      ResultSuccess,
			FailureCode: "",
			RequestID:   "req-2",
		},
		{
			OccurredAt:  ts,
			Username:    "\t+evil",
			SourceIP:    "\r-bad",
			EventType:   "FUTURE_EVT",
			Result:      "OTHER_RES",
			FailureCode: "=INJECT",
			RequestID:   "req-3",
		},
	})
	if !strings.HasPrefix(out, csvUTF8BOM) {
		t.Fatalf("missing UTF-8 BOM: %q", out[:min(len(out), 16)])
	}
	lines := strings.Split(strings.TrimRight(out, "\n"), "\n")
	if len(lines) != 4 {
		t.Fatalf("lines = %d, want 4", len(lines))
	}
	if lines[0] != csvUTF8BOM+"发生时间,用户名,来源 IP,事件类型,结果,失败原因,请求 ID" {
		t.Fatalf("unexpected header: %q", lines[0])
	}
	if lines[1] != "2026-11-24T12:00:00Z,admin,192.0.2.10,登录失败,失败,用户名或密码错误,req-1" {
		t.Fatalf("row 1 mismatch: %q", lines[1])
	}
	if lines[2] != "2026-11-24T12:00:00Z,'=CMD(),192.0.2.11,双因子挑战（TOTP）,成功,,req-2" {
		t.Fatalf("row 2 mismatch: %q", lines[2])
	}
	if !strings.Contains(lines[3], "'\t+evil") || !strings.Contains(lines[3], "\"'\r-bad\"") ||
		!strings.Contains(lines[3], ",FUTURE_EVT,OTHER_RES,'=INJECT,req-3") {
		t.Fatalf("row 3 fallback/escape mismatch: %q", lines[3])
	}
}

func TestListEmptyReturnsNonNilSliceAndJSONArray(t *testing.T) {
	st := &fakeStore{entries: nil}
	svc := &Service{store: st}

	entries, total, err := svc.List(context.Background(), ListFilter{Page: 1, PageSize: 20})
	if err != nil {
		t.Fatalf("List: %v", err)
	}
	if total != 0 {
		t.Fatalf("total = %d, want 0", total)
	}
	if entries == nil || len(entries) != 0 {
		t.Fatalf("entries = %#v, want non-nil empty slice []Entry{}", entries)
	}

	h := NewHandler(svc)
	req := httptest.NewRequest(http.MethodGet, "/api/v1/login-logs?page=1&page_size=200", nil)
	ctx := authz.WithPrincipal(req.Context(), &authz.Principal{
		UserID:      uuid.New(),
		Username:    "auditor",
		Permissions: []string{"login_logs.read"},
	})
	req = req.WithContext(ctx)
	rec := httptest.NewRecorder()
	h.List(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200", rec.Code)
	}
	var env struct {
		Code string `json:"code"`
		Data struct {
			Items    json.RawMessage `json:"items"`
			Page     int             `json:"page"`
			PageSize int             `json:"page_size"`
			Total    int64           `json:"total"`
		} `json:"data"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &env); err != nil {
		t.Fatalf("unmarshal response: %v", err)
	}
	if string(env.Data.Items) != "[]" {
		t.Fatalf("items JSON = %s, want []", string(env.Data.Items))
	}
	if env.Data.PageSize != 20 {
		t.Fatalf("page_size = %d, want 20 (clamped from 200)", env.Data.PageSize)
	}
}

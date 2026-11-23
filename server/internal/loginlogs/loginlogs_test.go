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

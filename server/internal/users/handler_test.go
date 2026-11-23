package users

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/jiuzhang-waf/server/internal/authz"
	"github.com/jiuzhang-waf/server/internal/loginlogs"
)

type fakeStatusStore struct {
	byID      map[uuid.UUID]*User
	enableErr error
	unlockErr error
}

func (f *fakeStatusStore) GetByID(_ context.Context, id uuid.UUID) (*User, error) {
	u, ok := f.byID[id]
	if !ok {
		return nil, ErrNotFound
	}
	cp := *u
	return &cp, nil
}

func (f *fakeStatusStore) Enable(_ context.Context, id uuid.UUID) error {
	if f.enableErr != nil {
		return f.enableErr
	}
	u, ok := f.byID[id]
	if !ok {
		return ErrNotFound
	}
	if u.Status != StatusDisabled {
		return ErrInvalidStatus
	}
	u.Status = StatusActive
	return nil
}

func (f *fakeStatusStore) Unlock(_ context.Context, id uuid.UUID) error {
	if f.unlockErr != nil {
		return f.unlockErr
	}
	u, ok := f.byID[id]
	if !ok {
		return ErrNotFound
	}
	if u.Status != StatusLocked {
		return ErrInvalidStatus
	}
	u.Status = StatusActive
	u.FailedLoginCount = 0
	u.LockedUntil = nil
	return nil
}

func doUserAction(h http.HandlerFunc, id string) *httptest.ResponseRecorder {
	req := httptest.NewRequest(http.MethodPost, "/api/v1/users/"+id, nil)
	req.SetPathValue("id", id)
	p := &authz.Principal{UserID: uuid.New(), Username: "admin"}
	req = req.WithContext(authz.WithPrincipal(req.Context(), p))
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	return rec
}

func TestMS3EnableAndUnlockStateMachine(t *testing.T) {
	disabledID := uuid.New()
	lockedID := uuid.New()
	activeID := uuid.New()

	st := &fakeStatusStore{
		byID: map[uuid.UUID]*User{
			disabledID: {ID: disabledID, Username: "u_disabled", Status: StatusDisabled},
			lockedID:   {ID: lockedID, Username: "u_locked", Status: StatusLocked},
			activeID:   {ID: activeID, Username: "u_active", Status: StatusActive},
		},
	}
	h := &Handler{statusStore: st}

	// Unlock 不能绕过停用状态把 DISABLED 账号重新启用
	if rec := doUserAction(h.Unlock, disabledID.String()); rec.Code != http.StatusConflict {
		t.Fatalf("Unlock(DISABLED) status = %d, want 409", rec.Code)
	}
	if st.byID[disabledID].Status != StatusDisabled {
		t.Fatalf("DISABLED user status mutated by Unlock: %s", st.byID[disabledID].Status)
	}

	// Unlock 对 ACTIVE 账号返回 409
	if rec := doUserAction(h.Unlock, activeID.String()); rec.Code != http.StatusConflict {
		t.Fatalf("Unlock(ACTIVE) status = %d, want 409", rec.Code)
	}

	// Enable 不能绕过锁定状态把 LOCKED 账号直接启用
	if rec := doUserAction(h.Enable, lockedID.String()); rec.Code != http.StatusConflict {
		t.Fatalf("Enable(LOCKED) status = %d, want 409", rec.Code)
	}
	if st.byID[lockedID].Status != StatusLocked {
		t.Fatalf("LOCKED user status mutated by Enable: %s", st.byID[lockedID].Status)
	}

	// Enable 对 ACTIVE 账号返回 409
	if rec := doUserAction(h.Enable, activeID.String()); rec.Code != http.StatusConflict {
		t.Fatalf("Enable(ACTIVE) status = %d, want 409", rec.Code)
	}

	// 合法流转：DISABLED -> ACTIVE via Enable
	if rec := doUserAction(h.Enable, disabledID.String()); rec.Code != http.StatusOK {
		t.Fatalf("Enable(DISABLED) status = %d, want 200", rec.Code)
	}
	if st.byID[disabledID].Status != StatusActive {
		t.Fatalf("DISABLED user status after Enable = %s, want ACTIVE", st.byID[disabledID].Status)
	}

	// 合法流转：LOCKED -> ACTIVE via Unlock
	if rec := doUserAction(h.Unlock, lockedID.String()); rec.Code != http.StatusOK {
		t.Fatalf("Unlock(LOCKED) status = %d, want 200", rec.Code)
	}
	if st.byID[lockedID].Status != StatusActive {
		t.Fatalf("LOCKED user status after Unlock = %s, want ACTIVE", st.byID[lockedID].Status)
	}

	// 并发竞争：仓储层原子条件未命中返回 ErrInvalidStatus 时必须映射为 409
	raceDisabled := uuid.New()
	st.byID[raceDisabled] = &User{ID: raceDisabled, Username: "race_d", Status: StatusDisabled}
	st.enableErr = ErrInvalidStatus
	if rec := doUserAction(h.Enable, raceDisabled.String()); rec.Code != http.StatusConflict {
		t.Fatalf("Enable concurrent ErrInvalidStatus status = %d, want 409", rec.Code)
	}
	st.enableErr = nil

	raceLocked := uuid.New()
	st.byID[raceLocked] = &User{ID: raceLocked, Username: "race_l", Status: StatusLocked}
	st.unlockErr = ErrInvalidStatus
	if rec := doUserAction(h.Unlock, raceLocked.String()); rec.Code != http.StatusConflict {
		t.Fatalf("Unlock concurrent ErrInvalidStatus status = %d, want 409", rec.Code)
	}
	st.unlockErr = nil

	// 不存在的用户返回 404
	if rec := doUserAction(h.Enable, uuid.NewString()); rec.Code != http.StatusNotFound {
		t.Fatalf("Enable(missing) status = %d, want 404", rec.Code)
	}
	if rec := doUserAction(h.Unlock, uuid.NewString()); rec.Code != http.StatusNotFound {
		t.Fatalf("Unlock(missing) status = %d, want 404", rec.Code)
	}
}

func TestMS3AndH19StoreSQLGuards(t *testing.T) {
	if !strings.Contains(sqlUnlockUser, "AND status = 'LOCKED'") {
		t.Fatalf("sqlUnlockUser missing status='LOCKED' guard: %s", sqlUnlockUser)
	}
	if !strings.Contains(sqlEnableUser, "AND status = 'DISABLED'") {
		t.Fatalf("sqlEnableUser missing status='DISABLED' guard: %s", sqlEnableUser)
	}
	if !strings.Contains(sqlSeedPasswordHistory, "INSERT INTO password_histories") {
		t.Fatalf("sqlSeedPasswordHistory missing password_histories insert: %s", sqlSeedPasswordHistory)
	}
}

func TestUserItemIncludesTOTPEnabled(t *testing.T) {
	now := time.Date(2026, 11, 20, 10, 0, 0, 0, time.UTC)
	for _, enabled := range []bool{false, true} {
		u := &User{
			ID:                 uuid.New(),
			Username:           "alice_ops",
			DisplayName:        "Alice",
			Status:             StatusActive,
			MustChangePassword: false,
			TOTPEnabled:        enabled,
			CreatedAt:          now,
			UpdatedAt:          now,
			Version:            1,
		}
		item := userItem(u, nil)
		raw, err := json.Marshal(item)
		if err != nil {
			t.Fatalf("json.Marshal(userItem) failed: %v", err)
		}
		var decoded map[string]any
		if err := json.Unmarshal(raw, &decoded); err != nil {
			t.Fatalf("json.Unmarshal failed: %v", err)
		}
		val, ok := decoded["totp_enabled"]
		if !ok {
			t.Fatalf("totp_enabled missing from serialized userItem (expected %v): %s", enabled, string(raw))
		}
		if val != enabled {
			t.Fatalf("totp_enabled = %v, want %v", val, enabled)
		}
		rolesVal, ok := decoded["roles"].([]any)
		if !ok || rolesVal == nil {
			t.Fatalf("roles should serialize as JSON array, got %#v", decoded["roles"])
		}
	}
}

func TestValidateUsernameRules(t *testing.T) {
	valid := []string{"abcd", "user_1-A", strings.Repeat("a", 64)}
	for _, name := range valid {
		if err := validateUsername(name); err != nil {
			t.Fatalf("validateUsername(%q) unexpected error: %v", name, err)
		}
	}
	invalid := []string{"abc", strings.Repeat("a", 65), "john.doe", "user@host", "root", "System"}
	for _, name := range invalid {
		if err := validateUsername(name); err == nil {
			t.Fatalf("validateUsername(%q) expected error, got nil", name)
		}
	}
}

type fakeProfileLoginLogLister struct {
	gotFilters []loginlogs.ListFilter
	entries    []loginlogs.Entry
	total      int64
}

func (f *fakeProfileLoginLogLister) List(_ context.Context, filter loginlogs.ListFilter) ([]loginlogs.Entry, int64, error) {
	f.gotFilters = append(f.gotFilters, filter)
	return f.entries, f.total, nil
}

func TestProfileLoginLogsClampsPageSize(t *testing.T) {
	principalID := uuid.New()
	lister := &fakeProfileLoginLogLister{
		entries: []loginlogs.Entry{},
		total:   0,
	}
	h := &ProfileHandler{logLister: lister}

	cases := []struct {
		name         string
		query        string
		wantPage     int
		wantPageSize int
	}{
		{name: "over_max_clamped_to_20", query: "?page=1&page_size=200", wantPage: 1, wantPageSize: 20},
		{name: "boundary_100_preserved", query: "?page=2&page_size=100", wantPage: 2, wantPageSize: 100},
		{name: "zero_values_normalized", query: "?page=0&page_size=0", wantPage: 1, wantPageSize: 20},
	}

	for i, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			req := httptest.NewRequest(http.MethodGet, "/api/v1/profile/login-logs"+tc.query, nil)
			p := &authz.Principal{UserID: principalID, Username: "alice_ops"}
			req = req.WithContext(authz.WithPrincipal(req.Context(), p))
			rec := httptest.NewRecorder()

			h.LoginLogs(rec, req)
			if rec.Code != http.StatusOK {
				t.Fatalf("status = %d, want 200; body=%s", rec.Code, rec.Body.String())
			}

			gotFilter := lister.gotFilters[i]
			if gotFilter.UserID == nil || *gotFilter.UserID != principalID {
				t.Fatalf("List UserID = %v, want %v", gotFilter.UserID, principalID)
			}
			if gotFilter.Page != tc.wantPage || gotFilter.PageSize != tc.wantPageSize {
				t.Fatalf("List filter = (page=%d, page_size=%d), want (%d, %d)",
					gotFilter.Page, gotFilter.PageSize, tc.wantPage, tc.wantPageSize)
			}

			var body struct {
				Code string `json:"code"`
				Data struct {
					Page     int `json:"page"`
					PageSize int `json:"page_size"`
				} `json:"data"`
			}
			if err := json.Unmarshal(rec.Body.Bytes(), &body); err != nil {
				t.Fatalf("json.Unmarshal failed: %v", err)
			}
			if body.Code != "SUCCESS" {
				t.Fatalf("code = %q, want SUCCESS", body.Code)
			}
			if body.Data.Page != tc.wantPage || body.Data.PageSize != tc.wantPageSize {
				t.Fatalf("response data = (page=%d, page_size=%d), want (%d, %d)",
					body.Data.Page, body.Data.PageSize, tc.wantPage, tc.wantPageSize)
			}
		})
	}
}

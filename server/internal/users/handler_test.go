package users

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/google/uuid"
	"github.com/jiuzhang-waf/server/internal/authz"
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

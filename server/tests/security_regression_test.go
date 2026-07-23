package tests

import (
	"context"
	"errors"
	"net/http"
	"sync"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/jiuzhang-waf/server/internal/security"
	"github.com/jiuzhang-waf/server/internal/sessions"
	"github.com/jiuzhang-waf/server/internal/upgrades"
	"github.com/jiuzhang-waf/server/internal/users"
)

func TestCreateUserWithRoleIsAtomic(t *testing.T) {
	env := setupTestEnv(t)
	store := users.NewStore(env.db)
	hash, err := security.HashPassword("Atomic@Test2026!")
	if err != nil {
		t.Fatalf("hash password: %v", err)
	}
	now := time.Now()
	user := &users.User{
		Username:           "atomic_user",
		DisplayName:        "Atomic User",
		PasswordHash:       hash,
		Status:             users.StatusActive,
		MustChangePassword: true,
		PasswordChangedAt:  &now,
	}

	if err := store.CreateWithRole(context.Background(), user, uuid.New(), uuid.New()); err == nil {
		t.Fatal("CreateWithRole() succeeded with a nonexistent role")
	}
	if _, err := store.GetByUsername(context.Background(), user.Username); !errors.Is(err, users.ErrNotFound) {
		t.Fatalf("user remained after role assignment failed: %v", err)
	}
}

func TestLastSystemAdminGuardIsAtomic(t *testing.T) {
	env := setupTestEnv(t)
	store := users.NewStore(env.db)
	first, err := store.GetByUsername(context.Background(), "test_sysadmin")
	if err != nil {
		t.Fatalf("get first admin: %v", err)
	}
	roleID, err := store.GetRoleIDByCode(context.Background(), "SYSTEM_ADMIN")
	if err != nil {
		t.Fatalf("get system admin role: %v", err)
	}
	hash, err := security.HashPassword("Second@Test2026!")
	if err != nil {
		t.Fatalf("hash password: %v", err)
	}
	now := time.Now()
	second := &users.User{
		Username:          "second_sysadmin",
		DisplayName:       "Second Admin",
		PasswordHash:      hash,
		Status:            users.StatusActive,
		PasswordChangedAt: &now,
	}
	if err := store.CreateWithRole(context.Background(), second, roleID, first.ID); err != nil {
		t.Fatalf("create second admin: %v", err)
	}

	ids := []uuid.UUID{first.ID, second.ID}
	errs := make(chan error, len(ids))
	var wg sync.WaitGroup
	for _, id := range ids {
		wg.Add(1)
		go func(userID uuid.UUID) {
			defer wg.Done()
			errs <- store.SetStatusGuarded(context.Background(), userID, users.StatusDisabled)
		}(id)
	}
	wg.Wait()
	close(errs)

	var succeeded, guarded int
	for err := range errs {
		switch {
		case err == nil:
			succeeded++
		case errors.Is(err, users.ErrLastSystemAdmin):
			guarded++
		default:
			t.Fatalf("unexpected status update error: %v", err)
		}
	}
	if succeeded != 1 || guarded != 1 {
		t.Fatalf("status results: succeeded=%d guarded=%d, want 1/1", succeeded, guarded)
	}
	count, err := store.CountActiveSystemAdmins(context.Background())
	if err != nil {
		t.Fatalf("count active system admins: %v", err)
	}
	if count != 1 {
		t.Fatalf("active system admins = %d, want 1", count)
	}
}

func TestCreateUpgradeJobIfNoActiveIsAtomic(t *testing.T) {
	env := setupTestEnv(t)
	store := upgrades.NewStore(env.db)
	pkg := &upgrades.Package{
		FileName:    "waf-v2.0.1.tar.gz",
		VersionFrom: "2.0.0",
		VersionTo:   "2.0.1",
		FileHash:    "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
		FileSize:    1,
		Status:      upgrades.PackageVerified,
	}
	if err := store.CreatePackage(context.Background(), pkg); err != nil {
		t.Fatalf("create upgrade package: %v", err)
	}

	errs := make(chan error, 2)
	var wg sync.WaitGroup
	for i := 0; i < 2; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			_, err := store.CreateJobIfNoActive(context.Background(), pkg.ID, nil, uuid.NewString())
			errs <- err
		}()
	}
	wg.Wait()
	close(errs)

	var succeeded, rejected int
	for err := range errs {
		switch {
		case err == nil:
			succeeded++
		case errors.Is(err, upgrades.ErrActiveUpgrade):
			rejected++
		default:
			t.Fatalf("unexpected create job error: %v", err)
		}
	}
	if succeeded != 1 || rejected != 1 {
		t.Fatalf("job results: succeeded=%d rejected=%d, want 1/1", succeeded, rejected)
	}
}

func TestAuthenticatedRequestRejectsRevokedSessionAndDisabledUser(t *testing.T) {
	env := setupTestEnv(t)
	ctx := context.Background()

	cookies, _ := env.login(t, "test_sysadmin", env.adminPwd)
	sessionID := sessionCookieValue(t, cookies)
	if _, err := env.db.Exec(ctx,
		`UPDATE login_sessions SET revoked_at = now(), revoke_reason = 'test' WHERE session_hash = $1`,
		sessions.HashSessionID(sessionID)); err != nil {
		t.Fatalf("revoke persistent session: %v", err)
	}
	resp := env.get(t, "/api/v1/auth/me", cookies)
	resp.Body.Close()
	if resp.StatusCode != 401 {
		t.Fatalf("revoked session status = %d, want 401", resp.StatusCode)
	}

	cookies, _ = env.login(t, "test_sysadmin", env.adminPwd)
	if _, err := env.db.Exec(ctx,
		`UPDATE users SET status = $1 WHERE username = 'test_sysadmin'`,
		users.StatusDisabled); err != nil {
		t.Fatalf("disable user: %v", err)
	}
	resp = env.get(t, "/api/v1/auth/me", cookies)
	resp.Body.Close()
	if resp.StatusCode != 401 {
		t.Fatalf("disabled user session status = %d, want 401", resp.StatusCode)
	}
}

func TestPasswordChangeAtomicallyRevokesPersistentSessions(t *testing.T) {
	env := setupTestEnv(t)
	ctx := context.Background()
	store := users.NewStore(env.db)
	user, err := store.GetByUsername(ctx, "test_sysadmin")
	if err != nil {
		t.Fatalf("get user: %v", err)
	}
	newHash, err := security.HashPassword("Changed@Test2026!")
	if err != nil {
		t.Fatalf("hash new password: %v", err)
	}
	currentSessionHash := sessions.HashSessionID("password-change-current-session")
	otherSessionHash := sessions.HashSessionID("password-change-other-session")
	if _, err := env.db.Exec(ctx, `
INSERT INTO login_sessions (user_id, session_hash, expires_at)
VALUES ($1, $2, now() + interval '1 hour'),
       ($1, $3, now() + interval '1 hour')`,
		user.ID, currentSessionHash, otherSessionHash); err != nil {
		t.Fatalf("insert sessions: %v", err)
	}

	if err := store.ChangePassword(
		ctx, user.ID, newHash, user.PasswordHash, nil, currentSessionHash, true,
	); err != nil {
		t.Fatalf("change password: %v", err)
	}

	var storedHash, historyHash, otherRevokeReason string
	var currentRevoked, otherRevoked bool
	if err := env.db.QueryRow(ctx, `
SELECT u.password_hash,
       (SELECT ph.password_hash FROM password_histories ph
        WHERE ph.user_id = u.id ORDER BY ph.created_at DESC LIMIT 1),
       (SELECT ls.revoked_at IS NOT NULL FROM login_sessions ls WHERE ls.session_hash = $2),
       (SELECT ls.revoked_at IS NOT NULL FROM login_sessions ls WHERE ls.session_hash = $3),
       (SELECT ls.revoke_reason FROM login_sessions ls WHERE ls.session_hash = $3)
FROM users u WHERE u.id = $1`, user.ID, currentSessionHash, otherSessionHash).
		Scan(&storedHash, &historyHash, &currentRevoked, &otherRevoked, &otherRevokeReason); err != nil {
		t.Fatalf("read password change state: %v", err)
	}
	if storedHash != newHash || historyHash != user.PasswordHash || currentRevoked ||
		!otherRevoked || otherRevokeReason != "password_changed" {
		t.Fatalf("unexpected password change state: new=%t history=%t current_revoked=%t other_revoked=%t reason=%q",
			storedHash == newHash, historyHash == user.PasswordHash, currentRevoked, otherRevoked, otherRevokeReason)
	}
}

func sessionCookieValue(t *testing.T, cookies []*http.Cookie) string {
	t.Helper()
	for _, cookie := range cookies {
		if cookie.Name == "jiuzhang_session" {
			return cookie.Value
		}
	}
	t.Fatal("login response did not include a session cookie")
	return ""
}

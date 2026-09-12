package auth

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/jiuzhang-waf/server/internal/audits"
	"github.com/jiuzhang-waf/server/internal/authz"
	"github.com/jiuzhang-waf/server/internal/encryption"
	"github.com/jiuzhang-waf/server/internal/loginlogs"
	"github.com/jiuzhang-waf/server/internal/security"
	"github.com/jiuzhang-waf/server/internal/sessions"
	"github.com/jiuzhang-waf/server/internal/settings"
	"github.com/jiuzhang-waf/server/internal/users"
)

// ---------- fakes（实现 service.go 中的窄接口） ----------

type fakeUserStore struct {
	byID       map[uuid.UUID]*users.User
	byName     map[string]*users.User
	failCounts map[uuid.UUID]int
	// changePwdRevokeSessions 记录每次 ChangePassword 调用的 revokeSessions 取值
	changePwdRevokeSessions []bool
}

func newFakeUserStore() *fakeUserStore {
	return &fakeUserStore{byID: map[uuid.UUID]*users.User{}, byName: map[string]*users.User{},
		failCounts: map[uuid.UUID]int{}}
}

func (f *fakeUserStore) add(u *users.User) {
	f.byID[u.ID] = u
	f.byName[u.Username] = u
}

func (f *fakeUserStore) GetByUsername(_ context.Context, username string) (*users.User, error) {
	if u, ok := f.byName[username]; ok {
		return u, nil
	}
	return nil, users.ErrNotFound
}

func (f *fakeUserStore) GetByID(_ context.Context, id uuid.UUID) (*users.User, error) {
	if u, ok := f.byID[id]; ok {
		return u, nil
	}
	return nil, users.ErrNotFound
}

func (f *fakeUserStore) ClearExpiredLock(_ context.Context, id uuid.UUID) error { return nil }

func (f *fakeUserStore) RecordLoginSuccess(_ context.Context, id uuid.UUID, _ string) error {
	f.failCounts[id] = 0
	return nil
}

func (f *fakeUserStore) RecordLoginFailure(_ context.Context, id uuid.UUID, maxAttempts int, lock time.Duration) (bool, error) {
	f.failCounts[id]++
	if maxAttempts > 0 && f.failCounts[id] >= maxAttempts {
		u := f.byID[id]
		u.Status = users.StatusLocked
		until := time.Now().Add(lock)
		u.LockedUntil = &until
		return true, nil
	}
	return false, nil
}

func (f *fakeUserStore) GetRoles(_ context.Context, _ uuid.UUID) ([]users.RoleInfo, error) {
	return []users.RoleInfo{{Code: "SYSTEM_ADMIN", Name: "系统管理员"}}, nil
}

func (f *fakeUserStore) GetPermissions(_ context.Context, _ uuid.UUID) ([]string, error) {
	return []string{"users.read"}, nil
}

func (f *fakeUserStore) GetPasswordHistories(_ context.Context, _ uuid.UUID, _ int) ([]string, error) {
	return nil, nil
}

func (f *fakeUserStore) ChangePassword(_ context.Context, _ uuid.UUID, _, _ string, _ *time.Time, revokeSessions bool) error {
	f.changePwdRevokeSessions = append(f.changePwdRevokeSessions, revokeSessions)
	return nil
}

func (f *fakeUserStore) SaveTOTPPending(_ context.Context, userID uuid.UUID, pendingEnc string, recoveryHashes []string) error {
	u, ok := f.byID[userID]
	if !ok {
		return users.ErrNotFound
	}
	u.TOTPPendingSecretEncrypted = &pendingEnc
	u.TOTPRecoveryCodeHashes = recoveryHashes
	return nil
}

func (f *fakeUserStore) EnableTOTP(_ context.Context, userID uuid.UUID) error {
	u, ok := f.byID[userID]
	if !ok {
		return users.ErrNotFound
	}
	if u.TOTPPendingSecretEncrypted == nil {
		return users.ErrNoTOTPPending
	}
	u.TOTPSecretEncrypted = u.TOTPPendingSecretEncrypted
	u.TOTPPendingSecretEncrypted = nil
	u.TOTPEnabled = true
	now := time.Now()
	u.TOTPEnabledAt = &now
	return nil
}

func (f *fakeUserStore) ClearTOTP(_ context.Context, userID uuid.UUID) error {
	u, ok := f.byID[userID]
	if !ok {
		return users.ErrNotFound
	}
	u.TOTPSecretEncrypted = nil
	u.TOTPPendingSecretEncrypted = nil
	u.TOTPEnabled = false
	u.TOTPEnabledAt = nil
	u.TOTPRecoveryCodeHashes = nil
	return nil
}

func (f *fakeUserStore) ConsumeTOTPRecoveryCode(_ context.Context, userID uuid.UUID, hash string) (bool, error) {
	u, ok := f.byID[userID]
	if !ok || !u.TOTPEnabled {
		return false, nil
	}
	for i, h := range u.TOTPRecoveryCodeHashes {
		if h == hash {
			// 命中即移除，保证一次性使用语义
			u.TOTPRecoveryCodeHashes = append(u.TOTPRecoveryCodeHashes[:i], u.TOTPRecoveryCodeHashes[i+1:]...)
			return true, nil
		}
	}
	return false, nil
}

type fakeSessionService struct {
	created int
	// revokedAll 记录 RevokeAllForUser 调用的 userID 与 reason
	revokedAll []revokeAllCall
}

type revokeAllCall struct {
	userID uuid.UUID
	reason string
}

func (f *fakeSessionService) Create(_ context.Context, userID uuid.UUID, username string, roles, perms []string,
	ip, ua string, mustChangePwd bool, _ sessions.Policy) (*sessions.Session, error) {
	f.created++
	return &sessions.Session{
		ID:             "test-session-" + uuid.NewString(),
		UserID:         userID,
		Username:       username,
		Roles:          roles,
		Permissions:    perms,
		AbsoluteExpiry: time.Now().Add(8 * time.Hour),
	}, nil
}

func (f *fakeSessionService) Revoke(_ context.Context, _, _ string) error { return nil }

func (f *fakeSessionService) RevokeAllForUser(_ context.Context, userID uuid.UUID, reason string) error {
	f.revokedAll = append(f.revokedAll, revokeAllCall{userID: userID, reason: reason})
	return nil
}

type fakeSettingsService struct{}

func (fakeSettingsService) LoginPolicy(context.Context) settings.LoginPolicy {
	return settings.LoginPolicy{MaxFailedAttempts: 5, LockMinutes: 15, RateLimitPerMinute: 10}
}

func (fakeSettingsService) PasswordPolicy(context.Context) security.PasswordPolicy {
	return security.PasswordPolicy{}
}

func (fakeSettingsService) SessionPolicyValues(context.Context) (int, int, int, bool) {
	return 30, 8, 3, true
}

func (fakeSettingsService) GetBool(_ context.Context, _, _ string, def bool) bool { return def }

type fakeLoginLogs struct{ entries []loginlogs.RecordInput }

func (f *fakeLoginLogs) Record(_ context.Context, in loginlogs.RecordInput) error {
	f.entries = append(f.entries, in)
	return nil
}

func (f *fakeLoginLogs) count(eventType, failureCode string) int {
	n := 0
	for _, e := range f.entries {
		if e.EventType == eventType && e.FailureCode == failureCode {
			n++
		}
	}
	return n
}

type fakeAudits struct{ entries []audits.RecordInput }

func (f *fakeAudits) Record(_ context.Context, in audits.RecordInput) error {
	f.entries = append(f.entries, in)
	return nil
}

func (f *fakeAudits) hasAction(action string) bool {
	for _, e := range f.entries {
		if e.Action == action {
			return true
		}
	}
	return false
}

type fakeCache struct{ m map[string]string }

func newFakeCache() *fakeCache { return &fakeCache{m: map[string]string{}} }

func (f *fakeCache) Get(_ context.Context, key string) (string, error) {
	if v, ok := f.m[key]; ok {
		return v, nil
	}
	return "", errors.New("key not found")
}

func (f *fakeCache) Set(_ context.Context, key, value string, _ time.Duration) error {
	f.m[key] = value
	return nil
}

func (f *fakeCache) Del(_ context.Context, keys ...string) error {
	for _, k := range keys {
		delete(f.m, k)
	}
	return nil
}

// ---------- 测试装配 ----------

type totpTestEnv struct {
	svc      *Service
	handler  *Handler
	store    *fakeUserStore
	sessions *fakeSessionService
	logs     *fakeLoginLogs
	audits   *fakeAudits
	cache    *fakeCache
	enc      *encryption.Service
}

func newTOTPTestEnv(t *testing.T) *totpTestEnv {
	t.Helper()
	enc, err := encryption.NewWithKey([]byte("0123456789abcdef0123456789abcdef"))
	if err != nil {
		t.Fatalf("new encryption: %v", err)
	}
	store := newFakeUserStore()
	sess := &fakeSessionService{}
	logs := &fakeLoginLogs{}
	au := &fakeAudits{}
	c := newFakeCache()
	svc := &Service{
		users: store, sessions: sess, settings: fakeSettingsService{},
		logs: logs, audits: au, cache: c, enc: enc,
	}
	return &totpTestEnv{
		svc: svc, handler: &Handler{svc: svc},
		store: store, sessions: sess, logs: logs, audits: au, cache: c, enc: enc,
	}
}

// addUser 创建测试用户（密码经真实哈希，可校验）。
func (e *totpTestEnv) addUser(t *testing.T, username, password string, totpEnabled bool) *users.User {
	t.Helper()
	hash, err := security.HashPassword(password)
	if err != nil {
		t.Fatalf("hash password: %v", err)
	}
	u := &users.User{
		ID:           uuid.New(),
		Username:     username,
		DisplayName:  username,
		PasswordHash: hash,
		Status:       users.StatusActive,
		TOTPEnabled:  totpEnabled,
	}
	e.store.add(u)
	return u
}

// armTOTP 为用户装配已启用的 TOTP（密钥加密落库 + 恢复码哈希），返回明文密钥与恢复码。
func (e *totpTestEnv) armTOTP(t *testing.T, u *users.User) (string, []string) {
	t.Helper()
	secret, err := security.GenerateTOTPSecret()
	if err != nil {
		t.Fatalf("generate secret: %v", err)
	}
	encSecret, err := e.enc.Encrypt(secret)
	if err != nil {
		t.Fatalf("encrypt secret: %v", err)
	}
	codes, err := security.GenerateRecoveryCodes(10)
	if err != nil {
		t.Fatalf("generate recovery codes: %v", err)
	}
	hashes := make([]string, len(codes))
	for i, c := range codes {
		hashes[i], err = security.HashRecoveryCode(c)
		if err != nil {
			t.Fatalf("hash recovery code: %v", err)
		}
	}
	u.TOTPSecretEncrypted = &encSecret
	u.TOTPRecoveryCodeHashes = hashes
	u.TOTPEnabled = true
	return secret, codes
}

// withPrincipal 模拟认证链：注入登录主体。
func withPrincipal(u *users.User, next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		p := &authz.Principal{UserID: u.ID, Username: u.Username}
		next.ServeHTTP(w, r.WithContext(authz.WithPrincipal(r.Context(), p)))
	})
}

type envelope struct {
	Code    string          `json:"code"`
	Message string          `json:"message"`
	Data    json.RawMessage `json:"data"`
}

func doJSON(t *testing.T, h http.Handler, method, path, body string) *httptest.ResponseRecorder {
	t.Helper()
	var reader *strings.Reader
	if body == "" {
		reader = strings.NewReader("")
	} else {
		reader = strings.NewReader(body)
	}
	req := httptest.NewRequest(method, path, reader)
	if body != "" {
		req.Header.Set("Content-Type", "application/json")
	}
	rr := httptest.NewRecorder()
	h.ServeHTTP(rr, req)
	return rr
}

func decodeEnvelope(t *testing.T, rr *httptest.ResponseRecorder) envelope {
	t.Helper()
	var env envelope
	if err := json.Unmarshal(rr.Body.Bytes(), &env); err != nil {
		t.Fatalf("decode response: %v, body=%s", err, rr.Body.String())
	}
	return env
}

// loginChallenge 走登录拿到 TOTP 挑战令牌。
func (e *totpTestEnv) loginChallenge(t *testing.T, username, password string) string {
	t.Helper()
	rr := doJSON(t, http.HandlerFunc(e.handler.Login), http.MethodPost, "/api/v1/auth/login",
		`{"username":"`+username+`","password":"`+password+`"}`)
	env := decodeEnvelope(t, rr)
	if rr.Code != http.StatusOK || env.Code != "TOTP_REQUIRED" {
		t.Fatalf("login status=%d code=%s, want 200 TOTP_REQUIRED", rr.Code, env.Code)
	}
	var data struct {
		ChallengeToken string `json:"challenge_token"`
	}
	if err := json.Unmarshal(env.Data, &data); err != nil || data.ChallengeToken == "" {
		t.Fatalf("missing challenge_token: %s", rr.Body.String())
	}
	return data.ChallengeToken
}

// wrongTOTPCode 返回一个与当前有效窗口（±1 时间步）均不匹配的 6 位错误令牌，避免测试偶发命中。
func wrongTOTPCode(t *testing.T, secret string) string {
	t.Helper()
	valid := map[string]bool{}
	for _, at := range []time.Time{time.Now().Add(-30 * time.Second), time.Now(), time.Now().Add(30 * time.Second)} {
		c, err := security.TOTPCode(secret, at)
		if err != nil {
			t.Fatalf("totp code: %v", err)
		}
		valid[c] = true
	}
	for i := 0; i < 1000000; i++ {
		c := fmt.Sprintf("%06d", i)
		if !valid[c] {
			return c
		}
	}
	t.Fatal("unreachable")
	return ""
}

// ---------- 登录分支 ----------

func TestLoginReturnsTOTPChallengeWhenEnabled(t *testing.T) {
	env := newTOTPTestEnv(t)
	u := env.addUser(t, "alice", "Passw0rd!2026", true)
	env.armTOTP(t, u)

	token := env.loginChallenge(t, "alice", "Passw0rd!2026")
	// 未创建会话
	if env.sessions.created != 0 {
		t.Fatalf("session created during TOTP challenge, created=%d", env.sessions.created)
	}
	// 挑战令牌落 Valkey（键纪律 jiuzhang:totp:challenge:<token> → 绑定用户与首步来源的 JSON）
	raw, ok := env.cache.m[totpChallengePrefix+token]
	if !ok {
		t.Fatal("challenge token not stored in cache")
	}
	var ch totpChallenge
	if err := json.Unmarshal([]byte(raw), &ch); err != nil {
		t.Fatalf("challenge cache value not JSON: %v", err)
	}
	if ch.UserID != u.ID {
		t.Fatalf("challenge user = %s, want %s", ch.UserID, u.ID)
	}
	if ch.SourceIP != "192.0.2.1" { // httptest 默认 RemoteAddr 192.0.2.1:1234
		t.Fatalf("challenge source ip = %q, want 192.0.2.1", ch.SourceIP)
	}
	if env.logs.count(loginlogs.EventLoginTOTPChallenge, "") != 1 {
		t.Fatal("missing LOGIN_TOTP_CHALLENGE login log")
	}
}

func TestLoginWithoutTOTPUnchanged(t *testing.T) {
	env := newTOTPTestEnv(t)
	env.addUser(t, "bob", "Passw0rd!2026", false)

	rr := doJSON(t, http.HandlerFunc(env.handler.Login), http.MethodPost, "/api/v1/auth/login",
		`{"username":"bob","password":"Passw0rd!2026"}`)
	env2 := decodeEnvelope(t, rr)
	if rr.Code != http.StatusOK || env2.Code != "SUCCESS" {
		t.Fatalf("login status=%d code=%s, want 200 SUCCESS", rr.Code, env2.Code)
	}
	if env.sessions.created != 1 {
		t.Fatalf("session not created, created=%d", env.sessions.created)
	}
	var data struct {
		CSRFToken string `json:"csrf_token"`
		User      struct {
			TOTPEnabled bool `json:"totp_enabled"`
		} `json:"user"`
	}
	if err := json.Unmarshal(env2.Data, &data); err != nil {
		t.Fatalf("decode login data: %v", err)
	}
	if data.CSRFToken == "" {
		t.Fatal("missing csrf_token")
	}
	if data.User.TOTPEnabled {
		t.Fatal("totp_enabled should be false")
	}
}

// ---------- 第二步验证 ----------

func TestTOTPVerifySuccessCreatesSession(t *testing.T) {
	env := newTOTPTestEnv(t)
	u := env.addUser(t, "carol", "Passw0rd!2026", true)
	secret, _ := env.armTOTP(t, u)
	token := env.loginChallenge(t, "carol", "Passw0rd!2026")

	code, err := security.TOTPCode(secret, time.Now())
	if err != nil {
		t.Fatalf("totp code: %v", err)
	}
	rr := doJSON(t, http.HandlerFunc(env.handler.TOTPVerify), http.MethodPost, "/api/v1/auth/totp-verify",
		`{"challenge_token":"`+token+`","code":"`+code+`"}`)
	envResp := decodeEnvelope(t, rr)
	if rr.Code != http.StatusOK || envResp.Code != "SUCCESS" {
		t.Fatalf("verify status=%d code=%s body=%s", rr.Code, envResp.Code, rr.Body.String())
	}
	if env.sessions.created != 1 {
		t.Fatalf("session not created after verify, created=%d", env.sessions.created)
	}
	// 会话 Cookie 与 CSRF Token 下发（与登录一致）
	var sessionCookie *http.Cookie
	for _, c := range rr.Result().Cookies() {
		if c.Name == SessionCookieName {
			sessionCookie = c
		}
	}
	if sessionCookie == nil || sessionCookie.Value == "" {
		t.Fatal("missing session cookie after verify")
	}
	if env.logs.count(loginlogs.EventLoginSuccess, "") != 1 {
		t.Fatal("missing LOGIN_SUCCESS log after verify")
	}

	// 挑战令牌一次性：二次使用拒绝
	rr2 := doJSON(t, http.HandlerFunc(env.handler.TOTPVerify), http.MethodPost, "/api/v1/auth/totp-verify",
		`{"challenge_token":"`+token+`","code":"`+code+`"}`)
	env2 := decodeEnvelope(t, rr2)
	if rr2.Code != http.StatusUnauthorized || env2.Code != "UNAUTHENTICATED" {
		t.Fatalf("reused challenge status=%d code=%s, want 401 UNAUTHENTICATED", rr2.Code, env2.Code)
	}
}

func TestTOTPVerifyInvalidCodeKeepsChallengeAndCountsFailure(t *testing.T) {
	env := newTOTPTestEnv(t)
	u := env.addUser(t, "dave", "Passw0rd!2026", true)
	secret, _ := env.armTOTP(t, u)
	token := env.loginChallenge(t, "dave", "Passw0rd!2026")

	// 错误动态令牌：401 TOTP_INVALID，挑战保留可重试，失败计数 +1
	rr := doJSON(t, http.HandlerFunc(env.handler.TOTPVerify), http.MethodPost, "/api/v1/auth/totp-verify",
		`{"challenge_token":"`+token+`","code":"`+wrongTOTPCode(t, secret)+`"}`)
	envResp := decodeEnvelope(t, rr)
	if rr.Code != http.StatusUnauthorized || envResp.Code != "TOTP_INVALID" {
		t.Fatalf("wrong code status=%d code=%s, want 401 TOTP_INVALID", rr.Code, envResp.Code)
	}
	if env.store.failCounts[u.ID] != 1 {
		t.Fatalf("fail count = %d, want 1", env.store.failCounts[u.ID])
	}
	if env.logs.count(loginlogs.EventLoginFailure, "TOTP_INVALID") != 1 {
		t.Fatal("missing TOTP_INVALID login failure log")
	}
	if env.sessions.created != 0 {
		t.Fatal("session must not be created on failed verify")
	}

	// 同一挑战重试正确令牌：成功
	code, _ := security.TOTPCode(secret, time.Now())
	rr2 := doJSON(t, http.HandlerFunc(env.handler.TOTPVerify), http.MethodPost, "/api/v1/auth/totp-verify",
		`{"challenge_token":"`+token+`","code":"`+code+`"}`)
	if rr2.Code != http.StatusOK {
		t.Fatalf("retry status=%d body=%s", rr2.Code, rr2.Body.String())
	}
}

func TestTOTPVerifyChallengeInvalid(t *testing.T) {
	env := newTOTPTestEnv(t)
	rr := doJSON(t, http.HandlerFunc(env.handler.TOTPVerify), http.MethodPost, "/api/v1/auth/totp-verify",
		`{"challenge_token":"no-such-token","code":"123456"}`)
	envResp := decodeEnvelope(t, rr)
	if rr.Code != http.StatusUnauthorized || envResp.Code != "UNAUTHENTICATED" {
		t.Fatalf("status=%d code=%s, want 401 UNAUTHENTICATED", rr.Code, envResp.Code)
	}
	if env.logs.count(loginlogs.EventLoginFailure, "TOTP_CHALLENGE_INVALID") != 1 {
		t.Fatal("missing TOTP_CHALLENGE_INVALID login failure log")
	}
}

func TestTOTPVerifyRecoveryCodeOneTime(t *testing.T) {
	env := newTOTPTestEnv(t)
	u := env.addUser(t, "erin", "Passw0rd!2026", true)
	_, codes := env.armTOTP(t, u)

	// 第一次使用恢复码：成功
	token := env.loginChallenge(t, "erin", "Passw0rd!2026")
	rr := doJSON(t, http.HandlerFunc(env.handler.TOTPVerify), http.MethodPost, "/api/v1/auth/totp-verify",
		`{"challenge_token":"`+token+`","code":"`+codes[0]+`"}`)
	if rr.Code != http.StatusOK {
		t.Fatalf("recovery verify status=%d body=%s", rr.Code, rr.Body.String())
	}
	if len(u.TOTPRecoveryCodeHashes) != 9 {
		t.Fatalf("recovery code not consumed, remaining=%d", len(u.TOTPRecoveryCodeHashes))
	}

	// 同一恢复码再次使用：失败（一次性）
	token2 := env.loginChallenge(t, "erin", "Passw0rd!2026")
	rr2 := doJSON(t, http.HandlerFunc(env.handler.TOTPVerify), http.MethodPost, "/api/v1/auth/totp-verify",
		`{"challenge_token":"`+token2+`","code":"`+codes[0]+`"}`)
	env2 := decodeEnvelope(t, rr2)
	if rr2.Code != http.StatusUnauthorized || env2.Code != "TOTP_INVALID" {
		t.Fatalf("reused recovery code status=%d code=%s, want 401 TOTP_INVALID", rr2.Code, env2.Code)
	}
}

// ---------- 自助管理（setup/enable/disable） ----------

func TestTOTPSetupEnableDisableFlow(t *testing.T) {
	env := newTOTPTestEnv(t)
	u := env.addUser(t, "frank", "Passw0rd!2026", false)
	authed := func(h http.HandlerFunc) http.Handler { return withPrincipal(u, h) }

	// setup：返回明文密钥/otpauth_url/10 个恢复码
	rr := doJSON(t, authed(env.handler.TOTPSetup), http.MethodPost, "/api/v1/auth/totp/setup", "")
	envResp := decodeEnvelope(t, rr)
	if rr.Code != http.StatusOK || envResp.Code != "SUCCESS" {
		t.Fatalf("setup status=%d code=%s", rr.Code, envResp.Code)
	}
	var setupData struct {
		Secret        string   `json:"secret"`
		OTPAuthURL    string   `json:"otpauth_url"`
		RecoveryCodes []string `json:"recovery_codes"`
	}
	if err := json.Unmarshal(envResp.Data, &setupData); err != nil {
		t.Fatalf("decode setup data: %v", err)
	}
	if setupData.Secret == "" || !strings.HasPrefix(setupData.OTPAuthURL, "otpauth://totp/") {
		t.Fatalf("bad setup data: %s", string(envResp.Data))
	}
	if len(setupData.RecoveryCodes) != 10 {
		t.Fatalf("recovery codes = %d, want 10", len(setupData.RecoveryCodes))
	}
	// 落库的是密文与哈希，明文不落库
	if u.TOTPPendingSecretEncrypted == nil || *u.TOTPPendingSecretEncrypted == setupData.Secret {
		t.Fatal("pending secret not stored encrypted")
	}
	if !u.TOTPEnabled {
		// setup 不开启，enable 才转正
	} else {
		t.Fatal("totp enabled before enable")
	}

	// enable 前置校验：非 6 位数字 → 400
	rr = doJSON(t, authed(env.handler.TOTPEnable), http.MethodPost, "/api/v1/auth/totp/enable", `{"code":"abc"}`)
	if rr.Code != http.StatusBadRequest {
		t.Fatalf("enable malformed code status=%d, want 400", rr.Code)
	}
	// enable 错误令牌 → 400 TOTP_INVALID，不转正
	rr = doJSON(t, authed(env.handler.TOTPEnable), http.MethodPost, "/api/v1/auth/totp/enable",
		`{"code":"`+wrongTOTPCode(t, setupData.Secret)+`"}`)
	if env2 := decodeEnvelope(t, rr); rr.Code != http.StatusBadRequest || env2.Code != "TOTP_INVALID" {
		t.Fatalf("enable wrong code status=%d code=%s, want 400 TOTP_INVALID", rr.Code, env2.Code)
	}
	if u.TOTPEnabled {
		t.Fatal("totp enabled on wrong code")
	}
	// enable 正确令牌 → 200，转正并清空 pending
	code, _ := security.TOTPCode(setupData.Secret, time.Now())
	rr = doJSON(t, authed(env.handler.TOTPEnable), http.MethodPost, "/api/v1/auth/totp/enable", `{"code":"`+code+`"}`)
	if rr.Code != http.StatusOK {
		t.Fatalf("enable status=%d body=%s", rr.Code, rr.Body.String())
	}
	if !u.TOTPEnabled || u.TOTPSecretEncrypted == nil || u.TOTPPendingSecretEncrypted != nil {
		t.Fatal("totp not promoted after enable")
	}

	// 已开启后重复 setup → 409
	rr = doJSON(t, authed(env.handler.TOTPSetup), http.MethodPost, "/api/v1/auth/totp/setup", "")
	if rr.Code != http.StatusConflict {
		t.Fatalf("re-setup status=%d, want 409", rr.Code)
	}

	// disable：错误令牌 → 400
	rr = doJSON(t, authed(env.handler.TOTPDisable), http.MethodPost, "/api/v1/auth/totp/disable",
		`{"code":"`+wrongTOTPCode(t, setupData.Secret)+`"}`)
	if env3 := decodeEnvelope(t, rr); rr.Code != http.StatusBadRequest || env3.Code != "TOTP_INVALID" {
		t.Fatalf("disable wrong code status=%d code=%s, want 400 TOTP_INVALID", rr.Code, env3.Code)
	}
	if !u.TOTPEnabled {
		t.Fatal("totp disabled on wrong code")
	}
	// disable：恢复码（一次性）→ 200，全部字段清空
	rr = doJSON(t, authed(env.handler.TOTPDisable), http.MethodPost, "/api/v1/auth/totp/disable",
		`{"code":"`+setupData.RecoveryCodes[0]+`"}`)
	if rr.Code != http.StatusOK {
		t.Fatalf("disable status=%d body=%s", rr.Code, rr.Body.String())
	}
	if u.TOTPEnabled || u.TOTPSecretEncrypted != nil || len(u.TOTPRecoveryCodeHashes) != 0 {
		t.Fatal("totp fields not cleared after disable")
	}

	// 审计：setup/enable/disable 均已记录（disable 为高危）
	for _, action := range []string{"totp_setup", "totp_enable", "totp_disable"} {
		if !env.audits.hasAction(action) {
			t.Fatalf("missing audit action %s", action)
		}
	}
}

func TestTOTPEnableWithoutPending(t *testing.T) {
	env := newTOTPTestEnv(t)
	u := env.addUser(t, "grace", "Passw0rd!2026", false)
	rr := doJSON(t, withPrincipal(u, http.HandlerFunc(env.handler.TOTPEnable)),
		http.MethodPost, "/api/v1/auth/totp/enable", `{"code":"123456"}`)
	if rr.Code != http.StatusConflict {
		t.Fatalf("enable without pending status=%d, want 409", rr.Code)
	}
}

func TestTOTPDisableWhenNotEnabled(t *testing.T) {
	env := newTOTPTestEnv(t)
	u := env.addUser(t, "heidi", "Passw0rd!2026", false)
	rr := doJSON(t, withPrincipal(u, http.HandlerFunc(env.handler.TOTPDisable)),
		http.MethodPost, "/api/v1/auth/totp/disable", `{"code":"123456"}`)
	if rr.Code != http.StatusConflict {
		t.Fatalf("disable when not enabled status=%d, want 409", rr.Code)
	}
}

func TestTOTPSelfServiceRequiresAuth(t *testing.T) {
	env := newTOTPTestEnv(t)
	for path, h := range map[string]http.HandlerFunc{
		"/api/v1/auth/totp/setup":   env.handler.TOTPSetup,
		"/api/v1/auth/totp/enable":  env.handler.TOTPEnable,
		"/api/v1/auth/totp/disable": env.handler.TOTPDisable,
	} {
		rr := doJSON(t, http.HandlerFunc(h), http.MethodPost, path, `{"code":"123456"}`)
		if rr.Code != http.StatusUnauthorized {
			t.Fatalf("%s without auth status=%d, want 401", path, rr.Code)
		}
	}
}

// ---------- 挑战令牌来源绑定（防跨机转移） ----------

// doJSONFrom 以指定来源 IP/UA 发起 JSON 请求（挑战绑定测试用）。
func doJSONFrom(t *testing.T, h http.Handler, remoteAddr, ua, body string) *httptest.ResponseRecorder {
	t.Helper()
	req := httptest.NewRequest(http.MethodPost, "/api/v1/auth/totp-verify", strings.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	req.RemoteAddr = remoteAddr
	if ua != "" {
		req.Header.Set("User-Agent", ua)
	}
	rr := httptest.NewRecorder()
	h.ServeHTTP(rr, req)
	return rr
}

func TestTOTPVerifyRejectsOriginMismatch(t *testing.T) {
	env := newTOTPTestEnv(t)
	u := env.addUser(t, "ivan", "Passw0rd!2026", true)
	secret, _ := env.armTOTP(t, u)
	token := env.loginChallenge(t, "ivan", "Passw0rd!2026") // 首步来源 192.0.2.1，UA 空
	code, err := security.TOTPCode(secret, time.Now())
	if err != nil {
		t.Fatalf("totp code: %v", err)
	}
	body := `{"challenge_token":"` + token + `","code":"` + code + `"}`

	// 来源 IP 不同：拒绝，视为令牌被转移
	rr := doJSONFrom(t, http.HandlerFunc(env.handler.TOTPVerify), "203.0.113.7:9000", "", body)
	if envResp := decodeEnvelope(t, rr); rr.Code != http.StatusUnauthorized || envResp.Code != "UNAUTHENTICATED" {
		t.Fatalf("cross-ip verify status=%d code=%s, want 401 UNAUTHENTICATED", rr.Code, envResp.Code)
	}
	if env.sessions.created != 0 {
		t.Fatal("session must not be created on origin mismatch")
	}
	if env.logs.count(loginlogs.EventLoginFailure, "TOTP_CHALLENGE_ORIGIN_MISMATCH") != 1 {
		t.Fatal("missing TOTP_CHALLENGE_ORIGIN_MISMATCH login failure log")
	}

	// UA 不同：同样拒绝
	rr = doJSONFrom(t, http.HandlerFunc(env.handler.TOTPVerify), "192.0.2.1:1234", "evil-agent", body)
	if rr.Code != http.StatusUnauthorized {
		t.Fatalf("cross-ua verify status=%d, want 401", rr.Code)
	}

	// 挑战未被消费：首步来源机器仍可正常完成第二步
	rr = doJSON(t, http.HandlerFunc(env.handler.TOTPVerify), http.MethodPost, "/api/v1/auth/totp-verify", body)
	if rr.Code != http.StatusOK {
		t.Fatalf("origin retry status=%d body=%s, want 200", rr.Code, rr.Body.String())
	}
}

// ---------- 改密吊销全部会话（含当前会话） ----------

func TestChangePasswordRevokesAllSessionsIncludingCurrent(t *testing.T) {
	env := newTOTPTestEnv(t)
	u := env.addUser(t, "judy", "Passw0rd!2026", false)

	err := env.svc.ChangePassword(context.Background(), ChangePasswordInput{
		UserID:      u.ID,
		OldPassword: "Passw0rd!2026",
		NewPassword: "N3w!Passw0rd2026",
	})
	if err != nil {
		t.Fatalf("change password: %v", err)
	}
	// 存储层 revokeSessions=true（事务内吊销含当前会话的全部持久化会话）
	if len(env.store.changePwdRevokeSessions) != 1 || !env.store.changePwdRevokeSessions[0] {
		t.Fatalf("store ChangePassword revokeSessions calls = %v, want [true]", env.store.changePwdRevokeSessions)
	}
	// 会话服务按用户全量吊销（清理 Valkey 缓存）
	if len(env.sessions.revokedAll) != 1 ||
		env.sessions.revokedAll[0].userID != u.ID ||
		env.sessions.revokedAll[0].reason != "password_changed" {
		t.Fatalf("RevokeAllForUser calls = %+v, want one password_changed for %s", env.sessions.revokedAll, u.ID)
	}
	if env.logs.count(loginlogs.EventPasswordChange, "") != 1 {
		t.Fatal("missing PASSWORD_CHANGE login log")
	}
}

// ---------- 登录用户名枚举时间侧信道 ----------

func TestLoginUnknownUserVerifiesDummyHash(t *testing.T) {
	env := newTOTPTestEnv(t)

	// 预设假哈希必须是格式合法、校验必失败的 Argon2id 编码（保证拉平分支真实执行完整运算）
	if err := security.VerifyPassword("any-password", dummyPasswordHash); !errors.Is(err, security.ErrPasswordMismatch) {
		t.Fatalf("dummy hash verify err = %v, want ErrPasswordMismatch", err)
	}

	// 用户不存在：仍走假哈希校验路径，对外统一 ErrInvalidCredentials
	_, err := env.svc.Login(context.Background(), LoginInput{Username: "no_such_user", Password: "x"})
	if !errors.Is(err, ErrInvalidCredentials) {
		t.Fatalf("unknown user login err = %v, want ErrInvalidCredentials", err)
	}
	if env.logs.count(loginlogs.EventLoginFailure, "BAD_CREDENTIALS") != 1 {
		t.Fatal("missing BAD_CREDENTIALS login failure log for unknown user")
	}
}

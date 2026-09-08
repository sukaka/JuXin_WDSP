// Package tests 是阶段2接口集成测试。
// 依赖运行中的 PostgreSQL 与 Valkey（通过环境变量配置），
// 使用独立测试数据库 jiuzhang_waf_test，测试前重建。
package tests

import (
	"context"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"testing"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/jiuzhang-waf/server/internal/app"
	"github.com/jiuzhang-waf/server/internal/cache"
	"github.com/jiuzhang-waf/server/internal/config"
	"github.com/jiuzhang-waf/server/internal/database"
	"github.com/jiuzhang-waf/server/internal/security"
	"github.com/jiuzhang-waf/server/internal/users"
)

const testDBName = "jiuzhang_waf_test"

// testEnv 是集成测试环境。
type testEnv struct {
	server   *httptest.Server
	db       *pgxpool.Pool
	cache    *cache.Client
	cfg      *config.Config
	adminPwd string
	app      *app.App
}

// baseTestCfg 公共测试配置（DB/Valkey/Security），各产品形态套件在此之上叠加
// Product 等差异配置后交给 newTestEnv 装配。
func baseTestCfg() *config.Config {
	return &config.Config{
		Env: "test",
		DB: config.DBConfig{
			Host:     envOr("POSTGRES_HOST", "127.0.0.1"),
			Port:     envInt("POSTGRES_PORT", 5432),
			Database: testDBName,
			User:     envOr("POSTGRES_USER", "jiuzhang"),
			Password: os.Getenv("POSTGRES_PASSWORD"),
			SSLMode:  "disable",
			MaxConns: 5,
		},
		Cache: config.CacheConfig{
			Host:     envOr("VALKEY_HOST", "127.0.0.1"),
			Port:     envInt("VALKEY_PORT", 6379),
			Password: os.Getenv("VALKEY_PASSWORD"),
			DB:       15, // 独立 Valkey DB
		},
		Security: config.SecurityConfig{
			CookieSecure: false,
		},
		AI: config.AIConfig{Enabled: true},
	}
}

// setupTestEnv 初始化测试环境（每个测试套件一次），并导入公共测试授权
// （离线授权门控下业务接口 423，存量用例统一在 setup 阶段解锁）。
func setupTestEnv(t *testing.T) *testEnv {
	t.Helper()
	env := newTestEnv(t, baseTestCfg())
	env.importBaseLicense(t)
	return env
}

// newTestEnv 装配测试应用环境：重建测试库、全量迁移、Valkey、测试管理员、
// 授权验签环境变量（app.New 前注入），启动真实应用 + httptest.Server。
// 不导入授权——授权流程测试直接用本函数构造无授权环境。
func newTestEnv(t *testing.T, cfg *config.Config) *testEnv {
	t.Helper()
	if testing.Short() {
		t.Skip("integration test skipped in short mode")
	}

	// 数据目录指向测试临时目录，避免在仓库内产生报告/备份/配置产物
	if cfg.Gateway.DataDir == "" {
		cfg.Gateway.DataDir = t.TempDir()
	}
	if cfg.DB.Password == "" || cfg.Cache.Password == "" {
		t.Skip("POSTGRES_PASSWORD/VALKEY_PASSWORD not set, skipping integration test")
	}

	ctx := context.Background()

	// 重建测试数据库
	adminDSN := fmt.Sprintf("postgres://%s:%s@%s:%d/postgres?sslmode=disable",
		cfg.DB.User, cfg.DB.Password, cfg.DB.Host, cfg.DB.Port)
	adminPool, err := pgxpool.New(ctx, adminDSN)
	if err != nil {
		t.Fatalf("connect admin db: %v", err)
	}
	_, _ = adminPool.Exec(ctx, fmt.Sprintf("DROP DATABASE IF EXISTS %s", testDBName))
	if _, err := adminPool.Exec(ctx, fmt.Sprintf("CREATE DATABASE %s", testDBName)); err != nil {
		adminPool.Close()
		t.Fatalf("create test db: %v", err)
	}
	adminPool.Close()

	// 迁移
	db, err := database.Connect(ctx, cfg.DB)
	if err != nil {
		t.Fatalf("connect test db: %v", err)
	}
	if err := database.Migrate(ctx, db, "../migrations", "up"); err != nil {
		t.Fatalf("migrate: %v", err)
	}

	// Valkey
	cacheClient, err := cache.New(ctx, cfg.Cache)
	if err != nil {
		t.Fatalf("connect valkey: %v", err)
	}
	cacheClient.Redis().FlushDB(ctx)

	// 创建测试管理员（密码固定用于测试）
	adminPwd := "Test@Admin2026!"
	hash, _ := security.HashPassword(adminPwd)
	store := users.NewStore(db)
	now := time.Now()
	adminUser := &users.User{
		Username:           "test_sysadmin",
		DisplayName:        "测试系统管理员",
		PasswordHash:       hash,
		Status:             users.StatusActive,
		MustChangePassword: false,
		PasswordChangedAt:  &now,
	}
	if err := store.Create(ctx, adminUser); err != nil {
		t.Fatalf("create admin: %v", err)
	}
	roleID, err := store.GetRoleIDByCode(ctx, "SYSTEM_ADMIN")
	if err != nil {
		t.Fatalf("get role: %v", err)
	}
	if err := store.AssignRole(ctx, adminUser.ID, roleID, adminUser.ID); err != nil {
		t.Fatalf("assign role: %v", err)
	}

	// 离线授权：测试验签公钥通过装配层显式注入；宿主机指纹文件仍由测试 env 指向。
	vendorKeys := configureTestLicense(t)

	// 启动服务
	application, err := app.NewWithVendorKeys(cfg, db, cacheClient, vendorKeys)
	if err != nil {
		t.Fatalf("initialize application: %v", err)
	}
	server := httptest.NewServer(application.Handler)
	t.Cleanup(func() {
		server.Close()
		db.Close()
		cacheClient.Close()
	})

	return &testEnv{
		server:   server,
		db:       db,
		cache:    cacheClient,
		cfg:      cfg,
		adminPwd: adminPwd,
		app:      application,
	}
}

// login 登录并返回 cookie 与 csrf token。
func (e *testEnv) login(t *testing.T, username, password string) ([]*http.Cookie, string) {
	t.Helper()
	// 验证码
	capID, capCode := e.captcha(t)
	body := fmt.Sprintf(`{"username":%q,"password":%q,"captcha_id":%q,"captcha_code":%q}`,
		username, password, capID, capCode)
	resp := e.post(t, "/api/v1/auth/login", body, nil, "")
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("login failed: status %d", resp.StatusCode)
	}
	var result apiResp
	readJSON(t, resp, &result)
	csrf, _ := result.Data["csrf_token"].(string)
	return resp.Cookies(), csrf
}

// captcha 获取验证码（直接从 Valkey 读答案）。
func (e *testEnv) captcha(t *testing.T) (string, string) {
	t.Helper()
	resp, err := http.Get(e.server.URL + "/api/v1/auth/captcha")
	if err != nil {
		t.Fatalf("get captcha: %v", err)
	}
	defer resp.Body.Close()
	var result apiResp
	readJSON(t, resp, &result)
	capID, _ := result.Data["captcha_id"].(string)
	code, err := e.cache.Get(context.Background(), "jiuzhang:captcha:"+capID)
	if err != nil {
		t.Fatalf("read captcha code: %v", err)
	}
	return capID, code
}

// captchaTolerant 获取验证码，被限速（429）时返回占位值而不失败（限速测试专用）。
func (e *testEnv) captchaTolerant(t *testing.T) (string, string) {
	t.Helper()
	resp, err := http.Get(e.server.URL + "/api/v1/auth/captcha")
	if err != nil {
		t.Fatalf("get captcha: %v", err)
	}
	defer resp.Body.Close()
	var result apiResp
	readJSON(t, resp, &result)
	capID, _ := result.Data["captcha_id"].(string)
	if capID == "" {
		// 验证码接口已限速：返回占位值（后续请求预期同样被限速）
		return "00000000-0000-0000-0000-000000000000", "0000"
	}
	code, err := e.cache.Get(context.Background(), "jiuzhang:captcha:"+capID)
	if err != nil {
		t.Fatalf("read captcha code: %v", err)
	}
	return capID, code
}

// do 执行请求。
func (e *testEnv) do(t *testing.T, method, path, body string, cookies []*http.Cookie, csrf string) *http.Response {
	t.Helper()
	resp := e.request(t, method, path, body, cookies, csrf)
	return resp
}

func (e *testEnv) post(t *testing.T, path, body string, cookies []*http.Cookie, csrf string) *http.Response {
	t.Helper()
	return e.request(t, http.MethodPost, path, body, cookies, csrf)
}

func (e *testEnv) get(t *testing.T, path string, cookies []*http.Cookie) *http.Response {
	t.Helper()
	return e.request(t, http.MethodGet, path, "", cookies, "")
}

func (e *testEnv) request(t *testing.T, method, path, body string, cookies []*http.Cookie, csrf string) *http.Response {
	t.Helper()
	resp, err := e.rawRequest(method, path, body, cookies, csrf)
	if err != nil {
		t.Fatalf("request %s %s: %v", method, path, err)
	}
	return resp
}

func (e *testEnv) rawRequest(method, path, body string, cookies []*http.Cookie, csrf string) (*http.Response, error) {
	var req *http.Request
	var err error
	if body != "" {
		req, err = http.NewRequest(method, e.server.URL+path, stringReader(body))
	} else {
		req, err = http.NewRequest(method, e.server.URL+path, nil)
	}
	if err != nil {
		return nil, err
	}
	if body != "" {
		req.Header.Set("Content-Type", "application/json")
	}
	if csrf != "" {
		req.Header.Set("X-CSRF-Token", csrf)
	}
	for _, c := range cookies {
		req.AddCookie(c)
	}
	return http.DefaultClient.Do(req)
}

// apiResp 是通用 API 响应。
type apiResp struct {
	Code    string                 `json:"code"`
	Message string                 `json:"message"`
	Data    map[string]interface{} `json:"data"`
	Details interface{}            `json:"details"`
}

func envOr(key, def string) string {
	if v := os.Getenv(key); v != "" {
		return v
	}
	return def
}

func envInt(key string, def int) int {
	if v := os.Getenv(key); v != "" {
		var n int
		if _, err := fmt.Sscanf(v, "%d", &n); err == nil {
			return n
		}
	}
	return def
}

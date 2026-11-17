package gatewayconfig

import (
	"bytes"
	"context"
	"encoding/hex"
	"errors"
	"net"
	"net/http"
	"os"
	"strconv"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/jiuzhang-waf/server/internal/applications"
	"github.com/jiuzhang-waf/server/internal/certificates"
	"github.com/jiuzhang-waf/server/internal/database"
)

const (
	publishSmokeE2EEnabledEnv    = "JIUZHANG_PUBLISH_SMOKE_E2E"
	publishSmokeE2EDSNEnv        = "JIUZHANG_PUBLISH_SMOKE_E2E_POSTGRES_DSN"
	publishSmokeE2ESocketEnv     = "JIUZHANG_PUBLISH_SMOKE_E2E_CADDY_SOCKET"
	publishSmokeE2EAddrEnv       = "JIUZHANG_PUBLISH_SMOKE_E2E_CADDY_ADDR"
	publishSmokeE2EOriginHostEnv = "JIUZHANG_PUBLISH_SMOKE_E2E_ORIGIN_HOST"
	publishSmokeE2EHTTPPort      = 82
	publishSmokeE2EHost          = "publish-smoke-e2e.test"
)

type publishSmokeE2EOrigin struct {
	addr        string
	total       atomic.Int64
	ordinary404 atomic.Int64
	server      *http.Server
	done        chan error
}

func startPublishSmokeE2EOrigin(t *testing.T) *publishSmokeE2EOrigin {
	t.Helper()
	listenAddr := "127.0.0.1:0"
	if os.Getenv(publishSmokeE2EOriginHostEnv) != "" {
		// 脚本内源站由另一隔离容器经用户自建 bridge 网络访问，不映射宿主端口。
		listenAddr = "0.0.0.0:0"
	}
	listener, err := net.Listen("tcp", listenAddr)
	if err != nil {
		t.Fatal(err)
	}
	origin := &publishSmokeE2EOrigin{addr: listener.Addr().String(), done: make(chan error, 1)}
	origin.server = &http.Server{
		ReadHeaderTimeout: 5 * time.Second,
		Handler: http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			origin.total.Add(1)
			if r.URL.Path == "/ordinary-404" {
				origin.ordinary404.Add(1)
			}
			// 故意复刻旧探针墓碑的所有公开特征；新 Publisher 仍必须判 FAIL。
			w.Header().Set("Cache-Control", "no-store")
			w.Header().Set("Content-Type", "text/plain; charset=utf-8")
			w.WriteHeader(http.StatusNotFound)
			_, _ = w.Write([]byte("404 not found"))
		}),
	}
	go func() { origin.done <- origin.server.Serve(listener) }()
	t.Cleanup(func() {
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		_ = origin.server.Shutdown(ctx)
		if err := <-origin.done; err != nil && !errors.Is(err, http.ErrServerClosed) {
			t.Errorf("origin server: %v", err)
		}
	})
	return origin
}

type publishSmokeE2ERoundTripper struct {
	transport *http.Transport
	mode      string
}

func (rt *publishSmokeE2ERoundTripper) RoundTrip(r *http.Request) (*http.Response, error) {
	req := r.Clone(r.Context())
	switch rt.mode {
	case "source-404":
		// 故障注入只改变真实线上路径：请求继续穿过后续 Caddy/WAF/反代，
		// 由真实源站返回带旧墓碑特征的普通 404。
		req.URL.Path = "/ordinary-404"
		req.URL.RawPath = ""
	case "wrong-host":
		req.Host = "wrong-" + req.Host
	case "wrong-key":
		timestamp, err := strconv.ParseInt(req.Header.Get(smokeTimestampHeader), 10, 64)
		if err != nil {
			return nil, err
		}
		binding := &smokeRequestBinding{
			appID: req.Header.Get(smokeAppIDHeader), appCode: req.Header.Get(smokeAppCodeHeader),
			host: smokeCanonicalHost(req.Host), publishID: req.Header.Get(smokePublishIDHeader),
			nonce: req.Header.Get(smokeNonceHeader), timestamp: timestamp,
			probe: req.Header.Get(SmokeMarkerHeader), key: bytes.Repeat([]byte{0x42}, 32),
		}
		req.Header.Set(smokeSignatureHeader, hex.EncodeToString(smokeRequestSignature(binding)))
	}
	return rt.transport.RoundTrip(req)
}

func (rt *publishSmokeE2ERoundTripper) CloseIdleConnections() {
	rt.transport.CloseIdleConnections()
}

type publishSmokeE2EHarness struct {
	ctx      context.Context
	db       *pgxpool.Pool
	apps     *applications.Store
	appID    uuid.UUID
	appCode  string
	dataDir  string
	socket   string
	dialAddr string
	origin   *publishSmokeE2EOrigin
}

func (h *publishSmokeE2EHarness) publisherWithGuard(cfg *GuardConfig) *Publisher {
	provider := &fakeGuardProvider{buildCfg: cfg}
	p := NewPublisher(h.db, nil, h.apps, certificates.NewStore(h.db, nil), h.socket, h.dataDir, nil, nil)
	p.SetGuardProvider(provider)
	// 仅 GuardProvider 与分布式锁使用既有测试替身；应用、任务、版本、验证结果
	// 均经下方真实 PostgreSQL，配置加载/读取使用真实 Caddy Unix Admin API。
	p.lockBackend = newFakePublishLock()
	p.SetSmokeProbe(h.dialAddr, nil)
	return p
}

func (h *publishSmokeE2EHarness) client(t *testing.T, dialAddr, mode string) *http.Client {
	t.Helper()
	dialer := &net.Dialer{Timeout: 3 * time.Second}
	transport := &http.Transport{
		DisableKeepAlives: true,
		DialContext: func(ctx context.Context, network, _ string) (net.Conn, error) {
			return dialer.DialContext(ctx, network, dialAddr)
		},
	}
	client := &http.Client{
		Timeout:   10 * time.Second,
		Transport: &publishSmokeE2ERoundTripper{transport: transport, mode: mode},
	}
	t.Cleanup(client.CloseIdleConnections)
	return client
}

func (h *publishSmokeE2EHarness) publish(t *testing.T, name string, cfg *GuardConfig, client *http.Client) *PublishTask {
	t.Helper()
	p := h.publisherWithGuard(cfg)
	if client != nil {
		p.SetSmokeProbe("", client)
	}
	task, err := p.PublishSync(h.ctx, PublishInput{
		RequestedBy: uuid.Nil,
		RequestID:   "publish-smoke-e2e-" + name,
		AppIDs:      []uuid.UUID{h.appID},
	})
	if err != nil {
		t.Fatalf("PublishSync %s: %v", name, err)
	}
	return task
}

func (h *publishSmokeE2EHarness) baseGuard() *GuardConfig {
	return &GuardConfig{
		TrustedProxies: []GuardProxy{
			{Name: "loopback", CIDR: "127.0.0.0/8", HeaderType: "X_FORWARDED_FOR", Priority: 1},
			{Name: "rfc1918-10", CIDR: "10.0.0.0/8", HeaderType: "X_FORWARDED_FOR", Priority: 2},
			{Name: "rfc1918-172", CIDR: "172.16.0.0/12", HeaderType: "X_FORWARDED_FOR", Priority: 3},
			{Name: "rfc1918-192", CIDR: "192.168.0.0/16", HeaderType: "X_FORWARDED_FOR", Priority: 4},
			{Name: "ula", CIDR: "fc00::/7", HeaderType: "X_FORWARDED_FOR", Priority: 5},
		},
		MaxProxyChain: 3,
		GlobalDeny:    []GuardRule{{ID: "e2e-deny", Address: "203.0.113.99", Priority: 1}},
		GlobalPolicies: []GuardPolicy{{
			ID: "e2e-cc", Name: "真实 CC 精确计数", Dimension: "CLIENT_IP", Algorithm: "SLIDING_WINDOW",
			URIMatchType: "ALL", RequestsLimit: 4, WindowSeconds: 60, Action: "REJECT", Priority: 1,
		}},
		AppRules:       map[string]*GuardAppRules{},
		CounterBackend: "memory",
		MaxCounterKeys: 10000,
		FailOpen:       true,
		EventsLog:      "/var/log/caddy/publish-smoke-e2e-events.log",
		GatewayNode:    "publish-smoke-e2e",
		// 打开真实 debug 回显，CC_EXACT 必须实际计数并在第 N+1 次 429，不能 SKIP。
		DebugCCCounter: true,
	}
}

func (h *publishSmokeE2EHarness) releasedGuard() *GuardConfig {
	cfg := h.baseGuard()
	cfg.APIDynamicProtection = true
	cfg.APIProtectionMode = "OFF"
	cfg.BotPolicy = map[string]*GuardBotPolicy{
		h.appCode: {
			SchemaVersion: 1, ApplicationID: h.appID.String(), Mode: "OFF", Version: 1,
			SignalRules: GuardBotSignalRules{MinIndependentGroups: 2, RequireBehaviorGroup: true},
			Challenge: GuardBotChallenge{
				Type: "JS", NonceTTLSeconds: 90, ClearanceTTLSeconds: 900, Difficulty: 14, MaxAttempts: 3,
			},
			RouteReservation: GuardBotRouteReservation{State: "RELEASED", Namespace: "/_wdsp/bot/v1/"},
		},
	}
	return cfg
}

func (h *publishSmokeE2EHarness) validationResult(t *testing.T, versionID uuid.UUID) (string, string) {
	t.Helper()
	var validation, publication string
	if err := h.db.QueryRow(h.ctx,
		`SELECT validation_result, publish_result FROM gateway_config_versions WHERE id=$1`, versionID,
	).Scan(&validation, &publication); err != nil {
		t.Fatal(err)
	}
	return validation, publication
}

func (h *publishSmokeE2EHarness) assertProtectionProbes(t *testing.T, taskID uuid.UUID) {
	t.Helper()
	rows, err := h.db.Query(h.ctx, `
SELECT validation_step, result, message FROM gateway_validation_results
WHERE publish_task_id=$1 AND validation_type='POST_PUBLISH_SMOKE'`, taskID)
	if err != nil {
		t.Fatal(err)
	}
	defer rows.Close()
	got := map[string]string{}
	for rows.Next() {
		var step, result, message string
		if err := rows.Scan(&step, &result, &message); err != nil {
			t.Fatal(err)
		}
		got[step] = result
		if result != SmokeResultPass {
			t.Logf("%s %s: %s", step, result, message)
		}
	}
	if err := rows.Err(); err != nil {
		t.Fatal(err)
	}
	for _, step := range []string{SmokeProbeRealIP, SmokeProbeBlacklist, SmokeProbeCC, SmokeProbeCCExact} {
		if got[step] != SmokeResultPass {
			t.Fatalf("%s result = %q, want PASS; all results=%v", step, got[step], got)
		}
	}
}

func (h *publishSmokeE2EHarness) assertSuccess(t *testing.T, task *PublishTask, wantValidation string, originBefore int64) {
	t.Helper()
	if task.Status != TaskSuccess || task.TargetVersionID == nil {
		t.Fatalf("publish status=%s code=%s message=%s", task.Status, task.FailureCode, task.FailureMessage)
	}
	validation, publication := h.validationResult(t, *task.TargetVersionID)
	if validation != wantValidation || publication != TaskSuccess {
		t.Fatalf("version validation=%s publish_result=%s, want %s/SUCCESS", validation, publication, wantValidation)
	}
	if got := h.origin.total.Load(); got != originBefore {
		t.Fatalf("successful smoke reached origin: before=%d after=%d", originBefore, got)
	}
	if wantValidation == VersionSmokeSkipped && !strings.Contains(task.ResultSummary, "流量验证降级") {
		t.Fatalf("unreachable smoke must record degradation: %q", task.ResultSummary)
	}
}

func (h *publishSmokeE2EHarness) currentVersion(t *testing.T) uuid.UUID {
	t.Helper()
	var id uuid.UUID
	if err := h.db.QueryRow(h.ctx, `SELECT id FROM gateway_config_versions WHERE is_current=TRUE`).Scan(&id); err != nil {
		t.Fatal(err)
	}
	return id
}

func (h *publishSmokeE2EHarness) currentConfigHash(t *testing.T) string {
	t.Helper()
	hash, err := NewCaddyClient(h.socket).GetConfigHash(h.ctx)
	if err != nil {
		t.Fatal(err)
	}
	return hash
}

func (h *publishSmokeE2EHarness) assertFailureRollback(t *testing.T, task *PublishTask, mode string, beforeVersion uuid.UUID, beforeHash string, originBefore int64) {
	t.Helper()
	if task.Status != TaskFailed || task.FailureCode != "VERIFY_FAILED_ROLLED_BACK" || task.TargetVersionID == nil {
		t.Fatalf("failure status=%s code=%s message=%s", task.Status, task.FailureCode, task.FailureMessage)
	}
	validation, publication := h.validationResult(t, *task.TargetVersionID)
	if validation != VersionSmokeFail || publication != "VERIFY_FAILED" {
		t.Fatalf("failed version validation=%s publish_result=%s", validation, publication)
	}
	var failedRows int
	if err := h.db.QueryRow(h.ctx, `
SELECT count(*) FROM gateway_validation_results
WHERE publish_task_id=$1 AND validation_type='POST_PUBLISH_SMOKE' AND result='FAIL'`, task.ID).Scan(&failedRows); err != nil {
		t.Fatal(err)
	}
	if failedRows == 0 {
		t.Fatal("task failed before recording a real smoke FAIL")
	}
	if got := h.currentConfigHash(t); got != beforeHash {
		t.Fatalf("Caddy config was not rolled back: before=%s after=%s", beforeHash, got)
	}
	if got := h.currentVersion(t); got != beforeVersion {
		t.Fatalf("current DB version changed on failed publish: before=%s after=%s", beforeVersion, got)
	}
	total := h.origin.total.Load()
	if mode == "source-404" {
		if total <= originBefore || h.origin.ordinary404.Load() == 0 {
			t.Fatal("source-404 fault did not reach the real origin through Caddy")
		}
	} else if total != originBefore {
		t.Fatalf("%s invalid authenticated probe reached origin: before=%d after=%d", mode, originBefore, total)
	}
}

func setupPublishSmokeE2E(t *testing.T) *publishSmokeE2EHarness {
	t.Helper()
	if testing.Short() || os.Getenv(publishSmokeE2EEnabledEnv) != "1" {
		t.Skip("real Docker Caddy/PostgreSQL E2E disabled; run scripts/tests/gateway-publish-smoke-e2e.sh")
	}
	dsn := os.Getenv(publishSmokeE2EDSNEnv)
	socket := os.Getenv(publishSmokeE2ESocketEnv)
	dialAddr := os.Getenv(publishSmokeE2EAddrEnv)
	if dsn == "" || socket == "" || dialAddr == "" {
		t.Fatal("E2E harness missing PostgreSQL DSN, Caddy socket or data-plane address")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 4*time.Minute)
	t.Cleanup(cancel)
	pool, err := pgxpool.New(ctx, dsn)
	if err != nil {
		t.Fatal("invalid E2E PostgreSQL configuration")
	}
	t.Cleanup(pool.Close)
	if err := pool.Ping(ctx); err != nil {
		t.Fatalf("E2E PostgreSQL ping: %v", err)
	}
	if err := database.Migrate(ctx, pool, "../../migrations", "up"); err != nil {
		t.Fatalf("E2E migrations: %v", err)
	}
	if err := NewCaddyClient(socket).Ping(ctx); err != nil {
		t.Fatalf("real Caddy Admin API: %v", err)
	}

	origin := startPublishSmokeE2EOrigin(t)
	_, portText, err := net.SplitHostPort(origin.addr)
	if err != nil {
		t.Fatal(err)
	}
	originPort, err := strconv.Atoi(portText)
	if err != nil {
		t.Fatal(err)
	}
	originHost := os.Getenv(publishSmokeE2EOriginHostEnv)
	if originHost == "" {
		originHost = "host.docker.internal"
	}
	apps := applications.NewStore(pool)
	app := &applications.Application{
		Code: "publish-smoke-e2e", Name: "真实 Caddy 发布探针 E2E", Status: applications.StatusActive,
		ProtectionMode: applications.ModeProtect, DeploymentMode: applications.DeployModeReverseProxy,
	}
	if err := apps.Create(ctx, app); err != nil {
		t.Fatal(err)
	}
	port := publishSmokeE2EHTTPPort
	if err := apps.AddDomain(ctx, &applications.Domain{
		ApplicationID: app.ID, Hostname: publishSmokeE2EHost, IsPrimary: true,
		HTTPEnabled: true, HTTPPort: &port, Status: "ACTIVE",
	}); err != nil {
		t.Fatal(err)
	}
	if err := apps.AddUpstream(ctx, &applications.Upstream{
		ApplicationID: app.ID, Name: "real-origin", Scheme: "http", Host: originHost,
		Port: originPort, Weight: 1, Priority: 1, Status: "ACTIVE", TLSVerify: true,
	}); err != nil {
		t.Fatal(err)
	}
	return &publishSmokeE2EHarness{
		ctx: ctx, db: pool, apps: apps, appID: app.ID, appCode: app.Code,
		dataDir: t.TempDir(), socket: socket, dialAddr: dialAddr, origin: origin,
	}
}

func TestPublishSmokeRealCaddyE2E(t *testing.T) {
	h := setupPublishSmokeE2E(t)

	t.Run("HTTP 82 Bot absent with REAL_IP BLACKLIST CC and CC_EXACT", func(t *testing.T) {
		before := h.origin.total.Load()
		task := h.publish(t, "bot-absent", h.baseGuard(), nil)
		h.assertSuccess(t, task, VersionSmokePass, before)
		h.assertProtectionProbes(t, task.ID)
		current, err := NewCaddyClient(h.socket).GetCurrentConfig(h.ctx)
		if err != nil {
			t.Fatal(err)
		}
		if !strings.Contains(current, `"listen":[":82"]`) || strings.Contains(current, `"bot_policy"`) {
			t.Fatal("real config must listen on :82 with Bot policy absent")
		}
	})

	t.Run("Bot OFF RELEASED succeeds without origin traffic", func(t *testing.T) {
		before := h.origin.total.Load()
		task := h.publish(t, "bot-released", h.releasedGuard(), nil)
		h.assertSuccess(t, task, VersionSmokePass, before)
		h.assertProtectionProbes(t, task.ID)
		current, err := NewCaddyClient(h.socket).GetCurrentConfig(h.ctx)
		if err != nil {
			t.Fatal(err)
		}
		if !strings.Contains(current, `"bot_policy"`) || !strings.Contains(current, `"state":"RELEASED"`) {
			t.Fatal("RELEASED scenario did not load the intended real Bot policy")
		}
	})

	for _, mode := range []string{"source-404", "wrong-host", "wrong-key"} {
		t.Run(mode+" fails and rolls back", func(t *testing.T) {
			beforeVersion := h.currentVersion(t)
			beforeHash := h.currentConfigHash(t)
			beforeOrigin := h.origin.total.Load()
			client := h.client(t, h.dialAddr, mode)
			task := h.publish(t, mode, h.baseGuard(), client)
			h.assertFailureRollback(t, task, mode, beforeVersion, beforeHash, beforeOrigin)
		})
	}

	t.Run("unreachable data plane degrades without origin traffic", func(t *testing.T) {
		listener, err := net.Listen("tcp", "127.0.0.1:0")
		if err != nil {
			t.Fatal(err)
		}
		deadAddr := listener.Addr().String()
		_ = listener.Close()
		before := h.origin.total.Load()
		client := h.client(t, deadAddr, "")
		task := h.publish(t, "unreachable", h.baseGuard(), client)
		h.assertSuccess(t, task, VersionSmokeSkipped, before)
	})
}

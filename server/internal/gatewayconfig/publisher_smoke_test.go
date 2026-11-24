package gatewayconfig

import (
	"bufio"
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/hmac"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"math/big"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/jiuzhang-waf/server/internal/applications"
	"github.com/jiuzhang-waf/server/internal/database"
)

func smokeTestApp(code, host string, port int) AppData {
	return AppData{
		AppID:          uuid.NewString(),
		Code:           code,
		ProtectionMode: applications.ModeProtect,
		Domains: []applications.Domain{{
			NormalizedHostname: host,
			HTTPEnabled:        true,
			HTTPPort:           &port,
		}},
	}
}

const smokeTestKeyHex = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"

func smokeTestGuardConfig(publishID uuid.UUID) *GuardConfig {
	return &GuardConfig{PublishSmoke: &GuardPublishSmoke{PublishID: publishID.String(), KeyHex: smokeTestKeyHex}}
}

func runSmokeTest(t *testing.T, p *Publisher, appsData []AppData, guardCfg *GuardConfig) *smokeReport {
	t.Helper()
	taskID := uuid.New()
	if guardCfg != nil {
		guardCfg.PublishSmoke = smokeTestGuardConfig(taskID).PublishSmoke
	}
	return p.runPublishSmoke(context.Background(), taskID, uuid.New(), appsData, guardCfg)
}

// writeAuthenticatedSmoke 模拟真实 guard：先验证请求 HMAC，再返回绑定同一请求
// 上下文的响应 HMAC。普通 404 不再被测试替身当作成功证据。
func writeAuthenticatedSmoke(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Cache-Control", "no-store")
	if r.URL.Path != smokeProbePath {
		w.WriteHeader(http.StatusNotFound)
		_, _ = w.Write([]byte("404 not found"))
		return
	}
	key, _ := hex.DecodeString(smokeTestKeyHex)
	timestamp, err := strconv.ParseInt(r.Header.Get(smokeTimestampHeader), 10, 64)
	if err != nil {
		w.WriteHeader(http.StatusNotFound)
		return
	}
	b := &smokeRequestBinding{
		appID: r.Header.Get(smokeAppIDHeader), appCode: r.Header.Get(smokeAppCodeHeader),
		host: smokeCanonicalHost(r.Host), publishID: r.Header.Get(smokePublishIDHeader),
		nonce: r.Header.Get(smokeNonceHeader), timestamp: timestamp,
		probe: r.Header.Get(SmokeMarkerHeader), key: key,
	}
	sig, sigErr := hex.DecodeString(r.Header.Get(smokeSignatureHeader))
	if sigErr != nil || !hmac.Equal(sig, smokeRequestSignature(b)) {
		w.WriteHeader(http.StatusNotFound)
		return
	}
	resp := smokeSignedResponse{
		AppID: b.appID, AppCode: b.appCode, Host: b.host, PublishID: b.publishID,
		Nonce: b.nonce, Timestamp: b.timestamp,
		Signature: hex.EncodeToString(smokeResponseSignature(b)),
	}
	body, _ := json.Marshal(resp)
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	w.Header().Set(SmokeMarkerHeader, b.probe)
	_, _ = w.Write(body)
}

func authenticatedSmokeGateway() http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get(SmokeMarkerHeader) == "" {
			http.Error(w, "unexpected", http.StatusInternalServerError)
			return
		}
		writeAuthenticatedSmoke(w, r)
	})
}

// newSmokeTestPublisher 指向 httptest 假网关的 Publisher（无库，跳过落库）。
func newSmokeTestPublisher(t *testing.T, handler http.Handler) (*Publisher, *httptest.Server) {
	t.Helper()
	srv := httptest.NewServer(handler)
	t.Cleanup(srv.Close)
	p := &Publisher{}
	p.SetSmokeProbe(srv.Listener.Addr().String(), nil)
	return p, srv
}

func signedSmokeResponseFixture(t *testing.T) *smokeResponse {
	t.Helper()
	key, _ := hex.DecodeString(smokeTestKeyHex)
	b := &smokeRequestBinding{
		appID: "app-1", appCode: "shop", host: "shop.example.com:80",
		publishID: uuid.NewString(), nonce: "0123456789abcdef0123456789abcdef",
		timestamp: time.Now().Unix(), probe: SmokeProbeRealIP, key: key,
	}
	body, err := json.Marshal(smokeSignedResponse{
		AppID: b.appID, AppCode: b.appCode, Host: b.host, PublishID: b.publishID,
		Nonce: b.nonce, Timestamp: b.timestamp, Signature: hex.EncodeToString(smokeResponseSignature(b)),
	})
	if err != nil {
		t.Fatal(err)
	}
	return &smokeResponse{status: http.StatusOK, header: http.Header{
		"Cache-Control": []string{"no-store"}, SmokeMarkerHeader: []string{b.probe},
	}, body: string(body), binding: b}
}

func mutateSignedSmokeResponse(t *testing.T, base *smokeResponse, mutate func(*smokeSignedResponse)) *smokeResponse {
	t.Helper()
	cp := *base
	cp.header = base.header.Clone()
	var body smokeSignedResponse
	if err := json.Unmarshal([]byte(base.body), &body); err != nil {
		t.Fatal(err)
	}
	mutate(&body)
	raw, err := json.Marshal(body)
	if err != nil {
		t.Fatal(err)
	}
	cp.body = string(raw)
	return &cp
}

func TestClassifySmokeResponse(t *testing.T) {
	hdr := func(kv ...string) http.Header {
		h := http.Header{}
		for i := 0; i+1 < len(kv); i += 2 {
			h.Set(kv[i], kv[i+1])
		}
		return h
	}
	valid := signedSmokeResponseFixture(t)
	withoutStore := *valid
	withoutStore.header = valid.header.Clone()
	withoutStore.header.Del("Cache-Control")
	expired := *valid
	expiredBinding := *valid.binding
	expiredBinding.timestamp = time.Now().Add(-smokeMaxAge - time.Second).Unix()
	expired.binding = &expiredBinding
	tests := []struct {
		name string
		resp *smokeResponse
		want smokeVerdict
	}{
		{"authenticated guard response", valid, verdictGuardAuthenticated},
		{"ordinary upstream 404", &smokeResponse{status: 404, header: hdr("Cache-Control", "no-store"), body: "404 not found"}, verdictUnexpected},
		{"authenticated response without no-store", &withoutStore, verdictUnexpected},
		{"wrong host", mutateSignedSmokeResponse(t, valid, func(b *smokeSignedResponse) { b.Host = "wrong.example.com:80" }), verdictUnexpected},
		{"cross site", mutateSignedSmokeResponse(t, valid, func(b *smokeSignedResponse) { b.AppID = "app-2" }), verdictUnexpected},
		{"cross publish", mutateSignedSmokeResponse(t, valid, func(b *smokeSignedResponse) { b.PublishID = uuid.NewString() }), verdictUnexpected},
		{"bad response signature", mutateSignedSmokeResponse(t, valid, func(b *smokeSignedResponse) { b.Signature = strings.Repeat("0", 64) }), verdictUnexpected},
		{"expired binding", &expired, verdictUnexpected},
		{"guard 403 block page", &smokeResponse{status: 403, header: hdr("X-Jiuzhang-Request-ID", "req-1")}, verdictGuardBlock},
		{"guard 429 rate limit", &smokeResponse{status: 429, header: hdr("X-Jiuzhang-Request-ID", "req-1")}, verdictGuardBlock},
		{"403 without request id is not guard", &smokeResponse{status: 403, header: hdr()}, verdictUnexpected},
		{"proxied 200", &smokeResponse{status: 200, header: hdr("X-Jiuzhang-Request-ID", "req-1"), body: "ok"}, verdictUnexpected},
		{"gateway 5xx", &smokeResponse{status: 502, header: hdr()}, verdictUnexpected},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := classifySmokeResponse(tt.resp); got != tt.want {
				t.Fatalf("classifySmokeResponse() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestResolveSmokeTargets(t *testing.T) {
	t.Run("nil guard config degrades", func(t *testing.T) {
		targets, reason := resolveSmokeTargets([]AppData{smokeTestApp("a1", "a1.example.com", 80)}, nil)
		if len(targets) != 0 || reason == "" {
			t.Fatalf("targets=%v reason=%q, want empty with reason", targets, reason)
		}
	})
	t.Run("bypass and mirror apps are not probeable", func(t *testing.T) {
		bypass := smokeTestApp("bp", "bp.example.com", 80)
		bypass.ProtectionMode = applications.ModeBypass
		mirror := smokeTestApp("mr", "mr.example.com", 80)
		mirror.DeploymentMode = applications.DeployModeMirror
		targets, reason := resolveSmokeTargets([]AppData{bypass, mirror}, &GuardConfig{})
		if len(targets) != 0 || reason == "" {
			t.Fatalf("targets=%v reason=%q, want empty with reason", targets, reason)
		}
	})
	t.Run("http target preferred", func(t *testing.T) {
		targets, _ := resolveSmokeTargets([]AppData{smokeTestApp("a1", "a1.example.com", 8080)}, &GuardConfig{})
		if len(targets) != 1 || targets[0].scheme != "http" || targets[0].port != 8080 || targets[0].host != "a1.example.com" {
			t.Fatalf("targets=%+v", targets)
		}
	})
	t.Run("redirect to https probes https", func(t *testing.T) {
		httpPort, httpsPort := 80, 443
		app := AppData{
			AppID: uuid.NewString(), Code: "a2", ProtectionMode: applications.ModeProtect,
			Domains: []applications.Domain{{
				NormalizedHostname: "a2.example.com",
				HTTPEnabled:        true, HTTPPort: &httpPort,
				HTTPSEnabled: true, HTTPSPort: &httpsPort,
				RedirectHTTPToHTTPS: true,
			}},
		}
		targets, _ := resolveSmokeTargets([]AppData{app}, &GuardConfig{})
		if len(targets) != 1 || targets[0].scheme != "https" || targets[0].port != 443 {
			t.Fatalf("targets=%+v", targets)
		}
	})
	t.Run("wildcard host is made probeable", func(t *testing.T) {
		targets, _ := resolveSmokeTargets([]AppData{smokeTestApp("a3", "*.example.com", 80)}, &GuardConfig{})
		if len(targets) != 1 || targets[0].host != "smoke.example.com" {
			t.Fatalf("targets=%+v", targets)
		}
	})
}

func TestRunPublishSmokeAllPassWithAuthenticatedEndpoint(t *testing.T) {
	p, _ := newSmokeTestPublisher(t, authenticatedSmokeGateway())
	rep := runSmokeTest(t, p,
		[]AppData{smokeTestApp("a1", "a1.example.com", 80)}, &GuardConfig{})
	if rep.failed() || rep.degraded {
		t.Fatalf("report = %+v, want pass", rep)
	}
	if rep.versionResult() != VersionSmokePass {
		t.Fatalf("versionResult = %q, want %q", rep.versionResult(), VersionSmokePass)
	}
	// 无黑名单条目：BLACKLIST 探针如实 SKIP，REAL_IP/CC PASS
	byProbe := map[string]smokeProbeResult{}
	for _, pr := range rep.probes {
		byProbe[pr.Probe] = pr
	}
	if byProbe[SmokeProbeRealIP].Result != SmokeResultPass || byProbe[SmokeProbeCC].Result != SmokeResultPass {
		t.Fatalf("probes = %+v", rep.probes)
	}
	if byProbe[SmokeProbeBlacklist].Result != SmokeResultSkip || byProbe[SmokeProbeBlacklist].Message == "" {
		t.Fatalf("blacklist probe = %+v, want SKIP with reason", byProbe[SmokeProbeBlacklist])
	}
	if !strings.Contains(rep.summary(), "SKIP") {
		t.Fatalf("summary = %q, want skip noted", rep.summary())
	}
}

func TestRunPublishSmokeBlacklistHit(t *testing.T) {
	const denyIP = "10.9.9.9"
	handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("X-Jiuzhang-Request-ID", "req-1")
		if r.Header.Get("X-Forwarded-For") == denyIP {
			w.WriteHeader(http.StatusForbidden)
			return
		}
		writeAuthenticatedSmoke(w, r)
	})
	p, _ := newSmokeTestPublisher(t, handler)
	guard := &GuardConfig{GlobalDeny: []GuardRule{{ID: "r1", Address: denyIP}}}
	rep := runSmokeTest(t, p,
		[]AppData{smokeTestApp("a1", "a1.example.com", 80)}, guard)
	if rep.failed() || rep.degraded {
		t.Fatalf("report = %+v, want pass", rep)
	}
	for _, pr := range rep.probes {
		if pr.Probe == SmokeProbeBlacklist && pr.Result != SmokeResultPass {
			t.Fatalf("blacklist probe = %+v, want PASS", pr)
		}
	}
}

func TestRunPublishSmokeBlacklistNotExercisable(t *testing.T) {
	// 探针源不在可信代理链：内部端点验签应答（XFF 未采信）→ 黑名单如实 SKIP 而非谎报 PASS
	p, _ := newSmokeTestPublisher(t, authenticatedSmokeGateway())
	guard := &GuardConfig{GlobalDeny: []GuardRule{{ID: "r1", Address: "10.9.9.9"}}}
	rep := runSmokeTest(t, p,
		[]AppData{smokeTestApp("a1", "a1.example.com", 80)}, guard)
	if rep.failed() {
		t.Fatalf("report = %+v, want no failure", rep)
	}
	for _, pr := range rep.probes {
		if pr.Probe == SmokeProbeBlacklist && (pr.Result != SmokeResultSkip || pr.Message == "") {
			t.Fatalf("blacklist probe = %+v, want SKIP with reason", pr)
		}
	}
}

func TestRunPublishSmokeCCRateLimited(t *testing.T) {
	var ccCount atomic.Int32
	handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("X-Jiuzhang-Request-ID", "req-1")
		if r.Header.Get(SmokeMarkerHeader) == SmokeProbeCC && ccCount.Add(1) >= 2 {
			w.Header().Set("Retry-After", "30")
			w.WriteHeader(http.StatusTooManyRequests)
			return
		}
		writeAuthenticatedSmoke(w, r)
	})
	p, _ := newSmokeTestPublisher(t, handler)
	rep := runSmokeTest(t, p,
		[]AppData{smokeTestApp("a1", "a1.example.com", 80)}, &GuardConfig{})
	if rep.failed() || rep.degraded {
		t.Fatalf("report = %+v, want pass", rep)
	}
	for _, pr := range rep.probes {
		if pr.Probe == SmokeProbeCC && (pr.Result != SmokeResultPass || !strings.Contains(pr.Message, "429")) {
			t.Fatalf("cc probe = %+v, want PASS with 429 evidence", pr)
		}
	}
}

func TestRunPublishSmokeUnexpectedResponseFails(t *testing.T) {
	// 防护链未接管（源站式 200 响应）→ FAIL（调用方走自动回滚）
	p, _ := newSmokeTestPublisher(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("X-Jiuzhang-Request-ID", "req-1")
		_, _ = w.Write([]byte("upstream ok"))
	}))
	rep := runSmokeTest(t, p,
		[]AppData{smokeTestApp("a1", "a1.example.com", 80)}, &GuardConfig{})
	if !rep.failed() {
		t.Fatalf("report = %+v, want failed", rep)
	}
	if rep.versionResult() != VersionSmokeFail {
		t.Fatalf("versionResult = %q, want %q", rep.versionResult(), VersionSmokeFail)
	}
	if rep.failureDetail() == "" {
		t.Fatal("failureDetail empty")
	}
}

func TestRunPublishSmokeDegradesWhenDataPlaneUnreachable(t *testing.T) {
	// 占用后立即释放一个回环端口，保证拨号被拒绝（传输层不可达 → 降级不判 FAIL）
	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	deadAddr := l.Addr().String()
	_ = l.Close()

	p := &Publisher{}
	p.SetSmokeProbe(deadAddr, nil)
	rep := runSmokeTest(t, p,
		[]AppData{smokeTestApp("a1", "a1.example.com", 80)}, &GuardConfig{})
	if rep.failed() {
		t.Fatalf("report = %+v, unreachable data plane must not fail smoke", rep)
	}
	if !rep.degraded || rep.degradeReason == "" {
		t.Fatalf("report = %+v, want degraded with reason", rep)
	}
	if rep.versionResult() != VersionSmokeSkipped {
		t.Fatalf("versionResult = %q, want %q", rep.versionResult(), VersionSmokeSkipped)
	}
	if !strings.Contains(rep.summary(), "降级") {
		t.Fatalf("summary = %q, want degrade noted", rep.summary())
	}
}

func TestRunPublishSmokeDegradesWithoutGuard(t *testing.T) {
	p := &Publisher{}
	rep := runSmokeTest(t, p,
		[]AppData{smokeTestApp("a1", "a1.example.com", 80)}, nil)
	if !rep.degraded || rep.degradeReason == "" || rep.failed() {
		t.Fatalf("report = %+v, want degraded without failure", rep)
	}
}

// TestPublishSmokePersistsReport 实库验证冒烟结果落库（版本 validation_result +
// gateway_validation_results 明细行）。无 POSTGRES_PASSWORD 时按仓库约定 Skip。
func TestPublishSmokePersistsReport(t *testing.T) {
	if testing.Short() {
		t.Skip("integration test skipped in short mode")
	}
	password := os.Getenv("POSTGRES_PASSWORD")
	if password == "" {
		t.Skip("POSTGRES_PASSWORD not set, skipping integration test")
	}
	ctx := context.Background()
	host := envOrDefault("POSTGRES_HOST", "127.0.0.1")
	port := envOrDefault("POSTGRES_PORT", "5432")
	user := envOrDefault("POSTGRES_USER", "jiuzhang")
	adminURL := fmt.Sprintf("postgres://%s:%s@%s:%s/postgres?sslmode=disable", user, password, host, port)
	admin, err := pgxpool.New(ctx, adminURL)
	if err != nil {
		t.Skipf("postgres dsn invalid: %v", err)
	}
	defer admin.Close()
	if err := admin.Ping(ctx); err != nil {
		t.Skipf("postgres unreachable: %v", err)
	}
	const dbName = "gatewayconfig_smoke_test"
	_, _ = admin.Exec(ctx, "DROP DATABASE IF EXISTS "+dbName)
	if _, err := admin.Exec(ctx, "CREATE DATABASE "+dbName); err != nil {
		t.Fatalf("create test database: %v", err)
	}
	t.Cleanup(func() {
		_, _ = admin.Exec(context.Background(), "DROP DATABASE IF EXISTS "+dbName+" WITH (FORCE)")
	})

	pool, err := pgxpool.New(ctx, fmt.Sprintf("postgres://%s:%s@%s:%s/%s?sslmode=disable", user, password, host, port, dbName))
	if err != nil {
		t.Fatalf("connect test database: %v", err)
	}
	defer pool.Close()
	if err := database.Migrate(ctx, pool, "../../migrations", "up"); err != nil {
		t.Fatalf("migrate: %v", err)
	}

	var taskID, versionID uuid.UUID
	if err := pool.QueryRow(ctx, `
INSERT INTO gateway_publish_tasks (task_type, status) VALUES ('PUBLISH', 'VERIFYING') RETURNING id`).Scan(&taskID); err != nil {
		t.Fatalf("insert task: %v", err)
	}
	if err := pool.QueryRow(ctx, `
INSERT INTO gateway_config_versions (version_number, configuration_json, configuration_hash)
VALUES ('V-smoke-test', '{}', 'hash-smoke-test') RETURNING id`).Scan(&versionID); err != nil {
		t.Fatalf("insert version: %v", err)
	}

	p, _ := newSmokeTestPublisher(t, authenticatedSmokeGateway())
	p.db = pool
	rep := p.runPublishSmoke(ctx, taskID, versionID,
		[]AppData{smokeTestApp("a1", "a1.example.com", 80)}, smokeTestGuardConfig(taskID))
	if rep.failed() || rep.degraded {
		t.Fatalf("report = %+v, want pass", rep)
	}

	var validationResult string
	if err := pool.QueryRow(ctx,
		`SELECT validation_result FROM gateway_config_versions WHERE id=$1`, versionID).Scan(&validationResult); err != nil {
		t.Fatalf("read version: %v", err)
	}
	if validationResult != VersionSmokePass {
		t.Fatalf("validation_result = %q, want %q", validationResult, VersionSmokePass)
	}
	var rowCount int
	if err := pool.QueryRow(ctx, `
SELECT count(*) FROM gateway_validation_results
WHERE publish_task_id=$1 AND validation_type='POST_PUBLISH_SMOKE'`, taskID).Scan(&rowCount); err != nil {
		t.Fatalf("count validation rows: %v", err)
	}
	if rowCount != 4 {
		t.Fatalf("validation rows = %d, want 4 (REAL_IP/BLACKLIST/CC/CC_EXACT)", rowCount)
	}
	// CC_EXACT：假网关未启用 debug 回显端点（墓碑 404）→ 如实 SKIP
	var ccExactReason string
	if err := pool.QueryRow(ctx, `
SELECT message FROM gateway_validation_results
WHERE publish_task_id=$1 AND validation_step='CC_EXACT' AND result='SKIP'`, taskID).Scan(&ccExactReason); err != nil {
		t.Fatalf("read cc_exact skip row: %v", err)
	}
	if ccExactReason == "" {
		t.Fatal("cc_exact skip reason empty")
	}
	var skipReason string
	if err := pool.QueryRow(ctx, `
SELECT message FROM gateway_validation_results
WHERE publish_task_id=$1 AND validation_step='BLACKLIST' AND result='SKIP'`, taskID).Scan(&skipReason); err != nil {
		t.Fatalf("read blacklist skip row: %v", err)
	}
	if skipReason == "" {
		t.Fatal("blacklist skip reason empty")
	}
}

func envOrDefault(key, def string) string {
	if v := os.Getenv(key); v != "" {
		return v
	}
	return def
}

// ---------- CC_EXACT 精确计数探针 ----------

func ccExactTestPolicy(id string, limit int64, windowSec int) GuardPolicy {
	return GuardPolicy{
		ID: id, Name: "精确限速", Dimension: "CLIENT_IP", Algorithm: "SLIDING_WINDOW",
		URIMatchType: "ALL", RequestsLimit: limit, WindowSeconds: windowSec,
		Action: "REJECT", Priority: 10,
	}
}

func TestCCExactTargetPolicy(t *testing.T) {
	now := time.Now()
	past := now.Add(-time.Hour).UTC().Format(time.RFC3339)
	future := now.Add(time.Hour).UTC().Format(time.RFC3339)
	t.Run("no policies", func(t *testing.T) {
		if pol, reason := ccExactTargetPolicy(&GuardConfig{}, "a1", now); pol != nil || reason == "" {
			t.Fatalf("pol=%v reason=%q", pol, reason)
		}
	})
	t.Run("eligible sliding window selected", func(t *testing.T) {
		g := &GuardConfig{GlobalPolicies: []GuardPolicy{ccExactTestPolicy("p1", 5, 60)}}
		pol, _ := ccExactTargetPolicy(g, "a1", now)
		if pol == nil || pol.ID != "p1" {
			t.Fatalf("pol=%v", pol)
		}
	})
	t.Run("smallest limit wins", func(t *testing.T) {
		g := &GuardConfig{GlobalPolicies: []GuardPolicy{ccExactTestPolicy("big", 20, 120), ccExactTestPolicy("small", 3, 60)}}
		pol, _ := ccExactTargetPolicy(g, "a1", now)
		if pol == nil || pol.ID != "small" {
			t.Fatalf("pol=%v", pol)
		}
	})
	t.Run("ineligible policies excluded", func(t *testing.T) {
		obs := ccExactTestPolicy("obs", 5, 60)
		obs.ObserveOnly = true
		tb := ccExactTestPolicy("tb", 5, 900)
		tb.Action = "TEMP_BLOCK"
		tb.BlockDurationSeconds = 60
		app := ccExactTestPolicy("app", 5, 60)
		app.Dimension = "APPLICATION"
		uri := ccExactTestPolicy("uri", 5, 60)
		uri.URIMatchType = "PREFIX"
		uri.URIPattern = "/api/"
		big := ccExactTestPolicy("big", 500, 3600)
		short := ccExactTestPolicy("short", 5, 8) // 窗口过短（< 阈值+5）
		expired := ccExactTestPolicy("expired", 5, 60)
		expired.EffectiveUntil = past
		notYet := ccExactTestPolicy("notyet", 5, 60)
		notYet.EffectiveFrom = future
		tbBurst := ccExactTestPolicy("tbburst", 5, 60)
		tbBurst.Algorithm = "TOKEN_BUCKET"
		tbBurst.BurstCapacity = 10 // burst > 阈值
		tbShortWin := ccExactTestPolicy("tbshort", 5, 10)
		tbShortWin.Algorithm = "TOKEN_BUCKET" // 窗口 < 3*阈值
		g := &GuardConfig{GlobalPolicies: []GuardPolicy{obs, tb, app, uri, big, short, expired, notYet, tbBurst, tbShortWin}}
		pol, reason := ccExactTargetPolicy(g, "a1", now)
		if pol != nil {
			t.Fatalf("want nil, got %v", pol.ID)
		}
		for _, id := range []string{"obs", "tb", "app", "uri", "big", "short", "expired", "notyet", "tbburst", "tbshort"} {
			if !strings.Contains(reason, id) {
				t.Fatalf("reason missing %s: %q", id, reason)
			}
		}
	})
	t.Run("token bucket with default burst eligible", func(t *testing.T) {
		tb := ccExactTestPolicy("tb", 4, 60)
		tb.Algorithm = "TOKEN_BUCKET"
		g := &GuardConfig{GlobalPolicies: []GuardPolicy{tb}}
		if pol, _ := ccExactTargetPolicy(g, "a1", now); pol == nil {
			t.Fatal("token bucket burst<=limit window>=3n should be eligible")
		}
	})
	t.Run("regex policy matching probe path eligible", func(t *testing.T) {
		re := ccExactTestPolicy("re", 3, 60)
		re.URIMatchType = "REGEX"
		re.URIPattern = "^/_wdsp/"
		g := &GuardConfig{GlobalPolicies: []GuardPolicy{re}}
		if pol, _ := ccExactTargetPolicy(g, "a1", now); pol == nil {
			t.Fatal("regex matching probe path should be eligible")
		}
	})
	t.Run("app rules policies considered", func(t *testing.T) {
		g := &GuardConfig{AppRules: map[string]*GuardAppRules{
			"a1": {Policies: []GuardPolicy{ccExactTestPolicy("ap1", 4, 60)}},
		}}
		if pol, _ := ccExactTargetPolicy(g, "a1", now); pol == nil || pol.ID != "ap1" {
			t.Fatalf("pol=%v", pol)
		}
	})
}

// ccExactFakeGateway 模拟启用 debug 回显端点的网关：按 policy|XFF 键计数，
// 超阈值 429；回显端点返回当前计数（模拟网关行为：回显请求本身不计数）。
func ccExactFakeGateway(policyID string, limit int64, adoptXFF bool) http.Handler {
	var mu sync.Mutex
	counts := map[string]int64{}
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		mu.Lock()
		defer mu.Unlock()
		w.Header().Set("Cache-Control", "no-store")
		if r.URL.Path == "/_wdsp/debug/v1/cc-counter" {
			key := r.URL.Query().Get("policy_id") + "|" + r.URL.Query().Get("ip")
			c := counts[key]
			w.Header().Set("Content-Type", "application/json; charset=utf-8")
			fmt.Fprintf(w, `{"policy_id":%q,"found":%v,"count":%d,"limit":%d,"window_seconds":60}`,
				r.URL.Query().Get("policy_id"), c > 0, c, limit)
			return
		}
		ip := r.Header.Get("X-Forwarded-For")
		if !adoptXFF {
			// 探针源不在可信代理链：XFF 不采信，合成键永远无计数（回显恒 0）
			ip = ""
		}
		if ip != "" {
			counts[policyID+"|"+ip]++
			if counts[policyID+"|"+ip] > limit {
				w.Header().Set("X-Jiuzhang-Request-ID", "req-1")
				w.WriteHeader(http.StatusTooManyRequests)
				return
			}
		}
		writeAuthenticatedSmoke(w, r)
	})
}

func ccExactProbeResult(t *testing.T, rep *smokeReport) smokeProbeResult {
	t.Helper()
	for _, pr := range rep.probes {
		if pr.Probe == SmokeProbeCCExact {
			return pr
		}
	}
	t.Fatalf("CC_EXACT probe missing: %+v", rep.probes)
	return smokeProbeResult{}
}

func TestRunPublishSmokeCCExactPass(t *testing.T) {
	policy := ccExactTestPolicy("p1", 4, 60)
	p, _ := newSmokeTestPublisher(t, ccExactFakeGateway("p1", policy.RequestsLimit, true))
	guard := &GuardConfig{GlobalPolicies: []GuardPolicy{policy}}
	rep := runSmokeTest(t, p,
		[]AppData{smokeTestApp("a1", "a1.example.com", 80)}, guard)
	if rep.failed() || rep.degraded {
		t.Fatalf("report = %+v, want pass", rep)
	}
	pr := ccExactProbeResult(t, rep)
	if pr.Result != SmokeResultPass || !strings.Contains(pr.Message, "429") {
		t.Fatalf("cc_exact = %+v, want PASS with 429 evidence", pr)
	}
}

// debug 回显端点未启用（墓碑 404）：如实 SKIP，不翻转发布结论。
func TestRunPublishSmokeCCExactEndpointDisabled(t *testing.T) {
	p, _ := newSmokeTestPublisher(t, authenticatedSmokeGateway())
	guard := &GuardConfig{GlobalPolicies: []GuardPolicy{ccExactTestPolicy("p1", 4, 60)}}
	rep := runSmokeTest(t, p,
		[]AppData{smokeTestApp("a1", "a1.example.com", 80)}, guard)
	if rep.failed() {
		t.Fatalf("report = %+v, want no failure", rep)
	}
	pr := ccExactProbeResult(t, rep)
	if pr.Result != SmokeResultSkip || !strings.Contains(pr.Message, "回显端点不可用") {
		t.Fatalf("cc_exact = %+v, want SKIP endpoint unavailable", pr)
	}
}

// 合成 XFF 未被采信（探针源不在可信代理链）：校准不递增 → 如实 SKIP。
func TestRunPublishSmokeCCExactXFFNotAdopted(t *testing.T) {
	policy := ccExactTestPolicy("p1", 4, 60)
	p, _ := newSmokeTestPublisher(t, ccExactFakeGateway("p1", policy.RequestsLimit, false))
	guard := &GuardConfig{GlobalPolicies: []GuardPolicy{policy}}
	rep := runSmokeTest(t, p,
		[]AppData{smokeTestApp("a1", "a1.example.com", 80)}, guard)
	if rep.failed() {
		t.Fatalf("report = %+v, want no failure", rep)
	}
	pr := ccExactProbeResult(t, rep)
	if pr.Result != SmokeResultSkip || !strings.Contains(pr.Message, "未被采信") {
		t.Fatalf("cc_exact = %+v, want SKIP XFF not adopted", pr)
	}
}

// 第 N+1 次未触发 429：阈值未生效的正面证据 → FAIL（走自动回滚）。
func TestRunPublishSmokeCCExactThresholdNotEnforced(t *testing.T) {
	policy := ccExactTestPolicy("p1", 4, 60)
	// 假网关计数但永不拦截
	p, _ := newSmokeTestPublisher(t, ccExactFakeGateway("p1", 1<<40, true))
	guard := &GuardConfig{GlobalPolicies: []GuardPolicy{policy}}
	rep := runSmokeTest(t, p,
		[]AppData{smokeTestApp("a1", "a1.example.com", 80)}, guard)
	if !rep.failed() {
		t.Fatalf("report = %+v, want failed", rep)
	}
	pr := ccExactProbeResult(t, rep)
	if pr.Result != SmokeResultFail || !strings.Contains(pr.Message, "阈值未生效") {
		t.Fatalf("cc_exact = %+v, want FAIL threshold not enforced", pr)
	}
	if rep.versionResult() != VersionSmokeFail {
		t.Fatalf("versionResult = %q, want %q", rep.versionResult(), VersionSmokeFail)
	}
}

func TestRunPublishSmokeUpstreamOrdinary404Fails(t *testing.T) {
	p, _ := newSmokeTestPublisher(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Cache-Control", "no-store")
		w.WriteHeader(http.StatusNotFound)
		_, _ = w.Write([]byte("404 not found"))
	}))
	rep := runSmokeTest(t, p, []AppData{smokeTestApp("a1", "a1.example.com", 80)}, &GuardConfig{})
	if !rep.failed() || rep.degraded || rep.versionResult() != VersionSmokeFail {
		t.Fatalf("ordinary upstream 404 must fail, not degrade or pass: %+v", rep)
	}
}

func TestRunPublishSmokeRejectsMissingOrCrossPublishAuthentication(t *testing.T) {
	for _, tc := range []struct {
		name  string
		guard func(uuid.UUID) *GuardConfig
	}{
		{name: "missing", guard: func(uuid.UUID) *GuardConfig { return &GuardConfig{} }},
		{name: "cross publish", guard: func(taskID uuid.UUID) *GuardConfig {
			return smokeTestGuardConfig(uuid.New())
		}},
		{name: "invalid key", guard: func(taskID uuid.UUID) *GuardConfig {
			g := smokeTestGuardConfig(taskID)
			g.PublishSmoke.KeyHex = "not-hex"
			return g
		}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			var requests atomic.Int32
			p, _ := newSmokeTestPublisher(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				requests.Add(1)
				writeAuthenticatedSmoke(w, r)
			}))
			taskID := uuid.New()
			rep := p.runPublishSmoke(context.Background(), taskID, uuid.New(),
				[]AppData{smokeTestApp("a1", "a1.example.com", 80)}, tc.guard(taskID))
			if !rep.failed() || rep.degraded || requests.Load() != 0 {
				t.Fatalf("invalid local authentication must fail before requests: report=%+v requests=%d", rep, requests.Load())
			}
		})
	}
}

func TestPreparePublishSmokeUniqueAndSecretsNotPersisted(t *testing.T) {
	firstTask, secondTask := uuid.New(), uuid.New()
	first, second := &GuardConfig{}, &GuardConfig{}
	if err := preparePublishSmoke(firstTask, first); err != nil {
		t.Fatal(err)
	}
	if err := preparePublishSmoke(secondTask, second); err != nil {
		t.Fatal(err)
	}
	if first.PublishSmoke == nil || second.PublishSmoke == nil ||
		first.PublishSmoke.PublishID != firstTask.String() || second.PublishSmoke.PublishID != secondTask.String() ||
		first.PublishSmoke.KeyHex == second.PublishSmoke.KeyHex {
		t.Fatalf("publish identities must be fresh and task-bound: first=%+v second=%+v", first.PublishSmoke, second.PublishSmoke)
	}
	key, err := hex.DecodeString(first.PublishSmoke.KeyHex)
	if err != nil || len(key) != 32 {
		t.Fatalf("generated key must be 32-byte hex: length=%d err=%v", len(key), err)
	}

	// access_control_versions 直接序列化 GuardConfig：整段必须缺席。
	accessSnapshot, err := json.Marshal(first)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(accessSnapshot), first.PublishSmoke.KeyHex) || strings.Contains(string(accessSnapshot), "publish_smoke") {
		t.Fatalf("access-control snapshot contains ephemeral publish authentication: %s", accessSnapshot)
	}

	// 运行时处理器需要秘密；整站不可变版本则移除整段，而不是重放旧发布身份。
	app := smokeTestApp("a1", "a1.example.com", 80)
	handlerJSON, err := json.Marshal(mapT{"handle": []interface{}{buildGuardHandler(first, app, 80)}})
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(handlerJSON), first.PublishSmoke.KeyHex) || !strings.Contains(string(handlerJSON), `"publish_smoke"`) {
		t.Fatalf("runtime guard handler missing publish authentication: %s", handlerJSON)
	}
	stored, err := RedactConfigSecrets(string(handlerJSON))
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(stored, first.PublishSmoke.KeyHex) || strings.Contains(stored, `"publish_smoke"`) {
		t.Fatalf("stored config contains ephemeral publish authentication: %s", stored)
	}
	if first.PublishSmoke.KeyHex == "" {
		t.Fatal("redaction must not mutate live publish config")
	}
}

func TestPublishSmokeRouteConflictValidation(t *testing.T) {
	for _, prefix := range []string{"/", "/_wdsp", "/_wdsp/internal/v1", smokeProbePath} {
		t.Run("path route "+prefix, func(t *testing.T) {
			app := smokeTestApp("a1", "a1.example.com", 80)
			app.PathRoutes = []AppPathRoute{{PathPrefix: prefix, UpstreamHost: "127.0.0.1", UpstreamPort: 8080}}
			if err := validatePublishSmokeRouteConflicts([]AppData{app}, &GuardConfig{}); err == nil ||
				!strings.Contains(err.Error(), smokeProbePath) {
				t.Fatalf("covering path route %q must conflict: %v", prefix, err)
			}
		})
	}

	app := smokeTestApp("a1", "a1.example.com", 80)
	app.PathRoutes = []AppPathRoute{
		{PathPrefix: "/api", UpstreamHost: "127.0.0.1", UpstreamPort: 8080},
		{PathPrefix: smokeProbePath + "-business", UpstreamHost: "127.0.0.1", UpstreamPort: 8080},
	}
	if err := validatePublishSmokeRouteConflicts([]AppData{app}, &GuardConfig{}); err != nil {
		t.Fatalf("adjacent/non-covering business routes must remain valid: %v", err)
	}
	bypass := smokeTestApp("bp", "bp.example.com", 80)
	bypass.ProtectionMode = applications.ModeBypass
	bypass.PathRoutes = []AppPathRoute{{PathPrefix: "/"}}
	if err := validatePublishSmokeRouteConflicts([]AppData{bypass}, &GuardConfig{}); err != nil {
		t.Fatalf("bypass app has no guard endpoint and must not conflict: %v", err)
	}

	registered := &GuardConfig{APIKnownEndpoints: map[string]string{"GET " + smokeProbePath: "CONFIRMED"}}
	if err := validatePublishSmokeRouteConflicts([]AppData{smokeTestApp("a1", "a1.example.com", 80)}, registered); err == nil {
		t.Fatal("registered business endpoint must conflict with internal exact path")
	}
	if err := validatePublishSmokeRouteConflicts([]AppData{app}, nil); err != nil {
		t.Fatalf("nil guard has no internal endpoint: %v", err)
	}

	conflictApp := smokeTestApp("a1", "a1.example.com", 80)
	conflictApp.PathRoutes = []AppPathRoute{{PathPrefix: "/", UpstreamHost: "127.0.0.1", UpstreamPort: 8080}}
	if _, err := Generate(GenerateInput{
		Apps: []AppData{conflictApp}, AdminSocket: "/var/run/caddy/admin.sock", Guard: &GuardConfig{},
	}); err == nil || !strings.Contains(err.Error(), smokeProbePath) {
		t.Fatalf("Generate must enforce route conflict validation: %v", err)
	}
}

func TestSmokeDialAddressHostFollowsEachSitePort(t *testing.T) {
	p := &Publisher{}
	t.Setenv("GATEWAY_PUBLISH_SMOKE_ADDR", "host.docker.internal")
	if got := p.smokeDialAddress(smokeTarget{port: 82}); got != "host.docker.internal:82" {
		t.Fatalf("host-only smoke address = %q", got)
	}
	if got := p.smokeDialAddress(smokeTarget{port: 8443}); got != "host.docker.internal:8443" {
		t.Fatalf("host-only smoke address did not follow site port: %q", got)
	}
	t.Setenv("GATEWAY_PUBLISH_SMOKE_ADDR", "gateway.example.internal:9443")
	if got := p.smokeDialAddress(smokeTarget{port: 82}); got != "gateway.example.internal:9443" {
		t.Fatalf("explicit host:port compatibility changed: %q", got)
	}
	t.Setenv("GATEWAY_PUBLISH_SMOKE_ADDR", "")
	if got := p.smokeDialAddress(smokeTarget{port: 82}); got != "127.0.0.1:82" {
		t.Fatalf("shared-network fallback changed: %q", got)
	}
}

func TestSmokeClientDoesNotFollowRedirect(t *testing.T) {
	var hits atomic.Int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		hits.Add(1)
		w.Header().Set("Location", "https://www.jxdr.cn"+r.URL.RequestURI())
		w.WriteHeader(http.StatusMovedPermanently)
	}))
	defer srv.Close()
	p := &Publisher{}
	p.SetSmokeProbe(srv.Listener.Addr().String(), nil)
	target := smokeTarget{
		appID: "app-1", appCode: "site", scheme: "http", host: "jxdr.cn", port: 80,
		publishSmoke: &GuardPublishSmoke{PublishID: uuid.NewString(), KeyHex: smokeTestKeyHex},
	}
	resp, err := p.doSmokeRequest(context.Background(), p.smokeClientFor(target), target, SmokeProbeRealIP, nil)
	if err != nil {
		t.Fatalf("doSmokeRequest: %v", err)
	}
	if resp.status != http.StatusMovedPermanently {
		t.Fatalf("smoke client must return 301 without following redirect, got %d", resp.status)
	}
	if hits.Load() != 1 {
		t.Fatalf("smoke client must not follow redirect: hits=%d", hits.Load())
	}
}

// proxyV1StripListener 模拟 Caddy proxy_protocol listener wrapper：每条新 TCP 连接必须以
// 合法的 PROXY v1 行开头（读取并记录后将剩余字节流透传给上层 HTTP 或 TLS server）。
type proxyV1StripListener struct {
	net.Listener
	mu        sync.Mutex
	proxyLine string
}

type bufferedConn struct {
	net.Conn
	r *bufio.Reader
}

func (c *bufferedConn) Read(p []byte) (int, error) { return c.r.Read(p) }

func (l *proxyV1StripListener) Accept() (net.Conn, error) {
	for {
		conn, err := l.Listener.Accept()
		if err != nil {
			return nil, err
		}
		br := bufio.NewReader(conn)
		line, err := br.ReadString('\n')
		if err != nil {
			_ = conn.Close()
			continue
		}
		if !strings.HasPrefix(line, "PROXY TCP4 ") {
			_ = conn.Close()
			continue
		}
		l.mu.Lock()
		l.proxyLine = line
		l.mu.Unlock()
		return &bufferedConn{Conn: conn, r: br}, nil
	}
}

func (l *proxyV1StripListener) lastProxyLine() string {
	l.mu.Lock()
	defer l.mu.Unlock()
	return l.proxyLine
}

func selfSignedSmokeTLSCert(t *testing.T) tls.Certificate {
	t.Helper()
	priv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject:      pkix.Name{CommonName: "tpx.example.com"},
		DNSNames:     []string{"tpx.example.com"},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(time.Hour),
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &priv.PublicKey, priv)
	if err != nil {
		t.Fatal(err)
	}
	return tls.Certificate{Certificate: [][]byte{der}, PrivateKey: priv}
}

// TestRunPublishSmokeTransparentProxyV1 验证 P1-1 修复：
// TRANSPARENT 探针拨号配置的透明回环端口（127.0.0.1:tproxyTarget / target_tls），
// 并在 HTTP 请求与 TLS 握手前前置合成 PROXY TCP4 127.0.0.1 127.0.0.1 54321 <dstPort>\r\n 头。
func TestRunPublishSmokeTransparentProxyV1(t *testing.T) {
	t.Setenv("GATEWAY_PUBLISH_SMOKE_ADDR", "")

	// 1. 透明 HTTP 探针
	rawHTTP, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	proxyHTTP := &proxyV1StripListener{Listener: rawHTTP}
	httpSrv := &http.Server{Handler: authenticatedSmokeGateway()}
	go func() { _ = httpSrv.Serve(proxyHTTP) }()
	t.Cleanup(func() { _ = httpSrv.Close() })

	// 2. 透明 HTTPS 探针（proxy_protocol 在 TLS 握手之前剥离）
	rawHTTPS, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	proxyHTTPS := &proxyV1StripListener{Listener: rawHTTPS}
	tlsListener := tls.NewListener(proxyHTTPS, &tls.Config{
		Certificates: []tls.Certificate{selfSignedSmokeTLSCert(t)},
	})
	httpsSrv := &http.Server{Handler: authenticatedSmokeGateway()}
	go func() { _ = httpsSrv.Serve(tlsListener) }()
	t.Cleanup(func() { _ = httpsSrv.Close() })

	p := &Publisher{}
	p.SetTproxyAddresses("0.0.0.0:15000", rawHTTP.Addr().String(), rawHTTPS.Addr().String())

	httpPort, httpsPort := 80, 443
	httpApp := AppData{
		AppID: uuid.NewString(), Code: "tpx-http", ProtectionMode: applications.ModeProtect,
		DeploymentMode: applications.DeployModeTransparent,
		Domains: []applications.Domain{{
			NormalizedHostname: "tpx.example.com", HTTPEnabled: true, HTTPPort: &httpPort,
		}},
	}
	repHTTP := runSmokeTest(t, p, []AppData{httpApp}, &GuardConfig{})
	if repHTTP.failed() || repHTTP.degraded || repHTTP.versionResult() != VersionSmokePass {
		t.Fatalf("transparent HTTP smoke report = %+v, want SMOKE_PASS", repHTTP)
	}
	if got := proxyHTTP.lastProxyLine(); got != "PROXY TCP4 127.0.0.1 127.0.0.1 54321 80\r\n" {
		t.Fatalf("transparent HTTP PROXY v1 line = %q", got)
	}

	httpsApp := AppData{
		AppID: uuid.NewString(), Code: "tpx-https", ProtectionMode: applications.ModeProtect,
		DeploymentMode: applications.DeployModeTransparent,
		Domains: []applications.Domain{{
			NormalizedHostname: "tpx.example.com", HTTPSEnabled: true, HTTPSPort: &httpsPort,
		}},
	}
	repHTTPS := runSmokeTest(t, p, []AppData{httpsApp}, &GuardConfig{})
	if repHTTPS.failed() || repHTTPS.degraded || repHTTPS.versionResult() != VersionSmokePass {
		t.Fatalf("transparent HTTPS smoke report = %+v, want SMOKE_PASS", repHTTPS)
	}
	if got := proxyHTTPS.lastProxyLine(); got != "PROXY TCP4 127.0.0.1 127.0.0.1 54321 443\r\n" {
		t.Fatalf("transparent HTTPS PROXY v1 line = %q", got)
	}
}

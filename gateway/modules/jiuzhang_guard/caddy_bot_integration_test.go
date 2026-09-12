// caddy_bot_integration_test.go 真实 Caddy 中间件顺序集成测试（WDSP P1-02 B3 验收，
// 任务书 §3.2 末段「须经真实中间件顺序集成测试验证」）：
// in-process caddy.Load（与生产同一 caddy v2.11.4 + coraza-caddy v2.5.0 模块注册链）
// + 真实 CRS 规则集（../../rules）+ 真实 Valkey（docker，锁定镜像）+ httptest 源站。
//
// 覆盖：中间件顺序（挑战 403 不到源站）、BOT-014（clearance 不绕过 Coraza/WAF——
// 完成挑战后发 SQLi 仍被 CRS 阻断且源站计数不增）、BOT-015（白名单仍挑战，
// 经 Load 热更新加白名单验证）、BOT-016（verify GET→405 / 未知子路径→404，
// 均不到源站）、挑战通过后正常 GET→200、Load 热更新换策略版本（旧通行按代次撤销
// 重新挑战）。
//
// 依赖 BOT_IT_VALKEY_ADDR 环境变量指向真实 Valkey；未设置时若本机 docker 可用
// 自动起一次性容器（锁定镜像 valkey/valkey:8.1.8-alpine  digest 与 docker-compose.yml
// 一致，--rm 退出即清），docker 不可用则 t.Skip（如实跳过，不冒充通过）。
package jiuzhang_guard_test

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"io"
	"math/big"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/caddyserver/caddy/v2"
	_ "github.com/caddyserver/caddy/v2/modules/standard"
	_ "github.com/corazawaf/coraza-caddy/v2"
	_ "github.com/jiuzhang-waf/gateway/modules/jiuzhang_guard"
	"github.com/jiuzhang-waf/gateway/modules/jiuzhang_guard/botchallenge"
)

// valkeyImage 锁定镜像（tag+digest 与 docker-compose.yml 一致；AGENTS.md 版本锁定纪律）。
const valkeyImage = "valkey/valkey:8.1.8-alpine@sha256:94365b275456ae14621001c03556c732b1d93a0cdeacc317d1bdd52eba680885"

// ensureITValkey 取真实 Valkey 地址：优先 BOT_IT_VALKEY_ADDR；否则 docker 起一次性容器。
func ensureITValkey(t *testing.T) string {
	t.Helper()
	if addr := os.Getenv("BOT_IT_VALKEY_ADDR"); addr != "" {
		return addr
	}
	if _, err := exec.LookPath("docker"); err != nil {
		t.Skip("BOT_IT_VALKEY_ADDR 未设置且 docker 不可用，跳过真实集成测试")
	}
	name := fmt.Sprintf("jz-bot-it-%d", time.Now().UnixNano())
	run := exec.Command("docker", "run", "-d", "--rm", "--name", name, "-p", "127.0.0.1:0:6379", valkeyImage)
	if out, err := run.CombinedOutput(); err != nil {
		t.Skipf("docker 起 Valkey 失败（跳过）: %v: %s", err, out)
	}
	t.Cleanup(func() {
		_ = exec.Command("docker", "rm", "-f", name).Run()
	})
	portOut, err := exec.Command("docker", "port", name, "6379/tcp").Output()
	if err != nil {
		t.Fatalf("docker port: %v", err)
	}
	// 输出形如 127.0.0.1:49153
	addr := strings.TrimSpace(strings.Split(string(portOut), "\n")[0])
	if i := strings.LastIndex(addr, ":"); i >= 0 {
		addr = "127.0.0.1" + addr[i:]
	}
	// 等待就绪
	deadline := time.Now().Add(30 * time.Second)
	for time.Now().Before(deadline) {
		conn, err := net.DialTimeout("tcp", addr, 500*time.Millisecond)
		if err == nil {
			conn.Write([]byte("PING\r\n"))
			buf := make([]byte, 16)
			conn.SetReadDeadline(time.Now().Add(time.Second))
			if n, _ := conn.Read(buf); n > 0 && strings.Contains(string(buf[:n]), "PONG") {
				conn.Close()
				return addr
			}
			conn.Close()
		}
		time.Sleep(300 * time.Millisecond)
	}
	t.Fatalf("valkey %s not ready", addr)
	return ""
}

// itFlushValkey 测试前清库（RESP 内联命令；测试专用实例，严禁指向共享/生产实例）。
func itFlushValkey(t *testing.T, addr string) {
	t.Helper()
	conn, err := net.DialTimeout("tcp", addr, 3*time.Second)
	if err != nil {
		t.Fatalf("flush valkey: %v", err)
	}
	defer conn.Close()
	conn.SetDeadline(time.Now().Add(5 * time.Second))
	if _, err := conn.Write([]byte("FLUSHDB\r\n")); err != nil {
		t.Fatalf("flush valkey: %v", err)
	}
	buf := make([]byte, 16)
	if _, err := conn.Read(buf); err != nil {
		t.Fatalf("flush valkey ack: %v", err)
	}
}

// freePort 取空闲回环端口。
func freePort(t *testing.T) int {
	t.Helper()
	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer l.Close()
	return l.Addr().(*net.TCPAddr).Port
}

// botITConfig 生成 Caddy JSON 配置（headers → jiuzhang_guard → waf(Coraza/CRS) →
// reverse_proxy 与生产 buildChainHandles 同一链序；TLS internal 自签，客户端
// InsecureSkipVerify）。
func botITConfig(t *testing.T, port, originPort int, valkeyAddr, dir string, extraAllow bool, policyVersion int) []byte {
	t.Helper()
	rules, err := filepath.Abs("../../rules")
	if err != nil {
		t.Fatal(err)
	}
	directives := "SecRuleEngine On\n" +
		"Include " + filepath.Join(rules, "coraza.conf") + "\n" +
		// coraza.conf 内的 POC 落盘路径（/tmp/coraza、/var/log/caddy）覆盖为测试临时目录
		"SecDataDir " + filepath.Join(dir, "coraza-data") + "\n" +
		"SecAuditEngine Off\n" +
		"SecAuditLog " + filepath.Join(dir, "coraza-audit.log") + "\n" +
		"Include " + filepath.Join(rules, "crs/crs-setup.conf") + "\n" +
		"Include " + filepath.Join(rules, "exclusions/before-crs.conf") + "\n" +
		"Include " + filepath.Join(rules, "crs/rules/*.conf") + "\n" +
		"Include " + filepath.Join(rules, "contrib/*/*.conf") + "\n" +
		"Include " + filepath.Join(rules, "exclusions/after-crs.conf") + "\n" +
		"Include " + filepath.Join(rules, "jiuzhang/jiuzhang-custom.conf") + "\n" +
		"Include " + filepath.Join(rules, "jiuzhang/post-contrib-blocking.conf") + "\n"

	botPolicy := map[string]interface{}{
		"schema_version": 1,
		"application_id": "app-it",
		"mode":           "PROTECT",
		"version":        policyVersion,
		"selectors":      []map[string]string{{"path_prefix": "/docs"}},
		"signal_rules": map[string]interface{}{
			"min_independent_groups": 2,
			"require_behavior_group": true,
			"rules": []map[string]interface{}{
				{"id": "ua_bot", "group": "client_claim", "metric": "ua_class_match",
					"params": map[string]string{"class": "BOT"}, "window_seconds": 300, "weight": 1},
				{"id": "uc", "group": "request_behavior", "metric": "uri_concentration",
					"window_seconds": 300, "weight": 1, "threshold": 0.5},
			},
		},
		"challenge": map[string]interface{}{
			"type": "JS", "nonce_ttl_seconds": 90, "clearance_ttl_seconds": 900,
			"difficulty": 10, "max_attempts": 3, "key_ref": "bot-it-key",
		},
		"route_reservation": map[string]string{"state": "ENABLED", "namespace": "/_wdsp/bot/v1/"},
		"signing_keys": map[string]string{
			"bot-it-key": "ab01cd23ef456789ab01cd23ef456789ab01cd23ef456789ab01cd23ef456789",
		},
	}
	bpRaw, err := json.Marshal(botPolicy)
	if err != nil {
		t.Fatal(err)
	}

	guard := map[string]interface{}{
		"handler":         "jiuzhang_guard",
		"app_id":          "app-it",
		"app_code":        "shopit",
		"counter_backend": "valkey",
		"valkey":          map[string]interface{}{"address": valkeyAddr, "db": 0},
		"fail_open":       true,
		"events_log":      filepath.Join(dir, "events.log"),
		"gateway_node":    "it-node",
		"identity_salt":   "it-salt",
		// 行为观测用 Valkey 后端：peekLua（Bot 信号只读快照）对真实 Valkey 实证
		"behavior_store":      "valkey",
		"identity_behavior":   map[string]interface{}{"enabled": true},
		"identity_events_log": filepath.Join(dir, "identity-events.log"),
		"bot_policy":          json.RawMessage(bpRaw),
	}
	if extraAllow {
		guard["global_allow"] = []map[string]interface{}{
			{"id": "allow-loopback", "address": "127.0.0.1", "priority": 1},
		}
	}

	certPath, keyPath := itWriteSelfSignedCert(t, dir)
	cfg := map[string]interface{}{
		"admin":   map[string]interface{}{"disabled": true},
		"storage": map[string]interface{}{"module": "file_system", "root": filepath.Join(dir, "caddy-storage")},
		"apps": map[string]interface{}{
			"tls": map[string]interface{}{
				// 预载自签证书（不使用 automation/internal issuer：避免信任安装
				// 交互与按需签发时序；客户端 InsecureSkipVerify 只验协议链）
				"certificates": map[string]interface{}{
					"load_files": []map[string]interface{}{
						{"certificate": certPath, "key": keyPath},
					},
				},
			},
			"http": map[string]interface{}{
				"servers": map[string]interface{}{
					"srv0": map[string]interface{}{
						"listen":                  []string{fmt.Sprintf("127.0.0.1:%d", port)},
						"automatic_https":         map[string]interface{}{"disable_redirects": true},
						"tls_connection_policies": []map[string]interface{}{{}},
						"routes": []map[string]interface{}{
							{"handle": []map[string]interface{}{
								{"handler": "headers", "request": map[string]interface{}{
									"set": map[string]interface{}{"X-Request-Id": []string{"{http.request.uuid}"}},
								}},
								guard,
								{"handler": "waf", "directives": directives},
								{"handler": "reverse_proxy", "upstreams": []map[string]string{
									{"dial": fmt.Sprintf("127.0.0.1:%d", originPort)},
								}},
							}},
						},
					},
				},
			},
		},
	}
	raw, err := json.Marshal(cfg)
	if err != nil {
		t.Fatal(err)
	}
	return raw
}

// itClient 测试 HTTP 客户端（TLS 自签跳过校验；手动管理 Cookie）。
func itClient() *http.Client {
	return &http.Client{
		Transport: &http.Transport{TLSClientConfig: &tls.Config{InsecureSkipVerify: true}},
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			return http.ErrUseLastResponse
		},
		Timeout: 15 * time.Second,
	}
}

// itBrowserHeaders 合格文档导航头（curl UA 命中 ua_class_match BOT 声明组）。
func itBrowserHeaders() map[string]string {
	return map[string]string{
		"User-Agent":     "curl/8.1",
		"Accept":         "text/html,application/xhtml+xml",
		"Sec-Fetch-Dest": "document",
		"Sec-Fetch-Mode": "navigate",
		"Sec-Fetch-Site": "none",
	}
}

func itGet(t *testing.T, c *http.Client, url string, hdrs map[string]string, cookies ...*http.Cookie) *http.Response {
	t.Helper()
	req, err := http.NewRequest(http.MethodGet, url, nil)
	if err != nil {
		t.Fatal(err)
	}
	for k, v := range hdrs {
		req.Header.Set(k, v)
	}
	for _, ck := range cookies {
		req.AddCookie(ck)
	}
	resp, err := c.Do(req)
	if err != nil {
		t.Fatalf("GET %s: %v", url, err)
	}
	return resp
}

var itParamsRe = regexp.MustCompile(`id="wdsp-bot-params" type="application/json">([^<]+)</script>`)

// itWriteSelfSignedCert 生成 localhost/127.0.0.1 自签 ECDSA 证书（PEM 落盘）——
// 不用 caddy internal issuer：避免信任安装交互（sudo 提示）与按需签发时序。
func itWriteSelfSignedCert(t *testing.T, dir string) (certPath, keyPath string) {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	tmpl := &x509.Certificate{
		SerialNumber:          big.NewInt(1),
		Subject:               pkix.Name{CommonName: "localhost"},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(24 * time.Hour),
		KeyUsage:              x509.KeyUsageDigitalSignature | x509.KeyUsageKeyEncipherment,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		DNSNames:              []string{"localhost"},
		IPAddresses:           []net.IP{net.ParseIP("127.0.0.1")},
		BasicConstraintsValid: true,
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	certPath = filepath.Join(dir, "it-cert.pem")
	keyPath = filepath.Join(dir, "it-key.pem")
	certOut, err := os.Create(certPath)
	if err != nil {
		t.Fatal(err)
	}
	if err := pem.Encode(certOut, &pem.Block{Type: "CERTIFICATE", Bytes: der}); err != nil {
		t.Fatal(err)
	}
	certOut.Close()
	keyDer, err := x509.MarshalECPrivateKey(key)
	if err != nil {
		t.Fatal(err)
	}
	keyOut, err := os.OpenFile(keyPath, os.O_WRONLY|os.O_CREATE|os.O_TRUNC, 0600)
	if err != nil {
		t.Fatal(err)
	}
	if err := pem.Encode(keyOut, &pem.Block{Type: "EC PRIVATE KEY", Bytes: keyDer}); err != nil {
		t.Fatal(err)
	}
	keyOut.Close()
	return certPath, keyPath
}

// itWaitReady 轮询直到 caddy 返回任意 HTTP 响应（监听启动前的连接拒绝属正常）。
func itWaitReady(t *testing.T, c *http.Client, base string) {
	t.Helper()
	deadline := time.Now().Add(45 * time.Second)
	for {
		req, err := http.NewRequest(http.MethodGet, base+"/docs/x", nil)
		if err != nil {
			t.Fatal(err)
		}
		for k, v := range itBrowserHeaders() {
			req.Header.Set(k, v)
		}
		resp, err := c.Do(req)
		if err == nil {
			resp.Body.Close()
			return
		}
		if time.Now().After(deadline) {
			t.Fatalf("caddy not ready: %v", err)
		}
		time.Sleep(300 * time.Millisecond)
	}
}

// itChallengeParams 挑战页题目参数。
type itChallengeParams struct {
	ChallengeID string `json:"challenge_id"`
	Nonce       string `json:"nonce"`
	Difficulty  int    `json:"difficulty"`
	App         string `json:"app"`
	Host        string `json:"host"`
	VerifyPath  string `json:"verify_path"`
}

// itSolvePoW 暴力求解：直接调 botchallenge.Solve（与浏览器 JS 同构的导出实现；
// 服务端权威判定为 CheckSolution，同一题目构造）。
func itSolvePoW(t *testing.T, p itChallengeParams) string {
	t.Helper()
	sol, ok := botchallenge.Solve(p.ChallengeID, p.Nonce, p.App, p.Host, p.Difficulty, 1<<24)
	if !ok {
		t.Fatal("no PoW solution within bound")
	}
	return sol
}

// itReadBody 读尽响应体并关闭。
func itReadBody(t *testing.T, resp *http.Response) string {
	t.Helper()
	b, err := io.ReadAll(resp.Body)
	resp.Body.Close()
	if err != nil {
		t.Fatal(err)
	}
	return string(b)
}

// itFindCookie 从响应 Set-Cookie 中取指定 Cookie。
func itFindCookie(resp *http.Response, name string) *http.Cookie {
	for _, c := range resp.Cookies() {
		if c.Name == name {
			return c
		}
	}
	return nil
}

// TestCaddyBotMiddlewareOrder 真实 Caddy 中间件顺序集成测试主流程。
func TestCaddyBotMiddlewareOrder(t *testing.T) {
	valkeyAddr := ensureITValkey(t)

	// 行为/挑战计数在同一 Valkey 跨运行留存（窗口最长 24h）——每次运行前清库，
	// 否则上次运行的计数会让首个请求立即达阈（BOT_IT_VALKEY_ADDR 必须指向测试专用实例）。
	itFlushValkey(t, valkeyAddr)

	var originHits int64
	origin := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		atomic.AddInt64(&originHits, 1)
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte("ok"))
	}))
	defer origin.Close()
	originPort, err := strconv.Atoi(origin.URL[strings.LastIndex(origin.URL, ":")+1:])
	if err != nil {
		t.Fatal(err)
	}

	port := freePort(t)
	dir := t.TempDir()
	if keep := os.Getenv("BOT_IT_KEEP_DIR"); keep != "" {
		if err := os.MkdirAll(keep, 0o755); err != nil {
			t.Fatal(err)
		}
		dir = keep
	}
	// SNI 用主机名（Go 客户端对 IP 地址不发 SNI，caddy 将无默认证书握手失败）
	base := fmt.Sprintf("https://localhost:%d", port)

	load := func(extraAllow bool, version int) {
		t.Helper()
		if err := caddy.Load(botITConfig(t, port, originPort, valkeyAddr, dir, extraAllow, version), true); err != nil {
			t.Fatalf("caddy.Load: %v", err)
		}
	}
	load(false, 1)
	t.Cleanup(func() { _ = caddy.Stop() })

	client := itClient()
	hits := func() int64 { return atomic.LoadInt64(&originHits) }

	// 就绪等待：证书签发与信任安装尝试耗时数秒，轮询直到拿到任意 HTTP 响应。
	itWaitReady(t, client, base)

	// ⓪ 探针：guard + bot_policy 须在链（命名空间未知路径本地 404；源站对任意路径
	// 都回 200——404 即证明请求真实经过了 guard 的 Bot 命名空间处理）。
	probe := itGet(t, client, base+"/_wdsp/bot/v1/unknown", nil)
	itReadBody(t, probe)
	if probe.StatusCode != http.StatusNotFound {
		t.Fatalf("guard/bot namespace probe: status=%d (guard not in chain?)", probe.StatusCode)
	}

	getDoc := func(cookies ...*http.Cookie) (int, string, *http.Response) {
		t.Helper()
		resp := itGet(t, client, base+"/docs/x", itBrowserHeaders(), cookies...)
		return resp.StatusCode, itReadBody(t, resp), resp
	}

	// ① 种子 + ② 达阈挑战：逐个 GET /docs/x（行为计数在真实 Valkey 中累积），
	// 直到出现 403 挑战页；此前的 200 须真实打到源站（中间件顺序：挑战在反代前）。
	// originBase 扣除就绪等待与探针请求的源站计数（它们同样真实过链）。
	originBase := hits()
	var (
		params  itChallengeParams
		session *http.Cookie
		passed  int
	)
	deadline := time.Now().Add(30 * time.Second)
	for i := 0; i < 16; i++ {
		status, body, resp := func() (int, string, *http.Response) {
			req, err := http.NewRequest(http.MethodGet, base+"/docs/x", nil)
			if err != nil {
				t.Fatal(err)
			}
			for k, v := range itBrowserHeaders() {
				req.Header.Set(k, v)
			}
			r, err := client.Do(req)
			if err != nil {
				if time.Now().After(deadline) {
					t.Fatalf("caddy not ready: %v", err)
				}
				time.Sleep(200 * time.Millisecond)
				return -1, "", nil
			}
			return r.StatusCode, itReadBody(t, r), r
		}()
		if status == -1 {
			continue
		}
		if status == http.StatusOK {
			passed++
			continue
		}
		if status == http.StatusForbidden && strings.Contains(body, "wdsp-bot-params") {
			m := itParamsRe.FindStringSubmatch(body)
			if m == nil {
				t.Fatal("challenge page missing wdsp-bot-params")
			}
			if err := json.Unmarshal([]byte(m[1]), &params); err != nil {
				t.Fatalf("params JSON: %v", err)
			}
			session = itFindCookie(resp, botchallenge.SessionCookieName)
			if session == nil {
				t.Fatal("challenge page did not set session cookie")
			}
			break
		}
		t.Fatalf("unexpected response %d body %.200s", status, body)
	}
	if params.ChallengeID == "" {
		t.Fatal("no challenge within request budget")
	}
	if passed == 0 {
		t.Fatal("no pass-through before challenge (selector/threshold gating broken)")
	}
	if got := hits() - originBase; got != int64(passed) {
		t.Fatalf("challenge must not reach origin: hits=%d passed=%d", got, passed)
	}

	// ③ 求解 + verify（严格同源 Origin + Fetch Metadata + 会话 Cookie）→ 204 + clearance。
	solution := itSolvePoW(t, params)
	vbody := fmt.Sprintf(`{"challenge_id":%q,"solution":%q}`, params.ChallengeID, solution)
	vreq, err := http.NewRequest(http.MethodPost, base+params.VerifyPath, strings.NewReader(vbody))
	if err != nil {
		t.Fatal(err)
	}
	vreq.Header.Set("Content-Type", "application/json")
	vreq.Header.Set("Origin", base)
	vreq.Header.Set("Sec-Fetch-Site", "same-origin")
	vreq.AddCookie(session)
	vresp, err := client.Do(vreq)
	if err != nil {
		t.Fatalf("verify: %v", err)
	}
	vrespBody := itReadBody(t, vresp)
	if vresp.StatusCode != http.StatusNoContent {
		t.Fatalf("verify status=%d body=%s", vresp.StatusCode, vrespBody)
	}
	clearance := itFindCookie(vresp, botchallenge.ClearanceCookieName)
	if clearance == nil {
		t.Fatal("verify did not set clearance cookie")
	}

	// ④ clearance 通行（双 Cookie：会话绑定）→ 200 到源站。
	status, body, _ := getDoc(session, clearance)
	if status != http.StatusOK || body != "ok" {
		t.Fatalf("clearance pass: status=%d body=%.100s", status, body)
	}
	if got := hits() - originBase; got != int64(passed)+1 {
		t.Fatalf("clearance pass must reach origin once: hits=%d", got)
	}

	// ⑤ BOT-014：clearance 不绕过 Coraza/CRS——SQLi 仍 403 且不是挑战页、源站计数不增。
	sqli := itGet(t, client, base+"/docs/x?id=1%27%20OR%20%271%27=%271", itBrowserHeaders(), session, clearance)
	sqliBody := itReadBody(t, sqli)
	if sqli.StatusCode != http.StatusForbidden {
		t.Fatalf("BOT-014 SQLi status=%d body=%.200s", sqli.StatusCode, sqliBody)
	}
	if strings.Contains(sqliBody, "wdsp-bot-params") {
		t.Fatal("BOT-014: SQLi got challenge page instead of WAF block")
	}
	if got := hits() - originBase; got != int64(passed)+1 {
		t.Fatalf("BOT-014: SQLi reached origin: hits=%d", got)
	}

	// ⑥ BOT-016：命名空间本地终结——verify GET→405、未知子路径→404，均不到源站。
	vget := itGet(t, client, base+"/_wdsp/bot/v1/verify", nil)
	itReadBody(t, vget)
	if vget.StatusCode != http.StatusMethodNotAllowed {
		t.Fatalf("BOT-016 verify GET status=%d", vget.StatusCode)
	}
	unk := itGet(t, client, base+"/_wdsp/bot/v1/unknown", nil)
	itReadBody(t, unk)
	if unk.StatusCode != http.StatusNotFound {
		t.Fatalf("BOT-016 unknown ns path status=%d", unk.StatusCode)
	}
	if got := hits() - originBase; got != int64(passed)+1 {
		t.Fatalf("BOT-016: namespace reached origin: hits=%d", got)
	}

	// ⑦ BOT-015：热更新加白名单（global_allow 127.0.0.1）——白名单不绕过 Bot，
	// 行为计数在 Valkey 跨重载留存，无 clearance 的新会话仍被挑战。
	load(true, 1)
	status, body, _ = getDoc()
	if status != http.StatusForbidden || !strings.Contains(body, "wdsp-bot-params") {
		t.Fatalf("BOT-015: allowlisted client must still be challenged: status=%d body=%.100s", status, body)
	}
	if got := hits() - originBase; got != int64(passed)+1 {
		t.Fatalf("BOT-015: challenge reached origin: hits=%d", got)
	}

	// ⑧ 热更新换策略版本（version 1→2）：旧 clearance 按代次撤销，重新挑战。
	load(false, 2)
	status, body, _ = getDoc(session, clearance)
	if status != http.StatusForbidden || !strings.Contains(body, "wdsp-bot-params") {
		t.Fatalf("policy version bump must revoke old clearance: status=%d body=%.100s", status, body)
	}
	if got := hits() - originBase; got != int64(passed)+1 {
		t.Fatalf("re-challenge reached origin: hits=%d", got)
	}
}

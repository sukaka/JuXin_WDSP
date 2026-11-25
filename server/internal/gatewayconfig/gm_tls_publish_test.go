// gm_tls_publish_test.go 阶段 M3 单元测试：
// 国密/国际双证 jiuzhang_tls_mux 生成、透明模式 listener_wrappers 顺序、
// TLS/HTTP 协议降级、tlcp 与降级回源/路径转发传输层、证书一致性校验、
// jiuzhang_tls_mux 私钥与 STEK 零明文脱敏/fail-closed 重注入、
// tls_mux/tlcp 能力发布门以及真实 gotlcp/tlcp 数据面发布冒烟探针。
package gatewayconfig

import (
	"bufio"
	"context"
	"crypto/rand"
	"crypto/tls"
	"encoding/json"
	"encoding/pem"
	"errors"
	"math/big"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"crypto/x509/pkix"

	"gitee.com/Trisia/gotlcp/tlcp"
	"github.com/emmansun/gmsm/sm2"
	"github.com/emmansun/gmsm/smx509"
	"github.com/google/uuid"
	"github.com/jiuzhang-waf/server/internal/applications"
	"github.com/jiuzhang-waf/server/internal/certificates"
)

const (
	testIntlCertPEM  = "-----BEGIN CERTIFICATE-----\nINTL-LEAF-CERT\n-----END CERTIFICATE-----\n"
	testIntlChainPEM = "-----BEGIN CERTIFICATE-----\nINTL-CHAIN-CA\n-----END CERTIFICATE-----\n"
	testIntlKeyPEM   = "-----BEGIN PRIVATE KEY-----\nINTL-SECRET-KEY-OLD\n-----END PRIVATE KEY-----\n"
	testGMSignCert   = "-----BEGIN CERTIFICATE-----\nGM-SIGN-CERT\n-----END CERTIFICATE-----\n"
	testGMSignKey    = "-----BEGIN PRIVATE KEY-----\nGM-SIGN-SECRET-OLD\n-----END PRIVATE KEY-----\n"
	testGMEncCert    = "-----BEGIN CERTIFICATE-----\nGM-ENC-CERT\n-----END CERTIFICATE-----\n"
	testGMEncKey     = "-----BEGIN PRIVATE KEY-----\nGM-ENC-SECRET-OLD\n-----END PRIVATE KEY-----\n"
	testGMChainPEM   = "-----BEGIN CERTIFICATE-----\nGM-CHAIN-CA\n-----END CERTIFICATE-----\n"
)

func dualCertTestApp(code, host string, httpsPort int, intlID, gmID string) AppData {
	return AppData{
		AppID:          uuid.NewString(),
		Code:           code,
		ProtectionMode: applications.ModeProtect,
		Domains: []applications.Domain{{
			ID:                 uuid.New(),
			Hostname:           host,
			NormalizedHostname: host,
			DomainType:         "EXACT",
			IsPrimary:          true,
			HTTPSEnabled:       true,
			HTTPSPort:          intPtr(httpsPort),
			Status:             "ACTIVE",
		}},
		Upstreams: []applications.Upstream{{
			ID:                      uuid.New(),
			Name:                    "u1",
			Scheme:                  "http",
			Host:                    "192.0.2.10",
			NormalizedHost:          "192.0.2.10",
			Port:                    8080,
			Status:                  "ACTIVE",
			ConnectTimeoutMs:        3000,
			ResponseHeaderTimeoutMs: 10000,
		}},
		HasCert:       true,
		CertID:        intlID,
		CertPEM:       testIntlCertPEM,
		ChainPEM:      testIntlChainPEM,
		KeyPEM:        testIntlKeyPEM,
		HasGMCert:     true,
		GMCertID:      gmID,
		GMSignCertPEM: testGMSignCert,
		GMSignKeyPEM:  testGMSignKey,
		GMEncCertPEM:  testGMEncCert,
		GMEncKeyPEM:   testGMEncKey,
		GMChainPEM:    testGMChainPEM,
	}
}

func makeRealSM2DualCertPair(t *testing.T, cn string) (signPair, encPair tlcp.Certificate) {
	t.Helper()
	now := time.Now()
	caPriv, err := sm2.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("sm2.GenerateKey CA: %v", err)
	}
	caTmpl := &smx509.Certificate{
		SerialNumber:          big.NewInt(1),
		Subject:               pkix.Name{CommonName: "JiuZhang Test SM2 CA"},
		NotBefore:             now.Add(-time.Hour),
		NotAfter:              now.Add(24 * time.Hour),
		KeyUsage:              smx509.KeyUsageCertSign | smx509.KeyUsageCRLSign,
		BasicConstraintsValid: true,
		IsCA:                  true,
	}
	caDER, err := smx509.CreateCertificate(rand.Reader, caTmpl, caTmpl, &caPriv.PublicKey, caPriv)
	if err != nil {
		t.Fatalf("CreateCertificate CA: %v", err)
	}
	caCert, err := smx509.ParseCertificate(caDER)
	if err != nil {
		t.Fatalf("ParseCertificate CA: %v", err)
	}

	issue := func(serial int64, usage smx509.KeyUsage) tlcp.Certificate {
		priv, err := sm2.GenerateKey(rand.Reader)
		if err != nil {
			t.Fatalf("sm2.GenerateKey leaf: %v", err)
		}
		tmpl := &smx509.Certificate{
			SerialNumber:          big.NewInt(serial),
			Subject:               pkix.Name{CommonName: cn},
			DNSNames:              []string{cn},
			NotBefore:             now.Add(-time.Hour),
			NotAfter:              now.Add(24 * time.Hour),
			KeyUsage:              usage,
			ExtKeyUsage:           []smx509.ExtKeyUsage{smx509.ExtKeyUsageServerAuth},
			BasicConstraintsValid: true,
		}
		der, err := smx509.CreateCertificate(rand.Reader, tmpl, caCert, &priv.PublicKey, caPriv)
		if err != nil {
			t.Fatalf("CreateCertificate leaf: %v", err)
		}
		certPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})
		keyDER, err := smx509.MarshalPKCS8PrivateKey(priv)
		if err != nil {
			t.Fatalf("MarshalPKCS8PrivateKey: %v", err)
		}
		keyPEM := pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: keyDER})
		pair, err := tlcp.X509KeyPair(certPEM, keyPEM)
		if err != nil {
			t.Fatalf("tlcp.X509KeyPair: %v", err)
		}
		return pair
	}
	return issue(101, smx509.KeyUsageDigitalSignature), issue(102, smx509.KeyUsageKeyEncipherment|smx509.KeyUsageDataEncipherment)
}

// 1. 双证站点生成 jiuzhang_tls_mux：不发默认 tls wrapper / tls_connection_policies，不重复 load_pem，确定性一致。
func TestGenerateDualCertTLSMuxAndNoLegacyDuplicate(t *testing.T) {
	intlID := uuid.NewString()
	gmID := uuid.NewString()
	app := dualCertTestApp("gm-portal", "gm.example.com", 443, intlID, gmID)
	guard := testGuardConfig()
	guard.GatewayNode = "gw-gm-01"
	guard.TLSSessionTicketKey = testTicketKey
	guard.SoftwareBypass = defaultSoftwareBypass()

	in := GenerateInput{
		Apps:        []AppData{app},
		AdminSocket: "unix//var/run/caddy/admin.sock",
		Guard:       guard,
	}
	g1, err := Generate(in)
	if err != nil {
		t.Fatalf("Generate(1): %v", err)
	}
	g2, err := Generate(in)
	if err != nil {
		t.Fatalf("Generate(2): %v", err)
	}
	if g1.Hash != g2.Hash || g1.JSON != g2.JSON {
		t.Fatal("dual-cert mux config generation must be deterministic")
	}

	var cfg map[string]interface{}
	if err := json.Unmarshal([]byte(g1.JSON), &cfg); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	servers := cfg["apps"].(map[string]interface{})["http"].(map[string]interface{})["servers"].(map[string]interface{})
	srv := servers["srv0"].(map[string]interface{})

	// 不得产出默认 tls_connection_policies
	if _, hasPolicies := srv["tls_connection_policies"]; hasPolicies {
		t.Fatalf("mux-managed HTTPS server must not emit tls_connection_policies: %v", srv["tls_connection_policies"])
	}
	// protocols 应为 ["h1", "h2"]
	protos, ok := srv["protocols"].([]interface{})
	if !ok || len(protos) != 2 || protos[0] != "h1" || protos[1] != "h2" {
		t.Fatalf("srv.protocols = %v, want [h1 h2]", srv["protocols"])
	}
	// listener_wrappers 顺序：jiuzhang_connection_metrics -> jiuzhang_tls_mux（不得含 "tls"）
	wrappers := srv["listener_wrappers"].([]interface{})
	if len(wrappers) != 2 ||
		wrappers[0].(map[string]interface{})["wrapper"] != "jiuzhang_connection_metrics" ||
		wrappers[1].(map[string]interface{})["wrapper"] != "jiuzhang_tls_mux" {
		t.Fatalf("listener_wrappers = %v, want [jiuzhang_connection_metrics, jiuzhang_tls_mux]", wrappers)
	}

	mux := wrappers[1].(map[string]interface{})
	if mux["gateway_node"] != "gw-gm-01" {
		t.Errorf("gateway_node = %v", mux["gateway_node"])
	}
	if mux["session_log_path"] != DefaultTLSSessionLogPath {
		t.Errorf("session_log_path = %v, want %s", mux["session_log_path"], DefaultTLSSessionLogPath)
	}
	stek := mux["session_ticket_keys_hex"].([]interface{})
	if len(stek) != 1 || stek[0] != testTicketKey {
		t.Errorf("session_ticket_keys_hex = %v", stek)
	}

	sites := mux["sites"].([]interface{})
	if len(sites) != 1 {
		t.Fatalf("sites len = %d, want 1", len(sites))
	}
	site := sites[0].(map[string]interface{})
	if site["cert_id"] != intlID || site["gm_cert_id"] != gmID {
		t.Errorf("cert ids mismatch: cert_id=%v gm_cert_id=%v", site["cert_id"], site["gm_cert_id"])
	}
	if !strings.Contains(site["cert_pem"].(string), "INTL-CHAIN-CA") {
		t.Error("intl cert_pem missing merged chain")
	}
	if !strings.Contains(site["gm_sign_cert_pem"].(string), "GM-CHAIN-CA") ||
		!strings.Contains(site["gm_enc_cert_pem"].(string), "GM-CHAIN-CA") {
		t.Error("GM sign/enc cert_pem missing merged GM chain")
	}
	if site["tls_protocol_mode"] != TLSProtocolModeAutoDetect {
		t.Errorf("tls_protocol_mode = %v, want AUTO_DETECT", site["tls_protocol_mode"])
	}

	// 不应在 apps.tls.certificates.load_pem 重复装载
	if tlsApp, ok := cfg["apps"].(map[string]interface{})["tls"].(map[string]interface{}); ok {
		if _, hasCerts := tlsApp["certificates"]; hasCerts {
			t.Fatalf("mux-only HTTPS apps should not duplicate certs in apps.tls.certificates: %v", tlsApp["certificates"])
		}
	}
}

// 2. 透明模式 HTTPS + 国密双证：wrapper 顺序严格为 jiuzhang_connection_metrics -> proxy_protocol -> jiuzhang_tls_mux（不含默认 tls）。
func TestGenerateTransparentTLSMuxWrapperOrder(t *testing.T) {
	app := dualCertTestApp("tpx-gm", "tpx-gm.example.com", 443, uuid.NewString(), uuid.NewString())
	app.DeploymentMode = applications.DeployModeTransparent
	app.TLSConfig = &AppTLSConfig{
		TLSProtocolMode:           TLSProtocolModeAutoDetect,
		AllowedTLSVersions:        []string{TLSVersion12, TLSVersion13, TLSVersionTLCP11},
		LegacySSLAnalysisVersions: []string{LegacySSLv2, LegacySSLv2v3, LegacySSLv3},
		HTTPVersions:              []string{HTTPVersion11}, // 降级关闭 HTTP/2
		UpstreamHTTPVersion:       UpstreamHTTPAuto,
		UpstreamTLSMinVersion:     TLSVersion12,
		SessionAnalysisEnabled:    true,
	}

	guard := testGuardConfig()
	guard.SoftwareBypass = defaultSoftwareBypass()
	g, err := Generate(GenerateInput{
		Apps:        []AppData{app},
		AdminSocket: "unix//var/run/caddy/admin.sock",
		Guard:       guard,
	})
	if err != nil {
		t.Fatalf("Generate: %v", err)
	}
	var cfg map[string]interface{}
	if err := json.Unmarshal([]byte(g.JSON), &cfg); err != nil {
		t.Fatal(err)
	}
	tHTTPS := cfg["apps"].(map[string]interface{})["http"].(map[string]interface{})["servers"].(map[string]interface{})["srv_transparent_https"].(map[string]interface{})
	wrappers := tHTTPS["listener_wrappers"].([]interface{})
	if len(wrappers) != 3 ||
		wrappers[0].(map[string]interface{})["wrapper"] != "jiuzhang_connection_metrics" ||
		wrappers[1].(map[string]interface{})["wrapper"] != "proxy_protocol" ||
		wrappers[2].(map[string]interface{})["wrapper"] != "jiuzhang_tls_mux" {
		t.Fatalf("srv_transparent_https listener_wrappers = %v", wrappers)
	}
	if _, hasPolicies := tHTTPS["tls_connection_policies"]; hasPolicies {
		t.Fatal("mux-managed srv_transparent_https must not emit tls_connection_policies")
	}
	protos := tHTTPS["protocols"].([]interface{})
	if len(protos) != 1 || protos[0] != "h1" {
		t.Fatalf("HTTP/2 downgraded server protocols = %v, want [h1]", protos)
	}
}

// 3. TLS 1.0/1.1 降级、HTTP/2 降级与 Guard allowed_http_versions 透传。
func TestGenerateTLSDowngradeAndHTTPVersionRestrictions(t *testing.T) {
	app := httpsOnlyApp("legacy-tls", uuid.NewString(), "", "legacy.example.com")
	app.CertPEM = testIntlCertPEM
	app.KeyPEM = testIntlKeyPEM
	app.TLSConfig = &AppTLSConfig{
		TLSProtocolMode:           TLSProtocolModeInternationalOnly,
		AllowedTLSVersions:        []string{TLSVersion10, TLSVersion11, TLSVersion12},
		LegacySSLAnalysisVersions: []string{LegacySSLv2, LegacySSLv3},
		HTTPVersions:              []string{HTTPVersion10, HTTPVersion11},
		UpstreamHTTPVersion:       UpstreamHTTPAuto,
		UpstreamTLSMinVersion:     TLSVersion12,
		SessionAnalysisEnabled:    false,
	}

	g, err := Generate(GenerateInput{
		Apps:        []AppData{app},
		AdminSocket: "unix//var/run/caddy/admin.sock",
		Guard:       testGuardConfig(),
	})
	if err != nil {
		t.Fatalf("Generate: %v", err)
	}
	var cfg map[string]interface{}
	if err := json.Unmarshal([]byte(g.JSON), &cfg); err != nil {
		t.Fatal(err)
	}
	srv := cfg["apps"].(map[string]interface{})["http"].(map[string]interface{})["servers"].(map[string]interface{})["srv0"].(map[string]interface{})

	// 无站点允许 HTTP/2 → server.protocols=["h1"]
	protos := srv["protocols"].([]interface{})
	if len(protos) != 1 || protos[0] != "h1" {
		t.Fatalf("protocols = %v, want [h1]", protos)
	}
	wrappers := srv["listener_wrappers"].([]interface{})
	mux := wrappers[0].(map[string]interface{})
	if mux["wrapper"] != "jiuzhang_tls_mux" {
		t.Fatalf("wrapper = %v, want jiuzhang_tls_mux", mux["wrapper"])
	}
	// 所有站点关闭 session_analysis_enabled → 不打开会话日志路径
	if _, hasLog := mux["session_log_path"]; hasLog {
		t.Fatalf("session_log_path should be omitted when all sites disable session_analysis_enabled: %v", mux)
	}
	site := mux["sites"].([]interface{})[0].(map[string]interface{})
	if site["session_analysis_enabled"] != false {
		t.Errorf("session_analysis_enabled = %v, want false", site["session_analysis_enabled"])
	}

	// Guard handler 必须携带 allowed_http_versions=["HTTP/1.0", "HTTP/1.1"]
	routes := srv["routes"].([]interface{})
	handles := routes[0].(map[string]interface{})["handle"].([]interface{})
	var foundGuard map[string]interface{}
	for _, h := range handles {
		hm := h.(map[string]interface{})
		if hm["handler"] == "jiuzhang_guard" {
			foundGuard = hm
			break
		}
	}
	if foundGuard == nil {
		t.Fatal("jiuzhang_guard handler missing")
	}
	ahv, ok := foundGuard["allowed_http_versions"].([]interface{})
	if !ok || len(ahv) != 2 || ahv[0] != "HTTP/1.0" || ahv[1] != "HTTP/1.1" {
		t.Fatalf("guard.allowed_http_versions = %v, want [HTTP/1.0 HTTP/1.1]", foundGuard["allowed_http_versions"])
	}

	// 全量开放（HTTP/1.0 + HTTP/1.1 + HTTP/2）→ 不下发 allowed_http_versions（零开销）
	appAll := app
	appAll.TLSConfig = DefaultAppTLSConfig()
	gAll, err := Generate(GenerateInput{
		Apps:        []AppData{appAll},
		AdminSocket: "unix//var/run/caddy/admin.sock",
		Guard:       testGuardConfig(),
	})
	if err != nil {
		t.Fatalf("Generate(all): %v", err)
	}
	if strings.Contains(gAll.JSON, `"allowed_http_versions"`) {
		t.Fatal("unrestricted HTTPVersions must omit allowed_http_versions")
	}
}

// 4. 上游 reverse_proxy 与路径转发（headers.go）的 jiuzhang_tls 传输层生成。
func TestGenerateUpstreamAndPathRouteJiuzhangTLSTransport(t *testing.T) {
	t.Run("tlcp upstream with server_name and skip verify", func(t *testing.T) {
		u := applications.Upstream{
			ID: uuid.New(), Name: "gm-up", Scheme: "tlcp", Host: "gm-origin.internal", NormalizedHost: "gm-origin.internal",
			Port: 8443, Status: "ACTIVE", TLSServerName: "sni.gm.internal", TLSVerify: false,
			ConnectTimeoutMs: 2500, ResponseHeaderTimeoutMs: 8000,
		}
		proxy := buildReverseProxyWithTLS([]applications.Upstream{u}, &AppTLSConfig{UpstreamHTTPVersion: HTTPVersion11})
		tr := proxy["transport"].(mapT)
		if tr["protocol"] != "jiuzhang_tls" || tr["mode"] != "tlcp" {
			t.Fatalf("transport = %+v", tr)
		}
		if tr["server_name"] != "sni.gm.internal" || tr["insecure_skip_verify"] != true || tr["http_version"] != "HTTP/1.1" {
			t.Fatalf("tlcp transport fields mismatch: %+v", tr)
		}
		if tr["dial_timeout"] != "2500ms" || tr["response_header_timeout"] != "8000ms" {
			t.Fatalf("tlcp timeouts mismatch: %+v", tr)
		}
	})

	t.Run("https upstream TLS1.0 downgrade uses jiuzhang_tls mode=tls", func(t *testing.T) {
		u := applications.Upstream{
			ID: uuid.New(), Name: "old-tls", Scheme: "https", Host: "old.internal", NormalizedHost: "old.internal",
			Port: 443, Status: "ACTIVE", TLSVerify: true, ConnectTimeoutMs: 3000, ResponseHeaderTimeoutMs: 10000,
		}
		proxy := buildReverseProxyWithTLS([]applications.Upstream{u}, &AppTLSConfig{
			UpstreamTLSMinVersion: TLSVersion10,
			UpstreamHTTPVersion:   HTTPVersion11,
		})
		tr := proxy["transport"].(mapT)
		if tr["protocol"] != "jiuzhang_tls" || tr["mode"] != "tls" || tr["tls_min_version"] != "TLS1.0" || tr["http_version"] != "HTTP/1.1" {
			t.Fatalf("https downgrade transport = %+v", tr)
		}
		if tr["server_name"] != "old.internal" {
			t.Fatalf("server_name fallback = %v", tr["server_name"])
		}
		if _, skip := tr["insecure_skip_verify"]; skip {
			t.Fatal("TLSVerify=true must not set insecure_skip_verify")
		}
	})

	t.Run("http upstream HTTP/1.0 downgrade uses jiuzhang_tls mode=plain", func(t *testing.T) {
		u := applications.Upstream{
			ID: uuid.New(), Name: "old-http", Scheme: "http", Host: "legacy-http.internal", NormalizedHost: "legacy-http.internal",
			Port: 80, Status: "ACTIVE", ConnectTimeoutMs: 3000, ResponseHeaderTimeoutMs: 10000,
		}
		proxy := buildReverseProxyWithTLS([]applications.Upstream{u}, &AppTLSConfig{
			UpstreamHTTPVersion: HTTPVersion10,
		})
		tr := proxy["transport"].(mapT)
		if tr["protocol"] != "jiuzhang_tls" || tr["mode"] != "plain" || tr["http_version"] != "HTTP/1.0" {
			t.Fatalf("http 1.0 downgrade transport = %+v", tr)
		}
	})

	t.Run("default https upstream preserves legacy caddy http transport", func(t *testing.T) {
		u := applications.Upstream{
			ID: uuid.New(), Name: "std-https", Scheme: "https", Host: "std.internal", NormalizedHost: "std.internal",
			Port: 443, Status: "ACTIVE", TLSVerify: true, ConnectTimeoutMs: 3000, ResponseHeaderTimeoutMs: 10000,
		}
		proxy := buildReverseProxyWithTLS([]applications.Upstream{u}, DefaultAppTLSConfig())
		tr := proxy["transport"].(mapT)
		if tr["protocol"] != "http" {
			t.Fatalf("default https upstream should keep protocol=http, got %+v", tr)
		}
		if _, ok := tr["tls"].(mapT); !ok {
			t.Fatalf("default https upstream missing tls block: %+v", tr)
		}
	})

	t.Run("path route with tlcp scheme emits jiuzhang_tls mode=tlcp with positive timeouts", func(t *testing.T) {
		app := sampleApps()[0]
		app.PathRoutes = []AppPathRoute{{
			PathPrefix:     "/gm-api",
			UpstreamScheme: "tlcp",
			UpstreamHost:   "gm-backend.internal",
			UpstreamPort:   8443,
			Priority:       10,
		}}
		entries := pathRouteEntries(GenerateInput{}, app, []string{"www.example.com"}, 443)
		if len(entries) != 1 {
			t.Fatalf("entries len = %d, want 1", len(entries))
		}
		handles := entries[0].route["handle"].([]interface{})
		proxy := handles[len(handles)-1].(mapT)
		tr := proxy["transport"].(mapT)
		if tr["protocol"] != "jiuzhang_tls" || tr["mode"] != "tlcp" || tr["server_name"] != "gm-backend.internal" {
			t.Fatalf("path route tlcp transport = %+v", tr)
		}
		if tr["dial_timeout"] != "3000ms" || tr["response_header_timeout"] != "10000ms" {
			t.Fatalf("path route tlcp default timeouts invalid: %+v", tr)
		}
	})
}

// 5. 发布前站点 TLS 模式与证书槽位一致性校验。
func TestValidateAppTLSConsistency(t *testing.T) {
	cases := []struct {
		name    string
		app     AppData
		wantErr string
	}{
		{
			name:    "GM_ONLY without GM cert rejected",
			app:     AppData{Code: "a1", HasCert: true, TLSConfig: &AppTLSConfig{TLSProtocolMode: TLSProtocolModeGMOnly}},
			wantErr: "GM_ONLY",
		},
		{
			name:    "INTERNATIONAL_ONLY without intl cert rejected",
			app:     AppData{Code: "a2", HasGMCert: true, TLSConfig: &AppTLSConfig{TLSProtocolMode: TLSProtocolModeInternationalOnly}},
			wantErr: "INTERNATIONAL_ONLY",
		},
		{
			name:    "neither cert bound rejected",
			app:     AppData{Code: "a3"},
			wantErr: "未绑定证书",
		},
		{
			name:    "PendingAutoSSL with GM_ONLY rejected",
			app:     AppData{Code: "a4", PendingAutoSSL: true, TLSConfig: &AppTLSConfig{TLSProtocolMode: TLSProtocolModeGMOnly}},
			wantErr: "GM_ONLY",
		},
		{
			name: "GM-only with GM_ONLY allowed",
			app:  AppData{Code: "a5", HasGMCert: true, TLSConfig: &AppTLSConfig{TLSProtocolMode: TLSProtocolModeGMOnly}},
		},
		{
			name: "GM-only with AUTO_DETECT allowed",
			app:  AppData{Code: "a6", HasGMCert: true, TLSConfig: &AppTLSConfig{TLSProtocolMode: TLSProtocolModeAutoDetect}},
		},
		{
			name: "dual-cert with AUTO_DETECT allowed",
			app:  AppData{Code: "a7", HasCert: true, HasGMCert: true, TLSConfig: &AppTLSConfig{TLSProtocolMode: TLSProtocolModeAutoDetect}},
		},
		{
			name: "PendingAutoSSL without GM_ONLY allowed",
			app:  AppData{Code: "a8", PendingAutoSSL: true},
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			err := validateAppTLSConsistency(tc.app)
			if tc.wantErr == "" {
				if err != nil {
					t.Fatalf("unexpected error: %v", err)
				}
				return
			}
			if err == nil || !strings.Contains(err.Error(), tc.wantErr) {
				t.Fatalf("err = %v, want substring %q", err, tc.wantErr)
			}
		})
	}
}

// 6. RedactConfigSecrets 零明文私钥/STEK 脱敏 + reinjectConfigSecrets 回填往返与 fail-closed。
func TestRedactAndReinjectTLSMuxSecrets(t *testing.T) {
	intlID := uuid.New()
	gmID := uuid.New()
	const (
		oldSTEK       = "1111111111111111111111111111111111111111111111111111111111111111"
		newSTEK       = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
		liveIntlKey   = "-----BEGIN PRIVATE KEY-----\nLIVE-INTL-KEY\n-----END PRIVATE KEY-----\n"
		liveGMSignKey = "-----BEGIN PRIVATE KEY-----\nLIVE-GM-SIGN-KEY\n-----END PRIVATE KEY-----\n"
		liveGMEncKey  = "-----BEGIN PRIVATE KEY-----\nLIVE-GM-ENC-KEY\n-----END PRIVATE KEY-----\n"
	)

	app := dualCertTestApp("gm-sec", "sec.example.com", 443, intlID.String(), gmID.String())
	oldGuard := secretTestGuardConfig("old")
	oldGuard.TLSSessionTicketKey = oldSTEK
	oldGuard.TLSSessionTicketKeys = []string{oldSTEK}

	gen, err := Generate(GenerateInput{
		Apps:        []AppData{app},
		AdminSocket: "unix//var/run/caddy/admin.sock",
		Guard:       oldGuard,
	})
	if err != nil {
		t.Fatalf("Generate: %v", err)
	}

	redacted, err := RedactConfigSecrets(gen.JSON)
	if err != nil {
		t.Fatalf("RedactConfigSecrets: %v", err)
	}
	// 零明文泄漏断言（私钥与 STEK 全部替换为 "***"）
	for _, leaked := range []string{
		"INTL-SECRET-KEY-OLD", "GM-SIGN-SECRET-OLD", "GM-ENC-SECRET-OLD", oldSTEK,
	} {
		if strings.Contains(redacted, leaked) {
			t.Fatalf("redacted config leaked plaintext secret %q", leaked)
		}
	}
	// 非密钥字段与标识完整保留
	for _, keep := range []string{
		"INTL-LEAF-CERT", "GM-SIGN-CERT", "GM-ENC-CERT",
		intlID.String(), gmID.String(),
		`"key_pem":"***"`, `"gm_sign_key_pem":"***"`, `"gm_enc_key_pem":"***"`,
		`"session_ticket_keys_hex":["***"]`,
	} {
		if !strings.Contains(redacted, keep) {
			t.Fatalf("redacted config missing %q", keep)
		}
	}
	// 幂等性
	if again, err := RedactConfigSecrets(redacted); err != nil || again != redacted {
		t.Fatalf("RedactConfigSecrets not idempotent: err=%v", err)
	}

	// 落盘（WriteActiveConfig / WriteFailedCandidate）同样零明文私钥泄漏
	dir := t.TempDir()
	activePath, err := WriteActiveConfig(dir, "current", gen.JSON)
	if err != nil {
		t.Fatalf("WriteActiveConfig: %v", err)
	}
	activeRaw, _ := os.ReadFile(activePath)
	for _, leaked := range []string{"INTL-SECRET-KEY-OLD", "GM-SIGN-SECRET-OLD", "GM-ENC-SECRET-OLD", oldSTEK} {
		if strings.Contains(string(activeRaw), leaked) {
			t.Fatalf("active config on disk leaked %q", leaked)
		}
	}
	if err := WriteFailedCandidate(dir, gen.JSON, "validate failed"); err != nil {
		t.Fatalf("WriteFailedCandidate: %v", err)
	}
	failedFiles, _ := filepath.Glob(filepath.Join(dir, "configs", "failed", "failed-*.json"))
	failedRaw, _ := os.ReadFile(failedFiles[0])
	for _, leaked := range []string{"INTL-SECRET-KEY-OLD", "GM-SIGN-SECRET-OLD", "GM-ENC-SECRET-OLD", oldSTEK} {
		if strings.Contains(string(failedRaw), leaked) {
			t.Fatalf("failed candidate on disk leaked %q", leaked)
		}
	}

	// 重注入往返
	newGuard := secretTestGuardConfig("new")
	newGuard.TLSSessionTicketKey = newSTEK
	newGuard.TLSSessionTicketKeys = []string{newSTEK}
	p := &Publisher{
		guard: &fakeGuardProvider{buildCfg: newGuard},
		certKeyLoader: func(_ context.Context, id uuid.UUID) (string, error) {
			if id == intlID {
				return liveIntlKey, nil
			}
			return "", errors.New("intl cert not found")
		},
		gmCertMaterialLoader: func(_ context.Context, id uuid.UUID) (*certificates.GMCertMaterial, error) {
			if id == gmID {
				return &certificates.GMCertMaterial{
					SignCertPEM: testGMSignCert,
					SignKeyPEM:  liveGMSignKey,
					EncCertPEM:  testGMEncCert,
					EncKeyPEM:   liveGMEncKey,
				}, nil
			}
			return nil, errors.New("gm cert not found")
		},
	}
	reinjected, err := p.reinjectConfigSecrets(context.Background(), redacted)
	if err != nil {
		t.Fatalf("reinjectConfigSecrets: %v", err)
	}
	for _, want := range []string{"LIVE-INTL-KEY", "LIVE-GM-SIGN-KEY", "LIVE-GM-ENC-KEY", newSTEK} {
		if !strings.Contains(reinjected, want) {
			t.Errorf("reinjected config missing %q", want)
		}
	}
	if strings.Contains(reinjected, `"***"`) {
		t.Fatalf("reinjected config still contains placeholder: %s", reinjected)
	}

	// 纯 WAF 国密单槽位形态（无 guard、无国际证书、无 STEK）：仅需 gmCertMaterialLoader 即可回填
	gmOnlyApp := dualCertTestApp("gm-waf-only", "gm-only.example.com", 443, "", gmID.String())
	gmOnlyApp.HasCert, gmOnlyApp.CertID, gmOnlyApp.CertPEM, gmOnlyApp.ChainPEM, gmOnlyApp.KeyPEM = false, "", "", "", ""
	gmOnlyGen, err := Generate(GenerateInput{Apps: []AppData{gmOnlyApp}, AdminSocket: "unix//var/run/caddy/admin.sock"})
	if err != nil {
		t.Fatalf("Generate gm-only: %v", err)
	}
	gmOnlyRedacted, err := RedactConfigSecrets(gmOnlyGen.JSON)
	if err != nil {
		t.Fatalf("Redact gm-only: %v", err)
	}
	pGMOnly := &Publisher{
		gmCertMaterialLoader: p.gmCertMaterialLoader,
	}
	gmOnlyOut, err := pGMOnly.reinjectConfigSecrets(context.Background(), gmOnlyRedacted)
	if err != nil {
		t.Fatalf("gm-only reinject failed: %v", err)
	}
	if !strings.Contains(gmOnlyOut, "LIVE-GM-SIGN-KEY") || !strings.Contains(gmOnlyOut, "LIVE-GM-ENC-KEY") || strings.Contains(gmOnlyOut, `"***"`) {
		t.Fatalf("gm-only reinject invalid: %s", gmOnlyOut)
	}

	// Fail-closed 拒绝场景（绝不回放 "***"）
	t.Run("missing GM cert loader", func(t *testing.T) {
		pNoGM := &Publisher{guard: p.guard, certKeyLoader: p.certKeyLoader}
		if _, err := pNoGM.reinjectConfigSecrets(context.Background(), redacted); err == nil || !strings.Contains(err.Error(), "未装配证书仓储") {
			t.Fatalf("err = %v, want missing cert store error", err)
		}
	})
	t.Run("missing GM cert in DB", func(t *testing.T) {
		pMissingGM := &Publisher{
			guard:         p.guard,
			certKeyLoader: p.certKeyLoader,
			gmCertMaterialLoader: func(context.Context, uuid.UUID) (*certificates.GMCertMaterial, error) {
				return nil, certificates.ErrNotFound
			},
		}
		if _, err := pMissingGM.reinjectConfigSecrets(context.Background(), redacted); err == nil || !strings.Contains(err.Error(), gmID.String()) {
			t.Fatalf("err = %v, want error naming gmID", err)
		}
	})
	t.Run("placeholder GM enc key rejected", func(t *testing.T) {
		pBadGM := &Publisher{
			guard:         p.guard,
			certKeyLoader: p.certKeyLoader,
			gmCertMaterialLoader: func(context.Context, uuid.UUID) (*certificates.GMCertMaterial, error) {
				return &certificates.GMCertMaterial{SignKeyPEM: liveGMSignKey, EncKeyPEM: "***"}, nil
			},
		}
		if _, err := pBadGM.reinjectConfigSecrets(context.Background(), redacted); err == nil || !strings.Contains(err.Error(), "脱敏占位") {
			t.Fatalf("err = %v, want placeholder rejection", err)
		}
	})
	t.Run("missing gm_cert_id rejected", func(t *testing.T) {
		bad := `{"apps":{"http":{"servers":{"srv0":{"listener_wrappers":[{"wrapper":"jiuzhang_tls_mux","sites":[{"domains":["gm.example.com"],"gm_sign_key_pem":"***","gm_enc_key_pem":"***"}]}]}}}}}`
		if _, err := p.reinjectConfigSecrets(context.Background(), bad); err == nil || !strings.Contains(err.Error(), "gm_cert_id") {
			t.Fatalf("err = %v, want missing gm_cert_id error", err)
		}
	})
	t.Run("missing cert_id rejected", func(t *testing.T) {
		bad := `{"apps":{"http":{"servers":{"srv0":{"listener_wrappers":[{"wrapper":"jiuzhang_tls_mux","sites":[{"domains":["a.example.com"],"key_pem":"***"}]}]}}}}}`
		if _, err := p.reinjectConfigSecrets(context.Background(), bad); err == nil || !strings.Contains(err.Error(), "cert_id") {
			t.Fatalf("err = %v, want missing cert_id error", err)
		}
	})
	t.Run("missing live STEK key rejected", func(t *testing.T) {
		noSTEKGuard := secretTestGuardConfig("new")
		noSTEKGuard.TLSSessionTicketKey = ""
		noSTEKGuard.TLSSessionTicketKeys = nil
		pNoSTEK := &Publisher{
			guard:                &fakeGuardProvider{buildCfg: noSTEKGuard},
			certKeyLoader:        p.certKeyLoader,
			gmCertMaterialLoader: p.gmCertMaterialLoader,
		}
		if _, err := pNoSTEK.reinjectConfigSecrets(context.Background(), redacted); err == nil || !strings.Contains(err.Error(), "tls_session_ticket_key") {
			t.Fatalf("err = %v, want missing STEK error", err)
		}
	})
}

// 7. 能力发布门：tls_mux 与 tlcp 缺口 fail-closed，存量发布零影响。
func TestCapabilityGateTLSMuxAndTLCP(t *testing.T) {
	// 存量国际应用（无 GM 证书、无自定义 TLSConfig、无 tlcp 源站）：空需求免门禁，无 manifest 也放行
	legacyApp := httpsOnlyApp("legacy", uuid.NewString(), "a.pem", "a.example.com")
	pEmpty := &Publisher{sidecarDir: t.TempDir()}
	if ok, code, msg := pEmpty.evaluateCapabilityGateWithApps(context.Background(), nil, []AppData{legacyApp}); !ok || code != "" {
		t.Fatalf("legacy publish must bypass capability gate: ok=%v code=%s msg=%s", ok, code, msg)
	}

	// RequiredCapabilities 映射校验
	rMuxOnly := RequiredCapabilities(CapabilityFacts{TLSMuxRequired: true})
	if rMuxOnly.Protocols["tls_mux"] != "v1" || rMuxOnly.Protocols["tlcp"] != "" {
		t.Fatalf("TLSMuxRequired mapping = %+v", rMuxOnly.Protocols)
	}
	rBoth := RequiredCapabilities(CapabilityFacts{TLSMuxRequired: true, TLCPRequired: true})
	if rBoth.Protocols["tls_mux"] != "v1" || rBoth.Protocols["tlcp"] != "1.1" {
		t.Fatalf("TLSMux+TLCP mapping = %+v", rBoth.Protocols)
	}

	// 仅 TLS 1.0 降级（无国密）→ 仅需求 tls_mux="v1"，不需求 tlcp
	downgradeApp := httpsOnlyApp("tls10", uuid.NewString(), "", "tls10.example.com")
	downgradeApp.CertPEM, downgradeApp.KeyPEM = testIntlCertPEM, testIntlKeyPEM
	downgradeApp.TLSConfig = &AppTLSConfig{
		TLSProtocolMode:    TLSProtocolModeInternationalOnly,
		AllowedTLSVersions: []string{TLSVersion10, TLSVersion12},
	}
	muxReq, tlcpReq := capabilityFactsFromApps([]AppData{downgradeApp})
	if !muxReq || tlcpReq {
		t.Fatalf("TLS1.0 downgrade facts = (mux=%v, tlcp=%v), want (true, false)", muxReq, tlcpReq)
	}

	// 国密双证站点 & tlcp 源站 & tlcp 路径转发 → 同时需求 tls_mux="v1" 与 tlcp="1.1"
	gmApp := dualCertTestApp("gm-cap", "gm.example.com", 443, uuid.NewString(), uuid.NewString())
	tlcpUpstreamApp := sampleApps()[0]
	tlcpUpstreamApp.Upstreams[0].Scheme = "tlcp"
	tlcpPathApp := sampleApps()[0]
	tlcpPathApp.PathRoutes = []AppPathRoute{{PathPrefix: "/gm", UpstreamScheme: "tlcp", UpstreamHost: "192.0.2.9", UpstreamPort: 8443}}

	for _, tc := range []struct {
		name string
		app  AppData
	}{
		{"gm dual cert site", gmApp},
		{"tlcp upstream", tlcpUpstreamApp},
		{"tlcp path route", tlcpPathApp},
	} {
		t.Run(tc.name, func(t *testing.T) {
			// 无 manifest → CAPABILITY_MANIFEST_UNAVAILABLE
			pNoManifest := &Publisher{sidecarDir: t.TempDir()}
			if ok, code, _ := pNoManifest.evaluateCapabilityGateWithApps(context.Background(), nil, []AppData{tc.app}); ok || code != "CAPABILITY_MANIFEST_UNAVAILABLE" {
				t.Fatalf("missing manifest: ok=%v code=%s, want CAPABILITY_MANIFEST_UNAVAILABLE", ok, code)
			}

			// 旧节点 manifest 不含 tls_mux / tlcp → fail-closed CAPABILITY_MISSING
			oldDir := t.TempDir()
			writeManifest(t, oldDir, fullManifest("gw-old", time.Now().UTC()))
			pOld := &Publisher{sidecarDir: oldDir}
			ok, code, msg := pOld.evaluateCapabilityGateWithApps(context.Background(), nil, []AppData{tc.app})
			if ok || code != "CAPABILITY_MISSING" {
				t.Fatalf("old node must fail-closed: ok=%v code=%s msg=%s", ok, code, msg)
			}
			if !strings.Contains(msg, "CAP_MISSING:protocols.tls_mux") || !strings.Contains(msg, "CAP_MISSING:protocols.tlcp") {
				t.Fatalf("missing capability detail incomplete: %s", msg)
			}

			// 新节点 manifest 声明 tls_mux="v1" + tlcp="1.1" → 放行
			newDir := t.TempDir()
			m := fullManifest("gw-new", time.Now().UTC())
			m.Protocols["tls_mux"] = "v1"
			m.Protocols["tlcp"] = "1.1"
			writeManifest(t, newDir, m)
			pNew := &Publisher{sidecarDir: newDir}
			if ok, code, msg := pNew.evaluateCapabilityGateWithApps(context.Background(), nil, []AppData{tc.app}); !ok || code != "" {
				t.Fatalf("capable node must allow: ok=%v code=%s msg=%s", ok, code, msg)
			}
		})
	}
}

// dualProtoTestListener 模拟同端口双协议监听器：首包 0x16 0x01 0x01 走 tlcp.Server，其余走 tls.Server。
type dualProtoTestListener struct {
	net.Listener
	tlsCfg    *tls.Config
	tlcpCfg   *tlcp.Config
	intlHits  atomic.Int32
	tlcpHits  atomic.Int32
	allowTLCP bool
}

func (l *dualProtoTestListener) Accept() (net.Conn, error) {
	for {
		raw, err := l.Listener.Accept()
		if err != nil {
			return nil, err
		}
		br := bufio.NewReader(raw)
		hdr, err := br.Peek(3)
		if err != nil {
			_ = raw.Close()
			continue
		}
		bc := &bufferedConn{Conn: raw, r: br}
		if hdr[0] == 0x16 && hdr[1] == 0x01 && hdr[2] == 0x01 {
			l.tlcpHits.Add(1)
			if !l.allowTLCP || l.tlcpCfg == nil {
				_ = raw.Close()
				continue
			}
			return tlcp.Server(bc, l.tlcpCfg), nil
		}
		l.intlHits.Add(1)
		return tls.Server(bc, l.tlsCfg), nil
	}
}

// 8. 真实 gotlcp/tlcp 发布后冒烟探针：国密单证 PASS、双证国际+国密双探针 PASS、国密握手失败 FAIL（触发回滚）与目标解析。
func TestRunPublishSmokeGMTLCPAndDualCert(t *testing.T) {
	t.Setenv("GATEWAY_PUBLISH_SMOKE_ADDR", "")
	signPair, encPair := makeRealSM2DualCertPair(t, "gm.example.com")
	tlcpCfg := &tlcp.Config{Certificates: []tlcp.Certificate{signPair, encPair}}
	intlCert := selfSignedSmokeTLSCert(t)
	tlsCfg := &tls.Config{Certificates: []tls.Certificate{intlCert}}

	t.Run("resolveSmokeTargets sets HasIntlCert and HasGMCert accurately", func(t *testing.T) {
		httpPort, httpsPort := 80, 443
		// 同时开启 HTTP:80 和 HTTPS:443（未设跳转）的国密双证站点必须优先探测 HTTPS:443
		dualApp := AppData{
			AppID: uuid.NewString(), Code: "dual", ProtectionMode: applications.ModeProtect,
			HasCert: true, HasGMCert: true,
			Domains: []applications.Domain{{
				NormalizedHostname: "gm.example.com",
				HTTPEnabled:        true, HTTPPort: &httpPort,
				HTTPSEnabled: true, HTTPSPort: &httpsPort,
			}},
		}
		targets, _ := resolveSmokeTargets([]AppData{dualApp}, &GuardConfig{})
		if len(targets) != 1 || targets[0].scheme != "https" || targets[0].port != 443 || !targets[0].HasIntlCert || !targets[0].HasGMCert {
			t.Fatalf("dual target = %+v", targets)
		}

		// GM_ONLY 模式仅置 HasGMCert=true, HasIntlCert=false
		gmOnlyApp := dualApp
		gmOnlyApp.TLSConfig = &AppTLSConfig{TLSProtocolMode: TLSProtocolModeGMOnly, AllowedTLSVersions: []string{TLSVersionTLCP11}}
		targetsGM, _ := resolveSmokeTargets([]AppData{gmOnlyApp}, &GuardConfig{})
		if len(targetsGM) != 1 || targetsGM[0].HasIntlCert || !targetsGM[0].HasGMCert {
			t.Fatalf("gm-only target = %+v", targetsGM)
		}
	})

	t.Run("GM-only site passes real local tlcp listener smoke", func(t *testing.T) {
		rawLn, err := net.Listen("tcp", "127.0.0.1:0")
		if err != nil {
			t.Fatal(err)
		}
		gmSrv := &http.Server{Handler: authenticatedSmokeGateway()}
		go func() { _ = gmSrv.Serve(tlcp.NewListener(rawLn, tlcpCfg)) }()
		t.Cleanup(func() { _ = gmSrv.Close() })

		p := &Publisher{}
		p.SetSmokeProbe(rawLn.Addr().String(), nil)
		app := AppData{
			AppID: uuid.NewString(), Code: "gm-only", ProtectionMode: applications.ModeProtect,
			HasGMCert: true,
			Domains: []applications.Domain{{
				NormalizedHostname: "gm.example.com", HTTPSEnabled: true, HTTPSPort: intPtr(443),
			}},
		}
		rep := runSmokeTest(t, p, []AppData{app}, &GuardConfig{})
		if rep.failed() || rep.degraded || rep.versionResult() != VersionSmokePass {
			t.Fatalf("GM-only smoke report = %+v, want SMOKE_PASS", rep)
		}
		foundGM := false
		for _, pr := range rep.probes {
			if pr.Probe == SmokeProbeGMTLCP && pr.Result == SmokeResultPass {
				foundGM = true
			}
		}
		if !foundGM {
			t.Fatalf("expected GM_TLCP PASS probe in %+v", rep.probes)
		}
	})

	t.Run("GM-only site fails smoke on TLCP handshake failure (triggers rollback)", func(t *testing.T) {
		// 对端仅监听国际 TLS（不支持 TLCP 1.1），TCP 可达但 TLCP 握手失败 → 必须判 FAIL
		rawLn, err := net.Listen("tcp", "127.0.0.1:0")
		if err != nil {
			t.Fatal(err)
		}
		intlSrv := &http.Server{Handler: authenticatedSmokeGateway()}
		go func() { _ = intlSrv.Serve(tls.NewListener(rawLn, tlsCfg)) }()
		t.Cleanup(func() { _ = intlSrv.Close() })

		p := &Publisher{}
		p.SetSmokeProbe(rawLn.Addr().String(), nil)
		app := AppData{
			AppID: uuid.NewString(), Code: "gm-broken", ProtectionMode: applications.ModeProtect,
			HasGMCert: true,
			Domains: []applications.Domain{{
				NormalizedHostname: "gm.example.com", HTTPSEnabled: true, HTTPSPort: intPtr(443),
			}},
		}
		rep := runSmokeTest(t, p, []AppData{app}, &GuardConfig{})
		if !rep.failed() || rep.degraded || rep.versionResult() != VersionSmokeFail {
			t.Fatalf("GM handshake failure must FAIL (trigger rollback), not degrade: %+v", rep)
		}
		if !strings.Contains(rep.failureDetail(), SmokeProbeGMTLCP) {
			t.Fatalf("failureDetail = %q, want GM_TLCP", rep.failureDetail())
		}
	})

	t.Run("dual-cert site probes BOTH international TLS and GM TLCP", func(t *testing.T) {
		rawLn, err := net.Listen("tcp", "127.0.0.1:0")
		if err != nil {
			t.Fatal(err)
		}
		dualLn := &dualProtoTestListener{
			Listener:  rawLn,
			tlsCfg:    tlsCfg,
			tlcpCfg:   tlcpCfg,
			allowTLCP: true,
		}
		srv := &http.Server{Handler: authenticatedSmokeGateway()}
		go func() { _ = srv.Serve(dualLn) }()
		t.Cleanup(func() { _ = srv.Close() })

		p := &Publisher{}
		p.SetSmokeProbe(rawLn.Addr().String(), nil)
		app := AppData{
			AppID: uuid.NewString(), Code: "dual-site", ProtectionMode: applications.ModeProtect,
			HasCert: true, HasGMCert: true,
			Domains: []applications.Domain{{
				NormalizedHostname: "gm.example.com", HTTPSEnabled: true, HTTPSPort: intPtr(443),
			}},
		}
		rep := runSmokeTest(t, p, []AppData{app}, &GuardConfig{})
		if rep.failed() || rep.degraded || rep.versionResult() != VersionSmokePass {
			t.Fatalf("dual-cert smoke report = %+v, want SMOKE_PASS", rep)
		}
		if dualLn.intlHits.Load() == 0 || dualLn.tlcpHits.Load() == 0 {
			t.Fatalf("dual-cert smoke must probe BOTH protocols: intlHits=%d tlcpHits=%d",
				dualLn.intlHits.Load(), dualLn.tlcpHits.Load())
		}
	})

	t.Run("dual-cert site fails rollback when GM TLCP broken while intl TLS works", func(t *testing.T) {
		rawLn, err := net.Listen("tcp", "127.0.0.1:0")
		if err != nil {
			t.Fatal(err)
		}
		dualLn := &dualProtoTestListener{
			Listener:  rawLn,
			tlsCfg:    tlsCfg,
			tlcpCfg:   tlcpCfg,
			allowTLCP: false, // 国际 TLS 正常，国密 TLCP 关闭/拒绝
		}
		srv := &http.Server{Handler: authenticatedSmokeGateway()}
		go func() { _ = srv.Serve(dualLn) }()
		t.Cleanup(func() { _ = srv.Close() })

		p := &Publisher{}
		p.SetSmokeProbe(rawLn.Addr().String(), nil)
		app := AppData{
			AppID: uuid.NewString(), Code: "dual-gm-broken", ProtectionMode: applications.ModeProtect,
			HasCert: true, HasGMCert: true,
			Domains: []applications.Domain{{
				NormalizedHostname: "gm.example.com", HTTPSEnabled: true, HTTPSPort: intPtr(443),
			}},
		}
		rep := runSmokeTest(t, p, []AppData{app}, &GuardConfig{})
		if !rep.failed() || rep.versionResult() != VersionSmokeFail {
			t.Fatalf("broken GM TLCP on dual-cert site must FAIL: %+v", rep)
		}
		if !strings.Contains(rep.failureDetail(), SmokeProbeGMTLCP) {
			t.Fatalf("failureDetail = %q, want GM_TLCP", rep.failureDetail())
		}
	})

	t.Run("GM-only site degrades gracefully when TCP port unreachable", func(t *testing.T) {
		deadLn, err := net.Listen("tcp", "127.0.0.1:0")
		if err != nil {
			t.Fatal(err)
		}
		deadAddr := deadLn.Addr().String()
		_ = deadLn.Close()

		p := &Publisher{}
		p.SetSmokeProbe(deadAddr, nil)
		app := AppData{
			AppID: uuid.NewString(), Code: "gm-dead", ProtectionMode: applications.ModeProtect,
			HasGMCert: true,
			Domains: []applications.Domain{{
				NormalizedHostname: "gm.example.com", HTTPSEnabled: true, HTTPSPort: intPtr(443),
			}},
		}
		rep := runSmokeTest(t, p, []AppData{app}, &GuardConfig{})
		if rep.failed() || !rep.degraded || rep.versionResult() != VersionSmokeSkipped {
			t.Fatalf("unreachable TCP must degrade cleanly: %+v", rep)
		}
	})
}

package iplibhttp

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/base64"
	"errors"
	"fmt"
	"io"
	"math/big"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/jiuzhang-waf/server/internal/encryption"
	"github.com/jiuzhang-waf/server/internal/outboundhttp"
)

type memSettingsStore struct {
	mu    sync.Mutex
	strs  map[string]string
	bools map[string]bool
	ints  map[string]int
}

func newMemSettingsStore() *memSettingsStore {
	return &memSettingsStore{
		strs:  map[string]string{},
		bools: map[string]bool{},
		ints:  map[string]int{},
	}
}

func (m *memSettingsStore) GetString(_ context.Context, g, k, def string) string {
	m.mu.Lock()
	defer m.mu.Unlock()
	if v, ok := m.strs[g+":"+k]; ok {
		return v
	}
	return def
}

func (m *memSettingsStore) GetBool(_ context.Context, g, k string, def bool) bool {
	m.mu.Lock()
	defer m.mu.Unlock()
	if v, ok := m.bools[g+":"+k]; ok {
		return v
	}
	return def
}

func (m *memSettingsStore) GetInt(_ context.Context, g, k string, def int) int {
	m.mu.Lock()
	defer m.mu.Unlock()
	if v, ok := m.ints[g+":"+k]; ok {
		return v
	}
	return def
}

func (m *memSettingsStore) UpsertString(_ context.Context, g, k, v, _ string, _ uuid.UUID) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.strs[g+":"+k] = v
	return nil
}

func (m *memSettingsStore) UpsertSensitiveString(_ context.Context, g, k, v, _ string, _ uuid.UUID) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.strs[g+":"+k] = v
	return nil
}

func (m *memSettingsStore) UpsertBool(_ context.Context, g, k string, v bool, _ string, _ uuid.UUID) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.bools[g+":"+k] = v
	return nil
}

type staticResolver map[string][]net.IP

func (r staticResolver) LookupIP(_ context.Context, _, host string) ([]net.IP, error) {
	ips, ok := r[normalizeHost(host)]
	if !ok {
		return nil, fmt.Errorf("no such host: %s", host)
	}
	return ips, nil
}

type dynamicResolver struct {
	mu sync.Mutex
	fn func(host string) ([]net.IP, error)
}

func (r *dynamicResolver) LookupIP(_ context.Context, _, host string) ([]net.IP, error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	return r.fn(normalizeHost(host))
}

func mustTestCipher(t *testing.T) *encryption.Service {
	t.Helper()
	key := bytes.Repeat([]byte{0x42}, 32)
	svc, err := encryption.NewWithKey(key)
	if err != nil {
		t.Fatalf("NewWithKey: %v", err)
	}
	return svc
}

func newTLSServerForHosts(t *testing.T, hosts []string, handler http.Handler) (*httptest.Server, *x509.Certificate) {
	t.Helper()
	priv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("generate key: %v", err)
	}
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(time.Now().UnixNano()),
		Subject:      pkix.Name{CommonName: hosts[0]},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(24 * time.Hour),
		KeyUsage:     x509.KeyUsageDigitalSignature | x509.KeyUsageKeyEncipherment,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		DNSNames:     hosts,
		IPAddresses:  []net.IP{net.ParseIP("127.0.0.1")},
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &priv.PublicKey, priv)
	if err != nil {
		t.Fatalf("create cert: %v", err)
	}
	cert, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatalf("parse cert: %v", err)
	}
	srv := httptest.NewUnstartedServer(handler)
	srv.TLS = &tls.Config{
		Certificates: []tls.Certificate{{Certificate: [][]byte{der}, PrivateKey: priv, Leaf: cert}},
	}
	srv.StartTLS()
	t.Cleanup(srv.Close)
	return srv, cert
}

func tlsConfigForCerts(certs ...*x509.Certificate) *tls.Config {
	pool := x509.NewCertPool()
	for _, c := range certs {
		pool.AddCert(c)
	}
	return &tls.Config{RootCAs: pool, MinVersion: tls.VersionTLS12}
}

func mustPort(t *testing.T, rawURL string) string {
	t.Helper()
	u, err := outboundhttp.ParseURL(rawURL)
	if err != nil {
		t.Fatalf("ParseURL(%s): %v", rawURL, err)
	}
	return u.Port()
}

func TestDownloaderOfflineOnlyRejected(t *testing.T) {
	d := NewDownloader(newMemSettingsStore(), nil)
	if err := d.ValidateTargetURL(context.Background(), SourceModeOfflineOnly, "https://download.db-ip.com/a.mmdb.gz"); !errors.Is(err, ErrOfflineOnly) {
		t.Fatalf("ValidateTargetURL offline = %v, want ErrOfflineOnly", err)
	}
	if _, err := d.Fetch(context.Background(), FetchRequest{
		SourceMode: SourceModeOfflineOnly,
		URL:        "https://download.db-ip.com/a.mmdb.gz",
	}); !errors.Is(err, ErrOfflineOnly) {
		t.Fatalf("Fetch offline = %v, want ErrOfflineOnly", err)
	}
}

func TestDownloaderOfficialHostAndSchemeValidation(t *testing.T) {
	resolver := staticResolver{
		"download.db-ip.com":        {net.ParseIP("93.184.216.34")},
		"download.maxmind.com":      {net.ParseIP("93.184.216.34")},
		"raw.githubusercontent.com": {net.ParseIP("93.184.216.34")},
		"github.com":                {net.ParseIP("93.184.216.34")},
		"feodotracker.abuse.ch":     {net.ParseIP("93.184.216.34")},
		"sslbl.abuse.ch":            {net.ParseIP("93.184.216.34")},
		"evil.example.com":          {net.ParseIP("93.184.216.34")},
	}
	d := NewDownloader(newMemSettingsStore(), nil).SetResolver(resolver)

	for host := range OfficialHosts {
		if err := d.ValidateTargetURL(context.Background(), SourceModeOfficial, "https://"+host+"/file"); err != nil {
			t.Errorf("official host %s should pass: %v", host, err)
		}
		if err := d.ValidateTargetURL(context.Background(), SourceModeOfficial, "http://"+host+"/file"); !errors.Is(err, outboundhttp.ErrDenied) {
			t.Errorf("official host http://%s should be denied, got %v", host, err)
		}
	}
	if err := d.ValidateTargetURL(context.Background(), SourceModeOfficial, "https://evil.example.com/file"); !errors.Is(err, outboundhttp.ErrDenied) {
		t.Fatalf("non-official host should be denied, got %v", err)
	}
	if err := d.ValidateTargetURL(context.Background(), SourceModeOfficial, "https://user:pass@download.maxmind.com/file"); !errors.Is(err, outboundhttp.ErrDenied) {
		t.Fatalf("embedded userinfo should be denied, got %v", err)
	}

	// 官方域名若被 DNS 污染到私网或云元数据必须拦截
	poisonResolver := staticResolver{
		"download.maxmind.com": {net.ParseIP("169.254.169.254")},
		"download.db-ip.com":   {net.ParseIP("10.0.0.1")},
	}
	dPoison := NewDownloader(newMemSettingsStore(), nil).SetResolver(poisonResolver)
	if err := dPoison.ValidateTargetURL(context.Background(), SourceModeOfficial, "https://download.maxmind.com/file"); !errors.Is(err, outboundhttp.ErrDenied) {
		t.Fatalf("official host resolving to metadata must be denied, got %v", err)
	}
	if err := dPoison.ValidateTargetURL(context.Background(), SourceModeOfficial, "https://download.db-ip.com/file"); !errors.Is(err, outboundhttp.ErrDenied) {
		t.Fatalf("official host resolving to private IP must be denied, got %v", err)
	}
}

func TestDownloaderOfficialMaxMindRedirectStripsAuthAndConditionalGET(t *testing.T) {
	var r2Auth, r2ProxyAuth, r2Cookie string
	r2Srv, r2Cert := newTLSServerForHosts(t, []string{"r2.cloudflarestorage.com"}, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		r2Auth = r.Header.Get("Authorization")
		r2ProxyAuth = r.Header.Get("Proxy-Authorization")
		r2Cookie = r.Header.Get("Cookie")
		w.Header().Set("ETag", `"mm-v1"`)
		w.Header().Set("Last-Modified", "Sat, 28 Nov 2026 08:00:00 GMT")
		w.Header().Set("Content-Disposition", `attachment; filename="GeoLite2-City_20261128.tar.gz"`)
		_, _ = w.Write([]byte("fake-tar-gz-payload"))
	}))
	r2Port := mustPort(t, r2Srv.URL)

	var mmUser, mmPass string
	var mmHasAuth bool
	mmSrv, mmCert := newTLSServerForHosts(t, []string{"download.maxmind.com"}, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		mmUser, mmPass, mmHasAuth = r.BasicAuth()
		if r.Header.Get("If-None-Match") == `"mm-v1"` {
			w.Header().Set("ETag", `"mm-v1"`)
			w.WriteHeader(http.StatusNotModified)
			return
		}
		if r.URL.Path == "/missing" {
			w.WriteHeader(http.StatusNotFound)
			return
		}
		http.Redirect(w, r, "https://r2.cloudflarestorage.com:"+r2Port+"/signed/bundle?X-Sig=secret", http.StatusFound)
	}))
	mmPort := mustPort(t, mmSrv.URL)

	d := NewDownloader(newMemSettingsStore(), nil).SetResolver(staticResolver{
		"download.maxmind.com":     {net.ParseIP("127.0.0.1")},
		"r2.cloudflarestorage.com": {net.ParseIP("127.0.0.1")},
	})
	d.officialAllowlist = "127.0.0.0/8"
	d.tlsConfig = tlsConfigForCerts(mmCert, r2Cert)

	// 1. 首次拉取：MaxMind 收到 Basic Auth，302 跳转 R2 后严格剥离 Authorization/Proxy-Authorization/Cookie
	res, err := d.Fetch(context.Background(), FetchRequest{
		SourceMode: SourceModeOfficial,
		URL:        "https://download.maxmind.com:" + mmPort + "/geoip/databases/GeoLite2-City/download?suffix=tar.gz",
		BasicUser:  "123456",
		BasicPass:  "maxmind-secret-key",
		MaxBytes:   1024,
	})
	if err != nil {
		t.Fatalf("Fetch MaxMind redirect: %v", err)
	}
	body, err := io.ReadAll(res.Body)
	_ = res.Body.Close()
	if err != nil {
		t.Fatalf("read body: %v", err)
	}
	if string(body) != "fake-tar-gz-payload" {
		t.Fatalf("body = %q", string(body))
	}
	if !mmHasAuth || mmUser != "123456" || mmPass != "maxmind-secret-key" {
		t.Fatalf("MaxMind did not receive expected Basic Auth: has=%v user=%q", mmHasAuth, mmUser)
	}
	if r2Auth != "" || r2ProxyAuth != "" || r2Cookie != "" {
		t.Fatalf("sensitive headers leaked to R2: auth=%q proxyAuth=%q cookie=%q", r2Auth, r2ProxyAuth, r2Cookie)
	}
	if res.Filename != "GeoLite2-City_20261128.tar.gz" || res.ETag != `"mm-v1"` {
		t.Fatalf("unexpected metadata: filename=%q etag=%q", res.Filename, res.ETag)
	}
	if strings.Contains(res.FinalURL, "X-Sig=secret") {
		t.Fatalf("FinalURL leaked query string: %q", res.FinalURL)
	}

	// 2. 条件请求命中 304 Not Modified
	res304, err := d.Fetch(context.Background(), FetchRequest{
		SourceMode: SourceModeOfficial,
		URL:        "https://download.maxmind.com:" + mmPort + "/geoip/databases/GeoLite2-City/download?suffix=tar.gz",
		ETag:       `"mm-v1"`,
		BasicUser:  "123456",
		BasicPass:  "maxmind-secret-key",
	})
	if err != nil {
		t.Fatalf("Fetch 304: %v", err)
	}
	if !res304.NotModified || res304.StatusCode != http.StatusNotModified || res304.Body != nil {
		t.Fatalf("expected NotModified=true, got %+v", res304)
	}

	// 3. 404 返回 typed HTTPStatusError（供 DB-IP 月度回退判断）
	_, err = d.Fetch(context.Background(), FetchRequest{
		SourceMode: SourceModeOfficial,
		URL:        "https://download.maxmind.com:" + mmPort + "/missing",
	})
	var statusErr *HTTPStatusError
	if !errors.As(err, &statusErr) || statusErr.StatusCode != http.StatusNotFound {
		t.Fatalf("expected HTTPStatusError 404, got %v", err)
	}

	// 4. MaxBytes 超限拒绝
	_, err = d.Fetch(context.Background(), FetchRequest{
		SourceMode: SourceModeOfficial,
		URL:        "https://download.maxmind.com:" + mmPort + "/geoip/databases/GeoLite2-City/download?suffix=tar.gz",
		MaxBytes:   4,
	})
	if !errors.Is(err, ErrResponseTooLarge) {
		t.Fatalf("expected ErrResponseTooLarge, got %v", err)
	}
}

func TestDownloaderOfficialRedirectDowngradeAndPrivateDenied(t *testing.T) {
	// 1. 禁止 HTTPS 降级重定向至 HTTP
	downgradeSrv, cert1 := newTLSServerForHosts(t, []string{"download.db-ip.com"}, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, "http://cdn.example.com/file.mmdb.gz", http.StatusFound)
	}))
	d := NewDownloader(newMemSettingsStore(), nil).SetResolver(staticResolver{
		"download.db-ip.com": {net.ParseIP("127.0.0.1")},
		"cdn.example.com":    {net.ParseIP("93.184.216.34")},
		"internal.evil":      {net.ParseIP("10.0.0.5")},
	})
	d.officialAllowlist = "127.0.0.0/8"
	d.tlsConfig = tlsConfigForCerts(cert1)

	if _, err := d.Fetch(context.Background(), FetchRequest{
		SourceMode: SourceModeOfficial,
		URL:        "https://download.db-ip.com:" + mustPort(t, downgradeSrv.URL) + "/db.mmdb.gz",
	}); !errors.Is(err, outboundhttp.ErrDenied) {
		t.Fatalf("HTTPS->HTTP downgrade should be denied, got %v", err)
	}

	// 2. 禁止重定向到私网地址（即使首跳合法）
	privSrv, cert2 := newTLSServerForHosts(t, []string{"download.db-ip.com"}, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, "https://internal.evil/secret", http.StatusFound)
	}))
	d.tlsConfig = tlsConfigForCerts(cert2)
	if _, err := d.Fetch(context.Background(), FetchRequest{
		SourceMode: SourceModeOfficial,
		URL:        "https://download.db-ip.com:" + mustPort(t, privSrv.URL) + "/db.mmdb.gz",
	}); !errors.Is(err, outboundhttp.ErrDenied) {
		t.Fatalf("redirect to private IP should be denied, got %v", err)
	}

	// 3. 超过 5 跳重定向拒绝
	var loopSrv *httptest.Server
	var cert3 *x509.Certificate
	loopSrv, cert3 = newTLSServerForHosts(t, []string{"download.db-ip.com"}, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, "https://download.db-ip.com:"+mustPort(t, loopSrv.URL)+"/loop", http.StatusFound)
	}))
	d.tlsConfig = tlsConfigForCerts(cert3)
	if _, err := d.Fetch(context.Background(), FetchRequest{
		SourceMode: SourceModeOfficial,
		URL:        "https://download.db-ip.com:" + mustPort(t, loopSrv.URL) + "/loop",
	}); !errors.Is(err, outboundhttp.ErrDenied) {
		t.Fatalf("redirect loop should be denied, got %v", err)
	}
}

func TestDownloaderCustomURLAllowlistHTTPMirrorAndMetadataHardDeny(t *testing.T) {
	httpSrv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte("mirror-ok"))
	}))
	defer httpSrv.Close()
	httpPort := mustPort(t, httpSrv.URL)

	httpsSrv, httpsCert := newTLSServerForHosts(t, []string{"mirror.corp.local"}, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte("https-mirror-ok"))
	}))
	httpsPort := mustPort(t, httpsSrv.URL)

	store := newMemSettingsStore()
	resolver := staticResolver{
		"mirror.corp.local":        {net.ParseIP("127.0.0.1")},
		"public.example.com":       {net.ParseIP("93.184.216.34")},
		"meta.corp.local":          {net.ParseIP("169.254.169.254")},
		"ecs-meta.corp.local":      {net.ParseIP("169.254.170.2")},
		"aliyun-meta.corp.local":   {net.ParseIP("100.100.100.200")},
		"metadata.google.internal": {net.ParseIP("169.254.169.254")},
	}
	d := NewDownloader(store, nil).SetResolver(resolver)
	d.tlsConfig = tlsConfigForCerts(httpsCert)

	// 1. 无白名单时拒绝内网 HTTPS 与明文 HTTP
	if err := d.ValidateTargetURL(context.Background(), SourceModeCustomURL, "https://mirror.corp.local:"+httpsPort+"/db.xdb"); !errors.Is(err, outboundhttp.ErrDenied) {
		t.Fatalf("private host without allowlist should be denied, got %v", err)
	}
	if err := d.ValidateTargetURL(context.Background(), SourceModeCustomURL, "http://public.example.com/db.xdb"); !errors.Is(err, outboundhttp.ErrDenied) {
		t.Fatalf("public http should be denied, got %v", err)
	}

	// 2. 配置白名单但未开启 allow_insecure_http_mirror：HTTPS 允许，HTTP 仍拒绝
	store.strs[SettingsGroup+":"+KeyOutboundAllowlist] = "mirror.corp.local, 127.0.0.0/8, 169.254.0.0/16, 100.64.0.0/10, fd00::/8, meta.corp.local"
	store.bools[SettingsGroup+":"+KeyAllowInsecureHTTPMirror] = false

	resHTTPS, err := d.Fetch(context.Background(), FetchRequest{
		SourceMode: SourceModeCustomURL,
		URL:        "https://mirror.corp.local:" + httpsPort + "/db.xdb",
	})
	if err != nil {
		t.Fatalf("allowlisted HTTPS mirror should succeed: %v", err)
	}
	body, _ := io.ReadAll(resHTTPS.Body)
	_ = resHTTPS.Body.Close()
	if string(body) != "https-mirror-ok" {
		t.Fatalf("https mirror body = %q", string(body))
	}
	if err := d.ValidateTargetURL(context.Background(), SourceModeCustomURL, "http://mirror.corp.local:"+httpPort+"/db.xdb"); !errors.Is(err, outboundhttp.ErrDenied) {
		t.Fatalf("http mirror without allow_insecure_http_mirror should be denied, got %v", err)
	}

	// 3. 开启 allow_insecure_http_mirror：白名单内网 HTTP 放行，但公网 HTTP 仍然拒绝
	store.bools[SettingsGroup+":"+KeyAllowInsecureHTTPMirror] = true
	resHTTP, err := d.Fetch(context.Background(), FetchRequest{
		SourceMode: SourceModeCustomURL,
		URL:        "http://mirror.corp.local:" + httpPort + "/db.xdb",
	})
	if err != nil {
		t.Fatalf("allowlisted HTTP mirror with flag should succeed: %v", err)
	}
	body, _ = io.ReadAll(resHTTP.Body)
	_ = resHTTP.Body.Close()
	if string(body) != "mirror-ok" {
		t.Fatalf("http mirror body = %q", string(body))
	}
	if err := d.ValidateTargetURL(context.Background(), SourceModeCustomURL, "http://public.example.com/db.xdb"); !errors.Is(err, outboundhttp.ErrDenied) {
		t.Fatalf("public http NOT in allowlist must remain denied even with allow_insecure_http_mirror=true, got %v", err)
	}

	// 4. 云元数据地址即使写进 allowlist 也永远硬阻断
	for _, metaURL := range []string{
		"https://169.254.169.254/latest/meta-data/",
		"http://169.254.169.254/latest/meta-data/",
		"https://169.254.170.2/v2/credentials",
		"https://100.100.100.200/latest/meta-data/",
		"https://[fd00:ec2::254]/latest/meta-data/",
		"https://meta.corp.local/secret",
		"https://metadata.google.internal/computeMetadata/v1/",
	} {
		if err := d.ValidateTargetURL(context.Background(), SourceModeCustomURL, metaURL); !errors.Is(err, outboundhttp.ErrDenied) {
			t.Fatalf("cloud metadata %s MUST be hard-denied, got %v", metaURL, err)
		}
	}

	// 5. DNS 重绑定防护：明文 HTTP 镜像校验时解析到白名单 CIDR，拨号时重绑定为公网 IP 必须拦截
	calls := 0
	rebindRes := &dynamicResolver{fn: func(host string) ([]net.IP, error) {
		calls++
		if calls <= 2 {
			return []net.IP{net.ParseIP("127.0.0.1")}, nil
		}
		return []net.IP{net.ParseIP("93.184.216.34")}, nil
	}}
	store.strs[SettingsGroup+":"+KeyOutboundAllowlist] = "127.0.0.0/8"
	dRebind := NewDownloader(store, nil).SetResolver(rebindRes)
	if _, err := dRebind.Fetch(context.Background(), FetchRequest{
		SourceMode: SourceModeCustomURL,
		URL:        "http://rebind.corp.local:" + httpPort + "/db.xdb",
	}); !errors.Is(err, outboundhttp.ErrDenied) {
		t.Fatalf("DNS rebinding on http mirror should be denied at dial, got %v", err)
	}
}

func TestDownloaderForwardProxyValidationAndAuth(t *testing.T) {
	cipher := mustTestCipher(t)
	encAuth, err := cipher.Encrypt("corp-user:proxy-secret-99")
	if err != nil {
		t.Fatalf("Encrypt: %v", err)
	}
	expectedProxyAuth := "Basic " + base64.StdEncoding.EncodeToString([]byte("corp-user:proxy-secret-99"))

	// 1. 代理地址校验：拒绝非法协议、内嵌凭据、云元数据
	for _, badProxy := range []string{
		"socks5://10.0.0.5:1080",
		"http://u:p@10.0.0.5:3128",
		"http://169.254.169.254:80",
		"http://100.100.100.200:80",
		"http://[fd00:ec2::254]:80",
		"http://metadata.google.internal:80",
	} {
		if _, err := ValidateProxyURL(context.Background(), badProxy, staticResolver{}, false); !errors.Is(err, outboundhttp.ErrDenied) {
			t.Fatalf("proxy URL %q should be denied, got %v", badProxy, err)
		}
	}

	// 2. 启动真实 HTTP 正向代理（同时支持普通 HTTP 代理与 HTTPS CONNECT 隧道）
	var proxyHits atomic.Int32
	var seenHTTPProxyAuth, seenConnectProxyAuth string
	var mu sync.Mutex

	upstreamHTTPS, upstreamCert := newTLSServerForHosts(t, []string{"download.db-ip.com"}, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte("via-connect-proxy-ok"))
	}))
	upstreamHTTPSAddr := strings.TrimPrefix(upstreamHTTPS.URL, "https://")
	upstreamHTTPSPort := mustPort(t, upstreamHTTPS.URL)

	proxySrv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		proxyHits.Add(1)
		if r.Method == http.MethodConnect {
			mu.Lock()
			seenConnectProxyAuth = r.Header.Get("Proxy-Authorization")
			mu.Unlock()
			// 将目标 download.db-ip.com:<port> 隧道转发到本机测试 HTTPS 服务器
			destConn, err := net.DialTimeout("tcp", upstreamHTTPSAddr, 3*time.Second)
			if err != nil {
				http.Error(w, err.Error(), http.StatusBadGateway)
				return
			}
			hj, ok := w.(http.Hijacker)
			if !ok {
				_ = destConn.Close()
				http.Error(w, "hijack unsupported", http.StatusInternalServerError)
				return
			}
			clientConn, _, err := hj.Hijack()
			if err != nil {
				_ = destConn.Close()
				return
			}
			_, _ = clientConn.Write([]byte("HTTP/1.1 200 Connection Established\r\n\r\n"))
			go func() {
				_, _ = io.Copy(destConn, clientConn)
				_ = destConn.Close()
			}()
			go func() {
				_, _ = io.Copy(clientConn, destConn)
				_ = clientConn.Close()
			}()
			return
		}
		mu.Lock()
		seenHTTPProxyAuth = r.Header.Get("Proxy-Authorization")
		mu.Unlock()
		_, _ = w.Write([]byte("via-http-proxy-ok"))
	}))
	defer proxySrv.Close()

	store := newMemSettingsStore()
	store.strs[SettingsGroup+":"+KeyProxyURL] = proxySrv.URL
	store.strs[SettingsGroup+":"+KeyProxyAuthEncrypted] = encAuth
	store.strs[SettingsGroup+":"+KeyOutboundAllowlist] = "mirror.corp.local"
	store.bools[SettingsGroup+":"+KeyAllowInsecureHTTPMirror] = true

	// 解析器故意不解析 download.db-ip.com，验证代理模式下隔离网段无外网 DNS 仍可放行官方域名走代理
	d := NewDownloader(store, cipher).SetResolver(staticResolver{
		"127.0.0.1": {net.ParseIP("127.0.0.1")},
	})
	d.tlsConfig = tlsConfigForCerts(upstreamCert)

	// 2a. 目标 URL 校验先于拨号代理：非法目标绝不能触达代理
	if _, err := d.Fetch(context.Background(), FetchRequest{
		SourceMode: SourceModeCustomURL,
		URL:        "https://169.254.169.254/latest/meta-data/",
	}); !errors.Is(err, outboundhttp.ErrDenied) {
		t.Fatalf("metadata target via proxy must be denied before dialing proxy, got %v", err)
	}
	if _, err := d.Fetch(context.Background(), FetchRequest{
		SourceMode: SourceModeOfficial,
		URL:        "https://evil.example.com/db.xdb",
	}); !errors.Is(err, outboundhttp.ErrDenied) {
		t.Fatalf("non-official target via proxy must be denied, got %v", err)
	}
	if proxyHits.Load() != 0 {
		t.Fatalf("proxy should not be contacted for denied targets, hits=%d", proxyHits.Load())
	}

	// 2b. 白名单明文 HTTP 镜像走代理并携带解密后的 Proxy-Authorization
	resHTTP, err := d.Fetch(context.Background(), FetchRequest{
		SourceMode: SourceModeCustomURL,
		URL:        "http://mirror.corp.local/ip2region_v4.xdb",
	})
	if err != nil {
		t.Fatalf("HTTP target via proxy failed: %v", err)
	}
	b1, _ := io.ReadAll(resHTTP.Body)
	_ = resHTTP.Body.Close()
	if string(b1) != "via-http-proxy-ok" {
		t.Fatalf("HTTP proxy body = %q", string(b1))
	}
	mu.Lock()
	gotHTTPAuth := seenHTTPProxyAuth
	mu.Unlock()
	if gotHTTPAuth != expectedProxyAuth {
		t.Fatalf("HTTP proxy auth = %q, want %q", gotHTTPAuth, expectedProxyAuth)
	}

	// 2c. 官方 HTTPS 走 CONNECT 隧道代理并携带 Proxy-Authorization
	resHTTPS, err := d.Fetch(context.Background(), FetchRequest{
		SourceMode: SourceModeOfficial,
		URL:        "https://download.db-ip.com:" + upstreamHTTPSPort + "/free/dbip-city-lite-2026-11.mmdb.gz",
	})
	if err != nil {
		t.Fatalf("HTTPS target via CONNECT proxy failed: %v", err)
	}
	b2, _ := io.ReadAll(resHTTPS.Body)
	_ = resHTTPS.Body.Close()
	if string(b2) != "via-connect-proxy-ok" {
		t.Fatalf("HTTPS proxy body = %q", string(b2))
	}
	mu.Lock()
	gotConnectAuth := seenConnectProxyAuth
	mu.Unlock()
	if gotConnectAuth != expectedProxyAuth {
		t.Fatalf("CONNECT proxy auth = %q, want %q", gotConnectAuth, expectedProxyAuth)
	}
}

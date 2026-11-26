// directory.go Web Bot Auth 爬虫公钥目录不可变原子快照与可选 SSRF 防护后台刷新。
//
// 安全纪律：
//   - 热路径（Lookup / LookupKey）仅读取 atomic.Pointer 指向的不可变快照，零锁竞争、零网络 IO；
//   - 离线环境（directory_url 为空）不启动任何后台 goroutine，100% 本地工作；
//   - 可选远程刷新严格执行 SSRF 防护：仅 HTTPS、禁跳转、禁代理继承、5s 超时、256KiB 上限、
//     拨号时 DNS 重解析并拒绝一切回环/私有/链路本地/元数据/保留 IP（防 DNS 重绑定），
//     随 Guard.Cleanup 取消 ctx 立即退出。
package aicrawl

import (
	"context"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"io"
	"math/big"
	"net"
	"net/http"
	"net/netip"
	"net/url"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/jiuzhang-waf/gateway/dynamic_security/httpsig"
)

const (
	// DefaultFetchTimeout 远程目录获取硬超时（5s）。
	DefaultFetchTimeout = 5 * time.Second
	// DefaultMaxDirectoryBytes 远程目录响应体硬上限（256 KiB）。
	DefaultMaxDirectoryBytes int64 = 256 << 10
	// DefaultRefreshInterval 远程目录后台刷新周期。
	DefaultRefreshInterval = 15 * time.Minute
)

var (
	errSSRFBlocked = errors.New("aicrawl: directory URL blocked by SSRF policy")

	ssrfBlockedPrefixes = mustParsePrefixes([]string{
		"0.0.0.0/8",          // unspecified / this network
		"10.0.0.0/8",         // RFC 1918 private
		"100.64.0.0/10",      // CGNAT
		"100.100.100.200/32", // Alibaba Cloud metadata
		"127.0.0.0/8",        // IPv4 loopback
		"169.254.0.0/16",     // IPv4 link-local & cloud metadata (169.254.169.254)
		"172.16.0.0/12",      // RFC 1918 private
		"192.168.0.0/16",     // RFC 1918 private
		"198.18.0.0/15",      // benchmark
		"224.0.0.0/4",        // multicast
		"240.0.0.0/4",        // reserved / broadcast
		"::/128",             // IPv6 unspecified
		"::1/128",            // IPv6 loopback
		"fc00::/7",           // IPv6 ULA
		"fe80::/10",          // IPv6 link-local
		"ff00::/8",           // IPv6 multicast
	})

	ssrfBlockedHosts = []string{
		"localhost",
		"metadata",
		"metadata.google.internal",
		"instance-data",
	}
)

func mustParsePrefixes(list []string) []netip.Prefix {
	out := make([]netip.Prefix, 0, len(list))
	for _, s := range list {
		p, err := netip.ParsePrefix(s)
		if err != nil {
			panic(fmt.Sprintf("aicrawl: invalid builtin prefix %q: %v", s, err))
		}
		out = append(out, p)
	}
	return out
}

// Resolver DNS 解析接口（便于测试注入，缺省 net.DefaultResolver）。
type Resolver interface {
	LookupIPAddr(ctx context.Context, host string) ([]net.IPAddr, error)
}

// FetcherConfig 受限目录获取器配置。
type FetcherConfig struct {
	Timeout          time.Duration
	MaxResponseBytes int64
	RootCAs          *x509.CertPool
	Resolver         Resolver
	DialTCP          func(ctx context.Context, network, address string) (net.Conn, error)

	// allowPrivateForTest 仅同包单测可开启（生产外部调用方不可见，恒执行 SSRF 防护）。
	allowPrivateForTest bool
}

// Fetcher SSRF 安全的 HTTPS 目录获取器（仅用于后台刷新，热路径绝不调用）。
type Fetcher struct {
	timeout      time.Duration
	maxBytes     int64
	rootCAs      *x509.CertPool
	resolver     Resolver
	dialTCP      func(ctx context.Context, network, address string) (net.Conn, error)
	allowPrivate bool
}

// NewFetcher 构造默认 SSRF 安全目录获取器。
func NewFetcher(cfg FetcherConfig) *Fetcher {
	timeout := cfg.Timeout
	if timeout <= 0 {
		timeout = DefaultFetchTimeout
	}
	maxBytes := cfg.MaxResponseBytes
	if maxBytes <= 0 {
		maxBytes = DefaultMaxDirectoryBytes
	}
	resolver := cfg.Resolver
	if resolver == nil {
		resolver = net.DefaultResolver
	}
	dial := cfg.DialTCP
	if dial == nil {
		d := &net.Dialer{Timeout: timeout}
		dial = d.DialContext
	}
	return &Fetcher{
		timeout:      timeout,
		maxBytes:     maxBytes,
		rootCAs:      cfg.RootCAs,
		resolver:     resolver,
		dialTCP:      dial,
		allowPrivate: cfg.allowPrivateForTest,
	}
}

// Fetch 获取远程目录 JSON（仅 HTTPS、禁跳转、禁代理继承、5s 超时、拨号前 SSRF 复检）。
func (f *Fetcher) Fetch(ctx context.Context, rawURL string) ([]byte, error) {
	if err := validateDirectoryURL(rawURL, f.allowPrivate); err != nil {
		return nil, err
	}
	u, err := url.Parse(rawURL)
	if err != nil {
		return nil, err
	}
	host := u.Hostname()
	port := u.Port()
	if port == "" {
		port = "443"
	}

	reqCtx, cancel := context.WithTimeout(ctx, f.timeout)
	defer cancel()

	transport := &http.Transport{
		Proxy:                 nil, // 显式禁用环境代理
		DisableCompression:    true,
		DisableKeepAlives:     true,
		TLSHandshakeTimeout:   f.timeout,
		ResponseHeaderTimeout: f.timeout,
		TLSClientConfig: &tls.Config{
			MinVersion: tls.VersionTLS12,
			ServerName: host,
			RootCAs:    f.rootCAs,
		},
		DialContext: func(dctx context.Context, _, _ string) (net.Conn, error) {
			return f.dialValidated(dctx, host, port)
		},
	}
	defer transport.CloseIdleConnections()

	client := &http.Client{
		Transport: transport,
		Timeout:   f.timeout,
		CheckRedirect: func(_ *http.Request, _ []*http.Request) error {
			return http.ErrUseLastResponse // 严格禁止跳转
		},
	}

	req, err := http.NewRequestWithContext(reqCtx, http.MethodGet, rawURL, nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("Accept", "application/http-message-signatures-directory+json, application/jwk-set+json, application/json")
	req.Header.Del("Accept-Encoding")

	resp, err := client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("aicrawl: fetch directory failed: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode >= 300 && resp.StatusCode < 400 {
		return nil, fmt.Errorf("aicrawl: directory redirects are forbidden (status %d)", resp.StatusCode)
	}
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("aicrawl: directory fetch returned HTTP %d", resp.StatusCode)
	}
	if resp.ContentLength > f.maxBytes {
		return nil, fmt.Errorf("aicrawl: directory response exceeds %d bytes", f.maxBytes)
	}
	body, err := io.ReadAll(io.LimitReader(resp.Body, f.maxBytes+1))
	if err != nil {
		return nil, fmt.Errorf("aicrawl: read directory response: %w", err)
	}
	if int64(len(body)) > f.maxBytes {
		return nil, fmt.Errorf("aicrawl: directory response exceeds %d bytes", f.maxBytes)
	}
	return body, nil
}

func (f *Fetcher) dialValidated(ctx context.Context, host, port string) (net.Conn, error) {
	var addrs []netip.Addr
	if ip, err := netip.ParseAddr(host); err == nil {
		addrs = []netip.Addr{ip.Unmap()}
	} else {
		ips, err := f.resolver.LookupIPAddr(ctx, host)
		if err != nil {
			return nil, fmt.Errorf("aicrawl: resolve directory host: %w", err)
		}
		for _, ipa := range ips {
			if addr, ok := netip.AddrFromSlice(ipa.IP); ok {
				addrs = append(addrs, addr.Unmap())
			}
		}
	}
	if len(addrs) == 0 {
		return nil, errors.New("aicrawl: directory host resolved to no addresses")
	}
	if !f.allowPrivate {
		for _, a := range addrs {
			if err := ValidateDialIP(a); err != nil {
				return nil, err
			}
		}
	}
	var lastErr error
	for _, a := range addrs {
		conn, err := f.dialTCP(ctx, "tcp", net.JoinHostPort(a.String(), port))
		if err == nil {
			return conn, nil
		}
		lastErr = err
	}
	return nil, fmt.Errorf("aicrawl: dial directory failed: %w", lastErr)
}

// ValidateDialIP 拒绝所有私有、回环、链路本地、元数据、组播与保留 IP。
func ValidateDialIP(addr netip.Addr) error {
	addr = addr.Unmap()
	if !addr.IsValid() {
		return fmt.Errorf("%w: invalid IP", errSSRFBlocked)
	}
	for _, p := range ssrfBlockedPrefixes {
		if p.Contains(addr) {
			return fmt.Errorf("%w: %s is in blocked range", errSSRFBlocked, addr)
		}
	}
	return nil
}

func validateDirectoryURL(raw string, allowPrivate bool) error {
	if len(raw) > maxDirURLLen || hasControlChars(raw) {
		return errors.New("directory_url too long or contains control characters")
	}
	u, err := url.Parse(raw)
	if err != nil {
		return fmt.Errorf("invalid URL: %w", err)
	}
	if !strings.EqualFold(u.Scheme, "https") {
		return errors.New("directory_url must use https scheme")
	}
	if u.User != nil {
		return errors.New("directory_url must not contain userinfo")
	}
	host := strings.TrimSpace(u.Hostname())
	if host == "" {
		return errors.New("directory_url missing host")
	}
	if allowPrivate {
		return nil
	}
	lower := strings.ToLower(strings.TrimSuffix(host, "."))
	for _, bh := range ssrfBlockedHosts {
		if lower == bh || strings.HasSuffix(lower, "."+bh) {
			return fmt.Errorf("%w: host %q is blocked", errSSRFBlocked, host)
		}
	}
	if ip, err := netip.ParseAddr(strings.Trim(host, "[]")); err == nil {
		return ValidateDialIP(ip)
	}
	return nil
}

// ResolvedKey 快照索引中的单个公钥及其归属目录元信息。
type ResolvedKey struct {
	DirectoryID    string
	Slug           string
	Name           string
	Category       string
	SignatureAgent string // 原始 SignatureAgent
	normAgent      string // 归一化 SignatureAgent
	Key            httpsig.Key
}

// DirectorySnapshot 不可变目录快照（经 atomic.Pointer 原子替换，热路径无锁读）。
type DirectorySnapshot struct {
	ByKeyID   map[string][]ResolvedKey
	UpdatedAt time.Time
}

// DirectoryStoreOptions 目录存储装配选项。
type DirectoryStoreOptions struct {
	Fetcher         *Fetcher
	RefreshInterval time.Duration
	OnWarn          func(msg string, err error)
}

// DirectoryStore 持有静态发布目录与可选后台刷新的不可变原子快照。
type DirectoryStore struct {
	staticSpecs []DirectorySpec
	fetcher     *Fetcher
	interval    time.Duration
	onWarn      func(msg string, err error)

	snap atomic.Pointer[DirectorySnapshot]

	mu         sync.Mutex
	remoteKeys map[string][]KeySpec // dirKey -> 远端刷新获取到的密钥
	started    bool
	wg         sync.WaitGroup
}

// NewDirectoryStore 由发布下发的静态目录构造不可变快照。
func NewDirectoryStore(specs []DirectorySpec, opts DirectoryStoreOptions) (*DirectoryStore, error) {
	cp := make([]DirectorySpec, len(specs))
	for i, s := range specs {
		sc := s
		sc.Keys = append([]KeySpec(nil), s.Keys...)
		cp[i] = sc
	}
	fetcher := opts.Fetcher
	if fetcher == nil {
		fetcher = NewFetcher(FetcherConfig{})
	}
	interval := opts.RefreshInterval
	if interval <= 0 {
		interval = DefaultRefreshInterval
	}
	ds := &DirectoryStore{
		staticSpecs: cp,
		fetcher:     fetcher,
		interval:    interval,
		onWarn:      opts.OnWarn,
		remoteKeys:  make(map[string][]KeySpec),
	}
	ds.snap.Store(ds.buildSnapshotLocked(time.Now().UTC()))
	return ds, nil
}

// Lookup 在当前不可变快照中按 (keyID, signatureAgent) 查找匹配公钥（零锁、零网络 IO）。
func (ds *DirectoryStore) Lookup(keyID, signatureAgent string) (ResolvedKey, bool) {
	if ds == nil || keyID == "" {
		return ResolvedKey{}, false
	}
	snap := ds.snap.Load()
	if snap == nil {
		return ResolvedKey{}, false
	}
	candidates := snap.ByKeyID[keyID]
	if len(candidates) == 0 {
		return ResolvedKey{}, false
	}
	normReq := httpsig.NormalizeSignatureAgent(signatureAgent)
	if normReq != "" {
		// 1. 优先精确匹配 Signature-Agent。
		for _, c := range candidates {
			if c.normAgent != "" && c.normAgent == normReq {
				return c, true
			}
		}
		// 2. 允许未绑定特定 signature_agent 的通用目录兜底；拒绝与另一目录 agent 冲突的密钥。
		for _, c := range candidates {
			if c.normAgent == "" {
				return c, true
			}
		}
		return ResolvedKey{}, false
	}
	return candidates[0], true
}

// LookupKey 适配 httpsig.WebBotAuthKeyLookup 回调签名。
func (ds *DirectoryStore) LookupKey(keyID, signatureAgent string) (httpsig.Key, bool) {
	rk, ok := ds.Lookup(keyID, signatureAgent)
	if !ok {
		return httpsig.Key{}, false
	}
	return rk.Key, true
}

// HasRemoteDirectories 是否存在配置了 directory_url 的目录。
func (ds *DirectoryStore) HasRemoteDirectories() bool {
	if ds == nil {
		return false
	}
	for _, s := range ds.staticSpecs {
		if strings.TrimSpace(s.DirectoryURL) != "" {
			return true
		}
	}
	return false
}

// StartBackgroundRefresh 若存在非空 directory_url，启动后台周期刷新协程；
// 离线环境（无 directory_url）立即返回不启动任何协程。ctx 取消时退出。
func (ds *DirectoryStore) StartBackgroundRefresh(ctx context.Context) {
	if ds == nil || !ds.HasRemoteDirectories() {
		return
	}
	ds.mu.Lock()
	if ds.started {
		ds.mu.Unlock()
		return
	}
	ds.started = true
	ds.wg.Add(1)
	ds.mu.Unlock()

	go func() {
		defer ds.wg.Done()
		_ = ds.RefreshOnce(ctx)
		ticker := time.NewTicker(ds.interval)
		defer ticker.Stop()
		for {
			select {
			case <-ctx.Done():
				return
			case <-ticker.C:
				_ = ds.RefreshOnce(ctx)
			}
		}
	}()
}

// WaitBackgroundRefresh 等待后台刷新协程退出（供 Cleanup/测试确保零 goroutine 泄漏）。
func (ds *DirectoryStore) WaitBackgroundRefresh() {
	if ds == nil {
		return
	}
	ds.wg.Wait()
}

// RefreshOnce 同步刷新所有配置了 directory_url 的目录并原子替换快照。
// 单个目录失败仅记告警并保留其静态密钥与上次成功快照（优雅降级）。
func (ds *DirectoryStore) RefreshOnce(ctx context.Context) error {
	if ds == nil || !ds.HasRemoteDirectories() {
		return nil
	}
	var errs []error
	updated := false
	for _, spec := range ds.staticSpecs {
		rawURL := strings.TrimSpace(spec.DirectoryURL)
		if rawURL == "" {
			continue
		}
		if ctx.Err() != nil {
			return ctx.Err()
		}
		body, err := ds.fetcher.Fetch(ctx, rawURL)
		if err != nil {
			if ds.onWarn != nil {
				ds.onWarn("aicrawl directory background refresh failed", err)
			}
			errs = append(errs, err)
			continue
		}
		keys, err := ParseDirectoryJWKS(body)
		if err != nil {
			if ds.onWarn != nil {
				ds.onWarn("aicrawl directory JWKS parse failed", err)
			}
			errs = append(errs, err)
			continue
		}
		ds.mu.Lock()
		ds.remoteKeys[directoryKey(spec)] = keys
		ds.mu.Unlock()
		updated = true
	}
	if updated {
		ds.mu.Lock()
		snap := ds.buildSnapshotLocked(time.Now().UTC())
		ds.mu.Unlock()
		ds.snap.Store(snap)
	}
	return errors.Join(errs...)
}

func directoryKey(s DirectorySpec) string {
	if s.ID != "" {
		return s.ID
	}
	return s.Slug
}

func (ds *DirectoryStore) buildSnapshotLocked(now time.Time) *DirectorySnapshot {
	byKid := make(map[string][]ResolvedKey)
	appendKey := func(spec DirectorySpec, k KeySpec) {
		alg := strings.ToLower(strings.TrimSpace(k.Alg))
		if k.Kid == "" || (alg != httpsig.AlgEd25519 && alg != httpsig.AlgECDSAP256SHA256) {
			return
		}
		rk := ResolvedKey{
			DirectoryID:    spec.ID,
			Slug:           spec.Slug,
			Name:           spec.Name,
			Category:       spec.Category,
			SignatureAgent: spec.SignatureAgent,
			normAgent:      httpsig.NormalizeSignatureAgent(spec.SignatureAgent),
			Key: httpsig.Key{
				Kid:          k.Kid,
				Alg:          alg,
				PublicKeyPEM: []byte(k.PublicKeyPEM),
			},
		}
		byKid[k.Kid] = append(byKid[k.Kid], rk)
	}
	for _, spec := range ds.staticSpecs {
		seenKid := make(map[string]bool, len(spec.Keys))
		for _, k := range spec.Keys {
			appendKey(spec, k)
			seenKid[k.Kid] = true
		}
		for _, rk := range ds.remoteKeys[directoryKey(spec)] {
			if seenKid[rk.Kid] {
				continue
			}
			appendKey(spec, rk)
			seenKid[rk.Kid] = true
		}
	}
	return &DirectorySnapshot{
		ByKeyID:   byKid,
		UpdatedAt: now,
	}
}

type directoryJWKS struct {
	Keys []directoryJWK `json:"keys"`
}

type directoryJWK struct {
	Kty string `json:"kty"`
	Crv string `json:"crv"`
	Kid string `json:"kid"`
	Alg string `json:"alg"`
	X   string `json:"x"`
	Y   string `json:"y"`
	D   string `json:"d"` // 禁止公钥目录包含私钥/对称密钥材料
	P   string `json:"p"`
	Q   string `json:"q"`
	DP  string `json:"dp"`
	DQ  string `json:"dq"`
	QI  string `json:"qi"`
	K   string `json:"k"`
}

// ParseDirectoryJWKS 解析 RFC 9421 /.well-known/http-message-signatures-directory JWKS 响应，
// 仅接受 Ed25519（OKP/Ed25519）与 ECDSA P-256（EC/P-256）公钥，拒绝含私钥/对称密钥参数的条目。
func ParseDirectoryJWKS(raw []byte) ([]KeySpec, error) {
	var set directoryJWKS
	if err := json.Unmarshal(raw, &set); err != nil {
		return nil, fmt.Errorf("invalid JWKS JSON: %w", err)
	}
	if len(set.Keys) == 0 {
		return nil, errors.New("JWKS contains no keys")
	}
	if len(set.Keys) > maxKeysPerDir {
		return nil, fmt.Errorf("JWKS exceeds max %d keys", maxKeysPerDir)
	}
	out := make([]KeySpec, 0, len(set.Keys))
	for _, k := range set.Keys {
		if k.D != "" || k.P != "" || k.Q != "" || k.DP != "" || k.DQ != "" || k.QI != "" || k.K != "" || strings.EqualFold(k.Kty, "oct") {
			return nil, errors.New("directory JWK must not contain private or symmetric key material")
		}
		switch {
		case k.Kty == "OKP" && k.Crv == "Ed25519":
			xb, err := base64.RawURLEncoding.DecodeString(k.X)
			if err != nil || len(xb) != ed25519.PublicKeySize {
				continue
			}
			pub := ed25519.PublicKey(xb)
			pemBytes, err := marshalPublicKeyPEM(pub)
			if err != nil {
				continue
			}
			kid := strings.TrimSpace(k.Kid)
			thumb := jwkThumbprintOKP(k.Crv, k.X)
			if kid == "" {
				kid = thumb
			}
			out = append(out, KeySpec{Kid: kid, Alg: httpsig.AlgEd25519, PublicKeyPEM: string(pemBytes)})
			if thumb != "" && thumb != kid {
				out = append(out, KeySpec{Kid: thumb, Alg: httpsig.AlgEd25519, PublicKeyPEM: string(pemBytes)})
			}
		case k.Kty == "EC" && k.Crv == "P-256":
			xb, err1 := base64.RawURLEncoding.DecodeString(k.X)
			yb, err2 := base64.RawURLEncoding.DecodeString(k.Y)
			if err1 != nil || err2 != nil || len(xb) == 0 || len(yb) == 0 || len(xb) > 32 || len(yb) > 32 {
				continue
			}
			xInt := new(big.Int).SetBytes(xb)
			yInt := new(big.Int).SetBytes(yb)
			if !elliptic.P256().IsOnCurve(xInt, yInt) {
				continue
			}
			pub := &ecdsa.PublicKey{Curve: elliptic.P256(), X: xInt, Y: yInt}
			pemBytes, err := marshalPublicKeyPEM(pub)
			if err != nil {
				continue
			}
			kid := strings.TrimSpace(k.Kid)
			thumb := jwkThumbprintEC(k.Crv, k.X, k.Y)
			if kid == "" {
				kid = thumb
			}
			out = append(out, KeySpec{Kid: kid, Alg: httpsig.AlgECDSAP256SHA256, PublicKeyPEM: string(pemBytes)})
			if thumb != "" && thumb != kid {
				out = append(out, KeySpec{Kid: thumb, Alg: httpsig.AlgECDSAP256SHA256, PublicKeyPEM: string(pemBytes)})
			}
		}
	}
	if len(out) == 0 {
		return nil, errors.New("JWKS contains no supported Ed25519/P-256 keys")
	}
	return out, nil
}

func marshalPublicKeyPEM(pub any) ([]byte, error) {
	der, err := x509.MarshalPKIXPublicKey(pub)
	if err != nil {
		return nil, err
	}
	return pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: der}), nil
}

// RFC 7638 JWK Thumbprint（规范字典序 JSON 的 SHA-256 base64url）。
func jwkThumbprintOKP(crv, x string) string {
	canonical := fmt.Sprintf(`{"crv":%q,"kty":"OKP","x":%q}`, crv, x)
	sum := sha256.Sum256([]byte(canonical))
	return base64.RawURLEncoding.EncodeToString(sum[:])
}

func jwkThumbprintEC(crv, x, y string) string {
	canonical := fmt.Sprintf(`{"crv":%q,"kty":"EC","x":%q,"y":%q}`, crv, x, y)
	sum := sha256.Sum256([]byte(canonical))
	return base64.RawURLEncoding.EncodeToString(sum[:])
}

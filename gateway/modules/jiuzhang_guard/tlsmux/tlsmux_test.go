package tlsmux

import (
	"bufio"
	"context"
	"crypto/rand"
	"crypto/rsa"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"io"
	"math/big"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"gitee.com/Trisia/gotlcp/tlcp"
	"github.com/caddyserver/caddy/v2"
	"github.com/emmansun/gmsm/sm2"
	"github.com/emmansun/gmsm/smx509"
	"golang.org/x/net/http2"
)

// ---------- 测试证书工厂 ----------

func makeTestRSACert(t *testing.T, cn string, sans []string) (certPEM, keyPEM string) {
	t.Helper()
	priv, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("rsa.GenerateKey: %v", err)
	}
	now := time.Now()
	tmpl := &x509.Certificate{
		SerialNumber:          big.NewInt(10001),
		Subject:               pkix.Name{CommonName: cn, Organization: []string{"JiuZhang Intl Test"}},
		NotBefore:             now.Add(-time.Hour),
		NotAfter:              now.Add(24 * time.Hour),
		KeyUsage:              x509.KeyUsageDigitalSignature | x509.KeyUsageKeyEncipherment,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		BasicConstraintsValid: true,
		DNSNames:              sans,
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &priv.PublicKey, priv)
	if err != nil {
		t.Fatalf("x509.CreateCertificate: %v", err)
	}
	certPEM = string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}))
	keyPEM = string(pem.EncodeToMemory(&pem.Block{Type: "RSA PRIVATE KEY", Bytes: x509.MarshalPKCS1PrivateKey(priv)}))
	return certPEM, keyPEM
}

func makeTestGMCAAndDualCert(t *testing.T, cn string, sans []string) (caPEM, signCertPEM, signKeyPEM, encCertPEM, encKeyPEM string) {
	t.Helper()
	now := time.Now()
	caPriv, err := sm2.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("sm2.GenerateKey CA: %v", err)
	}
	caTmpl := &smx509.Certificate{
		SerialNumber:          big.NewInt(1),
		Subject:               pkix.Name{CommonName: "JiuZhang Test SM2 Root CA"},
		NotBefore:             now.Add(-time.Hour),
		NotAfter:              now.Add(48 * time.Hour),
		KeyUsage:              smx509.KeyUsageCertSign | smx509.KeyUsageCRLSign,
		BasicConstraintsValid: true,
		IsCA:                  true,
	}
	caDER, err := smx509.CreateCertificate(rand.Reader, caTmpl, caTmpl, &caPriv.PublicKey, caPriv)
	if err != nil {
		t.Fatalf("create SM2 CA: %v", err)
	}
	caCert, err := smx509.ParseCertificate(caDER)
	if err != nil {
		t.Fatalf("parse SM2 CA: %v", err)
	}
	caPEM = string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: caDER}))

	issueLeaf := func(serial int64, usage smx509.KeyUsage) (string, string) {
		priv, err := sm2.GenerateKey(rand.Reader)
		if err != nil {
			t.Fatalf("sm2.GenerateKey leaf: %v", err)
		}
		tmpl := &smx509.Certificate{
			SerialNumber:          big.NewInt(serial),
			Subject:               pkix.Name{CommonName: cn, Organization: []string{"JiuZhang GM Test"}},
			NotBefore:             now.Add(-time.Hour),
			NotAfter:              now.Add(24 * time.Hour),
			KeyUsage:              usage,
			ExtKeyUsage:           []smx509.ExtKeyUsage{smx509.ExtKeyUsageServerAuth},
			BasicConstraintsValid: true,
			DNSNames:              sans,
		}
		der, err := smx509.CreateCertificate(rand.Reader, tmpl, caCert, &priv.PublicKey, caPriv)
		if err != nil {
			t.Fatalf("create SM2 leaf: %v", err)
		}
		keyDER, err := smx509.MarshalPKCS8PrivateKey(priv)
		if err != nil {
			t.Fatalf("marshal SM2 key: %v", err)
		}
		return string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})),
			string(pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: keyDER}))
	}

	signCertPEM, signKeyPEM = issueLeaf(101, smx509.KeyUsageDigitalSignature)
	encCertPEM, encKeyPEM = issueLeaf(102, smx509.KeyUsageKeyEncipherment|smx509.KeyUsageDataEncipherment)
	return caPEM, signCertPEM, signKeyPEM, encCertPEM, encKeyPEM
}

// buildSyntheticTLSClientHello 构造标准 TLS/SSLv3/TLCP ClientHello 二进制报文（用于协议解析单测与探测包）。
func buildSyntheticTLSClientHello(recVer, clientVer uint16, ciphers []uint16, sni string, alpn []string, supportedVersions []uint16) []byte {
	var exts []byte
	if sni != "" {
		// SNI extension (0x0000)
		nameBytes := []byte(sni)
		entry := make([]byte, 3+len(nameBytes))
		entry[0] = 0x00
		binary.BigEndian.PutUint16(entry[1:3], uint16(len(nameBytes)))
		copy(entry[3:], nameBytes)
		list := make([]byte, 2+len(entry))
		binary.BigEndian.PutUint16(list[0:2], uint16(len(entry)))
		copy(list[2:], entry)
		exts = appendExt(exts, 0x0000, list)
	}
	if len(alpn) > 0 {
		var list []byte
		for _, p := range alpn {
			list = append(list, byte(len(p)))
			list = append(list, []byte(p)...)
		}
		data := make([]byte, 2+len(list))
		binary.BigEndian.PutUint16(data[0:2], uint16(len(list)))
		copy(data[2:], list)
		exts = appendExt(exts, 0x0010, data)
	}
	if len(supportedVersions) > 0 {
		data := make([]byte, 1+len(supportedVersions)*2)
		data[0] = byte(len(supportedVersions) * 2)
		for i, v := range supportedVersions {
			binary.BigEndian.PutUint16(data[1+i*2:3+i*2], v)
		}
		exts = appendExt(exts, 0x002b, data)
	}
	// SupportedGroups + ECPointFormats（用于验证 JA3 完整五段）
	exts = appendExt(exts, 0x000a, []byte{0x00, 0x04, 0x0a, 0x0a, 0x00, 0x1d}) // GREASE + x25519
	exts = appendExt(exts, 0x000b, []byte{0x01, 0x00})

	var body []byte
	verBuf := make([]byte, 2)
	binary.BigEndian.PutUint16(verBuf, clientVer)
	body = append(body, verBuf...)
	body = append(body, make([]byte, 32)...) // random
	body = append(body, 0x00)                // session_id len=0
	csLen := make([]byte, 2)
	binary.BigEndian.PutUint16(csLen, uint16(len(ciphers)*2))
	body = append(body, csLen...)
	for _, c := range ciphers {
		cb := make([]byte, 2)
		binary.BigEndian.PutUint16(cb, c)
		body = append(body, cb...)
	}
	body = append(body, 0x01, 0x00) // compression: null
	if len(exts) > 0 {
		el := make([]byte, 2)
		binary.BigEndian.PutUint16(el, uint16(len(exts)))
		body = append(body, el...)
		body = append(body, exts...)
	}

	hs := make([]byte, 4+len(body))
	hs[0] = 0x01 // ClientHello
	hs[1] = byte(len(body) >> 16)
	hs[2] = byte(len(body) >> 8)
	hs[3] = byte(len(body))
	copy(hs[4:], body)

	rec := make([]byte, 5+len(hs))
	rec[0] = 0x16 // Handshake
	binary.BigEndian.PutUint16(rec[1:3], recVer)
	binary.BigEndian.PutUint16(rec[3:5], uint16(len(hs)))
	copy(rec[5:], hs)
	return rec
}

func appendExt(dst []byte, extType uint16, data []byte) []byte {
	hdr := make([]byte, 4)
	binary.BigEndian.PutUint16(hdr[0:2], extType)
	binary.BigEndian.PutUint16(hdr[2:4], uint16(len(data)))
	dst = append(dst, hdr...)
	return append(dst, data...)
}

// buildSyntheticSSLv2ClientHello 构造 SSLv2（0x0002）或 SSLv2/v3 兼容头（0x0300/0x0301）ClientHello 报文。
func buildSyntheticSSLv2ClientHello(ver uint16) []byte {
	// [2 len with MSB=1][1 msg_type=0x01][2 ver][2 cs_len=3][2 sid_len=0][2 chal_len=16][3 cipher][16 challenge]
	bodyLen := 1 + 2 + 2 + 2 + 2 + 3 + 16
	raw := make([]byte, 2+bodyLen)
	raw[0] = 0x80 | byte((bodyLen>>8)&0x7f)
	raw[1] = byte(bodyLen & 0xff)
	raw[2] = 0x01 // CLIENT-HELLO
	binary.BigEndian.PutUint16(raw[3:5], ver)
	binary.BigEndian.PutUint16(raw[5:7], 3)  // cipher specs len
	binary.BigEndian.PutUint16(raw[7:9], 0)  // session id len
	binary.BigEndian.PutUint16(raw[9:11], 16) // challenge len
	raw[11], raw[12], raw[13] = 0x00, 0x00, 0x2f
	return raw
}

// ---------- 1. ClientHello 全协议解析矩阵单测 ----------

func TestParseClientHelloAllProtocolsAndJA3(t *testing.T) {
	cases := []struct {
		name      string
		raw       []byte
		wantProto string
		wantGM    bool
		wantLeg   bool
		wantSNI   string
	}{
		{
			name:      "SSLv2",
			raw:       buildSyntheticSSLv2ClientHello(VersionSSLv2),
			wantProto: ProtoSSLv2,
			wantLeg:   true,
		},
		{
			name:      "SSLv2_v3_compat",
			raw:       buildSyntheticSSLv2ClientHello(VersionSSLv3),
			wantProto: ProtoSSLv2v3,
			wantLeg:   true,
		},
		{
			name:      "SSLv3",
			raw:       buildSyntheticTLSClientHello(VersionSSLv3, VersionSSLv3, []uint16{0x002f}, "legacy.example.com", nil, nil),
			wantProto: ProtoSSLv3,
			wantLeg:   true,
			wantSNI:   "legacy.example.com",
		},
		{
			name:      "TLS1.0",
			raw:       buildSyntheticTLSClientHello(VersionTLS10, VersionTLS10, []uint16{tls.TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA}, "tls10.example.com", nil, nil),
			wantProto: ProtoTLS10,
			wantSNI:   "tls10.example.com",
		},
		{
			name:      "TLS1.1",
			raw:       buildSyntheticTLSClientHello(VersionTLS10, VersionTLS11, []uint16{tls.TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA}, "tls11.example.com", nil, nil),
			wantProto: ProtoTLS11,
			wantSNI:   "tls11.example.com",
		},
		{
			name:      "TLS1.2",
			raw:       buildSyntheticTLSClientHello(VersionTLS10, VersionTLS12, []uint16{tls.TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256}, "tls12.example.com", []string{"http/1.1"}, nil),
			wantProto: ProtoTLS12,
			wantSNI:   "tls12.example.com",
		},
		{
			name:      "TLS1.3_with_GREASE",
			raw:       buildSyntheticTLSClientHello(VersionTLS10, VersionTLS12, []uint16{0x1a1a, tls.TLS_AES_128_GCM_SHA256}, "tls13.example.com", []string{"h2", "http/1.1"}, []uint16{0x2a2a, VersionTLS13, VersionTLS12}),
			wantProto: ProtoTLS13,
			wantSNI:   "tls13.example.com",
		},
		{
			name:      "TLCP1.1_SM2_SM4_SM3",
			raw:       buildSyntheticTLSClientHello(VersionTLCP11, VersionTLCP11, []uint16{0xe053, 0xe013}, "gm.example.com", nil, nil),
			wantProto: ProtoTLCP11,
			wantGM:    true,
			wantSNI:   "gm.example.com",
		},
		{
			name:      "Plaintext_HTTP_Unknown",
			raw:       []byte("GET / HTTP/1.1\r\nHost: x\r\n\r\n"),
			wantProto: ProtoUnknown,
		},
		{
			name:      "Truncated_Safe_NoPanic",
			raw:       []byte{0x16, 0x03, 0x01, 0x00, 0x50, 0x01, 0x00},
			wantProto: ProtoTLS10,
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			info := ParseClientHello(tc.raw)
			if info.DetectedProtocol != tc.wantProto {
				t.Errorf("DetectedProtocol = %q, want %q", info.DetectedProtocol, tc.wantProto)
			}
			if info.IsGM != tc.wantGM {
				t.Errorf("IsGM = %v, want %v", info.IsGM, tc.wantGM)
			}
			if info.IsLegacySSL != tc.wantLeg {
				t.Errorf("IsLegacySSL = %v, want %v", info.IsLegacySSL, tc.wantLeg)
			}
			if tc.wantSNI != "" && info.SNI != tc.wantSNI {
				t.Errorf("SNI = %q, want %q", info.SNI, tc.wantSNI)
			}
			if tc.wantProto != ProtoUnknown && tc.name != "Truncated_Safe_NoPanic" && len(info.JA3Hash) != 32 {
				t.Errorf("JA3Hash = %q, want 32-char md5 hex", info.JA3Hash)
			}
			// 确认 GREASE 已被 JA3 过滤
			if tc.name == "TLS1.3_with_GREASE" && strings.Contains(info.JA3String, "6682") {
				t.Errorf("GREASE value 0x1a1a (6682) leaked into JA3String: %s", info.JA3String)
			}
		})
	}
}

// ---------- 2. 同端口国密+国际双证自识别、协议降级与弱协议分析阻断真实 TCP 端到端测试 ----------

func TestListenerMuxDualProtocolAutoDetectDowngradeAndLegacySSL(t *testing.T) {
	intlCert, intlKey := makeTestRSACert(t, "dual.example.com", []string{"dual.example.com"})
	gmCA, gmSignCert, gmSignKey, gmEncCert, gmEncKey := makeTestGMCAAndDualCert(t, "dual.example.com", []string{"dual.example.com"})
	h1OnlyCert, h1OnlyKey := makeTestRSACert(t, "h1only.example.com", []string{"h1only.example.com"})

	sessionLogFile := filepath.Join(t.TempDir(), "tls-handshake-events.jsonl")
	ticketKeyHex := hex.EncodeToString(make([]byte, 32))

	mux := &ListenerMux{
		GatewayNode:          "gw-test-01",
		SessionLogPath:       sessionLogFile,
		HandshakeTimeout:     "5s",
		SessionTicketKeysHex: []string{ticketKeyHex},
		Sites: []SiteConfig{
			{
				AppID:              "app-dual",
				Domains:            []string{"dual.example.com"},
				TLSProtocolMode:    ModeAutoDetect,
				AllowedTLSVersions: []string{ProtoTLCP11, ProtoTLS10, ProtoTLS11, ProtoTLS12, ProtoTLS13},
				HTTPVersions:       []string{"HTTP/1.0", "HTTP/1.1", "HTTP/2"},
				CertID:             "cert-intl-1",
				CertPEM:            intlCert,
				KeyPEM:             intlKey,
				GMCertID:           "cert-gm-1",
				GMSignCertPEM:      gmSignCert,
				GMSignKeyPEM:       gmSignKey,
				GMEncCertPEM:       gmEncCert,
				GMEncKeyPEM:        gmEncKey,
			},
			{
				// 站点 2：仅允许 TLS 1.2+ 且显式降级禁用 HTTP/2（仅 HTTP/1.1）
				AppID:              "app-h1only",
				Domains:            []string{"h1only.example.com"},
				TLSProtocolMode:    ModeInternationalOnly,
				AllowedTLSVersions: []string{ProtoTLS12, ProtoTLS13},
				HTTPVersions:       []string{"HTTP/1.0", "HTTP/1.1"},
				CertID:             "cert-h1only",
				CertPEM:            h1OnlyCert,
				KeyPEM:             h1OnlyKey,
			},
		},
	}

	if err := mux.Provision(caddy.Context{}); err != nil {
		t.Fatalf("mux.Provision: %v", err)
	}
	defer func() { _ = mux.Cleanup() }()

	rawLn, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	wrappedLn := mux.WrapListener(rawLn)

	srv := &http.Server{
		Handler: http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			var localAddr net.Addr
			if v := r.Context().Value(http.LocalAddrContextKey); v != nil {
				localAddr, _ = v.(net.Addr)
			}
			meta := LookupConnMeta(r.RemoteAddr, localAddr)
			proto := ""
			isGM := "false"
			if meta != nil {
				proto = meta.NegotiatedProtocol
				if meta.IsGM {
					isGM = "true"
				}
			}
			w.Header().Set("X-Observed-TLS", proto)
			w.Header().Set("X-Observed-GM", isGM)
			w.Header().Set("X-Observed-HTTP", r.Proto)
			w.WriteHeader(http.StatusOK)
			_, _ = w.Write([]byte("ok"))
		}),
	}
	if err := http2.ConfigureServer(srv, &http2.Server{}); err != nil {
		t.Fatalf("http2.ConfigureServer: %v", err)
	}
	go func() { _ = srv.Serve(wrappedLn) }()
	defer srv.Close()

	addr := rawLn.Addr().String()

	// 场景 A：国密 TLCP 1.1 客户端（带 SM2 RootCA 严格校验证书）访问 dual.example.com
	t.Run("GM_TLCP11_AutoDetect", func(t *testing.T) {
		pool := smx509.NewCertPool()
		if !pool.AppendCertsFromPEM([]byte(gmCA)) {
			t.Fatal("append SM2 CA failed")
		}
		tr := &http.Transport{
			DisableKeepAlives: true,
			DialTLSContext: func(ctx context.Context, network, _ string) (net.Conn, error) {
				raw, err := net.DialTimeout(network, addr, 3*time.Second)
				if err != nil {
					return nil, err
				}
				tc := tlcp.Client(raw, &tlcp.Config{
					ServerName: "dual.example.com",
					RootCAs:    pool,
				})
				if err := tc.HandshakeContext(ctx); err != nil {
					_ = raw.Close()
					return nil, err
				}
				return tc, nil
			},
		}
		resp, err := (&http.Client{Transport: tr, Timeout: 5 * time.Second}).Get("https://dual.example.com/gm")
		if err != nil {
			t.Fatalf("GM TLCP request failed: %v", err)
		}
		defer resp.Body.Close()
		if resp.StatusCode != http.StatusOK || resp.Header.Get("X-Observed-TLS") != ProtoTLCP11 || resp.Header.Get("X-Observed-GM") != "true" {
			t.Fatalf("unexpected GM response: status=%d tls=%q gm=%q", resp.StatusCode, resp.Header.Get("X-Observed-TLS"), resp.Header.Get("X-Observed-GM"))
		}
	})

	// 场景 B：同一端口发国际 TLS 1.3 + HTTP/2 请求（验证裸 *tls.Conn 原生支持 h2）
	t.Run("Intl_TLS13_HTTP2_AutoDetect", func(t *testing.T) {
		tr := &http.Transport{
			DisableKeepAlives: true,
			ForceAttemptHTTP2: true,
			DialContext: func(ctx context.Context, network, _ string) (net.Conn, error) {
				return net.DialTimeout(network, addr, 3*time.Second)
			},
			TLSClientConfig: &tls.Config{
				ServerName:         "dual.example.com",
				InsecureSkipVerify: true,
				MinVersion:         tls.VersionTLS13,
				MaxVersion:         tls.VersionTLS13,
			},
		}
		resp, err := (&http.Client{Transport: tr, Timeout: 5 * time.Second}).Get("https://dual.example.com/h2")
		if err != nil {
			t.Fatalf("TLS 1.3 HTTP/2 request failed: %v", err)
		}
		defer resp.Body.Close()
		if resp.Proto != "HTTP/2.0" || resp.Header.Get("X-Observed-TLS") != ProtoTLS13 || resp.Header.Get("X-Observed-GM") != "false" {
			t.Fatalf("unexpected TLS1.3/h2 response: proto=%q tls=%q gm=%q", resp.Proto, resp.Header.Get("X-Observed-TLS"), resp.Header.Get("X-Observed-GM"))
		}
	})

	// 场景 C：同一端口发 TLS 1.0 降级请求（dual.example.com 允许 TLS 1.0，应真实解密成功）
	t.Run("Intl_TLS10_Downgrade_Allowed", func(t *testing.T) {
		tr := &http.Transport{
			DisableKeepAlives: true,
			DialContext: func(ctx context.Context, network, _ string) (net.Conn, error) {
				return net.DialTimeout(network, addr, 3*time.Second)
			},
			TLSClientConfig: &tls.Config{
				ServerName:         "dual.example.com",
				InsecureSkipVerify: true,
				MinVersion:         tls.VersionTLS10,
				MaxVersion:         tls.VersionTLS10,
				CipherSuites:       legacyCompatibleCipherSuites(),
			},
		}
		resp, err := (&http.Client{Transport: tr, Timeout: 5 * time.Second}).Get("https://dual.example.com/tls10")
		if err != nil {
			t.Fatalf("TLS 1.0 request failed: %v", err)
		}
		defer resp.Body.Close()
		if resp.Header.Get("X-Observed-TLS") != ProtoTLS10 {
			t.Fatalf("observed TLS = %q, want TLS1.0", resp.Header.Get("X-Observed-TLS"))
		}
	})

	// 场景 D：站点 2 仅允许 TLS 1.2+ 且禁用 HTTP/2（客户端请求 h2 应降级为 HTTP/1.1；请求 TLS 1.0 应拒绝）
	t.Run("Site2_HTTP2_Downgraded_To_HTTP11_And_TLS10_Rejected", func(t *testing.T) {
		tr := &http.Transport{
			DisableKeepAlives: true,
			ForceAttemptHTTP2: true,
			DialContext: func(ctx context.Context, network, _ string) (net.Conn, error) {
				return net.DialTimeout(network, addr, 3*time.Second)
			},
			TLSClientConfig: &tls.Config{
				ServerName:         "h1only.example.com",
				InsecureSkipVerify: true,
				MinVersion:         tls.VersionTLS12,
			},
		}
		resp, err := (&http.Client{Transport: tr, Timeout: 5 * time.Second}).Get("https://h1only.example.com/downgrade")
		if err != nil {
			t.Fatalf("h1only request failed: %v", err)
		}
		defer resp.Body.Close()
		if resp.Proto != "HTTP/1.1" {
			t.Fatalf("expected HTTP/2 downgraded to HTTP/1.1, got %q", resp.Proto)
		}

		// TLS 1.0 访问仅允许 TLS1.2+ 的站点 2 必须失败
		tr10 := &http.Transport{
			DisableKeepAlives: true,
			DialContext: func(ctx context.Context, network, _ string) (net.Conn, error) {
				return net.DialTimeout(network, addr, 3*time.Second)
			},
			TLSClientConfig: &tls.Config{
				ServerName:         "h1only.example.com",
				InsecureSkipVerify: true,
				MinVersion:         tls.VersionTLS10,
				MaxVersion:         tls.VersionTLS10,
				CipherSuites:       legacyCompatibleCipherSuites(),
			},
		}
		if _, err := (&http.Client{Transport: tr10, Timeout: 3 * time.Second}).Get("https://h1only.example.com/reject"); err == nil {
			t.Fatal("TLS 1.0 should be rejected on TLS1.2+-only site")
		}
	})

	// 场景 E：发送 SSLv2、SSLv2/v3、SSLv3 握手探测包，验证均收到 TLS Alert 拦截并写入会话分析日志
	t.Run("LegacySSL_Probes_Analyzed_And_Blocked", func(t *testing.T) {
		probes := [][]byte{
			buildSyntheticSSLv2ClientHello(VersionSSLv2),
			buildSyntheticSSLv2ClientHello(VersionSSLv3),
			buildSyntheticTLSClientHello(VersionSSLv3, VersionSSLv3, []uint16{0x002f}, "dual.example.com", nil, nil),
		}
		for _, pkt := range probes {
			c, err := net.DialTimeout("tcp", addr, 3*time.Second)
			if err != nil {
				t.Fatalf("dial probe: %v", err)
			}
			_, _ = c.Write(pkt)
			_ = c.SetReadDeadline(time.Now().Add(2 * time.Second))
			alertBuf := make([]byte, 7)
			n, _ := io.ReadFull(c, alertBuf)
			_ = c.Close()
			if n < 7 || alertBuf[0] != 0x15 || alertBuf[5] != 0x02 || alertBuf[6] != alertProtocolVersion {
				t.Errorf("expected fatal protocol_version TLS alert, got n=%d bytes=%x", n, alertBuf[:n])
			}
		}
	})

	// 校验会话分析 JSONL 日志已完整覆盖全部场景（等待异步关闭写完）
	time.Sleep(100 * time.Millisecond)
	rawLog, err := os.ReadFile(sessionLogFile)
	if err != nil {
		t.Fatalf("read session log: %v", err)
	}
	seen := map[string]bool{}
	scanner := bufio.NewScanner(strings.NewReader(string(rawLog)))
	for scanner.Scan() {
		var ev HandshakeEvent
		if err := json.Unmarshal(scanner.Bytes(), &ev); err != nil {
			t.Fatalf("invalid session event json: %v", err)
		}
		seen[ev.DetectedProtocol+":"+ev.Action] = true
	}
	for _, want := range []string{
		ProtoTLCP11 + ":" + ActionAllowed,
		ProtoTLS13 + ":" + ActionAllowed,
		ProtoTLS10 + ":" + ActionAllowed,
		ProtoSSLv2 + ":" + ActionBlockedLegacySSL,
		ProtoSSLv2v3 + ":" + ActionBlockedLegacySSL,
		ProtoSSLv3 + ":" + ActionBlockedLegacySSL,
	} {
		if !seen[want] {
			t.Errorf("session log missing expected event %q; got keys: %v", want, seen)
		}
	}
}

// ---------- 3. 回源传输模块（国密 TLCP 回源 + 国际 TLS 1.0 降级回源 + HTTP/1.0 降级回源） ----------

func TestUpstreamTransportTLCPAndProtocolDowngrade(t *testing.T) {
	gmCA, gmSignCert, gmSignKey, gmEncCert, gmEncKey := makeTestGMCAAndDualCert(t, "origin-gm.example.com", []string{"origin-gm.example.com"})
	signPair, err := tlcp.X509KeyPair([]byte(gmSignCert), []byte(gmSignKey))
	if err != nil {
		t.Fatalf("sign pair: %v", err)
	}
	encPair, err := tlcp.X509KeyPair([]byte(gmEncCert), []byte(gmEncKey))
	if err != nil {
		t.Fatalf("enc pair: %v", err)
	}

	// 启动真实国密 TLCP 1.1 源站
	rawGMLn, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen gm origin: %v", err)
	}
	defer rawGMLn.Close()
	gmOriginSrv := &http.Server{
		Handler: http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.Header().Set("X-Origin-Proto", r.Proto)
			w.WriteHeader(http.StatusOK)
			_, _ = w.Write([]byte("gm-origin-ok"))
		}),
	}
	go func() {
		_ = gmOriginSrv.Serve(tlcp.NewListener(rawGMLn, &tlcp.Config{
			Certificates: []tlcp.Certificate{signPair, encPair},
		}))
	}()
	defer gmOriginSrv.Close()

	// 3.1 国密 TLCP 1.1 加密回源（使用 SM2 RootCA 严格校验证书）
	t.Run("TLCP_Origin_With_SM2_CA_Verify", func(t *testing.T) {
		tr := &UpstreamTransport{
			Mode:        UpstreamModeTLCP,
			ServerName:  "origin-gm.example.com",
			RootCAPEM:   gmCA,
			HTTPVersion: "HTTP/1.1",
		}
		if err := tr.Provision(caddy.Context{}); err != nil {
			t.Fatalf("Provision: %v", err)
		}
		defer func() { _ = tr.Cleanup() }()
		if !tr.TLSEnabled() {
			t.Fatal("TLCP transport must report TLSEnabled()=true")
		}
		req, _ := http.NewRequest(http.MethodGet, "https://"+rawGMLn.Addr().String()+"/api", nil)
		resp, err := tr.RoundTrip(req)
		if err != nil {
			t.Fatalf("TLCP RoundTrip failed: %v", err)
		}
		defer resp.Body.Close()
		if resp.StatusCode != http.StatusOK || resp.Header.Get("X-Origin-Proto") != "HTTP/1.1" {
			t.Fatalf("unexpected origin response: status=%d proto=%q", resp.StatusCode, resp.Header.Get("X-Origin-Proto"))
		}
	})

	// 3.2 国密 TLCP 回源 + HTTP/1.0 协议降级（验证源站真实收到 HTTP/1.0）
	t.Run("TLCP_Origin_HTTP10_Downgrade", func(t *testing.T) {
		tr := &UpstreamTransport{
			Mode:               UpstreamModeTLCP,
			ServerName:         "origin-gm.example.com",
			InsecureSkipVerify: true,
			HTTPVersion:        "HTTP/1.0",
		}
		if err := tr.Provision(caddy.Context{}); err != nil {
			t.Fatalf("Provision: %v", err)
		}
		defer func() { _ = tr.Cleanup() }()
		req, _ := http.NewRequest(http.MethodGet, "https://"+rawGMLn.Addr().String()+"/legacy10", nil)
		resp, err := tr.RoundTrip(req)
		if err != nil {
			t.Fatalf("TLCP HTTP/1.0 RoundTrip failed: %v", err)
		}
		defer resp.Body.Close()
		if resp.StatusCode != http.StatusOK || resp.Header.Get("X-Origin-Proto") != "HTTP/1.0" {
			t.Fatalf("expected origin to observe HTTP/1.0, got status=%d proto=%q", resp.StatusCode, resp.Header.Get("X-Origin-Proto"))
		}
	})

	// 3.3 国际 TLS 1.0 降级回源（连接仅支持 TLS 1.0 的老源站）
	t.Run("Intl_TLS10_Origin_Downgrade", func(t *testing.T) {
		certPEM, keyPEM := makeTestRSACert(t, "legacy-origin.example.com", []string{"legacy-origin.example.com"})
		pair, err := tls.X509KeyPair([]byte(certPEM), []byte(keyPEM))
		if err != nil {
			t.Fatalf("rsa pair: %v", err)
		}
		rawLn, err := net.Listen("tcp", "127.0.0.1:0")
		if err != nil {
			t.Fatalf("listen legacy origin: %v", err)
		}
		defer rawLn.Close()
		legacySrv := &http.Server{
			Handler: http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				if r.TLS != nil {
					w.Header().Set("X-Origin-TLS", ProtocolLabel(r.TLS.Version))
				}
				w.WriteHeader(http.StatusOK)
			}),
		}
		go func() {
			_ = legacySrv.Serve(tls.NewListener(rawLn, &tls.Config{
				Certificates: []tls.Certificate{pair},
				MinVersion:   tls.VersionTLS10,
				MaxVersion:   tls.VersionTLS10,
				CipherSuites: legacyCompatibleCipherSuites(),
			}))
		}()
		defer legacySrv.Close()

		tr := &UpstreamTransport{
			Mode:               UpstreamModeTLS,
			ServerName:         "legacy-origin.example.com",
			InsecureSkipVerify: true,
			TLSMinVersion:      ProtoTLS10,
			HTTPVersion:        "HTTP/1.1",
		}
		if err := tr.Provision(caddy.Context{}); err != nil {
			t.Fatalf("Provision: %v", err)
		}
		defer func() { _ = tr.Cleanup() }()
		req, _ := http.NewRequest(http.MethodGet, "https://"+rawLn.Addr().String()+"/tls10", nil)
		resp, err := tr.RoundTrip(req)
		if err != nil {
			t.Fatalf("TLS 1.0 upstream RoundTrip failed: %v", err)
		}
		defer resp.Body.Close()
		if resp.Header.Get("X-Origin-TLS") != ProtoTLS10 {
			t.Fatalf("origin observed TLS=%q, want TLS1.0", resp.Header.Get("X-Origin-TLS"))
		}
	})
}

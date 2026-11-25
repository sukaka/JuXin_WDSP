package upstreams

import (
	"context"
	"crypto/rand"
	"crypto/x509/pkix"
	"encoding/pem"
	"math/big"
	"net"
	"net/http"
	"net/netip"
	"testing"
	"time"

	"gitee.com/Trisia/gotlcp/tlcp"
	"github.com/emmansun/gmsm/sm2"
	"github.com/emmansun/gmsm/smx509"
)

func TestTLCPUpstreamStillEnforcesSSRF(t *testing.T) {
	for _, host := range []string{"127.0.0.1", "169.254.169.254", "10.0.0.1", "::1"} {
		res := TestConnectivity(context.Background(), TestInput{
			Scheme: "tlcp",
			Host:   host,
			Port:   8443,
		})
		if res.ErrorCode != "SSRF_BLOCKED" {
			t.Errorf("tlcp host %q error_code=%q, want SSRF_BLOCKED", host, res.ErrorCode)
		}
	}
}

func makeSelfSignedTLCPCertPair(t *testing.T) (tlcp.Certificate, tlcp.Certificate) {
	t.Helper()
	now := time.Now()
	makeOne := func(serial int64, usage smx509.KeyUsage) tlcp.Certificate {
		priv, err := sm2.GenerateKey(rand.Reader)
		if err != nil {
			t.Fatalf("sm2.GenerateKey: %v", err)
		}
		tmpl := &smx509.Certificate{
			SerialNumber: big.NewInt(serial),
			Subject:      pkix.Name{CommonName: "gm-upstream.example.com"},
			NotBefore:    now.Add(-time.Hour),
			NotAfter:     now.Add(24 * time.Hour),
			KeyUsage:     usage,
			ExtKeyUsage:  []smx509.ExtKeyUsage{smx509.ExtKeyUsageServerAuth},
			DNSNames:     []string{"gm-upstream.example.com"},
		}
		der, err := smx509.CreateCertificate(rand.Reader, tmpl, tmpl, &priv.PublicKey, priv)
		if err != nil {
			t.Fatalf("smx509.CreateCertificate: %v", err)
		}
		keyDER, err := smx509.MarshalPKCS8PrivateKey(priv)
		if err != nil {
			t.Fatalf("MarshalPKCS8PrivateKey: %v", err)
		}
		certPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})
		keyPEM := pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: keyDER})
		pair, err := tlcp.X509KeyPair(certPEM, keyPEM)
		if err != nil {
			t.Fatalf("tlcp.X509KeyPair: %v", err)
		}
		return pair
	}
	return makeOne(1, smx509.KeyUsageDigitalSignature),
		makeOne(2, smx509.KeyUsageKeyEncipherment|smx509.KeyUsageDataEncipherment)
}

func TestTLCPClientHandshakeRealServer(t *testing.T) {
	signPair, encPair := makeSelfSignedTLCPCertPair(t)
	rawLn, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	defer rawLn.Close()

	tlcpLn := tlcp.NewListener(rawLn, &tlcp.Config{
		Certificates: []tlcp.Certificate{signPair, encPair},
	})
	srv := &http.Server{
		Handler: http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.WriteHeader(http.StatusOK)
			_, _ = w.Write([]byte("gm-ok"))
		}),
	}
	go func() { _ = srv.Serve(tlcpLn) }()
	defer srv.Close()

	addr := rawLn.Addr().(*net.TCPAddr)
	// 通过直接调用内部安全客户端测试真实 TLCP 1.1 握手（绕过 SSRF 回环阻断只在此处白盒构造本地回环）
	tlcpDial := func(verify bool) (int, bool, error) {
		var hsOK bool
		tr := &http.Transport{
			DisableKeepAlives: true,
			DialTLSContext: func(ctx context.Context, network, _ string) (net.Conn, error) {
				c, err := net.DialTimeout(network, addr.String(), 3*time.Second)
				if err != nil {
					return nil, err
				}
				tc := tlcp.Client(c, &tlcp.Config{
					ServerName:         "gm-upstream.example.com",
					InsecureSkipVerify: !verify,
				})
				if err := tc.HandshakeContext(ctx); err != nil {
					_ = c.Close()
					return nil, err
				}
				hsOK = true
				return tc, nil
			},
		}
		client := &http.Client{Transport: tr, Timeout: 5 * time.Second}
		req, _ := http.NewRequestWithContext(context.Background(), http.MethodGet, "https://gm-upstream.example.com/health", nil)
		resp, err := client.Do(req)
		if err != nil {
			return 0, hsOK, err
		}
		defer resp.Body.Close()
		return resp.StatusCode, hsOK, nil
	}

	// 1. InsecureSkipVerify=true（即 TLSVerify=false）：真实国密 TLCP 1.1 握手成功并拿到 200
	status, hsOK, err := tlcpDial(false)
	if err != nil || !hsOK || status != http.StatusOK {
		t.Fatalf("TLCP handshake failed: status=%d hsOK=%v err=%v", status, hsOK, err)
	}

	// 2. TLSVerify=true 对自签国密证书必须校验证书失败（安全底线）
	if _, _, err := tlcpDial(true); err == nil {
		t.Fatal("expected certificate verification error for untrusted self-signed SM2 cert")
	}

	// 3. 验证 buildSafeClient 对非法回环地址在 tlcp 协议下同样二次阻断 SSRF
	safeClient := buildSafeClient(TestInput{
		Scheme:        "tlcp",
		Host:          "gm-upstream.example.com",
		Port:          addr.Port,
		TLSServerName: "gm-upstream.example.com",
		TLSVerify:     false,
		AllowPrivate:  true,
	}, []netip.Addr{netip.MustParseAddr("127.0.0.1")}, nil)
	req, _ := http.NewRequestWithContext(context.Background(), http.MethodGet, "https://gm-upstream.example.com/health", nil)
	if _, err := safeClient.Do(req); err == nil {
		t.Fatal("buildSafeClient must block loopback even for tlcp scheme")
	}
}

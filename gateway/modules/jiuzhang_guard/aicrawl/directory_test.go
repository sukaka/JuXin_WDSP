package aicrawl

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"net"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/jiuzhang-waf/gateway/dynamic_security/httpsig"
)

type staticResolver map[string][]net.IPAddr

func (s staticResolver) LookupIPAddr(_ context.Context, host string) ([]net.IPAddr, error) {
	return s[host], nil
}

func TestSSRFProtection_RejectsPrivateLoopbackLinkLocalMetadataAndRedirects(t *testing.T) {
	f := NewFetcher(FetcherConfig{Timeout: 2 * time.Second})

	// Reject non-HTTPS, loopback, private, link-local, metadata URLs directly.
	badURLs := []string{
		"http://example.com/.well-known/http-message-signatures-directory",
		"https://127.0.0.1/.well-known/http-message-signatures-directory",
		"https://[::1]/.well-known/http-message-signatures-directory",
		"https://10.0.0.1/.well-known/http-message-signatures-directory",
		"https://172.16.0.5/.well-known/http-message-signatures-directory",
		"https://192.168.1.1/.well-known/http-message-signatures-directory",
		"https://169.254.169.254/latest/meta-data/",
		"https://100.100.100.200/latest/meta-data/",
		"https://localhost/.well-known/http-message-signatures-directory",
		"https://metadata.google.internal/.well-known/http-message-signatures-directory",
		"https://user:pass@example.com/.well-known/http-message-signatures-directory",
	}
	for _, u := range badURLs {
		if _, err := f.Fetch(context.Background(), u); err == nil {
			t.Errorf("expected SSRF block for %q", u)
		}
	}

	// DNS rebinding / private resolution rejected at dial time.
	dialCalled := false
	fDNS := NewFetcher(FetcherConfig{
		Timeout: 2 * time.Second,
		Resolver: staticResolver{
			"rebind.example.com": {{IP: net.ParseIP("169.254.169.254")}},
		},
		DialTCP: func(ctx context.Context, network, address string) (net.Conn, error) {
			dialCalled = true
			return nil, nil
		},
	})
	if _, err := fDNS.Fetch(context.Background(), "https://rebind.example.com/.well-known/http-message-signatures-directory"); err == nil {
		t.Fatal("expected dial-time SSRF rejection")
	}
	if dialCalled {
		t.Fatal("DialTCP must not be called when resolved IP fails SSRF validation")
	}

	// IPv4-mapped IPv6 address must be unmapped and blocked.
	if err := ValidateDialIP(netip.MustParseAddr("::ffff:127.0.0.1")); err == nil {
		t.Fatal("expected ::ffff:127.0.0.1 to be blocked")
	}
	if err := ValidateDialIP(netip.MustParseAddr("93.184.216.34")); err != nil {
		t.Fatalf("public IP should be allowed: %v", err)
	}

	// Redirects MUST be rejected (no redirect following).
	ts := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, "https://example.com/other", http.StatusFound)
	}))
	defer ts.Close()
	pool := x509.NewCertPool()
	pool.AddCert(ts.Certificate())
	fRedir := NewFetcher(FetcherConfig{
		Timeout:             2 * time.Second,
		RootCAs:             pool,
		allowPrivateForTest: true,
	})
	if _, err := fRedir.Fetch(context.Background(), ts.URL); err == nil || !strings.Contains(err.Error(), "redirect") {
		t.Fatalf("expected redirect rejection, got %v", err)
	}
}

func TestDirectoryStore_OfflineAndBackgroundRefreshAtomicSwap(t *testing.T) {
	_, _, staticPEM := mustEd25519Pair(t)
	remotePub, _, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	ecPriv, _ := mustECDSAP256Pair(t)
	ecX := make([]byte, 32)
	ecY := make([]byte, 32)
	ecPriv.PublicKey.X.FillBytes(ecX)
	ecPriv.PublicKey.Y.FillBytes(ecY)

	jwksPayload, err := json.Marshal(map[string]any{
		"keys": []map[string]any{
			{
				"kty": "OKP",
				"crv": "Ed25519",
				"kid": "remote-ed-1",
				"x":   base64.RawURLEncoding.EncodeToString(remotePub),
			},
			{
				"kty": "EC",
				"crv": "P-256",
				"kid": "remote-ec-1",
				"x":   base64.RawURLEncoding.EncodeToString(ecX),
				"y":   base64.RawURLEncoding.EncodeToString(ecY),
			},
		},
	})
	if err != nil {
		t.Fatal(err)
	}

	// 1. Offline mode (empty directory_url): zero network IO, no goroutine started.
	offlineStore, err := NewDirectoryStore([]DirectorySpec{
		{
			ID:             "dir-offline",
			Slug:           "offline-bot",
			Category:       CategorySearchEngine,
			SignatureAgent: "https://offline.example",
			Keys:           []KeySpec{{Kid: "static-1", Alg: httpsig.AlgEd25519, PublicKeyPEM: staticPEM}},
		},
	}, DirectoryStoreOptions{})
	if err != nil {
		t.Fatal(err)
	}
	if offlineStore.HasRemoteDirectories() {
		t.Fatal("offline store should report HasRemoteDirectories=false")
	}
	rk, ok := offlineStore.Lookup("static-1", "https://offline.example/")
	if !ok || rk.Slug != "offline-bot" {
		t.Fatalf("static lookup failed: ok=%v rk=%+v", ok, rk)
	}
	// Cross-agent confusion prevented: mismatched Signature-Agent rejected.
	if _, ok := offlineStore.Lookup("static-1", "https://other.example"); ok {
		t.Fatal("mismatched Signature-Agent must not match bound directory key")
	}

	// 2. Background refresh with TLS test server swaps snapshot atomically and stops cleanly on cancel.
	ts := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/http-message-signatures-directory+json")
		_, _ = w.Write(jwksPayload)
	}))
	defer ts.Close()
	pool := x509.NewCertPool()
	pool.AddCert(ts.Certificate())
	fetcher := NewFetcher(FetcherConfig{
		Timeout:             2 * time.Second,
		RootCAs:             pool,
		allowPrivateForTest: true,
	})

	store, err := NewDirectoryStore([]DirectorySpec{
		{
			ID:             "dir-hybrid",
			Slug:           "hybrid-bot",
			Category:       CategoryAIAgent,
			SignatureAgent: "https://hybrid.example",
			DirectoryURL:   ts.URL,
			Keys:           []KeySpec{{Kid: "static-1", Alg: httpsig.AlgEd25519, PublicKeyPEM: staticPEM}},
		},
	}, DirectoryStoreOptions{
		Fetcher:         fetcher,
		RefreshInterval: 50 * time.Millisecond,
	})
	if err != nil {
		t.Fatal(err)
	}

	ctx, cancel := context.WithCancel(context.Background())
	store.StartBackgroundRefresh(ctx)

	// Concurrent reads while background refresh swaps snapshot (verified under -race).
	var wg sync.WaitGroup
	for i := 0; i < 8; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for j := 0; j < 50; j++ {
				_, _ = store.Lookup("static-1", "https://hybrid.example")
				_, _ = store.Lookup("remote-ed-1", "https://hybrid.example")
				time.Sleep(time.Millisecond)
			}
		}()
	}

	deadline := time.Now().Add(2 * time.Second)
	for time.Now().Before(deadline) {
		if _, ok := store.Lookup("remote-ed-1", "https://hybrid.example"); ok {
			break
		}
		time.Sleep(10 * time.Millisecond)
	}
	wg.Wait()
	cancel()
	store.WaitBackgroundRefresh()

	if rk, ok := store.Lookup("remote-ed-1", "https://hybrid.example"); !ok || rk.Key.Alg != httpsig.AlgEd25519 {
		t.Fatalf("remote Ed25519 key missing after refresh: ok=%v rk=%+v", ok, rk)
	}
	if rk, ok := store.Lookup("remote-ec-1", "https://hybrid.example"); !ok || rk.Key.Alg != httpsig.AlgECDSAP256SHA256 {
		t.Fatalf("remote P-256 key missing after refresh: ok=%v rk=%+v", ok, rk)
	}
	// Static key must still be preserved.
	if _, ok := store.Lookup("static-1", "https://hybrid.example"); !ok {
		t.Fatal("static key lost after remote refresh")
	}
}

func TestParseDirectoryJWKS_RejectsPrivateKeyParam(t *testing.T) {
	pub, _, _ := ed25519.GenerateKey(rand.Reader)
	raw, _ := json.Marshal(map[string]any{
		"keys": []map[string]any{
			{
				"kty": "OKP",
				"crv": "Ed25519",
				"kid": "bad-priv",
				"x":   base64.RawURLEncoding.EncodeToString(pub),
				"d":   "SHOULD_NEVER_BE_IN_DIRECTORY",
			},
		},
	})
	if _, err := ParseDirectoryJWKS(raw); err == nil {
		t.Fatal("expected JWKS with private parameter d to be rejected")
	}
}

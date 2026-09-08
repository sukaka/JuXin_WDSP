package jwtverify

import (
	"context"
	"crypto/elliptic"
	"net"
	"net/http"
	"net/http/httptest"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

// JWT-16：高并发验证 + 并发轮换，无数据竞争（-race）、无 panic、结果一致。
func TestConcurrentVerifyRace(t *testing.T) {
	clock := newFakeClock()
	keyA := genRSA(t, 2048)
	keyB := genEC(t, elliptic.P256())
	v, ir := newRemoteVerifierStub(t, clock, 0)

	var current atomic.Value // []byte JWKS
	current.Store(jwksJSON(t, rsaJWK(keyA, "key-a")))
	ir.remoteCache.fetchFn = func(ctx context.Context) (*Keyset, error) {
		return ParseJWKS(current.Load().([]byte))
	}
	if err := ir.remoteCache.RefreshSync(context.Background()); err != nil {
		t.Fatal(err)
	}

	validA := signToken(t, keyA, "RS256", "key-a", validClaims(clock, testIssuer), nil)
	validB := signToken(t, keyB, "ES256", "key-b", validClaims(clock, testIssuer), nil)
	forged := signToken(t, genRSA(t, 2048), "RS256", "key-a", validClaims(clock, testIssuer), nil)
	unknownKid := signToken(t, keyA, "RS256", "kid-not-exist", validClaims(clock, testIssuer), nil)

	var wg sync.WaitGroup
	// 轮换 goroutine：A → A+B → B 循环。
	stop := make(chan struct{})
	wg.Add(1)
	go func() {
		defer wg.Done()
		sets := [][]byte{
			jwksJSON(t, rsaJWK(keyA, "key-a")),
			jwksJSON(t, rsaJWK(keyA, "key-a"), ecJWK(keyB, "key-b")),
			jwksJSON(t, ecJWK(keyB, "key-b")),
		}
		i := 0
		for {
			select {
			case <-stop:
				return
			default:
				current.Store(sets[i%len(sets)])
				i++
				_ = ir.remoteCache.RefreshSync(context.Background())
			}
		}
	}()

	tokens := []string{validA, validB, forged, unknownKid, "garbage.token.here"}
	for g := 0; g < 32; g++ {
		wg.Add(1)
		go func(g int) {
			defer wg.Done()
			for i := 0; i < 200; i++ {
				tok := tokens[(g+i)%len(tokens)]
				res := v.Verify(bearer(tok), "GET", "/api/orders")
				// 结果必须落在合法状态集合内；任何情况下不得产生
				// 伪造/畸形 Token 的可信主体。
				switch res.Status {
				case StatusVerified, StatusInvalid, StatusUnavailable:
				default:
					t.Errorf("非法状态: %s", res.Status)
				}
				if res.Status != StatusVerified && res.VerifiedPrincipalID != "" {
					t.Errorf("非 VERIFIED 不得携带可信主体: %s", res.Status)
				}
			}
		}(g)
	}
	close(stop)
	wg.Wait()
	waitCacheIdle(t, ir.remoteCache)
}

// JWT-16：热路径零网络 IO —— 有效缓存内验证已知 kid 不发生任何拨号。
func TestHotPathZeroNetworkIO(t *testing.T) {
	clock := newFakeClock()
	keyA := genRSA(t, 2048)
	jwksBody := jwksJSON(t, rsaJWK(keyA, "key-a"))

	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write(jwksBody)
	}))
	defer srv.Close()

	var dialCount atomic.Int32
	base := &net.Dialer{}
	fetcher, _ := newTLSTestFetcher(t, srv)
	fetcher.dialTCP = func(ctx context.Context, network, address string) (net.Conn, error) {
		dialCount.Add(1)
		return base.DialContext(ctx, network, address)
	}

	iss := IssuerConfig{
		Issuer:           testIssuer,
		Audiences:        []string{"api://orders"},
		Algorithms:       []Algorithm{AlgRS256},
		KeySource:        KeySourceRemoteJWKS,
		RemoteURL:        srv.URL + "/jwks",
		RemoteAllowCIDRs: []string{"127.0.0.0/8"},
	}
	v, err := NewVerifier(VerifierConfig{
		Policy:         testPolicy(ModeProtect, iss),
		IdentitySecret: testSecret,
		Fetcher:        fetcher,
		Clock:          clock,
	})
	if err != nil {
		t.Fatal(err)
	}
	ir := v.issuers[testIssuer]
	if err := ir.remoteCache.RefreshSync(context.Background()); err != nil {
		t.Fatalf("预热缓存失败: %v", err)
	}
	dialCount.Store(0)

	token := signToken(t, keyA, "RS256", "key-a", validClaims(clock, testIssuer), nil)
	var wg sync.WaitGroup
	for g := 0; g < 32; g++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for i := 0; i < 200; i++ {
				res := v.Verify(bearer(token), "GET", "/api")
				if res.Status != StatusVerified {
					t.Errorf("热路径验证失败: %s/%s", res.Status, res.ReasonCode)
				}
			}
		}()
	}
	wg.Wait()
	if got := dialCount.Load(); got != 0 {
		t.Fatalf("热路径发生网络拨号 %d 次", got)
	}
}

// JWT-16：异步刷新失败不阻塞热路径，冷却过后可恢复。
func TestAsyncRefreshRecovery(t *testing.T) {
	clock := newFakeClock()
	keyA := genRSA(t, 2048)
	v, ir := newRemoteVerifierStub(t, clock, 0)

	fail := atomic.Bool{}
	fail.Store(true)
	ir.remoteCache.fetchFn = func(ctx context.Context) (*Keyset, error) {
		if fail.Load() {
			return nil, context.DeadlineExceeded
		}
		return ParseJWKS(jwksJSON(t, rsaJWK(keyA, "key-a")))
	}
	token := signToken(t, keyA, "RS256", "key-a", validClaims(clock, testIssuer), nil)

	// 冷启动 + 故障：UNAVAILABLE，异步触发失败刷新。
	if res := v.Verify(bearer(token), "GET", "/api"); res.Status != StatusUnavailable {
		t.Fatalf("冷启动应 UNAVAILABLE: %+v", res)
	}
	waitCacheIdle(t, ir.remoteCache)

	// 冷却期内不再重试；冷却过后恢复。
	clock.Advance(DefaultRefreshCooldown + time.Second)
	fail.Store(false)
	if res := v.Verify(bearer(token), "GET", "/api"); res.Status != StatusUnavailable {
		t.Fatalf("恢复前仍 UNAVAILABLE（本次请求不阻塞等待网络）: %+v", res)
	}
	waitCacheIdle(t, ir.remoteCache)
	if res := v.Verify(bearer(token), "GET", "/api"); res.Status != StatusVerified {
		t.Fatalf("异步刷新恢复后应 VERIFIED: %+v", res)
	}
}

// 后台刷新循环按周期运行并尊重 ctx 取消。
func TestBackgroundRefreshLoop(t *testing.T) {
	clock := newFakeClock()
	keyA := genRSA(t, 2048)
	iss := IssuerConfig{
		Issuer:     testIssuer,
		Audiences:  []string{"api://orders"},
		Algorithms: []Algorithm{AlgRS256},
		KeySource:  KeySourceRemoteJWKS,
		RemoteURL:  "https://idp.example.com/jwks.json",
	}
	var fetchCount atomic.Int32
	v, err := NewVerifier(VerifierConfig{
		Policy:          testPolicy(ModeProtect, iss),
		IdentitySecret:  testSecret,
		Fetcher:         NewFetcher(FetcherConfig{}),
		Clock:           clock,
		RefreshInterval: 10 * time.Millisecond,
	})
	if err != nil {
		t.Fatal(err)
	}
	v.issuers[testIssuer].remoteCache.fetchFn = func(ctx context.Context) (*Keyset, error) {
		fetchCount.Add(1)
		return ParseJWKS(jwksJSON(t, rsaJWK(keyA, "key-a")))
	}
	ctx, cancel := context.WithCancel(context.Background())
	v.StartBackgroundRefresh(ctx)
	time.Sleep(55 * time.Millisecond)
	cancel()
	time.Sleep(20 * time.Millisecond)
	got := fetchCount.Load()
	if got < 2 {
		t.Fatalf("后台刷新应至少执行 2 次（启动+周期），实际 %d", got)
	}
}

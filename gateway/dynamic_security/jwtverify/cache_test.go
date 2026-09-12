package jwtverify

import (
	"context"
	"crypto/elliptic"
	"errors"
	"sync/atomic"
	"testing"
	"time"
)

// waitCacheIdle 等待异步刷新结束（测试辅助）。
func waitCacheIdle(t *testing.T, c *keysetCache) {
	t.Helper()
	deadline := time.Now().Add(5 * time.Second)
	for time.Now().Before(deadline) {
		c.mu.Lock()
		busy := c.inFlight
		c.mu.Unlock()
		if !busy {
			return
		}
		time.Sleep(time.Millisecond)
	}
	t.Fatalf("等待异步刷新超时")
}

// newRemoteVerifierStub 构造远程 issuer 验证器，fetchFn 由测试替换为桩。
func newRemoteVerifierStub(t *testing.T, clock *fakeClock, trustTTL time.Duration) (*Verifier, *issuerRuntime) {
	t.Helper()
	iss := IssuerConfig{
		Issuer:     testIssuer,
		Audiences:  []string{"api://orders"},
		Algorithms: []Algorithm{AlgRS256, AlgES256},
		KeySource:  KeySourceRemoteJWKS,
		RemoteURL:  "https://idp.example.com/jwks.json",
	}
	v, err := NewVerifier(VerifierConfig{
		Policy:         testPolicy(ModeProtect, iss),
		IdentitySecret: testSecret,
		Fetcher:        NewFetcher(FetcherConfig{}), // 桩替换后不会被调用
		Clock:          clock,
		TrustTTL:       trustTTL,
	})
	if err != nil {
		t.Fatalf("构造验证器失败: %v", err)
	}
	return v, v.issuers[testIssuer]
}

// JWT-07：新旧公钥重叠轮换可用；删除旧 key 后新请求立即不再信任旧 key。
func TestRotationOverlapAndRemoval(t *testing.T) {
	clock := newFakeClock()
	keyA := genRSA(t, 2048)
	keyB := genEC(t, elliptic.P256())
	v, ir := newRemoteVerifierStub(t, clock, 0)

	current := jwksJSON(t, rsaJWK(keyA, "key-a"))
	ir.remoteCache.fetchFn = func(ctx context.Context) (*Keyset, error) { return ParseJWKS(current) }
	if err := ir.remoteCache.RefreshSync(context.Background()); err != nil {
		t.Fatal(err)
	}

	tokenA := signToken(t, keyA, "RS256", "key-a", validClaims(clock, testIssuer), nil)
	tokenB := signToken(t, keyB, "ES256", "key-b", validClaims(clock, testIssuer), nil)

	if res := v.Verify(bearer(tokenA), "GET", "/api"); res.Status != StatusVerified {
		t.Fatalf("初始 key-a 应 VERIFIED: %s/%s", res.Status, res.ReasonCode)
	}
	// 重叠期：新集合同时含 A+B。
	current = jwksJSON(t, rsaJWK(keyA, "key-a"), ecJWK(keyB, "key-b"))
	if err := ir.remoteCache.RefreshSync(context.Background()); err != nil {
		t.Fatal(err)
	}
	if res := v.Verify(bearer(tokenA), "GET", "/api"); res.Status != StatusVerified {
		t.Fatalf("重叠期 key-a 应 VERIFIED: %s/%s", res.Status, res.ReasonCode)
	}
	if res := v.Verify(bearer(tokenB), "GET", "/api"); res.Status != StatusVerified {
		t.Fatalf("重叠期 key-b 应 VERIFIED: %s/%s", res.Status, res.ReasonCode)
	}
	// 删除 key-a：新请求立即不再信任。
	current = jwksJSON(t, ecJWK(keyB, "key-b"))
	if err := ir.remoteCache.RefreshSync(context.Background()); err != nil {
		t.Fatal(err)
	}
	if res := v.Verify(bearer(tokenA), "GET", "/api"); res.Status != StatusInvalid || res.ReasonCode != ReasonUnknownKid {
		t.Fatalf("删除后 key-a 应 UNKNOWN_KID: %s/%s", res.Status, res.ReasonCode)
	}
	if res := v.Verify(bearer(tokenB), "GET", "/api"); res.Status != StatusVerified {
		t.Fatalf("key-b 应继续 VERIFIED: %s/%s", res.Status, res.ReasonCode)
	}
}

// JWT-08：JWKS 失败但缓存未过期 → 本地验签 VERIFIED；硬过期 → UNAVAILABLE；
// 冷启动 → UNAVAILABLE；失败刷新不延长最后成功时间；stale 宽限为 0。
func TestCacheFailureStates(t *testing.T) {
	clock := newFakeClock()
	keyA := genRSA(t, 2048)
	v, ir := newRemoteVerifierStub(t, clock, 0)
	// Token 有效期须覆盖后续时钟前跳（信任期 15min），避免先落到 EXPIRED。
	longLived := validClaims(clock, testIssuer)
	longLived["exp"] = clock.Now().Add(time.Hour).Unix()
	token := signToken(t, keyA, "RS256", "key-a", longLived, nil)

	// 先替换为失败桩，避免任何真实网络访问。
	ir.remoteCache.fetchFn = func(ctx context.Context) (*Keyset, error) {
		return nil, errors.New("模拟远端故障")
	}

	// 冷启动：无可用集合。
	if res := v.Verify(bearer(token), "GET", "/api"); res.Status != StatusUnavailable || res.ReasonCode != ReasonKeysetUnavailable {
		t.Fatalf("冷启动应 UNAVAILABLE/KEYSET_UNAVAILABLE: %+v", res)
	}
	waitCacheIdle(t, ir.remoteCache)

	// 成功加载。
	ir.remoteCache.fetchFn = func(ctx context.Context) (*Keyset, error) {
		return ParseJWKS(jwksJSON(t, rsaJWK(keyA, "key-a")))
	}
	if err := ir.remoteCache.RefreshSync(context.Background()); err != nil {
		t.Fatal(err)
	}
	if res := v.Verify(bearer(token), "GET", "/api"); res.Status != StatusVerified {
		t.Fatalf("缓存内应 VERIFIED: %+v", res)
	}

	// 信任期内远端故障：缓存仍可完成完整验签。
	t0 := clock.Now()
	clock.Advance(10 * time.Minute)
	ir.remoteCache.fetchFn = func(ctx context.Context) (*Keyset, error) {
		return nil, errors.New("模拟远端故障")
	}
	if err := ir.remoteCache.RefreshSync(context.Background()); err == nil {
		t.Fatalf("故障刷新应返回错误")
	}
	if res := v.Verify(bearer(token), "GET", "/api"); res.Status != StatusVerified {
		t.Fatalf("信任期内故障应仍 VERIFIED: %+v", res)
	}

	// 失败不延长最后成功时间：t0+16min > t0+15min 硬过期；stale 宽限 0。
	clock.Set(t0.Add(DefaultTrustTTL + time.Second))
	if res := v.Verify(bearer(token), "GET", "/api"); res.Status != StatusUnavailable || res.ReasonCode != ReasonKeysetUnavailable {
		t.Fatalf("硬过期应 UNAVAILABLE: %+v", res)
	}
	waitCacheIdle(t, ir.remoteCache)
}

// JWT-07：未知 kid 洪泛有界 —— singleflight + ≥30s 冷却 + 有界负缓存。
func TestUnknownKidFloodBounded(t *testing.T) {
	clock := newFakeClock()
	keyA := genRSA(t, 2048)
	v, ir := newRemoteVerifierStub(t, clock, 0)

	var fetchCount atomic.Int32
	ir.remoteCache.fetchFn = func(ctx context.Context) (*Keyset, error) {
		fetchCount.Add(1)
		return ParseJWKS(jwksJSON(t, rsaJWK(keyA, "key-a")))
	}
	if err := ir.remoteCache.RefreshSync(context.Background()); err != nil {
		t.Fatal(err)
	}
	fetchCount.Store(0)
	// 初始刷新本身计入冷却，先推进时钟越过冷却窗再开始洪泛。
	clock.Advance(DefaultRefreshCooldown + time.Second)

	// 500 个不同未知 kid：冷却窗内仅触发一次异步刷新。
	for i := 0; i < 500; i++ {
		kid := string(rune('a'+i%26)) + string(rune('A'+i/26%26)) + string(rune('0'+i%10))
		res := v.Verify(bearer(signToken(t, keyA, "RS256", kid, validClaims(clock, testIssuer), nil)), "GET", "/api")
		if res.Status != StatusInvalid || res.ReasonCode != ReasonUnknownKid {
			t.Fatalf("未知 kid 应 INVALID/UNKNOWN_KID: %+v", res)
		}
	}
	waitCacheIdle(t, ir.remoteCache)
	if got := fetchCount.Load(); got != 1 {
		t.Fatalf("冷却窗内洪泛应只触发 1 次刷新，实际 %d", got)
	}
	// 负缓存有界。
	ir.remoteCache.mu.Lock()
	negLen := len(ir.remoteCache.negative)
	ir.remoteCache.mu.Unlock()
	if negLen > defaultNegativeMax {
		t.Fatalf("负缓存超界: %d", negLen)
	}
	// 冷却过后允许下一次受限刷新。
	clock.Advance(DefaultRefreshCooldown + time.Second)
	v.Verify(bearer(signToken(t, keyA, "RS256", "new-kid", validClaims(clock, testIssuer), nil)), "GET", "/api")
	waitCacheIdle(t, ir.remoteCache)
	if got := fetchCount.Load(); got != 2 {
		t.Fatalf("冷却后应再触发 1 次刷新，实际累计 %d", got)
	}
	// 同一未知 kid 在负缓存期内重复出现不再触发刷新。
	clock.Advance(DefaultRefreshCooldown + time.Second)
	for i := 0; i < 50; i++ {
		v.Verify(bearer(signToken(t, keyA, "RS256", "repeat-kid", validClaims(clock, testIssuer), nil)), "GET", "/api")
	}
	waitCacheIdle(t, ir.remoteCache)
	if got := fetchCount.Load(); got != 3 {
		t.Fatalf("负缓存内重复 kid 不应反复触发刷新，实际累计 %d", got)
	}
}

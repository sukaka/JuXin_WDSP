package hasyncd

import (
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"
)

const testSharedSecretHex = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"

func TestSharedHMACVector(t *testing.T) {
	secret, err := ParseSecretHex(testSharedSecretHex)
	if err != nil {
		t.Fatalf("ParseSecretHex: %v", err)
	}
	bodySum := sha256.Sum256([]byte(`{"ports":[80,443]}`))
	bodyHex := hex.EncodeToString(bodySum[:])
	// Shared cross-module vector verified identically in server/internal/nodesync.
	const (
		method = "POST"
		path   = "/v1/firewall/ensure"
		ts     = "1764000000"
		nonce  = "00112233445566778899aabbccddeeff"
	)
	got := ComputeSignature(secret, method, path, ts, nonce, bodyHex)
	const (
		wantBodyHex = "edd0c61bb02a963e0c2a2f8a50f01ce02b0df29a5d7b47a186e50fd3a958a387"
		wantSigHex  = "04a0f27a95a8c16d4a1819c55585caffd5a880f5ef45a85df31c98e80e49907d"
	)
	if bodyHex != wantBodyHex {
		t.Fatalf("unexpected body sha256: got %s want %s", bodyHex, wantBodyHex)
	}
	if got != wantSigHex {
		t.Fatalf("unexpected HMAC signature: got %s want %s", got, wantSigHex)
	}
	// Deterministic check against manual canonical form.
	wantCanonical := method + "\n" + path + "\n" + ts + "\n" + nonce + "\n" + bodyHex
	if CanonicalSignString(method, path, ts, nonce, bodyHex) != wantCanonical {
		t.Fatalf("canonical string mismatch")
	}
	// Uppercase hex secret must decode to identical raw bytes and signature.
	secretUpper, err := ParseSecretHex(strings.ToUpper(testSharedSecretHex))
	if err != nil {
		t.Fatalf("ParseSecretHex upper: %v", err)
	}
	if gotUpper := ComputeSignature(secretUpper, method, path, ts, nonce, bodyHex); gotUpper != got {
		t.Fatalf("case sensitivity mismatch: %s vs %s", gotUpper, got)
	}
}

func TestParseSecretHexAndLoadSecretFile(t *testing.T) {
	if _, err := ParseSecretHex("abcd"); err == nil {
		t.Fatal("expected short secret to fail")
	}
	if _, err := ParseSecretHex(strings.Repeat("a", 63)); err == nil {
		t.Fatal("expected odd/short secret to fail")
	}
	if _, err := ParseSecretHex(strings.Repeat("z", 64)); err == nil {
		t.Fatal("expected non-hex secret to fail")
	}
	if _, err := LoadSecretFile(""); err == nil {
		t.Fatal("expected empty path to fail closed")
	}

	tmp := t.TempDir()
	if _, err := LoadSecretFile(filepath.Join(tmp, "missing.key")); err == nil {
		t.Fatal("expected missing secret file to fail closed")
	}
	if _, err := LoadSecretFile(tmp); err == nil {
		t.Fatal("expected directory path to fail closed")
	}

	worldWritable := filepath.Join(tmp, "world.key")
	if err := os.WriteFile(worldWritable, []byte(testSharedSecretHex+"\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(worldWritable, 0o666); err != nil {
		t.Fatal(err)
	}
	if _, err := LoadSecretFile(worldWritable); err == nil {
		t.Fatal("expected world-writable secret file to fail closed")
	}

	goodPath := filepath.Join(tmp, "sync.key")
	if err := os.WriteFile(goodPath, []byte(testSharedSecretHex+"\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	got, err := LoadSecretFile(goodPath)
	if err != nil {
		t.Fatalf("LoadSecretFile valid: %v", err)
	}
	if len(got) != 32 {
		t.Fatalf("expected 32 decoded bytes, got %d", len(got))
	}
}

func TestAuthenticatorChecks(t *testing.T) {
	secret, _ := ParseSecretHex(testSharedSecretHex)
	now := time.Unix(1764000000, 0).UTC()
	auth, err := NewAuthenticator(secret, 4, func() time.Time { return now })
	if err != nil {
		t.Fatalf("NewAuthenticator: %v", err)
	}

	emptySum := sha256.Sum256(nil)
	emptyHex := hex.EncodeToString(emptySum[:])

	makeReq := func(method, path string, ts time.Time, nonce, bodyHex, sigOverride string) *http.Request {
		req := httptest.NewRequest(method, "http://127.0.0.1:18443"+path, nil)
		tsStr := strconv.FormatInt(ts.Unix(), 10)
		req.Header.Set(HeaderNode, "gw-a")
		req.Header.Set(HeaderTimestamp, tsStr)
		req.Header.Set(HeaderNonce, nonce)
		req.Header.Set(HeaderBodySHA256, bodyHex)
		sig := sigOverride
		if sig == "" {
			sig = ComputeSignature(secret, method, path, tsStr, nonce, bodyHex)
		}
		req.Header.Set(HeaderSignature, sig)
		return req
	}

	// Valid request succeeds.
	if _, err := auth.VerifyHeaders(makeReq(http.MethodGet, "/v1/health", now, "0011223344556677", emptyHex, "")); err != nil {
		t.Fatalf("expected valid request to succeed: %v", err)
	}

	// Exact replay fails.
	if _, err := auth.VerifyHeaders(makeReq(http.MethodGet, "/v1/health", now, "0011223344556677", emptyHex, "")); !errors.Is(err, ErrNonceReplayed) {
		t.Fatalf("expected ErrNonceReplayed, got %v", err)
	}
	// Uppercase hex variant of same nonce must also be rejected as replay.
	if _, err := auth.VerifyHeaders(makeReq(http.MethodGet, "/v1/health", now, "0011223344556677aabb", emptyHex, "")); err != nil {
		t.Fatalf("fresh nonce failed: %v", err)
	}
	if _, err := auth.VerifyHeaders(makeReq(http.MethodGet, "/v1/health", now, "0011223344556677AABB", emptyHex, "")); !errors.Is(err, ErrNonceReplayed) {
		t.Fatalf("expected case-variant replay to fail with ErrNonceReplayed, got %v", err)
	}

	// Expired timestamps (>60s past and >60s future) rejected.
	if _, err := auth.VerifyHeaders(makeReq(http.MethodGet, "/v1/health", now.Add(-61*time.Second), "1111222233334444", emptyHex, "")); !errors.Is(err, ErrAuthInvalid) {
		t.Fatalf("expected expired past timestamp to fail, got %v", err)
	}
	if _, err := auth.VerifyHeaders(makeReq(http.MethodGet, "/v1/health", now.Add(61*time.Second), "2222333344445555", emptyHex, "")); !errors.Is(err, ErrAuthInvalid) {
		t.Fatalf("expected future timestamp to fail, got %v", err)
	}

	// Tampered signature must NOT consume replay cache capacity.
	badSig := strings.Repeat("0", 64)
	for i := 0; i < 10; i++ {
		nonce := hex.EncodeToString([]byte{byte(i), 1, 2, 3, 4, 5, 6, 7})
		if _, err := auth.VerifyHeaders(makeReq(http.MethodGet, "/v1/health", now, nonce, emptyHex, badSig)); !errors.Is(err, ErrAuthInvalid) {
			t.Fatalf("expected tampered sig to fail, got %v", err)
		}
	}
	if auth.nonces.Len() != 2 {
		t.Fatalf("tampered signatures should not pollute nonce cache: len=%d", auth.nonces.Len())
	}

	// Fill remaining capacity (max=4) then verify fail-closed ErrNonceCacheFull.
	if _, err := auth.VerifyHeaders(makeReq(http.MethodGet, "/v1/health", now.Add(60*time.Second), "aaaa1111bbbb2222", emptyHex, "")); err != nil {
		t.Fatalf("boundary +60s should pass: %v", err)
	}
	if _, err := auth.VerifyHeaders(makeReq(http.MethodGet, "/v1/health", now.Add(-60*time.Second), "cccc3333dddd4444", emptyHex, "")); err != nil {
		t.Fatalf("boundary -60s should pass: %v", err)
	}
	if _, err := auth.VerifyHeaders(makeReq(http.MethodGet, "/v1/health", now, "eeee5555ffff6666", emptyHex, "")); !errors.Is(err, ErrNonceCacheFull) {
		t.Fatalf("expected ErrNonceCacheFull, got %v", err)
	}

	// Advance clock past 120s TTL: cache prunes automatically and old nonces become reusable.
	now = now.Add(121 * time.Second)
	if _, err := auth.VerifyHeaders(makeReq(http.MethodGet, "/v1/health", now, "0011223344556677", emptyHex, "")); err != nil {
		t.Fatalf("expected expired nonce to succeed after TTL: %v", err)
	}
}

func TestNonceCacheConcurrentRace(t *testing.T) {
	cache := NewNonceCache(NonceTTL, 100)
	now := time.Now().UTC()
	const workers = 16
	var (
		wg      sync.WaitGroup
		mu      sync.Mutex
		success int
	)
	for i := 0; i < workers; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			if err := cache.CheckAndRecord("deadbeefcafebabe", now); err == nil {
				mu.Lock()
				success++
				mu.Unlock()
			}
		}()
	}
	wg.Wait()
	if success != 1 {
		t.Fatalf("expected exactly 1 concurrent winner for same nonce, got %d", success)
	}
}

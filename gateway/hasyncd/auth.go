package hasyncd

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"log"
	"net/http"
	"os"
	"strconv"
	"strings"
	"sync"
	"time"
)

var (
	// ErrAuthInvalid indicates missing, malformed, expired, or invalid HMAC auth headers.
	ErrAuthInvalid = errors.New("authentication failed")
	// ErrNonceReplayed indicates a previously seen nonce within the replay TTL window.
	ErrNonceReplayed = errors.New("nonce replay detected")
	// ErrNonceCacheFull indicates the bounded replay cache has reached capacity.
	ErrNonceCacheFull = errors.New("nonce replay cache full")
)

// ParseSecretHex validates and decodes a hex-encoded HMAC secret (at least 32 bytes / 64 hex chars).
func ParseSecretHex(raw string) ([]byte, error) {
	trimmed := strings.TrimSpace(raw)
	if len(trimmed) < MinSecretBytes*2 {
		return nil, fmt.Errorf("sync secret too short: expect at least %d hex chars (%d bytes)", MinSecretBytes*2, MinSecretBytes)
	}
	if len(trimmed) > MaxSecretFileBytes {
		return nil, fmt.Errorf("sync secret too long")
	}
	if len(trimmed)%2 != 0 {
		return nil, fmt.Errorf("sync secret hex length must be even")
	}
	decoded, err := hex.DecodeString(trimmed)
	if err != nil {
		return nil, fmt.Errorf("sync secret is not valid hex: %w", err)
	}
	if len(decoded) < MinSecretBytes {
		return nil, fmt.Errorf("sync secret decoded length %d < %d bytes", len(decoded), MinSecretBytes)
	}
	return decoded, nil
}

// LoadSecretFile reads and validates the HMAC secret file in fail-closed mode.
func LoadSecretFile(path string) ([]byte, error) {
	path = strings.TrimSpace(path)
	if path == "" {
		return nil, errors.New("HASYNC_SECRET_FILE is required")
	}
	fi, err := os.Stat(path)
	if err != nil {
		return nil, fmt.Errorf("stat secret file %q: %w", path, err)
	}
	if !fi.Mode().IsRegular() {
		return nil, fmt.Errorf("secret file %q must be a regular file", path)
	}
	if fi.Mode().Perm()&0o002 != 0 {
		return nil, fmt.Errorf("secret file %q is world-writable (mode %04o)", path, fi.Mode().Perm())
	}
	if fi.Mode().Perm()&0o077 != 0 {
		log.Printf("[hasyncd] WARN: secret file %q has permissive mode %04o; recommend 0600 or 0640", path, fi.Mode().Perm())
	}
	f, err := os.Open(path)
	if err != nil {
		return nil, fmt.Errorf("open secret file %q: %w", path, err)
	}
	defer f.Close()
	raw, err := io.ReadAll(io.LimitReader(f, MaxSecretFileBytes+1))
	if err != nil {
		return nil, fmt.Errorf("read secret file %q: %w", path, err)
	}
	if len(raw) > MaxSecretFileBytes {
		return nil, fmt.Errorf("secret file %q exceeds %d bytes", path, MaxSecretFileBytes)
	}
	return ParseSecretHex(string(raw))
}

// CanonicalSignString builds the exact canonical string signed by X-JZ-Signature:
// method + "\n" + path + "\n" + timestamp + "\n" + nonce + "\n" + bodySHA256
func CanonicalSignString(method, path, timestamp, nonce, bodySHA256 string) string {
	return method + "\n" + path + "\n" + timestamp + "\n" + nonce + "\n" + bodySHA256
}

// ComputeSignature computes lowercase hex HMAC-SHA256 over the canonical request string.
func ComputeSignature(secret []byte, method, path, timestamp, nonce, bodySHA256 string) string {
	mac := hmac.New(sha256.New, secret)
	_, _ = mac.Write([]byte(CanonicalSignString(method, path, timestamp, nonce, bodySHA256)))
	return hex.EncodeToString(mac.Sum(nil))
}

// NonceCache is a bounded sliding-window anti-replay cache for request nonces.
type NonceCache struct {
	mu         sync.Mutex
	ttl        time.Duration
	maxEntries int
	entries    map[string]time.Time
}

// NewNonceCache constructs a bounded NonceCache.
func NewNonceCache(ttl time.Duration, maxEntries int) *NonceCache {
	if ttl <= 0 {
		ttl = NonceTTL
	}
	if maxEntries <= 0 {
		maxEntries = DefaultMaxNonceCount
	}
	return &NonceCache{
		ttl:        ttl,
		maxEntries: maxEntries,
		entries:    make(map[string]time.Time),
	}
}

// CheckAndRecord rejects duplicate active nonces and atomically records new ones.
// Fail-closed when capacity is exhausted even after pruning expired entries.
func (c *NonceCache) CheckAndRecord(nonce string, now time.Time) error {
	key := strings.ToLower(nonce)
	c.mu.Lock()
	defer c.mu.Unlock()

	if exp, exists := c.entries[key]; exists {
		if now.Before(exp) {
			return ErrNonceReplayed
		}
		delete(c.entries, key)
	}
	if len(c.entries) >= c.maxEntries {
		c.pruneLocked(now)
		if len(c.entries) >= c.maxEntries {
			return ErrNonceCacheFull
		}
	}
	c.entries[key] = now.Add(c.ttl)
	return nil
}

// Prune removes expired entries from the replay cache.
func (c *NonceCache) Prune(now time.Time) int {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.pruneLocked(now)
}

func (c *NonceCache) pruneLocked(now time.Time) int {
	removed := 0
	for k, exp := range c.entries {
		if !now.Before(exp) {
			delete(c.entries, k)
			removed++
		}
	}
	return removed
}

// Len returns the current number of entries in the cache (useful for tests/metrics).
func (c *NonceCache) Len() int {
	c.mu.Lock()
	defer c.mu.Unlock()
	return len(c.entries)
}

// VerifiedAuth holds authenticated header metadata for a request.
type VerifiedAuth struct {
	Node       string
	Timestamp  int64
	Nonce      string
	BodySHA256 string
}

// Authenticator verifies HMAC-SHA256 headers and enforces timestamp skew and nonce anti-replay.
type Authenticator struct {
	secret []byte
	nonces *NonceCache
	now    func() time.Time
}

// NewAuthenticator creates an Authenticator from validated raw secret bytes.
func NewAuthenticator(secret []byte, maxNonceEntries int, nowFn func() time.Time) (*Authenticator, error) {
	if len(secret) < MinSecretBytes {
		return nil, fmt.Errorf("secret must be at least %d bytes", MinSecretBytes)
	}
	cp := append([]byte(nil), secret...)
	if nowFn == nil {
		nowFn = time.Now
	}
	return &Authenticator{
		secret: cp,
		nonces: NewNonceCache(NonceTTL, maxNonceEntries),
		now:    nowFn,
	}, nil
}

// PruneNonces removes expired nonces from the cache.
func (a *Authenticator) PruneNonces() int {
	return a.nonces.Prune(a.now().UTC())
}

// VerifyHeaders validates all HMAC auth headers, signature, timestamp window, and nonce uniqueness.
// Signature is checked BEFORE recording the nonce so unauthenticated callers cannot exhaust the cache.
func (a *Authenticator) VerifyHeaders(r *http.Request) (VerifiedAuth, error) {
	node := strings.TrimSpace(r.Header.Get(HeaderNode))
	if !isValidNodeHeader(node) {
		return VerifiedAuth{}, fmt.Errorf("%w: invalid or missing %s", ErrAuthInvalid, HeaderNode)
	}

	tsRaw := strings.TrimSpace(r.Header.Get(HeaderTimestamp))
	if tsRaw == "" {
		return VerifiedAuth{}, fmt.Errorf("%w: missing %s", ErrAuthInvalid, HeaderTimestamp)
	}
	ts, err := strconv.ParseInt(tsRaw, 10, 64)
	if err != nil {
		return VerifiedAuth{}, fmt.Errorf("%w: malformed %s", ErrAuthInvalid, HeaderTimestamp)
	}
	now := a.now().UTC()
	skew := now.Unix() - ts
	if skew < -int64(MaxTimestampSkew/time.Second) || skew > int64(MaxTimestampSkew/time.Second) {
		return VerifiedAuth{}, fmt.Errorf("%w: timestamp outside ±%ds window", ErrAuthInvalid, int64(MaxTimestampSkew/time.Second))
	}

	nonce := strings.TrimSpace(r.Header.Get(HeaderNonce))
	if !isValidHexToken(nonce, MinNonceHexLen, MaxNonceHexLen, false) {
		return VerifiedAuth{}, fmt.Errorf("%w: invalid %s", ErrAuthInvalid, HeaderNonce)
	}

	bodySHA := strings.TrimSpace(r.Header.Get(HeaderBodySHA256))
	if !isValidHexToken(bodySHA, 64, 64, true) {
		return VerifiedAuth{}, fmt.Errorf("%w: invalid %s", ErrAuthInvalid, HeaderBodySHA256)
	}

	sigRaw := strings.TrimSpace(r.Header.Get(HeaderSignature))
	if !isValidHexToken(sigRaw, 64, 64, true) {
		return VerifiedAuth{}, fmt.Errorf("%w: invalid %s", ErrAuthInvalid, HeaderSignature)
	}
	sigBytes, err := hex.DecodeString(sigRaw)
	if err != nil {
		return VerifiedAuth{}, fmt.Errorf("%w: invalid %s", ErrAuthInvalid, HeaderSignature)
	}

	path := r.URL.EscapedPath()
	expectedHex := ComputeSignature(a.secret, r.Method, path, tsRaw, nonce, bodySHA)
	expectedBytes, _ := hex.DecodeString(expectedHex)
	if !hmac.Equal(expectedBytes, sigBytes) {
		return VerifiedAuth{}, fmt.Errorf("%w: signature mismatch", ErrAuthInvalid)
	}

	if err := a.nonces.CheckAndRecord(nonce, now); err != nil {
		return VerifiedAuth{}, err
	}

	return VerifiedAuth{
		Node:       node,
		Timestamp:  ts,
		Nonce:      nonce,
		BodySHA256: bodySHA,
	}, nil
}

// VerifyBodySHA256 checks that actualBody's SHA-256 equals the authenticated expectedSHA256.
func VerifyBodySHA256(actualBody []byte, expectedSHA256 string) bool {
	sum := sha256.Sum256(actualBody)
	actualHex := hex.EncodeToString(sum[:])
	return hmac.Equal([]byte(actualHex), []byte(expectedSHA256))
}

func isValidNodeHeader(s string) bool {
	if len(s) == 0 || len(s) > 128 {
		return false
	}
	for i := 0; i < len(s); i++ {
		c := s[i]
		isAlnum := (c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') || (c >= '0' && c <= '9')
		isPunct := c == '.' || c == '_' || c == '-' || c == ':'
		if !isAlnum && !isPunct {
			return false
		}
	}
	return true
}

func isValidHexToken(s string, minLen, maxLen int, lowerOnly bool) bool {
	if len(s) < minLen || len(s) > maxLen {
		return false
	}
	for i := 0; i < len(s); i++ {
		c := s[i]
		isDigit := c >= '0' && c <= '9'
		isLower := c >= 'a' && c <= 'f'
		isUpper := !lowerOnly && c >= 'A' && c <= 'F'
		if !isDigit && !isLower && !isUpper {
			return false
		}
	}
	return true
}

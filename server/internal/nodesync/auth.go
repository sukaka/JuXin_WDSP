package nodesync

import (
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"net/http"
	"strconv"
	"strings"
	"time"
)

const (
	// MinSecretBytes is the minimum raw HMAC secret size (32 bytes = 64 hex chars).
	MinSecretBytes = 32
	// MaxSecretHexChars bounds accepted secret hex length.
	MaxSecretHexChars = 4096
	// EmptyBodySHA256 is the lowercase SHA-256 hex of an empty request body.
	EmptyBodySHA256 = "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
)

// ParseSecretHex validates and decodes a hex-encoded sync secret (at least 32 bytes / 64 hex chars).
func ParseSecretHex(raw string) ([]byte, error) {
	trimmed := strings.TrimSpace(raw)
	if len(trimmed) < MinSecretBytes*2 {
		return nil, fmt.Errorf("sync secret too short: expect at least %d hex chars (%d bytes)", MinSecretBytes*2, MinSecretBytes)
	}
	if len(trimmed) > MaxSecretHexChars {
		return nil, errors.New("sync secret too long")
	}
	if len(trimmed)%2 != 0 {
		return nil, errors.New("sync secret hex length must be even")
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

// CanonicalSignString builds the exact canonical HMAC input string matching gateway/hasyncd:
// method + "\n" + path + "\n" + timestamp + "\n" + nonce + "\n" + bodySHA256
func CanonicalSignString(method, path, timestamp, nonce, bodySHA256 string) string {
	return method + "\n" + path + "\n" + timestamp + "\n" + nonce + "\n" + bodySHA256
}

// ComputeSignature computes the lowercase hex HMAC-SHA256 signature matching gateway/hasyncd.
func ComputeSignature(secret []byte, method, path, timestamp, nonce, bodySHA256 string) string {
	mac := hmac.New(sha256.New, secret)
	_, _ = mac.Write([]byte(CanonicalSignString(method, path, timestamp, nonce, bodySHA256)))
	return hex.EncodeToString(mac.Sum(nil))
}

// GenerateNonce creates a 16-byte (32 lowercase hex char) cryptographic random nonce.
func GenerateNonce() (string, error) {
	var b [16]byte
	if _, err := rand.Read(b[:]); err != nil {
		return "", fmt.Errorf("generate nonce: %w", err)
	}
	return hex.EncodeToString(b[:]), nil
}

// SignRequest attaches all five required X-JZ-* HMAC-SHA256 headers to req.
// If nonce is empty, a cryptographic random 32-char hex nonce is generated automatically.
func SignRequest(req *http.Request, secret []byte, node string, bodySHA256 string, now time.Time, nonce string) error {
	if len(secret) < MinSecretBytes {
		return fmt.Errorf("secret must be at least %d bytes", MinSecretBytes)
	}
	node = strings.TrimSpace(node)
	if node == "" {
		node = "control-plane"
	}
	if !isValidNodeHeader(node) {
		return fmt.Errorf("invalid %s header value %q", HeaderNode, node)
	}
	bodySHA256 = strings.ToLower(strings.TrimSpace(bodySHA256))
	if !isLowerHex64(bodySHA256) {
		return fmt.Errorf("invalid %s: expect 64 lowercase hex chars", HeaderBodySHA256)
	}
	if nonce == "" {
		var err error
		nonce, err = GenerateNonce()
		if err != nil {
			return err
		}
	}
	tsStr := strconv.FormatInt(now.UTC().Unix(), 10)
	path := req.URL.EscapedPath()
	sig := ComputeSignature(secret, req.Method, path, tsStr, nonce, bodySHA256)

	req.Header.Set(HeaderNode, node)
	req.Header.Set(HeaderTimestamp, tsStr)
	req.Header.Set(HeaderNonce, nonce)
	req.Header.Set(HeaderBodySHA256, bodySHA256)
	req.Header.Set(HeaderSignature, sig)
	return nil
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

func isLowerHex64(s string) bool {
	if len(s) != 64 {
		return false
	}
	for i := 0; i < 64; i++ {
		c := s[i]
		if !((c >= '0' && c <= '9') || (c >= 'a' && c <= 'f')) {
			return false
		}
	}
	return true
}

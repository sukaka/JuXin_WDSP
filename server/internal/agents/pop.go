// pop.go 机器端点请求级 PoP 认证（Phase 2-B；契约 docs/agents/WDSP_AGENT_PHASE2_CONTRACT.md §8）。
//
// mTLS 的应用层等价物（与 APM 同构，理由见 apm/agentca.go 包注释——TLS 客户端证书
// 无法穿透反代到本进程，应用层 PoP 与部署拓扑无关）。已持证书 Agent 对全部机器端点
// （heartbeat/metrics/config/ack/flows/packets/rotate-cert）携带三个头：
//
//	X-WDSP-Agent-Cert:       base64(DER) 客户端证书（本 CA 签发，标准编码）
//	X-WDSP-Agent-Timestamp:  Unix 秒（±300s 时钟偏差窗口，防重放）
//	X-WDSP-Agent-Signature:  base64(ECDSA/SHA256 签名)，签名串：
//	                         POP\n<METHOD>\n<PATH>\n<TS>\n<hex(SHA256(body))>
//	                         （空 body 的 SHA256 为空串哈希）
//
// 防降级纪律：三头齐全才走 PoP 校验；头不全或任一校验失败一律 401，绝不回退 Bearer；
// 三头全缺才回退既有 Bearer credential 校验（过渡期兼容，契约 §8）。
package agents

import (
	"crypto/ecdsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"fmt"
	"strconv"
	"strings"
	"sync"
	"time"
)

// PoP 认证头（契约 §8 冻结；X-WDSP-PoP-Nonce 为可选重放防重 nonce 扩展）。
const (
	popCertHeader      = "X-WDSP-Agent-Cert"
	popTimestampHeader = "X-WDSP-Agent-Timestamp"
	popSignatureHeader = "X-WDSP-Agent-Signature"
	popNonceHeader     = "X-WDSP-PoP-Nonce"
)

// popMaxClockSkewSeconds PoP 时间戳允许的最大时钟偏差（秒；契约 §8：≤300s）。
const (
	popMaxClockSkewSeconds     = 300
	defaultPopReplayMaxEntries = 65536
	maxPopNonceLen             = 128
)

// ErrPoPFailed 持有证明校验失败（HTTP 401；消息可安全返回客户端）。
var ErrPoPFailed = errors.New("客户端证书持有证明校验失败")

// ParseAgentCertHeader 解析 PoP 头中的客户端证书（base64 标准编码的 DER；
// 头值不能携带 PEM 换行，故约定 DER+base64——契约 §8）。
func ParseAgentCertHeader(v string) (*x509.Certificate, error) {
	der, err := base64.StdEncoding.DecodeString(strings.TrimSpace(v))
	if err != nil {
		return nil, fmt.Errorf("%w：证书须为 base64(DER)", ErrPoPFailed)
	}
	cert, err := x509.ParseCertificate(der)
	if err != nil {
		return nil, fmt.Errorf("%w：证书解析失败", ErrPoPFailed)
	}
	return cert, nil
}

// BodySHA256Hex 计算请求正文 SHA-256 hex（空正文同样参与签名——空串哈希，防剥离正文重放）。
func BodySHA256Hex(body []byte) string {
	sum := sha256.Sum256(body)
	return hex.EncodeToString(sum[:])
}

// popSigningInput 持有证明签名输入（契约 §8 冻结格式）：
// POP\n<METHOD>\n<PATH>\n<TS>\n<hex(SHA256(body))> ——绑定到具体请求，防跨接口重放。
func popSigningInput(method, path, timestamp, bodySHA256Hex string) []byte {
	return []byte("POP\n" + method + "\n" + path + "\n" + timestamp + "\n" + bodySHA256Hex)
}

// CheckPoPTimestamp 校验 PoP 时间戳新鲜度（Unix 秒，与服务器时差 ≤300s——契约 §8 校验第 4 条）。
func CheckPoPTimestamp(ts string, now time.Time) error {
	unix, err := strconv.ParseInt(strings.TrimSpace(ts), 10, 64)
	if err != nil {
		return fmt.Errorf("%w：时间戳须为 Unix 秒", ErrPoPFailed)
	}
	skew := now.UTC().Unix() - unix
	if skew < 0 {
		skew = -skew
	}
	if skew > popMaxClockSkewSeconds {
		return fmt.Errorf("%w：时间戳超出允许时钟偏差（±%ds）", ErrPoPFailed, popMaxClockSkewSeconds)
	}
	return nil
}

// VerifyPoPSignature 用客户端证书公钥验证 PoP 签名（ECDSA/SHA256，ASN.1 签名 base64 编码——
// 契约 §8 校验第 5 条）。签名覆盖 method+path+timestamp+正文摘要。
func VerifyPoPSignature(cert *x509.Certificate, method, path, timestamp string, body []byte, sigB64 string) error {
	sig, err := base64.StdEncoding.DecodeString(strings.TrimSpace(sigB64))
	if err != nil || len(sig) == 0 {
		return fmt.Errorf("%w：签名须为 base64 编码", ErrPoPFailed)
	}
	pub, ok := cert.PublicKey.(*ecdsa.PublicKey)
	if !ok {
		return fmt.Errorf("%w：证书公钥须为 ECDSA", ErrPoPFailed)
	}
	digest := sha256.Sum256(popSigningInput(method, path, timestamp, BodySHA256Hex(body)))
	if !ecdsa.VerifyASN1(pub, digest[:], sig) {
		return ErrPoPFailed
	}
	return nil
}

// ValidatePoPNonce 校验可选 X-WDSP-PoP-Nonce 头（空表示未携带；携带时限长且禁控制字符）。
func ValidatePoPNonce(nonce string) error {
	if nonce == "" {
		return nil
	}
	if len(nonce) > maxPopNonceLen || strings.ContainsAny(nonce, "\r\n\x00\t ") {
		return fmt.Errorf("%w：PoP nonce 格式非法", ErrPoPFailed)
	}
	return nil
}

type popReplayEntry struct {
	key       string
	expiresAt time.Time
}

// popReplayCache 有界 PoP 重放去重缓存（匹配 ±300s 时钟偏差窗口；内存硬上限防 OOM）。
type popReplayCache struct {
	mu         sync.Mutex
	entries    map[string]time.Time
	order      []popReplayEntry
	maxEntries int
}

func newPopReplayCache(maxEntries int) *popReplayCache {
	if maxEntries <= 0 {
		maxEntries = defaultPopReplayMaxEntries
	}
	return &popReplayCache{
		entries:    make(map[string]time.Time),
		maxEntries: maxEntries,
	}
}

func popReplayHashKey(parts ...string) string {
	h := sha256.New()
	for i, p := range parts {
		if i > 0 {
			_, _ = h.Write([]byte{0})
		}
		_, _ = h.Write([]byte(p))
	}
	return hex.EncodeToString(h.Sum(nil))
}

// CheckAndRecord 校验并登记一次已验签 PoP 请求（返回 false 表示窗口内重放）。
// 键覆盖 (agentID, ts, sig)；携带可选 X-WDSP-PoP-Nonce 时同时对 (agentID, nonce) 防重放。
func (c *popReplayCache) CheckAndRecord(agentID, ts, sig, nonce string, now time.Time) bool {
	now = now.UTC()
	exp := now.Add((popMaxClockSkewSeconds + 1) * time.Second)
	if unix, err := strconv.ParseInt(strings.TrimSpace(ts), 10, 64); err == nil {
		tsExp := time.Unix(unix, 0).UTC().Add((popMaxClockSkewSeconds + 1) * time.Second)
		if tsExp.After(now) {
			exp = tsExp
		}
	}
	sigKey := popReplayHashKey("sig", agentID, strings.TrimSpace(ts), strings.TrimSpace(sig))
	var nonceKey string
	if nonce != "" {
		nonceKey = popReplayHashKey("nonce", agentID, nonce)
	}

	c.mu.Lock()
	defer c.mu.Unlock()
	c.pruneLocked(now, 2)
	if existing, ok := c.entries[sigKey]; ok && existing.After(now) {
		return false
	}
	if nonceKey != "" {
		if existing, ok := c.entries[nonceKey]; ok && existing.After(now) {
			return false
		}
	}
	c.recordLocked(sigKey, exp)
	if nonceKey != "" {
		c.recordLocked(nonceKey, exp)
	}
	return true
}

func (c *popReplayCache) recordLocked(key string, expiresAt time.Time) {
	c.entries[key] = expiresAt
	c.order = append(c.order, popReplayEntry{key: key, expiresAt: expiresAt})
}

func (c *popReplayCache) pruneLocked(now time.Time, reserve int) {
	// 惰性清理队头已过期项
	drop := 0
	for drop < len(c.order) && !c.order[drop].expiresAt.After(now) {
		e := c.order[drop]
		if cur, ok := c.entries[e.key]; ok && !cur.After(now) {
			delete(c.entries, e.key)
		}
		drop++
	}
	if drop > 0 {
		if drop == len(c.order) {
			c.order = c.order[:0]
		} else if drop > len(c.order)/2 || len(c.order) > c.maxEntries {
			compacted := make([]popReplayEntry, len(c.order)-drop)
			copy(compacted, c.order[drop:])
			c.order = compacted
		} else {
			c.order = c.order[drop:]
		}
	}
	// 超容量时全量清过期项，仍超限则按 FIFO 淘汰最旧项，保证严格有界
	if len(c.entries)+reserve > c.maxEntries {
		live := make([]popReplayEntry, 0, len(c.entries))
		for _, e := range c.order {
			if cur, ok := c.entries[e.key]; ok && cur.Equal(e.expiresAt) && cur.After(now) {
				live = append(live, e)
			} else if ok && !cur.After(now) {
				delete(c.entries, e.key)
			}
		}
		c.order = live
		for len(c.entries)+reserve > c.maxEntries && len(c.order) > 0 {
			oldest := c.order[0]
			c.order = c.order[1:]
			if cur, ok := c.entries[oldest.key]; ok && cur.Equal(oldest.expiresAt) {
				delete(c.entries, oldest.key)
			}
		}
	}
}

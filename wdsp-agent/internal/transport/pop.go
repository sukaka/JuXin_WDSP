// 请求级 PoP 认证（Phase 2-B，契约 §8）：持有有效证书的 Agent 对全部机器端点
// 携带三头（X-WDSP-Agent-Cert / -Timestamp / -Signature），与 Bearer 同时发送；
// 无证书或证书已过期 → 仅 Bearer（现状行为）。三头一体：签名失败直接报错，
// 绝不发送残缺 PoP 头（服务端对残缺/无效 PoP 一律 401 不降级）。
package transport

import (
	"crypto/ecdsa"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"fmt"
	"log/slog"
	"net/http"
	"strconv"
	"time"
)

// PoP 头名（契约 §8 冻结）。
const (
	HeaderAgentCert      = "X-WDSP-Agent-Cert"      // 客户端证书 DER 的 base64（标准编码）
	HeaderAgentTimestamp = "X-WDSP-Agent-Timestamp" // Unix 秒
	HeaderAgentSignature = "X-WDSP-Agent-Signature" // base64(ECDSA/SHA256 签名)
)

// Identity 机器身份：客户端证书（DER）+ ECDSA P-256 私钥 + 证书到期时间。
type Identity struct {
	CertDER  []byte
	Key      *ecdsa.PrivateKey
	NotAfter time.Time
}

// SetIdentity 设置 PoP 机器身份；nil 清除（回退 Bearer）。并发安全。
func (c *Client) SetIdentity(id *Identity) { c.identity.Store(id) }

// popSigningInput 契约 §8 冻结签名串（逐字节）：
// "POP\n<METHOD>\n<PATH>\n<TS>\n<hex(SHA256(body))>"（空 body 也算哈希）。
func popSigningInput(method, path, ts string, body []byte) []byte {
	sum := sha256.Sum256(body)
	return []byte("POP\n" + method + "\n" + path + "\n" + ts + "\n" + hex.EncodeToString(sum[:]))
}

// sign 对签名串取 SHA-256 后 ECDSA 签名（ASN.1 DER），base64 标准编码返回。
func (id *Identity) sign(input []byte) (string, error) {
	digest := sha256.Sum256(input)
	sig, err := ecdsa.SignASN1(rand.Reader, id.Key, digest[:])
	if err != nil {
		return "", fmt.Errorf("PoP 签名: %w", err)
	}
	return base64.StdEncoding.EncodeToString(sig), nil
}

// applyPoP 注入 PoP 三头。证书已过期 → 不注入（回退 Bearer，防降级攻击面在服务端：
// PoP 头完全缺失时服务端才走 Bearer 校验）。签名失败返回错误（请求不发出）。
func (c *Client) applyPoP(req *http.Request, body []byte) error {
	id := c.identity.Load()
	if id == nil {
		return nil
	}
	now := c.now()
	if !now.Before(id.NotAfter) {
		if c.expiredWarned.CompareAndSwap(false, true) {
			slog.Warn("机器身份证书已过期，PoP 停用回退 Bearer（rotate-cert 需 PoP，需管理员重新注册）",
				"not_after", id.NotAfter)
		}
		return nil
	}
	ts := strconv.FormatInt(now.Unix(), 10)
	// PATH 为请求路径（不含 host/query），契约 §8
	sig, err := id.sign(popSigningInput(req.Method, req.URL.Path, ts, body))
	if err != nil {
		return err
	}
	req.Header.Set(HeaderAgentCert, base64.StdEncoding.EncodeToString(id.CertDER))
	req.Header.Set(HeaderAgentTimestamp, ts)
	req.Header.Set(HeaderAgentSignature, sig)
	return nil
}

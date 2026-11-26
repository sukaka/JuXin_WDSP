// directory.go Web Bot Auth（RFC 9421）爬虫公钥目录模型、公钥 PEM 校验与
// RFC 9421 /.well-known/http-message-signatures-directory 远程同步解析（纯 Go stdlib）。
package aicrawl

import (
	"context"
	"crypto/ecdh"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"io"
	"math/big"
	"net/http"
	"strings"
	"time"

	"github.com/google/uuid"
	"github.com/jiuzhang-waf/server/internal/outboundhttp"
)

// CrawlerKey 爬虫公钥条目（仅允许公钥 PEM，严禁私钥材料）。
type CrawlerKey struct {
	KID          string `json:"kid"`
	Alg          string `json:"alg"`
	PublicKeyPEM string `json:"public_key_pem"`
}

// Directory Web Bot Auth 爬虫公钥目录（对应 ai_crawler_directories 表）。
type Directory struct {
	ID             uuid.UUID    `json:"id"`
	Slug           string       `json:"slug"`
	Name           string       `json:"name"`
	Category       string       `json:"category"`
	SignatureAgent string       `json:"signature_agent"`
	DirectoryURL   string       `json:"directory_url"`
	Keys           []CrawlerKey `json:"keys"`
	IsBuiltin      bool         `json:"is_builtin"`
	Enabled        bool         `json:"enabled"`
	LastSyncedAt   *time.Time   `json:"last_synced_at,omitempty"`
	LastSyncError  string       `json:"last_sync_error"`
	CreatedAt      time.Time    `json:"created_at"`
	UpdatedAt      time.Time    `json:"updated_at"`
}

// jwkPrivateParams RFC 7517/7518 私钥与对称密钥参数黑名单（目录中严禁出现）。
var jwkPrivateParams = []string{"d", "p", "q", "dp", "dq", "qi", "oth", "k"}

// ErrDirectoryFetchInvalid 远程目录响应内容或格式非法（非网络错误，映射 400）。
var ErrDirectoryFetchInvalid = errors.New("crawler directory payload invalid")

// ValidatePublicKeyPEM 校验公钥 PEM 与声明算法一致，且严格拒绝任何私钥块。
func ValidatePublicKeyPEM(alg, pemStr string) error {
	trimmed := strings.TrimSpace(pemStr)
	if trimmed == "" {
		return errors.New("public_key_pem 不能为空")
	}
	block, rest := pem.Decode([]byte(trimmed))
	if block == nil {
		return errors.New("public_key_pem 不是合法的 PEM 编码")
	}
	if strings.TrimSpace(string(rest)) != "" {
		return errors.New("public_key_pem 只允许包含单个公钥 PEM 块")
	}
	if block.Type != "PUBLIC KEY" {
		return fmt.Errorf("public_key_pem 仅允许 PUBLIC KEY 块，拒绝 %q", block.Type)
	}
	pub, err := x509.ParsePKIXPublicKey(block.Bytes)
	if err != nil {
		return fmt.Errorf("public_key_pem PKIX 公钥解析失败: %w", err)
	}
	switch alg {
	case KeyAlgEd25519:
		k, ok := pub.(ed25519.PublicKey)
		if !ok || len(k) != ed25519.PublicKeySize {
			return errors.New("public_key_pem 与算法 ed25519 不匹配")
		}
	case KeyAlgECDSAP256:
		k, ok := pub.(*ecdsa.PublicKey)
		if !ok || k.Curve != elliptic.P256() {
			return errors.New("public_key_pem 与算法 ecdsa-p256-sha256 不匹配（须为 P-256 公钥）")
		}
	default:
		return fmt.Errorf("不支持的公钥算法 %q（仅支持 ed25519 / ecdsa-p256-sha256）", alg)
	}
	return nil
}

// ParseDirectoryJWKS 解析 RFC 9421 HTTP Message Signatures Directory（JWKS JSON）
// 并转换受支持的 Ed25519（OKP/Ed25519）与 ECDSA P-256（EC/P-256）公钥为 PKIX PEM。
// 严格拒绝私钥参数与对称密钥；缺少 kid 时按 RFC 7638 派生 SHA-256 JWK Thumbprint。
func ParseDirectoryJWKS(raw []byte) ([]CrawlerKey, error) {
	if len(raw) == 0 {
		return nil, fmt.Errorf("%w: 空响应体", ErrDirectoryFetchInvalid)
	}
	if len(raw) > MaxDirectoryBodyBytes {
		return nil, fmt.Errorf("%w: 响应体积超过 %d 字节上限", ErrDirectoryFetchInvalid, MaxDirectoryBodyBytes)
	}
	var doc struct {
		Keys []json.RawMessage `json:"keys"`
	}
	if err := json.Unmarshal(raw, &doc); err != nil {
		return nil, fmt.Errorf("%w: JSON 解析失败: %v", ErrDirectoryFetchInvalid, err)
	}
	if len(doc.Keys) == 0 {
		return nil, fmt.Errorf("%w: keys 数组为空", ErrDirectoryFetchInvalid)
	}

	out := make([]CrawlerKey, 0, len(doc.Keys))
	seenKID := map[string]bool{}
	for idx, entryRaw := range doc.Keys {
		var obj map[string]json.RawMessage
		if err := json.Unmarshal(entryRaw, &obj); err != nil {
			return nil, fmt.Errorf("%w: keys[%d] 不是合法 JSON 对象", ErrDirectoryFetchInvalid, idx)
		}
		for _, priv := range jwkPrivateParams {
			if _, found := obj[priv]; found {
				return nil, fmt.Errorf("%w: keys[%d] 包含禁止的私钥/对称密钥参数 %q", ErrDirectoryFetchInvalid, idx, priv)
			}
		}
		kty := unquoteJSONString(obj["kty"])
		if strings.EqualFold(kty, "oct") {
			return nil, fmt.Errorf("%w: keys[%d] 禁止对称密钥类型 oct", ErrDirectoryFetchInvalid, idx)
		}
		crv := unquoteJSONString(obj["crv"])
		kid := strings.TrimSpace(unquoteJSONString(obj["kid"]))
		if len(kid) > MaxKIDLen || hasControlChars(kid) {
			return nil, fmt.Errorf("%w: keys[%d] kid 非法", ErrDirectoryFetchInvalid, idx)
		}

		var (
			alg    string
			pubKey any
		)
		switch {
		case kty == "OKP" && crv == "Ed25519":
			xStr := unquoteJSONString(obj["x"])
			xBytes, err := base64.RawURLEncoding.DecodeString(xStr)
			if err != nil || len(xBytes) != ed25519.PublicKeySize {
				return nil, fmt.Errorf("%w: keys[%d] Ed25519 x 坐标非法", ErrDirectoryFetchInvalid, idx)
			}
			alg = KeyAlgEd25519
			pubKey = ed25519.PublicKey(xBytes)
			if kid == "" {
				kid = rfc7638ThumbprintOKP(crv, xStr)
			}
		case kty == "EC" && crv == "P-256":
			xStr := unquoteJSONString(obj["x"])
			yStr := unquoteJSONString(obj["y"])
			xBytes, err1 := base64.RawURLEncoding.DecodeString(xStr)
			yBytes, err2 := base64.RawURLEncoding.DecodeString(yStr)
			if err1 != nil || err2 != nil || len(xBytes) == 0 || len(yBytes) == 0 || len(xBytes) > 32 || len(yBytes) > 32 {
				return nil, fmt.Errorf("%w: keys[%d] EC P-256 坐标非法", ErrDirectoryFetchInvalid, idx)
			}
			uncompressed := make([]byte, 65)
			uncompressed[0] = 0x04
			copy(uncompressed[1+32-len(xBytes):33], xBytes)
			copy(uncompressed[33+32-len(yBytes):65], yBytes)
			if _, err := ecdh.P256().NewPublicKey(uncompressed); err != nil {
				return nil, fmt.Errorf("%w: keys[%d] EC P-256 点不在曲线上", ErrDirectoryFetchInvalid, idx)
			}
			alg = KeyAlgECDSAP256
			pubKey = &ecdsa.PublicKey{
				Curve: elliptic.P256(),
				X:     new(big.Int).SetBytes(xBytes),
				Y:     new(big.Int).SetBytes(yBytes),
			}
			if kid == "" {
				kid = rfc7638ThumbprintEC(crv, xStr, yStr)
			}
		default:
			// 跳过目录中可能共存的其它曲线或 RSA 公钥，仅提取 Web Bot Auth 支持的密钥类型
			continue
		}

		if seenKID[kid] {
			return nil, fmt.Errorf("%w: 目录包含重复 kid %q", ErrDirectoryFetchInvalid, kid)
		}
		seenKID[kid] = true

		der, err := x509.MarshalPKIXPublicKey(pubKey)
		if err != nil {
			return nil, fmt.Errorf("%w: keys[%d] 公钥编码失败: %v", ErrDirectoryFetchInvalid, idx, err)
		}
		pemBytes := pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: der})
		out = append(out, CrawlerKey{
			KID:          kid,
			Alg:          alg,
			PublicKeyPEM: string(pemBytes),
		})
		if len(out) > MaxDirectoryKeys {
			return nil, fmt.Errorf("%w: 受支持公钥数量超过上限 %d", ErrDirectoryFetchInvalid, MaxDirectoryKeys)
		}
	}
	if len(out) == 0 {
		return nil, fmt.Errorf("%w: 目录中未找到受支持的 Ed25519 或 ECDSA P-256 公钥", ErrDirectoryFetchInvalid)
	}
	return out, nil
}

// FetchDirectoryKeys 使用带 SSRF 防护的 HTTPS 客户端拉取远程爬虫公钥目录并解析为 PEM 公钥列表。
func FetchDirectoryKeys(ctx context.Context, rawURL string, policy *outboundhttp.Policy) ([]CrawlerKey, error) {
	if policy == nil {
		return nil, errors.New("outboundhttp policy is nil")
	}
	u, err := policy.ValidateURL(ctx, rawURL)
	if err != nil {
		return nil, err
	}
	if !strings.EqualFold(u.Scheme, "https") {
		return nil, fmt.Errorf("%w: directory_url 仅允许 HTTPS 地址", outboundhttp.ErrDenied)
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, u.String(), nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("Accept", "application/http-message-signatures-directory+json, application/jwk-set+json, application/json")
	resp, err := policy.Client().Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("远程目录返回 HTTP %d", resp.StatusCode)
	}
	body, err := io.ReadAll(io.LimitReader(resp.Body, MaxDirectoryBodyBytes+1))
	if err != nil {
		return nil, err
	}
	if len(body) > MaxDirectoryBodyBytes {
		return nil, fmt.Errorf("%w: 远程目录响应超过 %d 字节上限", ErrDirectoryFetchInvalid, MaxDirectoryBodyBytes)
	}
	return ParseDirectoryJWKS(body)
}

func unquoteJSONString(raw json.RawMessage) string {
	if len(raw) == 0 {
		return ""
	}
	var s string
	if err := json.Unmarshal(raw, &s); err != nil {
		return ""
	}
	return s
}

func rfc7638ThumbprintOKP(crv, x string) string {
	canonical, _ := json.Marshal(struct {
		Crv string `json:"crv"`
		Kty string `json:"kty"`
		X   string `json:"x"`
	}{Crv: crv, Kty: "OKP", X: x})
	sum := sha256.Sum256(canonical)
	return base64.RawURLEncoding.EncodeToString(sum[:])
}

func rfc7638ThumbprintEC(crv, x, y string) string {
	canonical, _ := json.Marshal(struct {
		Crv string `json:"crv"`
		Kty string `json:"kty"`
		X   string `json:"x"`
		Y   string `json:"y"`
	}{Crv: crv, Kty: "EC", X: x, Y: y})
	sum := sha256.Sum256(canonical)
	return base64.RawURLEncoding.EncodeToString(sum[:])
}

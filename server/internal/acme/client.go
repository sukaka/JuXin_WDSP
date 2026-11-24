package acme

import (
	"context"
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/base64"
	"encoding/pem"
	"errors"
	"fmt"
	"net/http"
	"strings"
	"time"

	"github.com/jiuzhang-waf/server/internal/outboundhttp"
	xacme "golang.org/x/crypto/acme"
)

const (
	acmeHTTPTimeout = 30 * time.Second
	acmeOrderWait   = 120 * time.Second
)

// IssueRequest 描述一次 ACME 签发调用输入。
type IssueRequest struct {
	DirectoryURL  string
	Allowlist     string
	Email         string
	AccountKey    crypto.Signer
	AccountURI    string
	EABKID        string
	EABHMACKey    string
	Domains       []string
	KeyType       string
	Solver        ChallengeSolver
	OnStageChange func(stage string)
}

// IssueResult 是签发成功的证书材料与最新账户 URI。
type IssueResult struct {
	CertPEM      string // 叶证书 PEM
	ChainPEM     string // 中间证书链 PEM（不含叶证书）
	FullchainPEM string // 完整证书链 PEM（叶 + 中间链）
	KeyPEM       string // PKCS#8 私钥 PEM
	AccountURI   string
}

// Issuer 封装 RFC 8555 ACME v2 协议交互与 SSRF 出站防护。
type Issuer struct {
	// httpClientFactory 测试注入点；nil 时生产路径强制经 outboundhttp.Policy 构造带 SSRF 防护客户端。
	httpClientFactory func(ctx context.Context, dirURL, allowlist string) (*http.Client, error)
}

// NewIssuer 创建 ACME 签发客户端。
func NewIssuer() *Issuer {
	return &Issuer{}
}

// ValidateDirectoryURL 严格校验 ACME 目录地址：必须 HTTPS 且通过 outboundhttp SSRF 防护策略。
func ValidateDirectoryURL(ctx context.Context, rawURL, allowlist string) (*outboundhttp.Policy, error) {
	policy, err := outboundhttp.NewPolicy(outboundhttp.Options{
		Timeout:      acmeHTTPTimeout,
		MaxRedirects: 3,
		Allowlist:    allowlist,
	})
	if err != nil {
		return nil, fmt.Errorf("ACME 允许列表配置非法: %w", err)
	}
	u, err := policy.ValidateURL(ctx, rawURL)
	if err != nil {
		return nil, fmt.Errorf("ACME 目录地址安全校验未通过: %w", err)
	}
	if !strings.EqualFold(u.Scheme, "https") {
		return nil, fmt.Errorf("ACME 目录地址必须使用 https:// 协议")
	}
	return policy, nil
}

func (i *Issuer) buildHTTPClient(ctx context.Context, dirURL, allowlist string) (*http.Client, error) {
	if i.httpClientFactory != nil {
		return i.httpClientFactory(ctx, dirURL, allowlist)
	}
	policy, err := ValidateDirectoryURL(ctx, dirURL, allowlist)
	if err != nil {
		return nil, err
	}
	return policy.Client(), nil
}

// TestDirectory 测试 ACME 目录可达性并回传目录端点元数据。
func (i *Issuer) TestDirectory(ctx context.Context, dirURL, allowlist string) (*TestConfigResult, error) {
	start := time.Now()
	httpClient, err := i.buildHTTPClient(ctx, dirURL, allowlist)
	if err != nil {
		return nil, err
	}
	client := &xacme.Client{
		DirectoryURL: dirURL,
		HTTPClient:   httpClient,
	}
	dir, err := client.Discover(ctx)
	latency := time.Since(start).Milliseconds()
	if err != nil {
		return &TestConfigResult{
			Reachable:    false,
			DirectoryURL: dirURL,
			LatencyMs:    latency,
			Message:      fmt.Sprintf("无法连接 ACME 目录: %v", err),
		}, err
	}
	return &TestConfigResult{
		Reachable:       true,
		DirectoryURL:    dirURL,
		LatencyMs:       latency,
		AuthzURL:        dir.AuthzURL,
		OrderURL:        dir.OrderURL,
		ExternalBinding: dir.ExternalAccountRequired,
		Message:         "ACME 目录连通正常",
	}, nil
}

// IssueCertificate 执行完整 RFC 8555 ACME v2 签发流程（注册账户 → 创建订单 → HTTP-01 验证 → Finalize → 获取 Fullchain）。
func (i *Issuer) IssueCertificate(ctx context.Context, req IssueRequest) (*IssueResult, error) {
	if req.AccountKey == nil {
		return nil, fmt.Errorf("缺少 ACME 账户私钥")
	}
	if req.Solver == nil {
		return nil, fmt.Errorf("缺少 ACME 挑战求解器")
	}
	if len(req.Domains) == 0 {
		return nil, fmt.Errorf("缺少待签发域名列表")
	}

	orderCtx, cancel := context.WithTimeout(ctx, acmeOrderWait)
	defer cancel()

	httpClient, err := i.buildHTTPClient(orderCtx, req.DirectoryURL, req.Allowlist)
	if err != nil {
		return nil, err
	}

	client := &xacme.Client{
		Key:          req.AccountKey,
		DirectoryURL: req.DirectoryURL,
		HTTPClient:   httpClient,
	}

	// 1. 注册或复用 ACME 账户
	acctURI := strings.TrimSpace(req.AccountURI)
	if acctURI == "" {
		acct := &xacme.Account{
			Contact: []string{"mailto:" + strings.TrimSpace(req.Email)},
		}
		if strings.TrimSpace(req.EABKID) != "" || strings.TrimSpace(req.EABHMACKey) != "" {
			if strings.TrimSpace(req.EABKID) == "" || strings.TrimSpace(req.EABHMACKey) == "" {
				return nil, fmt.Errorf("EAB KID 与 EAB HMAC 密钥须同时配置")
			}
			hmacBytes, decErr := decodeEABHMACKey(req.EABHMACKey)
			if decErr != nil {
				return nil, fmt.Errorf("EAB HMAC 密钥格式无效: %w", decErr)
			}
			acct.ExternalAccountBinding = &xacme.ExternalAccountBinding{
				KID: strings.TrimSpace(req.EABKID),
				Key: hmacBytes,
			}
		}
		reg, regErr := client.Register(orderCtx, acct, xacme.AcceptTOS)
		if regErr != nil {
			if errors.Is(regErr, xacme.ErrAccountAlreadyExists) {
				existing, getErr := client.GetReg(orderCtx, "")
				if getErr != nil {
					return nil, fmt.Errorf("获取已注册 ACME 账户失败: %w", getErr)
				}
				acctURI = existing.URI
			} else {
				return nil, fmt.Errorf("注册 ACME 账户失败: %w", regErr)
			}
		} else if reg != nil {
			acctURI = reg.URI
		}
	}

	// 2. 创建 ACME 订单
	if req.OnStageChange != nil {
		req.OnStageChange(OrderValidating)
	}
	order, err := client.AuthorizeOrder(orderCtx, xacme.DomainIDs(req.Domains...))
	if err != nil {
		return nil, fmt.Errorf("创建 ACME 订单失败: %w", err)
	}

	// 3. 逐个完成域名所有权验证（当前支持 http-01）
	for _, authzURL := range order.AuthzURLs {
		authz, err := client.GetAuthorization(orderCtx, authzURL)
		if err != nil {
			return nil, fmt.Errorf("查询域名授权状态失败: %w", err)
		}
		if authz.Status == xacme.StatusValid {
			continue
		}
		domain := authz.Identifier.Value
		chal := findChallenge(authz.Challenges, "http-01")
		if chal == nil {
			return nil, fmt.Errorf("域名 %s 未返回可用的 http-01 挑战", domain)
		}
		keyAuth, err := client.HTTP01ChallengeResponse(chal.Token)
		if err != nil {
			return nil, fmt.Errorf("计算域名 %s HTTP-01 响应失败: %w", domain, err)
		}
		if err := req.Solver.Present(orderCtx, domain, chal.Token, keyAuth); err != nil {
			return nil, fmt.Errorf("发布域名 %s HTTP-01 挑战失败: %w", domain, err)
		}
		// 无论成功与否均清理令牌
		cleanup := func(d, tok string) {
			cleanCtx, cleanCancel := context.WithTimeout(context.Background(), 5*time.Second)
			defer cleanCancel()
			_ = req.Solver.CleanUp(cleanCtx, d, tok)
		}
		_, acceptErr := client.Accept(orderCtx, chal)
		if acceptErr != nil {
			cleanup(domain, chal.Token)
			return nil, fmt.Errorf("提交域名 %s HTTP-01 挑战失败: %w", domain, acceptErr)
		}
		_, waitErr := client.WaitAuthorization(orderCtx, authzURL)
		cleanup(domain, chal.Token)
		if waitErr != nil {
			return nil, fmt.Errorf("域名 %s HTTP-01 验证未通过（请确认域名已解析至本网关且公网 80 端口可达）: %w", domain, waitErr)
		}
	}

	// 4. 等待订单就绪并提交 CSR 签发完整证书链
	if req.OnStageChange != nil {
		req.OnStageChange(OrderFinalizing)
	}
	if _, err := client.WaitOrder(orderCtx, order.URI); err != nil {
		return nil, fmt.Errorf("等待 ACME 订单就绪失败: %w", err)
	}

	certKey, keyPEM, err := GenerateCertPrivateKey(req.KeyType)
	if err != nil {
		return nil, fmt.Errorf("生成证书私钥失败: %w", err)
	}
	csrDER, err := x509.CreateCertificateRequest(rand.Reader, &x509.CertificateRequest{
		Subject:  pkix.Name{CommonName: req.Domains[0]},
		DNSNames: req.Domains,
	}, certKey)
	if err != nil {
		return nil, fmt.Errorf("生成 CSR 失败: %w", err)
	}

	derChain, _, err := client.CreateOrderCert(orderCtx, order.FinalizeURL, csrDER, true)
	if err != nil {
		return nil, fmt.Errorf("签发证书失败: %w", err)
	}
	if len(derChain) == 0 {
		return nil, fmt.Errorf("CA 返回空证书链")
	}

	leafPEM, chainPEM, fullchainPEM := encodeDERChainPEM(derChain)
	return &IssueResult{
		CertPEM:      leafPEM,
		ChainPEM:     chainPEM,
		FullchainPEM: fullchainPEM,
		KeyPEM:       keyPEM,
		AccountURI:   acctURI,
	}, nil
}

// GenerateAccountKey 生成 ECDSA P-256 ACME 账户私钥及 PKCS#8 PEM。
func GenerateAccountKey() (crypto.Signer, string, error) {
	return GenerateCertPrivateKey(KeyTypeEC256)
}

// GenerateCertPrivateKey 按指定算法生成证书私钥与 PKCS#8 PEM。
func GenerateCertPrivateKey(keyType string) (crypto.Signer, string, error) {
	if keyType == "" {
		keyType = KeyTypeEC256
	}
	var signer crypto.Signer
	var err error
	switch keyType {
	case KeyTypeEC256:
		signer, err = ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	case KeyTypeEC384:
		signer, err = ecdsa.GenerateKey(elliptic.P384(), rand.Reader)
	case KeyTypeRSA2048:
		signer, err = rsa.GenerateKey(rand.Reader, 2048)
	default:
		return nil, "", ValidateKeyType(keyType)
	}
	if err != nil {
		return nil, "", err
	}
	der, err := x509.MarshalPKCS8PrivateKey(signer)
	if err != nil {
		return nil, "", err
	}
	pemBytes := pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: der})
	return signer, string(pemBytes), nil
}

// ParsePrivateKeyPEM 解析 PKCS#8 / EC / PKCS#1 私钥 PEM 为 crypto.Signer。
func ParsePrivateKeyPEM(keyPEM string) (crypto.Signer, error) {
	block, _ := pem.Decode([]byte(strings.TrimSpace(keyPEM)))
	if block == nil {
		return nil, fmt.Errorf("无效的私钥 PEM 格式")
	}
	switch block.Type {
	case "PRIVATE KEY":
		k, err := x509.ParsePKCS8PrivateKey(block.Bytes)
		if err != nil {
			return nil, err
		}
		s, ok := k.(crypto.Signer)
		if !ok {
			return nil, fmt.Errorf("私钥不支持签名操作")
		}
		return s, nil
	case "EC PRIVATE KEY":
		return x509.ParseECPrivateKey(block.Bytes)
	case "RSA PRIVATE KEY":
		return x509.ParsePKCS1PrivateKey(block.Bytes)
	default:
		return nil, fmt.Errorf("不支持的私钥块类型 %s", block.Type)
	}
}

func findChallenge(chals []*xacme.Challenge, typ string) *xacme.Challenge {
	for _, c := range chals {
		if c != nil && c.Type == typ {
			return c
		}
	}
	return nil
}

func encodeDERChainPEM(derChain [][]byte) (leafPEM, chainPEM, fullchainPEM string) {
	var fullBuf, chainBuf strings.Builder
	for idx, der := range derChain {
		blk := string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}))
		fullBuf.WriteString(blk)
		if idx == 0 {
			leafPEM = blk
		} else {
			chainBuf.WriteString(blk)
		}
	}
	return leafPEM, chainBuf.String(), fullBuf.String()
}

func decodeEABHMACKey(raw string) ([]byte, error) {
	s := strings.TrimSpace(raw)
	if b, err := base64.RawURLEncoding.DecodeString(s); err == nil && len(b) > 0 {
		return b, nil
	}
	if b, err := base64.URLEncoding.DecodeString(s); err == nil && len(b) > 0 {
		return b, nil
	}
	if b, err := base64.StdEncoding.DecodeString(s); err == nil && len(b) > 0 {
		return b, nil
	}
	return nil, fmt.Errorf("须为合法的 base64url / base64 编码字符串")
}

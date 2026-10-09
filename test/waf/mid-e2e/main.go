// mid-e2e NG-ID G1 批次 C 联调参照客户端（机器身份 HTTP Message Signatures
// （RFC 9421+9530+8941）对测——设计 docs/nextgen/NG-ID-g1-machine-identity.md
// §4 对测纪律：Go stdlib crypto 三算法签名器 + 自实现最小 SF 序列化（候选库
// httpsfv 许可证已核实宽松（BSD-3-Clause），客户端只需序列化窄子集故自实现
// 保持零第三方依赖，登记于 s7 出口记录）；禁 curl 冒充签名请求；测试数据
// RFC5737/example.com 红线）。
//
// 子命令：
//
//	mid-e2e keygen -dir D                          生成固定集合密钥（幂等）
//	mid-e2e jwks -dir D                            输出 JWT 公钥 JWKS（jwt-k1）
//	mid-e2e mintjwt -dir D -iss I -aud A -sub S    铸造 RS256 JWT
//	mid-e2e principalfp -salt S -app ID -iss I -sub S   计算 JWT VerifiedPrincipalID
//	                                                 （第一层指纹——管理面 principal_binding
//	                                                 录入值；jwtverify PrincipalID 同算法）
//	mid-e2e noncekey -salt S -identity NAME -nonce N    计算重放存储 Valkey 键
//	mid-e2e send -gw URL -host H [请求/签名/变体 flags]   签名并发送，输出 VERDICT 行
//
// VERDICT 行形态：VERDICT <label> status=NNN origin=true|false rid=<id> body="<截断>"
// （-also-gw 时第二行 <label>.b 为同签名头原样发第二网关——重放矩阵用）。
package main

import (
	"bytes"
	"context"
	"crypto/hmac"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/tls"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"strings"
	"time"
)

func fatal(format string, args ...any) {
	fmt.Fprintf(os.Stderr, "FATAL: "+format+"\n", args...)
	os.Exit(2)
}

func nowUnix() int64 { return time.Now().Unix() }

// randomNonce 密码学随机 nonce（接入契约：16~32 字节随机 base64——取 24 字节
// base64url 32 字符（词长窗 8~64 内））。
func randomNonce() string {
	b := make([]byte, 24)
	if _, err := rand.Read(b); err != nil {
		panic(err)
	}
	return base64.RawURLEncoding.EncodeToString(b)
}

// b64u URL-safe 无填充（JWT 通道）。
func b64u(b []byte) string { return base64.RawURLEncoding.EncodeToString(b) }

// mintJWT RS256 铸造（jwt_trust 静态 JWKS 对测；claims=iss/aud/sub/iat/exp+roles 可选）。
func mintJWT(dir, iss, aud, sub, rolesCSV string, expIn int64) (string, error) {
	key, err := loadKey(dir, "jwt-k1")
	if err != nil {
		return "", err
	}
	now := nowUnix()
	header := map[string]any{"alg": "RS256", "typ": "JWT", "kid": "jwt-k1"}
	payload := map[string]any{"iss": iss, "aud": aud, "sub": sub, "iat": now, "exp": now + expIn}
	if rolesCSV != "" {
		payload["roles"] = strings.Split(rolesCSV, ",")
	}
	h, _ := json.Marshal(header)
	p, _ := json.Marshal(payload)
	input := b64u(h) + "." + b64u(p)
	sig, err := key.sign([]byte(input))
	if err != nil {
		return "", err
	}
	return input + "." + b64u(sig), nil
}

// jwksFromKey 输出 jwt-k1 公钥 JWKS（RS256 n/e base64url）。
func jwksFromKey(dir string) (string, error) {
	key, err := loadKey(dir, "jwt-k1")
	if err != nil {
		return "", err
	}
	pub, err := publicOf(key.priv)
	if err != nil {
		return "", err
	}
	rsaPub, ok := pub.(*rsa.PublicKey)
	if !ok {
		return "", fmt.Errorf("jwt-k1 非 RSA 公钥")
	}
	jwks := map[string]any{"keys": []map[string]any{{
		"kty": "RSA", "kid": "jwt-k1", "use": "sig", "alg": "RS256",
		"n": b64u(rsaPub.N.Bytes()), "e": b64u(bigIntE(rsaPub.E)),
	}}}
	raw, _ := json.Marshal(jwks)
	return string(raw), nil
}

// bigIntE RSA 公钥指数大端字节。
func bigIntE(e int) []byte {
	b := []byte{byte(e), byte(e >> 8), byte(e >> 16), byte(e >> 24)}
	for len(b) > 1 && b[len(b)-1] == 0 {
		b = b[:len(b)-1]
	}
	for i, j := 0, len(b)-1; i < j; i, j = i+1, j-1 {
		b[i], b[j] = b[j], b[i]
	}
	return b
}

// principalFP 计算 JWT VerifiedPrincipalID 第一层指纹（jwtverify.PrincipalID 同算法：
// HMAC-SHA256(key=identity_salt, 域分隔前缀+长度前缀编码 appID/issuer/sub+tenant 标志)
// 截前 16 字节 hex；tenant 未配置（本联调 issuer 不设 tenant_claim）→ 标志 0x00）。
// 管理面 principal_binding 录入值即此值（发布边界由 server 换算至网关比对域——
// S7 批次 C 裁决 3 修复，guardconfig.machineIDPrincipalBindingFP）。
func principalFP(salt, appID, issuer, sub string) string {
	const domain = "jiuzhang/wdsp-jwt-principal/v1"
	m := hmac.New(sha256.New, []byte(salt))
	m.Write([]byte(domain))
	lp := func(s string) {
		var lb [4]byte
		lb[0] = byte(len(s) >> 24)
		lb[1] = byte(len(s) >> 16)
		lb[2] = byte(len(s) >> 8)
		lb[3] = byte(len(s))
		m.Write(lb[:])
		m.Write([]byte(s))
	}
	lp(appID)
	lp(issuer)
	lp(sub)
	m.Write([]byte{0x00}) // tenantPresent=false
	return hex.EncodeToString(m.Sum(nil)[:16])
}

// nonceKey 重放存储 Valkey 键（mid:v1:nonce:{identityFP}:{nonceDigestHex32}——
// identityFP=HMAC(identity_salt,"machineid:identity:"+身份名) 截前 16 字节 hex，
// nonceDigest=sha256(nonce) hex 前 32——网关 registry.go/replay.go 同算法）。
func nonceKey(salt, identity, nonce string) string {
	m := hmac.New(sha256.New, []byte(salt))
	m.Write([]byte("machineid:identity:"))
	m.Write([]byte(identity))
	fp := hex.EncodeToString(m.Sum(nil))[:32]
	sum := sha256.Sum256([]byte(nonce))
	return "mid:v1:nonce:{" + fp + "}:" + hex.EncodeToString(sum[:])[:32]
}

// ---------- send ----------

var httpTr = &http.Transport{}

// sendOne 发送单个（已签名）请求并输出 VERDICT 行。返回是否源站到达。
func sendOne(label, gw string, req *http.Request, body []byte, tlsMode bool) (status int, origin bool, rid string) {
	urlStr := strings.TrimRight(gw, "/") + req.URL.RequestURI()
	wire, err := http.NewRequestWithContext(context.Background(), req.Method, urlStr, bytes.NewReader(body))
	if err != nil {
		fatal("构造请求失败: %v", err)
	}
	wire.Host = req.Host
	wire.Header = req.Header.Clone()
	if len(body) > 0 {
		wire.ContentLength = int64(len(body))
	}
	client := &http.Client{Timeout: 15 * time.Second}
	if tlsMode {
		client.Transport = &http.Transport{TLSClientConfig: &tls.Config{
			ServerName:         req.Host,
			InsecureSkipVerify: true, // 自签测试证书（RFC5737/example.com 同纪律——仅联调栈）
		}}
	} else {
		client.Transport = httpTr
	}
	resp, err := client.Do(wire)
	if err != nil {
		fmt.Printf("VERDICT %s status=0 origin=false rid= body=%q err=%v\n", label, err.Error(), err)
		return 0, false, ""
	}
	defer resp.Body.Close()
	raw, _ := io.ReadAll(io.LimitReader(resp.Body, 4096))
	status = resp.StatusCode
	origin = resp.Header.Get("X-Wdsp-Origin-Mark") != ""
	rid = resp.Header.Get("X-Jiuzhang-Request-ID")
	if rid == "" {
		// 源站回显通道（testorigin 回显 X-Request-Id 请求头）
		var echo struct {
			RequestID string `json:"request_id"`
		}
		if json.Unmarshal(raw, &echo) == nil {
			rid = echo.RequestID
		}
	}
	bs := strings.ReplaceAll(string(raw), "\"", "'")
	if len(bs) > 160 {
		bs = bs[:160]
	}
	fmt.Printf("VERDICT %s status=%d origin=%t rid=%s body=%q\n", label, status, origin, rid, bs)
	return status, origin, rid
}

func cmdSend(args []string) {
	fs := flag.NewFlagSet("send", flag.ExitOnError)
	gw := fs.String("gw", "http://127.0.0.1:18080", "网关基址")
	alsoGW := fs.String("also-gw", "", "第二网关基址（重放矩阵：同签名头原样再发）")
	host := fs.String("host", "", "Host 头（网关路由应用）")
	method := fs.String("method", "GET", "请求方法")
	path := fs.String("path", "/mid/ping", "路径（raw，不归一）")
	query := fs.String("query", "", "raw query（不含 ?；原文参与签名与发送）")
	body := fs.String("body", "", "请求体（非空即携 Content-Digest sha-256）")
	ct := fs.String("ct", "", "Content-Type（有体缺省 application/x-www-form-urlencoded——CRS 920340 规避）")
	label := fs.String("label", "case", "用例标签（VERDICT 行首字段）")
	dir := fs.String("dir", "", "密钥目录")
	kid := fs.String("kid", "", "签名 kid（manifest 内）")
	tlsMode := fs.Bool("tls", false, "经 HTTPS（SNI=Host；自签证书免校验——bot 合格性需 TLS）")
	browser := fs.Bool("browser", false, "浏览器文档导航头组（Accept text/html/Sec-Fetch-*/UA——bot 合格性）")
	xff := fs.String("xff", "", "X-Forwarded-For（RFC5737 测试地址；可信代理命中用例）")
	jwtTok := fs.String("jwt", "", "Bearer JWT（principal_binding 组合用例）")
	// 变体
	tamper := fs.String("tamper", "", "签后篡改：method|path|query|body")
	unsigned := fs.Bool("unsigned", false, "不携带签名头")
	nonce := fs.String("nonce", "", "固定 nonce（重放用例）")
	createdAt := fs.Int64("created-at", 0, "指定 created（时效变体）")
	expiresAt := fs.Int64("expires-at", 0, "指定 expires（时效变体）")
	lifetime := fs.Int64("lifetime", 0, "expires=created+N（寿命超限用例）")
	kidClaim := fs.String("kid-claim", "", "keyid 参数覆盖（未登记 keyid）")
	algClaim := fs.String("alg-claim", "", "alg 参数覆盖（词表外/与登记不符）")
	signWith := fs.String("sign-with", "", "用其他私钥签（签名无效）")
	omit := fs.String("omit", "", "省略覆盖成分（逗号分隔——覆盖不足）")
	rawInput := fs.String("raw-input", "", "Signature-Input 全自定义（畸形/多标签）")
	rawSig := fs.String("raw-sig", "", "Signature 全自定义")
	repeat := fs.Int("repeat", 1, "同签名头重复发送次数（本机重放用例）")
	printOnly := fs.Bool("print-headers", false, "不发送——打印签名请求 JSON（跨轨离线验签用）")
	_ = fs.Parse(args)

	if *host == "" {
		fatal("-host 必填")
	}
	// 请求组装（raw query 原文——签名与发送同串）
	bodyBytes := []byte(*body)
	req := &http.Request{
		Method: *method,
		Host:   *host,
		Header: http.Header{},
		URL:    mustURL(*path, *query),
	}
	if *browser {
		req.Header.Set("User-Agent", "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/126.0.0.0 Safari/537.36")
		req.Header.Set("Accept", "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8")
		req.Header.Set("Sec-Fetch-Dest", "document")
		req.Header.Set("Sec-Fetch-Mode", "navigate")
	} else {
		// 默认 UA 诚实标识本客户端——Go 默认 UA 触发 CRS 扫描器规则（PROTECT 应用下 403）
		req.Header.Set("User-Agent", "jiuzhang-mid-e2e/1.0 (RFC9421 reference client)")
	}
	// 有体必带 Content-Type（缺失触发 CRS 920340 CRITICAL——阶段 1 异常分 5 直接阻断）；
	// 默认 x-www-form-urlencoded 在 CRS 允许清单内，-ct 可覆盖（如 application/json）
	if len(bodyBytes) > 0 || *ct != "" {
		ctVal := *ct
		if ctVal == "" {
			ctVal = "application/x-www-form-urlencoded"
		}
		req.Header.Set("Content-Type", ctVal)
	}
	if *xff != "" {
		req.Header.Set("X-Forwarded-For", *xff)
	}
	if *jwtTok != "" {
		req.Header.Set("Authorization", "Bearer "+*jwtTok)
	}
	// 签名（禁 curl 冒充——签名构造必须经本实现）
	if !*unsigned && (*rawInput != "" || *rawSig != "") {
		if err := signRequest(req, bodyBytes, nil, *dir, signOptions{rawInput: *rawInput, rawSig: *rawSig}); err != nil {
			fatal("签名(raw): %v", err)
		}
	} else if !*unsigned {
		if *dir == "" || *kid == "" {
			fatal("签名请求需 -dir 与 -kid")
		}
		key, err := loadKey(*dir, *kid)
		if err != nil {
			fatal("加载密钥: %v", err)
		}
		omitSet := map[string]bool{}
		if *omit != "" {
			for _, c := range strings.Split(*omit, ",") {
				omitSet[strings.TrimSpace(c)] = true
			}
		}
		err = signRequest(req, bodyBytes, key, *dir, signOptions{
			nonce: *nonce, created: *createdAt, expires: *expiresAt, lifetime: *lifetime,
			kidClaim: *kidClaim, algClaim: *algClaim, signWith: *signWith,
			omit: omitSet,
		})
		if err != nil {
			fatal("签名: %v", err)
		}
	}
	// 签后篡改（签名头不变，线格式变化——密码学上不可区分 TARGET-MISMATCH/
	// SIGNATURE-INVALID 的断言按裁决 1 词表集合判定）
	switch *tamper {
	case "method":
		req.Method = "PUT"
	case "path":
		req.URL.Path = req.URL.Path + "-tampered"
	case "query":
		req.URL.RawQuery = "tampered=1"
	case "body":
		bodyBytes = []byte(*body + "-tampered")
	case "":
	default:
		fatal("未知 tamper %q", *tamper)
	}
	if *printOnly {
		out := map[string]any{
			"method": req.Method, "host": req.Host,
			"path": req.URL.EscapedPath(), "query": req.URL.RawQuery,
			"body_b64": base64.StdEncoding.EncodeToString(bodyBytes),
			"headers":  req.Header,
		}
		raw, _ := json.Marshal(out)
		fmt.Println(string(raw))
		return
	}
	for i := 0; i < *repeat; i++ {
		l := *label
		if *repeat > 1 {
			l = fmt.Sprintf("%s.%d", *label, i+1)
		}
		sendOne(l, *gw, req, bodyBytes, *tlsMode)
	}
	if *alsoGW != "" {
		sendOne(*label+".b", *alsoGW, req, bodyBytes, *tlsMode)
	}
}

func mustURL(path, rawQuery string) *url.URL {
	if !strings.HasPrefix(path, "/") {
		fatal("path 须 / 开头")
	}
	return &url.URL{Path: path, RawQuery: rawQuery}
}

func main() {
	if len(os.Args) < 2 {
		fatal("用法: mid-e2e <keygen|jwks|mintjwt|principalfp|noncekey|send> [flags]")
	}
	switch os.Args[1] {
	case "keygen":
		fs := flag.NewFlagSet("keygen", flag.ExitOnError)
		dir := fs.String("dir", "", "密钥目录")
		_ = fs.Parse(os.Args[2:])
		if *dir == "" {
			fatal("-dir 必填")
		}
		if err := keygen(*dir); err != nil {
			fatal("keygen: %v", err)
		}
		fmt.Println("KEYGEN_OK", *dir)
	case "jwks":
		fs := flag.NewFlagSet("jwks", flag.ExitOnError)
		dir := fs.String("dir", "", "密钥目录")
		_ = fs.Parse(os.Args[2:])
		s, err := jwksFromKey(*dir)
		if err != nil {
			fatal("jwks: %v", err)
		}
		fmt.Println(s)
	case "mintjwt":
		fs := flag.NewFlagSet("mintjwt", flag.ExitOnError)
		dir := fs.String("dir", "", "密钥目录")
		iss := fs.String("iss", "", "issuer")
		aud := fs.String("aud", "", "audience")
		sub := fs.String("sub", "", "subject")
		roles := fs.String("roles", "", "roles 逗号分隔")
		expIn := fs.Int64("exp-in", 1200, "有效期秒")
		_ = fs.Parse(os.Args[2:])
		tok, err := mintJWT(*dir, *iss, *aud, *sub, *roles, *expIn)
		if err != nil {
			fatal("mintjwt: %v", err)
		}
		fmt.Println(tok)
	case "principalfp":
		fs := flag.NewFlagSet("principalfp", flag.ExitOnError)
		salt := fs.String("salt", "", "identity_salt")
		app := fs.String("app", "", "application_id (UUID)")
		iss := fs.String("iss", "", "issuer")
		sub := fs.String("sub", "", "subject")
		_ = fs.Parse(os.Args[2:])
		if *salt == "" || *app == "" || *iss == "" || *sub == "" {
			fatal("-salt/-app/-iss/-sub 必填")
		}
		fmt.Println(principalFP(*salt, *app, *iss, *sub))
	case "noncekey":
		fs := flag.NewFlagSet("noncekey", flag.ExitOnError)
		salt := fs.String("salt", "", "identity_salt")
		identity := fs.String("identity", "", "身份名")
		nonce := fs.String("nonce", "", "nonce 原文")
		_ = fs.Parse(os.Args[2:])
		if *salt == "" || *identity == "" || *nonce == "" {
			fatal("-salt/-identity/-nonce 必填")
		}
		fmt.Println(nonceKey(*salt, *identity, *nonce))
	case "send":
		cmdSend(os.Args[2:])
	default:
		fatal("未知子命令 %q", os.Args[1])
	}
}

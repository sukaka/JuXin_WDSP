// poptool —— WDSP 流量采集 Agent 机器身份 PoP 认证调试/验收工具（契约
// docs/agents/WDSP_AGENT_PHASE2_CONTRACT.md §7-§9），仅供 test/wdsp-agent-e2e/run.sh 使用。
//
// 子命令：
//
//	poptool headers -key agent.key -cert agent.crt -method POST -path /api/v1/agents/<id>/heartbeat \
//	    [-body-file hb.json] [-tamper signature]
//	      输出 PoP 三头（每行一个 "Header: value"，可直接喂给 curl -H）：
//	      X-WDSP-Agent-Cert/Timestamp/Signature（契约 §8，签名串
//	      "POP\n<METHOD>\n<PATH>\n<TS>\n<hex(SHA256(body))>"，ECDSA/SHA256 ASN.1 签名 base64）。
//	      -tamper signature：生成合法三头后翻转签名中间一字节（仍为合法 base64），
//	      用于"PoP 头存在但签名校验失败 → 401 绝不降级 Bearer"的防降级负例。
//	poptool csr -new-key-out rotated.key
//	      生成新 P-256 密钥（SEC1 "EC PRIVATE KEY" PEM，0600 落盘）并向 stdout 打印
//	      CN 留空的 PKCS#10 CSR PEM（契约 §7 口径，供 rotate-cert 请求体 csr_pem）。
//	poptool fingerprint -cert agent.crt
//	      打印证书 DER 的 SHA-256 hex 指纹（与服务端 CertFingerprint 同口径，
//	      用于断言管理端 cert_fingerprint 已切换到新证书）。
//
// 仅依赖标准库；私钥格式兼容 SEC1 与 PKCS#8（与 wdsp-agent/internal/cert 同口径）。
package main

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/base64"
	"encoding/hex"
	"encoding/pem"
	"errors"
	"flag"
	"fmt"
	"os"
	"strconv"
	"time"
)

func main() {
	if len(os.Args) < 2 {
		usage()
		os.Exit(2)
	}
	var err error
	switch os.Args[1] {
	case "headers":
		err = cmdHeaders(os.Args[2:])
	case "csr":
		err = cmdCSR(os.Args[2:])
	case "fingerprint":
		err = cmdFingerprint(os.Args[2:])
	default:
		usage()
		os.Exit(2)
	}
	if err != nil {
		fmt.Fprintf(os.Stderr, "poptool %s: %v\n", os.Args[1], err)
		os.Exit(1)
	}
}

func usage() {
	fmt.Fprintf(os.Stderr, `用法:
  poptool headers -key K -cert C -method M -path P [-body-file F] [-tamper signature]
  poptool csr -new-key-out K
  poptool fingerprint -cert C
`)
}

// loadKey 解析 PEM 私钥（SEC1 优先，兼容 PKCS#8；须为 P-256）。
func loadKey(path string) (*ecdsa.PrivateKey, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	block, _ := pem.Decode(data)
	if block == nil {
		return nil, errors.New("非法私钥 PEM")
	}
	key, err := x509.ParseECPrivateKey(block.Bytes)
	if err != nil {
		k8, err8 := x509.ParsePKCS8PrivateKey(block.Bytes)
		if err8 != nil {
			return nil, fmt.Errorf("解析私钥: %w", err)
		}
		ek, ok := k8.(*ecdsa.PrivateKey)
		if !ok {
			return nil, errors.New("私钥非 ECDSA")
		}
		key = ek
	}
	if key.Curve != elliptic.P256() {
		return nil, errors.New("私钥曲线非 P-256")
	}
	return key, nil
}

// loadCert 解析证书 PEM。
func loadCert(path string) (*x509.Certificate, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	block, _ := pem.Decode(data)
	if block == nil || block.Type != "CERTIFICATE" {
		return nil, errors.New("非法证书 PEM")
	}
	return x509.ParseCertificate(block.Bytes)
}

// cmdHeaders 生成 PoP 三头（-tamper signature 时翻转签名一字节构造防降级负例）。
func cmdHeaders(args []string) error {
	fs := flag.NewFlagSet("headers", flag.ContinueOnError)
	keyPath := fs.String("key", "", "私钥 PEM（SEC1/PKCS8）")
	certPath := fs.String("cert", "", "客户端证书 PEM")
	method := fs.String("method", "", "HTTP 方法")
	path := fs.String("path", "", "请求路径（不含 host/query）")
	bodyFile := fs.String("body-file", "", "请求正文文件（缺省按空正文签名）")
	tamper := fs.String("tamper", "", "篡改对象（仅支持 signature）")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if *keyPath == "" || *certPath == "" || *method == "" || *path == "" {
		return errors.New("-key/-cert/-method/-path 均为必填")
	}
	key, err := loadKey(*keyPath)
	if err != nil {
		return err
	}
	cert, err := loadCert(*certPath)
	if err != nil {
		return err
	}
	pub, ok := cert.PublicKey.(*ecdsa.PublicKey)
	if !ok || !pub.Equal(key.Public()) {
		return errors.New("证书公钥与私钥不匹配")
	}
	var body []byte
	if *bodyFile != "" {
		if body, err = os.ReadFile(*bodyFile); err != nil {
			return err
		}
	}
	ts := strconv.FormatInt(time.Now().Unix(), 10)
	bodySum := sha256.Sum256(body)
	input := "POP\n" + *method + "\n" + *path + "\n" + ts + "\n" + hex.EncodeToString(bodySum[:])
	digest := sha256.Sum256([]byte(input))
	sig, err := ecdsa.SignASN1(rand.Reader, key, digest[:])
	if err != nil {
		return fmt.Errorf("签名: %w", err)
	}
	if *tamper == "signature" {
		// 翻转 ASN.1 签名中间一字节：base64 仍合法，ECDSA 校验必然失败
		sig[len(sig)/2] ^= 0x01
	} else if *tamper != "" {
		return fmt.Errorf("不支持的篡改对象: %q", *tamper)
	}
	fmt.Printf("X-WDSP-Agent-Cert: %s\n", base64.StdEncoding.EncodeToString(cert.Raw))
	fmt.Printf("X-WDSP-Agent-Timestamp: %s\n", ts)
	fmt.Printf("X-WDSP-Agent-Signature: %s\n", base64.StdEncoding.EncodeToString(sig))
	return nil
}

// cmdCSR 生成新密钥（0600 落盘）并输出 CN 留空的 CSR PEM（契约 §7 口径）。
func cmdCSR(args []string) error {
	fs := flag.NewFlagSet("csr", flag.ContinueOnError)
	keyOut := fs.String("new-key-out", "", "新私钥输出路径（0600）")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if *keyOut == "" {
		return errors.New("-new-key-out 必填")
	}
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return err
	}
	der, err := x509.MarshalECPrivateKey(key)
	if err != nil {
		return err
	}
	keyPEM := pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: der})
	if err := os.WriteFile(*keyOut, keyPEM, 0o600); err != nil {
		return err
	}
	csrDER, err := x509.CreateCertificateRequest(rand.Reader, &x509.CertificateRequest{
		Subject:            pkix.Name{}, // CN 留空，由服务端填 agent_id（契约 §7）
		SignatureAlgorithm: x509.ECDSAWithSHA256,
	}, key)
	if err != nil {
		return err
	}
	fmt.Print(string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE REQUEST", Bytes: csrDER})))
	return nil
}

// cmdFingerprint 打印证书 DER 的 SHA-256 hex 指纹（与服务端 CertFingerprint 同口径）。
func cmdFingerprint(args []string) error {
	fs := flag.NewFlagSet("fingerprint", flag.ContinueOnError)
	certPath := fs.String("cert", "", "客户端证书 PEM")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if *certPath == "" {
		return errors.New("-cert 必填")
	}
	cert, err := loadCert(*certPath)
	if err != nil {
		return err
	}
	sum := sha256.Sum256(cert.Raw)
	fmt.Println(hex.EncodeToString(sum[:]))
	return nil
}

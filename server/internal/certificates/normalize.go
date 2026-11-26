package certificates

import (
	"bytes"
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"strings"

	"github.com/emmansun/gmsm/smx509"
)

var utf8BOM = []byte{0xEF, 0xBB, 0xBF}

func stripUTF8BOM(b []byte) []byte {
	return bytes.TrimPrefix(b, utf8BOM)
}

func stripUTF8BOMString(s string) string {
	return strings.TrimPrefix(s, "\uFEFF")
}

// NormalizeCertFileToPEM 将上传的证书文件字节（支持 PEM 或 DER 编码）规范化为 PEM 文本。
// 若文件为包含多张证书的 PEM（如 fullchain.pem），原样保留完整 PEM 文本以维持证书链。
func NormalizeCertFileToPEM(data []byte, protocolType string) (string, error) {
	return normalizeCertLikeFileToPEM(data, protocolType, "证书")
}

// NormalizeChainFileToPEM 将上传的证书链文件字节（支持 PEM 或单张 DER 证书）规范化为 PEM 文本。
func NormalizeChainFileToPEM(data []byte, protocolType string) (string, error) {
	return normalizeCertLikeFileToPEM(data, protocolType, "证书链")
}

func normalizeCertLikeFileToPEM(data []byte, protocolType, label string) (string, error) {
	trimmed := bytes.TrimSpace(stripUTF8BOM(data))
	if len(trimmed) == 0 {
		return "", fmt.Errorf("%s文件内容不能为空: %w", label, ErrInvalidPEM)
	}
	if block, _ := pem.Decode(trimmed); block != nil {
		if strings.Contains(strings.ToUpper(block.Type), "PRIVATE KEY") {
			return "", fmt.Errorf("检测到私钥内容，请上传%s文件而非私钥: %w", label, ErrInvalidPEM)
		}
		if block.Type != "CERTIFICATE" {
			return "", fmt.Errorf("%s文件 PEM 块类型无效（期望 CERTIFICATE，实际 %s）: %w", label, block.Type, ErrInvalidPEM)
		}
		return string(trimmed), nil
	}

	protoType, err := NormalizeProtocolType(protocolType)
	if err != nil {
		return "", err
	}
	if protoType == ProtocolSMTLCP {
		if cert, err := smx509.ParseCertificate(data); err == nil {
			return strings.TrimSpace(string(pem.EncodeToMemory(&pem.Block{
				Type:  "CERTIFICATE",
				Bytes: cert.Raw,
			}))), nil
		}
	} else {
		if cert, err := x509.ParseCertificate(data); err == nil {
			return strings.TrimSpace(string(pem.EncodeToMemory(&pem.Block{
				Type:  "CERTIFICATE",
				Bytes: cert.Raw,
			}))), nil
		}
	}
	return "", fmt.Errorf("%s文件格式无效，请上传 PEM 或 DER 编码的证书文件: %w", label, ErrInvalidPEM)
}

// NormalizeKeyFileToPEM 将上传的私钥文件字节（支持未加密的 PEM 或 DER 编码）规范化为 PEM 文本。
func NormalizeKeyFileToPEM(data []byte, protocolType string) (string, error) {
	trimmed := bytes.TrimSpace(stripUTF8BOM(data))
	if len(trimmed) == 0 {
		return "", fmt.Errorf("私钥文件内容不能为空: %w", ErrInvalidKey)
	}
	if block, _ := pem.Decode(trimmed); block != nil {
		upperType := strings.ToUpper(block.Type)
		if upperType == "CERTIFICATE" {
			return "", fmt.Errorf("检测到证书内容，请上传私钥文件而非证书: %w", ErrInvalidKey)
		}
		if upperType == "ENCRYPTED PRIVATE KEY" ||
			strings.Contains(strings.ToUpper(block.Headers["Proc-Type"]), "ENCRYPTED") {
			return "", fmt.Errorf("暂不支持口令加密的私钥文件，请先解密私钥后再上传: %w", ErrInvalidKey)
		}
		return string(trimmed), nil
	}

	protoType, err := NormalizeProtocolType(protocolType)
	if err != nil {
		return "", err
	}
	if blockType, ok := detectDERPrivateKeyBlockType(data, protoType); ok {
		return strings.TrimSpace(string(pem.EncodeToMemory(&pem.Block{
			Type:  blockType,
			Bytes: data,
		}))), nil
	}
	return "", fmt.Errorf("私钥文件格式无效，请上传未加密的 PEM 或 DER 编码私钥文件: %w", ErrInvalidKey)
}

func detectDERPrivateKeyBlockType(raw []byte, protoType string) (string, bool) {
	if protoType == ProtocolSMTLCP {
		if _, err := smx509.ParsePKCS8PrivateKey(raw); err == nil {
			return "PRIVATE KEY", true
		}
		if _, err := smx509.ParseSM2PrivateKey(raw); err == nil {
			return "SM2 PRIVATE KEY", true
		}
		if _, err := smx509.ParseTypedECPrivateKey(raw); err == nil {
			return "EC PRIVATE KEY", true
		}
		return "", false
	}
	if _, err := x509.ParsePKCS8PrivateKey(raw); err == nil {
		return "PRIVATE KEY", true
	}
	if _, err := x509.ParsePKCS1PrivateKey(raw); err == nil {
		return "RSA PRIVATE KEY", true
	}
	if _, err := x509.ParseECPrivateKey(raw); err == nil {
		return "EC PRIVATE KEY", true
	}
	return "", false
}

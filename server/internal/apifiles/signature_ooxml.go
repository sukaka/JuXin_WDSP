package apifiles

import (
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"strings"

	gatewayresponse "github.com/jiuzhang-waf/gateway/dynamic_security/response"
)

const verifyOOXMLMaxBytes = 2 << 20

func decodeOOXMLSignaturePayload(encoded, format string) (string, string, error) {
	if format != "ooxml_zip" {
		return "", "", errors.New("文件载荷时 content_format 必须为 ooxml_zip")
	}
	raw, err := base64.StdEncoding.DecodeString(strings.TrimSpace(encoded))
	if err != nil {
		return "", "", errors.New("content_base64 不是有效的 Base64 文件")
	}
	if len(raw) == 0 || len(raw) > verifyOOXMLMaxBytes {
		return "", "", errors.New("OOXML 文件内容不能为空且不能超过 2 MiB")
	}
	original, token, found, err := gatewayresponse.RecoverOOXMLSignedContent(raw)
	if err != nil {
		return "", "", errors.New("OOXML 文件或签名注释格式非法")
	}
	if !found {
		return "", "", errors.New("OOXML 文件未包含签名注释")
	}
	sum := sha256.Sum256(original)
	return hex.EncodeToString(sum[:]), token, nil
}

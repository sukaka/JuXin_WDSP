package response

import (
	"crypto/sha256"
	"encoding/hex"
)

// FileContentSHA256 返回完整观测内容的 SHA-256 小写十六进制指纹，不包含正文。
func FileContentSHA256(body []byte) string {
	sum := sha256.Sum256(body)
	return hex.EncodeToString(sum[:])
}

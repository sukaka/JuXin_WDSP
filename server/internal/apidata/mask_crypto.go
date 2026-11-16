package apidata

import (
	"context"
	"encoding/base64"
	"encoding/hex"
	"net/http"
	"strings"
	"unicode/utf8"

	"github.com/jiuzhang-waf/server/internal/audits"
	"github.com/jiuzhang-waf/server/internal/authz"
	"github.com/jiuzhang-waf/server/internal/encryption"
	"github.com/jiuzhang-waf/server/internal/response"
)

const (
	decryptBodyMaxBytes       = 8192
	maxMaskCiphertextLen      = 4096
	maxMaskCryptoKIDLen       = 64
	maskCryptoKeyBytes        = 32
	maskCiphertextPrefix      = "enc_"
	maskCryptoUnavailableText = "脱敏加密密钥未配置或不可用"
)

type MaskCryptoLoader func(ctx context.Context) (kid, keyHex string, err error)

func (h *Handler) SetMaskCryptoLoader(l MaskCryptoLoader) *Handler {
	h.maskCrypto = l
	return h
}

func parseMaskCiphertext(raw string) (kid, encoded string, ok bool) {
	raw = strings.TrimSpace(raw)
	if raw == "" || len(raw) > maxMaskCiphertextLen || !strings.HasPrefix(raw, maskCiphertextPrefix) {
		return "", "", false
	}
	rest := strings.TrimPrefix(raw, maskCiphertextPrefix)
	separator := strings.LastIndex(rest, "_")
	if separator <= 0 || separator == len(rest)-1 {
		return "", "", false
	}
	kid, encoded = rest[:separator], rest[separator+1:]
	if utf8.RuneCountInString(kid) > maxMaskCryptoKIDLen {
		return "", "", false
	}
	for _, r := range kid {
		if (r >= 'a' && r <= 'z') || (r >= 'A' && r <= 'Z') || (r >= '0' && r <= '9') || r == '_' || r == '-' {
			continue
		}
		return "", "", false
	}
	if _, err := base64.StdEncoding.DecodeString(encoded); err != nil {
		return "", "", false
	}
	return kid, encoded, true
}

func (h *Handler) DecryptMaskingRule(w http.ResponseWriter, r *http.Request) {
	p := authz.PrincipalFrom(r.Context())
	if h.maskCrypto == nil {
		response.Error(w, r, http.StatusServiceUnavailable, response.CodeServiceUnavailable, maskCryptoUnavailableText)
		return
	}
	kid, keyHex, err := h.maskCrypto(r.Context())
	if err != nil || kid == "" || keyHex == "" {
		response.Error(w, r, http.StatusServiceUnavailable, response.CodeServiceUnavailable, maskCryptoUnavailableText)
		return
	}
	var req struct {
		Ciphertext string `json:"ciphertext"`
	}
	if err := response.DecodeJSON(w, r, &req, decryptBodyMaxBytes); err != nil {
		response.Error(w, r, http.StatusBadRequest, response.CodeInvalidArgument, "请求格式错误")
		return
	}
	ciphertextKID, encoded, ok := parseMaskCiphertext(req.Ciphertext)
	if !ok || ciphertextKID != kid {
		response.Error(w, r, http.StatusBadRequest, response.CodeInvalidArgument, "ciphertext 格式或 kid 不匹配")
		return
	}
	key, err := hex.DecodeString(keyHex)
	if err != nil || len(key) != maskCryptoKeyBytes {
		response.Error(w, r, http.StatusServiceUnavailable, response.CodeServiceUnavailable, maskCryptoUnavailableText)
		return
	}
	crypto, err := encryption.NewWithKey(key)
	if err != nil {
		response.Error(w, r, http.StatusServiceUnavailable, response.CodeServiceUnavailable, maskCryptoUnavailableText)
		return
	}
	plaintext, err := crypto.Decrypt(encoded)
	if err != nil {
		response.Error(w, r, http.StatusBadRequest, response.CodeInvalidArgument, "ciphertext 解密失败")
		return
	}
	h.recordAudit(r, p, "decrypt", "api_mask_crypto", kid, "脱敏数据还原", "", `{"kid":"`+kid+`"}`,
		audits.ResultSuccess, audits.RiskHigh)
	response.JSON(w, r, http.StatusOK, map[string]string{"plaintext": plaintext})
}

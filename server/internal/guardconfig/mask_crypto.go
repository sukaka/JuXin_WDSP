package guardconfig

import (
	"context"
	"encoding/hex"
	"fmt"
	"strings"
	"unicode/utf8"

	"github.com/jiuzhang-waf/server/internal/gatewayconfig"
)

const (
	maskCryptoKIDSettingsKey = "api_mask_encryption_kid"
	maskCryptoKeySettingsKey = "api_mask_encryption_key"
	maskCryptoKeyBytes       = 32
	maxMaskCryptoKIDLen      = 64
)

type MaskCryptoLoader func(ctx context.Context) (kid, keyHex string, err error)

func NewMaskCryptoLoader(
	get func(ctx context.Context, group, key, def string) string,
	decrypt func(encoded string) (string, error),
) MaskCryptoLoader {
	return func(ctx context.Context) (string, string, error) {
		if get == nil || decrypt == nil {
			return "", "", fmt.Errorf("mask crypto loader: settings/encryption 未装配")
		}
		kid := strings.TrimSpace(get(ctx, GatewayRuntimeSettingsGroup, maskCryptoKIDSettingsKey, ""))
		raw := strings.TrimSpace(get(ctx, GatewayRuntimeSettingsGroup, maskCryptoKeySettingsKey, ""))
		if kid == "" && raw == "" {
			return "", "", nil
		}
		if kid == "" || raw == "" {
			return "", "", fmt.Errorf("api mask encryption kid/key 必须同时配置")
		}
		if utf8.RuneCountInString(kid) > maxMaskCryptoKIDLen {
			return "", "", fmt.Errorf("gateway_runtime.api_mask_encryption_kid 长度超过 %d", maxMaskCryptoKIDLen)
		}
		for _, r := range kid {
			if (r >= 'a' && r <= 'z') || (r >= 'A' && r <= 'Z') || (r >= '0' && r <= '9') || r == '_' || r == '-' {
				continue
			}
			return "", "", fmt.Errorf("gateway_runtime.api_mask_encryption_kid 仅允许 [A-Za-z0-9_-]")
		}
		plain, err := decrypt(raw)
		if err != nil {
			return "", "", fmt.Errorf("decrypt api mask encryption key: %w", err)
		}
		key, err := hex.DecodeString(strings.TrimSpace(plain))
		if err != nil || len(key) != maskCryptoKeyBytes {
			return "", "", fmt.Errorf("api mask encryption key 格式非法（须 %d 字节 hex）", maskCryptoKeyBytes)
		}
		return kid, hex.EncodeToString(key), nil
	}
}

func (p *Provider) SetMaskCryptoLoader(l MaskCryptoLoader) { p.maskCrypto = l }

func maskRulesNeedCrypto(rules []gatewayconfig.GuardMaskRule) bool {
	for _, rule := range rules {
		if rule.Algorithm == "ENCRYPT" || rule.Algorithm == "MAP" {
			return true
		}
	}
	return false
}

func (p *Provider) loadAPIMaskCrypto(ctx context.Context, rules []gatewayconfig.GuardMaskRule) (*gatewayconfig.GuardMaskCrypto, error) {
	if !maskRulesNeedCrypto(rules) {
		return nil, nil
	}
	if p.maskCrypto == nil {
		return nil, fmt.Errorf("api_mask_encryption_key 未配置且存在 ENCRYPT/MAP 脱敏规则")
	}
	kid, keyHex, err := p.maskCrypto(ctx)
	if err != nil {
		return nil, fmt.Errorf("load api mask crypto: %w", err)
	}
	if kid == "" || keyHex == "" {
		return nil, fmt.Errorf("api_mask_encryption_kid/key 未配置且存在 ENCRYPT/MAP 脱敏规则")
	}
	key, err := hex.DecodeString(keyHex)
	if err != nil || len(key) != maskCryptoKeyBytes {
		return nil, fmt.Errorf("api mask crypto loader 返回非 32 字节 hex 密钥")
	}
	return &gatewayconfig.GuardMaskCrypto{KID: kid, KeyHex: hex.EncodeToString(key)}, nil
}

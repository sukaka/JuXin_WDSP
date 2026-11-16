package jiuzhang_guard

import (
	"encoding/hex"
	"fmt"
	"strings"

	"github.com/jiuzhang-waf/gateway/dynamic_security/response"
)

func compileAPIMaskCrypto(config *maskCryptoJSON, rules map[string][]response.MaskRule) (*response.MaskCrypto, error) {
	needsCrypto := false
	for _, endpointRules := range rules {
		for _, rule := range endpointRules {
			if rule.Algorithm == response.AlgorithmEncrypt || rule.Algorithm == response.AlgorithmMap {
				needsCrypto = true
			}
		}
	}
	if config == nil {
		if needsCrypto {
			return nil, fmt.Errorf("api_mask_crypto is required for ENCRYPT/MAP rules")
		}
		return nil, nil
	}
	key, err := hex.DecodeString(strings.TrimSpace(config.KeyHex))
	if err != nil {
		return nil, fmt.Errorf("api_mask_crypto: invalid key_hex")
	}
	crypto, err := response.NewMaskCrypto(config.Kid, key)
	if err != nil {
		return nil, fmt.Errorf("api_mask_crypto: %w", err)
	}
	for endpointKey, endpointRules := range rules {
		for _, rule := range endpointRules {
			if rule.Algorithm == response.AlgorithmEncrypt && rule.KeyID != config.Kid {
				return nil, fmt.Errorf("api_mask_crypto kid mismatch for ENCRYPT rule on %s", endpointKey)
			}
		}
	}
	return crypto, nil
}

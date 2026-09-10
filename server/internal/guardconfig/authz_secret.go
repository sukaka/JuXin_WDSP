package guardconfig

import (
	"context"
	"encoding/hex"
	"fmt"
	"strings"
)

type AuthzObjectHMACKeyLoader func(context.Context) (string, error)

func NewAuthzObjectHMACKeyLoader(get func(context.Context, string, string, string) string, decrypt func(string) (string, error)) AuthzObjectHMACKeyLoader {
	return func(ctx context.Context) (string, error) {
		if get == nil || decrypt == nil {
			return "", fmt.Errorf("authz object HMAC key loader is not configured")
		}
		raw := strings.TrimSpace(get(ctx, "api_authz", "object_hmac_key", ""))
		if raw == "" {
			return "", nil
		}
		plain, err := decrypt(raw)
		if err != nil {
			return "", fmt.Errorf("decrypt api authz object HMAC key: %w", err)
		}
		key, err := hex.DecodeString(strings.TrimSpace(plain))
		if err != nil || len(key) != 32 {
			return "", fmt.Errorf("api authz object HMAC key must be 32-byte hex")
		}
		return hex.EncodeToString(key), nil
	}
}

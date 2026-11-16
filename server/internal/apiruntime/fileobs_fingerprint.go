package apiruntime

import (
	"encoding/hex"
	"strings"
)

func normalizedFileSHA256(raw string) *string {
	value := strings.ToLower(strings.TrimSpace(raw))
	if len(value) != 64 {
		return nil
	}
	decoded, err := hex.DecodeString(value)
	if err != nil || len(decoded) != 32 {
		return nil
	}
	return &value
}

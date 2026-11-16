package jiuzhang_guard

import (
	"fmt"
	"regexp"
)

const maxIdentityBlockIDBytes = 64

var (
	identityBlockIDPattern  = regexp.MustCompile(`^[A-Za-z0-9_-]+$`)
	identityBlockKeyPattern = regexp.MustCompile(`^[0-9a-f]{32}$`)
)

type identityBlockJSON struct {
	ID          string `json:"id"`
	IdentityKey string `json:"identity_key"`
}

func compileAPIIdentityBlocks(in []identityBlockJSON) (map[string]string, error) {
	if len(in) == 0 {
		return nil, nil
	}
	out := make(map[string]string, len(in))
	ids := make(map[string]struct{}, len(in))
	for i, item := range in {
		if item.ID == "" || len(item.ID) > maxIdentityBlockIDBytes || !identityBlockIDPattern.MatchString(item.ID) {
			return nil, fmt.Errorf("api_identity_blocks[%d]: invalid id", i)
		}
		if !identityBlockKeyPattern.MatchString(item.IdentityKey) {
			return nil, fmt.Errorf("api_identity_blocks[%d]: invalid identity_key", i)
		}
		if _, duplicate := ids[item.ID]; duplicate {
			return nil, fmt.Errorf("api_identity_blocks[%d]: duplicate id", i)
		}
		if _, duplicate := out[item.IdentityKey]; duplicate {
			return nil, fmt.Errorf("api_identity_blocks[%d]: duplicate identity_key", i)
		}
		ids[item.ID] = struct{}{}
		out[item.IdentityKey] = item.ID
	}
	return out, nil
}

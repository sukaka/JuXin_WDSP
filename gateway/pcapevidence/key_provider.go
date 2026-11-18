package pcapevidence

import (
	"context"
	"crypto/rand"
	"fmt"

	"github.com/jiuzhang-waf/gateway/dynamic_security/evidencekey"
)

// PublicKeyDEKProvider 只保存管理面分发的证据公钥，不持有私钥或主密钥。
type PublicKeyDEKProvider struct {
	publicKey []byte
	keyID     string
}

func NewPublicKeyDEKProvider(publicKey []byte) (*PublicKeyDEKProvider, error) {
	keyID, err := evidencekey.PublicKeyID(publicKey)
	if err != nil {
		return nil, err
	}
	return &PublicKeyDEKProvider{publicKey: append([]byte(nil), publicKey...), keyID: keyID}, nil
}

func (p *PublicKeyDEKProvider) NewDEK(ctx context.Context) (DEK, error) {
	if p == nil || len(p.publicKey) == 0 {
		return DEK{}, fmt.Errorf("evidence public key is not configured")
	}
	if err := ctx.Err(); err != nil {
		return DEK{}, err
	}
	key := make([]byte, 32)
	if _, err := rand.Read(key); err != nil {
		return DEK{}, err
	}
	envelope, keyID, err := evidencekey.WrapDEK(p.publicKey, key)
	if err != nil {
		clear(key)
		return DEK{}, err
	}
	if keyID != p.keyID {
		clear(key)
		return DEK{}, fmt.Errorf("evidence key id changed during wrapping")
	}
	return DEK{Key: key, KeyID: keyID, WrappedKey: envelope}, nil
}

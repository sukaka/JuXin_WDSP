package pcapevidence

import (
	"context"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"time"

	"github.com/jiuzhang-waf/gateway/dynamic_security/evidencekey"
)

type SignedPublicKeyProvider struct {
	TrustPath string
	GrantPath string
	NodeID    string
	now       func() time.Time
}

func NewSignedPublicKeyProvider(trustPath, grantPath, nodeID string) (*SignedPublicKeyProvider, error) {
	if !filepath.IsAbs(trustPath) || !filepath.IsAbs(grantPath) || nodeID == "" {
		return nil, fmt.Errorf("absolute trust and grant paths and node are required")
	}
	provider := &SignedPublicKeyProvider{TrustPath: trustPath, GrantPath: grantPath, NodeID: nodeID, now: func() time.Time { return time.Now().UTC() }}
	if _, _, err := provider.publicKey(); err != nil {
		return nil, err
	}
	return provider, nil
}

func (p *SignedPublicKeyProvider) publicKey() ([]byte, string, error) {
	trust, err := readPublicKeyFile(p.TrustPath, 128)
	if err != nil {
		return nil, "", fmt.Errorf("read evidence release trust key: %w", err)
	}
	grant, err := readPublicKeyFile(p.GrantPath, 64<<10)
	if err != nil {
		return nil, "", fmt.Errorf("read evidence public key grant: %w", err)
	}
	return evidencekey.VerifyPublicKeyGrant(grant, trust, p.NodeID, p.now())
}

func (p *SignedPublicKeyProvider) NewDEK(ctx context.Context) (DEK, error) {
	if err := ctx.Err(); err != nil {
		return DEK{}, err
	}
	publicKey, _, err := p.publicKey()
	if err != nil {
		return DEK{}, err
	}
	provider, err := NewPublicKeyDEKProvider(publicKey)
	if err != nil {
		return DEK{}, err
	}
	return provider.NewDEK(ctx)
}

func readPublicKeyFile(path string, limit int64) ([]byte, error) {
	before, err := os.Lstat(path)
	if err != nil || !before.Mode().IsRegular() {
		return nil, fmt.Errorf("evidence public key is not a regular file")
	}
	file, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer file.Close()
	after, err := file.Stat()
	if err != nil || !os.SameFile(before, after) || after.Mode().Perm()&0o022 != 0 {
		return nil, fmt.Errorf("evidence public key is writable by group or others")
	}
	data, err := io.ReadAll(io.LimitReader(file, limit+1))
	if err != nil || int64(len(data)) > limit {
		return nil, fmt.Errorf("evidence public key file is too large or unreadable")
	}
	return data, nil
}

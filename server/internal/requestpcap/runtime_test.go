package requestpcap

import (
	"bytes"
	"context"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/jiuzhang-waf/gateway/pcapevidence"
	"github.com/jiuzhang-waf/server/internal/config"
	"github.com/jiuzhang-waf/server/internal/encryption"
)

func TestRuntimePublishesUsableGrantAndRotatesWithoutLosingHistory(t *testing.T) {
	directory := t.TempDir()
	hotRoot, warmRoot := filepath.Join(directory, "hot"), filepath.Join(directory, "warm")
	if err := os.Mkdir(hotRoot, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.Mkdir(warmRoot, 0o700); err != nil {
		t.Fatal(err)
	}
	master, err := encryption.NewWithKey(bytes.Repeat([]byte{25}, 32))
	if err != nil {
		t.Fatal(err)
	}
	runtime, err := NewRuntime(&pgxpool.Pool{}, config.RequestPCAPConfig{HotDir: hotRoot, WarmDir: warmRoot,
		KeyFile: filepath.Join(directory, "private.key"), Retention: time.Hour, HotAge: time.Minute, GrantTTL: time.Hour,
		MigrateBytesPerSecond: 32 << 20, MinFreePercent: 10}, "gw-runtime", master)
	if err != nil {
		t.Fatal(err)
	}
	defer runtime.Keyring.Close()
	provider, err := pcapevidence.NewSignedPublicKeyProvider(runtime.trustPath, runtime.grantPath, "gw-runtime")
	if err != nil {
		t.Fatal(err)
	}
	dek, err := provider.NewDEK(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	keyID := dek.KeyID
	if err := runtime.Rotate(); err != nil {
		t.Fatal(err)
	}
	oldDEK, err := runtime.Keyring.Unwrap(keyID, dek.WrappedKey)
	if err != nil || !bytes.Equal(oldDEK, dek.Key) {
		t.Fatalf("old evidence key was lost after rotation: %v", err)
	}
	clear(oldDEK)
	clear(dek.Key)
	provider, err = pcapevidence.NewSignedPublicKeyProvider(runtime.trustPath, runtime.grantPath, "gw-runtime")
	if err != nil {
		t.Fatal(err)
	}
	newDEK, err := provider.NewDEK(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	defer clear(newDEK.Key)
	if newDEK.KeyID == keyID {
		t.Fatal("daemon grant did not rotate to the new key")
	}
}

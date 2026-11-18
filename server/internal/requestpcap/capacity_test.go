package requestpcap

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"os"
	"path/filepath"
	"testing"
	"time"
)

func TestThrottledMigrationWriterAndCancellation(t *testing.T) {
	var output bytes.Buffer
	writer := &throttledWriter{writer: &output, rate: 8192}
	started := time.Now()
	if _, err := writer.Write(bytes.Repeat([]byte{7}, 8192)); err != nil {
		t.Fatal(err)
	}
	if elapsed := time.Since(started); elapsed < 900*time.Millisecond {
		t.Fatalf("migration writer was not throttled: %v", elapsed)
	}
	hotRoot, warmRoot := t.TempDir(), t.TempDir()
	payload := bytes.Repeat([]byte{9}, 128<<10)
	path := filepath.Join(hotRoot, "source.wpcap")
	if err := os.WriteFile(path, payload, 0o600); err != nil {
		t.Fatal(err)
	}
	hash := sha256.Sum256(payload)
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	err := copyArtifactFile(ctx, path, filepath.Join(warmRoot, "target.wpcap"), hex.EncodeToString(hash[:]), int64(len(payload)), 1)
	if !errors.Is(err, context.Canceled) {
		t.Fatalf("canceled copy error=%v", err)
	}
	entries, err := os.ReadDir(warmRoot)
	if err != nil || len(entries) != 0 {
		t.Fatalf("canceled migration left a temporary or published file: %+v err=%v", entries, err)
	}
}

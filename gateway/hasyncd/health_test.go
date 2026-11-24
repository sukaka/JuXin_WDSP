package hasyncd

import (
	"context"
	"os"
	"path/filepath"
	"testing"
	"time"
)

func TestHealthStampWriteAndCheck(t *testing.T) {
	tmp := t.TempDir()
	stampPath := filepath.Join(tmp, "hasyncd-health.json")
	now := time.Now().UTC()

	// Missing stamp fails.
	if err := CheckHealthStamp(stampPath, now, DefaultHealthStampMaxAge); err == nil {
		t.Fatal("expected missing stamp to fail")
	}

	// Valid stamp passes.
	if err := WriteHealthStamp(stampPath, HealthStamp{
		PID:       os.Getpid(),
		Node:      "gw-b",
		Listen:    "127.0.0.1:18443",
		Ready:     true,
		UpdatedAt: now,
	}); err != nil {
		t.Fatalf("WriteHealthStamp: %v", err)
	}
	if err := CheckHealthStamp(stampPath, now.Add(5*time.Second), DefaultHealthStampMaxAge); err != nil {
		t.Fatalf("expected fresh stamp to pass: %v", err)
	}

	// Stale stamp fails.
	if err := CheckHealthStamp(stampPath, now.Add(31*time.Second), DefaultHealthStampMaxAge); err == nil {
		t.Fatal("expected stale stamp to fail")
	}

	// Ready=false fails.
	if err := WriteHealthStamp(stampPath, HealthStamp{
		PID:       os.Getpid(),
		Node:      "gw-b",
		Ready:     false,
		UpdatedAt: now,
	}); err != nil {
		t.Fatal(err)
	}
	if err := CheckHealthStamp(stampPath, now, DefaultHealthStampMaxAge); err == nil {
		t.Fatal("expected Ready=false stamp to fail")
	}
}

func TestServerRunLifecycleAndHealthStamp(t *testing.T) {
	tmp := t.TempDir()
	secretFile := filepath.Join(tmp, "secret.key")
	stampPath := filepath.Join(tmp, "health.json")
	if err := os.WriteFile(secretFile, []byte(testSharedSecretHex), 0o600); err != nil {
		t.Fatal(err)
	}

	srv, err := NewServer(Config{
		ListenAddr:        "127.0.0.1:0",
		NodeName:          "gw-b",
		SecretFile:        secretFile,
		HealthStampPath:   stampPath,
		HealthStampPeriod: 50 * time.Millisecond,
	})
	if err != nil {
		t.Fatalf("NewServer: %v", err)
	}

	ctx, cancel := context.WithCancel(context.Background())
	errCh := make(chan error, 1)
	go func() { errCh <- srv.Run(ctx) }()

	// Wait for health stamp to appear and pass CheckHealthStamp.
	deadline := time.Now().Add(3 * time.Second)
	for {
		if err := CheckHealthStamp(stampPath, time.Now().UTC(), DefaultHealthStampMaxAge); err == nil {
			break
		}
		if time.Now().After(deadline) {
			cancel()
			t.Fatal("timed out waiting for healthy stamp from running server")
		}
		time.Sleep(20 * time.Millisecond)
	}

	cancel()
	if err := <-errCh; err != nil {
		t.Fatalf("Server.Run returned error on clean cancel: %v", err)
	}
	// Health stamp should be cleaned up on shutdown.
	if _, err := os.Stat(stampPath); !os.IsNotExist(err) {
		t.Fatalf("expected health stamp removed on shutdown, err=%v", err)
	}
}

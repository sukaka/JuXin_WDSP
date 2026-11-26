package main

import (
	"bytes"
	"context"
	"encoding/json"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/jiuzhang-waf/gateway/xdpguard"
)

func shortTempSocketDir(t *testing.T) string {
	t.Helper()
	dir, err := os.MkdirTemp("/tmp", "xdpcmd-*")
	if err != nil {
		t.Fatalf("create short temp dir: %v", err)
	}
	t.Cleanup(func() { _ = os.RemoveAll(dir) })
	return dir
}

func TestRunRejectsInvalidFlagsAndForbiddenInterfaces(t *testing.T) {
	tmpDir := shortTempSocketDir(t)
	sock := filepath.Join(tmpDir, "xdp.sock")
	var logBuf bytes.Buffer

	if err := run(context.Background(), []string{"--socket", sock, "--attach-mode", "bogus"}, &logBuf); err == nil {
		t.Fatal("expected error for invalid attach-mode")
	}
	if err := run(context.Background(), []string{"--socket", sock, "--interfaces", "lo"}, &logBuf); err == nil {
		t.Fatal("expected error for forbidden loopback interface")
	}
	if err := run(context.Background(), []string{"--socket", sock, "--interfaces", "eth0", "--exclude-interfaces", "eth0"}, &logBuf); err == nil {
		t.Fatal("expected error when default interface is excluded")
	}
	if err := run(context.Background(), []string{"--socket", "relative.sock"}, &logBuf); err == nil {
		t.Fatal("expected error for relative socket path")
	}
}

func TestRunServesUnixSocketAndCleansUpOnCancel(t *testing.T) {
	tmpDir := shortTempSocketDir(t)
	sock := filepath.Join(tmpDir, "xdp.sock")
	var logBuf bytes.Buffer

	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() {
		done <- run(ctx, []string{
			"--socket", sock,
			"--attach-mode", "auto",
			"--exclude-interfaces", "eno1",
		}, &logBuf)
	}()

	// Wait for Unix socket to come up.
	deadline := time.Now().Add(3 * time.Second)
	for time.Now().Before(deadline) {
		if fi, err := os.Lstat(sock); err == nil && fi.Mode()&os.ModeSocket != 0 {
			break
		}
		time.Sleep(20 * time.Millisecond)
	}

	client := &http.Client{
		Timeout: 2 * time.Second,
		Transport: &http.Transport{
			DialContext: func(dctx context.Context, _, _ string) (net.Conn, error) {
				var d net.Dialer
				return d.DialContext(dctx, "unix", sock)
			},
		},
	}

	resp, err := client.Get("http://unix/healthz")
	if err != nil {
		cancel()
		t.Fatalf("GET /healthz failed: %v (logs: %s)", err, logBuf.String())
	}
	var hz xdpguard.HealthzResponse
	if err := json.NewDecoder(resp.Body).Decode(&hz); err != nil {
		resp.Body.Close()
		cancel()
		t.Fatalf("decode healthz failed: %v", err)
	}
	resp.Body.Close()
	if hz.Status != xdpguard.StatusOK || hz.Mode != xdpguard.ModeFallbackUserspace || hz.KernelAttached {
		cancel()
		t.Fatalf("unexpected healthz response: %+v", hz)
	}

	cancel()
	select {
	case err := <-done:
		if err != nil {
			t.Fatalf("run returned unexpected error on shutdown: %v", err)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("timed out waiting for xdpguard graceful shutdown")
	}

	if _, err := os.Lstat(sock); !os.IsNotExist(err) {
		t.Fatalf("expected socket to be cleaned up on exit, err=%v", err)
	}
}

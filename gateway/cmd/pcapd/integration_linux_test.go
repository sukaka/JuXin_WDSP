//go:build linux

package main

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"syscall"
	"testing"
	"time"

	"github.com/jiuzhang-waf/gateway/dynamic_security/evidencekey"
	"github.com/jiuzhang-waf/gateway/pcapevidence"
)

func TestPCAPDHelperProcess(t *testing.T) {
	if os.Getenv("PCAPD_TEST_HELPER") != "1" {
		t.Skip("helper process")
	}
	separator := 0
	for i, arg := range os.Args {
		if arg == "--" {
			separator = i
			break
		}
	}
	os.Args = append([]string{"pcapd"}, os.Args[separator+1:]...)
	flag.CommandLine = flag.NewFlagSet("pcapd", flag.ContinueOnError)
	if err := run(); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
	os.Exit(0)
}

func TestPCAPDRealProcessCapturesEncryptedHTTP(t *testing.T) {
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	server := &http.Server{Handler: http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = io.WriteString(w, "daemon-pcap-response")
	})}
	go func() { _ = server.Serve(listener) }()
	defer server.Close()
	port := listener.Addr().(*net.TCPAddr).Port
	directory := t.TempDir()
	if err := os.Chmod(filepath.Dir(directory), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(directory, 0o755); err != nil {
		t.Fatal(err)
	}
	hotRoot := filepath.Join(directory, "hot")
	if err := os.Mkdir(hotRoot, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(hotRoot, 0o777); err != nil {
		t.Fatal(err)
	}
	releasePublic, releasePrivate, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	pair, err := evidencekey.GenerateKeyPair()
	if err != nil {
		t.Fatal(err)
	}
	now := time.Now().UTC()
	grant, err := evidencekey.SignPublicKeyGrant(pair.PublicKey, releasePrivate, "gw-daemon", now.Add(-time.Second), now.Add(time.Hour))
	if err != nil {
		t.Fatal(err)
	}
	trustPath, grantPath := filepath.Join(directory, "release.pub"), filepath.Join(directory, "grant.json")
	if err := os.WriteFile(trustPath, releasePublic, 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(grantPath, grant, 0o644); err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()
	command := exec.CommandContext(ctx, os.Args[0], "-test.run=^TestPCAPDHelperProcess$", "--",
		"--iface=lo", fmt.Sprintf("--ports=%d", port), "--node=gw-daemon", "--hot-dir="+hotRoot,
		"--grant="+grantPath, "--trust="+trustPath, "--policy-version=policy-daemon-test", "--segment-seconds=1", "--min-free-percent=1")
	command.Env = append(os.Environ(), "PCAPD_TEST_HELPER=1", "PCAPD_DEBUG_LINK=1")
	var logs bytes.Buffer
	command.Stdout, command.Stderr = &logs, &logs
	if err := command.Start(); err != nil {
		t.Fatal(err)
	}
	defer func() {
		if command.ProcessState == nil {
			_ = command.Process.Kill()
			_, _ = command.Process.Wait()
		}
	}()
	time.Sleep(200 * time.Millisecond)
	for i := 0; i < 3; i++ {
		request, err := http.NewRequest(http.MethodGet, fmt.Sprintf("http://127.0.0.1:%d/v1/daemon", port), nil)
		if err != nil {
			t.Fatal(err)
		}
		request.Header.Set("X-Request-Id", fmt.Sprintf("req-daemon-%d", i))
		request.Header.Set("Traceparent", "00-0123456789abcdef0123456789abcdef-0123456789abcdef-01")
		response, err := http.DefaultClient.Do(request)
		if err != nil {
			_ = command.Process.Signal(syscall.SIGTERM)
			_ = command.Wait()
			if os.Getenv("PCAPD_REQUIRE_LIVE") != "1" && strings.Contains(logs.String(), "operation not permitted") {
				t.Skip("real pcapd capture requires an explicitly authorized NET_RAW environment")
			}
			t.Fatalf("real pcapd HTTP request failed: %v logs=%s", err, logs.String())
		}
		_, _ = io.Copy(io.Discard, response.Body)
		response.Body.Close()
	}
	time.Sleep(1500 * time.Millisecond)
	if err := command.Process.Signal(syscall.SIGTERM); err != nil {
		t.Fatal(err)
	}
	if err := command.Wait(); err != nil {
		t.Fatalf("pcapd process failed: %v logs=%s", err, logs.String())
	}
	entries, err := os.ReadDir(hotRoot)
	if err != nil {
		t.Fatal(err)
	}
	seenRequests := make(map[string]bool)
	foundResponse := false
	segments := 0
	for _, entry := range entries {
		if filepath.Ext(entry.Name()) != ".json" {
			continue
		}
		segments++
		sealedPath := filepath.Join(hotRoot, entry.Name())
		payload, err := os.ReadFile(sealedPath)
		if err != nil {
			t.Fatal(err)
		}
		var record struct {
			Manifest   pcapevidence.Manifest          `json:"manifest"`
			KeyID      string                         `json:"key_id"`
			WrappedKey []byte                         `json:"wrapped_key"`
			Requests   []pcapevidence.RequestEvidence `json:"requests"`
		}
		if err := json.Unmarshal(payload, &record); err != nil {
			t.Fatal(err)
		}
		if record.Manifest.Segment.NodeID != "gw-daemon" || record.Manifest.Segment.PolicyVersion != "policy-daemon-test" || record.Manifest.Segment.Truncated {
			t.Fatalf("unexpected real daemon evidence metadata: %+v", record.Manifest.Segment)
		}
		for _, request := range record.Requests {
			if request.Path != "/v1/daemon" || request.FirstPacketNo == 0 || request.LastPacketNo < request.FirstPacketNo {
				t.Fatalf("real daemon request correlation missing: %+v", request)
			}
			seenRequests[request.RequestID] = true
		}
		key, err := evidencekey.UnwrapDEK(pair.PrivateKey, record.KeyID, record.WrappedKey)
		if err != nil {
			t.Fatal(err)
		}
		var plaintext bytes.Buffer
		pcapPath := sealedPath[:len(sealedPath)-5]
		if err := pcapevidence.VerifyAndDecrypt(pcapPath, record.Manifest, key, &plaintext); err != nil {
			clear(key)
			t.Fatal(err)
		}
		clear(key)
		foundResponse = foundResponse || bytes.Contains(plaintext.Bytes(), []byte("daemon-pcap-response"))
		ciphertext, err := os.ReadFile(pcapPath)
		if err != nil {
			t.Fatal(err)
		}
		if bytes.Contains(ciphertext, []byte("daemon-pcap-response")) {
			t.Fatal("daemon stored plaintext response in encrypted PCAP")
		}
	}
	if segments == 0 || len(seenRequests) != 3 || !foundResponse {
		t.Fatalf("real daemon evidence incomplete: segments=%d requests=%v response=%t logs=%s", segments, seenRequests, foundResponse, logs.String())
	}
}

package main

import (
	"bytes"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/json"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
	"time"

	"github.com/jiuzhang-waf/gateway/dynamic_security/evidencekey"
	"github.com/jiuzhang-waf/gateway/pcapevidence"
)

func TestPCAPDContainerRestrictedIdentityCapturesRealHTTP(t *testing.T) {
	image := os.Getenv("PCAPD_TEST_IMAGE")
	if image == "" {
		t.Skip("PCAPD_TEST_IMAGE not set, skipping container integration")
	}
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
	if os.Geteuid() == 0 {
		if err := os.Chown(hotRoot, 1000, 1000); err != nil {
			t.Fatal(err)
		}
	}
	releasePublic, releasePrivate, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	pair, err := evidencekey.GenerateKeyPair()
	if err != nil {
		t.Fatal(err)
	}
	grant, err := evidencekey.SignPublicKeyGrant(pair.PublicKey, releasePrivate, "gw-container", time.Now().Add(-time.Second), time.Now().Add(time.Hour))
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(directory, "release.pub"), releasePublic, 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(directory, "grant.json"), grant, 0o644); err != nil {
		t.Fatal(err)
	}
	name := fmt.Sprintf("jz-pcapd-container-%d", os.Getpid())
	run := func(args ...string) (string, error) {
		command := exec.Command("docker", args...)
		output, err := command.CombinedOutput()
		return string(output), err
	}
	originBinary := filepath.Join(directory, "http-origin")
	build := exec.Command("go", "build", "-o", originBinary, "./testdata")
	build.Env = append(os.Environ(), "CGO_ENABLED=0", "GOOS=linux", "GOARCH="+runtime.GOARCH)
	if output, err := build.CombinedOutput(); err != nil {
		t.Fatalf("build real HTTP origin: %v %s", err, output)
	}
	defer func() { _, _ = run("rm", "-f", name) }()
	output, err := run("run", "-d", "--name", name, "--network", "none", "--user", "0:0",
		"--cap-drop", "ALL", "--cap-add", "NET_RAW", "--cap-add", "SETUID", "--cap-add", "SETGID", "--security-opt", "no-new-privileges:true", "--read-only",
		"--tmpfs", "/tmp:rw,size=8m,mode=1777", "-v", directory+":/etc/jiuzhang:ro", "-v", hotRoot+":/var/lib/jiuzhang/pcap-hot",
		"-v", originBinary+":/usr/local/bin/pcap-test-origin:ro",
		image, "--iface=lo", "--ports=18082", "--node=gw-container", "--grant=/etc/jiuzhang/grant.json",
		"--trust=/etc/jiuzhang/release.pub", "--policy-version=container-test", "--segment-seconds=1", "--min-free-percent=1")
	if err != nil {
		t.Fatalf("start restricted PCAP container: %v %s", err, output)
	}
	output, err = run("exec", "-d", name, "/usr/local/bin/pcap-test-origin")
	if err != nil {
		logs, _ := run("logs", name)
		t.Fatalf("start real test HTTP origin: %v %s; pcapd logs=%s", err, output, logs)
	}
	time.Sleep(300 * time.Millisecond)
	for i := 0; i < 3; i++ {
		output, err = run("exec", name, "wget", "-q", "-O", "/dev/null", "--header", fmt.Sprintf("X-Request-Id: req-container-%d", i), "http://127.0.0.1:18082/")
		if err != nil {
			t.Fatalf("real HTTP request failed: %v %s", err, output)
		}
	}
	time.Sleep(1500 * time.Millisecond)
	output, err = run("stop", "--time", "10", name)
	if err != nil {
		logs, _ := run("logs", name)
		t.Fatalf("stop restricted PCAP container: %v %s %s", err, output, logs)
	}
	stoppedLogs, _ := run("logs", name)
	t.Logf("restricted pcapd logs: %s", stoppedLogs)
	entries, err := os.ReadDir(hotRoot)
	if err != nil {
		t.Fatal(err)
	}
	found := false
	totalRequests := 0
	for _, entry := range entries {
		if !strings.HasSuffix(entry.Name(), ".wpcap.json") {
			continue
		}
		found = true
		payload, err := os.ReadFile(filepath.Join(hotRoot, entry.Name()))
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
		if record.Manifest.Segment.Truncated || record.Manifest.Segment.DroppedCount != 0 {
			t.Fatalf("restricted container produced incomplete evidence: %+v", record.Manifest.Segment)
		}
		for _, request := range record.Requests {
			t.Logf("segment=%s request=%s path=%s range=%d..%d", entry.Name(), request.RequestID, request.Path, request.FirstPacketNo, request.LastPacketNo)
		}
		totalRequests += len(record.Requests)
		key, err := evidencekey.UnwrapDEK(pair.PrivateKey, record.KeyID, record.WrappedKey)
		if err != nil {
			t.Fatal(err)
		}
		var plaintext bytes.Buffer
		path := filepath.Join(hotRoot, strings.TrimSuffix(entry.Name(), ".json"))
		if err := pcapevidence.VerifyAndDecrypt(path, record.Manifest, key, &plaintext); err != nil {
			clear(key)
			t.Fatal(err)
		}
		clear(key)
		if !bytes.Contains(plaintext.Bytes(), []byte("container-real-pcap-response")) {
			t.Fatal("real HTTP response missing from restricted container PCAP")
		}
	}
	if !found || totalRequests != 3 {
		t.Fatalf("restricted container evidence incomplete: segments=%t requests=%d", found, totalRequests)
	}
}

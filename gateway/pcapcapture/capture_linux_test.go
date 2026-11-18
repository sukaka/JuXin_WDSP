//go:build linux

package pcapcapture

import (
	"bytes"
	"context"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/google/gopacket/pcapgo"
	"github.com/jiuzhang-waf/gateway/dynamic_security/evidencekey"
)

func TestCaptureRealHTTPToEncryptedPCAP(t *testing.T) {
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	server := &http.Server{Handler: http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = io.WriteString(w, "capture-evidence-response")
	})}
	go func() { _ = server.Serve(listener) }()
	defer server.Close()
	port := uint16(listener.Addr().(*net.TCPAddr).Port)

	keyPair, err := evidencekey.GenerateKeyPair()
	if err != nil {
		t.Fatal(err)
	}
	provider, err := NewPublicKeyDEKProvider(keyPair.PublicKey)
	if err != nil {
		t.Fatal(err)
	}
	sealedSegments := make(chan SealedSegment, 8)
	hotRoot := t.TempDir()
	if err := os.Chmod(filepath.Dir(hotRoot), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(hotRoot, 0o777); err != nil {
		t.Fatal(err)
	}
	capture, err := NewCapture(CaptureConfig{
		Iface: "lo", Ports: []uint16{port}, NodeID: "gw-test", CapturePoint: "GATEWAY_EGRESS",
		PolicyVersion: "policy-test-1", HotDir: hotRoot, QueuePackets: 128, QueueBytes: 1 << 20,
		SegmentMaxBytes: 1 << 20, SegmentMaxSeconds: 300 * time.Millisecond,
		DEKProvider: provider,
		OnSegment: func(_ context.Context, sealed SealedSegment) error {
			sealedSegments <- sealed
			return nil
		},
	})
	if err != nil {
		if os.Getenv("PCAPD_REQUIRE_LIVE") != "1" && strings.Contains(err.Error(), "operation not permitted") {
			t.Skip("real AF_PACKET capture requires an explicitly authorized NET_RAW test environment")
		}
		t.Fatal(err)
	}
	runDone := make(chan error, 1)
	go func() { runDone <- capture.Run() }()
	time.Sleep(150 * time.Millisecond)

	for i := 0; i < 3; i++ {
		request, err := http.NewRequest(http.MethodGet, fmt.Sprintf("http://127.0.0.1:%d/v1/evidence", port), nil)
		if err != nil {
			t.Fatal(err)
		}
		request.Header.Set("X-Request-Id", fmt.Sprintf("req-capture-%d", i))
		request.Header.Set("Traceparent", "00-0123456789abcdef0123456789abcdef-0123456789abcdef-01")
		response, err := http.DefaultClient.Do(request)
		if err != nil {
			t.Fatal(err)
		}
		_, _ = io.Copy(io.Discard, response.Body)
		response.Body.Close()
		if response.StatusCode != http.StatusOK {
			t.Fatalf("unexpected test origin status: %d", response.StatusCode)
		}
	}
	// 等待真实回环流量完成异步捕获，再执行停止与封口。
	time.Sleep(200 * time.Millisecond)
	if err := capture.Close(); err != nil {
		t.Fatal(err)
	}
	select {
	case err := <-runDone:
		if err != nil {
			t.Fatalf("capture run: %v", err)
		}
	case <-time.After(10 * time.Second):
		t.Fatal("capture did not stop and seal within deadline")
	}

	select {
	case sealed := <-sealedSegments:
		manifest := sealed.Manifest
		if manifest.Segment.PacketCount == 0 || manifest.Segment.NodeID != "gw-test" || manifest.Segment.PolicyVersion != "policy-test-1" {
			t.Fatalf("unexpected capture manifest: %+v", manifest)
		}
		if len(sealed.Requests) != 3 {
			t.Fatalf("captured request evidence count=%d want 3: %+v", len(sealed.Requests), sealed.Requests)
		}
		seenRequests := map[string]bool{}
		for _, evidence := range sealed.Requests {
			seenRequests[evidence.RequestID] = true
			if evidence.TraceID != "0123456789abcdef0123456789abcdef" || evidence.Path != "/v1/evidence" || evidence.CapturePoint != "GATEWAY_EGRESS" {
				t.Fatalf("invalid captured request evidence: %+v", evidence)
			}
			if evidence.FirstPacketNo == 0 || evidence.LastPacketNo < evidence.FirstPacketNo {
				t.Fatalf("missing real connection packet range: %+v", evidence)
			}
		}
		for i := 0; i < 3; i++ {
			if !seenRequests[fmt.Sprintf("req-capture-%d", i)] {
				t.Fatalf("missing request evidence req-capture-%d", i)
			}
		}
		ciphertext, err := os.ReadFile(sealed.Path)
		if err != nil {
			t.Fatal(err)
		}
		if bytes.Contains(ciphertext, []byte("capture-evidence-response")) {
			t.Fatal("captured HTTP response appears in encrypted file")
		}
		key, err := evidencekey.UnwrapDEK(keyPair.PrivateKey, sealed.KeyID, sealed.WrappedKey)
		if err != nil {
			t.Fatalf("unwrap real captured evidence DEK: %v", err)
		}
		defer clear(key)
		var decrypted bytes.Buffer
		if err := VerifyAndDecrypt(sealed.Path, manifest, key, &decrypted); err != nil {
			t.Fatal(err)
		}
		if !bytes.Contains(decrypted.Bytes(), []byte("capture-evidence-response")) {
			t.Fatal("real HTTP response is absent from decrypted PCAP")
		}
		reader, err := pcapgo.NewReader(bytes.NewReader(decrypted.Bytes()))
		if err != nil {
			t.Fatal(err)
		}
		if _, _, err := reader.ReadPacketData(); err != nil {
			t.Fatalf("read real captured PCAP: %v", err)
		}
		if _, err := os.Stat(sealed.Path + ".json"); !os.IsNotExist(err) {
			t.Fatalf("delivered sidecar was not removed: %v", err)
		}
	case <-time.After(10 * time.Second):
		t.Fatal("no sealed PCAP segment was delivered")
	}
	if capture.Stats().PacketsWritten == 0 || capture.Stats().DeliveryErrors != 0 {
		t.Fatalf("unexpected capture stats: %+v", capture.Stats())
	}
}

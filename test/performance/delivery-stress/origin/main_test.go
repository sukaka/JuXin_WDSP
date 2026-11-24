package main

import (
	"bytes"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestBenchOriginEMIXPayloadsAndBodyDrain(t *testing.T) {
	srv := httptest.NewServer(newOriginMux(4*1024*1024, "test-origin"))
	defer srv.Close()

	wantSizes := map[string]int{
		"/static/1b.txt":   1,
		"/static/256b.txt": 256,
		"/static/1k.bin":   1024,
		"/static/4k.bin":   4 * 1024,
		"/static/16k.bin":  16 * 1024,
		"/static/64k.bin":  64 * 1024,
		"/static/256k.bin": 256 * 1024,
		"/static/1m.bin":   1024 * 1024,
	}
	for path, want := range wantSizes {
		resp, err := http.Get(srv.URL + path)
		if err != nil {
			t.Fatalf("GET %s: %v", path, err)
		}
		body, _ := io.ReadAll(resp.Body)
		resp.Body.Close()
		if resp.StatusCode != http.StatusOK || len(body) != want {
			t.Fatalf("GET %s: status=%d len=%d want=%d", path, resp.StatusCode, len(body), want)
		}
		if resp.Header.Get("X-Wdsp-Bench-Origin") != "test-origin" {
			t.Fatalf("GET %s: missing origin marker", path)
		}
	}

	// 1.5 MiB POST 必须完整消费请求体且不早退断连
	large := bytes.Repeat([]byte("X"), 1536*1024)
	postResp, err := http.Post(srv.URL+"/v1/upload", "application/octet-stream", bytes.NewReader(large))
	if err != nil {
		t.Fatalf("POST /v1/upload: %v", err)
	}
	defer postResp.Body.Close()
	if postResp.StatusCode != http.StatusOK {
		t.Fatalf("expected 200, got %d", postResp.StatusCode)
	}
	var parsed apiResponse
	if err := json.NewDecoder(postResp.Body).Decode(&parsed); err != nil {
		t.Fatalf("decode response: %v", err)
	}
	if !parsed.OK || parsed.BytesRead != int64(len(large)) {
		t.Fatalf("expected bytes_read=%d, got %+v", len(large), parsed)
	}
}

func TestGenerateSelfSignedCertRSAAndECDSA(t *testing.T) {
	for _, kt := range []string{"rsa", "ecdsa"} {
		cert, err := generateSelfSignedCert(kt)
		if err != nil {
			t.Fatalf("generateSelfSignedCert(%s): %v", kt, err)
		}
		if len(cert.Certificate) == 0 || cert.PrivateKey == nil {
			t.Fatalf("empty certificate or private key for %s", kt)
		}
	}
	if _, err := generateSelfSignedCert("invalid"); err == nil {
		t.Fatalf("expected error for unsupported key type")
	}
}

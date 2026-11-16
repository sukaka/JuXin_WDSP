package tests

import (
	"archive/zip"
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"io"
	"net"
	"net/http"
	"os"
	"strconv"
	"strings"
	"testing"
	"time"

	gatewayresponse "github.com/jiuzhang-waf/gateway/dynamic_security/response"
	"github.com/jiuzhang-waf/server/internal/apifiles"
	"github.com/jiuzhang-waf/server/internal/gatewayconfig"
)

func TestOOXMLSignatureLiveGateway(t *testing.T) {
	if os.Getenv("WDSP_OOXML_LIVE_TEST") != "1" {
		t.Skip("set WDSP_OOXML_LIVE_TEST=1 to use the isolated live gateway verification")
	}
	body := ooxmlSignatureLiveFixture(t)
	if output := os.Getenv("WDSP_OOXML_LIVE_FIXTURE"); output != "" {
		if err := os.WriteFile(output, body, 0o644); err != nil {
			t.Fatal(err)
		}
		return
	}

	ctx, cancel := context.WithTimeout(context.Background(), 45*time.Second)
	defer cancel()
	if err := gatewayconfig.NewCaddyClient("/var/run/caddy/admin.sock").Ping(ctx); err != nil {
		t.Fatal(err)
	}
	transport := &http.Transport{DialContext: func(ctx context.Context, _, _ string) (net.Conn, error) {
		return (&net.Dialer{}).DialContext(ctx, "unix", "/var/run/caddy/admin.sock")
	}}
	admin := &http.Client{Transport: transport}
	defer transport.CloseIdleConnections()
	adminPath := "/config/apps/http/servers/wdsp_signature_verification"
	missing, err := ooxmlLiveServerMissing(ctx, admin, adminPath)
	if err != nil || !missing {
		t.Fatalf("temporary signature server must not exist: missing=%v err=%v", missing, err)
	}

	const kid = "ooxml-test"
	key := bytes.Repeat([]byte{0x5a}, 32)
	keyHex := hex.EncodeToString(key)
	format := liveOOXMLFormat{
		Extension: "docx", MIME: "application/vnd.openxmlformats-officedocument.wordprocessingml.document",
		Filename: "signed-report.docx", Port: 18092, Marker: "wdsp-file-test-slive",
	}
	runID := strconv.FormatInt(time.Now().UnixNano(), 36)
	downloadLog := "/var/log/caddy/wdsp-signature-" + runID + "-download.jsonl"
	server := ooxmlLiveServerConfig(format, "/var/log/caddy/wdsp-signature-"+runID+"-upload.jsonl", downloadLog)
	for _, route := range server["routes"].([]map[string]any) {
		for _, handler := range route["handle"].([]map[string]any) {
			if handler["handler"] == "jiuzhang_guard" {
				handler["api_file_signature"] = map[string]any{"enabled": true, "kid": kid, "key_hex": keyHex}
			}
		}
	}
	raw, err := json.Marshal(server)
	if err != nil {
		t.Fatal(err)
	}
	status, err := ooxmlLiveAdminRequest(ctx, admin, http.MethodPost, adminPath, raw)
	if err != nil || status != http.StatusOK {
		t.Fatalf("create temporary signature server: HTTP %d err=%v", status, err)
	}
	t.Cleanup(func() {
		cleanupCtx, cleanupCancel := context.WithTimeout(context.Background(), 15*time.Second)
		defer cleanupCancel()
		status, err := ooxmlLiveAdminRequest(cleanupCtx, admin, http.MethodDelete, adminPath, nil)
		if err != nil || status != http.StatusOK {
			t.Errorf("remove temporary signature server: HTTP %d err=%v", status, err)
			return
		}
		missing, err := ooxmlLiveServerMissing(cleanupCtx, admin, adminPath)
		if err != nil || !missing {
			t.Errorf("temporary signature server cleanup failed: missing=%v err=%v", missing, err)
		}
	})
	t.Logf("test event path: %s", downloadLog)

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, "http://jiuzhang-stage5-gateway:18092/api/v1/files/download", nil)
	if err != nil {
		t.Fatal(err)
	}
	req.Host = "docx.verify.local"
	req.Header.Set("X-Request-Id", "wdsp-ooxml-signature-live-"+runID)
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	downloaded, readErr := io.ReadAll(io.LimitReader(resp.Body, 2<<20))
	closeErr := resp.Body.Close()
	if readErr != nil || closeErr != nil {
		t.Fatalf("download response: read=%v close=%v", readErr, closeErr)
	}
	if resp.StatusCode != http.StatusOK || bytes.Equal(downloaded, body) {
		t.Fatalf("signed download mismatch: HTTP %d bytes=%d original=%d", resp.StatusCode, len(downloaded), len(body))
	}
	if got := resp.Header.Get("Content-Length"); got != strconv.Itoa(len(downloaded)) {
		t.Fatalf("Content-Length = %q, want %d", got, len(downloaded))
	}
	if _, err := zip.NewReader(bytes.NewReader(downloaded), int64(len(downloaded))); err != nil {
		t.Fatalf("signed OOXML is not a valid ZIP: %v", err)
	}
	original, token, signed, err := gatewayresponse.RecoverOOXMLSignedContent(downloaded)
	if err != nil || !signed || token == "" || !bytes.Equal(original, body) {
		t.Fatalf("original recovery failed: signed=%v err=%v", signed, err)
	}
	sum := sha256.Sum256(original)
	result := apifiles.VerifyFileToken(key, kid, format.Filename, hex.EncodeToString(sum[:]), token, "", 30, time.Now().UTC())
	if !result.Valid {
		t.Fatalf("live signature verification failed: %+v", result)
	}
	assertOOXMLSignatureLiveEvent(t, downloadLog, token, keyHex, format.Filename, kid, gatewayresponse.FileContentSHA256(downloaded))
	t.Logf("signed download HTTP %d; original bytes recovered; HMAC verified", resp.StatusCode)
}

func ooxmlSignatureLiveFixture(t *testing.T) []byte {
	t.Helper()
	var buf bytes.Buffer
	writer := zip.NewWriter(&buf)
	for _, entry := range []struct{ name, body string }{
		{"[Content_Types].xml", `<Types/>`},
		{"_rels/.rels", `<Relationships/>`},
		{"word/document.xml", `<w:document><w:body><w:p><w:r><w:t>ordinary signed report</w:t></w:r></w:p></w:body></w:document>`},
	} {
		part, err := writer.CreateHeader(&zip.FileHeader{Name: entry.name, Method: zip.Store})
		if err != nil {
			t.Fatal(err)
		}
		if _, err := io.WriteString(part, entry.body); err != nil {
			t.Fatal(err)
		}
	}
	if err := writer.SetComment("legacy-comment"); err != nil {
		t.Fatal(err)
	}
	if err := writer.Close(); err != nil {
		t.Fatal(err)
	}
	return buf.Bytes()
}

func assertOOXMLSignatureLiveEvent(t *testing.T, logPath, token, keyHex, filename, kid, expectedSHA256 string) {
	t.Helper()
	readPath := logPath
	if dir := os.Getenv("WDSP_OOXML_LIVE_LOG_READ_DIR"); dir != "" {
		readPath = strings.TrimSuffix(dir, "/") + "/" + strings.TrimPrefix(logPath, "/var/log/caddy/")
	}
	raw, err := os.ReadFile(readPath)
	if err != nil {
		t.Fatal(err)
	}
	if len(raw) > 1<<20 || bytes.Contains(raw, []byte(token)) || bytes.Contains(raw, []byte(keyHex)) {
		t.Fatal("unexpected signature log size or secret material in the event")
	}
	var event struct {
		IsAPI          bool `json:"is_api"`
		ResponseStatus int  `json:"response_status"`
		Details        []struct {
			RuleID   string            `json:"rule_id"`
			Evidence map[string]string `json:"evidence"`
		} `json:"details"`
		FileObservations []struct {
			ContentSHA256 string `json:"content_sha256"`
		} `json:"file_observations"`
	}
	if err := json.Unmarshal(bytes.TrimSpace(raw), &event); err != nil {
		t.Fatal(err)
	}
	if !event.IsAPI || event.ResponseStatus != http.StatusOK {
		t.Fatalf("unexpected signature event status: %+v", event)
	}
	if len(event.FileObservations) != 1 || event.FileObservations[0].ContentSHA256 != expectedSHA256 {
		t.Fatalf("final signed content fingerprint missing: %+v", event.FileObservations)
	}
	found := false
	for _, detail := range event.Details {
		if detail.RuleID == "file.signature_embedded" {
			found = true
			if detail.Evidence["filename"] != filename || detail.Evidence["kid"] != kid {
				t.Fatalf("unexpected signature event evidence: %+v", detail.Evidence)
			}
		}
	}
	if !found {
		t.Fatalf("file.signature_embedded missing: %+v", event.Details)
	}
}

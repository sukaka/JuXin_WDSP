package tests

import (
	"archive/zip"
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"mime/multipart"
	"net"
	"net/http"
	"os"
	"strconv"
	"testing"
	"time"

	gatewayresponse "github.com/jiuzhang-waf/gateway/dynamic_security/response"
	"github.com/jiuzhang-waf/server/internal/gatewayconfig"
)

type liveOOXMLFormat struct {
	Extension     string
	MIME          string
	Filename      string
	Marker        string
	RuleRegex     string
	Field         string
	Scope         string
	SourcePart    string
	ContentSHA256 string
	Port          int
	Fixture       func(*testing.T) []byte
}

func TestXLSXSensitiveContentLiveGateway(t *testing.T) {
	testOOXMLSensitiveContentLiveGateway(t, liveOOXMLFormat{
		Extension: "xlsx", MIME: "application/vnd.openxmlformats-officedocument.spreadsheetml.sheet",
		Filename: "report.xlsx", Marker: "wdsp-file-test-xlive", Field: "Demo!B2", Scope: "XLSX_WORKSHEETS",
		Port: 18087, Fixture: xlsxLiveFixture,
	})
}

func TestPPTXSensitiveContentLiveGateway(t *testing.T) {
	testOOXMLSensitiveContentLiveGateway(t, liveOOXMLFormat{
		Extension: "pptx", MIME: "application/vnd.openxmlformats-officedocument.presentationml.presentation",
		Filename: "briefing.pptx", Marker: "wdsp-file-test-plive", Field: "slide1!p1", Scope: "PPTX_SLIDES",
		Port: 18088, Fixture: pptxLiveFixture,
	})
}

func testOOXMLSensitiveContentLiveGateway(t *testing.T, format liveOOXMLFormat) {
	t.Helper()
	if os.Getenv("WDSP_OOXML_LIVE_TEST") != "1" {
		t.Skip("set WDSP_OOXML_LIVE_TEST=1 to use the isolated live gateway verification")
	}
	body := format.Fixture(t)
	format.ContentSHA256 = gatewayresponse.FileContentSHA256(body)
	if len(body) >= 512 {
		t.Fatalf("fixture must fit the complete upload prefix: %d", len(body))
	}
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
	adminPath := "/config/apps/http/servers/wdsp_" + format.Extension + "_verification"
	missing, err := ooxmlLiveServerMissing(ctx, admin, adminPath)
	if err != nil {
		t.Fatal(err)
	}
	if !missing {
		t.Fatal("temporary server must not already exist")
	}

	runID := strconv.FormatInt(time.Now().UnixNano(), 36)
	uploadLog := "/var/log/caddy/wdsp-" + format.Extension + "-" + runID + "-upload.jsonl"
	downloadLog := "/var/log/caddy/wdsp-" + format.Extension + "-" + runID + "-download.jsonl"
	raw, err := json.Marshal(ooxmlLiveServerConfig(format, uploadLog, downloadLog))
	if err != nil {
		t.Fatal(err)
	}
	status, err := ooxmlLiveAdminRequest(ctx, admin, http.MethodPost, adminPath, raw)
	if err != nil {
		t.Fatal(err)
	}
	if status != http.StatusOK {
		t.Fatalf("create temporary server: HTTP %d", status)
	}
	t.Cleanup(func() {
		cleanupCtx, cleanupCancel := context.WithTimeout(context.Background(), 15*time.Second)
		defer cleanupCancel()
		status, err := ooxmlLiveAdminRequest(cleanupCtx, admin, http.MethodDelete, adminPath, nil)
		if err != nil {
			t.Errorf("remove temporary server: %v", err)
			return
		}
		if status != http.StatusOK {
			t.Errorf("remove temporary server: HTTP %d", status)
			return
		}
		missing, err := ooxmlLiveServerMissing(cleanupCtx, admin, adminPath)
		if err != nil {
			t.Errorf("check temporary server removal: %v", err)
		} else if !missing {
			t.Error("temporary server still exists after cleanup")
		}
	})
	t.Logf("test event paths: %s %s", uploadLog, downloadLog)

	var multipartBody bytes.Buffer
	writer := multipart.NewWriter(&multipartBody)
	part, err := writer.CreateFormFile("file", format.Filename)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := part.Write(body); err != nil {
		t.Fatal(err)
	}
	if err := writer.Close(); err != nil {
		t.Fatal(err)
	}
	uploadPath := fmt.Sprintf("http://jiuzhang-stage5-gateway:%d/api/v1/tenants/t001/projects/p002/items", format.Port)
	uploadReq, err := http.NewRequestWithContext(ctx, http.MethodPost, uploadPath, &multipartBody)
	if err != nil {
		t.Fatal(err)
	}
	uploadReq.Host = format.Extension + ".verify.local"
	uploadReq.Header.Set("Content-Type", writer.FormDataContentType())
	uploadReq.Header.Set("X-Request-Id", "wdsp-"+format.Extension+"-live-upload-"+runID)
	uploadResp, err := http.DefaultClient.Do(uploadReq)
	if err != nil {
		t.Fatal(err)
	}
	_, readErr := io.Copy(io.Discard, io.LimitReader(uploadResp.Body, 4096))
	closeErr := uploadResp.Body.Close()
	if readErr != nil || closeErr != nil {
		t.Fatalf("upload response: read=%v close=%v", readErr, closeErr)
	}
	if uploadResp.StatusCode != http.StatusOK || uploadResp.Header.Get("X-Wdsp-Origin-Mark") != "jiuzhang-test-origin" {
		t.Fatalf("upload did not reach the test origin: HTTP %d", uploadResp.StatusCode)
	}

	downloadPath := fmt.Sprintf("http://jiuzhang-stage5-gateway:%d/api/v1/files/download", format.Port)
	downloadReq, err := http.NewRequestWithContext(ctx, http.MethodGet, downloadPath, nil)
	if err != nil {
		t.Fatal(err)
	}
	downloadReq.Host = format.Extension + ".verify.local"
	downloadReq.Header.Set("X-Request-Id", "wdsp-"+format.Extension+"-live-download-"+runID)
	downloadResp, err := http.DefaultClient.Do(downloadReq)
	if err != nil {
		t.Fatal(err)
	}
	downloaded, readErr := io.ReadAll(io.LimitReader(downloadResp.Body, int64(len(body)+1)))
	closeErr = downloadResp.Body.Close()
	if readErr != nil || closeErr != nil {
		t.Fatalf("download response: read=%v close=%v", readErr, closeErr)
	}
	if downloadResp.StatusCode != http.StatusOK || !bytes.Equal(downloaded, body) {
		t.Fatalf("download changed the package: HTTP %d bytes=%d want=%d", downloadResp.StatusCode, len(downloaded), len(body))
	}
	assertOOXMLLiveEvent(t, uploadLog, "UPLOAD", format)
	assertOOXMLLiveEvent(t, downloadLog, "DOWNLOAD", format)
	t.Logf("%s live upload HTTP %d; live download HTTP %d; original bytes preserved", format.Extension, uploadResp.StatusCode, downloadResp.StatusCode)
}

func xlsxLiveFixture(t *testing.T) []byte {
	t.Helper()
	return ooxmlLiveFixture(t, []struct{ name, body string }{
		{"xl/workbook.xml", `<workbook><sheets><sheet name="Demo" sheetId="1" r:id="rId1"/></sheets></workbook>`},
		{"xl/worksheets/sheet1.xml", `<worksheet><c r="B2" t="inlineStr"><is><t>wdsp-file-test-xlive</t></is></c></worksheet>`},
	})
}

func pptxLiveFixture(t *testing.T) []byte {
	t.Helper()
	return ooxmlLiveFixture(t, []struct{ name, body string }{
		{"ppt/presentation.xml", `<p:presentation/>`},
		{"ppt/slides/slide1.xml", `<p:sld><p:cSld><p:spTree><p:sp><p:txBody><a:p><a:r><a:t>wdsp-file-test-</a:t></a:r><a:r><a:t>plive</a:t></a:r></a:p></p:txBody></p:sp></p:spTree></p:cSld></p:sld>`},
	})
}

func ooxmlLiveFixture(t *testing.T, entries []struct{ name, body string }) []byte {
	t.Helper()
	var buf bytes.Buffer
	writer := zip.NewWriter(&buf)
	for _, entry := range entries {
		part, err := writer.CreateHeader(&zip.FileHeader{Name: entry.name, Method: zip.Store})
		if err != nil {
			t.Fatal(err)
		}
		if _, err := io.WriteString(part, entry.body); err != nil {
			t.Fatal(err)
		}
	}
	if err := writer.Close(); err != nil {
		t.Fatal(err)
	}
	return buf.Bytes()
}

func ooxmlLiveServerConfig(format liveOOXMLFormat, uploadLog, downloadLog string) map[string]any {
	host := format.Extension + ".verify.local"
	ruleRegex := format.RuleRegex
	if ruleRegex == "" {
		ruleRegex = `^wdsp-file-test-[a-z]+$`
	}
	guard := func(eventsLog string) map[string]any {
		return map[string]any{
			"handler":                "jiuzhang_guard",
			"app_id":                 "wdsp-" + format.Extension + "-verification",
			"app_code":               "wdsp-" + format.Extension + "-verification",
			"counter_backend":        "memory",
			"events_log":             "/tmp/wdsp-" + format.Extension + "-verification-guard.log",
			"api_dynamic_protection": true,
			"api_protection_mode":    "PROTECT",
			"api_events_log":         eventsLog,
			"api_sensitive_value_rules": []map[string]any{{
				"data_type": "wdsp_test_marker",
				"regex":     ruleRegex,
				"locations": []string{"file"},
				"level":     "SENSITIVE",
			}},
		}
	}
	return map[string]any{
		"listen":          []string{fmt.Sprintf(":%d", format.Port)},
		"automatic_https": map[string]any{"disable": true},
		"routes": []map[string]any{
			{
				"match": []map[string]any{{"host": []string{host}, "path": []string{"/api/v1/tenants/t001/projects/p002/items"}}},
				"handle": []map[string]any{
					guard(uploadLog),
					{"handler": "reverse_proxy", "upstreams": []map[string]any{{"dial": "testorigin:8081"}}},
				},
			},
			{
				"match": []map[string]any{{"host": []string{host}, "path": []string{"/api/v1/files/download"}}},
				"handle": []map[string]any{
					guard(downloadLog),
					{"handler": "headers", "response": map[string]any{"set": map[string][]string{
						"Content-Type":        {format.MIME},
						"Content-Disposition": {`attachment; filename="` + format.Filename + `"`},
					}}},
					{"handler": "rewrite", "uri": "/wdsp-" + format.Extension + "-live-" + format.Filename},
					{"handler": "file_server", "root": "/tmp"},
				},
			},
		},
	}
}

func ooxmlLiveServerMissing(ctx context.Context, client *http.Client, path string) (bool, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, "http://localhost"+path, nil)
	if err != nil {
		return false, err
	}
	resp, err := client.Do(req)
	if err != nil {
		return false, err
	}
	defer resp.Body.Close()
	if resp.StatusCode == http.StatusNotFound {
		return true, nil
	}
	body, err := io.ReadAll(io.LimitReader(resp.Body, 4096))
	if err != nil {
		return false, err
	}
	if resp.StatusCode != http.StatusOK {
		return false, fmt.Errorf("check temporary server: HTTP %d", resp.StatusCode)
	}
	var value any
	if err := json.Unmarshal(body, &value); err != nil {
		return false, fmt.Errorf("decode temporary server presence: %w", err)
	}
	return value == nil, nil
}

func ooxmlLiveAdminRequest(ctx context.Context, client *http.Client, method, path string, body []byte) (int, error) {
	req, err := http.NewRequestWithContext(ctx, method, "http://localhost"+path, bytes.NewReader(body))
	if err != nil {
		return 0, err
	}
	if body != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	resp, err := client.Do(req)
	if err != nil {
		return 0, err
	}
	defer resp.Body.Close()
	responseBody, err := io.ReadAll(io.LimitReader(resp.Body, 4096))
	if err != nil {
		return 0, err
	}
	if resp.StatusCode >= http.StatusBadRequest && resp.StatusCode != http.StatusNotFound {
		return resp.StatusCode, fmt.Errorf("admin request returned HTTP %d: %s", resp.StatusCode, responseBody)
	}
	return resp.StatusCode, nil
}

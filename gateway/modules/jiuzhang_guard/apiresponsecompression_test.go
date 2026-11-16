package jiuzhang_guard

import (
	"bytes"
	"compress/gzip"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"strconv"
	"strings"
	"testing"

	"github.com/andybalholm/brotli"
	"github.com/jiuzhang-waf/gateway/dynamic_security/response"
	"github.com/jiuzhang-waf/gateway/modules/jiuzhang_guard/apievents"
	"go.uber.org/zap"
	"go.uber.org/zap/zaptest/observer"
)

func compressedResponseFixture(t *testing.T, encoding string, body []byte) []byte {
	t.Helper()
	var out bytes.Buffer
	var writer io.WriteCloser
	switch encoding {
	case apiResponseEncodingGzip:
		writer = gzip.NewWriter(&out)
	case apiResponseEncodingBr:
		writer = brotli.NewWriter(&out)
	default:
		t.Fatalf("unsupported fixture encoding %q", encoding)
	}
	if _, err := writer.Write(body); err != nil {
		t.Fatal(err)
	}
	if err := writer.Close(); err != nil {
		t.Fatal(err)
	}
	return out.Bytes()
}

func decodedCompressedResponseFixture(t *testing.T, encoding string, body []byte) []byte {
	t.Helper()
	var reader io.Reader
	switch encoding {
	case apiResponseEncodingGzip:
		gzipReader, err := gzip.NewReader(bytes.NewReader(body))
		if err != nil {
			t.Fatal(err)
		}
		defer gzipReader.Close()
		reader = gzipReader
	case apiResponseEncodingBr:
		reader = brotli.NewReader(bytes.NewReader(body))
	default:
		t.Fatalf("unsupported fixture encoding %q", encoding)
	}
	decoded, err := io.ReadAll(reader)
	if err != nil {
		t.Fatal(err)
	}
	return decoded
}

func compressedResponseRequest(id string) *http.Request {
	req := httptest.NewRequest(http.MethodPost, "/v1/users", strings.NewReader(`{"name":"x"}`))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("X-Request-Id", id)
	req.RemoteAddr = "203.0.113.9:5001"
	return req
}

func compressedResponseMaskGuard(t *testing.T, mode string) (*Guard, string) {
	t.Helper()
	return newAPIResponseTestGuard(t, mode, []maskRuleJSON{
		{EndpointKey: "POST /v1/users", FieldPath: "phone", Algorithm: "MASK"},
	})
}

func compressedResponseRuleExists(records []apievents.Record, ruleID string) bool {
	for _, record := range records {
		for _, detail := range record.Details {
			if detail.RuleID == ruleID {
				return true
			}
		}
	}
	return false
}

func assertCompressedResponseEventRedacted(t *testing.T, records []apievents.Record, secret string) {
	t.Helper()
	encoded, err := json.Marshal(records)
	if err != nil {
		t.Fatal(err)
	}
	if bytes.Contains(encoded, []byte(secret)) {
		t.Fatalf("api event contains sensitive value: %s", encoded)
	}
}

func requireCompressedResponseWarn(t *testing.T, logs *observer.ObservedLogs, substring string) {
	t.Helper()
	for _, entry := range logs.All() {
		if strings.Contains(entry.Message, substring) {
			return
		}
	}
	t.Fatalf("warn containing %q missing: %+v", substring, logs.All())
}

func TestServeNextCompressedResponseSensitiveDetectionAndMask(t *testing.T) {
	const upstream = `{"phone":"13800138000","ok":true}`
	for _, encoding := range []string{apiResponseEncodingGzip, apiResponseEncodingBr} {
		t.Run(encoding, func(t *testing.T) {
			g, logPath := compressedResponseMaskGuard(t, "PROTECT")
			raw := compressedResponseFixture(t, encoding, []byte(upstream))
			next := nextFunc(func(w http.ResponseWriter, r *http.Request) error {
				w.Header().Set("Content-Type", "application/json")
				w.Header().Set("Content-Encoding", encoding)
				w.Header().Set("Content-Length", strconv.Itoa(len(raw)))
				w.Header().Set("ETag", `"compressed-v1"`)
				_, _ = w.Write(raw[:len(raw)/2])
				_, _ = w.Write(raw[len(raw)/2:])
				return nil
			})
			recorder := httptest.NewRecorder()
			if err := g.serveNext(recorder, compressedResponseRequest("compressed-mask-"+encoding), next); err != nil {
				t.Fatalf("serveNext: %v", err)
			}
			resp := recorder.Result()
			delivered, err := io.ReadAll(resp.Body)
			if err != nil {
				t.Fatal(err)
			}
			decoded := decodedCompressedResponseFixture(t, encoding, delivered)
			if strings.Contains(string(decoded), "13800138000") || !strings.Contains(string(decoded), "138****8000") {
				t.Fatalf("compressed response was not masked: %s", decoded)
			}
			if !strings.Contains(string(decoded), `"ok":true`) {
				t.Fatalf("unrelated field changed: %s", decoded)
			}
			if got := resp.Header.Get("Content-Encoding"); got != encoding {
				t.Fatalf("Content-Encoding = %q, want %q", got, encoding)
			}
			if got := resp.Header.Get("Content-Length"); got != strconv.Itoa(len(delivered)) {
				t.Fatalf("Content-Length = %q, want %d", got, len(delivered))
			}
			if resp.Header.Get("ETag") != "" {
				t.Fatal("stale ETag must be removed after compressed rewrite")
			}
			records := readAPIRecords(t, logPath)
			if len(records) != 1 || records[0].FinalAction != "MASK_RESPONSE" {
				t.Fatalf("unexpected event: %+v", records)
			}
			if !compressedResponseRuleExists(records, "sensitive.response_field") ||
				!compressedResponseRuleExists(records, "response.mask_applied") {
				t.Fatalf("sensitive detection or mask detail missing: %+v", records[0].Details)
			}
			assertCompressedResponseEventRedacted(t, records, "13800138000")
		})
	}
}

func TestServeNextCompressedResponseObservePreservesOriginalBytes(t *testing.T) {
	const upstream = `{"phone":"13800138000","ok":true}`
	for _, encoding := range []string{apiResponseEncodingGzip, apiResponseEncodingBr} {
		t.Run(encoding, func(t *testing.T) {
			g, logPath := compressedResponseMaskGuard(t, "OBSERVE")
			raw := compressedResponseFixture(t, encoding, []byte(upstream))
			next := nextFunc(func(w http.ResponseWriter, r *http.Request) error {
				w.Header().Set("Content-Type", "application/json")
				w.Header().Set("Content-Encoding", encoding)
				w.Header().Set("Content-Length", strconv.Itoa(len(raw)))
				_, _ = w.Write(raw)
				return nil
			})
			recorder := httptest.NewRecorder()
			if err := g.serveNext(recorder, compressedResponseRequest("compressed-observe-"+encoding), next); err != nil {
				t.Fatalf("serveNext: %v", err)
			}
			resp := recorder.Result()
			delivered, err := io.ReadAll(resp.Body)
			if err != nil {
				t.Fatal(err)
			}
			if !bytes.Equal(delivered, raw) {
				t.Fatal("unmodified compressed response must be byte-for-byte identical")
			}
			if got := resp.Header.Get("Content-Encoding"); got != encoding {
				t.Fatalf("Content-Encoding = %q, want %q", got, encoding)
			}
			if got := resp.Header.Get("Content-Length"); got != strconv.Itoa(len(raw)) {
				t.Fatalf("Content-Length = %q, want %d", got, len(raw))
			}
			records := readAPIRecords(t, logPath)
			if !compressedResponseRuleExists(records, "sensitive.response_field") ||
				!compressedResponseRuleExists(records, "response.mask_plan") {
				t.Fatalf("OBSERVE must inspect decoded JSON: %+v", records)
			}
			if compressedResponseRuleExists(records, "response.mask_applied") {
				t.Fatal("OBSERVE must not rewrite compressed response")
			}
			assertCompressedResponseEventRedacted(t, records, "13800138000")
		})
	}
}

func TestServeNextCompressedResponseInlineHTMLWatermark(t *testing.T) {
	const payload = `<html><body>compressed report</body></html>`
	for _, encoding := range []string{apiResponseEncodingGzip, apiResponseEncodingBr} {
		t.Run(encoding, func(t *testing.T) {
			g, logPath := newAPITestGuard(t, "OBSERVE", nil)
			cfg, err := response.NewFileWatermarkConfig(true, "trace ip={ip}", []string{"text/html"}, "")
			if err != nil {
				t.Fatal(err)
			}
			cfg.IncludeInlineHTML = true
			g.apiFileWatermark = cfg
			raw := compressedResponseFixture(t, encoding, []byte(payload))
			next := nextFunc(func(w http.ResponseWriter, r *http.Request) error {
				w.Header().Set("Content-Type", "text/html; charset=utf-8")
				w.Header().Set("Content-Encoding", encoding)
				_, _ = w.Write(raw)
				return nil
			})
			recorder := httptest.NewRecorder()
			if err := g.serveNext(recorder, compressedResponseRequest("compressed-watermark-"+encoding), next); err != nil {
				t.Fatalf("serveNext: %v", err)
			}
			resp := recorder.Result()
			delivered, _ := io.ReadAll(resp.Body)
			decoded := decodedCompressedResponseFixture(t, encoding, delivered)
			want := payload + "\n<!-- trace ip=203.0.113.9 -->"
			if string(decoded) != want {
				t.Fatalf("decoded watermark body = %q, want %q", decoded, want)
			}
			if got := resp.Header.Get("Content-Encoding"); got != encoding {
				t.Fatalf("Content-Encoding = %q, want %q", got, encoding)
			}
			if got := resp.Header.Get("Content-Length"); got != strconv.Itoa(len(delivered)) {
				t.Fatalf("Content-Length = %q, want %d", got, len(delivered))
			}
			records := readAPIRecords(t, logPath)
			if !compressedResponseRuleExists(records, "file.watermark_applied") {
				t.Fatalf("watermark detail missing: %+v", records)
			}
		})
	}
}

func TestServeNextCompressedResponseFileSignature(t *testing.T) {
	const payload = "order,amount\nA1,100\n"
	for _, encoding := range []string{apiResponseEncodingGzip, apiResponseEncodingBr} {
		t.Run(encoding, func(t *testing.T) {
			g, logPath := newFileSignatureTestGuard(t, "OBSERVE", "k2026")
			raw := compressedResponseFixture(t, encoding, []byte(payload))
			next := nextFunc(func(w http.ResponseWriter, r *http.Request) error {
				w.Header().Set("Content-Type", "text/csv; charset=utf-8")
				w.Header().Set("Content-Encoding", encoding)
				w.Header().Set("Content-Disposition", `attachment; filename="orders.csv"`)
				_, _ = w.Write(raw)
				return nil
			})
			recorder := httptest.NewRecorder()
			if err := g.serveNext(recorder, wmDownloadRequest("compressed-signature-"+encoding), next); err != nil {
				t.Fatalf("serveNext: %v", err)
			}
			resp := recorder.Result()
			delivered, _ := io.ReadAll(resp.Body)
			decoded := decodedCompressedResponseFixture(t, encoding, delivered)
			if !strings.HasPrefix(string(decoded), payload) || !strings.Contains(string(decoded), "jzsig1.k2026.") {
				t.Fatalf("signature missing from decoded response: %s", decoded)
			}
			if got := resp.Header.Get("Content-Encoding"); got != encoding {
				t.Fatalf("Content-Encoding = %q, want %q", got, encoding)
			}
			if got := resp.Header.Get("Content-Length"); got != strconv.Itoa(len(delivered)) {
				t.Fatalf("Content-Length = %q, want %d", got, len(delivered))
			}
			records := readAPIRecords(t, logPath)
			if !compressedResponseRuleExists(records, "file.signature_embedded") {
				t.Fatalf("signature detail missing: %+v", records)
			}
		})
	}
}

func TestServeNextCompressedResponseInvalidDataPolicies(t *testing.T) {
	const upstream = `{"phone":"13800138000"}`
	for _, encoding := range []string{apiResponseEncodingGzip, apiResponseEncodingBr} {
		for _, failClosed := range []bool{false, true} {
			name := encoding + "/fail-open"
			if failClosed {
				name = encoding + "/fail-closed"
			}
			t.Run(name, func(t *testing.T) {
				g, logPath := compressedResponseMaskGuard(t, "PROTECT")
				if failClosed {
					g.APIResponseFailPolicy = apiFailClosed
				}
				core, logs := observer.New(zap.WarnLevel)
				g.logger = zap.New(core)
				valid := compressedResponseFixture(t, encoding, []byte(upstream))
				invalid := valid[:len(valid)/2]
				if _, err := decodeAPIResponseBody(encoding, invalid, 1024); err == nil {
					t.Fatal("truncated fixture must be invalid")
				}
				next := nextFunc(func(w http.ResponseWriter, r *http.Request) error {
					w.Header().Set("Content-Type", "application/json")
					w.Header().Set("Content-Encoding", encoding)
					_, _ = w.Write(invalid)
					return nil
				})
				recorder := httptest.NewRecorder()
				if err := g.serveNext(recorder, compressedResponseRequest("compressed-invalid-"+encoding), next); err != nil {
					t.Fatalf("serveNext: %v", err)
				}
				resp := recorder.Result()
				delivered, _ := io.ReadAll(resp.Body)
				records := readAPIRecords(t, logPath)
				if failClosed {
					if resp.StatusCode != http.StatusInternalServerError || !strings.Contains(string(delivered), "response_processing_failed") {
						t.Fatalf("fail-closed response = %d %s", resp.StatusCode, delivered)
					}
					if resp.Header.Get("Content-Encoding") != "" {
						t.Fatal("fail-closed response must not retain upstream encoding")
					}
					if !compressedResponseRuleExists(records, "response.fail_closed") {
						t.Fatalf("fail-closed detail missing: %+v", records)
					}
				} else {
					if resp.StatusCode != http.StatusOK || !bytes.Equal(delivered, invalid) {
						t.Fatalf("fail-open must deliver original invalid bytes: status=%d equal=%v", resp.StatusCode, bytes.Equal(delivered, invalid))
					}
					if compressedResponseRuleExists(records, "response.mask_plan") ||
						compressedResponseRuleExists(records, "sensitive.response_field") {
						t.Fatalf("invalid compressed bytes must not be parsed as JSON: %+v", records)
					}
				}
				requireCompressedResponseWarn(t, logs, "decode failed")
				assertCompressedResponseEventRedacted(t, records, "13800138000")
			})
		}
	}
}

func TestServeNextCompressedResponseDecompressedLimitPolicies(t *testing.T) {
	upstream := `{"phone":"13800138000","pad":"` + strings.Repeat("x", 4096) + `"}`
	for _, encoding := range []string{apiResponseEncodingGzip, apiResponseEncodingBr} {
		for _, failClosed := range []bool{false, true} {
			name := encoding + "/fail-open"
			if failClosed {
				name = encoding + "/fail-closed"
			}
			t.Run(name, func(t *testing.T) {
				g, logPath := compressedResponseMaskGuard(t, "PROTECT")
				g.APIResponseCaptureMaxBytes = 512
				if failClosed {
					g.APIResponseFailPolicy = apiFailClosed
				}
				core, logs := observer.New(zap.WarnLevel)
				g.logger = zap.New(core)
				raw := compressedResponseFixture(t, encoding, []byte(upstream))
				if len(raw) >= g.APIResponseCaptureMaxBytes {
					t.Fatalf("fixture must exercise decompressed rather than raw limit: raw=%d", len(raw))
				}
				next := nextFunc(func(w http.ResponseWriter, r *http.Request) error {
					w.Header().Set("Content-Type", "application/json")
					w.Header().Set("Content-Encoding", encoding)
					_, _ = w.Write(raw)
					return nil
				})
				recorder := httptest.NewRecorder()
				if err := g.serveNext(recorder, compressedResponseRequest("compressed-limit-"+encoding), next); err != nil {
					t.Fatalf("serveNext: %v", err)
				}
				resp := recorder.Result()
				delivered, _ := io.ReadAll(resp.Body)
				records := readAPIRecords(t, logPath)
				if failClosed {
					if resp.StatusCode != http.StatusInternalServerError || strings.Contains(string(delivered), "13800138000") {
						t.Fatalf("fail-closed oversized response = %d %s", resp.StatusCode, delivered)
					}
				} else {
					if resp.StatusCode != http.StatusOK || !bytes.Equal(delivered, raw) {
						t.Fatal("fail-open oversized decoded body must deliver original compressed bytes")
					}
					if compressedResponseRuleExists(records, "response.mask_plan") {
						t.Fatalf("oversized decoded body must not produce a mask plan: %+v", records)
					}
				}
				requireCompressedResponseWarn(t, logs, "capture limit")
				assertCompressedResponseEventRedacted(t, records, "13800138000")
			})
		}
	}
}

func TestServeNextMultipleContentEncodingsPassThrough(t *testing.T) {
	g, logPath := compressedResponseMaskGuard(t, "PROTECT")
	core, logs := observer.New(zap.WarnLevel)
	g.logger = zap.New(core)
	raw := compressedResponseFixture(t, apiResponseEncodingGzip, []byte(`{"phone":"13800138000"}`))
	next := nextFunc(func(w http.ResponseWriter, r *http.Request) error {
		w.Header().Set("Content-Type", "application/json")
		w.Header().Set("Content-Encoding", "gzip, br")
		_, _ = w.Write(raw)
		return nil
	})
	recorder := httptest.NewRecorder()
	if err := g.serveNext(recorder, compressedResponseRequest("compressed-multi-encoding"), next); err != nil {
		t.Fatalf("serveNext: %v", err)
	}
	delivered, _ := io.ReadAll(recorder.Result().Body)
	if !bytes.Equal(delivered, raw) {
		t.Fatal("unsupported multiple encodings must pass through unchanged")
	}
	requireCompressedResponseWarn(t, logs, "unsupported content-encoding")
	records := readAPIRecords(t, logPath)
	if compressedResponseRuleExists(records, "response.mask_plan") {
		t.Fatalf("multiple encodings must not be decoded: %+v", records)
	}
	assertCompressedResponseEventRedacted(t, records, "13800138000")
}

func TestServeNextCompressedResponsePartialContentNotRewritten(t *testing.T) {
	const upstream = `{"phone":"13800138000"}`
	for _, encoding := range []string{apiResponseEncodingGzip, apiResponseEncodingBr} {
		t.Run(encoding, func(t *testing.T) {
			g, logPath := compressedResponseMaskGuard(t, "PROTECT")
			raw := compressedResponseFixture(t, encoding, []byte(upstream))
			next := nextFunc(func(w http.ResponseWriter, r *http.Request) error {
				w.Header().Set("Content-Type", "application/json")
				w.Header().Set("Content-Encoding", encoding)
				w.Header().Set("Content-Range", "bytes 0-20/100")
				w.WriteHeader(http.StatusPartialContent)
				_, _ = w.Write(raw)
				return nil
			})
			recorder := httptest.NewRecorder()
			if err := g.serveNext(recorder, compressedResponseRequest("compressed-range-"+encoding), next); err != nil {
				t.Fatalf("serveNext: %v", err)
			}
			resp := recorder.Result()
			delivered, _ := io.ReadAll(resp.Body)
			if resp.StatusCode != http.StatusPartialContent || !bytes.Equal(delivered, raw) {
				t.Fatal("compressed partial response must retain original bytes")
			}
			if got := resp.Header.Get("Content-Range"); got != "bytes 0-20/100" {
				t.Fatalf("Content-Range = %q", got)
			}
			records := readAPIRecords(t, logPath)
			if !compressedResponseRuleExists(records, "response.mask_skipped") ||
				compressedResponseRuleExists(records, "response.mask_applied") {
				t.Fatalf("partial response rewrite semantics changed: %+v", records)
			}
			assertCompressedResponseEventRedacted(t, records, "13800138000")
		})
	}
}

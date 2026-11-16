package apifiles

import (
	"archive/zip"
	"bytes"
	"context"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"net/http"
	"strings"
	"testing"
	"time"

	"github.com/google/uuid"
	gatewayresponse "github.com/jiuzhang-waf/gateway/dynamic_security/response"
)

func TestSignatureVerifyOOXMLHTTP(t *testing.T) {
	kv := &fakeSigKV{}
	enc := testEncryptor(t)
	if _, err := RotateFileSignatureKey(context.Background(), kv, enc, uuid.Nil); err != nil {
		t.Fatal(err)
	}
	key, kid, err := LoadFileSignatureKey(context.Background(), kv, enc)
	if err != nil {
		t.Fatal(err)
	}
	cfg, err := gatewayresponse.NewFileSignatureConfig(true, kid, hex.EncodeToString(key))
	if err != nil {
		t.Fatal(err)
	}
	mux := newSignatureMux(kv, enc, injectPrincipal("api_data.read"))
	body := testSignatureOOXMLPackage(t)
	signed, _, applied, err := gatewayresponse.ApplyFileSignature(body,
		"application/vnd.openxmlformats-officedocument.wordprocessingml.document", cfg, "report.docx", "test:fp", time.Now().UTC())
	if err != nil || !applied {
		t.Fatalf("sign OOXML fixture: applied=%v err=%v", applied, err)
	}
	verify := func(content []byte) (int, VerifyResult, string) {
		payload, err := json.Marshal(map[string]string{
			"filename": "report.docx", "content_format": "ooxml_zip",
			"content_base64": base64.StdEncoding.EncodeToString(content), "identity_fp": "test:fp",
		})
		if err != nil {
			t.Fatal(err)
		}
		rr := doJSON(t, mux, http.MethodPost, "/api/v1/api-security/file-signature/verify", string(payload))
		return rr.Code, decodeVerifyResp(t, rr), rr.Body.String()
	}
	status, result, responseBody := verify(signed)
	if status != http.StatusOK || !result.Valid || result.Kid != kid {
		t.Fatalf("OOXML verification failed: status=%d result=%+v", status, result)
	}
	if strings.Contains(responseBody, base64.StdEncoding.EncodeToString(signed)) {
		t.Fatal("OOXML verification response contains the original file")
	}
	tampered := append([]byte(nil), signed...)
	index := bytes.Index(tampered, []byte("ordinary content"))
	if index < 0 {
		t.Fatal("uncompressed fixture text not found")
	}
	tampered[index] ^= 1
	status, result, _ = verify(tampered)
	if status != http.StatusOK || result.Valid || result.Reason == "" {
		t.Fatalf("tampered OOXML must fail verification: status=%d result=%+v", status, result)
	}
}

func TestSignatureVerifyOOXMLRejectsInvalidPayload(t *testing.T) {
	kv := &fakeSigKV{}
	enc := testEncryptor(t)
	if _, err := RotateFileSignatureKey(context.Background(), kv, enc, uuid.Nil); err != nil {
		t.Fatal(err)
	}
	mux := newSignatureMux(kv, enc, injectPrincipal("api_data.read"))
	unsigned := base64.StdEncoding.EncodeToString(testSignatureOOXMLPackage(t))
	for name, payload := range map[string]string{
		"format":       `{"filename":"report.docx","content_format":"zip","content_base64":"` + unsigned + `"}`,
		"both_sources": `{"filename":"report.docx","content_format":"ooxml_zip","content_base64":"` + unsigned + `","content_sha256_hex":"` + testSHAHex + `"}`,
		"base64":       `{"filename":"report.docx","content_format":"ooxml_zip","content_base64":"not-base64"}`,
		"unsigned":     `{"filename":"report.docx","content_format":"ooxml_zip","content_base64":"` + unsigned + `"}`,
		"bad_zip":      `{"filename":"report.docx","content_format":"ooxml_zip","content_base64":"` + base64.StdEncoding.EncodeToString([]byte("not-a-zip")) + `"}`,
		"too_large":    `{"filename":"report.docx","content_format":"ooxml_zip","content_base64":"` + base64.StdEncoding.EncodeToString(make([]byte, verifyOOXMLMaxBytes+1)) + `"}`,
		"format_only":  `{"filename":"report.docx","content_format":"ooxml_zip"}`,
	} {
		t.Run(name, func(t *testing.T) {
			rr := doJSON(t, mux, http.MethodPost, "/api/v1/api-security/file-signature/verify", payload)
			if rr.Code != http.StatusBadRequest {
				t.Fatalf("invalid OOXML payload: status=%d body=%s", rr.Code, rr.Body.String())
			}
		})
	}
}

func testSignatureOOXMLPackage(t *testing.T) []byte {
	t.Helper()
	var buf bytes.Buffer
	writer := zip.NewWriter(&buf)
	for _, entry := range []struct{ name, body string }{
		{"[Content_Types].xml", `<Types/>`},
		{"_rels/.rels", `<Relationships/>`},
		{"word/document.xml", `<document><text>ordinary content</text></document>`},
	} {
		part, err := writer.CreateHeader(&zip.FileHeader{Name: entry.name, Method: zip.Store})
		if err != nil {
			t.Fatal(err)
		}
		if _, err := part.Write([]byte(entry.body)); err != nil {
			t.Fatal(err)
		}
	}
	if err := writer.Close(); err != nil {
		t.Fatal(err)
	}
	return buf.Bytes()
}

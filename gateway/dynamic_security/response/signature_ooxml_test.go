package response

import (
	"archive/zip"
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"strings"
	"testing"
	"time"
)

func testOOXMLSignaturePackage(t *testing.T, ext, comment string) []byte {
	t.Helper()
	mainPart := "word/document.xml"
	if ext == "xlsx" {
		mainPart = "xl/workbook.xml"
	} else if ext == "pptx" {
		mainPart = "ppt/presentation.xml"
	}
	var buf bytes.Buffer
	writer := zip.NewWriter(&buf)
	for _, entry := range []struct{ name, body string }{
		{ooxmlContentTypesPart, `<Types/>`},
		{ooxmlRelsPart, `<Relationships/>`},
		{mainPart, `<document><text>ordinary content</text></document>`},
	} {
		part, err := writer.CreateHeader(&zip.FileHeader{Name: entry.name, Method: zip.Store})
		if err != nil {
			t.Fatal(err)
		}
		if _, err := part.Write([]byte(entry.body)); err != nil {
			t.Fatal(err)
		}
	}
	if err := writer.SetComment(comment); err != nil {
		t.Fatal(err)
	}
	if err := writer.Close(); err != nil {
		t.Fatal(err)
	}
	return buf.Bytes()
}

func TestApplyFileSignatureOOXMLRoundTrip(t *testing.T) {
	cfg := sigTestConfig(t)
	now := time.Unix(1780000000, 0).UTC()
	for ext, mime := range map[string]string{
		"docx": "application/vnd.openxmlformats-officedocument.wordprocessingml.document",
		"xlsx": "application/vnd.openxmlformats-officedocument.spreadsheetml.sheet",
		"pptx": "application/vnd.openxmlformats-officedocument.presentationml.presentation",
	} {
		t.Run(ext, func(t *testing.T) {
			body := testOOXMLSignaturePackage(t, ext, "legacy\x50\x4b\x05\x06comment")
			out, token, applied, err := ApplyFileSignature(body, mime, cfg, "report."+ext, "test:fp", now)
			if err != nil || !applied || bytes.Equal(out, body) {
				t.Fatalf("OOXML signing failed: applied=%v err=%v", applied, err)
			}
			reader, err := zip.NewReader(bytes.NewReader(out), int64(len(out)))
			if err != nil || !strings.HasPrefix(reader.Comment, string(ooxmlSignatureCommentMagic)) {
				t.Fatalf("signed package comment missing: %v", err)
			}
			original, recoveredToken, signed, err := RecoverOOXMLSignedContent(out)
			if err != nil || !signed || recoveredToken != token || !bytes.Equal(original, body) {
				t.Fatalf("OOXML original recovery failed: signed=%v err=%v equal=%v", signed, err, bytes.Equal(original, body))
			}
			sum := sha256.Sum256(original)
			wantToken := BuildFileSignatureToken(cfg.key, cfg.KID, "report."+ext, hex.EncodeToString(sum[:]), now.Unix(), "test:fp")
			if recoveredToken != wantToken {
				t.Fatal("recovered OOXML token does not match the original content")
			}
			again, existingToken, appliedAgain, err := ApplyFileSignature(out, mime, cfg, "report."+ext, "test:fp", now.Add(time.Hour))
			if err != nil || appliedAgain || existingToken != token || !bytes.Equal(again, out) {
				t.Fatalf("OOXML signing must be idempotent: applied=%v err=%v", appliedAgain, err)
			}
			tampered := append([]byte(nil), out...)
			index := bytes.Index(tampered, []byte("ordinary content"))
			if index < 0 {
				t.Fatal("uncompressed fixture text not found")
			}
			tampered[index] ^= 1
			recovered, sameToken, signed, err := RecoverOOXMLSignedContent(tampered)
			if err != nil || !signed || sameToken != token {
				t.Fatalf("tampered package recovery failed: signed=%v err=%v", signed, err)
			}
			tamperedSum := sha256.Sum256(recovered)
			tamperedToken := BuildFileSignatureToken(cfg.key, cfg.KID, "report."+ext, hex.EncodeToString(tamperedSum[:]), now.Unix(), "test:fp")
			if tamperedToken == token {
				t.Fatal("content tampering must invalidate the original HMAC")
			}
		})
	}
}

func TestApplyFileSignatureOOXMLSkipsAndFailures(t *testing.T) {
	cfg := sigTestConfig(t)
	now := time.Unix(1780000000, 0).UTC()
	body := testOOXMLSignaturePackage(t, "docx", "")
	if out, token, applied, err := ApplyFileSignature(body, "application/vnd.openxmlformats-officedocument.wordprocessingml.document", cfg, "report.txt", "", now); err != nil || applied || token != "" || !bytes.Equal(out, body) {
		t.Fatalf("MIME/extension mismatch must pass through: applied=%v err=%v", applied, err)
	}
	if out, token, applied, err := ApplyFileSignature(body, "application/pdf", cfg, "report.docx", "", now); err != nil || applied || token != "" || !bytes.Equal(out, body) {
		t.Fatalf("unsupported type must pass through: applied=%v err=%v", applied, err)
	}
	if _, _, _, err := ApplyFileSignature([]byte("not-a-zip"), "application/vnd.openxmlformats-officedocument.wordprocessingml.document", cfg, "report.docx", "", now); err == nil {
		t.Fatal("invalid OOXML must fail open with an error")
	}
	var buf bytes.Buffer
	writer := zip.NewWriter(&buf)
	part, err := writer.CreateHeader(&zip.FileHeader{Name: "word/document.xml", Method: zip.Store})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := part.Write([]byte(`<document/>`)); err != nil {
		t.Fatal(err)
	}
	if err := writer.Close(); err != nil {
		t.Fatal(err)
	}
	if _, _, _, err := ApplyFileSignature(buf.Bytes(), "application/vnd.openxmlformats-officedocument.wordprocessingml.document", cfg, "report.docx", "", now); err == nil {
		t.Fatal("missing registration parts must not be signed")
	}

	largeComment := testOOXMLSignaturePackage(t, "docx", strings.Repeat("z", maxZipCommentBytes))
	if out, _, applied, err := ApplyFileSignature(largeComment, "application/vnd.openxmlformats-officedocument.wordprocessingml.document", cfg, "report.docx", "", now); err == nil || applied || !bytes.Equal(out, largeComment) {
		t.Fatalf("comment overflow must preserve the original: applied=%v err=%v", applied, err)
	}
	original, token, signed, err := RecoverOOXMLSignedContent(body)
	if err != nil || signed || token != "" || !bytes.Equal(original, body) {
		t.Fatalf("unsigned package must pass through unchanged: signed=%v err=%v", signed, err)
	}
}

func TestOOXMLSignatureRejectsZIP64Layout(t *testing.T) {
	body := testOOXMLSignaturePackage(t, "docx", "")
	offset, err := findOOXMLSignatureEOCD(body)
	if err != nil {
		t.Fatal(err)
	}
	withLocator := append([]byte(nil), body[:offset]...)
	withLocator = append(withLocator, []byte{0x50, 0x4b, 0x06, 0x07}...)
	withLocator = append(withLocator, make([]byte, 16)...)
	withLocator = append(withLocator, body[offset:]...)
	if _, _, _, err := RecoverOOXMLSignedContent(withLocator); err == nil {
		t.Fatal("ZIP64 layout must be explicitly rejected")
	}
}

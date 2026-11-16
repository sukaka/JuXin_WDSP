package detectors

import (
	"bytes"
	"strings"

	dsctx "github.com/jiuzhang-waf/gateway/dynamic_security/context"
	"github.com/jiuzhang-waf/gateway/dynamic_security/parser"
)

type fileSignature struct {
	kind  string
	class string
}

// CheckFileContentType compares a downloaded file's signature with its declared
// type. Detection is enabled by an existing download compliance policy so the
// guard already buffers these responses. Unknown signatures are not type mismatches.
func CheckFileContentType(ctx *dsctx.RequestContext, obs dsctx.FileObservation, body []byte, truncated, streamed bool, rules *FileComplianceRuleSet) {
	if ctx == nil || obs.Direction != dsctx.FileDirectionDownload || !rules.HasDownloadRules() {
		return
	}
	if streamed {
		addFileContentSkipped(ctx, obs, "STREAMED")
		return
	}
	inspectFileContent(ctx, obs, body, truncated)
}

// CheckUploadFileContentTypes evaluates bounded multipart prefixes without
// retaining the upload body. Prefixes never enter event JSON. A capped part
// list produces one explicit coverage disclosure rather than a clean verdict.
func CheckUploadFileContentTypes(ctx *dsctx.RequestContext, parts []parser.PartMeta, partsCapped bool, rules *FileComplianceRuleSet) {
	if ctx == nil || !rules.HasUploadRules() {
		return
	}
	for _, part := range parts {
		observations := parser.BuildUploadFileObservations([]parser.PartMeta{part})
		if len(observations) == 0 {
			continue
		}
		prefix, complete := part.ContentPrefix()
		inspectFileContent(ctx, observations[0], prefix, !complete)
	}
	if partsCapped {
		addFileContentSkipped(ctx, dsctx.FileObservation{Direction: dsctx.FileDirectionUpload}, "MULTIPART_PARTS_CAPPED")
	}
}

func inspectFileContent(ctx *dsctx.RequestContext, obs dsctx.FileObservation, body []byte, truncated bool) {
	if len(body) == 0 {
		reason := "BODY_UNAVAILABLE"
		if truncated {
			reason = "TRUNCATED_BODY_UNAVAILABLE"
		}
		addFileContentSkipped(ctx, obs, reason)
		return
	}
	signature, known := detectFileSignature(body)
	if !known {
		if truncated {
			addFileContentSkipped(ctx, obs, "TRUNCATED_UNKNOWN_SIGNATURE")
			return
		}
		declared := declaredFileClass(obs)
		if declared != "" && declared != "text" && declared != "script" && obs.Extension != "svg" && obs.MIME != "image/svg+xml" {
			ctx.AddMatch(dsctx.DetectorMatch{
				Detector: "file", RuleID: "file.content_unrecognized",
				Category: "OBSERVE", Severity: "LOW", Message: "file signature is not recognized",
				Evidence:   fileContentEvidence(obs, "unrecognized", declared, "FULL_BODY"),
				ScoreDelta: 5, Confidence: 0.5,
			})
		}
		return
	}
	declared := declaredFileClass(obs)
	if declared == "" || declared == signature.class {
		return
	}
	inspection := "FULL_BODY"
	if truncated {
		inspection = "PREFIX_ONLY"
	}
	ctx.AddMatch(dsctx.DetectorMatch{
		Detector: "file", RuleID: "file.content_type_mismatch",
		Category: "OBSERVE", Severity: "MEDIUM", Message: "file signature differs from declared type",
		Evidence:   fileContentEvidence(obs, signature.kind, declared, inspection),
		ScoreDelta: 15, Confidence: 0.9,
	})
}

func addFileContentSkipped(ctx *dsctx.RequestContext, obs dsctx.FileObservation, reason string) {
	ctx.AddMatch(dsctx.DetectorMatch{
		Detector: "file", RuleID: "file.content_not_inspected",
		Category: "OBSERVE", Severity: "INFO", Message: "file content signature was not inspected",
		Evidence: map[string]string{
			"direction": obs.Direction, "filename": obs.FileName, "ext": obs.Extension,
			"mime": obs.MIME, "reason": reason,
		},
		Confidence: 1,
	})
}

func fileContentEvidence(obs dsctx.FileObservation, detected, declared, inspection string) map[string]string {
	return map[string]string{
		"direction": obs.Direction, "filename": obs.FileName, "ext": obs.Extension,
		"mime": obs.MIME, "declared_class": declared, "detected_type": detected,
		"signature_source": "magic_prefix", "inspection": inspection,
	}
}

func detectFileSignature(body []byte) (fileSignature, bool) {
	prefix := body
	if len(prefix) > 64 {
		prefix = prefix[:64]
	}
	trimmed := bytes.TrimSpace(prefix)
	switch {
	case bytes.HasPrefix(trimmed, []byte("<?php")):
		return fileSignature{kind: "php_script", class: "script"}, true
	case bytes.HasPrefix(trimmed, []byte("#!/")):
		return fileSignature{kind: "shell_script", class: "script"}, true
	case bytes.HasPrefix(prefix, []byte("MZ")):
		return fileSignature{kind: "windows_executable", class: "executable"}, true
	case bytes.HasPrefix(prefix, []byte("\x7fELF")):
		return fileSignature{kind: "elf_executable", class: "executable"}, true
	case bytes.HasPrefix(prefix, []byte("%PDF-")):
		return fileSignature{kind: "pdf", class: "document"}, true
	case bytes.HasPrefix(prefix, []byte("\x89PNG\r\n\x1a\n")):
		return fileSignature{kind: "png", class: "image"}, true
	case bytes.HasPrefix(prefix, []byte("\xff\xd8\xff")):
		return fileSignature{kind: "jpeg", class: "image"}, true
	case bytes.HasPrefix(prefix, []byte("GIF87a")), bytes.HasPrefix(prefix, []byte("GIF89a")):
		return fileSignature{kind: "gif", class: "image"}, true
	case len(prefix) >= 12 && bytes.HasPrefix(prefix, []byte("RIFF")) && string(prefix[8:12]) == "WEBP":
		return fileSignature{kind: "webp", class: "image"}, true
	case bytes.HasPrefix(prefix, []byte("BM")):
		return fileSignature{kind: "bmp", class: "image"}, true
	case bytes.HasPrefix(prefix, []byte("II*\x00")), bytes.HasPrefix(prefix, []byte("MM\x00*")):
		return fileSignature{kind: "tiff", class: "image"}, true
	case bytes.HasPrefix(prefix, []byte("PK\x03\x04")):
		return fileSignature{kind: "zip_or_ooxml", class: "archive"}, true
	case bytes.HasPrefix(prefix, []byte("\x1f\x8b")):
		return fileSignature{kind: "gzip", class: "archive"}, true
	case bytes.HasPrefix(prefix, []byte("Rar!\x1a\x07")):
		return fileSignature{kind: "rar", class: "archive"}, true
	case bytes.HasPrefix(prefix, []byte("7z\xbc\xaf\x27\x1c")):
		return fileSignature{kind: "7z", class: "archive"}, true
	case bytes.HasPrefix(prefix, []byte("BZh")):
		return fileSignature{kind: "bzip2", class: "archive"}, true
	case len(body) >= 262 && string(body[257:262]) == "ustar":
		return fileSignature{kind: "tar", class: "archive"}, true
	case bytes.HasPrefix(prefix, []byte("\x00\x00\x01\x00")):
		return fileSignature{kind: "ico", class: "image"}, true
	default:
		return fileSignature{}, false
	}
}

func declaredFileClass(obs dsctx.FileObservation) string {
	switch obs.Extension {
	case "jpg", "jpeg", "png", "gif", "webp", "bmp", "tif", "tiff", "svg", "ico":
		return "image"
	case "pdf":
		return "document"
	case "zip", "docx", "xlsx", "pptx", "rar", "7z", "gz", "tgz", "bz2", "tar":
		return "archive"
	case "exe", "dll", "sys", "com", "msi":
		return "executable"
	case "php", "phar", "sh", "bash", "py", "pl", "rb", "js":
		return "script"
	case "txt", "csv", "json", "jsonl", "xml", "yaml", "yml", "md", "html", "htm", "log":
		return "text"
	}
	mime := strings.ToLower(obs.MIME)
	switch {
	case strings.HasPrefix(mime, "image/"):
		return "image"
	case mime == "application/pdf":
		return "document"
	case mime == "application/zip", mime == "application/gzip", mime == "application/x-gzip",
		mime == "application/x-7z-compressed", mime == "application/vnd.rar", mime == "application/x-rar-compressed",
		strings.Contains(mime, "openxmlformats-officedocument"):
		return "archive"
	case strings.Contains(mime, "executable"), mime == "application/x-dosexec", mime == "application/x-msdownload":
		return "executable"
	case strings.Contains(mime, "php"), strings.Contains(mime, "script"):
		return "script"
	case strings.HasPrefix(mime, "text/"), mime == "application/json", mime == "application/xml",
		mime == "application/x-yaml", mime == "application/yaml":
		return "text"
	default:
		return ""
	}
}

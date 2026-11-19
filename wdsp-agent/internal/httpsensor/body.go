// Body 后处理（Phase 3 契约 §4）：采集等级门控、Content-Encoding 解码、
// 内容类型白名单、multipart 元数据摘要。
//
// 红线：任何路径下驻留内存的 Body 均不超 maxBodySize（解码输出同样钳制）；
// 白名单外/解码失败不采 Body，但 original_body_size 照记。
package httpsensor

import (
	"bytes"
	"compress/gzip"
	"compress/zlib"
	"encoding/json"
	"errors"
	"io"
	"mime"
	"mime/multipart"
	"strings"

	"github.com/jiuzhang-waf/wdsp-agent/internal/config"
)

// skipped 原因枚举（契约 §4 body_skipped_reason）。
const (
	skipNone        = ""
	skipContentType = "content_type"
	skipEncoding    = "encoding"
)

// bodyResult Body 后处理结果。
type bodyResult struct {
	body      string
	truncated bool
	origSize  int64
	skipped   string
}

// processBody 按采集等级与契约 §4 约束处理线上 Body。
// masked 为脱敏字段计数累加器（可为 nil；masked 指标，P1-03 §5.7）。
//   - L1：不采 Body（origSize 照记）；
//   - gzip/deflate 尝试解码（br/未知编码/解码失败 → skipped=encoding）；
//   - 内容类型白名单外 → skipped=content_type；
//   - multipart/form-data：不采本体，提取字段/文件元数据摘要，解析失败 → skipped=content_type；
//   - 解码后大小同样钳制在 maxBodySize（防解压炸弹驻留）。
func processBody(raw []byte, wireSize int64, truncated bool, headers map[string]string, pol *Policy, masked *int) bodyResult {
	res := bodyResult{origSize: wireSize, truncated: truncated}
	if pol.Level == config.LevelL0 || pol.Level == config.LevelL1 {
		res.truncated = false // L1 不采 Body，无截断语义
		return res
	}
	if len(raw) == 0 {
		return res
	}

	data := raw
	// Content-Encoding 解码（线上字节 → 实体字节）
	if enc := strings.ToLower(strings.TrimSpace(headers["content-encoding"])); enc != "" && enc != "identity" {
		switch enc {
		case "gzip", "deflate":
			decoded, decodeTruncated, err := decompress(data, enc, int64(pol.MaxBodySize))
			if err != nil {
				res.body = ""
				res.truncated = false
				res.skipped = skipEncoding
				return res
			}
			data = decoded
			res.truncated = res.truncated || decodeTruncated
		default:
			// br 及其他编码：不解压直接 skipped（契约 §4）
			res.body = ""
			res.truncated = false
			res.skipped = skipEncoding
			return res
		}
	}

	mediaType := mediaTypeOf(headers["content-type"])
	switch {
	case mediaType == "multipart/form-data":
		// §35：不采本体，尽力提取字段/文件元数据摘要；失败 → content_type
		summary, err := multipartSummary(data, headers["content-type"], pol.Masking.Params, masked)
		if err != nil {
			res.body = ""
			res.truncated = false
			res.skipped = skipContentType
			return res
		}
		res.body = summary
		return res
	case bodyTypeAllowed(mediaType):
		res.body = strings.ReplaceAll(string(data), "\x00", "")
		// 表单/JSON/GraphQL/XML/纯文本敏感字段脱敏（契约 §5 增强）
		var n int
		res.body, n = maskBodyParams(res.body, mediaType, pol.Masking.Params)
		if masked != nil {
			*masked += n
		}
		return res
	default:
		res.body = ""
		res.truncated = false
		res.skipped = skipContentType
		return res
	}
}

// mediaTypeOf 取 content-type 的媒体类型部分（小写、去参数）。
func mediaTypeOf(ct string) string {
	if i := strings.IndexByte(ct, ';'); i >= 0 {
		ct = ct[:i]
	}
	return strings.ToLower(strings.TrimSpace(ct))
}

// bodyTypeAllowed 内容类型白名单（契约 §4 + +json/+xml 结构化变体）。
func bodyTypeAllowed(mt string) bool {
	switch mt {
	case "application/json", "application/x-www-form-urlencoded",
		"application/xml", "application/javascript", "application/graphql":
		return true
	}
	return strings.HasPrefix(mt, "text/") ||
		(strings.HasPrefix(mt, "application/") && (strings.HasSuffix(mt, "+json") || strings.HasSuffix(mt, "+xml")))
}

// decompress gzip/deflate 解码；输出钳制在 max（防解压炸弹驻留内存）。
// 返回值中的 truncated 表示解码输出超过 max，供调用方并入 BodyTruncated。
func decompress(data []byte, encoding string, max int64) ([]byte, bool, error) {
	var rc io.ReadCloser
	var err error
	switch encoding {
	case "gzip":
		rc, err = gzip.NewReader(bytes.NewReader(data))
	default: // deflate
		rc, err = zlib.NewReader(bytes.NewReader(data))
	}
	if err != nil {
		return nil, false, err
	}
	defer rc.Close()
	// 多读 1 字节探测超限；输出仍钳在 max，避免解压炸弹驻留内存。
	out, err := io.ReadAll(io.LimitReader(rc, max+1))
	if err != nil {
		return nil, false, err
	}
	truncated := int64(len(out)) > max
	if truncated {
		out = out[:max]
	}
	return out, truncated, nil
}

// multipartSummary 提取 multipart 字段与文件元数据摘要（契约 §4/§35）。
// 字段值过 params 脱敏；文件只取 filename/content_type/size 元数据。
func multipartSummary(data []byte, contentType string, rule config.MaskRule, masked *int) (string, error) {
	_, params, err := mime.ParseMediaType(contentType)
	if err != nil {
		return "", err
	}
	boundary := params["boundary"]
	if boundary == "" {
		return "", errNoBoundary
	}
	mr := multipart.NewReader(bytes.NewReader(data), boundary)
	summary := struct {
		Multipart struct {
			Fields map[string]string `json:"fields"`
			Files  []struct {
				Filename    string `json:"filename"`
				ContentType string `json:"content_type"`
				Size        int64  `json:"size"`
			} `json:"files"`
		} `json:"multipart"`
	}{}
	summary.Multipart.Fields = make(map[string]string)
	for i := 0; i < maxMultipartParts; i++ {
		part, err := mr.NextPart()
		if err == io.EOF {
			break
		}
		if err != nil {
			return "", err
		}
		if fn := part.FileName(); fn != "" {
			// 文件 part：只计大小（读空），元数据入摘要
			size, err := io.Copy(io.Discard, part)
			if err != nil {
				return "", err
			}
			summary.Multipart.Files = append(summary.Multipart.Files, struct {
				Filename    string `json:"filename"`
				ContentType string `json:"content_type"`
				Size        int64  `json:"size"`
			}{
				Filename:    strings.ReplaceAll(fn, "\x00", ""),
				ContentType: strings.ReplaceAll(part.Header.Get("Content-Type"), "\x00", ""),
				Size:        size,
			})
			continue
		}
		// 字段 part：值过 params 脱敏（契约 §4）
		val, err := io.ReadAll(io.LimitReader(part, maxMultipartFieldBytes+1))
		if err != nil {
			return "", err
		}
		if len(val) > maxMultipartFieldBytes {
			val = val[:maxMultipartFieldBytes]
		}
		name := strings.ReplaceAll(part.FormName(), "\x00", "")
		if name == "" {
			continue
		}
		cleanVal := strings.ReplaceAll(string(val), "\x00", "")
		v, hit := maskParamValue(name, cleanVal, rule)
		if hit {
			if masked != nil {
				*masked++
			}
			if rule.Mode == config.MaskModeDrop {
				continue
			}
		}
		summary.Multipart.Fields[name] = v
	}
	out, err := json.Marshal(summary)
	if err != nil {
		return "", err
	}
	return string(out), nil
}

// multipart 解析护栏。
const (
	maxMultipartParts      = 100
	maxMultipartFieldBytes = 4 << 10
)

var errNoBoundary = errors.New("multipart 缺少 boundary")

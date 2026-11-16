package parser

import (
	"crypto/sha256"
	"encoding/hex"
	"io"
	"mime/multipart"

	dsctx "github.com/jiuzhang-waf/gateway/dynamic_security/context"
)

const maxFileContentPrefix = 512

// PartMeta multipart 单个 part 的元数据。文件前缀只在请求内存活供签名检测，
// 非导出字段不会进入事件 JSON；其余文件内容仍流式计数后丢弃。
type PartMeta struct {
	FieldName       string
	FileName        string
	ContentType     string
	Size            int64
	SensitiveTypes  []string `json:"sensitive_types,omitempty"`
	prefix          []byte
	complete        bool
	contentSHA256   string
	contentComplete bool
}

// ContentPrefix 返回最多 512 字节的文件前缀，以及该 part 是否完整读取。
// 总请求限额在 part 前耗尽时前缀可能为空，检测侧必须披露未检查。
// 调用方只读使用，不得在请求结束后保留或写入事件。
func (m PartMeta) ContentPrefix() ([]byte, bool) {
	return m.prefix, m.complete
}

// ContentFingerprint 返回完整文件内容的小写 SHA-256；不完整读取时返回空值。
// 哈希在流式读取时计算，不要求文件全文进入内存。
func (m PartMeta) ContentFingerprint() (string, bool) {
	return m.contentSHA256, m.contentComplete
}

type filePrefixBuffer struct {
	data []byte
}

func (b *filePrefixBuffer) Write(p []byte) (int, error) {
	if remaining := maxFileContentPrefix - len(b.data); remaining > 0 {
		n := min(len(p), remaining)
		b.data = append(b.data, p[:n]...)
	}
	return len(p), nil
}

// parseMultipart 流式读取 multipart/form-data：逐 part 记录元数据，
// 文件仅保留有界前缀供签名检测，其余内容经 io.Discard 丢弃，TeeReader 同步累计 BodySize/BodyHash。
// 截断：总字节超 MaxBodyParseBytes 置 BodyTruncated；part 元数据数超 MaxFileMetaCount 置 MultipartCapped。
func (p *Parsed) parseMultipart(body io.ReadCloser, boundary string, limits dsctx.ParseLimits) {
	defer func() { _ = body.Close() }()
	hc := &hashCounter{h: 14695981039346656037} // 与 shortHash 同为 FNV-1a 64
	mr := multipart.NewReader(io.TeeReader(body, hc), boundary)
	limit := int64(limits.MaxBodyParseBytes)
	for {
		if hc.n > limit {
			p.BodyTruncated = true
			break
		}
		if len(p.MultipartParts) >= limits.MaxFileMetaCount {
			p.MultipartCapped = true
			break
		}
		part, err := mr.NextPart()
		if err != nil {
			break // io.EOF 正常结束；格式错误保留已解析元数据
		}
		meta := PartMeta{
			FieldName:   part.FormName(),
			FileName:    part.FileName(),
			ContentType: part.Header.Get("Content-Type"),
		}
		remaining := limit + 1 - hc.n
		if remaining < 0 {
			remaining = 0
		}
		var reader io.Reader = part
		var prefix filePrefixBuffer
		hasher := sha256.New()
		if meta.FileName != "" {
			reader = io.TeeReader(reader, io.MultiWriter(&prefix, hasher))
		}
		n, readErr := io.CopyN(io.Discard, reader, remaining)
		meta.Size = n
		if meta.FileName != "" {
			meta.prefix = prefix.data
			meta.complete = readErr == io.EOF && n <= maxFileContentPrefix
			meta.contentComplete = readErr == io.EOF
			if meta.contentComplete {
				meta.contentSHA256 = hex.EncodeToString(hasher.Sum(nil))
			}
			p.HasFiles = true
		}
		p.MultipartParts = append(p.MultipartParts, meta)
	}
	p.BodySize = int(hc.n)
	p.BodyHash = formatHex(hc.h)
}

// hashCounter 流式 FNV-1a 64 与字节计数（配合 io.TeeReader 边读边算）。
type hashCounter struct {
	h uint64
	n int64
}

func (w *hashCounter) Write(b []byte) (int, error) {
	for _, c := range b {
		w.h ^= uint64(c)
		w.h *= 1099511628211
	}
	w.n += int64(len(b))
	return len(b), nil
}

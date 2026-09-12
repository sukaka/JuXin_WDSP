package parser

import (
	"io"
	"mime/multipart"

	dsctx "github.com/jiuzhang-waf/gateway/dynamic_security/context"
)

// PartMeta multipart 单个 part 的元数据（文件内容不落内存，仅流式计数大小）。
type PartMeta struct {
	FieldName   string
	FileName    string
	ContentType string
	Size        int64
}

// parseMultipart 流式读取 multipart/form-data：逐 part 记录元数据，
// part 内容经 io.Discard 丢弃（不缓存进内存），TeeReader 同步累计 BodySize/BodyHash。
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
		n, _ := io.CopyN(io.Discard, part, remaining)
		meta.Size = n
		if meta.FileName != "" {
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

// fileobs.go 上传侧文件观测提取（P1-04 文件资产生产方）。
// 输入为 multipart 流式解析的 part 元数据（PartMeta：文件内容经 io.Discard 丢弃，
// 不落内存）；输出挂统一主事件 file_observations（direction=UPLOAD）。
package parser

import (
	dsctx "github.com/jiuzhang-waf/gateway/dynamic_security/context"
)

// BuildUploadFileObservations 从 multipart 解析元数据提取上传文件观测。
// 仅文件 part（FileName 非空）产出观测；纯表单字段 part（无文件名）不产生。
// 文件名归一化分两个口径（纪律见 dsctx.FileObservation 注释）：FileName 截断 128
// 供证据/落库；MatchName 不截断供规则匹配——扩展名按未截断完整名提取（先截断会把
// 超长文件名的后缀截掉，EXT 规则与双扩展名信号静默不命中，属安全绕过）。
// 数量为 MultipartParts 子集（解析期已受 MaxFileMetaCount 护栏），无需重复封顶。
func BuildUploadFileObservations(parts []PartMeta) []dsctx.FileObservation {
	var out []dsctx.FileObservation
	for _, p := range parts {
		if p.FileName == "" {
			continue // 表单字段 part（非文件）
		}
		full := dsctx.SanitizeFileNameFull(p.FileName)
		if full == "" {
			continue // 归一化后无可识别文件名（如纯目录前缀），不产生观测
		}
		out = append(out, dsctx.FileObservation{
			Direction: dsctx.FileDirectionUpload,
			FileName:  dsctx.TruncateFileName(full),
			MatchName: full,
			Extension: dsctx.FileExtension(full),
			MIME:      dsctx.SanitizeMIME(p.ContentType),
			Size:      p.Size,
		})
	}
	return out
}

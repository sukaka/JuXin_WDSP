// fileobs.go 响应侧文件下载观测提取（P1-04 文件资产生产方）。
// 输入为原始（未截断未脱敏）Content-Disposition/Content-Type 头值——挂点侧响应头快照
// 按 256 字节截断值，超长 Content-Disposition 经快照解析必然失败、观测整体缺失
// （下载 BLOCK 与 OOXML 水印门禁随之失效），故观测改由原始头值提取，原始值只在
// 请求内存活，落观测的仍只有元数据，响应体不落观测。
package response

import (
	"mime"

	dsctx "github.com/jiuzhang-waf/gateway/dynamic_security/context"
)

// BuildDownloadFileObservation 提取响应侧文件下载观测；非文件下载响应返回 nil（零产出）。
//
// 判定口径：Content-Disposition 为 attachment/inline 且携带 filename
// （RFC 5987 filename* 与 RFC 2231 续段由 mime.ParseMediaType 解码）。
// v1 精度优先：无 filename 的响应（普通 JSON/页面/无文件名的 octet-stream 流）
// 一律不产出观测——宁可漏报未知下载，不把常规响应误判为文件（已知缺口如实声明）。
//
// contentDisposition/contentType 必须是挂点侧的原始头值（未经快照截断脱敏）；
// 文件名归一化两个口径与上传侧一致：FileName 截断 128 供证据/落库，MatchName
// 不截断供规则匹配，扩展名按未截断完整名提取（超长文件名截断会截掉后缀，
// 造成 EXT 规则与双扩展名信号绕过）。bodySize 为实际传输字节数（流式直通同样计数）。
func BuildDownloadFileObservation(contentDisposition, contentType string, bodySize int64) *dsctx.FileObservation {
	cd := contentDisposition
	if cd == "" {
		return nil
	}
	mediaType, params, err := mime.ParseMediaType(cd)
	if err != nil {
		return nil // 畸形头：不猜测，不产出（与解析器"格式错误保留已解析产物"纪律一致）
	}
	if mediaType != "attachment" && mediaType != "inline" {
		return nil // form-data 等非下载语义
	}
	full := dsctx.SanitizeFileNameFull(params["filename"])
	if full == "" {
		return nil
	}
	return &dsctx.FileObservation{
		Direction: dsctx.FileDirectionDownload,
		FileName:  dsctx.TruncateFileName(full),
		MatchName: full,
		Extension: dsctx.FileExtension(full),
		MIME:      dsctx.SanitizeMIME(contentType),
		Size:      bodySize,
	}
}

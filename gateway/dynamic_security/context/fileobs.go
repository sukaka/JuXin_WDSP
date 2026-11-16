// fileobs.go 文件传输观测（P1-04 文件资产生产方）共享类型与清洗助手。
// 上传侧来自 multipart 解析元数据（parser.PartMeta，文件前缀有界留存供签名检测，其余内容流式计数后即弃），
// 下载侧来自响应捕获头快照（Content-Disposition/Content-Type）与实际传输字节数。
// 观测只含元数据，绝不携带文件内容。
package context

import (
	"mime"
	"strings"
	"unicode/utf8"
)

// 文件观测方向（与 api_file_assets.direction CHECK 词表对齐）。
const (
	FileDirectionUpload   = "UPLOAD"   // 请求侧 multipart 文件 part
	FileDirectionDownload = "DOWNLOAD" // 响应侧文件下载（Content-Disposition 携带文件名）
)

// 文件观测字段上限（与 api_file_assets 列宽对齐）。
const (
	MaxFileNameLen = 128
	MaxFileExtLen  = 16
	MaxFileMIMELen = 128
)

// FileObservation 一次文件传输观测（随统一主事件 file_observations 键上报，
// 供管理面 upsert api_file_assets）。
//
// 脱敏纪律（filename 选明文截断而非哈希，理由）：文件资产盘点的核心用途是
// 按文件名识别敏感文件流转（任务书 §106 File TOP/敏感文件统计与 §16 文件画像均
// 以文件名称为资产键），哈希会让资产表失去可读性与聚合意义；文件名属传输元数据
// 而非凭据，与 RawPath 同一纪律（basename 归一化 + 去控制字符 + 截断 128）。
type FileObservation struct {
	Direction string `json:"direction"` // UPLOAD / DOWNLOAD
	FileName  string `json:"filename"`  // 明文截断 128（理由见类型注释；basename 归一化）
	Extension string `json:"extension,omitempty"`
	MIME      string `json:"mime,omitempty"`
	// Size 声明/观测字节数：上传 = part 流式计数（含截断口径，见 MultipartCapped）；
	// 下载 = 实际传输字节数（流式直通同样计数）。
	Size int64 `json:"size"`
	// ContentSHA256 仅对完整读取的文件内容生成小写 SHA-256 指纹；截断/流式/未知内容为空。
	ContentSHA256 string `json:"content_sha256,omitempty"`
	// MatchName 规则匹配用完整文件名（basename 归一化 + 去控制字符，但不截断）：
	// EXT 扩展名提取、FILENAME_REGEX 与双扩展名判定一律以此为准——先截断后匹配会把
	// 超长文件名的后缀截掉（A×200.exe → 无扩展名），合规规则与双扩展名信号静默不命中。
	// 绝不序列化（json:"-"）：事件与资产落库一律用截断后的 FileName（列宽对齐）。
	MatchName string `json:"-"`
	// SensitiveTypes 为命中的数据类型标签，不含匹配值或文件正文。
	SensitiveTypes []string `json:"sensitive_types,omitempty"`
}

// MatchFileName 规则匹配口径文件名：MatchName 非空时用完整名，否则回退 FileName
// （历史构造点/直构观测未填 MatchName 时保持旧行为，匹配口径不劣化）。
func (o FileObservation) MatchFileName() string {
	if o.MatchName != "" {
		return o.MatchName
	}
	return o.FileName
}

// SanitizeFileName 文件名归一化：basename + 去控制字符 + 按字符截断 MaxFileNameLen
// （证据/落库口径；归一化后为空串表示无可识别文件名）。
func SanitizeFileName(name string) string {
	return TruncateFileName(SanitizeFileNameFull(name))
}

// SanitizeFileNameFull 文件名归一化（匹配口径，不截断）：basename（剥 \ 与 / 目录前缀——
// 浏览器可能上送 C:\fakepath\x.pdf，穿越形态 ../../etc/passwd 归一为 passwd，目录前缀
// 不具资产语义）+ 去控制字符 + 去首尾空白。规则匹配与扩展名提取必须用本产物，
// 截断（TruncateFileName/SanitizeFileName）只允许发生在证据落库前。
func SanitizeFileNameFull(name string) string {
	if i := strings.LastIndexAny(name, `/\`); i >= 0 {
		name = name[i+1:]
	}
	name = strings.Map(func(r rune) rune {
		if r < 0x20 || r == 0x7f {
			return -1
		}
		return r
	}, name)
	return strings.TrimSpace(name)
}

// TruncateFileName 按字符截断 MaxFileNameLen（证据/落库口径的最后一步）。
func TruncateFileName(name string) string {
	if utf8.RuneCountInString(name) > MaxFileNameLen {
		name = string([]rune(name)[:MaxFileNameLen])
	}
	return name
}

// FileExtension 从（已归一化）文件名提取扩展名：最后一段点后缀小写化。
// 无点、点结尾、点开头（.profile 隐藏文件）或后缀超 MaxFileExtLen（超长"后缀"实为
// 文件名一部分，不识别为扩展名，避免截断出错误分类键）时返回空串。
func FileExtension(name string) string {
	i := strings.LastIndexByte(name, '.')
	if i <= 0 || i == len(name)-1 {
		return ""
	}
	ext := strings.ToLower(name[i+1:])
	if len(ext) > MaxFileExtLen {
		return ""
	}
	return ext
}

// SanitizeMIME Content-Type 归一化：主类型小写、剥离 charset 等参数（资产聚合按
// 主类型口径），去控制字符并截断 MaxFileMIMELen；解析失败降级为 ';' 前缀小写
// （与 parser.splitMediaType 同一纪律）。
func SanitizeMIME(ct string) string {
	if ct == "" {
		return ""
	}
	mt, _, err := mime.ParseMediaType(ct)
	if err != nil {
		mt = strings.ToLower(strings.TrimSpace(strings.SplitN(ct, ";", 2)[0]))
	}
	mt = strings.Map(func(r rune) rune {
		if r < 0x20 || r == 0x7f {
			return -1
		}
		return r
	}, mt)
	if len(mt) > MaxFileMIMELen {
		mt = mt[:MaxFileMIMELen]
	}
	return mt
}

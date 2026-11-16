// signature.go 文件下载签名 v1（W13-GW / P2-02，任务书 §110 子集：签名嵌入+文件验证+来源追踪）：
// 与水印同一捕获路径、在水印之后执行——对下载响应体（脱敏/水印产物）计算内容
// sha256，生成来源追踪 token 并嵌入文本尾注释行、JSON 顶层 "_sig" 或 OOXML ZIP 注释：
//
//	token = "jzsig1.{kid}.{unixts}.{hex(HMAC-SHA256(key, kid|filename|content_sha256_hex|unixts|identity_fp))}"
//
// kid 标识密钥版本（轮换可追踪），identity_fp 为请求身份指纹（仅凭据派生，匿名为空串）——
// 外发文件可经管理面按 kid+filename+内容哈希+身份指纹复算验证，实现泄露来源追踪。
//
// 范围纪律（不引媒体处理依赖）：文本族（text/*）与 application/json 沿用注释行/顶层 "_sig"；
// DOCX/XLSX/PPTX 使用 OOXML ZIP 注释签名，原注释经 Base64 封装以保留原始字节，见 signature_ooxml.go。
//
// 安全纪律：key 为秘密材料（发布通道 system_settings 密文解密下发），配置错误信息不含密钥值；
// 证据只含 kid/filename/mime，不含密钥与完整内容哈希；签名嵌入失败一律 FAIL_OPEN 直通
// （审计能力，不阻断业务，不随 api_response_fail_policy 升级为抑制，与水印同一纪律）。
package response

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"path"
	"strconv"
	"strings"
	"time"
	"unicode/utf8"
)

// 文件签名 v1 常量（token 前缀/JSON 键名为跨分片契约：管理面验证侧按同一格式解析复算）。
const (
	// FileSignatureTokenPrefix token 版本前缀（v1 格式标识）。
	FileSignatureTokenPrefix = "jzsig1"
	// DefaultFileSignatureJSONKey JSON 顶层签名字段缺省键名。
	DefaultFileSignatureJSONKey = "_sig"
	// fileSignatureKeyBytes 签名密钥长度（字节；与扫描密钥同一 32 字节约束）。
	fileSignatureKeyBytes = 32
	// maxFileSignatureKIDLen kid 长度上限（防误配；kid 进入 token 第二段）。
	maxFileSignatureKIDLen = 64
)

// FileSignatureConfig 文件签名 v1 配置（发布通道下发 api_file_signature 段）。
type FileSignatureConfig struct {
	Enabled bool
	KID     string // 密钥标识（token 第二段；轮换追踪）
	key     []byte // HMAC 密钥（秘密材料，不落日志/证据）
}

// NewFileSignatureConfig 解析并校验文件签名配置（配置错误显式返回，不静默吞错）。
// enabled=false 时只做归一化不强校验（未启用不生效，网关零行为变化）；
// enabled=true 时 kid 必填（[A-Za-z0-9_-]，≤64——kid 以 '.' 分隔嵌入 token，
// 含 '.' 会破坏分段解析、含 '|' 会破坏 HMAC 消息字段边界）；
// key_hex 必填且为 32 字节 hex（错误信息不含密钥值）。
func NewFileSignatureConfig(enabled bool, kid, keyHex string) (*FileSignatureConfig, error) {
	cfg := &FileSignatureConfig{Enabled: enabled, KID: strings.TrimSpace(kid)}
	if !enabled {
		return cfg, nil
	}
	if cfg.KID == "" {
		return nil, fmt.Errorf("api_file_signature: kid required when enabled")
	}
	if utf8.RuneCountInString(cfg.KID) > maxFileSignatureKIDLen {
		return nil, fmt.Errorf("api_file_signature: kid must be <= %d chars", maxFileSignatureKIDLen)
	}
	for _, r := range cfg.KID {
		if (r >= 'a' && r <= 'z') || (r >= 'A' && r <= 'Z') || (r >= '0' && r <= '9') || r == '_' || r == '-' {
			continue
		}
		return nil, fmt.Errorf("api_file_signature: kid 仅允许 [A-Za-z0-9_-]（token 分段与 HMAC 字段边界约束）")
	}
	key, err := hex.DecodeString(strings.TrimSpace(keyHex))
	if err != nil {
		return nil, fmt.Errorf("api_file_signature: key_hex: invalid hex encoding")
	}
	if len(key) != fileSignatureKeyBytes {
		return nil, fmt.Errorf("api_file_signature: key must be %d bytes (%d hex chars)", fileSignatureKeyBytes, fileSignatureKeyBytes*2)
	}
	cfg.key = key
	return cfg, nil
}

// AllowsContentType 判定 Content-Type 是否可嵌入文本族或 OOXML 签名
// （text/*、application/json、docx/xlsx/pptx；签名段契约仅 enabled/kid/key_hex）。
func (c *FileSignatureConfig) AllowsContentType(contentType string) bool {
	if c == nil || !c.Enabled {
		return false
	}
	mt := fileWatermarkMediaType(contentType)
	return mt == "application/json" || strings.HasPrefix(mt, "text/") || OOXMLWatermarkExtension(mt) != ""
}

// BuildFileSignatureToken 生成签名 token（纯函数，可复算验证）：
// HMAC-SHA256(key, kid|filename|content_sha256_hex|unixts|identity_fp)，
// token = jzsig1.{kid}.{unixts}.{hmac_hex}。
func BuildFileSignatureToken(key []byte, kid, filename, contentSHA256Hex string, unixTS int64, identityFP string) string {
	mac := hmac.New(sha256.New, key)
	mac.Write([]byte(kid + "|" + filename + "|" + contentSHA256Hex + "|" + strconv.FormatInt(unixTS, 10) + "|" + identityFP))
	return FileSignatureTokenPrefix + "." + kid + "." + strconv.FormatInt(unixTS, 10) + "." + hex.EncodeToString(mac.Sum(nil))
}

// ApplyFileSignature 对完整捕获的下载响应体嵌入签名；返回改写后体、token、是否已嵌入、错误。
// 签名的内容快照为传入 body（挂点侧在水印之后调用——签名覆盖脱敏/水印后的最终交付内容，
// 与"验证外发文件实际内容"语义一致）。不嵌入的情形（applied=false, err=nil）：
// 未启用 / 空体 / 不支持的类型 / JSON 顶层非对象 / JSON 签名键已存在 / OOXML 已签名。
// JSON、OOXML 解析失败返回 err（调用方 FAIL_OPEN 直通，与水印同一纪律）。
func ApplyFileSignature(body []byte, contentType string, cfg *FileSignatureConfig, filename, identityFP string, now time.Time) ([]byte, string, bool, error) {
	if cfg == nil || !cfg.Enabled || len(body) == 0 || !cfg.AllowsContentType(contentType) {
		return body, "", false, nil
	}
	sum := sha256.Sum256(body)
	token := BuildFileSignatureToken(cfg.key, cfg.KID, filename, hex.EncodeToString(sum[:]), now.Unix(), identityFP)
	mt := fileWatermarkMediaType(contentType)
	if ext := OOXMLWatermarkExtension(mt); ext != "" {
		if !strings.EqualFold(path.Ext(filename), "."+ext) {
			return body, "", false, nil
		}
		return applyOOXMLFileSignature(body, token)
	}
	switch mt {
	case "application/json":
		out, applied, err := applyJSONFileWatermark(body, DefaultFileSignatureJSONKey, token)
		return out, token, applied, err
	case "text/markdown", "text/html":
		// HTML 注释行：渲染不可见，不破坏文档结构（与水印同一形态）
		return appendFileWatermarkLine(body, "<!-- "+token+" -->"), token, true, nil
	default:
		// text/* 其余类型："# " 注释行（各类型取舍见 watermark.go 文件头注释）
		return appendFileWatermarkLine(body, "# "+token), token, true, nil
	}
}

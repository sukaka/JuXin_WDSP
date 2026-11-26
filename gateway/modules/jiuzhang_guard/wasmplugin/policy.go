// Package wasmplugin 实现 Phase 9D-1 网关 Wasm（wazero）热插拔自定义检测插件沙箱。
//
// 安全与隔离纪律：
//   - 纯 Go 零 CGO 解释器模式（wazero.NewRuntimeConfigInterpreter），启用
//     WithCloseOnContextDone(true) 与 WithMemoryLimitPages(pages)；
//   - 零 WASI、零文件系统、零网络、零环境变量、零时钟/随机数导入；仅注册只读宿主模块 "wdsp_env"；
//   - 严格 JSON 解码（DisallowUnknownFields）+ 常量时间 SHA-256 完整性校验，任何校验失败
//     fail-closed 拒绝配置加载；
//   - 凭据头严格隔离：Authorization / Cookie / Proxy-Authorization / DPoP / X-Api-Key
//     对 Wasm 客体恒返回 -1，彻底阻断第三方插件窃取凭据；
//   - 每请求全新实例化并 defer 关闭，零跨请求线性内存残留；
//   - ALLOW 绝不绕过下游 API 动态防护或 Coraza WAF。
package wasmplugin

import (
	"bytes"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"regexp"
	"strings"
)

const (
	// SchemaVersion 本网关支持的 wasm_plugins 配置段契约版本（不一致 fail-closed 拒载）。
	SchemaVersion = 1

	// ABIVersionV1 唯一支持的宿主 ABI 版本标识。
	ABIVersionV1 = "wdsp_v1"

	// HostModuleName 暴露给 Wasm 客体的唯一只读宿主模块名。
	HostModuleName = "wdsp_env"

	// ExportMemoryName 与 ExportEntrypointName 客体模块必须导出的符号名。
	ExportMemoryName     = "memory"
	ExportEntrypointName = "wdsp_on_request"

	// 插件运行模式词表（跨层冻结契约）。
	ModeOff     = "OFF"
	ModeObserve = "OBSERVE"
	ModeProtect = "PROTECT"

	// 故障处置策略词表（跨层冻结契约）。
	FailOpen   = "FAIL_OPEN"
	FailClosed = "FAIL_CLOSED"

	// 客体通过 set_result 上报的动作码枚举。
	ActionAllow     int32 = 0
	ActionObserve   int32 = 1
	ActionBlock     int32 = 2
	ActionRateLimit int32 = 3

	// 配置与资源护栏上限（与 server/internal/wasmplugins 及 web/src/api/wasmPlugins.ts 严格对齐）。
	MaxPluginsPerApp = 16
	MaxAppIDLen      = 128
	MaxPluginIDLen   = 128
	MaxPluginNameLen = 128
	MaxWasmBytes     = 4 * 1024 * 1024 // 4 MiB 解码后上限

	MinPriority = 0
	MaxPriority = 10000

	MinTimeoutMS     = 1
	MaxTimeoutMS     = 50
	DefaultTimeoutMS = 2

	MinMemoryKB     = 256
	MaxMemoryKB     = 16384
	DefaultMemoryKB = 4096

	MinBodyBytes     = 0
	MaxBodyBytes     = 65536
	DefaultBodyBytes = 65536

	MaxPathPrefixes = 32
	MaxPathLen      = 256

	// 客体结果字段边界。
	MaxScoreDelta = 100
	MaxRuleLen    = 128
	MaxReasonLen  = 128

	// WebAssembly 线性内存单页大小（64 KiB）。
	WasmPageSizeBytes = 65536
	WasmPageSizeKB    = 64
)

var (
	pluginNamePattern = regexp.MustCompile(`^[a-zA-Z0-9][a-zA-Z0-9._-]{0,127}$`)
	wasmMagicHeader   = []byte{0x00, 0x61, 0x73, 0x6d, 0x01, 0x00, 0x00, 0x00}
)

// Config 发布通道下发的 wasm_plugins 处理器段。
type Config struct {
	SchemaVersion int            `json:"schema_version"`
	ApplicationID string         `json:"application_id"`
	Plugins       []PluginConfig `json:"plugins"`
}

// PluginConfig 单个 Wasm 检测插件的配置与已验证二进制。
type PluginConfig struct {
	ID           string   `json:"id"`
	Name         string   `json:"name"`
	Version      int      `json:"version"`
	ABIVersion   string   `json:"abi_version"`
	Mode         string   `json:"mode"`
	SHA256       string   `json:"sha256"`
	WasmBase64   string   `json:"wasm_base64"`
	Priority     int      `json:"priority"`
	TimeoutMS    int      `json:"timeout_ms"`
	MaxMemoryKB  int      `json:"max_memory_kb"`
	MaxBodyBytes int      `json:"max_body_bytes"`
	FailPolicy   string   `json:"fail_policy"`
	PathPrefixes []string `json:"path_prefixes"`

	// WasmBytes 解码并通过常量时间 SHA-256 校验后的原始 Wasm 二进制，绝不参与 JSON 序列化。
	WasmBytes []byte `json:"-"`
}

// MemoryLimitPages 返回该插件对应的 WebAssembly 线性内存页数上限（每页 64 KiB，向下取整严守上限）。
func (p PluginConfig) MemoryLimitPages() uint32 {
	pages := p.MaxMemoryKB / WasmPageSizeKB
	if pages < 1 {
		return 1
	}
	return uint32(pages)
}

// rawConfig / rawPluginConfig 用于严格 JSON 解码并区分显式 0 值与缺省省略（如 max_body_bytes: 0）。
type rawConfig struct {
	SchemaVersion int               `json:"schema_version"`
	ApplicationID string            `json:"application_id"`
	Plugins       []rawPluginConfig `json:"plugins"`
}

type rawPluginConfig struct {
	ID           string   `json:"id"`
	Name         string   `json:"name"`
	Version      int      `json:"version"`
	ABIVersion   string   `json:"abi_version"`
	Mode         string   `json:"mode"`
	SHA256       string   `json:"sha256"`
	WasmBase64   string   `json:"wasm_base64"`
	Priority     *int     `json:"priority"`
	TimeoutMS    *int     `json:"timeout_ms"`
	MaxMemoryKB  *int     `json:"max_memory_kb"`
	MaxBodyBytes *int     `json:"max_body_bytes"`
	FailPolicy   string   `json:"fail_policy"`
	PathPrefixes []string `json:"path_prefixes"`
}

// ParseAndValidateConfig 严格解码（DisallowUnknownFields）并全量校验 wasm_plugins 段。
// 任何未知字段、不支持的 schema_version、超出边界、非法 Wasm 头或 SHA-256 不一致均拒绝加载（fail-closed）。
func ParseAndValidateConfig(raw json.RawMessage) (*Config, error) {
	dec := json.NewDecoder(bytes.NewReader(raw))
	dec.DisallowUnknownFields()
	var rc rawConfig
	if err := dec.Decode(&rc); err != nil {
		return nil, fmt.Errorf("wasm_plugins: 配置结构解析失败（拒绝加载）: %w", err)
	}
	var extra any
	if err := dec.Decode(&extra); err != io.EOF {
		return nil, fmt.Errorf("wasm_plugins: 配置含多余内容（拒绝加载）")
	}

	cfg := &Config{
		SchemaVersion: rc.SchemaVersion,
		ApplicationID: rc.ApplicationID,
		Plugins:       make([]PluginConfig, 0, len(rc.Plugins)),
	}
	for _, rp := range rc.Plugins {
		priority := 0
		if rp.Priority != nil {
			priority = *rp.Priority
		}
		timeoutMS := DefaultTimeoutMS
		if rp.TimeoutMS != nil {
			timeoutMS = *rp.TimeoutMS
		}
		maxMemoryKB := DefaultMemoryKB
		if rp.MaxMemoryKB != nil {
			maxMemoryKB = *rp.MaxMemoryKB
		}
		maxBodyBytes := DefaultBodyBytes
		if rp.MaxBodyBytes != nil {
			maxBodyBytes = *rp.MaxBodyBytes
		}
		failPolicy := rp.FailPolicy
		if failPolicy == "" {
			failPolicy = FailOpen
		}
		cfg.Plugins = append(cfg.Plugins, PluginConfig{
			ID:           rp.ID,
			Name:         rp.Name,
			Version:      rp.Version,
			ABIVersion:   rp.ABIVersion,
			Mode:         rp.Mode,
			SHA256:       rp.SHA256,
			WasmBase64:   rp.WasmBase64,
			Priority:     priority,
			TimeoutMS:    timeoutMS,
			MaxMemoryKB:  maxMemoryKB,
			MaxBodyBytes: maxBodyBytes,
			FailPolicy:   failPolicy,
			PathPrefixes: append([]string(nil), rp.PathPrefixes...),
		})
	}

	if err := ValidateConfig(cfg); err != nil {
		return nil, fmt.Errorf("wasm_plugins: 配置校验未通过（拒绝加载）: %w", err)
	}
	return cfg, nil
}

// ValidateConfig 全量校验解析后的 wasm_plugins 配置并完成 base64 解码与常量时间 SHA-256 校验。
func ValidateConfig(cfg *Config) error {
	if cfg == nil {
		return errors.New("config is nil")
	}
	var errs []error
	add := func(format string, args ...any) {
		errs = append(errs, fmt.Errorf(format, args...))
	}

	if cfg.SchemaVersion != SchemaVersion {
		add("schema_version: 不支持的版本 %d（本网关支持 %d）", cfg.SchemaVersion, SchemaVersion)
	}
	if len(cfg.ApplicationID) > MaxAppIDLen || hasControlChars(cfg.ApplicationID) {
		add("application_id: 长度超过 %d 或含控制字符", MaxAppIDLen)
	}
	if len(cfg.Plugins) > MaxPluginsPerApp {
		add("plugins: 数量 %d 超过单应用上限 %d", len(cfg.Plugins), MaxPluginsPerApp)
	}

	seenIDs := make(map[string]struct{}, len(cfg.Plugins))
	for i := range cfg.Plugins {
		p := &cfg.Plugins[i]
		prefix := fmt.Sprintf("plugins[%d]", i)

		trimmedID := strings.TrimSpace(p.ID)
		if trimmedID == "" || trimmedID != p.ID || len(p.ID) > MaxPluginIDLen || hasControlChars(p.ID) {
			add("%s.id: 不能为空、含首尾空白/控制字符或超过 %d 字符", prefix, MaxPluginIDLen)
		} else {
			if _, dup := seenIDs[p.ID]; dup {
				add("%s.id: 重复的插件 ID %q", prefix, p.ID)
			}
			seenIDs[p.ID] = struct{}{}
		}

		if !pluginNamePattern.MatchString(p.Name) {
			add("%s.name: 非法插件名称 %q（须匹配 ^[a-zA-Z0-9][a-zA-Z0-9._-]{0,127}$）", prefix, p.Name)
		}
		if p.Version < 1 {
			add("%s.version: 必须 >= 1，实际 %d", prefix, p.Version)
		}
		if p.ABIVersion != ABIVersionV1 {
			add("%s.abi_version: 不支持的 ABI 版本 %q（仅支持 %q）", prefix, p.ABIVersion, ABIVersionV1)
		}
		switch p.Mode {
		case ModeOff, ModeObserve, ModeProtect:
		default:
			add("%s.mode: 非法运行模式 %q（仅支持 OFF|OBSERVE|PROTECT）", prefix, p.Mode)
		}
		if !isLowerHexSHA256(p.SHA256) {
			add("%s.sha256: 必须为 64 位小写十六进制摘要", prefix)
		}
		if p.Priority < MinPriority || p.Priority > MaxPriority {
			add("%s.priority: %d 超出允许范围 [%d, %d]", prefix, p.Priority, MinPriority, MaxPriority)
		}
		if p.TimeoutMS < MinTimeoutMS || p.TimeoutMS > MaxTimeoutMS {
			add("%s.timeout_ms: %d 超出允许范围 [%d, %d]", prefix, p.TimeoutMS, MinTimeoutMS, MaxTimeoutMS)
		}
		if p.MaxMemoryKB < MinMemoryKB || p.MaxMemoryKB > MaxMemoryKB {
			add("%s.max_memory_kb: %d 超出允许范围 [%d, %d]", prefix, p.MaxMemoryKB, MinMemoryKB, MaxMemoryKB)
		}
		if p.MaxBodyBytes < MinBodyBytes || p.MaxBodyBytes > MaxBodyBytes {
			add("%s.max_body_bytes: %d 超出允许范围 [%d, %d]", prefix, p.MaxBodyBytes, MinBodyBytes, MaxBodyBytes)
		}
		switch p.FailPolicy {
		case FailOpen, FailClosed:
		default:
			add("%s.fail_policy: 非法故障策略 %q（仅支持 FAIL_OPEN|FAIL_CLOSED）", prefix, p.FailPolicy)
		}
		if len(p.PathPrefixes) > MaxPathPrefixes {
			add("%s.path_prefixes: 数量 %d 超过上限 %d", prefix, len(p.PathPrefixes), MaxPathPrefixes)
		}
		for j, pfx := range p.PathPrefixes {
			if pfx == "" || strings.TrimSpace(pfx) != pfx || !strings.HasPrefix(pfx, "/") ||
				len(pfx) > MaxPathLen || strings.ContainsAny(pfx, "?# \t") || hasControlChars(pfx) {
				add("%s.path_prefixes[%d]: 必须以 / 开头、长度 <= %d 且不含 ?/#、空白或控制字符", prefix, j, MaxPathLen)
			}
		}

		// 解码 Wasm 二进制并执行常量时间 SHA-256 校验（fail-closed）
		wasmBytes, err := decodeAndVerifyWasm(p.WasmBase64, p.SHA256)
		if err != nil {
			add("%s.wasm_base64: %v", prefix, err)
		} else {
			p.WasmBytes = wasmBytes
		}
	}

	return errors.Join(errs...)
}

func decodeAndVerifyWasm(b64, expectedSHA256 string) ([]byte, error) {
	if b64 == "" {
		return nil, errors.New("不能为空")
	}
	if base64.StdEncoding.DecodedLen(len(b64)) > MaxWasmBytes+3 {
		return nil, fmt.Errorf("编码体积超过解码上限 %d 字节", MaxWasmBytes)
	}
	decoded, err := base64.StdEncoding.DecodeString(b64)
	if err != nil {
		return nil, fmt.Errorf("base64 解码失败: %w", err)
	}
	if len(decoded) < len(wasmMagicHeader) {
		return nil, fmt.Errorf("二进制长度不足 %d 字节（缺少 Wasm 魔数与版本头）", len(wasmMagicHeader))
	}
	if len(decoded) > MaxWasmBytes {
		return nil, fmt.Errorf("解码后大小 %d 字节超过上限 %d 字节", len(decoded), MaxWasmBytes)
	}
	if !bytes.Equal(decoded[:len(wasmMagicHeader)], wasmMagicHeader) {
		return nil, errors.New("无效的 WebAssembly 魔数或版本头（须为 \\x00asm\\x01\\x00\\x00\\x00）")
	}
	if isLowerHexSHA256(expectedSHA256) {
		sum := sha256.Sum256(decoded)
		actualHex := hex.EncodeToString(sum[:])
		if subtle.ConstantTimeCompare([]byte(actualHex), []byte(expectedSHA256)) != 1 {
			return nil, errors.New("SHA-256 摘要校验不匹配（疑似篡改或配置损坏，已 fail-closed 拒绝）")
		}
	}
	return decoded, nil
}

func isLowerHexSHA256(s string) bool {
	if len(s) != 64 {
		return false
	}
	for i := 0; i < 64; i++ {
		c := s[i]
		if !((c >= '0' && c <= '9') || (c >= 'a' && c <= 'f')) {
			return false
		}
	}
	return true
}

func hasControlChars(s string) bool {
	for _, r := range s {
		if r < 0x20 || r == 0x7f {
			return true
		}
	}
	return false
}

// sanitizeText 剥离 ASCII 控制字符并按字节上限安全截断（防日志注入与超长输出）。
func sanitizeText(s string, maxLen int) string {
	s = strings.Map(func(r rune) rune {
		if r < 0x20 || r == 0x7f {
			return -1
		}
		return r
	}, strings.TrimSpace(s))
	if maxLen > 0 && len(s) > maxLen {
		s = s[:maxLen]
	}
	return s
}

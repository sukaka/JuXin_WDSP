// validate.go 内核级 XDP 加速配置、Unix Socket 路径与物理网卡名安全校验（纯函数，无网络 IO）。
package xdpaccel

import (
	"fmt"
	"path"
	"regexp"
	"strings"
)

// FieldError 字段级校验错误。
type FieldError struct {
	Field   string `json:"field"`
	Message string `json:"message"`
}

// ValidationError 校验错误集合（handler 映射为 400 details）。
type ValidationError struct {
	Errors []FieldError
}

func (e *ValidationError) Error() string {
	return fmt.Sprintf("xdp acceleration validation failed: %d field(s)", len(e.Errors))
}

// interfaceNameRE 限制为合法 Linux 网卡名（IFNAMSIZ-1 = 15 字符）。
var interfaceNameRE = regexp.MustCompile(`^[a-zA-Z0-9][a-zA-Z0-9._-]{0,14}$`)

// forbiddenVirtualPrefixes 容器、虚拟网桥与隧道网卡前缀（小写比较，严禁挂载 XDP）。
var forbiddenVirtualPrefixes = []string{
	"docker",
	"br-",
	"veth",
	"virbr",
	"cni",
	"flannel",
	"cali",
	"tun",
	"tap",
	"wg",
}

// ValidAttachMode 判断挂载模式是否合法。
func ValidAttachMode(mode string) bool {
	return mode == AttachModeAuto || mode == AttachModeNative || mode == AttachModeGeneric
}

// NormalizeConfig 规范化配置（去首尾空白、attach_mode 小写化、保证 interfaces 非 nil）。
func NormalizeConfig(cfg *Config) {
	if cfg == nil {
		return
	}
	cfg.SocketPath = strings.TrimSpace(cfg.SocketPath)
	cfg.AttachMode = strings.ToLower(strings.TrimSpace(cfg.AttachMode))
	if cfg.Interfaces == nil {
		cfg.Interfaces = []string{}
		return
	}
	out := make([]string, 0, len(cfg.Interfaces))
	for _, item := range cfg.Interfaces {
		out = append(out, strings.TrimSpace(item))
	}
	cfg.Interfaces = out
}

// ValidateSocketPath 严格校验本地 Unix Domain Socket 路径：
//   - 非空且长度 <= 256，不含空白、反斜杠、控制字符或网络协议 scheme；
//   - 必须位于 /var/run/caddy/sidecars/ 或 /run/jiuzhang/ 目录下并指向具体文件名；
//   - 禁止包含 ".."、"//" 或未归一化路径段（path.Clean 后须与原串完全一致且仍在白名单前缀下）。
func ValidateSocketPath(socketPath string) string {
	return validateSocketPathWithPrefixes(socketPath, AllowedSocketPrefixCaddy, AllowedSocketPrefixRun)
}

func validateSocketPathWithPrefixes(socketPath string, prefixes ...string) string {
	if socketPath == "" {
		return "Unix Socket 路径不能为空"
	}
	if len(socketPath) > MaxSocketPathLen {
		return fmt.Sprintf("Unix Socket 路径长度不能超过 %d 字符", MaxSocketPathLen)
	}
	if hasControlChars(socketPath) || strings.ContainsAny(socketPath, " \t\\") {
		return "Unix Socket 路径不得包含空白、反斜杠或控制字符"
	}
	lower := strings.ToLower(socketPath)
	if strings.Contains(lower, "://") ||
		strings.HasPrefix(lower, "http:") ||
		strings.HasPrefix(lower, "https:") ||
		strings.HasPrefix(lower, "tcp:") ||
		strings.HasPrefix(lower, "unix:") {
		return "Unix Socket 路径必须为本地绝对路径，禁止网络协议地址"
	}
	if strings.Contains(socketPath, "..") {
		return "Unix Socket 路径不得包含上级目录引用（..）"
	}
	if strings.Contains(socketPath, "//") {
		return "Unix Socket 路径不得包含重复斜杠"
	}
	if strings.HasSuffix(socketPath, "/") {
		return "Unix Socket 路径必须指向具体 Socket 文件，不能以 / 结尾"
	}
	if !hasAnyPrefix(socketPath, prefixes) {
		return fmt.Sprintf("Unix Socket 路径必须位于 %s 或 %s 目录下", AllowedSocketPrefixCaddy, AllowedSocketPrefixRun)
	}
	cleaned := path.Clean(socketPath)
	if cleaned != socketPath || !hasAnyPrefix(cleaned, prefixes) {
		return "Unix Socket 路径必须为规范化绝对路径且不得跳出受控目录"
	}
	return ""
}

func hasAnyPrefix(s string, prefixes []string) bool {
	for _, p := range prefixes {
		if p != "" && strings.HasPrefix(s, p) && len(s) > len(p) {
			return true
		}
	}
	return false
}

// ValidateInterfaceName 校验单个物理业务网卡名称，拒绝环回口 lo 及虚拟/容器/隧道前缀。
func ValidateInterfaceName(name string) string {
	if name == "" {
		return "网卡名称不能为空"
	}
	if !interfaceNameRE.MatchString(name) {
		return fmt.Sprintf("网卡名称 %q 格式非法（仅允许字母数字开头，可含 ._- 且长度 1~15）", name)
	}
	lower := strings.ToLower(name)
	if lower == "lo" {
		return "禁止对环回网卡 lo 挂载 XDP"
	}
	for _, prefix := range forbiddenVirtualPrefixes {
		if strings.HasPrefix(lower, prefix) {
			return fmt.Sprintf("禁止对虚拟/容器/隧道网卡 %q（前缀 %s）挂载 XDP", name, prefix)
		}
	}
	return ""
}

// ValidateReason 校验可选变更原因字段。
func ValidateReason(reason string) string {
	if reason == "" {
		return ""
	}
	if len(reason) > MaxReasonLen {
		return fmt.Sprintf("变更原因不能超过 %d 字符", MaxReasonLen)
	}
	if hasDisallowedTextControlChars(reason) {
		return "变更原因不得包含非法控制字符"
	}
	return ""
}

// ValidateConfig 校验完整 XDP 加速配置（使用生产受控 Socket 前缀）。
func ValidateConfig(cfg *Config) []FieldError {
	return validateConfigWithSocketValidator(cfg, ValidateSocketPath)
}

func validateConfigWithSocketValidator(cfg *Config, validateSocket func(string) string) []FieldError {
	errs := []FieldError{}
	if cfg == nil {
		return []FieldError{{Field: "config", Message: "配置不能为空"}}
	}
	add := func(field, msg string) {
		errs = append(errs, FieldError{Field: field, Message: msg})
	}

	if validateSocket == nil {
		validateSocket = ValidateSocketPath
	}
	if msg := validateSocket(cfg.SocketPath); msg != "" {
		add("socket_path", msg)
	}
	if !ValidAttachMode(cfg.AttachMode) {
		add("attach_mode", "挂载模式仅支持 auto / native / generic")
	}
	if cfg.SyncIntervalSeconds < MinSyncIntervalSeconds || cfg.SyncIntervalSeconds > MaxSyncIntervalSeconds {
		add("sync_interval_seconds", fmt.Sprintf("同步周期必须在 %d~%d 秒之间", MinSyncIntervalSeconds, MaxSyncIntervalSeconds))
	}
	if len(cfg.Interfaces) > MaxInterfaces {
		add("interfaces", fmt.Sprintf("网卡数量不能超过 %d 个", MaxInterfaces))
	} else {
		seen := make(map[string]bool, len(cfg.Interfaces))
		for _, iface := range cfg.Interfaces {
			if msg := ValidateInterfaceName(iface); msg != "" {
				add("interfaces", msg)
				break
			}
			if seen[iface] {
				add("interfaces", fmt.Sprintf("网卡列表存在重复项 %q", iface))
				break
			}
			seen[iface] = true
		}
	}
	if cfg.Enabled && len(cfg.Interfaces) == 0 {
		add("interfaces", "启用 XDP 内核加速时至少需要指定 1 个物理业务网卡")
	}
	return errs
}

func hasControlChars(s string) bool {
	for _, c := range s {
		if c < 0x20 || c == 0x7f {
			return true
		}
	}
	return false
}

func hasDisallowedTextControlChars(s string) bool {
	for _, c := range s {
		if c == '\n' || c == '\t' {
			continue
		}
		if c < 0x20 || c == 0x7f {
			return true
		}
	}
	return false
}

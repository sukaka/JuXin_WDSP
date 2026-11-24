package capture

import (
	"path/filepath"
	"strings"
	"time"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"

	"github.com/jiuzhang-waf/wdsp-agent/internal/filter"
)

// WindowsAdapterInfo Windows 网络适配器摘要（供 Npcap 设备名与友好名映射，平台无关可单测）。
type WindowsAdapterInfo struct {
	FriendlyName string // Go net.Interfaces() 返回的友好名（如 "Ethernet0"）
	AdapterGUID  string // Windows AdapterName（如 "{1234-...}"）
	IPv4s        []string
}

// BuildNpcapDLLPaths 构造严格限定在 SystemRoot 下的 Npcap wpcap.dll 绝对路径。
// 严禁包含当前工作目录或相对路径，防止 DLL 搜索顺序劫持。
func BuildNpcapDLLPaths(systemRoot string) []string {
	root := strings.TrimSpace(systemRoot)
	if root == "" {
		root = `C:\Windows`
	}
	// 统一用反斜杠拼接 Windows 系统路径（跨平台测试稳定）
	root = strings.TrimRight(root, `\/`)
	return []string{
		root + `\System32\Npcap\wpcap.dll`,
	}
}

// FormatNpcapDeviceName 将适配器 GUID 转换为 Npcap 设备路径（\Device\NPF_{GUID}）。
func FormatNpcapDeviceName(adapterGUID string) string {
	g := strings.TrimSpace(adapterGUID)
	if g == "" {
		return ""
	}
	if strings.HasPrefix(strings.ToLower(g), `\device\npf_`) {
		return g
	}
	return `\Device\NPF_` + g
}

// MatchWindowsAdapter 按友好名（大小写不敏感）、GUID、Npcap 设备路径或 IPv4 匹配适配器。
func MatchWindowsAdapter(requested string, adapters []WindowsAdapterInfo) (WindowsAdapterInfo, bool) {
	req := strings.TrimSpace(requested)
	if req == "" {
		return WindowsAdapterInfo{}, false
	}
	reqLower := strings.ToLower(req)
	for _, a := range adapters {
		if strings.ToLower(strings.TrimSpace(a.FriendlyName)) == reqLower {
			return a, true
		}
		if a.AdapterGUID != "" {
			guidLower := strings.ToLower(strings.TrimSpace(a.AdapterGUID))
			if reqLower == guidLower || reqLower == strings.ToLower(FormatNpcapDeviceName(a.AdapterGUID)) {
				return a, true
			}
		}
		for _, ip := range a.IPv4s {
			if ip == req {
				return a, true
			}
		}
	}
	return WindowsAdapterInfo{}, false
}

// DecodeRawIPv4Frame 解码无二层以太网头的原始 IPv4 报文（Windows Winsock SIO_RCVALL）。
// 复用 DecodePacket 统一端口/方向/TCP 状态提取逻辑，NonEthernet 自动置 true。
func DecodeRawIPv4Frame(raw []byte, ts time.Time, filt *filter.Filter, st *Stats) (Packet, bool) {
	if len(raw) < 20 {
		return Packet{}, false
	}
	pkt := gopacket.NewPacket(raw, layers.LayerTypeIPv4, gopacket.DecodeOptions{Lazy: true, NoCopy: true})
	pkt.Metadata().Timestamp = ts
	pkt.Metadata().CaptureInfo = gopacket.CaptureInfo{
		Timestamp:     ts,
		CaptureLength: len(raw),
		Length:        len(raw),
	}
	return DecodePacket(pkt, filt, st)
}

// sanitizeNpcapPath 仅用于内部防御性检查：确保路径为绝对路径且不含 .. 目录穿越段。
func sanitizeNpcapPath(p string) bool {
	if p == "" || strings.Contains(p, "..") {
		return false
	}
	// Windows 绝对路径形如 C:\...
	if len(p) >= 3 && p[1] == ':' && (p[2] == '\\' || p[2] == '/') {
		return true
	}
	return filepath.IsAbs(p)
}

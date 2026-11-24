// PROXY protocol v1 头构造与内核 sockaddr_in 解码（纯函数，可单测）。
package tproxyd

import (
	"encoding/binary"
	"fmt"
	"net"
)

// afInet Linux AF_INET 地址族值（与平台无关的固定常量，避免引入 syscall 依赖）。
const afInet = 2

// BuildProxyV1Header 构造 PROXY protocol v1 头（仅 IPv4，即 TCP4）。
// 格式：PROXY TCP4 <srcIP> <dstIP> <srcPort> <dstPort>\r\n
// Caddy 的 proxy_protocol listener wrapper 读取该行后以其中的源地址替换连接
// 对端地址，访问日志/审计日志/事件中的 client_ip 即为真实客户端地址。
func BuildProxyV1Header(src, dst *net.TCPAddr) ([]byte, error) {
	if src == nil || dst == nil {
		return nil, fmt.Errorf("源/目的地址不能为空")
	}
	s4, d4 := src.IP.To4(), dst.IP.To4()
	if s4 == nil || d4 == nil {
		return nil, fmt.Errorf("PROXY v1 仅支持 IPv4（TCP4）: src=%s dst=%s", src.IP, dst.IP)
	}
	if err := checkPort("源端口", src.Port); err != nil {
		return nil, err
	}
	if err := checkPort("目的端口", dst.Port); err != nil {
		return nil, err
	}
	return []byte(fmt.Sprintf("PROXY TCP4 %s %s %d %d\r\n", s4, d4, src.Port, dst.Port)), nil
}

// DecodeOriginalDst 把内核 getsockopt(SO_ORIGINAL_DST) 返回的 sockaddr_in
// 字段解码为 TCPAddr。portBE 为 RawSockaddrInet4.Port 的原样值——内存中为网络
// 字节序（大端），经 NativeEndian 写回两字节后再按 BigEndian 解码，大小端主机均正确。
func DecodeOriginalDst(family, portBE uint16, addr [4]byte) (*net.TCPAddr, error) {
	if family != afInet {
		return nil, fmt.Errorf("原始目的地址族非 IPv4（AF_INET）: family=%d", family)
	}
	var portBytes [2]byte
	binary.NativeEndian.PutUint16(portBytes[:], portBE)
	port := int(binary.BigEndian.Uint16(portBytes[:]))
	if port < 1 || port > 65535 {
		return nil, fmt.Errorf("原始目的端口非法: %d", port)
	}
	return &net.TCPAddr{IP: net.IPv4(addr[0], addr[1], addr[2], addr[3]), Port: port}, nil
}

func checkPort(name string, port int) error {
	if port < 1 || port > 65535 {
		return fmt.Errorf("%s非法（需 1-65535）: %d", name, port)
	}
	return nil
}

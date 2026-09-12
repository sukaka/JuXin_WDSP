//go:build !linux

// 非 Linux 平台桩：SO_ORIGINAL_DST 依赖 Linux netfilter/conntrack，
// 其他平台给出明确错误（不静默）。
package tproxyd

import (
	"errors"
	"net"
)

// originalDst 非 Linux 平台直接失败并提示。
func originalDst(conn *net.TCPConn) (*net.TCPAddr, error) {
	return nil, errors.New("SO_ORIGINAL_DST 仅支持 Linux（netfilter REDIRECT 牵引）；当前平台不可用")
}

// Package stek 九章静态 STEK 提供模块（tls.stek.jiuzhang）：
// 实现 caddytls.STEKProvider，从 JSON 配置读取固定 TLS 会话票据密钥
// （32 字节 hex 列表），使主备多节点共用同一份票据密钥——客户端 TLS
// session resumption 跨节点可恢复（docs/HA_ACTIVE_STANDBY_DESIGN.md §7.2）。
//
// 密钥材料经发布通道下发（apps.tls.session_tickets.key_source），随发布
// 版本换新；版本内静态（Next 不推新键），轮换即一次 /load 生效——
// Caddy 的 STEK 服务以 Initialize 返回的键 SetSessionTicketKeys 到各
// tls.Config，多节点收到同一份发布 JSON，天然逐字节一致。
//
// 安全纪律：密钥属高敏材料——服务端版本快照按 key_hex/keys_hex Redact
// （与 identity_salt 同通道纪律），网关侧禁入日志。
package stek

import (
	"encoding/hex"
	"fmt"

	"github.com/caddyserver/caddy/v2"
	"github.com/caddyserver/caddy/v2/modules/caddytls"
)

// JiuzhangSTEK 静态 STEK 提供模块（tls.stek.jiuzhang）。
type JiuzhangSTEK struct {
	// KeysHex 固定票据密钥列表（每项 32 字节 hex；首个为加密主键，
	// 其余为解密兼容键——轮换窗口期可带新旧两键）。
	KeysHex []string `json:"keys_hex,omitempty"`
}

func init() {
	caddy.RegisterModule(&JiuzhangSTEK{})
}

// CaddyModule 实现 caddy.Module。
func (JiuzhangSTEK) CaddyModule() caddy.ModuleInfo {
	return caddy.ModuleInfo{
		ID:  "tls.stek.jiuzhang",
		New: func() caddy.Module { return new(JiuzhangSTEK) },
	}
}

// Initialize 实现 caddytls.STEKProvider：返回固定初始键（至少 1 个 32 字节）。
func (j *JiuzhangSTEK) Initialize(_ *caddytls.SessionTicketService) ([][32]byte, error) {
	if len(j.KeysHex) == 0 {
		return nil, fmt.Errorf("keys_hex 至少 1 个（32 字节 hex）")
	}
	keys := make([][32]byte, 0, len(j.KeysHex))
	for i, kh := range j.KeysHex {
		raw, err := hex.DecodeString(kh)
		if err != nil || len(raw) != 32 {
			return nil, fmt.Errorf("keys_hex[%d] 需 32 字节 hex（64 位十六进制字符）", i)
		}
		var k [32]byte
		copy(k[:], raw)
		keys = append(keys, k)
	}
	return keys, nil
}

// Next 实现 caddytls.STEKProvider：静态键不推新（轮换=随发布下发新材料，
// 经 /load 重建 TLS 装配生效）；doneChan 关闭时清理。
func (j *JiuzhangSTEK) Next(doneChan <-chan struct{}) <-chan [][32]byte {
	out := make(chan [][32]byte)
	go func() {
		<-doneChan
		close(out)
	}()
	return out
}

// 接口断言。
var _ caddytls.STEKProvider = (*JiuzhangSTEK)(nil)

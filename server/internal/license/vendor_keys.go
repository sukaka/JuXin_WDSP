// vendor_keys.go 验签公钥表：go:embed 内嵌 vendor_pubkey.hex。
// 文件格式：每行一条 `key_id:hexpub`（Ed25519 公钥 hex，64 字符），
// # 注释行与空行跳过，支持多条实现密钥轮换。
// 无任何有效公钥时所有授权验签失败（fail-closed，严禁测试密钥进入生产路径）。
package license

import (
	"crypto/ed25519"
	_ "embed"
	"encoding/hex"
	"log/slog"
	"strings"
)

//go:embed vendor_pubkey.hex
var embeddedVendorKeys string

// LoadVendorKeys 加载正式构建内嵌的验签公钥表。
// 生产路径不读取运行时环境变量，避免部署者或启动参数替换信任根。
// 临时测试公钥只能通过显式 wdsp_testkeys 构建标签或应用装配层依赖注入使用。
// 返回空表 = 无可用公钥，Verify 将全部失败（fail-closed）。
func LoadVendorKeys() map[string]ed25519.PublicKey {
	return parseVendorKeys(loadVendorKeysSource())
}

// parseVendorKeys 解析公钥表文本（逗号视为换行，兼容测试构建的单行输入）。
// 非法行（缺冒号 / hex 解码失败 / 长度非 32 字节）跳过并记告警日志，
// 不因此放行任何签名，也不让单条坏行拖垮整表。
func parseVendorKeys(src string) map[string]ed25519.PublicKey {
	src = strings.ReplaceAll(src, ",", "\n")
	out := map[string]ed25519.PublicKey{}
	for _, line := range strings.Split(src, "\n") {
		line = strings.TrimSpace(line)
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		keyID, hexPub, ok := strings.Cut(line, ":")
		if !ok {
			slog.Warn("license: 跳过非法公钥行（缺少 key_id: 前缀）")
			continue
		}
		keyID = strings.TrimSpace(keyID)
		pub, err := hex.DecodeString(strings.TrimSpace(hexPub))
		if err != nil || len(pub) != ed25519.PublicKeySize || keyID == "" {
			slog.Warn("license: 跳过非法公钥行（key_id 为空或公钥 hex 非法）", "key_id", keyID)
			continue
		}
		out[keyID] = ed25519.PublicKey(pub)
	}
	return out
}

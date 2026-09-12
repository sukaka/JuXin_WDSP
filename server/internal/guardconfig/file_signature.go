// file_signature.go 文件签名 v1 密钥下发（W13-GW / P2-02，任务书 §110 子集）：
// system_settings gateway_runtime 组 api_file_signature_key（密文）解密后明文 hex
// + api_file_signature_kid → api_file_signature {enabled,kid,key_hex} 下发网关
// （网关对文本族/JSON 下载响应嵌入 jzsig1 来源追踪 token，实现文件验证与泄露来源追踪）。
// 复用扫描密钥 NewScanVerificationLoader 的模式与设置组约定：密文不落版本快照明文
// （RedactGuardConfig 脱敏）、不写日志、不参与 api_policy_version 计算（与扫描密钥同一纪律）。
package guardconfig

import (
	"context"
	"encoding/hex"
	"fmt"
	"strings"
	"unicode/utf8"

	"github.com/jiuzhang-waf/server/internal/gatewayconfig"
)

// 文件签名密钥在设置表的位置（gateway_runtime 组；与网关侧 api_file_signature 段约定一致。
// 密文由管理面设置接口经加密服务写入，发布时解密下发——与 api_scan.signing_key 同一模式）。
const (
	fileSignatureSettingsGroup  = GatewayRuntimeSettingsGroup // "gateway_runtime"
	fileSignatureKeySettingsKey = "api_file_signature_key"    // 密文
	fileSignatureKIDSettingsKey = "api_file_signature_kid"    // 密钥标识（明文）
)

// fileSignatureKeyBytes 签名密钥长度（字节；与扫描密钥同一 32 字节约束，网关侧同一口径）。
const fileSignatureKeyBytes = 32

// maxFileSignatureKIDLen kid 长度上限（与网关 response.NewFileSignatureConfig 同一口径）。
const maxFileSignatureKIDLen = 64

// FileSignatureLoader 读取文件签名密钥明文 hex 与 kid（发布通道装配时由 app 注入：
// settings 读取 + 加密服务解密；返回空 kid/keyHex 表示未配置，不下发 api_file_signature，
// 网关响应侧零行为变化）。读取/解密/校验失败返回错误，发布侧中止发布（fail-hard，
// 与 applyGatewayRuntime 非法取值同纪律）：已配置签名却静默停用会让管理面显示与
// 网关行为不一致，不允许带病发布。
type FileSignatureLoader func(ctx context.Context) (kid, keyHex string, err error)

// NewFileSignatureLoader 以设置读取与解密函数构造文件签名密钥加载器
// （get/decrypt 与 settings.Service.GetString、encryption.Service.Decrypt 签名对齐，
// 装配一行接线：guardconfig.NewFileSignatureLoader(settingsSvc.GetString, encSvc.Decrypt)）。
// 密钥明文 hex 仅随发布通道下发网关，不落版本快照明文（RedactGuardConfig 脱敏）、不写日志；
// 错误信息不含密钥值。
func NewFileSignatureLoader(
	get func(ctx context.Context, group, key, def string) string,
	decrypt func(encoded string) (string, error),
) FileSignatureLoader {
	return func(ctx context.Context) (string, string, error) {
		if get == nil || decrypt == nil {
			return "", "", fmt.Errorf("file signature loader: settings/encryption 未装配")
		}
		raw := strings.TrimSpace(get(ctx, fileSignatureSettingsGroup, fileSignatureKeySettingsKey, ""))
		if raw == "" {
			return "", "", nil // 未配置签名密钥：不下发（网关零行为变化）
		}
		kid := strings.TrimSpace(get(ctx, fileSignatureSettingsGroup, fileSignatureKIDSettingsKey, ""))
		if kid == "" {
			return "", "", fmt.Errorf("gateway_runtime.api_file_signature_kid 配置签名密钥时必填")
		}
		// kid 口径与网关 response.NewFileSignatureConfig 一致（[A-Za-z0-9_-] ≤64：
		// token 以 '.' 分段、HMAC 消息以 '|' 分字段，越界字符会破坏两侧边界）
		if utf8.RuneCountInString(kid) > maxFileSignatureKIDLen {
			return "", "", fmt.Errorf("gateway_runtime.api_file_signature_kid 长度超过 %d", maxFileSignatureKIDLen)
		}
		for _, r := range kid {
			if (r >= 'a' && r <= 'z') || (r >= 'A' && r <= 'Z') || (r >= '0' && r <= '9') || r == '_' || r == '-' {
				continue
			}
			return "", "", fmt.Errorf("gateway_runtime.api_file_signature_kid 仅允许 [A-Za-z0-9_-]")
		}
		plain, err := decrypt(raw)
		if err != nil {
			return "", "", fmt.Errorf("decrypt api file signature key: %w", err)
		}
		key, err := hex.DecodeString(strings.TrimSpace(plain))
		if err != nil || len(key) != fileSignatureKeyBytes {
			return "", "", fmt.Errorf("api file signature key 格式非法（须 %d 字节 hex）", fileSignatureKeyBytes)
		}
		return kid, hex.EncodeToString(key), nil
	}
}

// SetFileSignatureLoader 注入文件签名密钥读取（nil 时不下发 api_file_signature 段）。
func (p *Provider) SetFileSignatureLoader(l FileSignatureLoader) { p.fileSignature = l }

// loadAPIFileSignature 读取文件签名密钥并组装下发段；未注入/未配置返回 (nil, nil)（不下发）。
// 读取/解密失败如实返回错误、中止发布（fail-hard）：Warn-skip 会静默停用签名嵌入，
// 管理面显示与网关行为不一致，故不静默降级。
func (p *Provider) loadAPIFileSignature(ctx context.Context) (*gatewayconfig.GuardFileSignature, error) {
	if p.fileSignature == nil {
		return nil, nil
	}
	kid, keyHex, err := p.fileSignature(ctx)
	if err != nil {
		return nil, fmt.Errorf("load api file signature key: %w", err)
	}
	if kid == "" || keyHex == "" {
		return nil, nil
	}
	return &gatewayconfig.GuardFileSignature{Enabled: true, KID: kid, KeyHex: keyHex}, nil
}

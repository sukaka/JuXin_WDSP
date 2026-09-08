// scan_verify.go 扫描流量识别密钥下发（W9-GW，背景A 扫描识别闭环）：
// system_settings api_scan.signing_key 密文 → 解密后明文 hex → api_scan_verification.key_hex
// 下发网关（网关校验 X-JiuZhang-Scan 签名头，识别扫描流量打标，学习样本排除）。
// 密钥位置与签名构造与 server/internal/apiscan/sign.go 同一约定（常量未导出，此处镜像并注释）。
package guardconfig

import (
	"context"
	"encoding/hex"
	"fmt"
	"strings"

	"github.com/jiuzhang-waf/server/internal/gatewayconfig"
)

// 扫描签名密钥在设置表的位置（与 apiscan sign.go signingKeySettingsGroup/Key 同一约定；
// apiscan 常量未导出，此处镜像，改动需双侧同步）。
const (
	scanSigningKeySettingsGroup = "api_scan"
	scanSigningKeySettingsKey   = "signing_key"
)

// scanSigningKeyBytes 签名密钥长度（字节；与 apiscan.NewSigner 的 32 字节约束一致）。
const scanSigningKeyBytes = 32

// ScanVerificationLoader 读取扫描签名密钥明文 hex（发布通道装配时由 app 注入：
// settings 读取 + 加密服务解密；返回空串表示未配置，不下发 api_scan_verification）。
// 读取/解密失败返回错误，发布侧中止发布（fail-hard，与 applyGatewayRuntime 非法取值
// 同纪律）：降级为仅按头存在性识别意味着任何人设置 X-JiuZhang-Scan 头即被排除出
// 学习样本（可投毒），不允许带病发布。
type ScanVerificationLoader func(ctx context.Context) (keyHex string, err error)

// NewScanVerificationLoader 以设置读取与解密函数构造扫描密钥加载器
// （get/decrypt 与 settings.Service.GetString、encryption.Service.Decrypt 签名对齐，
// 装配一行接线：guardconfig.NewScanVerificationLoader(settingsSvc.GetString, encSvc.Decrypt)）。
// 密钥明文 hex 仅随发布通道下发网关，不落版本快照明文（RedactGuardConfig 脱敏）、不写日志。
func NewScanVerificationLoader(
	get func(ctx context.Context, group, key, def string) string,
	decrypt func(encoded string) (string, error),
) ScanVerificationLoader {
	return func(ctx context.Context) (string, error) {
		if get == nil || decrypt == nil {
			return "", fmt.Errorf("scan verification loader: settings/encryption 未装配")
		}
		raw := strings.TrimSpace(get(ctx, scanSigningKeySettingsGroup, scanSigningKeySettingsKey, ""))
		if raw == "" {
			return "", nil // 未配置签名密钥：不下发（网关仅存在性识别）
		}
		plain, err := decrypt(raw)
		if err != nil {
			return "", fmt.Errorf("decrypt api scan signing key: %w", err)
		}
		key, err := hex.DecodeString(strings.TrimSpace(plain))
		if err != nil || len(key) != scanSigningKeyBytes {
			return "", fmt.Errorf("api scan signing key 格式非法（须 %d 字节 hex）", scanSigningKeyBytes)
		}
		return hex.EncodeToString(key), nil
	}
}

// SetScanVerificationLoader 注入扫描签名密钥读取（nil 时不下发 api_scan_verification 段）。
func (p *Provider) SetScanVerificationLoader(l ScanVerificationLoader) { p.scanVerification = l }

// loadAPIScanVerification 读取扫描签名密钥并组装下发段；未注入/未配置返回 (nil, nil)（不下发）。
// 读取/解密失败如实返回错误、中止发布（fail-hard）：Warn-skip 会把扫描侧降级为只认头存在性，
// 任何人设置 X-JiuZhang-Scan 头即被排除出学习样本（可投毒），故不静默降级。
func (p *Provider) loadAPIScanVerification(ctx context.Context) (*gatewayconfig.GuardScanVerification, error) {
	if p.scanVerification == nil {
		return nil, nil
	}
	keyHex, err := p.scanVerification(ctx)
	if err != nil {
		return nil, fmt.Errorf("load api scan verification key: %w", err)
	}
	if keyHex == "" {
		return nil, nil
	}
	return &gatewayconfig.GuardScanVerification{KeyHex: keyHex}, nil
}

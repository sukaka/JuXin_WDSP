// bot_keys.go Bot 挑战签名密钥下发（WDSP P1-02 B3 预备，任务书 §5.3）：
// system_settings gateway_runtime 组 bot_signing_keys（密文 JSON 对象
// {"<key_ref>": "<hex 密钥>"}）解密校验后 → GuardConfig.BotSigningKeys
// 随发布通道下发网关（网关在 bot_policy 段装配处以 key_ref 为 current、
// 其余为轮换窗口 previous 构造 botchallenge.NewKeyring）。
// 复用扫描/文件签名密钥 NewScanVerificationLoader 的模式与设置组约定：
//   - 密钥材料不落普通配置明文、不落版本快照（RedactGuardConfig 脱敏为占位，
//     回滚时由 replayRuntimeSecrets 按当前设置重新解密注入）、不写日志/审计、
//     不参与 api_policy_version 版本戳（密钥轮换不视为防护内容变更）；
//   - 读取/解密/校验失败中止发布（fail-hard，与既有密钥段同一纪律）——
//     错误信息只含 key_ref 引用名与长度，绝不含密钥材料；
//   - key_ref 词形与 server/internal/botpolicy.validate.go keyRefPattern、
//     网关 botchallenge.keyIDPattern 同一正则（常量未导出，此处镜像，改动需三侧同步）。
package guardconfig

import (
	"context"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"regexp"
	"strings"
)

// Bot 签名密钥在设置表的位置（gateway_runtime 组；密文由管理面设置接口经加密服务
// 写入，发布时解密下发——与 api_scan.signing_key / api_file_signature_key 同一模式）。
const (
	botSigningKeysSettingsGroup = GatewayRuntimeSettingsGroup // "gateway_runtime"
	botSigningKeysSettingsKey   = "bot_signing_keys"          // 密文 JSON 对象
)

// botKeyRefPattern key_ref 引用名词形（仅引用名——不是密钥材料；防路径拼接与注入；
// 与 botpolicy.validate.go keyRefPattern / 网关 botchallenge.keyIDPattern 同一正则）。
var botKeyRefPattern = regexp.MustCompile(`^[a-z0-9][a-z0-9_.-]{0,63}$`)

// Bot 签名密钥约束（与网关 botchallenge.NewKeyring 同一口径：HMAC-SHA-256 密钥 ≥32 字节）。
const (
	botSigningKeyMinBytes = 32
	botSigningKeysMaxKeys = 8 // 轮换窗口上限（current + previous），防配置膨胀
)

// BotSigningKeysLoader 读取 Bot 挑战签名密钥（发布通道装配时由 app 注入：
// settings 读取 + 加密服务解密；返回 key_ref → 明文 hex（小写规范化）映射，
// 空映射表示未配置，不下发 bot_signing_keys）。读取/解密/校验失败返回错误，
// 发布侧中止发布（fail-hard）：已配置密钥却静默丢弃会让 PROTECT 门禁语义与
// 管理面显示不一致，不允许带病发布。
type BotSigningKeysLoader func(ctx context.Context) (keys map[string]string, err error)

// NewBotSigningKeysLoader 以设置读取与解密函数构造 Bot 签名密钥加载器
// （get/decrypt 与 settings.Service.GetString、encryption.Service.Decrypt 签名对齐，
// 装配一行接线：guardconfig.NewBotSigningKeysLoader(settingsSvc.GetString, encSvc.Decrypt)）。
// 密钥明文 hex 仅随发布通道下发网关；错误信息不含密钥材料。
func NewBotSigningKeysLoader(
	get func(ctx context.Context, group, key, def string) string,
	decrypt func(encoded string) (string, error),
) BotSigningKeysLoader {
	return func(ctx context.Context) (map[string]string, error) {
		if get == nil || decrypt == nil {
			return nil, fmt.Errorf("bot signing keys loader: settings/encryption 未装配")
		}
		raw := strings.TrimSpace(get(ctx, botSigningKeysSettingsGroup, botSigningKeysSettingsKey, ""))
		if raw == "" {
			return nil, nil // 未配置签名密钥：不下发（PROTECT 策略由就绪门禁拒绝发布）
		}
		plain, err := decrypt(raw)
		if err != nil {
			return nil, fmt.Errorf("decrypt bot signing keys: %w", err)
		}
		return parseBotSigningKeysJSON([]byte(strings.TrimSpace(plain)))
	}
}

// parseBotSigningKeysJSON 解析并校验密钥 JSON 对象（纯函数，可测）：
// 密钥材料 hex 解码 ≥32 字节、key_ref 词形、条数上限；非法如实报错（错误不含密钥材料）。
func parseBotSigningKeysJSON(plain []byte) (map[string]string, error) {
	var m map[string]string
	dec := json.NewDecoder(strings.NewReader(string(plain)))
	dec.DisallowUnknownFields()
	if err := dec.Decode(&m); err != nil {
		return nil, fmt.Errorf("bot signing keys JSON 解析失败（须为 {\"<key_ref>\": \"<hex>\"} 对象）: %v", err)
	}
	if len(m) == 0 {
		return nil, nil // 空对象视同未配置
	}
	if len(m) > botSigningKeysMaxKeys {
		return nil, fmt.Errorf("bot signing keys 条数超过上限 %d（轮换窗口 current+previous 有限）", botSigningKeysMaxKeys)
	}
	out := make(map[string]string, len(m))
	for ref, hexKey := range m {
		if !botKeyRefPattern.MatchString(ref) {
			return nil, fmt.Errorf("bot signing keys: 非法 key_ref %q（仅 [a-z0-9._-] 引用名，禁止路径/URL 形态）", ref)
		}
		key, err := hex.DecodeString(strings.TrimSpace(hexKey))
		if err != nil {
			return nil, fmt.Errorf("bot signing keys: key_ref %q 密钥材料非合法 hex", ref)
		}
		if len(key) < botSigningKeyMinBytes {
			return nil, fmt.Errorf("bot signing keys: key_ref %q 密钥材料过短（%d < %d 字节）", ref, len(key), botSigningKeyMinBytes)
		}
		out[ref] = hex.EncodeToString(key)
	}
	return out, nil
}

// SetBotSigningKeysLoader 注入 Bot 签名密钥读取（nil 时不下发 bot_signing_keys；
// 存在 PROTECT 策略时由就绪门禁拒绝发布）。
func (p *Provider) SetBotSigningKeysLoader(l BotSigningKeysLoader) { p.botSigningKeys = l }

// loadBotSigningKeys 读取 Bot 签名密钥；未注入/未配置返回 (nil, nil)（不下发）。
// 读取/解密/校验失败如实返回错误、中止发布（fail-hard，与扫描/文件签名密钥同一纪律）。
func (p *Provider) loadBotSigningKeys(ctx context.Context) (map[string]string, error) {
	if p.botSigningKeys == nil {
		return nil, nil
	}
	keys, err := p.botSigningKeys(ctx)
	if err != nil {
		return nil, fmt.Errorf("load bot signing keys: %w", err)
	}
	if len(keys) == 0 {
		return nil, nil
	}
	return keys, nil
}

// botSigningKeysReady 判定 key_ref 在已注入密钥集合中就绪（空引用名/未注入/
// 脱敏占位均视同未就绪——回滚重放路径快照值为 "***" 占位，必须先重放再判定）。
func botSigningKeysReady(keys map[string]string, keyRef string) bool {
	if keyRef == "" {
		return false
	}
	v, ok := keys[keyRef]
	return ok && v != "" && v != redactPlaceholder
}

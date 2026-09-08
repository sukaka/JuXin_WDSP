// bot_policy.go Bot 挑战策略下发（WDSP P1-02 B1）：bot_policies 表按应用行
// → GuardConfig.bot_policy 段（key=应用编码）随发布通道下发网关（表由迁移 000128 建立；
// 仅 WDSP 开启（APIDynamicProtection）时下发，回滚覆盖快照经 stripAPIGuardSections 剥除——
// 与 jwt_trust 段同一门控口径；内容纳入 api_policy_version 版本戳）。
// 纪律（任务书 §4.1 末段/§5.4，B0 冻结）：
//   - 读取失败中止发布（fail-hard，与 jwt_trust.go 同一口径）——静默跳过会让已 PROTECT
//     的应用在新配置中丢失 bot_policy 段，等于静默关闭挑战强制；
//   - 存在 PROTECT 策略而共享状态存储（Valkey）未配置时拒绝发布并给出可读原因——
//     Bot 挑战 nonce/通行状态依赖共享 Valkey（键前缀 jiuzhang:guard:bot，B0 冻结），
//     PROTECT 无共享状态时网关侧按任务书 §5.4 只能 fail-closed 503，
//     发布一个必然全站 503 的配置不如拒绝发布；
//   - PROTECT 策略的 challenge.key_ref 必须在已注入签名密钥集合中就绪
//     （bot_signing_keys，gateway_runtime 组密文经解密注入；空引用名/未配置/
//     快照脱敏占位均视同未就绪），否则拒绝发布（fail-hard，任务书 §5.4 末段——
//     防发布时新 key 未安装导致全站挑战故障）；密钥材料本身不下发进策略段，
//     经 GuardConfig.BotSigningKeys 独立注入并在渲染时并入 bot_policy 段
//     signing_keys 键（与 identity_salt/api_scan_verification 同一密钥通道纪律）。
package guardconfig

import (
	"context"
	"fmt"
	"sort"

	"github.com/jiuzhang-waf/server/internal/gatewayconfig"
)

// BotPolicyLister Bot 策略读取接口（由 botpolicy.Store 实现——
// 返回按应用编码组织的网关下发契约，含策略版本与信号/挑战/路由保留配置）。
type BotPolicyLister interface {
	ListForGuard(ctx context.Context) (map[string]*gatewayconfig.GuardBotPolicy, error)
}

// SetBotPolicyLister 注入 Bot 策略读取（nil 时不下发 bot_policy 段）。
func (p *Provider) SetBotPolicyLister(l BotPolicyLister) { p.botPolicy = l }

// loadBotPolicy 读取 Bot 策略并填充 bot_policy 段（仅 WDSP 开启时调用）。
// 返回错误即中止发布（拒绝发布并给出可读原因，旧有效版本保留）。
func (p *Provider) loadBotPolicy(ctx context.Context, cfg *gatewayconfig.GuardConfig) error {
	if p.botPolicy == nil {
		return nil
	}
	policies, err := p.botPolicy.ListForGuard(ctx)
	if err != nil {
		return fmt.Errorf("list bot policies: %w", err)
	}
	if len(policies) == 0 {
		return nil
	}
	// 签名密钥经独立密钥通道注入（秘密材料不进策略段；未配置/未注入 → nil，
	// PROTECT 由下方就绪门禁拒绝发布；读取/解密失败中止发布 fail-hard）
	keys, err := p.loadBotSigningKeys(ctx)
	if err != nil {
		return err
	}
	if len(keys) > 0 {
		cfg.BotSigningKeys = keys
	}
	protectApps := []string{}
	for code, pol := range policies {
		if pol != nil && pol.Mode == "PROTECT" {
			protectApps = append(protectApps, code)
		}
	}
	if len(protectApps) > 0 {
		sort.Strings(protectApps)
		if err := checkBotPolicyDeps(cfg, protectApps, policies); err != nil {
			return err
		}
	}
	cfg.BotPolicy = policies
	return nil
}

// checkBotPolicyDeps PROTECT 发布依赖门禁：
//   - 共享状态存储（Valkey）未配置时拒绝发布（挑战 nonce/clearance 状态依赖共享
//     Valkey——键前缀 jiuzhang:guard:bot 为 B0 冻结保留；无共享状态时 PROTECT
//     必然全站 fail-closed 503）；
//   - key_ref 签名密钥就绪检查（B3 预备）：每个 PROTECT 策略的 challenge.key_ref
//     必须在已注入密钥集合（cfg.BotSigningKeys，发布/回滚重放均已按当前设置注入）
//     中就绪，否则拒绝发布——防发布时新 key 未安装导致全站挑战故障（任务书 §5.4 末段）。
//
// 供 loadBotPolicy（正常发布）与 replayRuntimeSecrets（回滚重放）共用同一口径；
// policies 为本次发布/快照中的策略集（key=应用编码），用于取各应用的 key_ref。
func checkBotPolicyDeps(cfg *gatewayconfig.GuardConfig, protectApps []string, policies map[string]*gatewayconfig.GuardBotPolicy) error {
	if cfg.Valkey == nil {
		return fmt.Errorf(
			"应用 %v 的 Bot 策略为 PROTECT，但共享状态存储（Valkey）未配置："+
				"挑战 nonce 与通行状态依赖共享 Valkey（键前缀 jiuzhang:guard:bot），"+
				"缺少共享状态时网关只能 fail-closed 503，拒绝发布；请先配置 Valkey",
			protectApps)
	}
	notReady := []string{}
	for _, code := range protectApps {
		pol := policies[code]
		keyRef := ""
		if pol != nil {
			keyRef = pol.Challenge.KeyRef
		}
		if !botSigningKeysReady(cfg.BotSigningKeys, keyRef) {
			notReady = append(notReady, fmt.Sprintf("%s(key_ref=%q)", code, keyRef))
		}
	}
	if len(notReady) > 0 {
		return fmt.Errorf(
			"应用 %v 的 Bot 策略为 PROTECT，但 key_ref 引用的签名密钥未就绪："+
				"密钥须经系统设置 gateway_runtime.bot_signing_keys 配置并随发布下发，"+
				"缺少密钥时网关对挑战/通行只能 fail-closed 503，拒绝发布；"+
				"请先配置对应 key_ref 的签名密钥（多节点先完成密钥准备再发布策略）",
			notReady)
	}
	return nil
}

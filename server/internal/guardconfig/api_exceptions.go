// api_exceptions.go API 引擎受限例外下发（WDSP P0-04 A 侧，契约
// docs/tasks/wdsp-p0/S4_DESIGN_BASELINE.md §6/§10）：exception_policies 表
// target_engine='API' 的 ENABLED+VALID 行 → GuardConfig.api_exceptions 段
// （key=应用编码）随发布通道下发网关；仅 WDSP 开启（APIDynamicProtection）时下发，
// 回滚覆盖快照经 stripAPIGuardSections 剥除——与 jwt_trust/bot_policy 段同一门控口径；
// 内容纳入 api_policy_version 版本戳。
// 纪律：
//   - 读取失败中止发布（fail-hard，与 loadJWTTrust 同一口径）——静默跳过会让已启用
//     的 API 例外在新配置中整段丢失，等于静默恢复执法且无任何告警；
//   - 未注入 lister 或无启用行 → 不下发该段（nil map），网关 API 决策零行为变化。
package guardconfig

import (
	"context"
	"fmt"

	"github.com/jiuzhang-waf/server/internal/gatewayconfig"
)

// APIExceptionLister API 例外读取接口（由 exceptions.Store 实现——
// 返回按应用编码组织的 GuardAPIException 下发契约，含 exception_id/version 与
// 目标规则引用 detector_id/rule_id/model_version）。
type APIExceptionLister interface {
	ListAPIExceptionsForGuard(ctx context.Context) (map[string][]gatewayconfig.GuardAPIException, error)
}

// SetAPIExceptionsLister 注入 API 例外读取（nil 时不下发 api_exceptions 段）。
func (p *Provider) SetAPIExceptionsLister(l APIExceptionLister) { p.apiExceptions = l }

// loadAPIExceptions 读取 API 引擎受限例外并填充 api_exceptions 段（仅 WDSP 开启时调用）。
// 返回错误即中止发布（拒绝发布并给出可读原因，旧有效版本保留）。
func (p *Provider) loadAPIExceptions(ctx context.Context, cfg *gatewayconfig.GuardConfig) error {
	if p.apiExceptions == nil {
		return nil
	}
	exceptions, err := p.apiExceptions.ListAPIExceptionsForGuard(ctx)
	if err != nil {
		return fmt.Errorf("list api exceptions: %w", err)
	}
	if len(exceptions) == 0 {
		return nil
	}
	cfg.APIExceptions = exceptions
	return nil
}

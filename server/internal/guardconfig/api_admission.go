// api_admission.go API 准入策略下发（WDSP P1，docs/API_ADMISSION_CONTROL_DESIGN.md §4.2）：
// applications.api_admission_mode<>'OFF' 的应用行 + 各应用 CONFIRMED 端点确认集
// → GuardConfig.api_admission（key=application_id）随发布通道下发网关
// （列由迁移 000166 建立；仅 WDSP 开启（APIDynamicProtection）时下发，回滚覆盖快照经
// stripAPIGuardSections 剥除——与 API 动态防护其余段同一门控口径；内容纳入
// api_policy_version 版本戳）。
// 纪律（与 jwt_trust 同一口径）：
//   - 读取失败中止发布（fail-hard）——静默跳过会让已 PROTECT 的应用在新配置中
//     丢失 api_admission 段，等于静默关闭准入拦截（不拦截优于误拦截的 fail-safe
//     回落发生在网关侧非法值场景，发布侧不替网关做静默决定）；
//   - mode=OFF 的应用不出现在 policies（OFF 语义=不启用，网关无条目即不判定）；
//   - confirmed_endpoints 只含 CONFIRMED 端点键（IGNORED/DEPRECATED/ZOMBIE 不下发——
//     不在集合即拒绝，语义一致）；确认集为空的应用（OBSERVE 学习初期）同样下发，
//     空数组语义=无确认端点。
package guardconfig

import (
	"context"
	"fmt"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/jiuzhang-waf/server/internal/gatewayconfig"
)

// APIAdmissionLister 准入策略读取接口（由 AdmissionPolicyStore 实现——
// 返回按 application_id 组织的网关下发契约）。
type APIAdmissionLister interface {
	ListForGuard(ctx context.Context) (map[string]*gatewayconfig.GuardAPIAdmissionPolicy, error)
}

// AdmissionConfirmedLister 确认集读取接口（由 *apiassets.Store 实现——
// 应用下 CONFIRMED 端点键，排序确定）。
type AdmissionConfirmedLister interface {
	ListConfirmedByApplication(ctx context.Context, appID uuid.UUID) ([]string, error)
}

// AdmissionPolicyStore 准入策略读取（applications 模式列 + api_endpoints 确认集联查；
// 两表均本服务自有，冻结列名读取）。
type AdmissionPolicyStore struct {
	db        *pgxpool.Pool
	confirmed AdmissionConfirmedLister
}

// NewAdmissionPolicyStore 创建准入策略读取仓储（confirmed 为 apiassets.Store，确认集数据源）。
func NewAdmissionPolicyStore(db *pgxpool.Pool, confirmed AdmissionConfirmedLister) *AdmissionPolicyStore {
	return &AdmissionPolicyStore{db: db, confirmed: confirmed}
}

var _ APIAdmissionLister = (*AdmissionPolicyStore)(nil)

// ListForGuard 读取全部准入启用应用（mode<>'OFF'，软删除除外）的策略与确认集。
// 应用数为管理面启用量级（非高基数），逐应用查确认集走 idx_api_endpoints_application
// 索引，无 N+1 风险；确认集为空归一为非 nil 空切片（下发 JSON 为 [] 而非 null，
// 与冻结契约 confirmed_endpoints 数组形态一致）。
func (s *AdmissionPolicyStore) ListForGuard(ctx context.Context) (map[string]*gatewayconfig.GuardAPIAdmissionPolicy, error) {
	rows, err := s.db.Query(ctx, `
SELECT id, api_admission_mode FROM applications
WHERE deleted_at IS NULL AND api_admission_mode <> 'OFF'
ORDER BY id`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	type appRow struct {
		id   uuid.UUID
		mode string
	}
	apps := []appRow{}
	for rows.Next() {
		var a appRow
		if err := rows.Scan(&a.id, &a.mode); err != nil {
			return nil, err
		}
		apps = append(apps, a)
	}
	if err := rows.Err(); err != nil {
		return nil, err
	}
	out := map[string]*gatewayconfig.GuardAPIAdmissionPolicy{}
	for _, a := range apps {
		keys, err := s.confirmed.ListConfirmedByApplication(ctx, a.id)
		if err != nil {
			return nil, fmt.Errorf("list confirmed endpoints for application %s: %w", a.id, err)
		}
		if keys == nil {
			keys = []string{}
		}
		out[a.id.String()] = &gatewayconfig.GuardAPIAdmissionPolicy{Mode: a.mode, ConfirmedEndpoints: keys}
	}
	return out, nil
}

// SetAPIAdmissionLister 注入准入策略读取（nil 时不下发 api_admission 段）。
func (p *Provider) SetAPIAdmissionLister(l APIAdmissionLister) { p.apiAdmission = l }

// loadAPIAdmission 读取准入策略并填充 api_admission 段（仅 WDSP 开启时调用）。
// 返回错误即中止发布（fail-hard，与 loadJWTTrust 同一纪律）。
func (p *Provider) loadAPIAdmission(ctx context.Context, cfg *gatewayconfig.GuardConfig) error {
	if p.apiAdmission == nil {
		return nil
	}
	policies, err := p.apiAdmission.ListForGuard(ctx)
	if err != nil {
		return fmt.Errorf("list api admission policies: %w", err)
	}
	if len(policies) == 0 {
		return nil
	}
	// 防御性归一：确认集 nil → 空切片（单测 fake 或未来实现返回 nil 时
	// 下发 JSON 仍为 []，不破坏冻结契约数组形态）
	for _, pol := range policies {
		if pol != nil && pol.ConfirmedEndpoints == nil {
			pol.ConfirmedEndpoints = []string{}
		}
	}
	cfg.APIAdmission = policies
	return nil
}

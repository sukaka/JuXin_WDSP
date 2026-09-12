// store.go Bot 策略仓储（bot_policies 草稿行 + bot_policy_versions 不可变版本记录，
// 迁移 000128）。读取侧同时供管理面接口与 guardconfig 发布下发——ListForGuard 实现
// guardconfig.BotPolicyLister 接口（Go 隐式接口，无反向导入；跨分片契约类型见
// gatewayconfig.GuardBotPolicy）。
package botpolicy

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/jiuzhang-waf/server/internal/gatewayconfig"
)

// ErrNotFound 策略草稿不存在（应用从未配置——按默认 OFF 空策略处理）。
var ErrNotFound = errors.New("bot policy not found")

// ErrConflict 乐观锁冲突（expected_version 与当前版本不匹配：并发修改，需刷新后重试）。
var ErrConflict = errors.New("bot policy version conflict")

// Store 是 Bot 策略仓储。
type Store struct {
	db *pgxpool.Pool
}

// NewStore 创建仓储。
func NewStore(db *pgxpool.Pool) *Store {
	return &Store{db: db}
}

// policyColumns 查询列清单（与 scanPolicy 顺序一致）。
const policyColumns = `id, application_id, mode, version, selectors, signal_rules, challenge, route_reservation, updated_by, created_at, updated_at`

// scanPolicy 扫描一行策略（JSONB 列经 []byte 中转反序列化）。
func scanPolicy(row pgx.Row) (*Policy, error) {
	var p Policy
	var selectors, signalRules, challenge, reservation []byte
	var updatedBy *string
	err := row.Scan(&p.ID, &p.ApplicationID, &p.Mode, &p.Version,
		&selectors, &signalRules, &challenge, &reservation, &updatedBy, &p.CreatedAt, &p.UpdatedAt)
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return nil, ErrNotFound
		}
		return nil, err
	}
	if updatedBy != nil {
		p.UpdatedBy = *updatedBy
	}
	p.Selectors = []Selector{}
	p.SignalRules = DefaultSignalRules()
	p.Challenge = DefaultChallenge()
	p.RouteReservation = RouteReservation{State: ReservationReleased, Namespace: ReservedNamespace}
	if err := json.Unmarshal(selectors, &p.Selectors); err != nil {
		return nil, fmt.Errorf("decode selectors: %w", err)
	}
	if err := json.Unmarshal(signalRules, &p.SignalRules); err != nil {
		return nil, fmt.Errorf("decode signal_rules: %w", err)
	}
	if p.SignalRules.Rules == nil {
		p.SignalRules.Rules = []SignalRule{}
	}
	if err := json.Unmarshal(challenge, &p.Challenge); err != nil {
		return nil, fmt.Errorf("decode challenge: %w", err)
	}
	if err := json.Unmarshal(reservation, &p.RouteReservation); err != nil {
		return nil, fmt.Errorf("decode route_reservation: %w", err)
	}
	return &p, nil
}

// GetByApp 读取应用当前草稿策略；无记录返回 ErrNotFound（调用方映射为默认 OFF 策略）。
func (s *Store) GetByApp(ctx context.Context, appID uuid.UUID) (*Policy, error) {
	row := s.db.QueryRow(ctx, `SELECT `+policyColumns+` FROM bot_policies WHERE application_id = $1`, appID)
	return scanPolicy(row)
}

// marshalSections 序列化四个 JSONB 段（列序与 policyColumns 对应）。
func marshalSections(p *Policy) (selectors, signalRules, challenge, reservation string, err error) {
	marshal := func(v interface{}) (string, error) {
		b, mErr := json.Marshal(v)
		return string(b), mErr
	}
	if selectors, err = marshal(p.Selectors); err != nil {
		return
	}
	if signalRules, err = marshal(p.SignalRules); err != nil {
		return
	}
	if challenge, err = marshal(p.Challenge); err != nil {
		return
	}
	reservation, err = marshal(p.RouteReservation)
	return
}

// SaveDraft 校验并保存草稿（乐观锁 + 同事务追加不可变版本记录）：
//   - 应用已有草稿：expected_version 须等于当前 version，更新后 version+1；
//   - 应用无草稿：expected_version 须为 0，创建 version=1 首版；
//   - 版本不匹配返回 ErrConflict（409）。
//
// reason 非空（变更理由，随版本记录留存并进入操作审计）。
// 回退通过「以旧版本内容 PUT 生成新版本」实现，不修改历史版本行。
func (s *Store) SaveDraft(ctx context.Context, p *Policy, expectedVersion int, reason, updatedBy string) error {
	if errs := ValidateStructure(p); len(errs) > 0 {
		return &ValidationError{Errors: errs}
	}
	if reason == "" {
		return &ValidationError{Errors: []FieldError{{Field: "reason", Message: "变更理由不能为空"}}}
	}
	selectors, signalRules, challenge, reservation, err := marshalSections(p)
	if err != nil {
		return err
	}

	tx, err := s.db.Begin(ctx)
	if err != nil {
		return err
	}
	defer tx.Rollback(ctx)

	var newVersion int
	if expectedVersion == 0 {
		// 首版创建：并发首建由 application_id UNIQUE 兜底为冲突
		err = tx.QueryRow(ctx, `
INSERT INTO bot_policies (application_id, mode, version, selectors, signal_rules, challenge, route_reservation, updated_by)
VALUES ($1, $2, 1, $3::jsonb, $4::jsonb, $5::jsonb, $6::jsonb, $7)
RETURNING id, version`, p.ApplicationID, p.Mode, selectors, signalRules, challenge, reservation, updatedBy).
			Scan(&p.ID, &newVersion)
		if err != nil {
			if isUniqueViolation(err) {
				return ErrConflict
			}
			return err
		}
	} else {
		err = tx.QueryRow(ctx, `
UPDATE bot_policies SET mode=$1, selectors=$2::jsonb, signal_rules=$3::jsonb, challenge=$4::jsonb,
  route_reservation=$5::jsonb, updated_by=$6, updated_at=now(), version=version+1
WHERE application_id=$7 AND version=$8
RETURNING id, version`, p.Mode, selectors, signalRules, challenge, reservation, updatedBy,
			p.ApplicationID, expectedVersion).Scan(&p.ID, &newVersion)
		if err != nil {
			if errors.Is(err, pgx.ErrNoRows) {
				return ErrConflict
			}
			return err
		}
	}

	// 不可变版本记录（同版本唯一由 UNIQUE(application_id, version) 兜底）
	if _, err := tx.Exec(ctx, `
INSERT INTO bot_policy_versions (application_id, version, mode, selectors, signal_rules, challenge, route_reservation, reason, created_by)
VALUES ($1, $2, $3, $4::jsonb, $5::jsonb, $6::jsonb, $7::jsonb, $8, $9)`,
		p.ApplicationID, newVersion, p.Mode, selectors, signalRules, challenge, reservation, reason, updatedBy); err != nil {
		return err
	}
	if err := tx.Commit(ctx); err != nil {
		return err
	}
	p.Version = newVersion
	p.UpdatedBy = updatedBy
	return nil
}

// isUniqueViolation 判定唯一约束冲突（pgcode 23505，不引入 pgconn 类型断言以外的依赖）。
func isUniqueViolation(err error) bool {
	var iface interface{ SQLState() string }
	if errors.As(err, &iface) {
		return iface.SQLState() == "23505"
	}
	return false
}

// LatestPublishState 读取最近 SUCCESS 访问控制发布快照中本应用的 Bot 策略生效状态
// （发布整站快照含 GuardConfig.bot_policy 段，回滚发布产生新的 SUCCESS 快照，
// 故最新 SUCCESS 即当前生效集合；Found=false = 从未成功发布，
// PolicyVersion=0 = 该快照未下发本应用策略）。
func (s *Store) LatestPublishState(ctx context.Context, appCode string) (PublishState, error) {
	var st PublishState
	var raw []byte
	err := s.db.QueryRow(ctx, `
SELECT version_no, id, config FROM access_control_versions
WHERE publish_result = 'SUCCESS'
ORDER BY version_no DESC LIMIT 1`).Scan(&st.VersionNo, &st.VersionID, &raw)
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return st, nil
		}
		return st, err
	}
	st.Found = true
	var cfg struct {
		BotPolicy map[string]struct {
			Version int `json:"version"`
		} `json:"bot_policy"`
	}
	if err := json.Unmarshal(raw, &cfg); err != nil {
		return st, fmt.Errorf("decode published guard config: %w", err)
	}
	if pol, ok := cfg.BotPolicy[appCode]; ok {
		st.PolicyVersion = pol.Version
	}
	return st, nil
}

// ListForGuard 读取全部应用策略并映射为网关下发契约（guardconfig 发布通道注入用；
// key 为应用编码。OFF 策略同样下发——网关按 mode 关闭判定，同时覆盖旧配置中
// 可能残留的同名应用策略，避免「管理面已关、网关仍在按旧策略观测」）。
func (s *Store) ListForGuard(ctx context.Context) (map[string]*gatewayconfig.GuardBotPolicy, error) {
	rows, err := s.db.Query(ctx, `
SELECT p.application_id, a.code, p.mode, p.version, p.selectors, p.signal_rules, p.challenge, p.route_reservation
FROM bot_policies p
JOIN applications a ON a.id = p.application_id
WHERE a.deleted_at IS NULL
ORDER BY a.code`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := map[string]*gatewayconfig.GuardBotPolicy{}
	for rows.Next() {
		var (
			appID                                  uuid.UUID
			code, mode                             string
			version                                int
			selectors, signalRules, challenge, res []byte
		)
		if err := rows.Scan(&appID, &code, &mode, &version, &selectors, &signalRules, &challenge, &res); err != nil {
			return nil, err
		}
		p := DefaultPolicy(appID)
		p.Mode = mode
		p.Version = version
		if err := json.Unmarshal(selectors, &p.Selectors); err != nil {
			return nil, fmt.Errorf("decode selectors for %s: %w", code, err)
		}
		if err := json.Unmarshal(signalRules, &p.SignalRules); err != nil {
			return nil, fmt.Errorf("decode signal_rules for %s: %w", code, err)
		}
		if p.SignalRules.Rules == nil {
			p.SignalRules.Rules = []SignalRule{}
		}
		if err := json.Unmarshal(challenge, &p.Challenge); err != nil {
			return nil, fmt.Errorf("decode challenge for %s: %w", code, err)
		}
		if err := json.Unmarshal(res, &p.RouteReservation); err != nil {
			return nil, fmt.Errorf("decode route_reservation for %s: %w", code, err)
		}
		out[code] = toGuardPolicy(p)
	}
	return out, rows.Err()
}

// toGuardPolicy 映射为网关下发契约（跨分片冻结类型 gatewayconfig.GuardBotPolicy；
// 内容无任何秘密材料——key_ref 仅引用名）。
func toGuardPolicy(p *Policy) *gatewayconfig.GuardBotPolicy {
	gp := &gatewayconfig.GuardBotPolicy{
		SchemaVersion: SchemaVersion,
		ApplicationID: p.ApplicationID.String(),
		Mode:          p.Mode,
		Version:       p.Version,
		Selectors:     make([]gatewayconfig.GuardBotSelector, 0, len(p.Selectors)),
		SignalRules: gatewayconfig.GuardBotSignalRules{
			MinIndependentGroups: p.SignalRules.MinIndependentGroups,
			RequireBehaviorGroup: p.SignalRules.RequireBehaviorGroup,
			Rules:                make([]gatewayconfig.GuardBotSignalRule, 0, len(p.SignalRules.Rules)),
		},
		Challenge: gatewayconfig.GuardBotChallenge{
			Type:                p.Challenge.Type,
			NonceTTLSeconds:     p.Challenge.NonceTTLSeconds,
			ClearanceTTLSeconds: p.Challenge.ClearanceTTLSeconds,
			Difficulty:          p.Challenge.Difficulty,
			MaxAttempts:         p.Challenge.MaxAttempts,
			KeyRef:              p.Challenge.KeyRef,
		},
		RouteReservation: gatewayconfig.GuardBotRouteReservation{
			State:     p.RouteReservation.State,
			Namespace: p.RouteReservation.Namespace,
		},
	}
	for _, s := range p.Selectors {
		gp.Selectors = append(gp.Selectors, gatewayconfig.GuardBotSelector{
			PathExact:  s.PathExact,
			PathPrefix: s.PathPrefix,
		})
	}
	for _, r := range p.SignalRules.Rules {
		var params map[string]string
		if len(r.Params) > 0 {
			params = make(map[string]string, len(r.Params))
			for k, v := range r.Params {
				params[k] = v
			}
		}
		gp.SignalRules.Rules = append(gp.SignalRules.Rules, gatewayconfig.GuardBotSignalRule{
			ID:            r.ID,
			Group:         r.Group,
			Metric:        r.Metric,
			Params:        params,
			WindowSeconds: r.WindowSeconds,
			Weight:        r.Weight,
			Threshold:     r.Threshold,
		})
	}
	return gp
}

// ReservedNamespaceConflict 保留命名空间占用冲突（已有应用路径登记落入 /_wdsp/bot/）。
type ReservedNamespaceConflict struct {
	Method string `json:"method"`
	Path   string `json:"path"`
	Source string `json:"source"` // 数据来源（api_endpoints 已知端点资产）
}

// ListReservedNamespacePaths 查询本应用已登记路径中落入 Bot 保留命名空间的条目
// （数据源：api_endpoints 已知端点资产——管理面唯一已知的应用路径登记；
// 未登记的业务路径预检无法发现，由 B3 启用手册与实测兜底）。
// 表由迁移 000016 建立，000018 起列名为 http_method/normalized_path；
// 表缺失/查询失败如实返回错误（预检降级 FAIL，不静默放行）。
func (s *Store) ListReservedNamespacePaths(ctx context.Context, appID uuid.UUID) ([]ReservedNamespaceConflict, error) {
	rows, err := s.db.Query(ctx, `
SELECT http_method, normalized_path FROM api_endpoints
WHERE application_id = $1 AND normalized_path LIKE '/_wdsp/bot/%'
ORDER BY normalized_path LIMIT 50`, appID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := []ReservedNamespaceConflict{}
	for rows.Next() {
		var c ReservedNamespaceConflict
		if err := rows.Scan(&c.Method, &c.Path); err != nil {
			return nil, err
		}
		c.Source = "api_endpoints"
		out = append(out, c)
	}
	return out, rows.Err()
}

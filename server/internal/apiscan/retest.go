// retest.go 扫描复测回写桥接（设计稿 §十）。
//
// 跨包纪律：本包仅以「小接口 + 显式 import apiweakness」的方式耦合弱点中心
// （任务书允许的两条路径之一，选小接口便于集成方装配与单测替身）；复测结论回写
// 走 apiweakness 已实现的 Transition 状态机（RETEST_PASS/RETEST_FAIL，仅 FIXED 可流转），
// 扫描侧不直接 UPDATE 弱点状态、不伪造复测结论。
package apiscan

import (
	"context"

	"github.com/google/uuid"
	"github.com/jiuzhang-waf/server/internal/apiweakness"
)

// RetestWriter 弱点复测回写接口（由集成方装配，见 NewWeaknessRetestWriter）。
// pass=true → RETEST_PASS（FIXED→ARCHIVED）；pass=false → RETEST_FAIL（FIXED→REPRODUCED）。
// 弱点非 FIXED 状态或不存在时返回错误，调用方如实向上返回（任务置 FAILED / 接口报错），
// 不伪造复测结论。WeaknessStatus 供发包前预检（避免对必败请求真实发包），
// 状态机写回仍为权威校验（预检后状态可能被并发改变）。
type RetestWriter interface {
	RetestWeakness(ctx context.Context, weaknessID uuid.UUID, pass bool, actor, note string) error
	WeaknessStatus(ctx context.Context, weaknessID uuid.UUID) (string, error)
}

// WeaknessTransition 弱点状态机接口（*apiweakness.Store / *apiweakness.MemStore 实现）。
type WeaknessTransition interface {
	Transition(ctx context.Context, id uuid.UUID, action string, in apiweakness.TransitionInput) (*apiweakness.Weakness, error)
}

// WeaknessGetter 弱点查询接口（*apiweakness.Store / *apiweakness.MemStore 实现）。
type WeaknessGetter interface {
	GetByID(ctx context.Context, id uuid.UUID) (*apiweakness.Weakness, error)
}

// WeaknessStore 弱点仓储组合接口（状态机写回 + 状态查询）。
type WeaknessStore interface {
	WeaknessTransition
	WeaknessGetter
}

// weaknessRetestWriter RetestWriter 的 apiweakness 适配器。
type weaknessRetestWriter struct {
	store WeaknessStore
}

// NewWeaknessRetestWriter 用弱点仓储创建复测回写器（集成方装配一行：
// apiscan.NewWeaknessRetestWriter(apiweakness.NewStore(db))）。
func NewWeaknessRetestWriter(store WeaknessStore) RetestWriter {
	return &weaknessRetestWriter{store: store}
}

// RetestWeakness 按 apiweakness 复测语义回写（动作历史 actor 记录操作者/扫描任务标识）。
func (w *weaknessRetestWriter) RetestWeakness(ctx context.Context, weaknessID uuid.UUID, pass bool, actor, note string) error {
	action := apiweakness.ActionRetestFail
	if pass {
		action = apiweakness.ActionRetestPass
	}
	_, err := w.store.Transition(ctx, weaknessID, action, apiweakness.TransitionInput{
		Actor: actor,
		Note:  note,
	})
	return err
}

// WeaknessStatus 查询弱点当前状态（复测发包前预检用；不存在时返回 apiweakness.ErrNotFound）。
func (w *weaknessRetestWriter) WeaknessStatus(ctx context.Context, weaknessID uuid.UUID) (string, error) {
	weak, err := w.store.GetByID(ctx, weaknessID)
	if err != nil {
		return "", err
	}
	return weak.Status, nil
}

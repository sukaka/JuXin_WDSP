// noise_tools.go AI 自动降噪 Tool 组：降噪簇查询与详情（全部 READ_ONLY）。
// AI 可解释降噪聚类结果，但不得自动 suppress/resolve——状态流转只走人工接口。
package aitools

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"

	"github.com/google/uuid"
	"github.com/jiuzhang-waf/server/internal/ainoise"
)

// NoiseClusterReader 降噪簇只读依赖（*ainoise.SQLStore / *ainoise.MemStore 均满足）。
type NoiseClusterReader interface {
	List(ctx context.Context, f ainoise.ListFilter) ([]ainoise.Cluster, int64, error)
	Get(ctx context.Context, id uuid.UUID) (*ainoise.Cluster, error)
	ListEvents(ctx context.Context, clusterID uuid.UUID, limit int) ([]ainoise.ClusterEvent, error)
}

// 编译期保证：生产与内存仓储均满足只读契约。
var (
	_ NoiseClusterReader = (*ainoise.SQLStore)(nil)
	_ NoiseClusterReader = (*ainoise.MemStore)(nil)
)

// 输入枚举白名单（非法值直接拒绝）。
var (
	noiseSourceWhitelist  = map[string]bool{"WAF": true, "API": true}
	noiseStatusWhitelist  = map[string]bool{"ACTIVE": true, "SUPPRESSED": true, "RESOLVED": true}
	noiseVerdictWhitelist = map[string]bool{"TRUE_POSITIVE": true, "LIKELY_FALSE_POSITIVE": true, "UNKNOWN": true}
)

// NewNoiseTools 注册降噪 Tool（2 个，全部 READ_ONLY，权限 ai.noise_reduction.use）。
func NewNoiseTools(r *Registry, store NoiseClusterReader) {
	r.Register(&noiseClusterSearch{baseTool: baseTool{meta: toolMeta{
		code: "noise_cluster.search", name: "降噪簇查询", version: "1.0",
		description: "按来源/状态/AI判定分页查询 AI 自动降噪簇（事件折叠结果）",
		risk:        RiskReadOnly, permission: "ai.noise_reduction.use", timeout: 15, maxResults: 50,
		schema: obj(map[string]interface{}{
			"source":  sch("string", "来源 WAF/API（可选）"),
			"status":  sch("string", "状态 ACTIVE/SUPPRESSED/RESOLVED（可选）"),
			"verdict": sch("string", "AI判定 TRUE_POSITIVE/LIKELY_FALSE_POSITIVE/UNKNOWN（可选）"),
			"page":    sch("integer", "页码"),
		})}}, store: store})
	r.Register(&noiseClusterGet{baseTool: baseTool{meta: toolMeta{
		code: "noise_cluster.get", name: "降噪簇详情", version: "1.0",
		description: "按簇ID获取降噪簇详情与代表事件（计数、指纹、AI判定依据）",
		risk:        RiskReadOnly, permission: "ai.noise_reduction.use", timeout: 10, maxResults: 1,
		schema: obj(map[string]interface{}{
			"cluster_id": sch("string", "降噪簇ID"),
		})}}, store: store})
}

type noiseClusterSearch struct {
	baseTool
	store NoiseClusterReader
}

func (t *noiseClusterSearch) Run(ctx context.Context, input json.RawMessage) (interface{}, error) {
	var m map[string]interface{}
	if err := Decode(input, &m); err != nil {
		return nil, err
	}
	f := ainoise.ListFilter{Page: IntField(m, "page", 1), PageSize: 20}
	if v := StrField(m, "source", 8); v != "" {
		if !noiseSourceWhitelist[v] {
			return nil, fmt.Errorf("%w: invalid source", ErrInvalidInput)
		}
		f.Source = v
	}
	if v := StrField(m, "status", 16); v != "" {
		if !noiseStatusWhitelist[v] {
			return nil, fmt.Errorf("%w: invalid status", ErrInvalidInput)
		}
		f.Status = v
	}
	if v := StrField(m, "verdict", 32); v != "" {
		if !noiseVerdictWhitelist[v] {
			return nil, fmt.Errorf("%w: invalid verdict", ErrInvalidInput)
		}
		f.Verdict = v
	}
	items, total, err := t.store.List(ctx, f)
	if err != nil {
		return nil, err
	}
	return map[string]interface{}{
		"total": total, "page": f.Page, "page_size": f.PageSize, "items": items,
	}, nil
}

type noiseClusterGet struct {
	baseTool
	store NoiseClusterReader
}

func (t *noiseClusterGet) Run(ctx context.Context, input json.RawMessage) (interface{}, error) {
	var m map[string]interface{}
	if err := Decode(input, &m); err != nil {
		return nil, err
	}
	id, err := uuid.Parse(StrField(m, "cluster_id", 64))
	if err != nil {
		return nil, fmt.Errorf("%w: invalid cluster_id", ErrInvalidInput)
	}
	c, err := t.store.Get(ctx, id)
	if err != nil {
		if errors.Is(err, ainoise.ErrClusterNotFound) {
			return nil, fmt.Errorf("noise cluster not found")
		}
		return nil, err
	}
	events, err := t.store.ListEvents(ctx, id, 20)
	if err != nil {
		return nil, err
	}
	return map[string]interface{}{
		"cluster": c, "events": events,
	}, nil
}

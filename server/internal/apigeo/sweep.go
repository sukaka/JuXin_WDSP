// sweep.go api_cross_border_events 生产写入方：增量扫描 api_runtime_events 中
// 涉敏事件（details_json 含 detector=sensitive_data 明细），对 client_ip 做
// GeoIP 归属判定，境外来源（FOREIGN）按方向落库跨境观察记录。
//
// 水位纪律：水位存于 api_cross_border_state 单行表（而非产出表 max(occurred_at)）——
// 绝大多数事件因本土/内网/未知归属被跳过、不产生观察行，产出表水位会永久停滞导致
// 每轮全量重扫，故独立状态表记录「已扫描到的事件时刻」，与事件写入同事务推进；
// 叠加 (source_event_id, direction) 唯一约束 + ON CONFLICT DO NOTHING 双保险，
// 连续两次 SweepOnce 不重复落库（幂等）。单次最多处理 sweepBatchSize 条事件
// （防长事务），打满时 HasMore=true 提示调用方继续调度。
// 已知边界：与水位同刻（微秒精度 occurred_at）且超出批量的余量事件会被跳过，
// 概率极低（与 apidata/apiauthz 同口径）。空表/无命中安全返回零值结果。
//
// GeoIP 未启用（数据源文件未部署/损坏）时本清扫空转：结果 GeoEnabled=false 如实
// 标注，水位不推进（数据源就位后自动全量回填），不吞错不伪造判定。
package apigeo

import (
	"context"
	"encoding/json"
	"fmt"
	"net/netip"
	"reflect"
	"sort"
	"strings"
	"time"
)

// sweepBatchSize 单次清扫事件批大小（与 apidata/apiauthz 同口径）。
const sweepBatchSize = 2000

// SettingsReader 设置读取窄接口（settings.Service 满足；测试注入假实现）。
type SettingsReader interface {
	GetString(ctx context.Context, group, key, def string) string
}

// SweepResult 一次跨境清扫的结果统计。
type SweepResult struct {
	GeoEnabled       bool       `json:"geo_enabled"`          // GeoIP 数据源是否可用（false 时其余为本次空转零值）
	HomeRegions      []string   `json:"home_regions"`         // 本次判定所用本土地区集合
	EventsScanned    int        `json:"events_scanned"`       // 扫描到的涉敏带 IP 事件数
	EventsInserted   int        `json:"events_inserted"`      // 实际落库观察行数（幂等冲突不计）
	SkippedHome      int        `json:"skipped_home"`         // 本土来源跳过
	SkippedInternal  int        `json:"skipped_internal"`     // 内网/保留地址跳过
	SkippedUnknown   int        `json:"skipped_unknown"`      // GeoIP 未收录跳过（未知不证明出境）
	SkippedBadIP     int        `json:"skipped_bad_ip"`       // client_ip 非法跳过
	SkippedNoSensHit int        `json:"skipped_no_sensitive"` // 明细提取为空（防御计数）
	HasMore          bool       `json:"has_more"`             // 本批打满，可能还有余量
	Watermark        *time.Time `json:"watermark"`            // 本次推进到的水位（最大事件时间）
}

// Sweeper 跨境观察生产方（无内部状态，并发安全；配置每轮重读即时生效）。
type Sweeper struct {
	store    sweepStore
	lookup   CountryLookup  // nil = GeoIP 数据源未加载（空转降级）
	settings SettingsReader // home_regions 来源（nil 时用默认值）
}

// NewSweeper 创建生产方。sweepStore 为窄接口（*Store 满足；测试注入内存实现）。
func NewSweeper(store sweepStore, lookup CountryLookup, settings SettingsReader) *Sweeper {
	if lookup != nil {
		v := reflect.ValueOf(lookup)
		if (v.Kind() == reflect.Ptr || v.Kind() == reflect.Interface || v.Kind() == reflect.Map || v.Kind() == reflect.Func || v.Kind() == reflect.Slice) && v.IsNil() {
			lookup = nil
		}
	}
	return &Sweeper{store: store, lookup: lookup, settings: settings}
}

// sweepDetail 运行时事件检测明细子集（镜像 dsctx.DetectorMatch 的 JSON 形状）。
type sweepDetail struct {
	Detector string            `json:"detector"`
	Evidence map[string]string `json:"evidence"`
}

// extractSensitiveTypes 从 details_json 提取各方向涉敏数据类型集合（纯函数）。
// 方向映射：evidence.direction RESPONSE → OUT（出境），REQUEST/缺省 → IN（入境），
// 与 apidata sweep 的缺省 REQUEST 口径一致。返回键仅含确有敏感命中的方向
// （值可为空切片：命中但明细未带 data_type 标签）。
func extractSensitiveTypes(detailsJSON []byte) (map[string][]string, error) {
	var details []sweepDetail
	if err := json.Unmarshal(detailsJSON, &details); err != nil {
		return nil, fmt.Errorf("parse details_json: %w", err)
	}
	sets := map[string]map[string]bool{}
	for _, d := range details {
		if d.Detector != "sensitive_data" {
			continue
		}
		dir := DirectionIn
		if d.Evidence != nil && d.Evidence["direction"] == "RESPONSE" {
			dir = DirectionOut
		}
		if sets[dir] == nil {
			sets[dir] = map[string]bool{}
		}
		if d.Evidence != nil {
			if dt := strings.TrimSpace(d.Evidence["data_type"]); dt != "" {
				sets[dir][dt] = true
			}
		}
	}
	out := map[string][]string{}
	for dir, set := range sets {
		out[dir] = sortedKeys(set)
	}
	return out, nil
}

// riskOf 由数据类型集合推导风险等级（纯函数）：
// 任一类型 CORE/IMPORTANT → HIGH；SENSITIVE 或字典外类型（保守口径，宁可高估）→
// MEDIUM；其余（GENERAL/无类型）→ LOW。levels 来自 api_sensitive_data_types。
func riskOf(dataTypes []string, levels map[string]string) string {
	risk := RiskLow
	for _, dt := range dataTypes {
		level, ok := levels[dt]
		if !ok {
			if risk == RiskLow {
				risk = RiskMedium // 字典外类型保守计 MEDIUM
			}
			continue
		}
		switch level {
		case "CORE", "IMPORTANT":
			return RiskHigh
		case "SENSITIVE":
			risk = RiskMedium
		}
	}
	return risk
}

// SweepOnce 执行一次跨境清扫。
func (s *Sweeper) SweepOnce(ctx context.Context) (*SweepResult, error) {
	res := &SweepResult{HomeRegions: []string{}}
	if s.lookup == nil {
		return res, nil // GeoIP 数据源未加载：空转降级（GeoEnabled=false 如实标注）
	}
	res.GeoEnabled = true
	rawHome := DefaultHomeRegions
	if s.settings != nil {
		rawHome = s.settings.GetString(ctx, SettingsGroup, SettingsKeyHomeRegions, DefaultHomeRegions)
	}
	resolver := NewGeoResolver(s.lookup, ParseHomeRegions(rawHome))
	res.HomeRegions = resolver.HomeRegions()

	levels, err := s.store.DataTypeLevels(ctx)
	if err != nil {
		return nil, err
	}
	wm, err := s.store.Watermark(ctx)
	if err != nil {
		return nil, err
	}
	events, err := s.store.FetchSensitiveEvents(ctx, wm, sweepBatchSize)
	if err != nil {
		return nil, err
	}
	if len(events) == 0 {
		return res, nil // 空表/无命中安全
	}
	res.HasMore = len(events) >= sweepBatchSize

	rows := []crossBorderRow{}
	for _, ev := range events {
		res.EventsScanned++
		scope, country, err := resolver.Classify(ev.clientIP)
		if err != nil {
			return nil, fmt.Errorf("cross-border sweep geo lookup event %s: %w", ev.id, err)
		}
		switch scope {
		case ScopeHome:
			res.SkippedHome++
			continue
		case ScopeInternal:
			res.SkippedInternal++
			continue
		case ScopeUnknown:
			res.SkippedUnknown++
			continue
		case ScopeInvalid:
			res.SkippedBadIP++
			continue
		}
		typesByDir, err := extractSensitiveTypes(ev.details)
		if err != nil {
			return nil, fmt.Errorf("cross-border sweep event %s: %w", ev.id, err)
		}
		if len(typesByDir) == 0 {
			res.SkippedNoSensHit++ // @> 命中但提取为空（防御；正常不发生）
			continue
		}
		// client_ip 归一化存储（maskIP 纪律：netip canonical 形态）
		normalizedIP := ev.clientIP
		if addr, perr := netip.ParseAddr(strings.TrimSpace(ev.clientIP)); perr == nil {
			normalizedIP = addr.String()
		}
		// 方向固定序遍历（结果确定）
		dirs := make([]string, 0, len(typesByDir))
		for dir := range typesByDir {
			dirs = append(dirs, dir)
		}
		sort.Strings(dirs)
		for _, dir := range dirs {
			dataTypes := typesByDir[dir]
			rows = append(rows, crossBorderRow{
				occurredAt:    ev.occurredAt,
				clientIP:      normalizedIP,
				country:       country,
				endpointKey:   ev.endpointKey,
				identity:      ev.identity,
				dataTypes:     dataTypes,
				direction:     dir,
				riskLevel:     riskOf(dataTypes, levels),
				sourceEventID: ev.id,
			})
		}
	}
	last := events[len(events)-1].occurredAt
	inserted, err := s.store.RecordCrossBorder(ctx, rows, last)
	if err != nil {
		return nil, err
	}
	res.EventsInserted = inserted
	res.Watermark = &last
	return res, nil
}

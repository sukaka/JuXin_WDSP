// sweep.go api_object_ownership 生产写入方：扫描 api_runtime_events
// （identity_fingerprint 非空），用端点 normalized_path 模板（api_endpoints）匹配
// raw_path，提取路径占位符段值（{id}/{uuid}/...）作为对象标识，
// upsert api_object_ownership（access_count++/last_seen 前移）。
//
// 水位纪律（与 apidata sweep 同模式）：取 api_object_ownership 的 max(last_seen)
// 作为水位，只处理其后的新事件，连续两次 SweepOnce 不重复计数（幂等）；首次无水位
// 时全量回填。单次最多处理 sweepBatchSize 条事件（防长事务），打满时 HasMore=true
// 提示调用方继续调度。已知边界：与水位同刻（微秒精度 occurred_at）且超出批量的
// 余量事件会被跳过，概率极低；事件因 endpoint_key 未匹配资产或 raw_path 与模板
// 段数不符被跳过时，水位仍随同批事件前移、该事件不再重扫（端点发现正常先于事件
// 落库，见 apiruntime.Collector）。空表/无命中安全返回零值结果。
package apiauthz

import (
	"context"
	"fmt"
	"strings"
	"time"

	"github.com/google/uuid"
)

// sweepBatchSize 单次清扫事件批大小。
const sweepBatchSize = 2000

// SweepResult 一次权属清扫的结果统计。
type SweepResult struct {
	EventsScanned     int        `json:"events_scanned"`      // 扫描到的实名事件数
	ObjectsExtracted  int        `json:"objects_extracted"`   // 提取的对象引用数
	OwnershipUpserted int        `json:"ownership_upserted"`  // upsert 权属条数（同一对象多次访问按次数累计）
	SkippedNoEndpoint int        `json:"skipped_no_endpoint"` // endpoint_key 未匹配资产而跳过的事件数
	SkippedNoMatch    int        `json:"skipped_no_match"`    // raw_path 与模板不匹配/无对象段而跳过的事件数
	HasMore           bool       `json:"has_more"`            // 本批打满，可能还有余量
	Watermark         *time.Time `json:"watermark"`           // 本次推进到的水位（最大事件时间）
}

// objectRef 从模板/原始路径段对齐提取的对象引用。
type objectRef struct {
	ObjectType string // 占位符前一个静态段（资源名），无则占位符名
	ObjectID   string // 原始路径对应段值
}

// isPlaceholder 模板段是否为占位符（{name} 形态）。
func isPlaceholder(seg string) bool {
	return len(seg) >= 3 && strings.HasPrefix(seg, "{") && strings.HasSuffix(seg, "}")
}

// extractObjectRefs 用 normalized_path 模板匹配 raw_path，提取占位符段值（纯函数）。
//
// 规则：段数一致且静态段字面相同才算匹配；占位符段 {name} 捕获原始段值（空值跳过）；
// object_type 取占位符前一个静态段（资源名，如 /users/{id} → users），前一个段也是
// 占位符或不存在时退化为占位符名。raw_path 带查询串时先截断（?/# 之后不参与匹配）。
// 不匹配（段数不符/静态段不一致/无占位符）返回 nil。
//
// 实现为 extractObjectSegmentRefs（objectmodels.go，同一匹配纪律）的路径段投影：
// 权属只取路径占位段，Query 对象参数不参与权属。
func extractObjectRefs(template, rawPath string) []objectRef {
	segRefs := extractObjectSegmentRefs(template, rawPath)
	refs := []objectRef{}
	for _, r := range segRefs {
		if strings.HasPrefix(r.Segment, "path:") {
			refs = append(refs, objectRef{ObjectType: r.ObjectType, ObjectID: r.Value})
		}
	}
	return refs
}

// SweepOnce 执行一次权属清扫（SQL 实现）。
func (s *Store) SweepOnce(ctx context.Context) (*SweepResult, error) {
	res := &SweepResult{}
	// 水位：全部权属行的 max(last_seen)（空表为 NULL → 全量回填）
	var wm *time.Time
	if err := s.db.QueryRow(ctx,
		`SELECT max(last_seen) FROM api_object_ownership`).Scan(&wm); err != nil {
		return nil, fmt.Errorf("authz sweep watermark: %w", err)
	}
	rows, err := s.db.Query(ctx, `
SELECT id, endpoint_key, identity_fingerprint, raw_path, occurred_at
FROM api_runtime_events
WHERE identity_fingerprint <> ''
  AND raw_path IS NOT NULL AND raw_path <> ''
  AND ($1::timestamptz IS NULL OR occurred_at > $1)
ORDER BY occurred_at ASC, id ASC
LIMIT $2`, wm, sweepBatchSize)
	if err != nil {
		return nil, fmt.Errorf("authz sweep query: %w", err)
	}
	defer rows.Close()

	type eventRow struct {
		id         uuid.UUID
		key        string
		identity   string
		rawPath    string
		occurredAt time.Time
	}
	events := []eventRow{}
	for rows.Next() {
		var ev eventRow
		if err := rows.Scan(&ev.id, &ev.key, &ev.identity, &ev.rawPath, &ev.occurredAt); err != nil {
			return nil, err
		}
		events = append(events, ev)
	}
	if err := rows.Err(); err != nil {
		return nil, err
	}
	if len(events) == 0 {
		return res, nil // 空表/无命中安全
	}
	res.HasMore = len(events) >= sweepBatchSize

	// 端点键 → (端点 ID, 路径模板) 解析缓存（同批内复用；未命中资产负缓存）
	type endpointInfo struct {
		id       uuid.UUID
		template string
	}
	endpoints := map[string]*endpointInfo{}
	resolve := func(key string) (*endpointInfo, error) {
		if info, ok := endpoints[key]; ok {
			return info, nil
		}
		var info endpointInfo
		err := s.db.QueryRow(ctx,
			`SELECT id, normalized_path FROM api_endpoints WHERE endpoint_key = $1`, key).
			Scan(&info.id, &info.template)
		if err != nil {
			endpoints[key] = nil // 负缓存：同批不再重复查
			return nil, nil
		}
		endpoints[key] = &info
		return &info, nil
	}

	tx, err := s.db.Begin(ctx)
	if err != nil {
		return nil, err
	}
	defer func() { _ = tx.Rollback(ctx) }()

	for _, ev := range events {
		res.EventsScanned++
		info, err := resolve(ev.key)
		if err != nil {
			return nil, fmt.Errorf("authz sweep resolve endpoint %q: %w", ev.key, err)
		}
		if info == nil {
			res.SkippedNoEndpoint++
			continue
		}
		refs := extractObjectRefs(info.template, ev.rawPath)
		if len(refs) == 0 {
			res.SkippedNoMatch++
			continue
		}
		res.ObjectsExtracted += len(refs)
		for _, ref := range refs {
			// upsert：唯一键 (endpoint_id, identity_fingerprint, object_type, object_id)；
			// access_count 累加；首末次时间不回头（乱序防御）。
			if _, err := tx.Exec(ctx, `
INSERT INTO api_object_ownership
    (endpoint_id, identity_fingerprint, object_type, object_id, first_seen, last_seen, access_count)
VALUES ($1, $2, $3, $4, $5, $5, 1)
ON CONFLICT (endpoint_id, identity_fingerprint, object_type, object_id) DO UPDATE SET
    access_count = api_object_ownership.access_count + 1,
    first_seen = LEAST(api_object_ownership.first_seen, EXCLUDED.first_seen),
    last_seen  = GREATEST(api_object_ownership.last_seen, EXCLUDED.last_seen)`,
				info.id, ev.identity, ref.ObjectType, ref.ObjectID, ev.occurredAt); err != nil {
				return nil, fmt.Errorf("authz sweep upsert: %w", err)
			}
			res.OwnershipUpserted++
		}
	}
	if err := tx.Commit(ctx); err != nil {
		return nil, err
	}
	last := events[len(events)-1].occurredAt
	res.Watermark = &last
	return res, nil
}

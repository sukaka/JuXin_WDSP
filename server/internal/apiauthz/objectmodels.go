// objectmodels.go api_object_models 生产写入方（W16-TABLES）：扫描 api_runtime_events
// 全量事件（raw_path 非空，不限身份——对象模型刻画端点的对象面，与权属按身份切分不同），
// 用端点 normalized_path 模板匹配 raw_path，产出对象模型候选（路径占位段 + Query
// 对象参数形态）后 upsert api_object_models（sample_count++/last_seen 前移）。
//
// object_segment 键口径（对齐迁移 000018 列注释「归一化段位置或参数名」）：
//   - 路径占位段："path:<pos>"，pos 为去前导斜杠后的 0 起段序号
//     （与 apiassets api_endpoint_path_segments.position 同口径）；
//   - Query 对象参数："query:<参数名>"，参数值经 normalizer.IdentifierShape 识别为
//     对象标识形态（numeric/uuid/hex）才产出（「只认形态不认语义」，数值型普通参数
//     会被视作候选，是启发式信号而非结论）。
//
// identifier_type 对齐列注释口径 numeric/uuid/hash/mixed/unknown：normalizer 的
// hex 形态落为 hash；同一段观测到多种已知形态合并为 mixed；形态未识别为 unknown
// （unknown 不覆盖已知形态）。观测值只留 SHA-256 示例哈希（不落明文，与权属/
// 学习样本的脱敏纪律一致）；entropy_estimate 暂不落（计数不足以支撑估计，列保留 NULL）。
//
// 水位纪律与权属 SweepOnce 同模式：取 api_object_models max(last_seen) 为水位，
// 只处理其后新事件，连续两次清扫不重复计数（幂等）；首次无水位全量回填；单次最多
// sweepBatchSize 条，打满 HasMore=true 提示继续调度。first_seen/last_seen 只随事件
// occurred_at 移动（乱序不回头）；created_at/updated_at 保持行元数据语义不参与水位。
// 空表/无命中安全返回零值结果。
package apiauthz

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"strconv"
	"strings"
	"time"

	"github.com/google/uuid"
	"github.com/jiuzhang-waf/gateway/dynamic_security/normalizer"
)

// ObjectModelSweepResult 一次对象模型清扫的结果统计。
type ObjectModelSweepResult struct {
	EventsScanned     int        `json:"events_scanned"`      // 扫描到的事件数（含匿名事件）
	SegmentsExtracted int        `json:"segments_extracted"`  // 提取的对象段引用数
	ModelsUpserted    int        `json:"models_upserted"`     // upsert 对象模型条数
	SkippedNoEndpoint int        `json:"skipped_no_endpoint"` // endpoint_key 未匹配资产而跳过的事件数
	SkippedNoMatch    int        `json:"skipped_no_match"`    // raw_path 与模板不匹配/无对象段而跳过的事件数
	HasMore           bool       `json:"has_more"`            // 本批打满，可能还有余量
	Watermark         *time.Time `json:"watermark"`           // 本次推进到的水位（最大事件时间）
}

// objectSegmentRef 对象模型段引用：路径占位段或 Query 对象参数的一次观测。
type objectSegmentRef struct {
	Segment    string // api_object_models.object_segment 键："path:<pos>" / "query:<参数名>"
	ObjectType string // 路径段：占位符前一个静态段（资源名），无则占位符名；Query 参数：参数名
	Value      string // 观测原值（只用于形态识别与示例哈希，不落库明文）
	Shape      string // normalizer.IdentifierShape 输出：numeric / uuid / hex（空 = 未识别）
}

// identifierTypeOf 形态 → identifier_type 列口径（列注释 numeric/uuid/hash/mixed）。
func identifierTypeOf(shape string) string {
	switch shape {
	case "numeric":
		return "numeric"
	case "uuid":
		return "uuid"
	case "hex":
		return "hash"
	default:
		return "unknown"
	}
}

// mergeIdentifierType 形态合并（与 SQL upsert 的 CASE 同口径）：unknown 不覆盖已知；
// 已知形态不一致 → mixed。
func mergeIdentifierType(oldType, newType string) string {
	if newType == "unknown" {
		return oldType
	}
	if oldType == "unknown" || oldType == newType {
		return newType
	}
	return "mixed"
}

// objectExampleHash 观测值示例哈希（SHA-256 hex；不落明文，与 sample_hash 纪律一致）。
func objectExampleHash(value string) string {
	sum := sha256.Sum256([]byte(value))
	return hex.EncodeToString(sum[:])
}

// splitPathSegments 去一个前导斜杠后切段（位置口径与 apiassets 段形表一致）。
func splitPathSegments(p string) []string {
	return strings.Split(strings.TrimPrefix(p, "/"), "/")
}

// extractObjectSegmentRefs 用 normalized_path 模板匹配 raw_path，产出对象模型段引用（纯函数）。
//
// 路径匹配与权属提取同一纪律：段数一致且静态段字面相同才算匹配（不匹配返回 nil）；
// 占位段 {name} 捕获原始段值（空值/超长跳过），段位置为去前导斜杠后的 0 起序号。
// Query 部分在路径匹配成功后解析：仅参数值呈对象标识形态（numeric/uuid/hex）的参数
// 产出引用；参数值不做 URL 解码（编码值形态识别不到即保守跳过）。同段键一次调用内
// 只取首次出现（重复 Query 参数等）。
func extractObjectSegmentRefs(template, rawPath string) []objectSegmentRef {
	pathPart, queryPart := rawPath, ""
	if i := strings.IndexAny(rawPath, "?#"); i >= 0 {
		pathPart = rawPath[:i]
		if rawPath[i] == '?' {
			queryPart = rawPath[i+1:]
			if j := strings.IndexByte(queryPart, '#'); j >= 0 {
				queryPart = queryPart[:j]
			}
		}
	}
	tsegs := splitPathSegments(template)
	rsegs := splitPathSegments(pathPart)
	if len(tsegs) != len(rsegs) || len(tsegs) == 0 {
		return nil
	}
	refs := []objectSegmentRef{}
	seen := map[string]bool{}
	for i, tseg := range tsegs {
		if !isPlaceholder(tseg) {
			if tseg != rsegs[i] {
				return nil // 静态段不一致：整条路径不匹配
			}
			continue
		}
		value := rsegs[i]
		if value == "" || len(value) > maxObjectID {
			continue // 空段/超长段不产出（防御脏路径）
		}
		objType := strings.TrimSuffix(strings.TrimPrefix(tseg, "{"), "}")
		// object_type 取前置静态段（资源名更贴近业务对象语义）
		if i > 0 && tsegs[i-1] != "" && !isPlaceholder(tsegs[i-1]) {
			objType = tsegs[i-1]
		}
		if objType == "" || len(objType) > maxObjectType {
			continue
		}
		key := "path:" + strconv.Itoa(i)
		if seen[key] {
			continue
		}
		seen[key] = true
		refs = append(refs, objectSegmentRef{
			Segment: key, ObjectType: objType, Value: value, Shape: normalizer.IdentifierShape(value),
		})
	}
	// Query 对象参数形态（路径已匹配；模板无占位段时也可仅由 Query 参数产出对象面）
	for _, kv := range strings.Split(queryPart, "&") {
		if kv == "" {
			continue
		}
		name, value, _ := strings.Cut(kv, "=")
		if name == "" || len(name) > maxObjectType || value == "" || len(value) > maxObjectID {
			continue
		}
		shape := normalizer.IdentifierShape(value)
		if shape == "" {
			continue // 非标识形态参数不是对象候选
		}
		key := "query:" + name
		if seen[key] {
			continue
		}
		seen[key] = true
		refs = append(refs, objectSegmentRef{
			Segment: key, ObjectType: name, Value: value, Shape: shape,
		})
	}
	if len(refs) == 0 {
		return nil
	}
	return refs
}

// SweepObjectModelsOnce 执行一次对象模型清扫（SQL 实现）。
func (s *Store) SweepObjectModelsOnce(ctx context.Context) (*ObjectModelSweepResult, error) {
	res := &ObjectModelSweepResult{}
	// 水位：全部对象模型行的 max(last_seen)（空表为 NULL → 全量回填）
	var wm *time.Time
	if err := s.db.QueryRow(ctx,
		`SELECT max(last_seen) FROM api_object_models`).Scan(&wm); err != nil {
		return nil, fmt.Errorf("object model sweep watermark: %w", err)
	}
	rows, err := s.db.Query(ctx, `
SELECT id, endpoint_key, raw_path, occurred_at
FROM api_runtime_events
WHERE raw_path IS NOT NULL AND raw_path <> ''
  AND ($1::timestamptz IS NULL OR occurred_at > $1)
ORDER BY occurred_at ASC, id ASC
LIMIT $2`, wm, sweepBatchSize)
	if err != nil {
		return nil, fmt.Errorf("object model sweep query: %w", err)
	}
	defer rows.Close()

	type eventRow struct {
		id         uuid.UUID
		key        string
		rawPath    string
		occurredAt time.Time
	}
	events := []eventRow{}
	for rows.Next() {
		var ev eventRow
		if err := rows.Scan(&ev.id, &ev.key, &ev.rawPath, &ev.occurredAt); err != nil {
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
			return nil, fmt.Errorf("object model sweep resolve endpoint %q: %w", ev.key, err)
		}
		if info == nil {
			res.SkippedNoEndpoint++
			continue
		}
		refs := extractObjectSegmentRefs(info.template, ev.rawPath)
		if len(refs) == 0 {
			res.SkippedNoMatch++
			continue
		}
		res.SegmentsExtracted += len(refs)
		for _, ref := range refs {
			// upsert：唯一键 (endpoint_id, object_segment)；sample_count 累加；
			// 形态按 mergeIdentifierType 合并；示例哈希只留首个；首末次时间不回头（乱序防御）。
			if _, err := tx.Exec(ctx, `
INSERT INTO api_object_models
    (endpoint_id, object_segment, identifier_type, example_hash, sample_count, first_seen, last_seen)
VALUES ($1, $2, $3, $4, 1, $5, $5)
ON CONFLICT (endpoint_id, object_segment) DO UPDATE SET
    sample_count = api_object_models.sample_count + 1,
    identifier_type = CASE
        WHEN EXCLUDED.identifier_type = 'unknown' THEN api_object_models.identifier_type
        WHEN api_object_models.identifier_type = 'unknown' THEN EXCLUDED.identifier_type
        WHEN api_object_models.identifier_type = EXCLUDED.identifier_type THEN api_object_models.identifier_type
        ELSE 'mixed' END,
    example_hash = CASE WHEN api_object_models.example_hash = '' THEN EXCLUDED.example_hash
                        ELSE api_object_models.example_hash END,
    first_seen = LEAST(api_object_models.first_seen, EXCLUDED.first_seen),
    last_seen  = GREATEST(api_object_models.last_seen, EXCLUDED.last_seen)`,
				info.id, ref.Segment, identifierTypeOf(ref.Shape), objectExampleHash(ref.Value), ev.occurredAt); err != nil {
				return nil, fmt.Errorf("object model sweep upsert: %w", err)
			}
			res.ModelsUpserted++
		}
	}
	if err := tx.Commit(ctx); err != nil {
		return nil, err
	}
	last := events[len(events)-1].occurredAt
	res.Watermark = &last
	return res, nil
}

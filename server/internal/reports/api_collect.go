package reports

import (
	"context"
	"fmt"
	"time"

	"github.com/google/uuid"
)

// API 报告数据采集：全部真实 SQL（api_endpoints / api_runtime_findings /
// api_weaknesses / api_weakness_actions / api_sensitive_fields），禁止 Mock。
// 任何一步失败都返回明确错误（不静默吞错），与 Collect 同一纪律。

// CollectAPI 采集 API 域报告数据（按报告类型填充对应小节并生成结论建议）。
// in.ApplicationIDs 非空时按站点（应用）过滤：端点类直接过滤 application_id，
// 发现/弱点/敏感字段经端点关联过滤；空值表示全部站点。
func (c *Collector) CollectAPI(ctx context.Context, in CollectInput) (*APIReportData, error) {
	d := &APIReportData{
		ReportType:      in.ReportType,
		PageOrientation: NormalizePageOrientation(in.PageOrientation),
		RangeStart:      in.Start.UTC(),
		RangeEnd:        in.End.UTC(),
		GeneratedAt:     time.Now().UTC(),
	}
	var err error
	switch in.ReportType {
	case TypeAPIAsset:
		err = c.collectAPIAsset(ctx, d, in.ApplicationIDs)
	case TypeAPIRisk:
		err = c.collectAPIRisk(ctx, d, in.ApplicationIDs)
	case TypeAPIWeak:
		err = c.collectAPIWeakness(ctx, d, in.ApplicationIDs)
	case TypeAPISens:
		err = c.collectAPISensitive(ctx, d, in.ApplicationIDs)
	default:
		return nil, fmt.Errorf("%w: 未知的 API 报告类型 %q", ErrInvalidInput, in.ReportType)
	}
	if err != nil {
		return nil, err
	}
	d.Conclusions = BuildAPIConclusions(d)
	d.Suggestions = BuildAPISuggestions(d)
	return d, nil
}

// collectAPICombined 采集主报告 API 安全部分（四类数据合并采集 + 合并结论）。
// includeAssets 为 true 时附加采集全量资产清单（含用途与影子/僵尸标记）。
func (c *Collector) collectAPICombined(ctx context.Context, d *APIReportData, appIDs []uuid.UUID, includeAssets bool) error {
	if err := c.collectAPIAsset(ctx, d, appIDs); err != nil {
		return err
	}
	if err := c.collectAPIRisk(ctx, d, appIDs); err != nil {
		return err
	}
	if err := c.collectAPIWeakness(ctx, d, appIDs); err != nil {
		return err
	}
	if err := c.collectAPISensitive(ctx, d, appIDs); err != nil {
		return err
	}
	if includeAssets {
		if err := c.collectAPIAssetList(ctx, d, appIDs); err != nil {
			return err
		}
	}
	d.Conclusions = BuildCombinedAPIConclusions(d)
	d.Suggestions = BuildCombinedAPISuggestions(d)
	return nil
}

// maxAPIAssetList 全量资产清单展示上限（超出在章节注明「共 N 条，显示前 500」）。
const maxAPIAssetList = 500

// collectAPIAssetList 全量 API 资产清单：方法/路径/用途分类/状态/影子/僵尸/命中次数。
// 影子判定：存在未关闭 SHADOW 发现；僵尸判定：asset_status=ZOMBIE。
func (c *Collector) collectAPIAssetList(ctx context.Context, d *APIReportData, appIDs []uuid.UUID) error {
	cond1, cond1Args := appCond(appIDs, "application_id", 1)
	if err := c.db.QueryRow(ctx,
		`SELECT count(*) FROM api_endpoints WHERE is_api`+cond1, cond1Args...).Scan(&d.AssetListTotal); err != nil {
		return fmt.Errorf("collect api asset list total: %w", err)
	}
	cond2, cond2Args := appCond(appIDs, "e.application_id", 2)
	args := append([]interface{}{findingOpenStatuses}, cond2Args...)
	rows, err := c.db.Query(ctx, `
SELECT e.http_method, e.normalized_path,
       COALESCE(string_agg(DISTINCT c.name, '、') FILTER (WHERE c.name IS NOT NULL), ''),
       e.asset_status,
       EXISTS(SELECT 1 FROM api_runtime_findings f
              WHERE f.endpoint_id = e.id AND f.finding_type = 'SHADOW' AND f.status = ANY($1)) AS is_shadow,
       e.asset_status = 'ZOMBIE' AS is_zombie,
       e.hit_count
FROM api_endpoints e
LEFT JOIN api_classification_dimensions dim ON dim.endpoint_id = e.id AND dim.dimension = 'PURPOSE'
LEFT JOIN api_classifications c ON c.code = dim.value
WHERE e.is_api`+cond2+`
GROUP BY e.id
ORDER BY e.hit_count DESC, e.normalized_path
LIMIT `+fmt.Sprint(maxAPIAssetList), args...)
	if err != nil {
		return fmt.Errorf("collect api asset list: %w", err)
	}
	defer rows.Close()
	for rows.Next() {
		var it APIAssetListItem
		if err := rows.Scan(&it.Method, &it.Path, &it.Purpose, &it.Status, &it.IsShadow, &it.IsZombie, &it.Hits); err != nil {
			return err
		}
		it.Path = truncateRunes(it.Path, 120)
		d.AssetList = append(d.AssetList, it)
	}
	return rows.Err()
}

// appCond 应用范围可选过滤：appIDs 非空时返回 ` AND <column> = ANY($<idx>)` 与参数。
// column 为应用 ID 列表达式（endpoints 表为 application_id，关联表为 e.application_id）。
func appCond(appIDs []uuid.UUID, column string, idx int) (string, []interface{}) {
	if len(appIDs) == 0 {
		return "", nil
	}
	return fmt.Sprintf(` AND %s = ANY($%d)`, column, idx), []interface{}{appIDs}
}

// appEndpointSubquery 应用范围过滤（经端点关联的子查询，用于无 application_id 的表）。
// column 为端点 ID 列（如 endpoint_id / f.endpoint_id / w.endpoint_id / a.weakness_id 不适用）。
func appEndpointSubquery(appIDs []uuid.UUID, column string, idx int) (string, []interface{}) {
	if len(appIDs) == 0 {
		return "", nil
	}
	return fmt.Sprintf(` AND %s IN (SELECT id FROM api_endpoints WHERE application_id = ANY($%d))`, column, idx), []interface{}{appIDs}
}

// collectAPIAsset API 资产周报：总数/新增/确认率/状态分布/Shadow/清单摘要。
func (c *Collector) collectAPIAsset(ctx context.Context, d *APIReportData, appIDs []uuid.UUID) error {
	r := &APIAssetReport{}
	d.Asset = r

	// 总览：总数 / 报告期内新增 / 已确认 / 僵尸 / 已下线
	cond, condArgs := appCond(appIDs, "application_id", 3)
	args := append([]interface{}{d.RangeStart, d.RangeEnd}, condArgs...)
	if err := c.db.QueryRow(ctx, `
SELECT count(*),
       count(*) FILTER (WHERE first_seen_at >= $1 AND first_seen_at < $2),
       count(*) FILTER (WHERE asset_status = 'CONFIRMED'),
       count(*) FILTER (WHERE asset_status = 'ZOMBIE'),
       count(*) FILTER (WHERE asset_status = 'DEPRECATED')
FROM api_endpoints WHERE is_api`+cond, args...).
		Scan(&r.TotalEndpoints, &r.NewEndpoints, &r.Confirmed, &r.Zombie, &r.Deprecated); err != nil {
		return fmt.Errorf("collect api asset overview: %w", err)
	}

	// 资产状态分布
	cond1, cond1Args := appCond(appIDs, "application_id", 1)
	statusDist, err := c.groupCount(ctx,
		`SELECT asset_status, count(*) FROM api_endpoints WHERE is_api`+cond1+` GROUP BY 1 ORDER BY 2 DESC`, cond1Args...)
	if err != nil {
		return fmt.Errorf("collect api asset status dist: %w", err)
	}
	r.StatusDist = statusDist

	// 当前未关闭的 Shadow 发现数
	sub, subArgs := appEndpointSubquery(appIDs, "endpoint_id", 2)
	shadowArgs := append([]interface{}{findingOpenStatuses}, subArgs...)
	if err := c.db.QueryRow(ctx, `
SELECT count(*) FROM api_runtime_findings
WHERE finding_type = 'SHADOW' AND status = ANY($1)`+sub, shadowArgs...).Scan(&r.ShadowOpen); err != nil {
		return fmt.Errorf("collect api shadow open: %w", err)
	}

	// 新增端点清单摘要（最近20条）
	condN, condNArgs := appCond(appIDs, "application_id", 3)
	newArgs := append([]interface{}{d.RangeStart, d.RangeEnd}, condNArgs...)
	r.NewList, err = c.endpointDigests(ctx, `
SELECT http_method, normalized_path, asset_status, hit_count, first_seen_at, last_seen_at
FROM api_endpoints
WHERE is_api AND first_seen_at >= $1 AND first_seen_at < $2`+condN+`
ORDER BY first_seen_at DESC LIMIT 20`, newArgs...)
	if err != nil {
		return fmt.Errorf("collect api new endpoints: %w", err)
	}

	// Shadow 端点清单（未关闭 SHADOW 发现关联端点，按发现数排序，前20）
	condS, condSArgs := appCond(appIDs, "e.application_id", 2)
	shadowListArgs := append([]interface{}{findingOpenStatuses}, condSArgs...)
	rows, err := c.db.Query(ctx, `
SELECT e.http_method, e.normalized_path, e.asset_status, e.hit_count, e.first_seen_at, e.last_seen_at,
       count(f.id) AS findings
FROM api_runtime_findings f
JOIN api_endpoints e ON e.id = f.endpoint_id
WHERE f.finding_type = 'SHADOW' AND f.status = ANY($1)`+condS+`
GROUP BY e.id
ORDER BY findings DESC, e.last_seen_at DESC LIMIT 20`, shadowListArgs...)
	if err != nil {
		return fmt.Errorf("collect api shadow endpoints: %w", err)
	}
	defer rows.Close()
	for rows.Next() {
		var item APIEndpointDigest
		var n int64
		if err := rows.Scan(&item.Method, &item.Path, &item.Status, &item.Hits,
			&item.FirstSeen, &item.LastSeen, &n); err != nil {
			return err
		}
		r.ShadowList = append(r.ShadowList, item)
	}
	return rows.Err()
}

// endpointDigests 端点清单摘要通用查询（五列固定顺序）。
func (c *Collector) endpointDigests(ctx context.Context, query string, args ...interface{}) ([]APIEndpointDigest, error) {
	rows, err := c.db.Query(ctx, query, args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []APIEndpointDigest
	for rows.Next() {
		var item APIEndpointDigest
		if err := rows.Scan(&item.Method, &item.Path, &item.Status, &item.Hits,
			&item.FirstSeen, &item.LastSeen); err != nil {
			return nil, err
		}
		out = append(out, item)
	}
	return out, rows.Err()
}

// collectAPIRisk API 风险周报：新增/关闭/类型与严重度分布/Top 端点与主体。
func (c *Collector) collectAPIRisk(ctx context.Context, d *APIReportData, appIDs []uuid.UUID) error {
	r := &APIRiskReport{}
	d.Risk = r

	// 总览：报告期内新增 / 报告期内关闭 / 当前未关闭
	// 关闭时间口径：COALESCE(updated_at, created_at)（updated_at 为 000036 后补列，存量可空）
	sub, subArgs := appEndpointSubquery(appIDs, "endpoint_id", 5)
	ovArgs := append([]interface{}{d.RangeStart, d.RangeEnd, findingClosedStatuses, findingOpenStatuses}, subArgs...)
	if err := c.db.QueryRow(ctx, `
SELECT count(*) FILTER (WHERE created_at >= $1 AND created_at < $2),
       count(*) FILTER (WHERE status = ANY($3)
                        AND COALESCE(updated_at, created_at) >= $1 AND COALESCE(updated_at, created_at) < $2),
       count(*) FILTER (WHERE status = ANY($4))
FROM api_runtime_findings WHERE TRUE`+sub, ovArgs...).
		Scan(&r.NewFindings, &r.ClosedFindings, &r.OpenFindings); err != nil {
		return fmt.Errorf("collect api risk overview: %w", err)
	}

	// 新增发现的类型分布
	subT, subTArgs := appEndpointSubquery(appIDs, "endpoint_id", 3)
	typeArgs := append([]interface{}{d.RangeStart, d.RangeEnd}, subTArgs...)
	typeDist, err := c.groupCount(ctx, `
SELECT finding_type, count(*) FROM api_runtime_findings
WHERE created_at >= $1 AND created_at < $2`+subT+` GROUP BY 1 ORDER BY 2 DESC LIMIT 10`, typeArgs...)
	if err != nil {
		return fmt.Errorf("collect api risk type dist: %w", err)
	}
	r.TypeDist = typeDist

	// 新增发现的严重度分布
	sevDist, err := c.groupCount(ctx, `
SELECT severity, count(*) FROM api_runtime_findings
WHERE created_at >= $1 AND created_at < $2`+subT+` GROUP BY 1 ORDER BY 2 DESC`, typeArgs...)
	if err != nil {
		return fmt.Errorf("collect api risk severity dist: %w", err)
	}
	r.SeverityDist = sevDist

	// 风险端点 Top10（报告期内新增发现关联端点）
	condE, condEArgs := appCond(appIDs, "e.application_id", 3)
	topArgs := append([]interface{}{d.RangeStart, d.RangeEnd}, condEArgs...)
	rows, err := c.db.Query(ctx, `
SELECT e.http_method, e.normalized_path, count(*),
       count(*) FILTER (WHERE f.severity IN ('HIGH','CRITICAL'))
FROM api_runtime_findings f
JOIN api_endpoints e ON e.id = f.endpoint_id
WHERE f.created_at >= $1 AND f.created_at < $2`+condE+`
GROUP BY e.id ORDER BY 3 DESC, 4 DESC LIMIT 10`, topArgs...)
	if err != nil {
		return fmt.Errorf("collect api risk top endpoints: %w", err)
	}
	defer rows.Close()
	for rows.Next() {
		var item APIRiskEndpoint
		if err := rows.Scan(&item.Method, &item.Path, &item.Findings, &item.High); err != nil {
			return err
		}
		r.TopEndpoints = append(r.TopEndpoints, item)
	}
	if err := rows.Err(); err != nil {
		return err
	}

	// 风险主体 Top10（subject_id 为指纹，不落明文，展示截断至12位）
	subjArgs := append([]interface{}{d.RangeStart, d.RangeEnd}, subTArgs...)
	subjectRows, err := c.db.Query(ctx, `
SELECT subject_type, subject_id, count(*) FROM api_runtime_findings
WHERE created_at >= $1 AND created_at < $2 AND subject_id IS NOT NULL AND subject_id <> ''`+subT+`
GROUP BY 1, 2 ORDER BY 3 DESC LIMIT 10`, subjArgs...)
	if err != nil {
		return fmt.Errorf("collect api risk top subjects: %w", err)
	}
	defer subjectRows.Close()
	for subjectRows.Next() {
		var item APIRiskSubject
		if err := subjectRows.Scan(&item.SubjectType, &item.SubjectID, &item.Findings); err != nil {
			return err
		}
		if len(item.SubjectID) > 12 {
			item.SubjectID = item.SubjectID[:12] + "…"
		}
		r.TopSubjects = append(r.TopSubjects, item)
	}
	return subjectRows.Err()
}

// collectAPIWeakness 弱点整改报告：状态分布/超期未修/复测记录。
func (c *Collector) collectAPIWeakness(ctx context.Context, d *APIReportData, appIDs []uuid.UUID) error {
	r := &APIWeaknessReport{}
	d.Weakness = r

	// 报告期内新派生 / 报告期内完成整改
	sub, subArgs := appEndpointSubquery(appIDs, "endpoint_id", 3)
	ovArgs := append([]interface{}{d.RangeStart, d.RangeEnd}, subArgs...)
	if err := c.db.QueryRow(ctx, `
SELECT count(*) FILTER (WHERE first_seen >= $1 AND first_seen < $2),
       count(*) FILTER (WHERE fixed_at >= $1 AND fixed_at < $2)
FROM api_weaknesses WHERE TRUE`+sub, ovArgs...).
		Scan(&r.NewInRange, &r.FixedInRange); err != nil {
		return fmt.Errorf("collect api weakness overview: %w", err)
	}

	// 超期未修（期限早于报告期末且状态未闭环）
	odArgs := append([]interface{}{d.RangeEnd, weaknessOpenStatuses}, subArgs...)
	if err := c.db.QueryRow(ctx, `
SELECT count(*) FROM api_weaknesses
WHERE due_date IS NOT NULL AND due_date < $1 AND status = ANY($2)`+sub,
		odArgs...).Scan(&r.OverdueOpen); err != nil {
		return fmt.Errorf("collect api weakness overdue: %w", err)
	}

	// 报告期内复测通过/失败次数（经弱点 → 端点关联过滤）
	subA, subAArgs := appEndpointSubquery(appIDs, "w.endpoint_id", 3)
	rtArgs := append([]interface{}{d.RangeStart, d.RangeEnd}, subAArgs...)
	if err := c.db.QueryRow(ctx, `
SELECT count(*) FILTER (WHERE a.action = 'RETEST_PASS'),
       count(*) FILTER (WHERE a.action = 'RETEST_FAIL')
FROM api_weakness_actions a
JOIN api_weaknesses w ON w.id = a.weakness_id
WHERE a.created_at >= $1 AND a.created_at < $2 AND a.action IN ('RETEST_PASS','RETEST_FAIL')`+subA,
		rtArgs...).Scan(&r.RetestPass, &r.RetestFail); err != nil {
		return fmt.Errorf("collect api weakness retest: %w", err)
	}

	// 状态分布（全量）
	sub1, sub1Args := appEndpointSubquery(appIDs, "endpoint_id", 1)
	statusDist, err := c.groupCount(ctx,
		`SELECT status, count(*) FROM api_weaknesses WHERE TRUE`+sub1+` GROUP BY 1 ORDER BY 2 DESC`, sub1Args...)
	if err != nil {
		return fmt.Errorf("collect api weakness status dist: %w", err)
	}
	r.StatusDist = statusDist

	// 未闭环弱点严重度分布
	sub2, sub2Args := appEndpointSubquery(appIDs, "endpoint_id", 2)
	sevArgs := append([]interface{}{weaknessOpenStatuses}, sub2Args...)
	sevDist, err := c.groupCount(ctx, `
SELECT severity, count(*) FROM api_weaknesses WHERE status = ANY($1)`+sub2+` GROUP BY 1 ORDER BY 2 DESC`,
		sevArgs...)
	if err != nil {
		return fmt.Errorf("collect api weakness severity dist: %w", err)
	}
	r.SeverityDist = sevDist

	// 超期未修清单（按期限升序，前20）
	rows, err := c.db.Query(ctx, `
SELECT weakness_name, weakness_code, severity, status, owner, due_date
FROM api_weaknesses
WHERE due_date IS NOT NULL AND due_date < $1 AND status = ANY($2)`+sub+`
ORDER BY due_date ASC LIMIT 20`, odArgs...)
	if err != nil {
		return fmt.Errorf("collect api weakness overdue list: %w", err)
	}
	defer rows.Close()
	for rows.Next() {
		var item APIWeaknessItem
		if err := rows.Scan(&item.Name, &item.Code, &item.Severity, &item.Status, &item.Owner, &item.DueDate); err != nil {
			return err
		}
		r.OverdueList = append(r.OverdueList, item)
	}
	if err := rows.Err(); err != nil {
		return err
	}

	// 最近复测记录（前10）
	retestRows, err := c.db.Query(ctx, `
SELECT a.action, a.actor, a.created_at, COALESCE(NULLIF(w.weakness_name,''), w.weakness_code)
FROM api_weakness_actions a
JOIN api_weaknesses w ON w.id = a.weakness_id
WHERE a.created_at >= $1 AND a.created_at < $2 AND a.action IN ('RETEST_PASS','RETEST_FAIL')`+subA+`
ORDER BY a.created_at DESC LIMIT 10`, rtArgs...)
	if err != nil {
		return fmt.Errorf("collect api weakness retest list: %w", err)
	}
	defer retestRows.Close()
	for retestRows.Next() {
		var item APIRetestItem
		if err := retestRows.Scan(&item.Action, &item.Actor, &item.CreatedAt, &item.WeaknessName); err != nil {
			return err
		}
		r.RetestList = append(r.RetestList, item)
	}
	return retestRows.Err()
}

// collectAPISensitive 敏感数据报告：类型分布/涉敏端点 Top/按天新增趋势。
func (c *Collector) collectAPISensitive(ctx context.Context, d *APIReportData, appIDs []uuid.UUID) error {
	r := &APISensitiveReport{}
	d.Sensitive = r

	// 总数 / 报告期内新识别（first_seen 为 000040 后补列，存量可空 → COALESCE created_at）
	sub, subArgs := appEndpointSubquery(appIDs, "endpoint_id", 3)
	ovArgs := append([]interface{}{d.RangeStart, d.RangeEnd}, subArgs...)
	if err := c.db.QueryRow(ctx, `
SELECT count(*),
       count(*) FILTER (WHERE COALESCE(first_seen, created_at) >= $1 AND COALESCE(first_seen, created_at) < $2)
FROM api_sensitive_fields WHERE TRUE`+sub, ovArgs...).
		Scan(&r.TotalFields, &r.NewInRange); err != nil {
		return fmt.Errorf("collect api sensitive overview: %w", err)
	}

	// 数据类型分布
	sub1, sub1Args := appEndpointSubquery(appIDs, "endpoint_id", 1)
	typeDist, err := c.groupCount(ctx,
		`SELECT data_type, count(*) FROM api_sensitive_fields WHERE TRUE`+sub1+` GROUP BY 1 ORDER BY 2 DESC`, sub1Args...)
	if err != nil {
		return fmt.Errorf("collect api sensitive type dist: %w", err)
	}
	r.TypeDist = typeDist

	// 涉敏端点 Top10（敏感字段数排序）
	condE, condEArgs := appCond(appIDs, "e.application_id", 1)
	rows, err := c.db.Query(ctx, `
SELECT e.http_method, e.normalized_path, count(*), count(DISTINCT f.data_type)
FROM api_sensitive_fields f
JOIN api_endpoints e ON e.id = f.endpoint_id
WHERE TRUE`+condE+`
GROUP BY e.id ORDER BY 3 DESC, 4 DESC LIMIT 10`, condEArgs...)
	if err != nil {
		return fmt.Errorf("collect api sensitive top endpoints: %w", err)
	}
	defer rows.Close()
	for rows.Next() {
		var item APISensitiveEndpoint
		if err := rows.Scan(&item.Method, &item.Path, &item.Fields, &item.Types); err != nil {
			return err
		}
		r.TopEndpoints = append(r.TopEndpoints, item)
	}
	if err := rows.Err(); err != nil {
		return err
	}

	// 报告期内按天新增趋势
	trendArgs := append([]interface{}{d.RangeStart, d.RangeEnd}, subArgs...)
	trendRows, err := c.db.Query(ctx, `
SELECT date_trunc('day', COALESCE(first_seen, created_at)), count(*)
FROM api_sensitive_fields
WHERE COALESCE(first_seen, created_at) >= $1 AND COALESCE(first_seen, created_at) < $2`+sub+`
GROUP BY 1 ORDER BY 1`, trendArgs...)
	if err != nil {
		return fmt.Errorf("collect api sensitive daily trend: %w", err)
	}
	defer trendRows.Close()
	for trendRows.Next() {
		var p Point
		if err := trendRows.Scan(&p.Time, &p.Value); err != nil {
			return err
		}
		r.DailyNew = append(r.DailyNew, p)
	}
	return trendRows.Err()
}

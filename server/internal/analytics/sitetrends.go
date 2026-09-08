// sitetrends.go 网站访问趋势：应用/域名维度聚合（直查 access_logs，含零流量应用与补桶）。
// access_logs 保留期默认 7 天，故查询跨度上限 7 天（校验在本文件 handler，不动公共 ParseRange）。
package analytics

import (
	"context"
	"net/http"
	"sort"
	"time"

	"github.com/google/uuid"
	"github.com/jiuzhang-waf/server/internal/response"
)

// siteTrendMaxRange 访问日志数据保留期约 7 天，趋势查询跨度上限 7 天。
const siteTrendMaxRange = 7 * 24 * time.Hour

// TrendPoint 单个时间桶的请求计数点。
type TrendPoint struct {
	T        time.Time `json:"t"`
	Requests int64     `json:"requests"`
}

// SiteAccessTrendItem 单应用的访问趋势项。
type SiteAccessTrendItem struct {
	ApplicationID uuid.UUID    `json:"application_id"`
	AppCode       string       `json:"app_code"`
	AppName       string       `json:"app_name"`
	TotalRequests int64        `json:"total_requests"`
	Series        []TrendPoint `json:"series"`
}

// DomainAccessTrendItem 单域名的访问趋势项。
type DomainAccessTrendItem struct {
	Domain        string       `json:"domain"`
	TotalRequests int64        `json:"total_requests"`
	Series        []TrendPoint `json:"series"`
}

// SiteAccessTrendsData 应用维度访问趋势响应。
type SiteAccessTrendsData struct {
	Start       time.Time             `json:"start"`
	End         time.Time             `json:"end"`
	Granularity string                `json:"granularity"`
	Items       []SiteAccessTrendItem `json:"items"`
}

// DomainAccessTrendsData 域名维度访问趋势响应。
type DomainAccessTrendsData struct {
	Start       time.Time               `json:"start"`
	End         time.Time               `json:"end"`
	Granularity string                  `json:"granularity"`
	Items       []DomainAccessTrendItem `json:"items"`
}

// ---------- 纯函数：时间轴补桶与排序 ----------

// bucketFloor 把时间向下取整到桶边界（UTC）。
func bucketFloor(t time.Time, bucket string) time.Time {
	t = t.UTC()
	switch bucket {
	case "minute":
		return t.Truncate(time.Minute)
	case "day":
		return time.Date(t.Year(), t.Month(), t.Day(), 0, 0, 0, 0, time.UTC)
	default: // hour
		return t.Truncate(time.Hour)
	}
}

// bucketStep 返回桶粒度对应的步长。
func bucketStep(bucket string) time.Duration {
	switch bucket {
	case "minute":
		return time.Minute
	case "day":
		return 24 * time.Hour
	default:
		return time.Hour
	}
}

// fillBuckets 生成 [Start, End) 完整时间轴，范围内空桶补 0。
func fillBuckets(r Range, counts map[time.Time]int64) []TrendPoint {
	bucket := r.TrendBucket()
	step := bucketStep(bucket)
	out := []TrendPoint{}
	for t := bucketFloor(r.Start, bucket); t.Before(r.End); t = t.Add(step) {
		out = append(out, TrendPoint{T: t, Requests: counts[t]})
	}
	return out
}

// sortSiteTrendItems 总访问量降序，相同按应用编码升序（保证确定性输出）。
func sortSiteTrendItems(items []SiteAccessTrendItem) {
	sort.Slice(items, func(i, j int) bool {
		if items[i].TotalRequests != items[j].TotalRequests {
			return items[i].TotalRequests > items[j].TotalRequests
		}
		return items[i].AppCode < items[j].AppCode
	})
}

// sortDomainTrendItems 总访问量降序，相同按域名升序。
func sortDomainTrendItems(items []DomainAccessTrendItem) {
	sort.Slice(items, func(i, j int) bool {
		if items[i].TotalRequests != items[j].TotalRequests {
			return items[i].TotalRequests > items[j].TotalRequests
		}
		return items[i].Domain < items[j].Domain
	})
}

// ---------- Store 查询 ----------

// SiteAccessTrends 应用维度访问趋势：以 applications 为准 LEFT JOIN access_logs，
// 含零流量应用，按总访问量降序，series 为补桶后的完整时间轴。
func (s *Store) SiteAccessTrends(ctx context.Context, r Range) (*SiteAccessTrendsData, error) {
	rows, err := s.db.Query(ctx, `
SELECT a.id, a.code, a.name, date_trunc($1, l.occurred_at) AS b, count(l.id) AS n
FROM applications a
LEFT JOIN access_logs l ON l.application_id = a.id AND l.occurred_at >= $2 AND l.occurred_at < $3
WHERE a.deleted_at IS NULL AND a.status <> 'DELETED'
GROUP BY a.id, a.code, a.name, b`, r.TrendBucket(), r.Start, r.End)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	type agg struct {
		code, name string
		total      int64
		counts     map[time.Time]int64
	}
	apps := map[uuid.UUID]*agg{}
	order := []uuid.UUID{}
	for rows.Next() {
		var id uuid.UUID
		var code, name string
		var b *time.Time
		var n int64
		if err := rows.Scan(&id, &code, &name, &b, &n); err != nil {
			return nil, err
		}
		a, ok := apps[id]
		if !ok {
			a = &agg{code: code, name: name, counts: map[time.Time]int64{}}
			apps[id] = a
			order = append(order, id)
		}
		a.total += n
		if b != nil {
			a.counts[b.UTC()] += n
		}
	}
	if err := rows.Err(); err != nil {
		return nil, err
	}
	out := &SiteAccessTrendsData{
		Start: r.Start, End: r.End, Granularity: r.TrendBucket(),
		Items: []SiteAccessTrendItem{},
	}
	for _, id := range order {
		a := apps[id]
		out.Items = append(out.Items, SiteAccessTrendItem{
			ApplicationID: id,
			AppCode:       a.code,
			AppName:       a.name,
			TotalRequests: a.total,
			Series:        fillBuckets(r, a.counts),
		})
	}
	sortSiteTrendItems(out.Items)
	return out, nil
}

// SiteAccessTrendDomains 域名维度访问趋势（限定应用），按总访问量降序。
func (s *Store) SiteAccessTrendDomains(ctx context.Context, r Range, appID uuid.UUID) (*DomainAccessTrendsData, error) {
	rows, err := s.db.Query(ctx, `
SELECT domain, date_trunc($1, occurred_at) AS b, count(*) AS n
FROM access_logs
WHERE application_id = $2 AND occurred_at >= $3 AND occurred_at < $4
GROUP BY domain, b`, r.TrendBucket(), appID, r.Start, r.End)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	type agg struct {
		total  int64
		counts map[time.Time]int64
	}
	domains := map[string]*agg{}
	order := []string{}
	for rows.Next() {
		var domain string
		var b time.Time
		var n int64
		if err := rows.Scan(&domain, &b, &n); err != nil {
			return nil, err
		}
		d, ok := domains[domain]
		if !ok {
			d = &agg{counts: map[time.Time]int64{}}
			domains[domain] = d
			order = append(order, domain)
		}
		d.total += n
		d.counts[b.UTC()] += n
	}
	if err := rows.Err(); err != nil {
		return nil, err
	}
	out := &DomainAccessTrendsData{
		Start: r.Start, End: r.End, Granularity: r.TrendBucket(),
		Items: []DomainAccessTrendItem{},
	}
	for _, domain := range order {
		d := domains[domain]
		out.Items = append(out.Items, DomainAccessTrendItem{
			Domain:        domain,
			TotalRequests: d.total,
			Series:        fillBuckets(r, d.counts),
		})
	}
	sortDomainTrendItems(out.Items)
	return out, nil
}

// ---------- HTTP Handler ----------

// parseSiteTrendRange 解析时间范围并施加 7 天数据保留期上限。
func (h *Handler) parseSiteTrendRange(w http.ResponseWriter, r *http.Request) (Range, bool) {
	rng, err := ParseRange(r.URL.Query(), time.Now())
	if err != nil {
		response.Error(w, r, http.StatusBadRequest, response.CodeInvalidArgument, err.Error())
		return Range{}, false
	}
	if rng.End.Sub(rng.Start) > siteTrendMaxRange {
		response.Error(w, r, http.StatusBadRequest, response.CodeInvalidArgument,
			"时间跨度不能超过 7 天（访问日志数据保留期限制）")
		return Range{}, false
	}
	return rng, true
}

// SiteAccessTrends GET /api/v1/analytics/site-access-trends
func (h *Handler) SiteAccessTrends(w http.ResponseWriter, r *http.Request) {
	rng, ok := h.parseSiteTrendRange(w, r)
	if !ok {
		return
	}
	data, err := h.store.SiteAccessTrends(r.Context(), rng)
	if err != nil {
		response.InternalError(w, r, err)
		return
	}
	response.JSON(w, r, http.StatusOK, data)
}

// SiteAccessTrendDomains GET /api/v1/analytics/site-access-trends/domains
func (h *Handler) SiteAccessTrendDomains(w http.ResponseWriter, r *http.Request) {
	rng, ok := h.parseSiteTrendRange(w, r)
	if !ok {
		return
	}
	v := r.URL.Query().Get("application_id")
	if v == "" {
		response.Error(w, r, http.StatusBadRequest, response.CodeInvalidArgument, "缺少 application_id 参数")
		return
	}
	appID, err := uuid.Parse(v)
	if err != nil {
		response.Error(w, r, http.StatusBadRequest, response.CodeInvalidArgument, "无效的应用ID")
		return
	}
	data, err := h.store.SiteAccessTrendDomains(r.Context(), rng, appID)
	if err != nil {
		response.InternalError(w, r, err)
		return
	}
	response.JSON(w, r, http.StatusOK, data)
}

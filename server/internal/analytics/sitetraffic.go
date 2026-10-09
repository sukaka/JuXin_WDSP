// sitetraffic.go 站点流量分析：按站点（应用）查看流量（请求数/收发字节/独立 IP/阻断数）。
// 数据源路由：跨度 ≤7 天直查 access_logs；>7 天查日聚合表 site_traffic_daily
// （access_logs 留存约 7 天，由 aggregations.RunSiteTrafficDaily 按 UTC 天重算）。
// 桶粒度沿用 Range.TrendBucket：≤1h 分钟桶，≤7d 小时桶，更大为天桶；空桶补 0。
// 时间全部 UTC 约定，响应字段名为冻结契约（前端同步开发，不得改名）。
package analytics

import (
	"context"
	"fmt"
	"net/http"
	"sort"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jiuzhang-waf/server/internal/response"
)

const (
	// siteTrafficMaxRange 站点流量查询跨度上限（31 天）。
	siteTrafficMaxRange = 31 * 24 * time.Hour
	// siteTrafficDirectMaxRange 直查 access_logs 的跨度上限（访问日志保留期约 7 天）。
	siteTrafficDirectMaxRange = 7 * 24 * time.Hour

	// siteTrafficSourceAccessLogs 数据源：实时直查访问日志。
	siteTrafficSourceAccessLogs = "access_logs"
	// siteTrafficSourceDaily 数据源：站点流量日聚合表。
	siteTrafficSourceDaily = "site_traffic_daily"
)

// SiteTrafficPoint 单个时间桶的流量点。
type SiteTrafficPoint struct {
	T               time.Time `json:"t"`
	Requests        int64     `json:"requests"`
	BytesIn         int64     `json:"bytes_in"`
	BytesOut        int64     `json:"bytes_out"`
	UniqueIPs       int64     `json:"unique_ips"`
	BlockedRequests int64     `json:"blocked_requests"`
}

// SiteTrafficItem 单站点的流量项（含补桶后的完整时间轴）。
// >7 天视图中 UniqueIPs 为逐日去重计数的加和（非跨天去重），仅供站点间相对比较。
type SiteTrafficItem struct {
	ApplicationID   uuid.UUID          `json:"application_id"`
	AppCode         string             `json:"app_code"`
	AppName         string             `json:"app_name"`
	TotalRequests   int64              `json:"total_requests"`
	TotalBytesIn    int64              `json:"total_bytes_in"`
	TotalBytesOut   int64              `json:"total_bytes_out"`
	UniqueIPs       int64              `json:"unique_ips"`
	BlockedRequests int64              `json:"blocked_requests"`
	Series          []SiteTrafficPoint `json:"series"`
}

// SiteTrafficSummary 全部 items 的合计。>7 天时 UniqueIPs 为 null：
// 日聚合表的 unique_ips 是单日去重值，跨天加和会重复计数，不可作为区间去重结果。
// PeakBucketRequests 口径：items 汇总序列（各站点同一桶的 requests 加总）的单桶最大值。
type SiteTrafficSummary struct {
	TotalRequests      int64  `json:"total_requests"`
	TotalBytesIn       int64  `json:"total_bytes_in"`
	TotalBytesOut      int64  `json:"total_bytes_out"`
	UniqueIPs          *int64 `json:"unique_ips"`
	BlockedRequests    int64  `json:"blocked_requests"`
	PeakBucketRequests int64  `json:"peak_bucket_requests"`
}

// SiteTrafficData 站点流量分析响应。
type SiteTrafficData struct {
	Start       time.Time          `json:"start"`
	End         time.Time          `json:"end"`
	Granularity string             `json:"granularity"`
	Source      string             `json:"source"`
	Summary     SiteTrafficSummary `json:"summary"`
	Items       []SiteTrafficItem  `json:"items"`
}

// ---------- 纯函数：数据源路由、补桶、组装 ----------

// siteTrafficSource 数据源路由：跨度 ≤7 天直查 access_logs，>7 天查日聚合表。
func siteTrafficSource(r Range) string {
	if r.End.Sub(r.Start) <= siteTrafficDirectMaxRange {
		return siteTrafficSourceAccessLogs
	}
	return siteTrafficSourceDaily
}

// siteTrafficBucket 单桶聚合值（两数据源共用形状）。
type siteTrafficBucket struct {
	requests  int64
	bytesIn   int64
	bytesOut  int64
	uniqueIPs int64
	blocked   int64
}

// siteTrafficRow 查询返回的单应用单桶行；bucket 为 nil 表示该应用无流量（LEFT JOIN 空侧）。
type siteTrafficRow struct {
	appID  uuid.UUID
	code   string
	name   string
	bucket *time.Time
	m      siteTrafficBucket
}

// fillTrafficBuckets 生成 [Start, End) 完整时间轴，范围内空桶补 0。
func fillTrafficBuckets(r Range, buckets map[time.Time]siteTrafficBucket) []SiteTrafficPoint {
	bucket := r.TrendBucket()
	step := bucketStep(bucket)
	out := []SiteTrafficPoint{}
	for t := bucketFloor(r.Start, bucket); t.Before(r.End); t = t.Add(step) {
		m := buckets[t]
		out = append(out, SiteTrafficPoint{
			T: t, Requests: m.requests, BytesIn: m.bytesIn, BytesOut: m.bytesOut,
			UniqueIPs: m.uniqueIPs, BlockedRequests: m.blocked,
		})
	}
	return out
}

// sortSiteTrafficItems 总请求数降序，相同按应用编码升序（保证确定性输出）。
func sortSiteTrafficItems(items []SiteTrafficItem) {
	sort.Slice(items, func(i, j int) bool {
		if items[i].TotalRequests != items[j].TotalRequests {
			return items[i].TotalRequests > items[j].TotalRequests
		}
		return items[i].AppCode < items[j].AppCode
	})
}

// assembleSiteTraffic 把查询行组装为响应：以 applications 为准（零流量应用也在结果中），
// series 补桶，item 合计等于其 series 各桶加总（保证与坐标轴一致），summary 为 items 合计。
func assembleSiteTraffic(r Range, source string, rows []siteTrafficRow) *SiteTrafficData {
	type agg struct {
		code, name string
		buckets    map[time.Time]siteTrafficBucket
	}
	apps := map[uuid.UUID]*agg{}
	order := []uuid.UUID{}
	for _, row := range rows {
		a, ok := apps[row.appID]
		if !ok {
			a = &agg{code: row.code, name: row.name, buckets: map[time.Time]siteTrafficBucket{}}
			apps[row.appID] = a
			order = append(order, row.appID)
		}
		if row.bucket != nil {
			t := row.bucket.UTC()
			b := a.buckets[t]
			b.requests += row.m.requests
			b.bytesIn += row.m.bytesIn
			b.bytesOut += row.m.bytesOut
			b.uniqueIPs += row.m.uniqueIPs
			b.blocked += row.m.blocked
			a.buckets[t] = b
		}
	}
	out := &SiteTrafficData{
		Start: r.Start, End: r.End, Granularity: r.TrendBucket(), Source: source,
		Items: []SiteTrafficItem{},
	}
	for _, id := range order {
		a := apps[id]
		item := SiteTrafficItem{
			ApplicationID: id, AppCode: a.code, AppName: a.name,
			Series: fillTrafficBuckets(r, a.buckets),
		}
		for _, p := range item.Series {
			item.TotalRequests += p.Requests
			item.TotalBytesIn += p.BytesIn
			item.TotalBytesOut += p.BytesOut
			item.UniqueIPs += p.UniqueIPs
			item.BlockedRequests += p.BlockedRequests
		}
		out.Items = append(out.Items, item)
	}
	sortSiteTrafficItems(out.Items)
	// summary：items 合计；peak 取 items 汇总序列（同桶 requests 加总）的单桶最大值。
	var uniqueSum int64
	peakByBucket := map[time.Time]int64{}
	for _, item := range out.Items {
		out.Summary.TotalRequests += item.TotalRequests
		out.Summary.TotalBytesIn += item.TotalBytesIn
		out.Summary.TotalBytesOut += item.TotalBytesOut
		out.Summary.BlockedRequests += item.BlockedRequests
		uniqueSum += item.UniqueIPs
		for _, p := range item.Series {
			peakByBucket[p.T] += p.Requests
			if peakByBucket[p.T] > out.Summary.PeakBucketRequests {
				out.Summary.PeakBucketRequests = peakByBucket[p.T]
			}
		}
	}
	if source == siteTrafficSourceAccessLogs {
		// 直查 access_logs 时 unique_ips 为区间真实去重值，可加和；
		// 走日聚合表（>7 天）时跨天去重不可加和，summary.unique_ips 置 null。
		out.Summary.UniqueIPs = &uniqueSum
	}
	return out
}

// ---------- Store 查询 ----------

// SiteTraffic 站点流量分析：按跨度路由数据源，含零流量应用，按总请求数降序。
// 指定 appID 时只返回该站点一项（未知 id 返回空 items，不报错）。
func (s *Store) SiteTraffic(ctx context.Context, r Range, appID *uuid.UUID) (*SiteTrafficData, error) {
	source := siteTrafficSource(r)
	var (
		rows []siteTrafficRow
		err  error
	)
	if source == siteTrafficSourceAccessLogs {
		rows, err = s.siteTrafficFromAccessLogs(ctx, r, appID)
	} else {
		rows, err = s.siteTrafficFromDaily(ctx, r, appID)
	}
	if err != nil {
		return nil, err
	}
	return assembleSiteTraffic(r, source, rows), nil
}

// siteTrafficFromAccessLogs 直查 access_logs（≤7 天）：独立 IP 为区间真实去重，
// 阻断数为 waf_action='BLOCK' 计数；以 applications 为准 LEFT JOIN 含零流量应用。
func (s *Store) siteTrafficFromAccessLogs(ctx context.Context, r Range, appID *uuid.UUID) ([]siteTrafficRow, error) {
	where := "a.deleted_at IS NULL AND a.status <> 'DELETED'"
	args := []interface{}{r.TrendBucket(), r.Start, r.End}
	if appID != nil {
		where += fmt.Sprintf(" AND a.id = $%d", len(args)+1)
		args = append(args, *appID)
	}
	rows, err := s.db.Query(ctx, fmt.Sprintf(`
SELECT a.id, a.code, a.name, date_trunc($1, l.occurred_at) AS b,
  count(l.id),
  COALESCE(sum(l.bytes_in), 0),
  COALESCE(sum(l.bytes_out), 0),
  count(DISTINCT l.client_ip),
  count(l.id) FILTER (WHERE l.waf_action = 'BLOCK')
FROM applications a
LEFT JOIN access_logs l ON l.application_id = a.id AND l.occurred_at >= $2 AND l.occurred_at < $3
WHERE %s
GROUP BY a.id, a.code, a.name, b`, where), args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	return scanSiteTrafficRows(rows)
}

// siteTrafficFromDaily 查站点流量日聚合表（>7 天，天桶）：桶范围为坐标轴覆盖的
// 日期闭区间 [起始日, 末桶日]；末桶日 = 最后一个天桶（end 恰在零点时不含 end 当日）。
func (s *Store) siteTrafficFromDaily(ctx context.Context, r Range, appID *uuid.UUID) ([]siteTrafficRow, error) {
	startDate := bucketFloor(r.Start, "day")
	lastDate := bucketFloor(r.End.Add(-time.Nanosecond), "day")
	where := "a.deleted_at IS NULL AND a.status <> 'DELETED'"
	args := []interface{}{startDate, lastDate}
	if appID != nil {
		where += fmt.Sprintf(" AND a.id = $%d", len(args)+1)
		args = append(args, *appID)
	}
	rows, err := s.db.Query(ctx, fmt.Sprintf(`
SELECT a.id, a.code, a.name, d.bucket_date AS b,
  COALESCE(d.requests, 0),
  COALESCE(d.bytes_in, 0),
  COALESCE(d.bytes_out, 0),
  COALESCE(d.unique_ips, 0),
  COALESCE(d.blocked_requests, 0)
FROM applications a
LEFT JOIN site_traffic_daily d ON d.application_id = a.id
  AND d.bucket_date >= $1::date AND d.bucket_date <= $2::date
WHERE %s`, where), args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	return scanSiteTrafficRows(rows)
}

// scanSiteTrafficRows 扫描两数据源共用的行形状（id, code, name, bucket, 5 个聚合值）。
func scanSiteTrafficRows(rows pgx.Rows) ([]siteTrafficRow, error) {
	out := []siteTrafficRow{}
	for rows.Next() {
		var row siteTrafficRow
		if err := rows.Scan(&row.appID, &row.code, &row.name, &row.bucket,
			&row.m.requests, &row.m.bytesIn, &row.m.bytesOut, &row.m.uniqueIPs, &row.m.blocked); err != nil {
			return nil, err
		}
		out = append(out, row)
	}
	return out, rows.Err()
}

// ---------- HTTP Handler ----------

// SiteTraffic GET /api/v1/analytics/site-traffic
func (h *Handler) SiteTraffic(w http.ResponseWriter, r *http.Request) {
	rng, err := ParseRange(r.URL.Query(), time.Now())
	if err != nil {
		response.Error(w, r, http.StatusBadRequest, response.CodeInvalidArgument, err.Error())
		return
	}
	if rng.End.Sub(rng.Start) > siteTrafficMaxRange {
		response.Error(w, r, http.StatusBadRequest, response.CodeInvalidArgument, "时间跨度不能超过 31 天")
		return
	}
	var appID *uuid.UUID
	if v := r.URL.Query().Get("application_id"); v != "" {
		id, err := uuid.Parse(v)
		if err != nil {
			response.Error(w, r, http.StatusBadRequest, response.CodeInvalidArgument, "无效的应用ID")
			return
		}
		appID = &id
	}
	data, err := h.store.SiteTraffic(r.Context(), rng, appID)
	if err != nil {
		response.InternalError(w, r, err)
		return
	}
	response.JSON(w, r, http.StatusOK, data)
}

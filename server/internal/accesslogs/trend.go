package accesslogs

import (
	"context"
	"fmt"
	"time"
)

// TrendPoint 是访问日志时间桶的真实聚合计数。
type TrendPoint struct {
	Bucket  time.Time `json:"bucket"`
	Total   int64     `json:"total"`
	Blocked int64     `json:"blocked"`
	Errors  int64     `json:"errors"`
}

// Trend 按已有访问日志聚合趋势；不读取请求/响应正文或PCAP文件。
func (s *Store) Trend(ctx context.Context, f ListFilter, bucketSeconds int) ([]TrendPoint, error) {
	query, args := buildTrendQuery(f, bucketSeconds)
	rows, err := s.db.Query(ctx, query, args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := make([]TrendPoint, 0)
	for rows.Next() {
		var point TrendPoint
		if err := rows.Scan(&point.Bucket, &point.Total, &point.Blocked, &point.Errors); err != nil {
			return nil, err
		}
		out = append(out, point)
	}
	return out, rows.Err()
}

func buildTrendQuery(f ListFilter, bucketSeconds int) (string, []interface{}) {
	where, args := buildListWhere(f)
	bucketArg := len(args) + 1
	args = append(args, bucketSeconds)
	query := fmt.Sprintf(`
SELECT to_timestamp((floor(extract(epoch FROM occurred_at) / $%[1]d) * $%[1]d)::double precision) AS bucket,
  count(*) AS total,
  count(*) FILTER (WHERE waf_action = 'BLOCK') AS blocked,
  count(*) FILTER (WHERE response_status >= 500) AS errors
FROM access_logs
WHERE %s
GROUP BY bucket
ORDER BY bucket`, bucketArg, where)
	return query, args
}

func trendBucketSeconds(start, end time.Time, requested string) (int, error) {
	if requested != "" {
		var seconds int
		if _, err := fmt.Sscanf(requested, "%d", &seconds); err != nil {
			return 0, fmt.Errorf("bucket_seconds 必须是支持的整数秒数")
		}
		switch seconds {
		case 60, 300, 900, 3600, 86400:
			return seconds, nil
		default:
			return 0, fmt.Errorf("bucket_seconds 仅支持 60/300/900/3600/86400")
		}
	}
	duration := end.Sub(start)
	switch {
	case duration <= time.Hour:
		return 60, nil
	case duration <= 6*time.Hour:
		return 300, nil
	case duration <= 24*time.Hour:
		return 900, nil
	case duration <= 7*24*time.Hour:
		return 3600, nil
	default:
		return 86400, nil
	}
}

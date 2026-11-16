package apisecurity

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/google/uuid"
	"github.com/jiuzhang-waf/server/internal/response"
)

type SharedDeviceTrendFilter struct {
	SharedDeviceFilter
	Bucket string
}

type SharedDeviceTrendPoint struct {
	Bucket      time.Time `json:"bucket"`
	GroupCount  int64     `json:"group_count"`
	SignalCount int64     `json:"signal_count"`
	EventCount  int64     `json:"event_count"`
}

func (h *Handler) SharedDeviceTrend(w http.ResponseWriter, r *http.Request) {
	filter, err := parseSharedDeviceFilter(r, time.Now().UTC())
	if err != nil {
		response.Error(w, r, http.StatusBadRequest, response.CodeInvalidArgument, err.Error())
		return
	}
	bucket := strings.ToLower(strings.TrimSpace(r.URL.Query().Get("bucket")))
	if bucket == "" {
		bucket = "hour"
		if filter.End.Sub(filter.Start) > 48*time.Hour {
			bucket = "day"
		}
	}
	if bucket != "hour" && bucket != "day" {
		response.Error(w, r, http.StatusBadRequest, response.CodeInvalidArgument, "bucket 仅支持 hour 或 day")
		return
	}
	if h.groupControl == nil {
		response.Error(w, r, http.StatusServiceUnavailable, response.CodeServiceUnavailable, "群控观察数据读取未装配")
		return
	}
	items, err := h.groupControl.SharedDeviceTrend(r.Context(), SharedDeviceTrendFilter{SharedDeviceFilter: filter, Bucket: bucket})
	if err != nil {
		response.InternalError(w, r, err)
		return
	}
	response.JSON(w, r, http.StatusOK, map[string]any{
		"items": items, "start": filter.Start, "end": filter.End, "bucket": bucket,
		"partial": true, "data_scope": "NOTABLE_SECURITY_EVENTS",
	})
}

func (s *Store) SharedDeviceTrend(ctx context.Context, filter SharedDeviceTrendFilter) ([]SharedDeviceTrendPoint, error) {
	base := filter.SharedDeviceFilter
	if base.Start.IsZero() || base.End.IsZero() || !base.Start.Before(base.End) || base.End.Sub(base.Start) > 31*24*time.Hour {
		return nil, errors.New("invalid shared-device time range")
	}
	if base.MinAccounts < 2 || base.MinAccounts > 1000 {
		return nil, errors.New("invalid shared-device threshold")
	}
	if filter.Bucket != "hour" && filter.Bucket != "day" {
		return nil, errors.New("invalid trend bucket")
	}
	where := []string{
		"occurred_at >= $1", "occurred_at < $2", "application_id IS NOT NULL",
		"device_fingerprint IS NOT NULL", "device_fingerprint <> ''",
		"jwt_verification->>'status' = 'VERIFIED'",
		"jwt_verification->>'verified_principal_id' ~ '^[0-9a-f]{32}$'",
	}
	args := []any{base.Start, base.End}
	if base.ApplicationID != "" {
		applicationID, err := uuid.Parse(base.ApplicationID)
		if err != nil {
			return nil, errors.New("invalid application_id")
		}
		args = append(args, applicationID)
		where = append(where, fmt.Sprintf("application_id = $%d", len(args)))
	}
	if base.DeviceFingerprint != "" {
		if !isSharedDeviceFingerprint(base.DeviceFingerprint) {
			return nil, errors.New("invalid device_fingerprint")
		}
		args = append(args, base.DeviceFingerprint)
		where = append(where, fmt.Sprintf("device_fingerprint = $%d", len(args)))
	}
	args = append(args, base.MinAccounts, filter.Bucket)
	minimumPlaceholder := strconv.Itoa(len(args) - 1)
	bucketPlaceholder := strconv.Itoa(len(args))
	rows, err := s.db.Query(ctx, `
WITH bucketed AS (
 SELECT date_trunc($`+bucketPlaceholder+`, occurred_at, 'UTC') AS bucket,
        application_id, device_fingerprint,
        COUNT(*) AS event_count,
        COUNT(*) FILTER (WHERE details_json @> '[{"rule_id":"`+sharedDeviceSignalRule+`"}]'::jsonb) AS signal_count,
        COUNT(DISTINCT jwt_verification->>'verified_principal_id') AS account_count
 FROM api_runtime_events
 WHERE `+strings.Join(where, " AND ")+`
 GROUP BY bucket, application_id, device_fingerprint
)
SELECT bucket, COUNT(*) AS group_count,
       COALESCE(SUM(signal_count), 0)::bigint AS signal_count,
       COALESCE(SUM(event_count), 0)::bigint AS event_count
FROM bucketed
WHERE account_count >= $`+minimumPlaceholder+`
GROUP BY bucket
ORDER BY bucket`, args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	items := []SharedDeviceTrendPoint{}
	for rows.Next() {
		var item SharedDeviceTrendPoint
		if err := rows.Scan(&item.Bucket, &item.GroupCount, &item.SignalCount, &item.EventCount); err != nil {
			return nil, err
		}
		items = append(items, item)
	}
	return items, rows.Err()
}

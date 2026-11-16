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

const sharedDeviceSignalRule = "behavior.shared_device_accounts"

type GroupControlRepository interface {
	ListSharedDevices(context.Context, SharedDeviceFilter) ([]SharedDeviceGroup, int64, error)
	ListSharedDeviceAccounts(context.Context, SharedDeviceFilter) ([]SharedDeviceAccount, int64, error)
	SharedDeviceTrend(context.Context, SharedDeviceTrendFilter) ([]SharedDeviceTrendPoint, error)
}

type SharedDeviceFilter struct {
	Start             time.Time
	End               time.Time
	ApplicationID     string
	DeviceFingerprint string
	MinAccounts       int
	Page              int
	PageSize          int
}

type SharedDeviceGroup struct {
	ApplicationID     uuid.UUID `json:"application_id"`
	ApplicationName   string    `json:"application_name"`
	DeviceFingerprint string    `json:"device_fingerprint"`
	DistinctAccounts  int64     `json:"distinct_accounts"`
	EventCount        int64     `json:"event_count"`
	SignalCount       int64     `json:"signal_count"`
	EndpointCount     int64     `json:"endpoint_count"`
	GatewayNodeCount  int64     `json:"gateway_node_count"`
	FirstSeenAt       time.Time `json:"first_seen_at"`
	LastSeenAt        time.Time `json:"last_seen_at"`
}

func (h *Handler) SetGroupControlRepository(repository GroupControlRepository) *Handler {
	h.groupControl = repository
	return h
}

func (h *Handler) ListSharedDevices(w http.ResponseWriter, r *http.Request) {
	filter, err := parseSharedDeviceFilter(r, time.Now().UTC())
	if err != nil {
		response.Error(w, r, http.StatusBadRequest, response.CodeInvalidArgument, err.Error())
		return
	}
	if h.groupControl == nil {
		response.Error(w, r, http.StatusServiceUnavailable, response.CodeServiceUnavailable, "群控观察数据读取未装配")
		return
	}
	items, total, err := h.groupControl.ListSharedDevices(r.Context(), filter)
	if err != nil {
		response.InternalError(w, r, err)
		return
	}
	response.JSON(w, r, http.StatusOK, map[string]any{
		"items": items, "total": total, "page": filter.Page, "page_size": filter.PageSize,
		"partial": true, "data_scope": "NOTABLE_SECURITY_EVENTS",
	})
}

func parseSharedDeviceFilter(r *http.Request, now time.Time) (SharedDeviceFilter, error) {
	filter := SharedDeviceFilter{Start: now.Add(-24 * time.Hour), End: now, MinAccounts: 3, Page: 1, PageSize: 20}
	query := r.URL.Query()
	var err error
	if value := strings.TrimSpace(query.Get("start")); value != "" {
		filter.Start, err = time.Parse(time.RFC3339, value)
		if err != nil {
			return filter, errors.New("start 须为 RFC3339 时间")
		}
		filter.Start = filter.Start.UTC()
	}
	if value := strings.TrimSpace(query.Get("end")); value != "" {
		filter.End, err = time.Parse(time.RFC3339, value)
		if err != nil {
			return filter, errors.New("end 须为 RFC3339 时间")
		}
		filter.End = filter.End.UTC()
	}
	if !filter.Start.Before(filter.End) {
		return filter, errors.New("start 必须早于 end")
	}
	if filter.End.Sub(filter.Start) > 31*24*time.Hour {
		return filter, errors.New("查询时间范围不得超过 31 天")
	}
	filter.ApplicationID = strings.TrimSpace(query.Get("application_id"))
	if filter.ApplicationID != "" {
		if _, err := uuid.Parse(filter.ApplicationID); err != nil {
			return filter, errors.New("无效的 application_id")
		}
	}
	filter.DeviceFingerprint = strings.TrimSpace(query.Get("device_fingerprint"))
	if filter.DeviceFingerprint != "" && !isSharedDeviceFingerprint(filter.DeviceFingerprint) {
		return filter, errors.New("device_fingerprint 须为 32 位小写十六进制指纹")
	}
	if filter.MinAccounts, err = sharedDeviceQueryInt(query.Get("min_accounts"), 3, 2, 1000); err != nil {
		return filter, errors.New("min_accounts 须为 2 到 1000 的整数")
	}
	if filter.Page, err = sharedDeviceQueryInt(query.Get("page"), 1, 1, 1000000); err != nil {
		return filter, errors.New("page 须为 1 到 1000000 的整数")
	}
	if filter.PageSize, err = sharedDeviceQueryInt(query.Get("page_size"), 20, 1, 100); err != nil {
		return filter, errors.New("page_size 须为 1 到 100 的整数")
	}
	return filter, nil
}

func sharedDeviceQueryInt(raw string, fallback, minimum, maximum int) (int, error) {
	if strings.TrimSpace(raw) == "" {
		return fallback, nil
	}
	value, err := strconv.Atoi(raw)
	if err != nil || value < minimum || value > maximum {
		return 0, errors.New("out of range")
	}
	return value, nil
}

func isSharedDeviceFingerprint(value string) bool {
	if len(value) != 32 {
		return false
	}
	for _, char := range value {
		if (char < '0' || char > '9') && (char < 'a' || char > 'f') {
			return false
		}
	}
	return true
}

func (s *Store) ListSharedDevices(ctx context.Context, filter SharedDeviceFilter) ([]SharedDeviceGroup, int64, error) {
	if filter.Start.IsZero() || filter.End.IsZero() || !filter.Start.Before(filter.End) || filter.End.Sub(filter.Start) > 31*24*time.Hour {
		return nil, 0, errors.New("invalid shared-device time range")
	}
	if filter.MinAccounts < 2 || filter.MinAccounts > 1000 || filter.Page < 1 || filter.PageSize < 1 || filter.PageSize > 100 {
		return nil, 0, errors.New("invalid shared-device pagination or threshold")
	}
	where := []string{
		"occurred_at >= $1", "occurred_at < $2", "application_id IS NOT NULL",
		"device_fingerprint IS NOT NULL", "device_fingerprint <> ''",
		"jwt_verification->>'status' = 'VERIFIED'",
		"jwt_verification->>'verified_principal_id' ~ '^[0-9a-f]{32}$'",
	}
	args := []any{filter.Start, filter.End}
	if filter.ApplicationID != "" {
		applicationID, err := uuid.Parse(filter.ApplicationID)
		if err != nil {
			return nil, 0, errors.New("invalid application_id")
		}
		args = append(args, applicationID)
		where = append(where, fmt.Sprintf("application_id = $%d", len(args)))
	}
	if filter.DeviceFingerprint != "" {
		if !isSharedDeviceFingerprint(filter.DeviceFingerprint) {
			return nil, 0, errors.New("invalid device_fingerprint")
		}
		args = append(args, filter.DeviceFingerprint)
		where = append(where, fmt.Sprintf("device_fingerprint = $%d", len(args)))
	}
	args = append(args, filter.MinAccounts, filter.PageSize, (filter.Page-1)*filter.PageSize)
	rows, err := s.db.Query(ctx, `
WITH aggregated AS (
 SELECT application_id, device_fingerprint,
  COUNT(DISTINCT jwt_verification->>'verified_principal_id') AS distinct_accounts,
  COUNT(*) AS event_count,
  COUNT(*) FILTER (WHERE details_json @> '[{"rule_id":"`+sharedDeviceSignalRule+`"}]'::jsonb) AS signal_count,
  COUNT(DISTINCT endpoint_key) AS endpoint_count,
  COUNT(DISTINCT gateway_node) FILTER (WHERE COALESCE(gateway_node, '') <> '') AS gateway_node_count,
  MIN(occurred_at) AS first_seen_at,
  MAX(occurred_at) AS last_seen_at
 FROM api_runtime_events
 WHERE `+strings.Join(where, " AND ")+`
 GROUP BY application_id, device_fingerprint
 HAVING COUNT(DISTINCT jwt_verification->>'verified_principal_id') >= $`+strconv.Itoa(len(args)-2)+`
)
SELECT g.application_id, COALESCE(a.name, ''), g.device_fingerprint,
       g.distinct_accounts, g.event_count, g.signal_count, g.endpoint_count,
       g.gateway_node_count, g.first_seen_at, g.last_seen_at, COUNT(*) OVER() AS total
FROM aggregated g
LEFT JOIN applications a ON a.id = g.application_id
ORDER BY g.distinct_accounts DESC, g.last_seen_at DESC, g.application_id, g.device_fingerprint
LIMIT $`+strconv.Itoa(len(args)-1)+` OFFSET $`+strconv.Itoa(len(args)), args...)
	if err != nil {
		return nil, 0, err
	}
	defer rows.Close()
	items := []SharedDeviceGroup{}
	var total int64
	for rows.Next() {
		var item SharedDeviceGroup
		if err := rows.Scan(&item.ApplicationID, &item.ApplicationName, &item.DeviceFingerprint,
			&item.DistinctAccounts, &item.EventCount, &item.SignalCount, &item.EndpointCount,
			&item.GatewayNodeCount, &item.FirstSeenAt, &item.LastSeenAt, &total); err != nil {
			return nil, 0, err
		}
		items = append(items, item)
	}
	return items, total, rows.Err()
}

package apisecurity

import (
	"context"
	"errors"
	"net/http"
	"time"

	"github.com/google/uuid"
	"github.com/jiuzhang-waf/server/internal/response"
)

type SharedDeviceAccount struct {
	PrincipalRef  string    `json:"principal_ref"`
	EventCount    int64     `json:"event_count"`
	SignalCount   int64     `json:"signal_count"`
	EndpointCount int64     `json:"endpoint_count"`
	FirstSeenAt   time.Time `json:"first_seen_at"`
	LastSeenAt    time.Time `json:"last_seen_at"`
}

func (h *Handler) ListSharedDeviceAccounts(w http.ResponseWriter, r *http.Request) {
	filter, err := parseSharedDeviceFilter(r, time.Now().UTC())
	if err != nil {
		response.Error(w, r, http.StatusBadRequest, response.CodeInvalidArgument, err.Error())
		return
	}
	if filter.ApplicationID == "" || filter.DeviceFingerprint == "" {
		response.Error(w, r, http.StatusBadRequest, response.CodeInvalidArgument, "application_id 与 device_fingerprint 均为必填")
		return
	}
	if h.groupControl == nil {
		response.Error(w, r, http.StatusServiceUnavailable, response.CodeServiceUnavailable, "群控观察数据读取未装配")
		return
	}
	items, total, err := h.groupControl.ListSharedDeviceAccounts(r.Context(), filter)
	if err != nil {
		response.InternalError(w, r, err)
		return
	}
	response.JSON(w, r, http.StatusOK, map[string]any{
		"items": items, "total": total, "page": filter.Page, "page_size": filter.PageSize,
		"partial": true, "data_scope": "NOTABLE_SECURITY_EVENTS",
	})
}

func (s *Store) ListSharedDeviceAccounts(ctx context.Context, filter SharedDeviceFilter) ([]SharedDeviceAccount, int64, error) {
	if filter.Start.IsZero() || filter.End.IsZero() || !filter.Start.Before(filter.End) || filter.End.Sub(filter.Start) > 31*24*time.Hour {
		return nil, 0, errors.New("invalid shared-device time range")
	}
	if filter.Page < 1 || filter.Page > 1000000 || filter.PageSize < 1 || filter.PageSize > 100 {
		return nil, 0, errors.New("invalid shared-device pagination")
	}
	applicationID, err := uuid.Parse(filter.ApplicationID)
	if err != nil {
		return nil, 0, errors.New("application_id is required and must be a UUID")
	}
	if !isSharedDeviceFingerprint(filter.DeviceFingerprint) {
		return nil, 0, errors.New("device_fingerprint is required and must be a fingerprint")
	}
	rows, err := s.db.Query(ctx, `
SELECT jwt_verification->>'verified_principal_id' AS principal_ref,
       COUNT(*) AS event_count,
       COUNT(*) FILTER (WHERE details_json @> '[{"rule_id":"`+sharedDeviceSignalRule+`"}]'::jsonb) AS signal_count,
       COUNT(DISTINCT endpoint_key) AS endpoint_count,
       MIN(occurred_at) AS first_seen_at,
       MAX(occurred_at) AS last_seen_at,
       COUNT(*) OVER() AS total
FROM api_runtime_events
WHERE occurred_at >= $1 AND occurred_at < $2
  AND application_id = $3
  AND device_fingerprint = $4
  AND jwt_verification->>'status' = 'VERIFIED'
  AND jwt_verification->>'verified_principal_id' ~ '^[0-9a-f]{32}$'
GROUP BY jwt_verification->>'verified_principal_id'
ORDER BY event_count DESC, principal_ref
LIMIT $5 OFFSET $6`,
		filter.Start, filter.End, applicationID, filter.DeviceFingerprint,
		filter.PageSize, (filter.Page-1)*filter.PageSize)
	if err != nil {
		return nil, 0, err
	}
	defer rows.Close()
	items := []SharedDeviceAccount{}
	var total int64
	for rows.Next() {
		var item SharedDeviceAccount
		if err := rows.Scan(&item.PrincipalRef, &item.EventCount, &item.SignalCount,
			&item.EndpointCount, &item.FirstSeenAt, &item.LastSeenAt, &total); err != nil {
			return nil, 0, err
		}
		items = append(items, item)
	}
	return items, total, rows.Err()
}

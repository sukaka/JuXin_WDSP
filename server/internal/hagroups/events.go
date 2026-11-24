// 主备高可用持久化历史事件（ha_events）模型与仓储实现。
package hagroups

import (
	"context"
	"encoding/json"
	"fmt"
	"sort"
	"strings"
	"time"

	"github.com/google/uuid"
)

// 事件类型常量（ha_events.event_type）。
const (
	EventTypeFailback       = "FAILBACK"
	EventTypeSyncFailed     = "SYNC_FAILED"
	EventTypeSplitBrain     = "SPLIT_BRAIN"
	EventTypeVIPTransition  = "VIP_TRANSITION"
	EventTypeLinkPairChange = "LINK_PAIR_CHANGE"
)

const (
	defaultEventPageSize = 20
	maxEventPageSize     = 100
)

// HaEvent 主备高可用持久化事件（ha_events）。
type HaEvent struct {
	ID         int64          `json:"id"`
	GroupID    string         `json:"group_id,omitempty"`
	GroupName  string         `json:"group_name"`
	NodeName   string         `json:"node_name"`
	EventType  string         `json:"event_type"`
	Detail     map[string]any `json:"detail"`
	OccurredAt time.Time      `json:"occurred_at"`
}

// EventFilter ha_events 查询过滤条件。
type EventFilter struct {
	GroupID   string
	NodeName  string
	EventType string
	Page      int
	PageSize  int
}

// EventRepository 事件持久化子接口（*Store 与 *MemStore 均实现，供 hastatus/nodesync 复用）。
type EventRepository interface {
	RecordEvent(ctx context.Context, ev HaEvent) error
	ListEvents(ctx context.Context, filter EventFilter) ([]HaEvent, int64, error)
}

func normalizeEventPagination(page, pageSize int) (int, int) {
	if page < 1 {
		page = 1
	}
	if pageSize <= 0 {
		pageSize = defaultEventPageSize
	} else if pageSize > maxEventPageSize {
		pageSize = maxEventPageSize
	}
	return page, pageSize
}

func cloneDetailMap(src map[string]any) map[string]any {
	if len(src) == 0 {
		return map[string]any{}
	}
	raw, err := json.Marshal(src)
	if err != nil {
		out := make(map[string]any, len(src))
		for k, v := range src {
			out[k] = v
		}
		return out
	}
	out := map[string]any{}
	if err := json.Unmarshal(raw, &out); err != nil {
		return map[string]any{}
	}
	return out
}

// ---------- PostgreSQL ----------

// RecordEvent 写入一条 HA 持久化事件。
func (s *Store) RecordEvent(ctx context.Context, ev HaEvent) error {
	ev.EventType = strings.TrimSpace(ev.EventType)
	if ev.EventType == "" {
		return fmt.Errorf("ha_events.event_type 不能为空")
	}
	if ev.OccurredAt.IsZero() {
		ev.OccurredAt = time.Now().UTC()
	}
	var groupID any
	if gid := strings.TrimSpace(ev.GroupID); gid != "" {
		uid, err := uuid.Parse(gid)
		if err != nil {
			return fmt.Errorf("ha_events.group_id 非法 UUID: %w", err)
		}
		groupID = uid
	}
	detail := ev.Detail
	if detail == nil {
		detail = map[string]any{}
	}
	detailJSON, err := json.Marshal(detail)
	if err != nil {
		return fmt.Errorf("序列化 ha_events.detail: %w", err)
	}
	_, err = s.db.Exec(ctx, `
INSERT INTO ha_events (group_id, group_name, node_name, event_type, detail, occurred_at)
VALUES ($1, $2, $3, $4, $5, $6)`,
		groupID, strings.TrimSpace(ev.GroupName), strings.TrimSpace(ev.NodeName), ev.EventType, detailJSON, ev.OccurredAt.UTC())
	return err
}

// ListEvents 分页查询 HA 持久化事件（occurred_at 降序、id 降序）。
func (s *Store) ListEvents(ctx context.Context, filter EventFilter) ([]HaEvent, int64, error) {
	page, pageSize := normalizeEventPagination(filter.Page, filter.PageSize)

	conds := []string{}
	args := []any{}
	if gid := strings.TrimSpace(filter.GroupID); gid != "" {
		uid, err := uuid.Parse(gid)
		if err != nil {
			return nil, 0, fmt.Errorf("group_id 非法 UUID: %w", err)
		}
		args = append(args, uid)
		conds = append(conds, fmt.Sprintf("group_id = $%d", len(args)))
	}
	if node := strings.TrimSpace(filter.NodeName); node != "" {
		args = append(args, node)
		conds = append(conds, fmt.Sprintf("node_name = $%d", len(args)))
	}
	if evType := strings.TrimSpace(filter.EventType); evType != "" {
		args = append(args, evType)
		conds = append(conds, fmt.Sprintf("event_type = $%d", len(args)))
	}

	where := ""
	if len(conds) > 0 {
		where = " WHERE " + strings.Join(conds, " AND ")
	}

	var total int64
	if err := s.db.QueryRow(ctx, `SELECT COUNT(*) FROM ha_events`+where, args...).Scan(&total); err != nil {
		return nil, 0, err
	}

	limitArg := len(args) + 1
	offsetArg := len(args) + 2
	queryArgs := append(append([]any(nil), args...), pageSize, (page-1)*pageSize)
	rows, err := s.db.Query(ctx, fmt.Sprintf(`
SELECT id, COALESCE(group_id::text, ''), group_name, node_name, event_type, detail, occurred_at
FROM ha_events%s
ORDER BY occurred_at DESC, id DESC
LIMIT $%d OFFSET $%d`, where, limitArg, offsetArg), queryArgs...)
	if err != nil {
		return nil, 0, err
	}
	defer rows.Close()

	items := []HaEvent{}
	for rows.Next() {
		var ev HaEvent
		var detailRaw []byte
		if err := rows.Scan(&ev.ID, &ev.GroupID, &ev.GroupName, &ev.NodeName, &ev.EventType, &detailRaw, &ev.OccurredAt); err != nil {
			return nil, 0, err
		}
		ev.OccurredAt = ev.OccurredAt.UTC()
		ev.Detail = map[string]any{}
		if len(detailRaw) > 0 {
			if err := json.Unmarshal(detailRaw, &ev.Detail); err != nil {
				return nil, 0, fmt.Errorf("解析 ha_events.detail: %w", err)
			}
			if ev.Detail == nil {
				ev.Detail = map[string]any{}
			}
		}
		items = append(items, ev)
	}
	if err := rows.Err(); err != nil {
		return nil, 0, err
	}
	return items, total, nil
}

// ---------- 内存实现（测试） ----------

// RecordEvent 实现 EventRepository。
func (m *MemStore) RecordEvent(_ context.Context, ev HaEvent) error {
	ev.EventType = strings.TrimSpace(ev.EventType)
	if ev.EventType == "" {
		return fmt.Errorf("ha_events.event_type 不能为空")
	}
	if ev.OccurredAt.IsZero() {
		ev.OccurredAt = time.Now().UTC()
	} else {
		ev.OccurredAt = ev.OccurredAt.UTC()
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	m.nextEventID++
	ev.ID = m.nextEventID
	ev.GroupID = strings.TrimSpace(ev.GroupID)
	ev.GroupName = strings.TrimSpace(ev.GroupName)
	ev.NodeName = strings.TrimSpace(ev.NodeName)
	ev.Detail = cloneDetailMap(ev.Detail)
	m.events = append(m.events, ev)
	return nil
}

// ListEvents 实现 EventRepository。
func (m *MemStore) ListEvents(_ context.Context, filter EventFilter) ([]HaEvent, int64, error) {
	page, pageSize := normalizeEventPagination(filter.Page, filter.PageSize)
	gid := strings.TrimSpace(filter.GroupID)
	node := strings.TrimSpace(filter.NodeName)
	evType := strings.TrimSpace(filter.EventType)

	m.mu.Lock()
	defer m.mu.Unlock()

	filtered := make([]HaEvent, 0, len(m.events))
	for _, ev := range m.events {
		if gid != "" && ev.GroupID != gid {
			continue
		}
		if node != "" && ev.NodeName != node {
			continue
		}
		if evType != "" && ev.EventType != evType {
			continue
		}
		cp := ev
		cp.Detail = cloneDetailMap(ev.Detail)
		filtered = append(filtered, cp)
	}
	sort.Slice(filtered, func(i, j int) bool {
		if filtered[i].OccurredAt.Equal(filtered[j].OccurredAt) {
			return filtered[i].ID > filtered[j].ID
		}
		return filtered[i].OccurredAt.After(filtered[j].OccurredAt)
	})

	total := int64(len(filtered))
	start := (page - 1) * pageSize
	if start >= len(filtered) {
		return []HaEvent{}, total, nil
	}
	end := start + pageSize
	if end > len(filtered) {
		end = len(filtered)
	}
	out := make([]HaEvent, end-start)
	copy(out, filtered[start:end])
	return out, total, nil
}

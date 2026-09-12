package securityevents

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/netip"
	"strings"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
)

// Store 是安全事件仓储。
type Store struct {
	db *pgxpool.Pool
}

// NewStore 创建事件仓储。
func NewStore(db *pgxpool.Pool) *Store {
	return &Store{db: db}
}

// InsertEvent 插入安全事件与匹配记录（去重：同 request_id + 时间窗口）。
// inserted 为 false 表示命中去重（事件已存在，未重复插入）。
// P0-04：final_decision 随插入落列；去重命中时若本次解析携带 final_decision，
// 按「已确认拦截优先」条件补全——仅当现有行 final_decision IS NULL，或现有行为
// PENDING_CORRELATION 且未被确认执法（security_action 不在 BLOCK/TEMP_BLOCK/
// RATE_LIMIT/MASK_RESPONSE）且 incoming completion_status ∈ (COMPLETED, ABORTED)
// 时更新（契约 S4_DESIGN_BASELINE §2：先到先得 + 终止动作优先）。
func (s *Store) InsertEvent(ctx context.Context, evt *NormalizedEvent) (uuid.UUID, bool, error) {
	tx, err := s.db.BeginTx(ctx, pgx.TxOptions{})
	if err != nil {
		return uuid.Nil, false, err
	}
	defer func() { _ = tx.Rollback(ctx) }()

	var fdJSON any
	if evt.FinalDecision != nil {
		if b, merr := json.Marshal(evt.FinalDecision); merr == nil {
			fdJSON = string(b)
		}
	}

	// 去重：相同 request_id + occurred_at（同一事务不重复入库）
	var existingID uuid.UUID
	err = tx.QueryRow(ctx,
		`SELECT id FROM security_events WHERE request_id = $1 AND occurred_at = $2 LIMIT 1`,
		evt.RequestID, evt.OccurredAt).Scan(&existingID)
	if err == nil {
		// 已存在：去重；final_decision 按「已确认拦截优先」条件补全（P0-04）
		if fdJSON != nil {
			if _, uerr := tx.Exec(ctx, `
UPDATE security_events SET final_decision = $3::jsonb
WHERE request_id = $1 AND occurred_at = $2
  AND (final_decision IS NULL
       OR (final_decision->>'completion_status' = 'PENDING_CORRELATION'
           AND COALESCE(final_decision->>'security_action', 'NONE') NOT IN ('BLOCK','TEMP_BLOCK','RATE_LIMIT','MASK_RESPONSE','CHALLENGE')
           AND $4 IN ('COMPLETED','ABORTED')))`,
				evt.RequestID, evt.OccurredAt, fdJSON, evt.FinalDecision.CompletionStatus); uerr != nil {
				return uuid.Nil, false, uerr
			}
		}
		_ = tx.Commit(ctx)
		return existingID, false, nil
	}
	if !errors.Is(err, pgx.ErrNoRows) {
		return uuid.Nil, false, err
	}

	var eventID uuid.UUID
	err = tx.QueryRow(ctx, `
INSERT INTO security_events (request_id, occurred_at, application_id, application_name_snapshot, domain, gateway_node_id, client_ip, connection_ip,
  client_port, request_method, request_uri, request_path, query_summary, http_version, content_type,
  user_agent_summary, referer_summary, event_source, attack_type, severity, anomaly_score, action,
  response_status, rule_match_count, disposition_status, raw_log_reference,
  request_headers, request_body, request_body_truncated, response_headers, response_body, response_body_truncated, final_decision)
VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,$14,$15,$16,$17,$18,$19,$20,$21,$22,$23,$24,$25,$26,$27,$28,$29,$30,$31,$32,$33)
RETURNING id`,
		evt.RequestID, evt.OccurredAt, evt.ApplicationID, evt.ApplicationName, evt.Host, evt.GatewayNode, nullableIP(evt.ClientIP), nullableIP(evt.ClientIP),
		evt.ClientPort, evt.Method, evt.URI, evt.Path, evt.QuerySummary, evt.HTTPVersion, evt.ContentType,
		evt.UserAgent, evt.Referer, "coraza", evt.AttackType, evt.Severity, evt.AnomalyScore, evt.Action,
		evt.ResponseStatus, len(evt.Matches), "UNPROCESSED", evt.RawRef,
		nonNilHeaders(evt.RequestHeaders), evt.RequestBody, evt.RequestBodyTruncated,
		nonNilHeaders(evt.ResponseHeaders), evt.ResponseBody, evt.ResponseBodyTruncated, fdJSON,
	).Scan(&eventID)
	if err != nil {
		return uuid.Nil, false, err
	}

	// 插入匹配记录
	for _, m := range evt.Matches {
		_, err = tx.Exec(ctx, `
INSERT INTO security_event_matches (event_id, event_occurred_at, rule_id, rule_name, rule_source, rule_version,
  severity, message, matched_variable, matched_data_masked, tags, phase, anomaly_score)
VALUES ($1,$2,$3,$4,COALESCE(NULLIF($5, ''), 'OWASP_CRS'),$6,$7,$8,$9,$10,$11,$12,$13)`,
			eventID, evt.OccurredAt, m.RuleID, m.RuleName, m.RuleSource, m.RuleVersion, m.Severity, m.Message,
			m.MatchedVariable, m.MatchedData, mustJSONStr(m.Tags), m.Phase, evt.AnomalyScore)
		if err != nil {
			return uuid.Nil, false, err
		}
	}
	if err := tx.Commit(ctx); err != nil {
		return uuid.Nil, false, err
	}
	return eventID, true, nil
}

// InsertFailure 记录解析失败到错误队列。
func (s *Store) InsertFailure(ctx context.Context, collectorID, rawLine, reason string) error {
	if len(rawLine) > 4096 {
		rawLine = rawLine[:4096]
	}
	_, err := s.db.Exec(ctx,
		`INSERT INTO event_parse_failures (collector_id, raw_line, error_reason) VALUES ($1, $2, $3)`,
		collectorID, rawLine, reason)
	return err
}

// Event 是安全事件。
type Event struct {
	ID                uuid.UUID           `json:"id"`
	RequestID         string              `json:"request_id"`
	OccurredAt        time.Time           `json:"occurred_at"`
	ApplicationID     *uuid.UUID          `json:"application_id"`
	AppName           string              `json:"application_name_snapshot"`
	Domain            string              `json:"domain"`
	GatewayNode       string              `json:"gateway_node_id"`
	ClientIP          string              `json:"client_ip"`
	ClientPort        int                 `json:"client_port"`
	Method            string              `json:"request_method"`
	URI               string              `json:"request_uri"`
	Path              string              `json:"request_path"`
	QuerySummary      string              `json:"query_summary"`
	HTTPVersion       string              `json:"http_version"`
	ContentType       string              `json:"content_type"`
	UserAgent         string              `json:"user_agent_summary"`
	Referer           string              `json:"referer_summary"`
	AttackType        string              `json:"attack_type"`
	Severity          string              `json:"severity"`
	AnomalyScore      int                 `json:"anomaly_score"`
	Action            string              `json:"action"`
	ResponseStatus    int                 `json:"response_status"`
	RuleMatchCount    int                 `json:"rule_match_count"`
	DispositionStatus string              `json:"disposition_status"`
	DispositionResult string              `json:"disposition_result"`
	// FinalDecision 最终处置事实（WDSP P0-04；迁移 000132 列，nil=旧事件无此证据，
	// 详情 API 投影——列表不投影以控制载荷）
	FinalDecision *FinalDecision `json:"final_decision,omitempty"`
	RawRef            string              `json:"raw_log_reference"`
	RequestHeaders    map[string][]string `json:"request_headers"`
	RequestBody       string              `json:"request_body"`
	RequestBodyTrunc  bool                `json:"request_body_truncated"`
	ResponseHeaders   map[string][]string `json:"response_headers"`
	ResponseBody      string              `json:"response_body"`
	ResponseBodyTrunc bool                `json:"response_body_truncated"`
}

// ListFilter 是事件查询筛选。
type ListFilter struct {
	StartTime         *time.Time
	EndTime           *time.Time
	ApplicationID     *uuid.UUID
	Domain            string
	ClientIP          string
	URI               string
	Method            string
	AttackType        string
	Severity          string
	Action            string
	RuleID            *int
	DispositionStatus string
	RequestID         string
	GatewayNode       string
	Page              int
	PageSize          int
}

// List 分页查询事件。
func (s *Store) List(ctx context.Context, f ListFilter) ([]Event, int64, error) {
	if f.Page <= 0 {
		f.Page = 1
	}
	if f.PageSize <= 0 || f.PageSize > 100 {
		f.PageSize = 20
	}
	where := "1=1"
	args := []interface{}{}
	argIdx := 1
	add := func(cond string, v interface{}) {
		where += fmt.Sprintf(" AND "+cond, argIdx)
		args = append(args, v)
		argIdx++
	}
	if f.StartTime != nil {
		add("occurred_at >= $%d", *f.StartTime)
	}
	if f.EndTime != nil {
		add("occurred_at <= $%d", *f.EndTime)
	}
	if f.ApplicationID != nil {
		add("application_id = $%d", *f.ApplicationID)
	}
	if f.Domain != "" {
		add("domain ILIKE $%d", "%"+f.Domain+"%")
	}
	if f.ClientIP != "" {
		add("client_ip = $%d", f.ClientIP)
	}
	if f.URI != "" {
		add("request_uri ILIKE $%d", "%"+f.URI+"%")
	}
	if f.Method != "" {
		add("request_method = $%d", f.Method)
	}
	if f.AttackType != "" {
		add("attack_type = $%d", f.AttackType)
	}
	if f.Severity != "" {
		add("severity = $%d", f.Severity)
	}
	if f.Action != "" {
		add("action = $%d", f.Action)
	}
	if f.DispositionStatus != "" {
		add("disposition_status = $%d", f.DispositionStatus)
	}
	if f.RequestID != "" {
		add("request_id = $%d", f.RequestID)
	}
	if f.GatewayNode != "" {
		add("gateway_node_id = $%d", f.GatewayNode)
	}
	if f.RuleID != nil {
		where += fmt.Sprintf(" AND id IN (SELECT event_id FROM security_event_matches WHERE rule_id = $%d)", argIdx)
		args = append(args, *f.RuleID)
		argIdx++
	}

	var total int64
	if err := s.db.QueryRow(ctx, `SELECT count(*) FROM security_events WHERE `+where, args...).Scan(&total); err != nil {
		return nil, 0, err
	}
	query := `
SELECT id, request_id, occurred_at, application_id, application_name_snapshot, domain, gateway_node_id,
  client_ip, connection_ip, COALESCE(client_port, 0), request_method, request_uri, request_path, query_summary,
  http_version, content_type, user_agent_summary, referer_summary, attack_type, severity, anomaly_score,
  action, COALESCE(response_status, 0), rule_match_count, disposition_status, disposition_result, raw_log_reference
FROM security_events WHERE ` + where + fmt.Sprintf(" ORDER BY occurred_at DESC LIMIT $%d OFFSET $%d", argIdx, argIdx+1)
	args = append(args, f.PageSize, (f.Page-1)*f.PageSize)
	rows, err := s.db.Query(ctx, query, args...)
	if err != nil {
		return nil, 0, err
	}
	defer rows.Close()
	var out []Event
	for rows.Next() {
		var e Event
		var appID *uuid.UUID
		var cip, connIP *netip.Addr
		if err := rows.Scan(&e.ID, &e.RequestID, &e.OccurredAt, &appID, &e.AppName, &e.Domain, &e.GatewayNode,
			&cip, &connIP, &e.ClientPort, &e.Method, &e.URI, &e.Path, &e.QuerySummary, &e.HTTPVersion,
			&e.ContentType, &e.UserAgent, &e.Referer, &e.AttackType, &e.Severity, &e.AnomalyScore,
			&e.Action, &e.ResponseStatus, &e.RuleMatchCount, &e.DispositionStatus, &e.DispositionResult, &e.RawRef); err != nil {
			return nil, 0, err
		}
		e.ApplicationID = appID
		if cip != nil {
			e.ClientIP = cip.String()
		}
		out = append(out, e)
	}
	return out, total, rows.Err()
}

// GetByID 查询事件详情（含请求/响应头体留痕）。
func (s *Store) GetByID(ctx context.Context, id uuid.UUID) (*Event, []MatchInfo, error) {
	row := s.db.QueryRow(ctx, `
SELECT id, request_id, occurred_at, application_id, application_name_snapshot, domain, gateway_node_id,
  client_ip, connection_ip, COALESCE(client_port, 0), request_method, request_uri, request_path, query_summary,
  http_version, content_type, user_agent_summary, referer_summary, attack_type, severity, anomaly_score,
  action, COALESCE(response_status, 0), rule_match_count, disposition_status, disposition_result, raw_log_reference,
  request_headers, request_body, request_body_truncated, response_headers, response_body, response_body_truncated,
  final_decision
FROM security_events WHERE id = $1`, id)
	var e Event
	var appID *uuid.UUID
	var cip, connIP *netip.Addr
	var fdRaw []byte
	err := row.Scan(&e.ID, &e.RequestID, &e.OccurredAt, &appID, &e.AppName, &e.Domain, &e.GatewayNode,
		&cip, &connIP, &e.ClientPort, &e.Method, &e.URI, &e.Path, &e.QuerySummary, &e.HTTPVersion,
		&e.ContentType, &e.UserAgent, &e.Referer, &e.AttackType, &e.Severity, &e.AnomalyScore,
		&e.Action, &e.ResponseStatus, &e.RuleMatchCount, &e.DispositionStatus, &e.DispositionResult, &e.RawRef,
		&e.RequestHeaders, &e.RequestBody, &e.RequestBodyTrunc, &e.ResponseHeaders, &e.ResponseBody, &e.ResponseBodyTrunc,
		&fdRaw)
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return nil, nil, fmt.Errorf("event not found")
		}
		return nil, nil, err
	}
	e.ApplicationID = appID
	if cip != nil {
		e.ClientIP = cip.String()
	}
	if len(fdRaw) > 0 {
		var fd FinalDecision
		if uerr := json.Unmarshal(fdRaw, &fd); uerr != nil {
			return nil, nil, fmt.Errorf("decode final_decision: %w", uerr)
		}
		e.FinalDecision = &fd
	}

	// 匹配记录
	matchRows, err := s.db.Query(ctx, `
SELECT rule_id, rule_name, rule_source, rule_version, severity, message, matched_variable, matched_data_masked, tags, phase
FROM security_event_matches WHERE event_id = $1 ORDER BY id`, id)
	if err != nil {
		return nil, nil, err
	}
	defer matchRows.Close()
	var matches []MatchInfo
	for matchRows.Next() {
		var m MatchInfo
		var tags []byte
		if err := matchRows.Scan(&m.RuleID, &m.RuleName, &m.RuleSource, &m.RuleVersion, &m.Severity, &m.Message,
			&m.MatchedVariable, &m.MatchedData, &tags, &m.Phase); err != nil {
			return nil, nil, err
		}
		m.Tags = parseTags(tags)
		matches = append(matches, m)
	}
	return &e, matches, nil
}

// UpdateDisposition 更新事件处置状态。
func (s *Store) UpdateDisposition(ctx context.Context, id uuid.UUID, status, result string, userID uuid.UUID) error {
	res, err := s.db.Exec(ctx, `
UPDATE security_events SET disposition_status=$1, disposition_result=$2, disposition_user_id=$3, disposition_at=now()
WHERE id=$4`, status, result, userID, id)
	if err != nil {
		return err
	}
	if res.RowsAffected() == 0 {
		return fmt.Errorf("event not found")
	}
	return nil
}

// UpdateDispositionIfCurrent 原子更新处置状态，防止并发处置覆盖较新的结论。
func (s *Store) UpdateDispositionIfCurrent(ctx context.Context, id uuid.UUID, current, status, result string, userID uuid.UUID) (bool, error) {
	res, err := s.db.Exec(ctx, `
UPDATE security_events SET disposition_status=$1, disposition_result=$2, disposition_user_id=$3, disposition_at=now()
WHERE id=$4 AND COALESCE(disposition_status, 'UNPROCESSED')=$5`, status, result, userID, id, current)
	if err != nil {
		return false, err
	}
	return res.RowsAffected() > 0, nil
}

// AddNote 添加事件备注。
func (s *Store) AddNote(ctx context.Context, eventID, userID uuid.UUID, username, note string) error {
	_, err := s.db.Exec(ctx,
		`INSERT INTO security_event_notes (event_id, user_id, username, note) VALUES ($1, $2, $3, $4)`,
		eventID, userID, username, note)
	return err
}

// ListNotes 查询事件备注。
func (s *Store) ListNotes(ctx context.Context, eventID uuid.UUID) ([]map[string]interface{}, error) {
	rows, err := s.db.Query(ctx,
		`SELECT username, note, created_at FROM security_event_notes WHERE event_id = $1 ORDER BY created_at DESC`, eventID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []map[string]interface{}
	for rows.Next() {
		var username, note string
		var createdAt time.Time
		if err := rows.Scan(&username, &note, &createdAt); err != nil {
			return nil, err
		}
		out = append(out, map[string]interface{}{"username": username, "note": note, "created_at": createdAt})
	}
	return out, rows.Err()
}

// AddAction 记录处置动作。
func (s *Store) AddAction(ctx context.Context, eventID uuid.UUID, actionType string, operatorID uuid.UUID, operatorName, detail, refID string) error {
	_, err := s.db.Exec(ctx,
		`INSERT INTO security_event_actions (event_id, action_type, operator_id, operator_name, detail, related_ref_id) VALUES ($1, $2, $3, $4, $5, $6)`,
		eventID, actionType, operatorID, operatorName, detail, refID)
	return err
}

// ListActions 查询事件处置记录。
func (s *Store) ListActions(ctx context.Context, eventID uuid.UUID) ([]map[string]interface{}, error) {
	rows, err := s.db.Query(ctx,
		`SELECT action_type, operator_name, detail, related_ref_id, created_at FROM security_event_actions WHERE event_id = $1 ORDER BY created_at DESC`, eventID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []map[string]interface{}
	for rows.Next() {
		var at, on, detail, refID string
		var createdAt time.Time
		if err := rows.Scan(&at, &on, &detail, &refID, &createdAt); err != nil {
			return nil, err
		}
		out = append(out, map[string]interface{}{
			"action_type": at, "operator_name": on, "detail": detail, "related_ref_id": refID, "created_at": createdAt,
		})
	}
	return out, rows.Err()
}

// RelatedEvents 查询相关事件。
func (s *Store) RelatedEvents(ctx context.Context, e *Event, limit int) ([]Event, error) {
	if limit <= 0 {
		limit = 10
	}
	rows, err := s.db.Query(ctx, `
SELECT id, request_id, occurred_at, application_id, application_name_snapshot, domain, gateway_node_id,
  client_ip, connection_ip, COALESCE(client_port, 0), request_method, request_uri, request_path, query_summary,
  http_version, content_type, user_agent_summary, referer_summary, attack_type, severity, anomaly_score,
  action, COALESCE(response_status, 0), rule_match_count, disposition_status, disposition_result, raw_log_reference
FROM security_events
WHERE id <> $1 AND (client_ip = $2 OR attack_type = $3 OR domain = $4)
ORDER BY occurred_at DESC LIMIT $5`,
		e.ID, nullableIP(e.ClientIP), e.AttackType, e.Domain, limit*3)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []Event
	for rows.Next() {
		var ev Event
		var appID *uuid.UUID
		var cip, connIP *netip.Addr
		if err := rows.Scan(&ev.ID, &ev.RequestID, &ev.OccurredAt, &appID, &ev.AppName, &ev.Domain, &ev.GatewayNode,
			&cip, &connIP, &ev.ClientPort, &ev.Method, &ev.URI, &ev.Path, &ev.QuerySummary, &ev.HTTPVersion,
			&ev.ContentType, &ev.UserAgent, &ev.Referer, &ev.AttackType, &ev.Severity, &ev.AnomalyScore,
			&ev.Action, &ev.ResponseStatus, &ev.RuleMatchCount, &ev.DispositionStatus, &ev.DispositionResult, &ev.RawRef); err != nil {
			return nil, err
		}
		ev.ApplicationID = appID
		if cip != nil {
			ev.ClientIP = cip.String()
		}
		out = append(out, ev)
		if len(out) >= limit {
			break
		}
	}
	return out, rows.Err()
}

func nullableIP(ip string) interface{} {
	if ip == "" {
		return nil
	}
	return ip
}

// nonNilHeaders 保证头部 map 非 nil（jsonb 列 NOT NULL，nil 会编码为 SQL NULL）。
func nonNilHeaders(h map[string][]string) map[string][]string {
	if h == nil {
		return map[string][]string{}
	}
	return h
}

func mustJSONStr(v []string) string {
	if len(v) == 0 {
		return "[]"
	}
	var b strings.Builder
	b.WriteString("[")
	for i, s := range v {
		if i > 0 {
			b.WriteString(",")
		}
		b.WriteString(`"` + strings.ReplaceAll(s, `"`, `\"`) + `"`)
	}
	b.WriteString("]")
	return b.String()
}

func parseTags(data []byte) []string {
	if len(data) == 0 || string(data) == "[]" || string(data) == "null" {
		return nil
	}
	var out []string
	s := strings.Trim(string(data), "[]")
	for _, part := range strings.Split(s, ",") {
		part = strings.Trim(part, ` "`)
		if part != "" {
			out = append(out, part)
		}
	}
	return out
}

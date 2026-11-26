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
	"github.com/jiuzhang-waf/server/internal/apigeo"
	"github.com/jiuzhang-waf/server/internal/wafrules"
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

	// connection_ip 严格取 TCP 对端（guard 内部头上报）；旧版网关未上报时回退
	// 既有口径（与 client_ip 同值）
	connIP := evt.ConnectionIP
	if connIP == "" {
		connIP = evt.ClientIP
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
		evt.RequestID, evt.OccurredAt, evt.ApplicationID, evt.ApplicationName, evt.Host, evt.GatewayNode, nullableIP(evt.ClientIP), nullableIP(connIP),
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
	ID                uuid.UUID  `json:"id"`
	RequestID         string     `json:"request_id"`
	OccurredAt        time.Time  `json:"occurred_at"`
	ApplicationID     *uuid.UUID `json:"application_id"`
	AppName           string     `json:"application_name_snapshot"`
	Domain            string     `json:"domain"`
	GatewayNode       string          `json:"gateway_node_id"`
	ClientIP          string          `json:"client_ip"`
	ClientIPGeo       *apigeo.GeoInfo `json:"client_ip_geo,omitempty"`
	ClientPort        int             `json:"client_port"`
	Method            string     `json:"request_method"`
	URI               string     `json:"request_uri"`
	Path              string     `json:"request_path"`
	QuerySummary      string     `json:"query_summary"`
	HTTPVersion       string     `json:"http_version"`
	ContentType       string     `json:"content_type"`
	UserAgent         string     `json:"user_agent_summary"`
	Referer           string     `json:"referer_summary"`
	AttackType        string     `json:"attack_type"`
	Severity          string     `json:"severity"`
	AnomalyScore      int        `json:"anomaly_score"`
	Action            string     `json:"action"`
	ResponseStatus    int        `json:"response_status"`
	RuleMatchCount    int        `json:"rule_match_count"`
	DispositionStatus string     `json:"disposition_status"`
	DispositionResult string     `json:"disposition_result"`
	// FinalDecision 最终处置事实（WDSP P0-04；迁移 000132 列，nil=旧事件无此证据，
	// 详情 API 投影——列表不投影以控制载荷）
	FinalDecision     *FinalDecision      `json:"final_decision,omitempty"`
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
	IDs               []uuid.UUID
	Page              int
	PageSize          int
}

func buildListWhere(f ListFilter) (string, []interface{}) {
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
		cond := fmt.Sprintf("EXISTS (SELECT 1 FROM security_event_matches m WHERE m.event_id = security_events.id AND m.event_occurred_at = security_events.occurred_at AND m.rule_id = $%d", argIdx)
		args = append(args, *f.RuleID)
		argIdx++
		if f.StartTime != nil {
			cond += fmt.Sprintf(" AND m.event_occurred_at >= $%d", argIdx)
			args = append(args, *f.StartTime)
			argIdx++
		}
		if f.EndTime != nil {
			cond += fmt.Sprintf(" AND m.event_occurred_at <= $%d", argIdx)
			args = append(args, *f.EndTime)
			argIdx++
		}
		where += " AND " + cond + ")"
	}
	if len(f.IDs) > 0 {
		add("id = ANY($%d::uuid[])", f.IDs)
	}
	return where, args
}

// List 分页查询事件。
func (s *Store) List(ctx context.Context, f ListFilter) ([]Event, int64, error) {
	if f.Page <= 0 {
		f.Page = 1
	}
	if f.PageSize <= 0 || f.PageSize > 100 {
		f.PageSize = 20
	}
	where, args := buildListWhere(f)
	argIdx := len(args) + 1

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

const getByIDMatchesSQL = `
SELECT rule_id, rule_name, rule_source, rule_version, severity, message, matched_variable, matched_data_masked, tags, phase
FROM security_event_matches WHERE event_id = $1 AND event_occurred_at = $2 ORDER BY id`

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

	// 匹配记录（带分区键 event_occurred_at 触发分区裁剪）
	matchRows, err := s.db.Query(ctx, getByIDMatchesSQL, id, e.OccurredAt)
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
		m.RuleName = wafrules.LocalizeRule(m.RuleID, "", m.RuleName)
		m.Message = wafrules.LocalizeMatchMessage(m.RuleID, m.Message)
		m.Tags = parseTags(tags)
		// 编号缺省空数组（契约：[] 非 null）；现值由 AttachVulnIDs 联查填充
		m.CNNVDIDs = []string{}
		m.CVEIDs = []string{}
		matches = append(matches, m)
	}
	return &e, matches, nil
}

// AttachVulnIDs 为事件匹配记录联查漏洞编号（CNNVD 兼容性 P1，查询时现值口径）：
// rule_id 先查 custom_rules（自定义规则），未中查 waf_rules（CRS 目录，优先同
// rule_source，跨 crs_version 取最新行；rule_source 缺失时退化为该 rule_id 任一
// 来源的最新行）。规则已删除或两表均无标注时保持空数组——调用方对错误降级处理，
// 不得因此阻塞事件详情。
func (s *Store) AttachVulnIDs(ctx context.Context, matches []MatchInfo) error {
	if len(matches) == 0 {
		return nil
	}
	idSet := map[int]bool{}
	ids := make([]int, 0, len(matches))
	for _, m := range matches {
		if m.RuleID != 0 && !idSet[m.RuleID] {
			idSet[m.RuleID] = true
			ids = append(ids, m.RuleID)
		}
	}
	if len(ids) == 0 {
		return nil
	}
	type vulnIDs struct{ cnnvd, cve []string }
	scanIDs := func(rows pgx.Rows, fill func(ruleID int, ruleSource string, v vulnIDs)) error {
		defer rows.Close()
		for rows.Next() {
			var ruleID int
			var ruleSource string
			var cnnvd, cve []byte
			if err := rows.Scan(&ruleID, &ruleSource, &cnnvd, &cve); err != nil {
				return err
			}
			fill(ruleID, ruleSource, vulnIDs{cnnvd: decodeIDArray(cnnvd), cve: decodeIDArray(cve)})
		}
		return rows.Err()
	}

	// 自定义规则（rule_id 全表唯一）
	custom := map[int]vulnIDs{}
	customRows, err := s.db.Query(ctx,
		`SELECT rule_id, '' AS rule_source, cnnvd_ids, cve_ids FROM custom_rules WHERE rule_id = ANY($1::int[])`, ids)
	if err != nil {
		return err
	}
	if err := scanIDs(customRows, func(ruleID int, _ string, v vulnIDs) { custom[ruleID] = v }); err != nil {
		return err
	}

	// CRS 目录（同 rule_id+rule_source 可能有多 crs_version 行，取最新）
	catalog := map[string]vulnIDs{}
	catalogAny := map[int]vulnIDs{}
	catalogRows, err := s.db.Query(ctx, `
SELECT DISTINCT ON (rule_id, rule_source) rule_id, rule_source, cnnvd_ids, cve_ids
FROM waf_rules WHERE rule_id = ANY($1::int[])
ORDER BY rule_id, rule_source, crs_version DESC`, ids)
	if err != nil {
		return err
	}
	if err := scanIDs(catalogRows, func(ruleID int, ruleSource string, v vulnIDs) {
		catalog[fmt.Sprintf("%d\x00%s", ruleID, ruleSource)] = v
		if _, ok := catalogAny[ruleID]; !ok {
			catalogAny[ruleID] = v
		}
	}); err != nil {
		return err
	}

	for i := range matches {
		m := &matches[i]
		v := vulnIDs{cnnvd: []string{}, cve: []string{}}
		if c, ok := custom[m.RuleID]; ok {
			v = c
		} else if c, ok := catalog[fmt.Sprintf("%d\x00%s", m.RuleID, m.RuleSource)]; ok {
			v = c
		} else if c, ok := catalogAny[m.RuleID]; ok {
			v = c
		}
		m.CNNVDIDs, m.CVEIDs = v.cnnvd, v.cve
	}
	return nil
}

// decodeIDArray 反序列化 JSONB 编号数组；空/损坏一律落空数组（降级语义）。
func decodeIDArray(data []byte) []string {
	out := []string{}
	if len(data) == 0 {
		return out
	}
	if err := json.Unmarshal(data, &out); err != nil || out == nil {
		return []string{}
	}
	return out
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

// RelatedResult 相关事件查询结果。
// Mode 关联口径：attack_session=同一攻击会话（按攻击时间线升序，最有叙事价值）；
// same_source_ip=同来源 IP ±24h 兜底（事件未入任何会话时）；none=无可用关联线索。
// SessionID 仅 attack_session 口径时有值（前端跳转攻击活动详情）。
type RelatedResult struct {
	Events    []Event
	Mode      string
	SessionID *uuid.UUID
}

// relatedEventColumns 相关事件查询列（与 Event 字段一一对应；全部带 security_events
// 限定符——会话关联查询 JOIN attack_session_event 后 request_id/occurred_at 等列两表
// 同名，裸列名会报 ambiguous）。
const relatedEventColumns = `security_events.id, security_events.request_id, security_events.occurred_at, security_events.application_id, security_events.application_name_snapshot, security_events.domain, security_events.gateway_node_id,
  security_events.client_ip, security_events.connection_ip, COALESCE(security_events.client_port, 0), security_events.request_method, security_events.request_uri, security_events.request_path, security_events.query_summary,
  security_events.http_version, security_events.content_type, security_events.user_agent_summary, security_events.referer_summary, security_events.attack_type, security_events.severity, security_events.anomaly_score,
  security_events.action, COALESCE(security_events.response_status, 0), security_events.rule_match_count, security_events.disposition_status, security_events.disposition_result, security_events.raw_log_reference`

// scanRelatedEvents 扫描相关事件行集合（列序与 relatedEventColumns 一致）。
func scanRelatedEvents(rows pgx.Rows, limit int) ([]Event, error) {
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

// RelatedEvents 查询相关事件：优先同一攻击会话（attack_session_event 关联，按攻击
// 时间线升序）；事件未入会话时兜底同来源 IP ±24h（时间倒序）；IP 为空则无关联。
func (s *Store) RelatedEvents(ctx context.Context, e *Event, limit int) (*RelatedResult, error) {
	if limit <= 0 {
		limit = 10
	}
	res := &RelatedResult{Events: []Event{}, Mode: "none"}

	// 1) 攻击会话归属（聚合器 60s 一轮异步维护，新事件可能暂未入会话——走兜底）
	var sessionID uuid.UUID
	err := s.db.QueryRow(ctx,
		`SELECT session_id FROM attack_session_event WHERE source_table='security_events' AND source_id=$1`,
		e.ID.String()).Scan(&sessionID)
	if err != nil && !errors.Is(err, pgx.ErrNoRows) {
		return nil, err
	}
	if err == nil {
		rows, err := s.db.Query(ctx, `
SELECT `+relatedEventColumns+`
FROM security_events
JOIN attack_session_event ase ON ase.source_table='security_events' AND ase.source_id = security_events.id::text
WHERE ase.session_id = $1 AND security_events.id <> $2
ORDER BY security_events.occurred_at ASC, security_events.id ASC LIMIT $3`,
			sessionID, e.ID, limit)
		if err != nil {
			return nil, err
		}
		events, err := scanRelatedEvents(rows, limit)
		rows.Close()
		if err != nil {
			return nil, err
		}
		res.Events = events
		res.Mode = "attack_session"
		res.SessionID = &sessionID
		return res, nil
	}

	// 2) 兜底：同来源 IP ±24h（旧「同IP/同类型/同域名」三 OR 口径过松，域名条件会把
	// 同站点不相关事件全部圈入，已废弃）
	if e.ClientIP == "" {
		return res, nil
	}
	rows, err := s.db.Query(ctx, `
SELECT `+relatedEventColumns+`
FROM security_events
WHERE id <> $1 AND client_ip = $2 AND occurred_at >= $3 AND occurred_at <= $4
ORDER BY occurred_at DESC LIMIT $5`,
		e.ID, e.ClientIP, e.OccurredAt.Add(-24*time.Hour), e.OccurredAt.Add(24*time.Hour), limit)
	if err != nil {
		return nil, err
	}
	events, err := scanRelatedEvents(rows, limit)
	rows.Close()
	if err != nil {
		return nil, err
	}
	res.Events = events
	if len(events) > 0 {
		res.Mode = "same_source_ip"
	}
	return res, nil
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

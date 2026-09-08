package accesslogs

import (
	"context"
	"errors"
	"fmt"
	"net/netip"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
)

// Store 是全量访问日志仓储。
type Store struct {
	db DBTX
}

// NewStore 创建访问日志仓储。
func NewStore(db *pgxpool.Pool) *Store {
	return &Store{db: db}
}

// WithDB 返回绑定到给定句柄的浅拷贝（W22 采集器批次事务化：句柄为该批次的
// pgx.Tx；Insert/InsertFailure 并入外层批次事务，提交权归采集器，
// 失败整体回滚、断点不前移、重放由 request_id 去重兜底）。
func (s *Store) WithDB(db DBTX) *Store {
	return &Store{db: db}
}

// Insert 插入一条访问日志（request_id 非空时去重：采集器重读/断点回退不产生重复行）。
// inserted 为 false 表示命中去重（已存在，未重复插入）。
// waf_action 写入侧归一（ADR D9）：旧网关上报空串按 ALLOW 口径落库，历史行不回改。
// APM 新字段（trace_id/span_id/endpoint_key/path_template/ttfb_ms）空值写 NULL。
func (s *Store) Insert(ctx context.Context, e *LogEntry) (bool, error) {
	var appID *uuid.UUID
	if e.ApplicationID != "" {
		if id, err := uuid.Parse(e.ApplicationID); err == nil {
			appID = &id
		}
	}
	res, err := s.db.Exec(ctx, `
INSERT INTO access_logs (occurred_at, request_id, application_id, domain, gateway_node_id,
  client_ip, client_port, request_method, request_uri, request_path, query_summary,
  http_version, content_type, user_agent_summary, referer_summary,
  response_status, bytes_in, bytes_out, duration_ms, waf_action,
  trace_id, span_id, endpoint_key, path_template, ttfb_ms,
  request_headers, request_body, request_body_truncated,
  response_headers, response_body, response_body_truncated)
VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,$14,$15,$16,$17,$18,$19,$20,$21,$22,$23,$24,$25,$26,$27,$28,$29,$30,$31)
ON CONFLICT (request_id) WHERE request_id <> '' DO NOTHING`,
		e.OccurredAt, e.RequestID, appID, e.Domain, e.GatewayNodeID,
		nullableIP(e.ClientIP), e.ClientPort, e.RequestMethod, e.RequestURI, e.RequestPath, e.QuerySummary,
		e.HTTPVersion, e.ContentType, e.UserAgentSummary, e.RefererSummary,
		e.ResponseStatus, e.BytesIn, e.BytesOut, e.DurationMS, NormalizeWAFAction(e.WAFAction),
		nullStr(e.TraceID), nullStr(e.SpanID), nullStr(e.EndpointKey), nullStr(e.PathTemplate), nullInt64(e.TTFBMs),
		nonNilHeaders(e.RequestHeaders), e.RequestBody, e.RequestBodyTruncated,
		nonNilHeaders(e.ResponseHeaders), e.ResponseBody, e.ResponseBodyTruncated)
	if err != nil {
		return false, err
	}
	return res.RowsAffected() > 0, nil
}

// NormalizeWAFAction 访问日志 waf_action 写入/读取归一（ADR D9 三态）：
// 空串（旧网关两态数据）按 ALLOW 口径归一；其余原样返回。
func NormalizeWAFAction(action string) string {
	if action == "" {
		return "ALLOW"
	}
	return action
}

// InsertFailure 记录解析失败到错误队列（与安全事件共用 event_parse_failures 表）。
func (s *Store) InsertFailure(ctx context.Context, collectorID, rawLine, reason string) error {
	if len(rawLine) > 4096 {
		rawLine = rawLine[:4096]
	}
	_, err := s.db.Exec(ctx,
		`INSERT INTO event_parse_failures (collector_id, raw_line, error_reason) VALUES ($1, $2, $3)`,
		collectorID, rawLine, reason)
	return err
}

// AccessLog 是一条全量访问日志（API 输出）。
type AccessLog struct {
	ID                    uuid.UUID           `json:"id"`
	OccurredAt            time.Time           `json:"occurred_at"`
	RequestID             string              `json:"request_id"`
	ApplicationID         *uuid.UUID          `json:"application_id"`
	Domain                string              `json:"domain"`
	GatewayNodeID         string              `json:"gateway_node_id"`
	ClientIP              string              `json:"client_ip"`
	ClientPort            int                 `json:"client_port"`
	RequestMethod         string              `json:"request_method"`
	RequestURI            string              `json:"request_uri"`
	RequestPath           string              `json:"request_path"`
	QuerySummary          string              `json:"query_summary"`
	HTTPVersion           string              `json:"http_version"`
	ContentType           string              `json:"content_type"`
	UserAgentSummary      string              `json:"user_agent_summary"`
	RefererSummary        string              `json:"referer_summary"`
	ResponseStatus        int                 `json:"response_status"`
	BytesIn               int64               `json:"bytes_in"`
	BytesOut              int64               `json:"bytes_out"`
	DurationMS            int                 `json:"duration_ms"`
	WAFAction             string              `json:"waf_action"`
	RequestHeaders        map[string][]string `json:"request_headers,omitempty"`
	RequestBody           string              `json:"request_body,omitempty"`
	RequestBodyTruncated  bool                `json:"request_body_truncated,omitempty"`
	ResponseHeaders       map[string][]string `json:"response_headers,omitempty"`
	ResponseBody          string              `json:"response_body,omitempty"`
	ResponseBodyTruncated bool                `json:"response_body_truncated,omitempty"`
}

// ListFilter 是访问日志查询筛选。
type ListFilter struct {
	StartTime *time.Time
	EndTime   *time.Time
	Domain    string
	ClientIP  string
	Method    string
	URI       string
	Status    *int
	WAFAction string
	RequestID string
	Page      int
	PageSize  int
}

// buildListWhere 构建参数化 WHERE 子句（单测覆盖；禁止字符串拼接用户输入）。
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
	if f.Domain != "" {
		add("domain ILIKE $%d", "%"+f.Domain+"%")
	}
	if f.ClientIP != "" {
		add("host(client_ip) = $%d", f.ClientIP)
	}
	if f.Method != "" {
		add("request_method = $%d", f.Method)
	}
	if f.URI != "" {
		add("request_uri ILIKE $%d", "%"+f.URI+"%")
	}
	if f.Status != nil {
		add("response_status = $%d", *f.Status)
	}
	if f.WAFAction != "" {
		add("waf_action = $%d", f.WAFAction)
	}
	if f.RequestID != "" {
		add("request_id = $%d", f.RequestID)
	}
	return where, args
}

// 列表/详情公共列（不含头体留痕）。
const listColumns = `id, occurred_at, request_id, application_id, domain, gateway_node_id,
  host(client_ip), COALESCE(client_port, 0), request_method, request_uri, request_path, query_summary,
  http_version, content_type, user_agent_summary, referer_summary,
  response_status, bytes_in, bytes_out, duration_ms, waf_action`

const payloadColumns = `, request_headers, request_body, request_body_truncated,
  response_headers, response_body, response_body_truncated`

// List 分页查询访问日志（列表不返回头体留痕，详情走 GetByID；page_size 上限 100）。
func (s *Store) List(ctx context.Context, f ListFilter) ([]AccessLog, int64, error) {
	return s.list(ctx, f, 100)
}

// ListForExport 导出查询（上限 10000 行；列与 List 一致，不带头体留痕）。
func (s *Store) ListForExport(ctx context.Context, f ListFilter) ([]AccessLog, int64, error) {
	return s.list(ctx, f, 10000)
}

func (s *Store) list(ctx context.Context, f ListFilter, maxPageSize int) ([]AccessLog, int64, error) {
	if f.Page <= 0 {
		f.Page = 1
	}
	if f.PageSize <= 0 {
		f.PageSize = 20
	}
	if f.PageSize > maxPageSize {
		f.PageSize = maxPageSize
	}
	where, args := buildListWhere(f)

	var total int64
	if err := s.db.QueryRow(ctx, `SELECT count(*) FROM access_logs WHERE `+where, args...).Scan(&total); err != nil {
		return nil, 0, err
	}
	query := `SELECT ` + listColumns + ` FROM access_logs WHERE ` + where +
		fmt.Sprintf(" ORDER BY occurred_at DESC LIMIT $%d OFFSET $%d", len(args)+1, len(args)+2)
	args = append(args, f.PageSize, (f.Page-1)*f.PageSize)
	rows, err := s.db.Query(ctx, query, args...)
	if err != nil {
		return nil, 0, err
	}
	defer rows.Close()
	var out []AccessLog
	for rows.Next() {
		var e AccessLog
		var cip *string
		if err := rows.Scan(&e.ID, &e.OccurredAt, &e.RequestID, &e.ApplicationID, &e.Domain, &e.GatewayNodeID,
			&cip, &e.ClientPort, &e.RequestMethod, &e.RequestURI, &e.RequestPath, &e.QuerySummary,
			&e.HTTPVersion, &e.ContentType, &e.UserAgentSummary, &e.RefererSummary,
			&e.ResponseStatus, &e.BytesIn, &e.BytesOut, &e.DurationMS, &e.WAFAction); err != nil {
			return nil, 0, err
		}
		if cip != nil {
			e.ClientIP = *cip
		}
		out = append(out, e)
	}
	return out, total, rows.Err()
}

// ErrNotFound 访问日志不存在。
var ErrNotFound = errors.New("access log not found")

// GetByID 查询访问日志详情（含请求/响应头体留痕）。
func (s *Store) GetByID(ctx context.Context, id uuid.UUID) (*AccessLog, error) {
	row := s.db.QueryRow(ctx,
		`SELECT `+listColumns+payloadColumns+` FROM access_logs WHERE id = $1`, id)
	var e AccessLog
	var cip *string
	err := row.Scan(&e.ID, &e.OccurredAt, &e.RequestID, &e.ApplicationID, &e.Domain, &e.GatewayNodeID,
		&cip, &e.ClientPort, &e.RequestMethod, &e.RequestURI, &e.RequestPath, &e.QuerySummary,
		&e.HTTPVersion, &e.ContentType, &e.UserAgentSummary, &e.RefererSummary,
		&e.ResponseStatus, &e.BytesIn, &e.BytesOut, &e.DurationMS, &e.WAFAction,
		&e.RequestHeaders, &e.RequestBody, &e.RequestBodyTruncated,
		&e.ResponseHeaders, &e.ResponseBody, &e.ResponseBodyTruncated)
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return nil, ErrNotFound
		}
		return nil, err
	}
	if cip != nil {
		e.ClientIP = *cip
	}
	return &e, nil
}

func nullableIP(ip string) interface{} {
	if ip == "" {
		return nil
	}
	if _, err := netip.ParseAddr(ip); err != nil {
		return nil // 脏数据不入 inet 列（防插入失败整行丢失）
	}
	return ip
}

// nullStr 空串转 NULL（APM 新列可空：旧网关不携带时保持 NULL，不占部分索引）。
func nullStr(s string) interface{} {
	if s == "" {
		return nil
	}
	return s
}

// nullInt64 nil 指针转 NULL（ttfb_ms 可空：旧网关缺省不入库值）。
func nullInt64(p *int64) interface{} {
	if p == nil {
		return nil
	}
	return *p
}

// nonNilHeaders 保证头部 map 非 nil（jsonb 列 NOT NULL，nil 会编码为 SQL NULL）。
func nonNilHeaders(h map[string][]string) map[string][]string {
	if h == nil {
		return map[string][]string{}
	}
	return h
}

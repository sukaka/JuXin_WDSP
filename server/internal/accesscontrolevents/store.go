package accesscontrolevents

import (
	"context"
	"errors"
	"fmt"
	"net/netip"
	"strings"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
)

// Store 是访问控制事件仓储。
type Store struct {
	db *pgxpool.Pool
}

// NewStore 创建事件仓储。
func NewStore(db *pgxpool.Pool) *Store {
	return &Store{db: db}
}

// ListFilter 是事件查询筛选。
type ListFilter struct {
	StartTime     *time.Time
	EndTime       *time.Time
	ApplicationID *uuid.UUID
	ClientIP      string
	EventType     string
	Action        string
	PolicyID      string
	RequestID     string
	GatewayNodeID string
	Page          int
	PageSize      int
}

const eventColumns = `
SELECT id, request_id, occurred_at, application_id, application_code, client_ip, connection_ip,
  domain, request_method, request_path, event_type, action, policy_id, access_rule_id,
  current_count, limit_value, window_seconds, block_expires_at, response_status, gateway_node_id,
  message, created_at
FROM access_control_events`

// buildWhere 构造筛选条件与参数。
func buildWhere(f ListFilter) (string, []interface{}) {
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
	if f.ClientIP != "" {
		add("client_ip = $%d", f.ClientIP)
	}
	if f.EventType != "" {
		add("event_type = $%d", f.EventType)
	}
	if f.Action != "" {
		add("action = $%d", f.Action)
	}
	if f.PolicyID != "" {
		add("policy_id = $%d", f.PolicyID)
	}
	if f.RequestID != "" {
		add("request_id = $%d", f.RequestID)
	}
	if f.GatewayNodeID != "" {
		add("gateway_node_id = $%d", f.GatewayNodeID)
	}
	return where, args
}

// queryEvents 按筛选查询事件（limit 上限由调用方决定）。
func (s *Store) queryEvents(ctx context.Context, f ListFilter, limit, offset int) ([]Event, error) {
	where, args := buildWhere(f)
	argIdx := len(args) + 1
	query := eventColumns + ` WHERE ` + where +
		fmt.Sprintf(" ORDER BY occurred_at DESC LIMIT $%d OFFSET $%d", argIdx, argIdx+1)
	args = append(args, limit, offset)
	rows, err := s.db.Query(ctx, query, args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []Event
	for rows.Next() {
		e, err := scanEvent(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, *e)
	}
	return out, rows.Err()
}

// List 分页查询事件。
func (s *Store) List(ctx context.Context, f ListFilter) ([]Event, int64, error) {
	if f.Page <= 0 {
		f.Page = 1
	}
	if f.PageSize <= 0 || f.PageSize > 100 {
		f.PageSize = 20
	}
	where, args := buildWhere(f)
	var total int64
	if err := s.db.QueryRow(ctx, `SELECT count(*) FROM access_control_events WHERE `+where, args...).Scan(&total); err != nil {
		return nil, 0, err
	}
	out, err := s.queryEvents(ctx, f, f.PageSize, (f.Page-1)*f.PageSize)
	if err != nil {
		return nil, 0, err
	}
	return out, total, nil
}

// GetByID 查询事件详情。
func (s *Store) GetByID(ctx context.Context, id uuid.UUID) (*Event, error) {
	row := s.db.QueryRow(ctx, eventColumns+` WHERE id = $1`, id)
	return scanEvent(row)
}

func scanEvent(row pgx.Row) (*Event, error) {
	var e Event
	var cip, connIP *netip.Addr
	err := row.Scan(&e.ID, &e.RequestID, &e.OccurredAt, &e.ApplicationID, &e.ApplicationCode,
		&cip, &connIP, &e.Domain, &e.RequestMethod, &e.RequestPath, &e.EventType, &e.Action,
		&e.PolicyID, &e.AccessRuleID, &e.CurrentCount, &e.LimitValue, &e.WindowSeconds,
		&e.BlockExpiresAt, &e.ResponseStatus, &e.GatewayNodeID, &e.Message, &e.CreatedAt)
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return nil, fmt.Errorf("access control event not found")
		}
		return nil, err
	}
	if cip != nil {
		e.ClientIP = cip.String()
	}
	if connIP != nil {
		e.ConnectionIP = connIP.String()
	}
	return &e, nil
}

// Insert 批量插入事件（同一事务，分区表自动路由）。
func (s *Store) Insert(ctx context.Context, batch []Event) (int, error) {
	if len(batch) == 0 {
		return 0, nil
	}
	tx, err := s.db.BeginTx(ctx, pgx.TxOptions{})
	if err != nil {
		return 0, err
	}
	defer func() { _ = tx.Rollback(ctx) }()

	b := &pgx.Batch{}
	for i := range batch {
		e := &batch[i]
		b.Queue(`
INSERT INTO access_control_events (request_id, occurred_at, application_id, application_code,
  client_ip, connection_ip, domain, request_method, request_path, event_type, action,
  policy_id, access_rule_id, current_count, limit_value, window_seconds, block_expires_at,
  response_status, gateway_node_id, message)
VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,$14,$15,$16,$17,$18,$19,$20)`,
			e.RequestID, e.OccurredAt, e.ApplicationID, e.ApplicationCode,
			e.ClientIP, nullableIP(e.ConnectionIP), e.Domain, e.RequestMethod, e.RequestPath,
			e.EventType, e.Action, e.PolicyID, e.AccessRuleID, e.CurrentCount, e.LimitValue,
			e.WindowSeconds, e.BlockExpiresAt, e.ResponseStatus, e.GatewayNodeID, e.Message)
	}
	br := tx.SendBatch(ctx, b)
	for range batch {
		if _, err := br.Exec(); err != nil {
			_ = br.Close()
			return 0, err
		}
	}
	if err := br.Close(); err != nil {
		return 0, err
	}
	if err := tx.Commit(ctx); err != nil {
		return 0, err
	}
	return len(batch), nil
}

// RuntimeSummary 是 CC 策略运行汇总。
type RuntimeSummary struct {
	PolicyID         uuid.UUID `json:"policy_id"`
	WindowStart      time.Time `json:"window_start"`
	TotalRequests    int64     `json:"total_requests"`
	RejectedRequests int64     `json:"rejected_requests"`
	BlockedIPs       int       `json:"blocked_ips"`
}

// InsertRuntimeSummary 写入一条 CC 运行汇总。
func (s *Store) InsertRuntimeSummary(ctx context.Context, sum RuntimeSummary) error {
	_, err := s.db.Exec(ctx, `
INSERT INTO rate_limit_runtime_summaries (policy_id, window_start, total_requests, rejected_requests, blocked_ips)
VALUES ($1,$2,$3,$4,$5)`,
		sum.PolicyID, sum.WindowStart, sum.TotalRequests, sum.RejectedRequests, sum.BlockedIPs)
	return err
}

// Export 导出事件 CSV（最多 10000 条，防公式注入）。
func (s *Store) Export(ctx context.Context, f ListFilter) (string, error) {
	list, err := s.queryEvents(ctx, f, 10000, 0)
	if err != nil {
		return "", err
	}
	var b strings.Builder
	b.WriteString("occurred_at,request_id,application_code,client_ip,connection_ip,domain,method,path,event_type,action,policy_id,access_rule_id,current_count,limit_value,window_seconds,response_status,gateway_node_id,message\n")
	for _, e := range list {
		fmt.Fprintf(&b, "%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s\n",
			e.OccurredAt.UTC().Format(time.RFC3339),
			csvCell(e.RequestID), csvCell(e.ApplicationCode), e.ClientIP, e.ConnectionIP,
			csvCell(e.Domain), e.RequestMethod, csvCell(e.RequestPath), e.EventType, e.Action,
			csvCell(e.PolicyID), csvCell(e.AccessRuleID),
			int64PtrStr(e.CurrentCount), int64PtrStr(e.LimitValue), intPtrStr(e.WindowSeconds),
			intPtrStr(e.ResponseStatus), csvCell(e.GatewayNodeID), csvCell(e.Message))
	}
	return b.String(), nil
}

// csvCell CSV 单元格转义 + 防公式注入（= + - @ 开头加 '）。
func csvCell(s string) string {
	if s == "" {
		return s
	}
	switch s[0] {
	case '=', '+', '-', '@':
		s = "'" + s
	}
	if strings.ContainsAny(s, ",\"\n\r") {
		return "\"" + strings.ReplaceAll(s, "\"", "\"\"") + "\""
	}
	return s
}

func int64PtrStr(v *int64) string {
	if v == nil {
		return ""
	}
	return fmt.Sprintf("%d", *v)
}

func intPtrStr(v *int) string {
	if v == nil {
		return ""
	}
	return fmt.Sprintf("%d", *v)
}

func nullableIP(ip string) interface{} {
	if ip == "" {
		return nil
	}
	return ip
}

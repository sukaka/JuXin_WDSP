// Package loginlogs 提供登录日志记录与查询。
package loginlogs

import (
	"context"
	"fmt"
	"net/netip"
	"strings"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgxpool"
)

// 事件类型
const (
	EventLoginSuccess   = "LOGIN_SUCCESS"
	EventLoginFailure   = "LOGIN_FAILURE"
	EventCaptchaFailure = "CAPTCHA_FAILURE"
	EventAccountLocked  = "ACCOUNT_LOCKED"
	EventLogout         = "LOGOUT"
	EventForceLogout    = "FORCE_LOGOUT"
	EventSessionExpired = "SESSION_EXPIRED"
	EventPasswordChange = "PASSWORD_CHANGE"
	EventPasswordReset  = "PASSWORD_RESET"
	EventFirstChangePwd = "FIRST_CHANGE_PASSWORD"
)

// 结果
const (
	ResultSuccess = "SUCCESS"
	ResultFailure = "FAILURE"
)

// Entry 是一条登录日志。
type Entry struct {
	ID           uuid.UUID  `json:"id"`
	OccurredAt   time.Time  `json:"occurred_at"`
	Username     string     `json:"username"`
	UserID       *uuid.UUID `json:"user_id"`
	SourceIP     string     `json:"source_ip"`
	ConnectionIP string     `json:"connection_ip"`
	UserAgent    string     `json:"user_agent_summary"`
	EventType    string     `json:"event_type"`
	Result       string     `json:"result"`
	FailureCode  string     `json:"failure_code"`
	RequestID    string     `json:"request_id"`
}

// Service 是登录日志服务。
type Service struct {
	db *pgxpool.Pool
}

// NewService 创建登录日志服务。
func NewService(db *pgxpool.Pool) *Service {
	return &Service{db: db}
}

// RecordInput 是记录登录日志的输入。
type RecordInput struct {
	Username     string
	UserID       *uuid.UUID
	SourceIP     string
	ConnectionIP string
	UserAgent    string
	EventType    string
	Result       string
	FailureCode  string
	RequestID    string
}

// Record 写入登录日志。日志中不得包含密码、验证码、完整会话标识。
func (s *Service) Record(ctx context.Context, in RecordInput) error {
	_, err := s.db.Exec(ctx, `
INSERT INTO login_logs (username, user_id, source_ip, connection_ip, user_agent_summary,
                        event_type, result, failure_code, request_id)
VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9)`,
		in.Username, in.UserID, nullableIP(in.SourceIP), nullableIP(in.ConnectionIP),
		truncateUA(in.UserAgent), in.EventType, in.Result, in.FailureCode, in.RequestID)
	return err
}

// ListFilter 是登录日志查询筛选。
type ListFilter struct {
	Username  string
	SourceIP  string
	Result    string
	EventType string
	RequestID string
	StartTime *time.Time
	EndTime   *time.Time
	UserID    *uuid.UUID // 限定查看自己的日志
	Page      int
	PageSize  int
}

// List 分页查询登录日志。
func (s *Service) List(ctx context.Context, f ListFilter) ([]Entry, int64, error) {
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
	if f.Username != "" {
		add("username ILIKE $%d", "%"+f.Username+"%")
	}
	if f.SourceIP != "" {
		add("host(source_ip) = $%d", f.SourceIP)
	}
	if f.Result != "" {
		add("result = $%d", f.Result)
	}
	if f.EventType != "" {
		add("event_type = $%d", f.EventType)
	}
	if f.RequestID != "" {
		add("request_id = $%d", f.RequestID)
	}
	if f.UserID != nil {
		add("user_id = $%d", *f.UserID)
	}
	if f.StartTime != nil {
		add("occurred_at >= $%d", *f.StartTime)
	}
	if f.EndTime != nil {
		add("occurred_at <= $%d", *f.EndTime)
	}

	var total int64
	if err := s.db.QueryRow(ctx, `SELECT count(*) FROM login_logs WHERE `+where, args...).Scan(&total); err != nil {
		return nil, 0, err
	}
	query := `
SELECT id, occurred_at, username, user_id, source_ip, connection_ip, user_agent_summary,
       event_type, result, failure_code, request_id
FROM login_logs WHERE ` + where +
		fmt.Sprintf(" ORDER BY occurred_at DESC LIMIT $%d OFFSET $%d", argIdx, argIdx+1)
	args = append(args, f.PageSize, (f.Page-1)*f.PageSize)

	rows, err := s.db.Query(ctx, query, args...)
	if err != nil {
		return nil, 0, err
	}
	defer rows.Close()
	var out []Entry
	for rows.Next() {
		var e Entry
		var sip, cip *netip.Addr
		if err := rows.Scan(&e.ID, &e.OccurredAt, &e.Username, &e.UserID, &sip, &cip,
			&e.UserAgent, &e.EventType, &e.Result, &e.FailureCode, &e.RequestID); err != nil {
			return nil, 0, err
		}
		if sip != nil {
			e.SourceIP = sip.String()
		}
		if cip != nil {
			e.ConnectionIP = cip.String()
		}
		out = append(out, e)
	}
	return out, total, rows.Err()
}

// Export 导出登录日志（CSV 格式，最多 10000 条）。
func (s *Service) Export(ctx context.Context, f ListFilter) (string, error) {
	f.Page = 1
	f.PageSize = 10000
	entries, _, err := s.List(ctx, f)
	if err != nil {
		return "", err
	}
	var b strings.Builder
	b.WriteString("occurred_at,username,source_ip,event_type,result,failure_code,request_id\n")
	for _, e := range entries {
		fmt.Fprintf(&b, "%s,%s,%s,%s,%s,%s,%s\n",
			e.OccurredAt.UTC().Format(time.RFC3339),
			csvEscape(e.Username), csvEscape(e.SourceIP),
			e.EventType, e.Result, csvEscape(e.FailureCode), e.RequestID)
	}
	return b.String(), nil
}

func csvEscape(s string) string {
	if strings.ContainsAny(s, ",\"\n\r") {
		return "\"" + strings.ReplaceAll(s, "\"", "\"\"") + "\""
	}
	return s
}

func nullableIP(ip string) interface{} {
	if ip == "" {
		return nil
	}
	return ip
}

func truncateUA(ua string) string {
	if len(ua) > 500 {
		return ua[:500]
	}
	return ua
}

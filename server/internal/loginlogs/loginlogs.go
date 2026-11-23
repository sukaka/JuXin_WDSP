// Package loginlogs 提供登录日志记录与查询。
package loginlogs

import (
	"context"
	"fmt"
	"log/slog"
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
	// EventLoginTOTPChallenge 密码校验通过、等待双因子第二步验证（未创建会话）。
	EventLoginTOTPChallenge = "LOGIN_TOTP_CHALLENGE"
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

// SyslogEnqueueFunc 是 syslog 外发投递函数（装配层闭包注入，本包不依赖 syslogfw，
// 避免循环导入；模式参考 backups.AlertFunc）。nil 时跳过外发。
type SyslogEnqueueFunc func(severityHint string, payload interface{})

type logRowScanner interface {
	Next() bool
	Scan(dest ...interface{}) error
	Err() error
	Close()
}

type logStore interface {
	Exec(ctx context.Context, sql string, args ...interface{}) error
	Count(ctx context.Context, sql string, args ...interface{}) (int64, error)
	Query(ctx context.Context, sql string, args ...interface{}) (logRowScanner, error)
}

type pgxPoolStore struct {
	pool *pgxpool.Pool
}

func (p pgxPoolStore) Exec(ctx context.Context, sql string, args ...interface{}) error {
	_, err := p.pool.Exec(ctx, sql, args...)
	return err
}

func (p pgxPoolStore) Count(ctx context.Context, sql string, args ...interface{}) (int64, error) {
	var total int64
	err := p.pool.QueryRow(ctx, sql, args...).Scan(&total)
	return total, err
}

func (p pgxPoolStore) Query(ctx context.Context, sql string, args ...interface{}) (logRowScanner, error) {
	return p.pool.Query(ctx, sql, args...)
}

// Service 是登录日志服务。
type Service struct {
	db     *pgxpool.Pool
	store  logStore
	syslog SyslogEnqueueFunc // nil 时跳过 syslog 外发
}

// NewService 创建登录日志服务。
func NewService(db *pgxpool.Pool) *Service {
	var st logStore
	if db != nil {
		st = pgxPoolStore{pool: db}
	}
	return &Service{db: db, store: st}
}

func (s *Service) getStore() logStore {
	if s.store != nil {
		return s.store
	}
	return pgxPoolStore{pool: s.db}
}

// SetSyslogForwarder 设置 syslog 外发投递函数（应用装配时使用，可为 nil）。
func (s *Service) SetSyslogForwarder(fn SyslogEnqueueFunc) { s.syslog = fn }

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
	occurredAt := time.Now().UTC()
	err := s.getStore().Exec(ctx, `
INSERT INTO login_logs (username, user_id, source_ip, connection_ip, user_agent_summary,
                        event_type, result, failure_code, request_id)
VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9)`,
		in.Username, in.UserID, nullableIP(in.SourceIP), nullableIP(in.ConnectionIP),
		truncateUA(in.UserAgent), in.EventType, in.Result, in.FailureCode, in.RequestID)
	if err != nil {
		// 写库失败必须可见：调用方多为安全审计旁路（忽略返回错误不阻断主流程），
		// 此处 Warn 是唯一留存痕迹；不输出用户名/UA 等字段，避免泄露与刷屏。
		slog.Warn("login log insert failed",
			"event_type", in.EventType, "result", in.Result,
			"failure_code", in.FailureCode, "request_id", in.RequestID, "error", err)
		return err
	}
	// syslog 外发：入库成功后非阻塞投递，外发器异常（含 panic）不影响登录主流程。
	// occurred_at 取 Record 入口时间（库内列为 default now()，二者近似相等）。
	s.enqueueSyslog(syslogSeverityHint(in.Result), map[string]interface{}{
		"occurred_at":   occurredAt.Format(time.RFC3339Nano),
		"username":      in.Username,
		"source_ip":     in.SourceIP,
		"connection_ip": in.ConnectionIP,
		"event_type":    in.EventType,
		"result":        in.Result,
		"failure_code":  in.FailureCode,
		"request_id":    in.RequestID,
	})
	return nil
}

// syslogSeverityHint 计算登录日志外发的 severity 提示：失败（登录失败/锁定等）→ warning，成功 → info。
func syslogSeverityHint(result string) string {
	if result == ResultFailure {
		return "warning"
	}
	return ""
}

// enqueueSyslog 非阻塞投递 syslog 外发；未注入投递函数时跳过，
// 投递函数 panic 时记录错误日志而不扩散到调用方主流程。
func (s *Service) enqueueSyslog(severityHint string, payload interface{}) {
	if s.syslog == nil {
		return
	}
	defer func() {
		if r := recover(); r != nil {
			slog.Error("syslog enqueue panicked", "panic", r)
		}
	}()
	s.syslog(severityHint, payload)
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
	IDs       []uuid.UUID
	Page      int
	PageSize  int
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
	if len(f.IDs) > 0 {
		add("id = ANY($%d::uuid[])", f.IDs)
	}
	return where, args
}

func normalizePage(page, pageSize, maxPageSize int) (int, int) {
	if page <= 0 {
		page = 1
	}
	if pageSize <= 0 || pageSize > maxPageSize {
		pageSize = 20
	}
	return page, pageSize
}

// List 分页查询登录日志（单页上限 100）。
func (s *Service) List(ctx context.Context, f ListFilter) ([]Entry, int64, error) {
	return s.list(ctx, f, 100)
}

func (s *Service) list(ctx context.Context, f ListFilter, maxPageSize int) ([]Entry, int64, error) {
	f.Page, f.PageSize = normalizePage(f.Page, f.PageSize, maxPageSize)
	where, args := buildListWhere(f)
	argIdx := len(args) + 1

	st := s.getStore()
	total, err := st.Count(ctx, `SELECT count(*) FROM login_logs WHERE `+where, args...)
	if err != nil {
		return nil, 0, err
	}
	query := `
SELECT id, occurred_at, username, user_id, source_ip, connection_ip, user_agent_summary,
       event_type, result, failure_code, request_id
FROM login_logs WHERE ` + where +
		fmt.Sprintf(" ORDER BY occurred_at DESC LIMIT $%d OFFSET $%d", argIdx, argIdx+1)
	args = append(args, f.PageSize, (f.Page-1)*f.PageSize)

	rows, err := st.Query(ctx, query, args...)
	if err != nil {
		return nil, 0, err
	}
	defer rows.Close()
	out := []Entry{}
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
	entries, _, err := s.list(ctx, f, 10000)
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

// csvEscape CSV 字段转义：=、+、-、@、\t 开头前加 ' 防公式注入；含逗号/引号/换行加双引号。
func csvEscape(s string) string {
	if s == "" {
		return s
	}
	switch s[0] {
	case '=', '+', '-', '@', '\t':
		s = "'" + s
	}
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

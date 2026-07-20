// Package audits 提供操作审计记录、查询与完整性校验。
// 审计记录仅支持新增与查询，数据库层通过 RULE 禁止 UPDATE/DELETE。
package audits

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"net/netip"
	"sort"
	"strings"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
)

// 风险等级
const (
	RiskLow      = "LOW"
	RiskMedium   = "MEDIUM"
	RiskHigh     = "HIGH"
	RiskCritical = "CRITICAL"
)

// 结果
const (
	ResultSuccess = "SUCCESS"
	ResultFailure = "FAILURE"
)

// Entry 是一条操作审计。
type Entry struct {
	ID            uuid.UUID  `json:"id"`
	OccurredAt    time.Time  `json:"occurred_at"`
	UserID        *uuid.UUID `json:"user_id"`
	Username      string     `json:"username"`
	SourceIP      string     `json:"source_ip"`
	ConnectionIP  string     `json:"connection_ip"`
	UserAgent     string     `json:"user_agent_summary"`
	Module        string     `json:"module"`
	Action        string     `json:"action"`
	ObjectType    string     `json:"object_type"`
	ObjectID      string     `json:"object_id"`
	ObjectName    string     `json:"object_name"`
	BeforeSummary string     `json:"before_summary"`
	AfterSummary  string     `json:"after_summary"`
	Result        string     `json:"result"`
	FailureReason string     `json:"failure_reason"`
	RiskLevel     string     `json:"risk_level"`
	RequestID     string     `json:"request_id"`
	PreviousHash  string     `json:"previous_hash"`
	RecordHash    string     `json:"record_hash"`
}

// RecordInput 是写入审计的输入。
type RecordInput struct {
	UserID        *uuid.UUID
	Username      string
	SourceIP      string
	ConnectionIP  string
	UserAgent     string
	Module        string
	Action        string
	ObjectType    string
	ObjectID      string
	ObjectName    string
	BeforeSummary string
	AfterSummary  string
	Result        string
	FailureReason string
	RiskLevel     string
	RequestID     string
}

// Service 是操作审计服务。
type Service struct {
	db *pgxpool.Pool
}

// NewService 创建审计服务。
func NewService(db *pgxpool.Pool) *Service {
	return &Service{db: db}
}

// 敏感字段（审计摘要中脱敏）
var sensitiveFields = map[string]bool{
	"password": true, "password_hash": true, "old_password": true,
	"new_password": true, "temporary_password": true, "session_id": true,
	"cookie": true, "token": true, "csrf_token": true, "captcha_code": true,
	"private_key": true, "secret": true, "authorization": true,
}

const maskedValue = "********"

// MaskSensitiveJSON 对 JSON 字符串中的敏感字段脱敏。
// 输入必须是合法 JSON 对象；非法输入返回固定占位，绝不原样放行。
func MaskSensitiveJSON(raw string) string {
	if raw == "" {
		return ""
	}
	var obj map[string]interface{}
	if err := json.Unmarshal([]byte(raw), &obj); err != nil {
		return "(unstructured, masked)"
	}
	maskMap(obj)
	out, err := json.Marshal(obj)
	if err != nil {
		return "(mask error)"
	}
	return string(out)
}

func maskMap(m map[string]interface{}) {
	for k, v := range m {
		lk := strings.ToLower(k)
		if sensitiveFields[lk] {
			m[k] = maskedValue
			continue
		}
		switch vv := v.(type) {
		case map[string]interface{}:
			maskMap(vv)
		case []interface{}:
			for _, item := range vv {
				if im, ok := item.(map[string]interface{}); ok {
					maskMap(im)
				}
			}
		}
	}
}

// computeHash 计算审计记录哈希（固定字段顺序的规范化数据）。
func computeHash(occurredAt time.Time, username, module, action, objectType, objectID, result, requestID, previousHash string) string {
	h := sha256.New()
	h.Write([]byte(strings.Join([]string{
		occurredAt.UTC().Format(time.RFC3339Nano),
		username, module, action, objectType, objectID, result, requestID, previousHash,
	}, "|")))
	return hex.EncodeToString(h.Sum(nil))
}

// Record 写入一条审计记录（含哈希链）。
func (s *Service) Record(ctx context.Context, in RecordInput) error {
	occurredAt := time.Now().UTC()
	previousHash, err := s.latestHash(ctx)
	if err != nil {
		return err
	}
	recordHash := computeHash(occurredAt, in.Username, in.Module, in.Action,
		in.ObjectType, in.ObjectID, in.Result, in.RequestID, previousHash)

	before := MaskSensitiveJSON(in.BeforeSummary)
	after := MaskSensitiveJSON(in.AfterSummary)

	_, err = s.db.Exec(ctx, `
INSERT INTO operation_audits
(occurred_at, user_id, username, source_ip, connection_ip, user_agent_summary,
 module, action, object_type, object_id, object_name, before_summary, after_summary,
 result, failure_reason, risk_level, request_id, previous_hash, record_hash)
VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,$14,$15,$16,$17,$18,$19)`,
		occurredAt, in.UserID, in.Username, nullableIP(in.SourceIP), nullableIP(in.ConnectionIP),
		truncateStr(in.UserAgent, 500), in.Module, in.Action, in.ObjectType, in.ObjectID,
		in.ObjectName, before, after, in.Result, in.FailureReason, in.RiskLevel,
		in.RequestID, previousHash, recordHash)
	return err
}

func (s *Service) latestHash(ctx context.Context) (string, error) {
	var h string
	err := s.db.QueryRow(ctx,
		`SELECT record_hash FROM operation_audits ORDER BY occurred_at DESC, id DESC LIMIT 1`).Scan(&h)
	if err != nil {
		if err == pgx.ErrNoRows {
			return "", nil
		}
		return "", err
	}
	return h, nil
}

// VerifyChain 校验审计哈希链完整性。
// 返回错误数与首条不一致记录 ID（如有）。
func (s *Service) VerifyChain(ctx context.Context, limit int) (int, []uuid.UUID, error) {
	if limit <= 0 {
		limit = 10000
	}
	rows, err := s.db.Query(ctx, `
SELECT id, occurred_at, username, module, action, object_type, object_id, result,
       request_id, previous_hash, record_hash
FROM operation_audits
ORDER BY occurred_at ASC, id ASC
LIMIT $1`, limit)
	if err != nil {
		return 0, nil, err
	}
	defer rows.Close()

	var mismatches []uuid.UUID
	var prevHash string
	first := true
	for rows.Next() {
		var (
			id         uuid.UUID
			occurredAt time.Time
			username   string
			module     string
			action     string
			objectType string
			objectID   string
			result     string
			requestID  string
			prevStored string
			recHash    string
		)
		if err := rows.Scan(&id, &occurredAt, &username, &module, &action, &objectType,
			&objectID, &result, &requestID, &prevStored, &recHash); err != nil {
			return 0, nil, err
		}
		// 首条的 previous_hash 应为空（链起点）
		expectedPrev := prevHash
		if first {
			expectedPrev = ""
		}
		if prevStored != expectedPrev {
			mismatches = append(mismatches, id)
		}
		recomputed := computeHash(occurredAt, username, module, action, objectType,
			objectID, result, requestID, prevStored)
		if recomputed != recHash {
			mismatches = append(mismatches, id)
		}
		prevHash = recHash
		first = false
	}
	return len(mismatches), mismatches, rows.Err()
}

// ListFilter 是审计查询筛选。
type ListFilter struct {
	Username   string
	SourceIP   string
	Module     string
	Action     string
	ObjectType string
	Result     string
	RiskLevel  string
	RequestID  string
	StartTime  *time.Time
	EndTime    *time.Time
	Page       int
	PageSize   int
}

// List 分页查询审计。
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
	if f.Module != "" {
		add("module = $%d", f.Module)
	}
	if f.Action != "" {
		add("action = $%d", f.Action)
	}
	if f.ObjectType != "" {
		add("object_type = $%d", f.ObjectType)
	}
	if f.Result != "" {
		add("result = $%d", f.Result)
	}
	if f.RiskLevel != "" {
		add("risk_level = $%d", f.RiskLevel)
	}
	if f.RequestID != "" {
		add("request_id = $%d", f.RequestID)
	}
	if f.StartTime != nil {
		add("occurred_at >= $%d", *f.StartTime)
	}
	if f.EndTime != nil {
		add("occurred_at <= $%d", *f.EndTime)
	}

	var total int64
	if err := s.db.QueryRow(ctx, `SELECT count(*) FROM operation_audits WHERE `+where, args...).Scan(&total); err != nil {
		return nil, 0, err
	}
	query := `
SELECT id, occurred_at, user_id, username, source_ip, connection_ip, user_agent_summary,
       module, action, object_type, object_id, object_name, before_summary, after_summary,
       result, failure_reason, risk_level, request_id, previous_hash, record_hash
FROM operation_audits WHERE ` + where +
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
		if err := rows.Scan(&e.ID, &e.OccurredAt, &e.UserID, &e.Username, &sip, &cip,
			&e.UserAgent, &e.Module, &e.Action, &e.ObjectType, &e.ObjectID, &e.ObjectName,
			&e.BeforeSummary, &e.AfterSummary, &e.Result, &e.FailureReason, &e.RiskLevel,
			&e.RequestID, &e.PreviousHash, &e.RecordHash); err != nil {
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

// GetByID 查询单条审计。
func (s *Service) GetByID(ctx context.Context, id uuid.UUID) (*Entry, error) {
	row := s.db.QueryRow(ctx, `
SELECT id, occurred_at, user_id, username, source_ip, connection_ip, user_agent_summary,
       module, action, object_type, object_id, object_name, before_summary, after_summary,
       result, failure_reason, risk_level, request_id, previous_hash, record_hash
FROM operation_audits WHERE id = $1`, id)
	var e Entry
	var sip, cip *netip.Addr
	err := row.Scan(&e.ID, &e.OccurredAt, &e.UserID, &e.Username, &sip, &cip,
		&e.UserAgent, &e.Module, &e.Action, &e.ObjectType, &e.ObjectID, &e.ObjectName,
		&e.BeforeSummary, &e.AfterSummary, &e.Result, &e.FailureReason, &e.RiskLevel,
		&e.RequestID, &e.PreviousHash, &e.RecordHash)
	if err != nil {
		if err == pgx.ErrNoRows {
			return nil, fmt.Errorf("audit not found")
		}
		return nil, err
	}
	if sip != nil {
		e.SourceIP = sip.String()
	}
	if cip != nil {
		e.ConnectionIP = cip.String()
	}
	return &e, nil
}

// Export 导出审计（CSV，最多 10000 条）。
func (s *Service) Export(ctx context.Context, f ListFilter) (string, error) {
	f.Page = 1
	f.PageSize = 10000
	entries, _, err := s.List(ctx, f)
	if err != nil {
		return "", err
	}
	var b strings.Builder
	b.WriteString("occurred_at,username,source_ip,module,action,object_type,object_id,result,risk_level,request_id\n")
	for _, e := range entries {
		fmt.Fprintf(&b, "%s,%s,%s,%s,%s,%s,%s,%s,%s,%s\n",
			e.OccurredAt.UTC().Format(time.RFC3339),
			csvEscape(e.Username), csvEscape(e.SourceIP), e.Module, e.Action,
			e.ObjectType, e.ObjectID, e.Result, e.RiskLevel, e.RequestID)
	}
	return b.String(), nil
}

// DistinctModules 返回审计中出现过的模块清单（供筛选器）。
func (s *Service) DistinctModules(ctx context.Context) ([]string, error) {
	rows, err := s.db.Query(ctx, `SELECT DISTINCT module FROM operation_audits ORDER BY module`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []string
	for rows.Next() {
		var m string
		if err := rows.Scan(&m); err != nil {
			return nil, err
		}
		out = append(out, m)
	}
	return out, rows.Err()
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

func truncateStr(s string, n int) string {
	if len(s) > n {
		return s[:n]
	}
	return s
}

// SortObjectKeys 辅助：将 map 的键排序（规范化哈希输入用）。
func SortObjectKeys(m map[string]interface{}) []string {
	keys := make([]string, 0, len(m))
	for k := range m {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	return keys
}

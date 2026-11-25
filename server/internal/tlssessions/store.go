package tlssessions

import (
	"context"
	"fmt"
	"net/netip"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgxpool"
)

// SessionEvent 是单条 SSL/HTTPS 加密会话分析记录（API 输出结构）。
type SessionEvent struct {
	ID                 uuid.UUID  `json:"id"`
	OccurredAt         time.Time  `json:"occurred_at"`
	GatewayNodeID      string     `json:"gateway_node_id"`
	ApplicationID      *uuid.UUID `json:"application_id"`
	SNI                string     `json:"sni"`
	ClientIP           string     `json:"client_ip"`
	ClientPort         int        `json:"client_port"`
	ServerPort         int        `json:"server_port"`
	DetectedProtocol   string     `json:"detected_protocol"`
	NegotiatedProtocol string     `json:"negotiated_protocol"`
	CipherSuite        string     `json:"cipher_suite"`
	IsGM               bool       `json:"is_gm"`
	JA3Hash            string     `json:"ja3_hash"`
	ALPN               string     `json:"alpn"`
	Action             string     `json:"action"`
	ErrorReason        string     `json:"error_reason"`
}

// ProtocolStat 是按检测协议维度的汇总统计项。
type ProtocolStat struct {
	Protocol string `json:"protocol"`
	Count    int64  `json:"count"`
	IsGM     bool   `json:"is_gm"`
	IsLegacy bool   `json:"is_legacy"`
}

// CipherSuiteStat 是按协商密码套件维度的汇总统计项。
type CipherSuiteStat struct {
	CipherSuite string `json:"cipher_suite"`
	Count       int64  `json:"count"`
	IsGM        bool   `json:"is_gm"`
}

// Summary 是加密会话分析汇总统计响应。
type Summary struct {
	TotalHandshakes       int64             `json:"total_handshakes"`
	AllowedCount          int64             `json:"allowed_count"`
	GMCount               int64             `json:"gm_count"`
	IntlCount             int64             `json:"intl_count"`
	LegacySSLBlockedCount int64             `json:"legacy_ssl_blocked_count"`
	PolicyBlockedCount    int64             `json:"policy_blocked_count"`
	HandshakeFailedCount  int64             `json:"handshake_failed_count"`
	ByProtocol            []ProtocolStat    `json:"by_protocol"`
	ByCipherSuite         []CipherSuiteStat `json:"by_cipher_suite"`
}

// ListFilter 是加密会话明细分页筛选条件。
type ListFilter struct {
	StartTime        *time.Time
	EndTime          *time.Time
	SNI              string
	ClientIP         string
	DetectedProtocol string
	Action           string
	IsGM             *bool
	ApplicationID    *uuid.UUID
	Page             int
	PageSize         int
}

// SummaryFilter 是加密会话汇总统计筛选条件。
type SummaryFilter struct {
	StartTime     *time.Time
	EndTime       *time.Time
	ApplicationID *uuid.UUID
}

// Repository 定义加密会话事件读写与统计仓储契约（PostgreSQL Store 与内存 MemStore 共用）。
type Repository interface {
	Insert(ctx context.Context, e *HandshakeEntry) error
	List(ctx context.Context, f ListFilter) ([]SessionEvent, int64, error)
	Summary(ctx context.Context, f SummaryFilter) (*Summary, error)
}

// Store 是基于 PostgreSQL 的加密会话事件仓储。
type Store struct {
	db DBTX
}

// NewStore 创建 PostgreSQL 加密会话仓储。
func NewStore(db *pgxpool.Pool) *Store {
	return &Store{db: db}
}

// WithDB 返回绑定到指定 DBTX（如批次 pgx.Tx）的浅拷贝。
func (s *Store) WithDB(db DBTX) *Store {
	return &Store{db: db}
}

// Insert 写入一条加密会话握手事件。
func (s *Store) Insert(ctx context.Context, e *HandshakeEntry) error {
	var appID *uuid.UUID
	if e.ApplicationID != "" {
		if id, err := uuid.Parse(e.ApplicationID); err == nil {
			appID = &id
		}
	}
	_, err := s.db.Exec(ctx, `
INSERT INTO tls_handshake_events (
  occurred_at, gateway_node_id, application_id, sni, client_ip,
  client_port, server_port, detected_protocol, negotiated_protocol,
  cipher_suite, is_gm, ja3_hash, alpn, action, error_reason
) VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,$14,$15)`,
		e.OccurredAt, e.GatewayNodeID, appID, e.SNI, e.ClientIP,
		e.ClientPort, e.ServerPort, e.DetectedProtocol, e.NegotiatedProtocol,
		e.CipherSuite, e.IsGM, e.JA3Hash, e.ALPN, e.Action, e.ErrorReason)
	return err
}

// InsertFailure 将损坏/入库失败行写入共享的 event_parse_failures 失败队列。
func (s *Store) InsertFailure(ctx context.Context, collectorID, rawLine, reason string) error {
	if len(rawLine) > 4096 {
		rawLine = rawLine[:4096]
	}
	_, err := s.db.Exec(ctx,
		`INSERT INTO event_parse_failures (collector_id, raw_line, error_reason) VALUES ($1, $2, $3)`,
		collectorID, stripNUL(rawLine), stripNUL(reason))
	return err
}

// buildListWhere 构建参数化 WHERE 子句（禁止字符串拼接用户输入）。
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
	if f.SNI != "" {
		add("sni ILIKE $%d", "%"+f.SNI+"%")
	}
	if f.ClientIP != "" {
		if addr, err := netip.ParseAddr(f.ClientIP); err == nil {
			add("client_ip = $%d", addr.Unmap().String())
		} else {
			add("client_ip ILIKE $%d", f.ClientIP+"%")
		}
	}
	if f.DetectedProtocol != "" {
		add("detected_protocol = $%d", f.DetectedProtocol)
	}
	if f.Action != "" {
		add("action = $%d", f.Action)
	}
	if f.IsGM != nil {
		add("is_gm = $%d", *f.IsGM)
	}
	if f.ApplicationID != nil {
		add("application_id = $%d", *f.ApplicationID)
	}
	return where, args
}

// buildSummaryWhere 构建汇总查询参数化 WHERE 子句。
func buildSummaryWhere(f SummaryFilter) (string, []interface{}) {
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
	return where, args
}

func normalizePagination(page, pageSize int) (int, int) {
	if page <= 0 {
		page = 1
	}
	if pageSize <= 0 {
		pageSize = 20
	}
	if pageSize > 100 {
		pageSize = 100
	}
	return page, pageSize
}

const sessionColumns = `id, occurred_at, gateway_node_id, application_id, sni,
  client_ip, client_port, server_port, detected_protocol, negotiated_protocol,
  cipher_suite, is_gm, ja3_hash, alpn, action, error_reason`

// List 分页查询加密会话握手事件（按 occurred_at DESC 倒序）。
func (s *Store) List(ctx context.Context, f ListFilter) ([]SessionEvent, int64, error) {
	page, pageSize := normalizePagination(f.Page, f.PageSize)
	where, args := buildListWhere(f)

	var total int64
	if err := s.db.QueryRow(ctx, `SELECT count(*) FROM tls_handshake_events WHERE `+where, args...).Scan(&total); err != nil {
		return nil, 0, err
	}

	query := `SELECT ` + sessionColumns + ` FROM tls_handshake_events WHERE ` + where +
		fmt.Sprintf(" ORDER BY occurred_at DESC, id DESC LIMIT $%d OFFSET $%d", len(args)+1, len(args)+2)
	args = append(args, pageSize, (page-1)*pageSize)
	rows, err := s.db.Query(ctx, query, args...)
	if err != nil {
		return nil, 0, err
	}
	defer rows.Close()

	out := make([]SessionEvent, 0)
	for rows.Next() {
		var ev SessionEvent
		if err := rows.Scan(
			&ev.ID, &ev.OccurredAt, &ev.GatewayNodeID, &ev.ApplicationID, &ev.SNI,
			&ev.ClientIP, &ev.ClientPort, &ev.ServerPort, &ev.DetectedProtocol, &ev.NegotiatedProtocol,
			&ev.CipherSuite, &ev.IsGM, &ev.JA3Hash, &ev.ALPN, &ev.Action, &ev.ErrorReason,
		); err != nil {
			return nil, 0, err
		}
		out = append(out, ev)
	}
	return out, total, rows.Err()
}

// Summary 统计加密会话总览、协议分布与密码套件分布。
func (s *Store) Summary(ctx context.Context, f SummaryFilter) (*Summary, error) {
	where, args := buildSummaryWhere(f)
	summary := &Summary{
		ByProtocol:    make([]ProtocolStat, 0),
		ByCipherSuite: make([]CipherSuiteStat, 0),
	}

	if err := s.db.QueryRow(ctx, `
SELECT
  count(*),
  count(*) FILTER (WHERE action = 'ALLOWED'),
  count(*) FILTER (WHERE is_gm = TRUE),
  count(*) FILTER (WHERE is_gm = FALSE),
  count(*) FILTER (WHERE action = 'BLOCKED_LEGACY_SSL'),
  count(*) FILTER (WHERE action = 'BLOCKED_PROTOCOL_POLICY'),
  count(*) FILTER (WHERE action = 'HANDSHAKE_FAILED')
FROM tls_handshake_events
WHERE `+where, args...).Scan(
		&summary.TotalHandshakes,
		&summary.AllowedCount,
		&summary.GMCount,
		&summary.IntlCount,
		&summary.LegacySSLBlockedCount,
		&summary.PolicyBlockedCount,
		&summary.HandshakeFailedCount,
	); err != nil {
		return nil, err
	}

	protoRows, err := s.db.Query(ctx, `
SELECT detected_protocol, count(*) AS cnt, COALESCE(bool_or(is_gm), FALSE) AS has_gm
FROM tls_handshake_events
WHERE `+where+`
GROUP BY detected_protocol
ORDER BY cnt DESC, detected_protocol ASC`, args...)
	if err != nil {
		return nil, err
	}
	defer protoRows.Close()
	for protoRows.Next() {
		var ps ProtocolStat
		var hasGM bool
		if err := protoRows.Scan(&ps.Protocol, &ps.Count, &hasGM); err != nil {
			return nil, err
		}
		ps.IsGM = ps.Protocol == ProtoTLCP11 || hasGM
		ps.IsLegacy = IsLegacyProtocol(ps.Protocol)
		summary.ByProtocol = append(summary.ByProtocol, ps)
	}
	if err := protoRows.Err(); err != nil {
		return nil, err
	}

	cipherRows, err := s.db.Query(ctx, `
SELECT cipher_suite, count(*) AS cnt, COALESCE(bool_or(is_gm), FALSE) AS has_gm
FROM tls_handshake_events
WHERE `+where+` AND cipher_suite <> ''
GROUP BY cipher_suite
ORDER BY cnt DESC, cipher_suite ASC
LIMIT 50`, args...)
	if err != nil {
		return nil, err
	}
	defer cipherRows.Close()
	for cipherRows.Next() {
		var cs CipherSuiteStat
		var hasGM bool
		if err := cipherRows.Scan(&cs.CipherSuite, &cs.Count, &hasGM); err != nil {
			return nil, err
		}
		cs.IsGM = hasGM || IsGMCipherSuiteName(cs.CipherSuite)
		summary.ByCipherSuite = append(summary.ByCipherSuite, cs)
	}
	if err := cipherRows.Err(); err != nil {
		return nil, err
	}

	return summary, nil
}

// ---------- 内存仓储（供单测与无 PG 环境验证全链路 HTTP 查询与聚合行为） ----------

// MemStore 是线程安全的内存加密会话仓储，实现 Repository 接口。
type MemStore struct {
	mu     sync.RWMutex
	events []SessionEvent
}

// NewMemStore 创建内存仓储实例。
func NewMemStore() *MemStore {
	return &MemStore{events: make([]SessionEvent, 0)}
}

// Insert 将握手事件写入内存仓储。
func (m *MemStore) Insert(_ context.Context, e *HandshakeEntry) error {
	if e == nil {
		return fmt.Errorf("nil entry")
	}
	var appID *uuid.UUID
	if e.ApplicationID != "" {
		if parsed, err := uuid.Parse(e.ApplicationID); err == nil {
			appID = &parsed
		}
	}
	ev := SessionEvent{
		ID:                 uuid.New(),
		OccurredAt:         e.OccurredAt.UTC(),
		GatewayNodeID:      e.GatewayNodeID,
		ApplicationID:      appID,
		SNI:                e.SNI,
		ClientIP:           e.ClientIP,
		ClientPort:         e.ClientPort,
		ServerPort:         e.ServerPort,
		DetectedProtocol:   e.DetectedProtocol,
		NegotiatedProtocol: e.NegotiatedProtocol,
		CipherSuite:        e.CipherSuite,
		IsGM:               e.IsGM,
		JA3Hash:            e.JA3Hash,
		ALPN:               e.ALPN,
		Action:             e.Action,
		ErrorReason:        e.ErrorReason,
	}
	m.mu.Lock()
	m.events = append(m.events, ev)
	m.mu.Unlock()
	return nil
}

// List 按与 PostgreSQL Store 一致的筛选、排序与分页口径返回事件。
func (m *MemStore) List(_ context.Context, f ListFilter) ([]SessionEvent, int64, error) {
	page, pageSize := normalizePagination(f.Page, f.PageSize)

	var exactIP string
	ipPrefixLower := ""
	if f.ClientIP != "" {
		if addr, err := netip.ParseAddr(f.ClientIP); err == nil {
			exactIP = addr.Unmap().String()
		} else {
			ipPrefixLower = strings.ToLower(f.ClientIP)
		}
	}
	sniLower := strings.ToLower(f.SNI)

	m.mu.RLock()
	matched := make([]SessionEvent, 0, len(m.events))
	for _, ev := range m.events {
		if f.StartTime != nil && ev.OccurredAt.Before(*f.StartTime) {
			continue
		}
		if f.EndTime != nil && ev.OccurredAt.After(*f.EndTime) {
			continue
		}
		if sniLower != "" && !strings.Contains(strings.ToLower(ev.SNI), sniLower) {
			continue
		}
		if exactIP != "" {
			if ev.ClientIP != exactIP {
				continue
			}
		} else if ipPrefixLower != "" {
			if !strings.HasPrefix(strings.ToLower(ev.ClientIP), ipPrefixLower) {
				continue
			}
		}
		if f.DetectedProtocol != "" && ev.DetectedProtocol != f.DetectedProtocol {
			continue
		}
		if f.Action != "" && ev.Action != f.Action {
			continue
		}
		if f.IsGM != nil && ev.IsGM != *f.IsGM {
			continue
		}
		if f.ApplicationID != nil {
			if ev.ApplicationID == nil || *ev.ApplicationID != *f.ApplicationID {
				continue
			}
		}
		matched = append(matched, ev)
	}
	m.mu.RUnlock()

	sort.Slice(matched, func(i, j int) bool {
		if !matched[i].OccurredAt.Equal(matched[j].OccurredAt) {
			return matched[i].OccurredAt.After(matched[j].OccurredAt)
		}
		return matched[i].ID.String() > matched[j].ID.String()
	})

	total := int64(len(matched))
	start := (page - 1) * pageSize
	if start >= len(matched) {
		return []SessionEvent{}, total, nil
	}
	end := start + pageSize
	if end > len(matched) {
		end = len(matched)
	}
	out := make([]SessionEvent, end-start)
	copy(out, matched[start:end])
	return out, total, nil
}

// Summary 按与 PostgreSQL Store 一致的聚合口径计算汇总统计。
func (m *MemStore) Summary(_ context.Context, f SummaryFilter) (*Summary, error) {
	summary := &Summary{
		ByProtocol:    make([]ProtocolStat, 0),
		ByCipherSuite: make([]CipherSuiteStat, 0),
	}
	protoMap := make(map[string]*ProtocolStat)
	cipherMap := make(map[string]*CipherSuiteStat)

	m.mu.RLock()
	for _, ev := range m.events {
		if f.StartTime != nil && ev.OccurredAt.Before(*f.StartTime) {
			continue
		}
		if f.EndTime != nil && ev.OccurredAt.After(*f.EndTime) {
			continue
		}
		if f.ApplicationID != nil {
			if ev.ApplicationID == nil || *ev.ApplicationID != *f.ApplicationID {
				continue
			}
		}
		summary.TotalHandshakes++
		switch ev.Action {
		case ActionAllowed:
			summary.AllowedCount++
		case ActionBlockedLegacySSL:
			summary.LegacySSLBlockedCount++
		case ActionBlockedProtocolPolicy:
			summary.PolicyBlockedCount++
		case ActionHandshakeFailed:
			summary.HandshakeFailedCount++
		}
		if ev.IsGM {
			summary.GMCount++
		} else {
			summary.IntlCount++
		}

		ps, ok := protoMap[ev.DetectedProtocol]
		if !ok {
			ps = &ProtocolStat{
				Protocol: ev.DetectedProtocol,
				IsGM:     ev.DetectedProtocol == ProtoTLCP11,
				IsLegacy: IsLegacyProtocol(ev.DetectedProtocol),
			}
			protoMap[ev.DetectedProtocol] = ps
		}
		ps.Count++
		if ev.IsGM {
			ps.IsGM = true
		}

		if ev.CipherSuite != "" {
			cs, ok := cipherMap[ev.CipherSuite]
			if !ok {
				cs = &CipherSuiteStat{
					CipherSuite: ev.CipherSuite,
					IsGM:        IsGMCipherSuiteName(ev.CipherSuite),
				}
				cipherMap[ev.CipherSuite] = cs
			}
			cs.Count++
			if ev.IsGM {
				cs.IsGM = true
			}
		}
	}
	m.mu.RUnlock()

	for _, ps := range protoMap {
		summary.ByProtocol = append(summary.ByProtocol, *ps)
	}
	sort.Slice(summary.ByProtocol, func(i, j int) bool {
		if summary.ByProtocol[i].Count != summary.ByProtocol[j].Count {
			return summary.ByProtocol[i].Count > summary.ByProtocol[j].Count
		}
		return summary.ByProtocol[i].Protocol < summary.ByProtocol[j].Protocol
	})

	for _, cs := range cipherMap {
		summary.ByCipherSuite = append(summary.ByCipherSuite, *cs)
	}
	sort.Slice(summary.ByCipherSuite, func(i, j int) bool {
		if summary.ByCipherSuite[i].Count != summary.ByCipherSuite[j].Count {
			return summary.ByCipherSuite[i].Count > summary.ByCipherSuite[j].Count
		}
		return summary.ByCipherSuite[i].CipherSuite < summary.ByCipherSuite[j].CipherSuite
	})
	if len(summary.ByCipherSuite) > 50 {
		summary.ByCipherSuite = summary.ByCipherSuite[:50]
	}

	return summary, nil
}

package accesslogs

import (
	"context"
	"encoding/json"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
)

func TestBuildListWhere(t *testing.T) {
	now := time.Date(2026, 7, 23, 10, 0, 0, 0, time.UTC)
	status := 403

	cases := []struct {
		name         string
		filter       ListFilter
		wantConds    []string // 必须出现的条件片段
		wantNotConds []string // 不得出现的条件片段
		wantArgs     int
	}{
		{
			name:     "empty filter",
			filter:   ListFilter{},
			wantArgs: 0,
		},
		{
			name: "time range",
			filter: ListFilter{
				StartTime: &now, EndTime: &now,
			},
			wantConds: []string{"occurred_at >= $1", "occurred_at < $2"},
			wantArgs:  2,
		},
		{
			name:   "full filter",
			filter: ListFilter{Domain: "waf", ClientIP: "203.0.113.10", Method: "POST", URI: "/login", Status: &status, WAFAction: "BLOCK", RequestID: "req-1"},
			wantConds: []string{
				"domain ILIKE $1", "client_ip = $2::inet", "request_method = $3",
				"request_uri ILIKE $4", "response_status = $5", "waf_action = $6", "request_id = $7",
			},
			wantNotConds: []string{"host(client_ip)"},
			wantArgs:     7,
		},
		{
			name:         "ipv6 client_ip uses inet index predicate",
			filter:       ListFilter{ClientIP: "2001:db8::1"},
			wantConds:    []string{"client_ip = $1::inet"},
			wantNotConds: []string{"host(client_ip)", "1=0"},
			wantArgs:     1,
		},
		{
			name:         "invalid client_ip short-circuits without inet cast error",
			filter:       ListFilter{ClientIP: "not-an-ip"},
			wantConds:    []string{"1=0"},
			wantNotConds: []string{"client_ip ="},
			wantArgs:     0,
		},
		{
			name:         "scoped ipv6 with zone id short-circuits without inet cast error",
			filter:       ListFilter{ClientIP: "fe80::1%eth0"},
			wantConds:    []string{"1=0"},
			wantNotConds: []string{"client_ip ="},
			wantArgs:     0,
		},
		{
			name:         "percent-encoded scoped ipv6 short-circuits without inet cast error",
			filter:       ListFilter{ClientIP: "fe80::1%25eth0"},
			wantConds:    []string{"1=0"},
			wantNotConds: []string{"client_ip ="},
			wantArgs:     0,
		},
		{
			name:         "no injection from user input",
			filter:       ListFilter{Domain: "'; DROP TABLE access_logs;--"},
			wantConds:    []string{"domain ILIKE $1"},
			wantNotConds: []string{"DROP TABLE"},
			wantArgs:     1,
		},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			where, args := buildListWhere(c.filter)
			for _, cond := range c.wantConds {
				if !strings.Contains(where, cond) {
					t.Errorf("where missing %q: %s", cond, where)
				}
			}
			for _, cond := range c.wantNotConds {
				if strings.Contains(where, cond) {
					t.Errorf("where must not contain %q: %s", cond, where)
				}
			}
			if len(args) != c.wantArgs {
				t.Errorf("args = %d, want %d (%s)", len(args), c.wantArgs, where)
			}
		})
	}
}

func TestBuildListWhereArgOrder(t *testing.T) {
	f := ListFilter{Domain: "a", Method: "GET"}
	where, args := buildListWhere(f)
	if !strings.Contains(where, "domain ILIKE $1") || !strings.Contains(where, "request_method = $2") {
		t.Errorf("arg indexes wrong: %s", where)
	}
	if args[0] != "%a%" || args[1] != "GET" {
		t.Errorf("arg values wrong: %v", args)
	}
}

// captureDB 最小 DBTX 假实现：捕获 Insert 的 SQL 与参数并返回 1 行受影响。
type captureDB struct {
	sql  string
	args []interface{}
}

func (c *captureDB) Exec(_ context.Context, sql string, args ...any) (pgconn.CommandTag, error) {
	c.sql = sql
	c.args = args
	return pgconn.NewCommandTag("INSERT 0 1"), nil
}

func (c *captureDB) Query(context.Context, string, ...any) (pgx.Rows, error) {
	return nil, errors.New("not implemented")
}

func (c *captureDB) QueryRow(context.Context, string, ...any) pgx.Row {
	return nil
}

// TestInsertAPMFields APM 阶段1 入库：新列写入参数与可空语义（空串→NULL）、
// waf_action 空串写入侧归一为 ALLOW（ADR D9，历史行不回改）。
func TestInsertAPMFields(t *testing.T) {
	newEntry := func() *LogEntry {
		return &LogEntry{OccurredAt: time.Date(2026, 8, 30, 10, 0, 0, 0, time.UTC), RequestID: "req-1"}
	}
	// 参数位序与 Insert 的 VALUES 一致（$20..$25 = waf_action/trace_id/span_id/endpoint_key/path_template/ttfb_ms）
	const (
		argWAFAction = 19
		argTraceID   = 20
		argSpanID    = 21
		argEndpoint  = 22
		argPathTpl   = 23
		argTTFB      = 24
	)

	t.Run("old gateway entry normalized", func(t *testing.T) {
		db := &captureDB{}
		s := NewStore(nil).WithDB(db)
		inserted, err := s.Insert(context.Background(), newEntry())
		if err != nil || !inserted {
			t.Fatalf("inserted=%v err=%v", inserted, err)
		}
		if !strings.Contains(db.sql, "trace_id") || !strings.Contains(db.sql, "ttfb_ms") {
			t.Errorf("insert sql missing apm columns: %s", db.sql)
		}
		if !strings.Contains(db.sql, "ON CONFLICT (request_id, occurred_at) WHERE request_id <> '' DO NOTHING") {
			t.Errorf("insert sql must include partition key occurred_at in ON CONFLICT: %s", db.sql)
		}
		if strings.Contains(db.sql, "ON CONFLICT (request_id) ") {
			t.Errorf("insert sql must not use non-partitioned ON CONFLICT (request_id): %s", db.sql)
		}
		if db.args[argWAFAction] != "ALLOW" {
			t.Errorf("empty waf_action must normalize to ALLOW, got %v", db.args[argWAFAction])
		}
		for _, i := range []int{argTraceID, argSpanID, argEndpoint, argPathTpl, argTTFB} {
			if db.args[i] != nil {
				t.Errorf("args[%d] must be NULL for old gateway entry, got %v", i, db.args[i])
			}
		}
	})

	t.Run("new gateway entry carries apm fields", func(t *testing.T) {
		db := &captureDB{}
		s := NewStore(nil).WithDB(db)
		e := newEntry()
		e.WAFAction = "BLOCK"
		e.TraceID = "0123456789abcdef0123456789abcdef"
		e.SpanID = "0123456789abcdef"
		e.EndpointKey = "GET /api/users/{id}"
		e.PathTemplate = "/api/users/{id}"
		ttfb := int64(42)
		e.TTFBMs = &ttfb
		if _, err := s.Insert(context.Background(), e); err != nil {
			t.Fatal(err)
		}
		if db.args[argWAFAction] != "BLOCK" {
			t.Errorf("waf_action must pass through, got %v", db.args[argWAFAction])
		}
		if db.args[argTraceID] != e.TraceID || db.args[argSpanID] != e.SpanID {
			t.Errorf("trace/span args wrong: %v %v", db.args[argTraceID], db.args[argSpanID])
		}
		if db.args[argEndpoint] != e.EndpointKey || db.args[argPathTpl] != e.PathTemplate {
			t.Errorf("endpoint args wrong: %v %v", db.args[argEndpoint], db.args[argPathTpl])
		}
		if db.args[argTTFB] != int64(42) {
			t.Errorf("ttfb arg = %v, want 42", db.args[argTTFB])
		}
	})
}

func TestNormalizeWAFAction(t *testing.T) {
	if NormalizeWAFAction("") != "ALLOW" {
		t.Error("empty must normalize to ALLOW")
	}
	if NormalizeWAFAction("BLOCK") != "BLOCK" || NormalizeWAFAction("OBSERVE") != "OBSERVE" {
		t.Error("explicit actions must pass through")
	}
}

func TestNullableIPRejectsScopedIPv6AndMalformed(t *testing.T) {
	if got := nullableIP("203.0.113.10"); got != "203.0.113.10" {
		t.Fatalf("valid IPv4 = %v, want 203.0.113.10", got)
	}
	if got := nullableIP("2001:db8::1"); got != "2001:db8::1" {
		t.Fatalf("valid IPv6 = %v, want 2001:db8::1", got)
	}
	for _, bad := range []string{"", "not-an-ip", "fe80::1%eth0", "fe80::1%25eth0"} {
		if got := nullableIP(bad); got != nil {
			t.Fatalf("nullableIP(%q) = %v, want nil", bad, got)
		}
	}
}

func TestFlowBuilderPreservesEdgeRequestCountAndNodeFilters(t *testing.T) {
	start := time.Date(2026, 11, 19, 0, 0, 0, 0, time.UTC)
	end := start.Add(time.Hour)
	filter := ListFilter{StartTime: &start, EndTime: &end}
	builder := &flowBuilder{
		nodes:       make(map[string]*flowAggregate),
		edges:       make(map[string]*flowAggregate),
		nodeMeta:    make(map[string]FlowNode),
		edgeMeta:    make(map[string]FlowEdge),
		allRequests: make(map[string]struct{}),
		sensitive:   make(map[string]struct{}),
	}
	rows := []flowRow{
		{
			requestID: "req-1", sourceIP: "192.0.2.10", applicationID: "app-1", applicationName: "Shop",
			endpoint: "POST /v1/login", identity: "id-alice", jwtStatus: "VERIFIED",
			eventID: "ev-1", fieldPath: "form.pwd", dataType: "credential", direction: "REQUEST",
		},
		{
			requestID: "req-2", sourceIP: "192.0.2.10", applicationID: "app-1", applicationName: "Shop",
			endpoint: "POST /v1/login", identity: "id-alice", jwtStatus: "VERIFIED",
			eventID: "ev-2", fieldPath: "form.pwd", dataType: "credential", direction: "REQUEST",
		},
		{
			requestID: "req-3", sourceIP: "192.0.2.11", applicationID: "app-1", applicationName: "Shop",
			endpoint: "POST /v1/login", identity: "id-bob", jwtStatus: "VERIFIED",
			eventID: "ev-3", fieldPath: "form.pwd", dataType: "credential", direction: "REQUEST",
		},
	}
	for _, row := range rows {
		builder.addRow(row, filter)
	}

	res := builder.result(start, end, 8)
	if len(res.Edges) == 0 {
		t.Fatal("expected non-empty edges")
	}
	foundSourceToAccount := false
	foundAccountToField := false
	for _, edge := range res.Edges {
		if edge.RequestCount == 0 || edge.RequestCount != len(edge.RequestIDs) {
			t.Fatalf("edge %s RequestCount=%d, want %d (RequestIDs=%v)", edge.ID, edge.RequestCount, len(edge.RequestIDs), edge.RequestIDs)
		}
		if edge.SourceID == "SOURCE:192.0.2.10" && edge.TargetID == "ACCOUNT:id-alice" {
			foundSourceToAccount = true
			if edge.RequestCount != 2 {
				t.Fatalf("SOURCE->ACCOUNT RequestCount=%d, want 2", edge.RequestCount)
			}
			if edge.Filters["client_ip"] != "192.0.2.10" || edge.Filters["identity_fingerprint"] != "id-alice" {
				t.Fatalf("edge did not inherit source/target node filters: %+v", edge.Filters)
			}
		}
		if edge.SourceID == "ACCOUNT:id-alice" && strings.HasPrefix(edge.TargetID, "REQUEST_FIELD:") {
			foundAccountToField = true
			if edge.Filters["identity_fingerprint"] != "id-alice" || edge.Filters["field_path"] != "form.pwd" || edge.Filters["direction"] != "REQUEST" {
				t.Fatalf("account->field edge missing node filters: %+v", edge.Filters)
			}
		}
	}
	if !foundSourceToAccount || !foundAccountToField {
		t.Fatalf("expected edges not found: sourceToAccount=%v accountToField=%v", foundSourceToAccount, foundAccountToField)
	}

	// Verify RequestCount is also populated when nodes collapse into OTHER buckets.
	limited := builder.result(start, end, 1)
	if !limited.Truncated {
		t.Fatal("expected truncated result when nodeLimit=1")
	}
	for _, edge := range limited.Edges {
		if edge.RequestCount == 0 || edge.RequestCount != len(edge.RequestIDs) {
			t.Fatalf("aggregated edge %s RequestCount=%d, want %d", edge.ID, edge.RequestCount, len(edge.RequestIDs))
		}
	}
}

// TestInsertAndSerializeTLSFields 验证迁移 000241 扩展的 5 个 TLS 字段在 Insert 参数、
// SELECT 列与 AccessLog JSON 序列化中向后兼容且完整输出。
func TestInsertAndSerializeTLSFields(t *testing.T) {
	const (
		argTLSProtocol   = 34
		argTLSCipher     = 35
		argTLSIsGM       = 36
		argTLSJA3        = 37
		argClientHelloV  = 38
	)

	t.Run("insert with TLS/GM fields", func(t *testing.T) {
		db := &captureDB{}
		s := NewStore(nil).WithDB(db)
		e := &LogEntry{
			OccurredAt:         time.Date(2026, 11, 25, 10, 0, 0, 0, time.UTC),
			RequestID:          "req-tls-1",
			TLSProtocol:        "TLCP1.1",
			TLSCipherSuite:     "TLCP_ECC_SM4_GCM_SM3",
			TLSIsGM:            true,
			TLSJA3:             "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
			ClientHelloVersion: "TLCP1.1",
		}
		if _, err := s.Insert(context.Background(), e); err != nil {
			t.Fatal(err)
		}
		for _, col := range []string{"tls_protocol", "tls_cipher_suite", "tls_is_gm", "tls_ja3", "client_hello_version"} {
			if !strings.Contains(db.sql, col) {
				t.Errorf("insert SQL missing %s: %s", col, db.sql)
			}
			if !strings.Contains(listColumns, col) {
				t.Errorf("listColumns missing %s", col)
			}
		}
		if len(db.args) != 39 {
			t.Fatalf("insert args count = %d, want 39", len(db.args))
		}
		if db.args[argTLSProtocol] != "TLCP1.1" || db.args[argTLSCipher] != "TLCP_ECC_SM4_GCM_SM3" ||
			db.args[argTLSIsGM] != true || db.args[argTLSJA3] != "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa" ||
			db.args[argClientHelloV] != "TLCP1.1" {
			t.Fatalf("TLS insert args mismatch: %#v", db.args[argTLSProtocol:])
		}
	})

	t.Run("legacy entry defaults to empty and false", func(t *testing.T) {
		db := &captureDB{}
		s := NewStore(nil).WithDB(db)
		if _, err := s.Insert(context.Background(), &LogEntry{
			OccurredAt: time.Date(2026, 11, 25, 10, 0, 0, 0, time.UTC),
			RequestID:  "req-old-1",
		}); err != nil {
			t.Fatal(err)
		}
		if db.args[argTLSProtocol] != "" || db.args[argTLSCipher] != "" ||
			db.args[argTLSIsGM] != false || db.args[argTLSJA3] != "" || db.args[argClientHelloV] != "" {
			t.Fatalf("legacy TLS insert args should default empty/false: %#v", db.args[argTLSProtocol:])
		}
	})

	t.Run("AccessLog JSON always includes all 5 TLS keys", func(t *testing.T) {
		raw, err := json.Marshal(AccessLog{})
		if err != nil {
			t.Fatal(err)
		}
		var m map[string]any
		if err := json.Unmarshal(raw, &m); err != nil {
			t.Fatal(err)
		}
		for _, k := range []string{"tls_protocol", "tls_cipher_suite", "tls_is_gm", "tls_ja3", "client_hello_version"} {
			if _, ok := m[k]; !ok {
				t.Errorf("AccessLog JSON missing key %q: %s", k, string(raw))
			}
		}
	})
}

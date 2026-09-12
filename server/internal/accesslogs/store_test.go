package accesslogs

import (
	"context"
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
			wantConds: []string{"occurred_at >= $1", "occurred_at <= $2"},
			wantArgs:  2,
		},
		{
			name:   "full filter",
			filter: ListFilter{Domain: "waf", ClientIP: "203.0.113.10", Method: "POST", URI: "/login", Status: &status, WAFAction: "BLOCK", RequestID: "req-1"},
			wantConds: []string{
				"domain ILIKE $1", "host(client_ip) = $2", "request_method = $3",
				"request_uri ILIKE $4", "response_status = $5", "waf_action = $6", "request_id = $7",
			},
			wantArgs: 7,
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

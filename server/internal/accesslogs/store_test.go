package accesslogs

import (
	"strings"
	"testing"
	"time"
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

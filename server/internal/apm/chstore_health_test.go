// chstore_health_test.go CHHealth 数据面健康/滞后读数单测（fake CHQuerier 注入：
// Ping 成败、表存在性、最新遥测 NULL/有值、查询失败上抛）。
package apm

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"testing"
	"time"
)

// healthFakeRows 预置行的 CHRows（支持 *uint8 与 **time.Time 扫描目标）。
type healthFakeRows struct {
	scans [][]any
	idx   int
	err   error
}

func (r *healthFakeRows) Next() bool { return r.idx < len(r.scans) }

func (r *healthFakeRows) Scan(dest ...any) error {
	row := r.scans[r.idx]
	r.idx++
	if len(dest) != len(row) {
		return fmt.Errorf("scan arity = %d, want %d", len(dest), len(row))
	}
	for i, v := range row {
		switch d := dest[i].(type) {
		case *uint8:
			*d, _ = v.(uint8)
		case **time.Time:
			*d, _ = v.(*time.Time)
		default:
			return fmt.Errorf("unsupported scan dest %T", dest[i])
		}
	}
	return nil
}

func (r *healthFakeRows) Close() error { return nil }
func (r *healthFakeRows) Err() error   { return r.err }

// healthFakeQuerier 按调用序返回预置结果（记录 SQL 供断言）。
type healthFakeQuerier struct {
	queries []string
	results []*healthFakeRows
	err     error
}

func (q *healthFakeQuerier) Query(_ context.Context, query string, _ ...any) (CHRows, error) {
	q.queries = append(q.queries, query)
	if q.err != nil {
		return nil, q.err
	}
	if len(q.results) == 0 {
		return &healthFakeRows{}, nil
	}
	r := q.results[0]
	q.results = q.results[1:]
	return r, nil
}

// TestCHHealthPing 连通性轻探测：查询成功（含空行集）为通；查询/迭代失败上抛。
func TestCHHealthPing(t *testing.T) {
	ctx := context.Background()
	q := &healthFakeQuerier{}
	if err := NewCHHealth(q).Ping(ctx); err != nil {
		t.Fatalf("ping: %v", err)
	}
	if len(q.queries) != 1 || q.queries[0] != "SELECT 1" {
		t.Errorf("ping query = %v, want SELECT 1", q.queries)
	}
	qErr := &healthFakeQuerier{err: errors.New("connection refused")}
	if err := NewCHHealth(qErr).Ping(ctx); err == nil {
		t.Fatal("query error must propagate")
	}
	qRows := &healthFakeQuerier{results: []*healthFakeRows{{err: errors.New("iterate boom")}}}
	if err := NewCHHealth(qRows).Ping(ctx); err == nil {
		t.Fatal("rows error must propagate")
	}
}

// TestCHHealthTracesTableExists 表存在性：1/0 映射 bool；查询失败上抛；SQL 走元数据。
func TestCHHealthTracesTableExists(t *testing.T) {
	ctx := context.Background()
	q := &healthFakeQuerier{results: []*healthFakeRows{{scans: [][]any{{uint8(1)}}}}}
	ok, err := NewCHHealth(q).TracesTableExists(ctx)
	if err != nil || !ok {
		t.Errorf("exists = %v, %v, want true, nil", ok, err)
	}
	if len(q.queries) != 1 || !strings.Contains(q.queries[0], "EXISTS TABLE apm.otel_traces") {
		t.Errorf("query = %v, want EXISTS TABLE apm.otel_traces", q.queries)
	}

	q = &healthFakeQuerier{results: []*healthFakeRows{{scans: [][]any{{uint8(0)}}}}}
	ok, err = NewCHHealth(q).TracesTableExists(ctx)
	if err != nil || ok {
		t.Errorf("missing = %v, %v, want false, nil", ok, err)
	}

	qErr := &healthFakeQuerier{err: errors.New("ch down")}
	if _, err := NewCHHealth(qErr).TracesTableExists(ctx); err == nil {
		t.Fatal("query error must propagate")
	}
}

// TestCHHealthLatestIngestAt 最新遥测：有值返回 UTC；NULL（表空）ok=false 非错误；
// 查询失败上抛。
func TestCHHealthLatestIngestAt(t *testing.T) {
	ctx := context.Background()
	ts := time.Date(2026, 8, 31, 11, 59, 30, 0, time.UTC)
	q := &healthFakeQuerier{results: []*healthFakeRows{{scans: [][]any{{&ts}}}}}
	got, ok, err := NewCHHealth(q).LatestIngestAt(ctx)
	if err != nil || !ok || !got.Equal(ts) {
		t.Errorf("latest = %v, %v, %v, want %v, true, nil", got, ok, err, ts)
	}
	if len(q.queries) != 1 || !strings.Contains(q.queries[0], "max(Timestamp) FROM apm.otel_traces") {
		t.Errorf("query = %v, want max(Timestamp) FROM apm.otel_traces", q.queries)
	}

	// 表空：max(Timestamp) 为 NULL → ok=false（无数据非故障）
	q = &healthFakeQuerier{results: []*healthFakeRows{{scans: [][]any{{(*time.Time)(nil)}}}}}
	_, ok, err = NewCHHealth(q).LatestIngestAt(ctx)
	if err != nil || ok {
		t.Errorf("empty = %v, %v, want false, nil", ok, err)
	}

	qErr := &healthFakeQuerier{err: errors.New("ch down")}
	if _, _, err := NewCHHealth(qErr).LatestIngestAt(ctx); err == nil {
		t.Fatal("query error must propagate")
	}
}

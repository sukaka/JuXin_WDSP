// 九章 §55 性能矩阵缺口项（大规模维度）本机测量程序。
//
// 口径声明：本程序逐字复刻 server 侧仓储 SQL（不改生产代码，仅复制查询语句）：
//  1. guardconfig.Provider.BuildGuardConfig 的 API 段五个规模敏感查询
//     （server/internal/apimodels/store.go ListFormalSchemas / ListFormalModelVersions、
//     server/internal/apimodels/parameters.go ListFormalParameterConstraints、
//     server/internal/apimodels/relations.go ListConfirmedParameterRelations、
//     server/internal/apiassets/store.go ListKeyStatus），
//     含 provider.go 中相同的 Go 侧组装（map 构建 / jsonb 解码 / 结构转换）与
//     json.Marshal 序列化（字段名与 gatewayconfig.GuardConfig 一致），
//     计量：各查询耗时、组装总耗时、产物字节数、构建期堆内存增量。
//  2. 图谱查询（server/internal/apisecurity/store.go ListGraphFiltered 节点查询 /
//     listEdges 三种过滤形态 / ListTopologyFiltered / metrics 边总数计数），
//     每项 21 次全行扫描计量 P50/P95/max，并各留一份 EXPLAIN (ANALYZE, BUFFERS)。
//
// 用法：PERF_DSN=postgres://... go run . -runs 5 -graph-runs 21 -raw /tmp/w23-raw
package main

import (
	"bytes"
	"compress/gzip"
	"context"
	"encoding/json"
	"flag"
	"fmt"
	"os"
	"path/filepath"
	"runtime"
	"sort"
	"strconv"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"
)

func gzipBytes(b []byte) []byte {
	var buf bytes.Buffer
	w := gzip.NewWriter(&buf)
	_, _ = w.Write(b)
	_ = w.Close()
	return buf.Bytes()
}

func gzipLen(b []byte) int { return len(gzipBytes(b)) }

// ---------- 逐字复刻的生产 SQL（来源见文件头注释） ----------

// server/internal/apimodels/store.go ListFormalSchemas
const sqlFormalSchemas = `
SELECT DISTINCT ON (endpoint_key) endpoint_key, schema_json
FROM api_model_versions WHERE status='FORMAL'
ORDER BY endpoint_key, confirmed_at DESC NULLS LAST`

// server/internal/apimodels/store.go ListFormalModelVersions
const sqlFormalModelVersions = `
SELECT DISTINCT ON (endpoint_key) endpoint_key, version_number
FROM api_model_versions WHERE status='FORMAL'
ORDER BY endpoint_key, confirmed_at DESC NULLS LAST`

// server/internal/apimodels/parameters.go ListFormalParameterConstraints
const sqlFormalParamConstraints = `
WITH formal AS (
    SELECT DISTINCT ON (endpoint_key) id, endpoint_key
    FROM api_model_versions WHERE status='FORMAL'
    ORDER BY endpoint_key, confirmed_at DESC NULLS LAST
)
SELECT f.endpoint_key, p.location, p.parameter_name, p.structured_path, p.base_type, p.required,
       COALESCE(p.semantic_type,''), p.confirmed_constraints
FROM formal f
JOIN api_parameter_models p ON p.model_version_id = f.id
WHERE p.direction='REQUEST'
  AND (p.required OR p.confirmed_constraints <> '{}'::jsonb OR COALESCE(p.semantic_type,'') <> '')
ORDER BY f.endpoint_key, p.location, p.parameter_name`

// server/internal/apimodels/relations.go ListConfirmedParameterRelations
const sqlConfirmedParamRelations = `
WITH formal AS (
    SELECT DISTINCT ON (endpoint_key) id, endpoint_key
    FROM api_model_versions WHERE status='FORMAL'
    ORDER BY endpoint_key, confirmed_at DESC NULLS LAST
)
SELECT f.endpoint_key, r.relation_type,
       a.location, a.structured_path, a.parameter_name,
       b.location, b.structured_path, b.parameter_name
FROM formal f
JOIN api_parameter_relations r ON r.model_version_id = f.id AND r.confirmed
JOIN api_parameter_models a ON a.id = r.source_parameter_id
JOIN api_parameter_models b ON b.id = r.target_parameter_id
ORDER BY f.endpoint_key, r.relation_type, a.parameter_name, b.parameter_name`

// server/internal/apiassets/store.go ListKeyStatus
const sqlKeyStatus = `SELECT endpoint_key, asset_status FROM api_endpoints`

// server/internal/apisecurity/store.go ListGraphFiltered 节点查询（activeFindingsJoin 逐字）
const activeFindingsJoin = `
LEFT JOIN (
    SELECT endpoint_id, count(*) AS open_count FROM api_runtime_findings
    WHERE status IN ('NEW','CONFIRMED','IN_PROGRESS') GROUP BY endpoint_id
) f ON f.endpoint_id = e.id`

const sqlGraphNodes = `
SELECT e.id, e.endpoint_key, e.http_method, e.normalized_path, e.application_id,
       e.asset_status, e.learning_status, e.hit_count, COALESCE(f.open_count, 0)
FROM api_endpoints e` + activeFindingsJoin + `
ORDER BY e.endpoint_key`

// server/internal/apisecurity/store.go ListTopologyFiltered 节点查询
const sqlTopologyNodes = `
SELECT e.id, e.endpoint_key, e.http_method, e.normalized_path, e.application_id,
       e.asset_status, e.learning_status, e.hit_count, COALESCE(a.name, ''), COALESCE(f.open_count, 0)
FROM api_endpoints e
LEFT JOIN applications a ON a.id = e.application_id` + activeFindingsJoin + `
ORDER BY e.application_id NULLS LAST, e.endpoint_key`

// server/internal/apisecurity/store.go listEdges（三种过滤形态，值参数化同生产）
const sqlEdgesAll = `
SELECT id, caller_fingerprint, source_endpoint_id, target_endpoint_id, call_count, identity_count, first_seen_at, last_seen_at
FROM api_call_edges WHERE TRUE ORDER BY call_count DESC`

const sqlEdgesTimeRange = `
SELECT id, caller_fingerprint, source_endpoint_id, target_endpoint_id, call_count, identity_count, first_seen_at, last_seen_at
FROM api_call_edges WHERE TRUE AND last_seen_at >= $1 AND first_seen_at <= $2 ORDER BY call_count DESC`

const sqlEdgesMinCount = `
SELECT id, caller_fingerprint, source_endpoint_id, target_endpoint_id, call_count, identity_count, first_seen_at, last_seen_at
FROM api_call_edges WHERE TRUE AND call_count >= $1 ORDER BY call_count DESC`

// server/internal/metrics/api_collector.go 图谱边数量指标
const sqlEdgesCount = `SELECT count(*) FROM api_call_edges`

// ---------- 与 gatewayconfig.GuardConfig 相同 json tag 的下发结构 ----------

type guardParamConstraint struct {
	Location    string         `json:"location"`
	Name        string         `json:"name"`
	Path        string         `json:"path"`
	BaseType    string         `json:"base_type"`
	Required    bool           `json:"required"`
	Constraints map[string]any `json:"constraints"`
}

type guardParamRef struct {
	Location string `json:"location"`
	Path     string `json:"path"`
	Name     string `json:"name"`
}

type guardParamRelation struct {
	EndpointKey  string        `json:"endpoint_key"`
	RelationType string        `json:"relation_type"`
	ParamA       guardParamRef `json:"param_a"`
	ParamB       guardParamRef `json:"param_b"`
}

type graphEdge struct {
	ID        string
	Caller    string
	Source    *string
	Target    string
	CallCount int64
	IdentCnt  int
	FirstSeen time.Time
	LastSeen  time.Time
}

type queryStat struct {
	Name string    `json:"name"`
	Rows int       `json:"rows"`
	Runs []float64 `json:"runs_ms"`
	P50  float64   `json:"p50_ms"`
	P95  float64   `json:"p95_ms"`
	Min  float64   `json:"min_ms"`
	Max  float64   `json:"max_ms"`
}

type report struct {
	StartedAt    string      `json:"started_at"`
	DSN          string      `json:"-"`
	BuildQueries []queryStat `json:"build_queries"`
	BuildTotalMs float64     `json:"build_total_median_ms"`
	MarshalMs    []float64   `json:"marshal_ms"`
	MarshalP50   float64     `json:"marshal_p50_ms"`
	ConfigBytes  int         `json:"config_json_bytes"`
	GzipBytes    int         `json:"config_gzip_bytes"`
	HeapBaseline uint64      `json:"heap_baseline_bytes"`
	HeapAfter    uint64      `json:"heap_after_build_bytes"`
	HeapDelta    uint64      `json:"heap_delta_bytes"`
	TotalAlloc   uint64      `json:"total_alloc_during_build_bytes"`
	GraphQueries []queryStat `json:"graph_queries"`
}

func percentile(sorted []float64, p float64) float64 {
	if len(sorted) == 0 {
		return 0
	}
	idx := int(p * float64(len(sorted)-1))
	return sorted[idx]
}

func summarize(name string, rows int, runs []float64) queryStat {
	s := append([]float64(nil), runs...)
	sort.Float64s(s)
	return queryStat{
		Name: name, Rows: rows, Runs: runs,
		P50: percentile(s, 0.50), P95: percentile(s, 0.95),
		Min: s[0], Max: s[len(s)-1],
	}
}

func main() {
	runs := flag.Int("runs", 5, "构建路径每个查询的计量次数")
	graphRuns := flag.Int("graph-runs", 21, "图谱查询每项计量次数")
	rawDir := flag.String("raw", "", "EXPLAIN 等原始输出目录")
	flag.Parse()

	dsn := os.Getenv("PERF_DSN")
	if dsn == "" {
		fmt.Fprintln(os.Stderr, "PERF_DSN is required")
		os.Exit(2)
	}
	ctx := context.Background()
	pool, err := pgxpool.New(ctx, dsn)
	if err != nil {
		fmt.Fprintln(os.Stderr, "connect:", err)
		os.Exit(1)
	}
	defer pool.Close()

	if *rawDir != "" {
		if err := os.MkdirAll(*rawDir, 0o755); err != nil {
			fmt.Fprintln(os.Stderr, "mkdir raw:", err)
			os.Exit(1)
		}
	}

	rep := &report{StartedAt: time.Now().Format(time.RFC3339)}

	// ---------- 阶段 A：下发构建（API 段） ----------
	fmt.Println("== 阶段A：下发构建 API 段（逐字复刻 store SQL + provider 组装） ==")

	var memBase, memStart runtime.MemStats
	runtime.GC()
	runtime.ReadMemStats(&memBase)
	runtime.ReadMemStats(&memStart)
	allocBefore := memStart.TotalAlloc

	// 1) ListFormalSchemas
	var schemas map[string]map[string]string
	var st queryStat
	st, schemas = benchQuery(*runs, "ListFormalSchemas", func() (int, error) {
		rows, err := pool.Query(ctx, sqlFormalSchemas)
		if err != nil {
			return 0, err
		}
		defer rows.Close()
		out := map[string]map[string]string{}
		for rows.Next() {
			var key string
			var raw []byte
			if err := rows.Scan(&key, &raw); err != nil {
				return 0, err
			}
			var schema map[string]string
			if err := json.Unmarshal(raw, &schema); err != nil {
				return 0, err
			}
			out[key] = schema
		}
		schemas = out
		return len(out), rows.Err()
	})
	rep.BuildQueries = append(rep.BuildQueries, st)
	printStat(st)

	// 2) ListFormalModelVersions
	var versions map[string]string
	st, _ = benchQuery(*runs, "ListFormalModelVersions", func() (int, error) {
		rows, err := pool.Query(ctx, sqlFormalModelVersions)
		if err != nil {
			return 0, err
		}
		defer rows.Close()
		out := map[string]string{}
		for rows.Next() {
			var key string
			var vn int
			if err := rows.Scan(&key, &vn); err != nil {
				return 0, err
			}
			out[key] = strconv.Itoa(vn)
		}
		versions = out
		return len(out), rows.Err()
	})
	rep.BuildQueries = append(rep.BuildQueries, st)
	printStat(st)

	// 3) ListFormalParameterConstraints（含 provider.go 的 GuardParamConstraint 转换）
	var constraints map[string][]guardParamConstraint
	st, _ = benchQuery(*runs, "ListFormalParameterConstraints", func() (int, error) {
		rows, err := pool.Query(ctx, sqlFormalParamConstraints)
		if err != nil {
			return 0, err
		}
		defer rows.Close()
		type paramConstraint struct {
			Location, Name, Path, BaseType, SemanticType string
			Required                                     bool
			Constraints                                  map[string]any
		}
		tmp := map[string][]paramConstraint{}
		n := 0
		for rows.Next() {
			var key string
			var pc paramConstraint
			var raw []byte
			if err := rows.Scan(&key, &pc.Location, &pc.Name, &pc.Path, &pc.BaseType, &pc.Required, &pc.SemanticType, &raw); err != nil {
				return 0, err
			}
			if len(raw) > 0 {
				_ = json.Unmarshal(raw, &pc.Constraints)
			}
			tmp[key] = append(tmp[key], pc)
			n++
		}
		if err := rows.Err(); err != nil {
			return 0, err
		}
		// provider.go BuildGuardConfig 的 out 转换（逐字段拷贝）
		out := make(map[string][]guardParamConstraint, len(tmp))
		for ek, list := range tmp {
			items := make([]guardParamConstraint, 0, len(list))
			for _, pc := range list {
				items = append(items, guardParamConstraint{
					Location: pc.Location, Name: pc.Name, Path: pc.Path,
					BaseType: pc.BaseType, Required: pc.Required, Constraints: pc.Constraints,
				})
			}
			out[ek] = items
		}
		constraints = out
		return n, nil
	})
	rep.BuildQueries = append(rep.BuildQueries, st)
	printStat(st)

	// 4) ListConfirmedParameterRelations（含 provider.go 的 GuardParamRelation 转换）
	var relations []guardParamRelation
	st, _ = benchQuery(*runs, "ListConfirmedParameterRelations", func() (int, error) {
		rows, err := pool.Query(ctx, sqlConfirmedParamRelations)
		if err != nil {
			return 0, err
		}
		defer rows.Close()
		out := []guardParamRelation{}
		for rows.Next() {
			var rel guardParamRelation
			if err := rows.Scan(&rel.EndpointKey, &rel.RelationType,
				&rel.ParamA.Location, &rel.ParamA.Path, &rel.ParamA.Name,
				&rel.ParamB.Location, &rel.ParamB.Path, &rel.ParamB.Name); err != nil {
				return 0, err
			}
			out = append(out, rel)
		}
		relations = out
		return len(out), rows.Err()
	})
	rep.BuildQueries = append(rep.BuildQueries, st)
	printStat(st)

	// 5) ListKeyStatus
	var known map[string]string
	st, _ = benchQuery(*runs, "ListKeyStatus", func() (int, error) {
		rows, err := pool.Query(ctx, sqlKeyStatus)
		if err != nil {
			return 0, err
		}
		defer rows.Close()
		out := map[string]string{}
		for rows.Next() {
			var key, status string
			if err := rows.Scan(&key, &status); err != nil {
				return 0, err
			}
			out[key] = status
		}
		known = out
		return len(out), rows.Err()
	})
	rep.BuildQueries = append(rep.BuildQueries, st)
	printStat(st)

	var total float64
	for _, q := range rep.BuildQueries {
		total += q.P50
	}
	rep.BuildTotalMs = total
	fmt.Printf("  API 段五查询 P50 合计: %.1f ms\n", total)

	// 序列化：与 GuardConfig 相同 json 字段名组装下发产物
	payload := map[string]any{
		"api_formal_schemas":        schemas,
		"api_formal_model_versions": versions,
		"api_parameter_constraints": constraints,
		"api_parameter_relations":   relations,
		"api_known_endpoints":       known,
	}
	var configBytes []byte
	for i := 0; i < *runs; i++ {
		t0 := time.Now()
		b, err := json.Marshal(payload)
		if err != nil {
			fmt.Fprintln(os.Stderr, "marshal:", err)
			os.Exit(1)
		}
		rep.MarshalMs = append(rep.MarshalMs, float64(time.Since(t0).Microseconds())/1000.0)
		configBytes = b
	}
	srt := append([]float64(nil), rep.MarshalMs...)
	sort.Float64s(srt)
	rep.MarshalP50 = percentile(srt, 0.50)
	rep.ConfigBytes = len(configBytes)
	rep.GzipBytes = gzipLen(configBytes)
	fmt.Printf("  下发产物: json=%d 字节 (%.2f MB) gzip=%d 字节 (%.2f MB) marshal P50=%.1f ms\n",
		rep.ConfigBytes, float64(rep.ConfigBytes)/1048576, rep.GzipBytes, float64(rep.GzipBytes)/1048576, rep.MarshalP50)

	if *rawDir != "" {
		_ = os.WriteFile(filepath.Join(*rawDir, "guard-config-api-segments.json.gz"), gzipBytes(configBytes), 0o644)
	}

	var memEnd runtime.MemStats
	runtime.GC()
	runtime.ReadMemStats(&memEnd)
	rep.HeapBaseline = memBase.HeapAlloc
	rep.HeapAfter = memEnd.HeapAlloc
	if memEnd.HeapAlloc >= memBase.HeapAlloc {
		rep.HeapDelta = memEnd.HeapAlloc - memBase.HeapAlloc
	}
	rep.TotalAlloc = memEnd.TotalAlloc - allocBefore
	fmt.Printf("  构建期堆内存: baseline=%.1f MB after=%.1f MB delta=%.1f MB totalAlloc=%.1f MB\n",
		float64(rep.HeapBaseline)/1048576, float64(rep.HeapAfter)/1048576,
		float64(rep.HeapDelta)/1048576, float64(rep.TotalAlloc)/1048576)

	// ---------- 阶段 B：图谱查询 ----------
	fmt.Println("== 阶段B：图谱查询（全行扫描计量） ==")
	graphCases := []struct {
		name string
		sql  string
		args []any
	}{
		{"graph_nodes(ListGraphFiltered)", sqlGraphNodes, nil},
		{"topology_nodes(ListTopologyFiltered)", sqlTopologyNodes, nil},
		{"edges_all(listEdges无过滤)", sqlEdgesAll, nil},
		{"edges_timerange(近24h)", sqlEdgesTimeRange, []any{time.Now().Add(-24 * time.Hour), time.Now()}},
		{"edges_mincount(>=1000)", sqlEdgesMinCount, []any{1000}},
		{"edges_count(metrics)", sqlEdgesCount, nil},
	}
	for _, c := range graphCases {
		var runsMs []float64
		var rowCnt int
		for i := 0; i < *graphRuns; i++ {
			t0 := time.Now()
			n, err := scanAll(pool, ctx, c.sql, c.args)
			if err != nil {
				fmt.Fprintf(os.Stderr, "graph query %s: %v\n", c.name, err)
				os.Exit(1)
			}
			rowCnt = n
			runsMs = append(runsMs, float64(time.Since(t0).Microseconds())/1000.0)
		}
		gs := summarize(c.name, rowCnt, runsMs)
		rep.GraphQueries = append(rep.GraphQueries, gs)
		printStat(gs)
		if *rawDir != "" {
			saveExplain(pool, ctx, *rawDir, c)
		}
	}

	out, _ := json.MarshalIndent(rep, "", "  ")
	if *rawDir != "" {
		_ = os.WriteFile(filepath.Join(*rawDir, "w23-bench-summary.json"), out, 0o644)
	}
	fmt.Println(string(out))
}

func benchQuery(runs int, name string, fn func() (int, error)) (queryStat, map[string]map[string]string) {
	var runsMs []float64
	var n int
	for i := 0; i < runs; i++ {
		t0 := time.Now()
		cnt, err := fn()
		if err != nil {
			fmt.Fprintf(os.Stderr, "query %s: %v\n", name, err)
			os.Exit(1)
		}
		n = cnt
		runsMs = append(runsMs, float64(time.Since(t0).Microseconds())/1000.0)
	}
	return summarize(name, n, runsMs), nil
}

func printStat(s queryStat) {
	fmt.Printf("  %-42s rows=%-8d runs=%d  P50=%.1f ms  P95=%.1f ms  min=%.1f  max=%.1f\n",
		s.Name, s.Rows, len(s.Runs), s.P50, s.P95, s.Min, s.Max)
}

// scanAll 执行查询并全行扫描（与生产 rows.Next 循环同成本），返回行数。
func scanAll(pool *pgxpool.Pool, ctx context.Context, sql string, args []any) (int, error) {
	rows, err := pool.Query(ctx, sql, args...)
	if err != nil {
		return 0, err
	}
	defer rows.Close()
	n := 0
	for rows.Next() {
		vals, err := rows.Values()
		if err != nil {
			return 0, err
		}
		_ = vals
		n++
	}
	return n, rows.Err()
}

func saveExplain(pool *pgxpool.Pool, ctx context.Context, dir string, c struct {
	name string
	sql  string
	args []any
}) {
	rows, err := pool.Query(ctx, "EXPLAIN (ANALYZE, BUFFERS) "+c.sql, c.args...)
	if err != nil {
		return
	}
	defer rows.Close()
	var out string
	for rows.Next() {
		var line string
		if err := rows.Scan(&line); err != nil {
			return
		}
		out += line + "\n"
	}
	_ = os.WriteFile(filepath.Join(dir, "explain-"+sanitize(c.name)+".txt"), []byte(out), 0o644)
}

func sanitize(s string) string {
	out := []rune{}
	for _, r := range s {
		switch {
		case r >= 'a' && r <= 'z', r >= 'A' && r <= 'Z', r >= '0' && r <= '9', r == '-', r == '_':
			out = append(out, r)
		default:
			out = append(out, '_')
		}
	}
	return string(out)
}

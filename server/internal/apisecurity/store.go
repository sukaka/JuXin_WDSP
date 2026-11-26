// Package apisecurity 阶段8（WDSP）任务书 51.4 分类图谱 / 51.5 规范导入 / 51.6 风险运行时接口。
package apisecurity

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/jiuzhang-waf/gateway/dynamic_security/classifier"
)

// ErrNotFound 资源不存在（端点/规范）。
var ErrNotFound = errors.New("api security resource not found")

// Store API 安全仓储。
type Store struct {
	db *pgxpool.Pool
}

// NewStore 创建。
func NewStore(db *pgxpool.Pool) *Store { return &Store{db: db} }

// ---------- 用途分类（任务书 51.4） ----------

// ClassificationItem 内置分类（api_classifications）。
type ClassificationItem struct {
	ID          uuid.UUID `json:"id"`
	Code        string    `json:"code"`
	Name        string    `json:"name"`
	Description string    `json:"description"`
	IsBuiltin   bool      `json:"is_builtin"`
	CreatedAt   time.Time `json:"created_at"`
}

// CustomTaxonomyItem 自定义分类法（api_custom_taxonomies）。
type CustomTaxonomyItem struct {
	ID          uuid.UUID  `json:"id"`
	Dimension   string     `json:"dimension"`
	Value       string     `json:"value"`
	Description string     `json:"description"`
	CreatedBy   *uuid.UUID `json:"created_by,omitempty"`
	CreatedAt   time.Time  `json:"created_at"`
}

// ClassificationList 内置 + 自定义合并列表。
type ClassificationList struct {
	Builtin []ClassificationItem `json:"builtin"`
	Custom  []CustomTaxonomyItem `json:"custom"`
}

// ListClassifications 内置分类与自定义分类法合并返回。
func (s *Store) ListClassifications(ctx context.Context) (*ClassificationList, error) {
	out := &ClassificationList{
		Builtin: []ClassificationItem{},
		Custom:  []CustomTaxonomyItem{},
	}
	rows, err := s.db.Query(ctx, `
SELECT id, code, name, description, is_builtin, created_at
FROM api_classifications ORDER BY is_builtin DESC, code`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	for rows.Next() {
		var it ClassificationItem
		if err := rows.Scan(&it.ID, &it.Code, &it.Name, &it.Description, &it.IsBuiltin, &it.CreatedAt); err != nil {
			return nil, err
		}
		out.Builtin = append(out.Builtin, it)
	}
	if err := rows.Err(); err != nil {
		return nil, err
	}

	rows2, err := s.db.Query(ctx, `
SELECT id, dimension, value, description, created_by, created_at
FROM api_custom_taxonomies ORDER BY dimension, value`)
	if err != nil {
		return nil, err
	}
	defer rows2.Close()
	for rows2.Next() {
		var it CustomTaxonomyItem
		if err := rows2.Scan(&it.ID, &it.Dimension, &it.Value, &it.Description, &it.CreatedBy, &it.CreatedAt); err != nil {
			return nil, err
		}
		out.Custom = append(out.Custom, it)
	}
	return out, rows2.Err()
}

// ExistsCustomTaxonomy 判断同 (dimension, value) 自定义分类条目是否已存在。
func (s *Store) ExistsCustomTaxonomy(ctx context.Context, dimension, value string) (bool, error) {
	var exists bool
	err := s.db.QueryRow(ctx,
		`SELECT EXISTS(SELECT 1 FROM api_custom_taxonomies WHERE dimension = $1 AND value = $2)`,
		dimension, value).Scan(&exists)
	return exists, err
}

// CreateCustomTaxonomy 新增自定义分类法条目；同 (dimension, value) 冲突返回错误。
func (s *Store) CreateCustomTaxonomy(ctx context.Context, item *CustomTaxonomyItem) error {
	err := s.db.QueryRow(ctx, `
INSERT INTO api_custom_taxonomies (dimension, value, description, created_by)
VALUES ($1, $2, $3, $4)
RETURNING id, created_at`,
		item.Dimension, item.Value, item.Description, item.CreatedBy).
		Scan(&item.ID, &item.CreatedAt)
	return err
}

// ClassificationDimension 端点分类维度（api_classification_dimensions）。
type ClassificationDimension struct {
	Dimension  string     `json:"dimension"`
	Value      string     `json:"value"`
	Source     string     `json:"source"`
	Confidence float64    `json:"confidence"`
	UpdatedAt  *time.Time `json:"updated_at,omitempty"`
}

// EndpointExists 判断端点是否存在。
func (s *Store) EndpointExists(ctx context.Context, endpointID uuid.UUID) (bool, error) {
	var exists bool
	err := s.db.QueryRow(ctx, `SELECT EXISTS(SELECT 1 FROM api_endpoints WHERE id = $1)`, endpointID).Scan(&exists)
	return exists, err
}

// GetEndpointDimensions 读取端点当前分类维度（审计前摘要/响应用）。
func (s *Store) GetEndpointDimensions(ctx context.Context, endpointID uuid.UUID) ([]ClassificationDimension, error) {
	rows, err := s.db.Query(ctx, `
SELECT dimension, value, source, confidence, updated_at
FROM api_classification_dimensions WHERE endpoint_id = $1 ORDER BY dimension`, endpointID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := []ClassificationDimension{}
	for rows.Next() {
		var d ClassificationDimension
		if err := rows.Scan(&d.Dimension, &d.Value, &d.Source, &d.Confidence, &d.UpdatedAt); err != nil {
			return nil, err
		}
		out = append(out, d)
	}
	return out, rows.Err()
}

// SetEndpointClassification 手动覆盖端点分类维度：
// 逐维 upsert（source=MANUAL）并锁定 api_endpoints.classification_locked，整体一个事务。
func (s *Store) SetEndpointClassification(ctx context.Context, endpointID uuid.UUID, dims []ClassificationDimension) error {
	tx, err := s.db.Begin(ctx)
	if err != nil {
		return err
	}
	defer func() { _ = tx.Rollback(ctx) }()
	for _, d := range dims {
		if _, err := tx.Exec(ctx, `
INSERT INTO api_classification_dimensions (endpoint_id, dimension, value, source, confidence, updated_at)
VALUES ($1, $2, $3, 'MANUAL', 1, now())
ON CONFLICT (endpoint_id, dimension)
DO UPDATE SET value = EXCLUDED.value, source = 'MANUAL', confidence = 1, updated_at = now()`,
			endpointID, d.Dimension, d.Value); err != nil {
			return err
		}
	}
	// 手动分类后锁定，防止自动分类覆盖
	ct, err := tx.Exec(ctx, `UPDATE api_endpoints SET classification_locked = TRUE, updated_at = now() WHERE id = $1`, endpointID)
	if err != nil {
		return err
	}
	if ct.RowsAffected() == 0 {
		return ErrNotFound
	}
	return tx.Commit(ctx)
}

// ---------- 调用图谱 / 拓扑（任务书 51.4） ----------

// GraphNode 图谱节点（api_endpoints 摘要）。
type GraphNode struct {
	ID              uuid.UUID  `json:"id"`
	EndpointKey     string     `json:"endpoint_key"`
	HTTPMethod      string     `json:"http_method"`
	NormalizedPath  string     `json:"normalized_path"`
	ApplicationID   *uuid.UUID `json:"application_id,omitempty"`
	ApplicationName string     `json:"application_name,omitempty"`
	Host            string     `json:"host,omitempty"`
	ProtocolType    string     `json:"protocol_type,omitempty"`
	IsAPI           bool       `json:"is_api"`
	AssetStatus     string     `json:"asset_status"`
	LearningStatus  string     `json:"learning_status"`
	HitCount        int64      `json:"hit_count"`
	// 未闭环风险发现数（活动状态 NEW/CONFIRMED/IN_PROGRESS，000042 七态词表，
	// 口径与 GetPosture 一致；W6-A 图谱/拓扑节点风险计数）
	OpenFindingsCount int64 `json:"open_findings_count"`
}

// GraphEdge 调用边（api_call_edges）。
type GraphEdge struct {
	ID                uuid.UUID  `json:"id"`
	CallerFingerprint string     `json:"caller_fingerprint"`
	SourceEndpointID  *uuid.UUID `json:"source_endpoint_id,omitempty"`
	TargetEndpointID  uuid.UUID  `json:"target_endpoint_id"`
	CallCount         int64      `json:"call_count"`
	// 走过该边的 distinct 身份数（近似下界；000067 起，派生口径见
	// aggregations/call_edges.go 文件头：首见身份计 1，同身份重复经过不增）
	IdentityCount int64     `json:"identity_count"`
	FirstSeenAt   time.Time `json:"first_seen_at"`
	LastSeenAt    time.Time `json:"last_seen_at"`
}

// GraphSummary 身份调用轨迹图谱过滤前后统计摘要（便于界面直观提示噪声与孤立点数量）。
type GraphSummary struct {
	TotalNodes       int `json:"total_nodes"`
	VisibleNodes     int `json:"visible_nodes"`
	StaticNoiseNodes int `json:"static_noise_nodes"`
	IgnoredNodes     int `json:"ignored_nodes"`
	IsolatedNodes    int `json:"isolated_nodes"`
	TotalEdges       int `json:"total_edges"`
	VisibleEdges     int `json:"visible_edges"`
}

// Graph 调用图谱（节点 + 调用边 + 可选摘要）。
type Graph struct {
	Nodes   []GraphNode   `json:"nodes"`
	Edges   []GraphEdge   `json:"edges"`
	Summary *GraphSummary `json:"summary,omitempty"`
}

const (
	// DefaultGraphEdgeLimit 图谱/拓扑调用边默认返回上限（兼顾响应体大小与性能）。
	DefaultGraphEdgeLimit = 5000
	// MaxGraphEdgeLimit 图谱/拓扑调用边单次最大允许返回上限。
	MaxGraphEdgeLimit = 10000
	// graphCandidateArrayThreshold 小规模候选节点直接用 = ANY(uuid[]) 命中目标边索引；
	// 大规模候选节点改用 JOIN api_endpoints（附带少数静态噪声排除 ID），避免大数组线性退化。
	graphCandidateArrayThreshold = 2000
	// findingsNodeIDBatchThreshold 可见节点数不超过该阈值时按 endpoint_id = ANY($1) 精准聚合未闭环发现数。
	findingsNodeIDBatchThreshold = 5000
)

func normalizeGraphEdgeLimit(limit int) int {
	if limit <= 0 {
		return DefaultGraphEdgeLimit
	}
	if limit > MaxGraphEdgeLimit {
		return MaxGraphEdgeLimit
	}
	return limit
}

// EdgeFilter 调用边过滤（W6-A 图谱/拓扑读接口增强）。零值 = 不过滤（按 DefaultGraphEdgeLimit 上限返回）。
// 时间窗按「边在窗口内有观测」语义匹配：last_seen_at >= Start 且 first_seen_at <= End。
type EdgeFilter struct {
	Start    *time.Time // 边活跃窗口下界（last_seen_at 不早于 Start）
	End      *time.Time // 边活跃窗口上界（first_seen_at 不晚于 End）
	MinCount int64      // 最小调用次数（call_count >= MinCount）
	Limit    int        // 返回边数上限（<=0 默认 DefaultGraphEdgeLimit，上限 MaxGraphEdgeLimit）
}

// GraphFilter 图谱读接口完整过滤条件（含节点与边过滤；零值完全兼容历史全量返回语义）。
type GraphFilter struct {
	EdgeFilter
	ApplicationID  *uuid.UUID // 可选：仅查看指定应用的接口节点及边
	Status         string     // 可选：资产状态白名单过滤
	Keyword        string     // 可选：按 endpoint_key / 路径 / 应用名 / Host 关键字过滤
	ExcludeStatic  bool       // 排除静态资源与非 API 噪声节点（永不排除 CONFIRMED）
	ExcludeIgnored bool       // 排除 IGNORED 状态节点
	OnlyConnected  bool       // 仅保留至少有 1 条边关联的节点
}

type pgQueryer interface {
	Query(ctx context.Context, sql string, args ...any) (pgx.Rows, error)
	QueryRow(ctx context.Context, sql string, args ...any) pgx.Row
}

type edgeQueryScope struct {
	candidateIDs      []uuid.UUID
	excludedStaticIDs []uuid.UUID
	nodeFilter        *GraphFilter
}

// isGraphStaticNoiseNode 判断图谱节点是否属于静态资源或非 API 噪声（保护 CONFIRMED 正式资产）。
func isGraphStaticNoiseNode(n GraphNode) bool {
	if strings.EqualFold(strings.TrimSpace(n.AssetStatus), "CONFIRMED") {
		return false
	}
	if !n.IsAPI {
		return true
	}
	if matched, _ := classifier.DefaultStaticFilter().MatchStaticPath(n.HTTPMethod, n.NormalizedPath); matched {
		return true
	}
	return false
}

// buildGraphNodeWhere 构建 api_endpoints (e) / applications (a) 节点过滤 WHERE 子句（不含 WHERE）。
func buildGraphNodeWhere(f GraphFilter) (where string, args []any, hasNodeFilter bool, needsAppJoin bool) {
	return buildGraphNodeWhereWithAliases(f, "e", "a", 1)
}

func buildGraphNodeWhereWithAliases(f GraphFilter, epAlias, appAlias string, startArgIdx int) (where string, args []any, hasNodeFilter bool, needsAppJoin bool) {
	clauses := []string{}
	epPrefix := ""
	if epAlias != "" {
		epPrefix = epAlias + "."
	}
	appPrefix := ""
	if appAlias != "" {
		appPrefix = appAlias + "."
	}
	if f.ExcludeIgnored {
		clauses = append(clauses, epPrefix+"asset_status <> 'IGNORED'")
		hasNodeFilter = true
	}
	if f.ExcludeStatic {
		clauses = append(clauses, fmt.Sprintf("(%sasset_status = 'CONFIRMED' OR %sis_api = TRUE)", epPrefix, epPrefix))
		hasNodeFilter = true
	}
	if f.ApplicationID != nil {
		args = append(args, *f.ApplicationID)
		clauses = append(clauses, fmt.Sprintf("%sapplication_id = $%d", epPrefix, startArgIdx+len(args)-1))
		hasNodeFilter = true
	}
	if st := strings.ToUpper(strings.TrimSpace(f.Status)); st != "" {
		args = append(args, st)
		clauses = append(clauses, fmt.Sprintf("%sasset_status = $%d", epPrefix, startArgIdx+len(args)-1))
		hasNodeFilter = true
	}
	if kw := strings.ToLower(strings.TrimSpace(f.Keyword)); kw != "" {
		args = append(args, kw)
		clauses = append(clauses, fmt.Sprintf(
			"strpos(lower(COALESCE(%sendpoint_key, '') || ' ' || COALESCE(%snormalized_path, '') || ' ' || COALESCE(%sname, '') || ' ' || COALESCE(%shost, '')), $%d) > 0",
			epPrefix, epPrefix, appPrefix, epPrefix, startArgIdx+len(args)-1,
		))
		hasNodeFilter = true
		needsAppJoin = true
	}
	if len(clauses) == 0 {
		return "TRUE", args, false, false
	}
	return strings.Join(clauses, " AND "), args, true, needsAppJoin
}

func buildEdgeWhere(alias string, f EdgeFilter, startArgIdx int) (string, []any) {
	prefix := ""
	if alias != "" {
		prefix = alias + "."
	}
	clauses := []string{}
	args := []any{}
	if f.Start != nil {
		args = append(args, *f.Start)
		clauses = append(clauses, fmt.Sprintf("%slast_seen_at >= $%d", prefix, startArgIdx+len(args)-1))
	}
	if f.End != nil {
		args = append(args, *f.End)
		clauses = append(clauses, fmt.Sprintf("%sfirst_seen_at <= $%d", prefix, startArgIdx+len(args)-1))
	}
	if f.MinCount > 0 {
		args = append(args, f.MinCount)
		clauses = append(clauses, fmt.Sprintf("%scall_count >= $%d", prefix, startArgIdx+len(args)-1))
	}
	if len(clauses) == 0 {
		return "TRUE", args
	}
	return strings.Join(clauses, " AND "), args
}

const graphEdgeColumns = `id, caller_fingerprint, source_endpoint_id, target_endpoint_id, call_count, identity_count, first_seen_at, last_seen_at`

func shouldUseTwoPhaseEdgeFetch(f EdgeFilter, scope edgeQueryScope) bool {
	return scope.candidateIDs != nil || scope.nodeFilter != nil || f.Start != nil || f.End != nil
}

func buildListEdgesByIDsQuery() string {
	return `SELECT ` + graphEdgeColumns + ` FROM api_call_edges WHERE id = ANY($1::uuid[])`
}

func restoreGraphEdgeOrder(ids []uuid.UUID, byID map[uuid.UUID]GraphEdge) []GraphEdge {
	out := make([]GraphEdge, 0, len(ids))
	for _, id := range ids {
		if e, ok := byID[id]; ok {
			out = append(out, e)
		}
	}
	return out
}

func buildListEdgesQuery(f EdgeFilter, scope edgeQueryScope) (query string, args []any, idOnly bool) {
	limit := normalizeGraphEdgeLimit(f.Limit)
	if scope.candidateIDs != nil && len(scope.candidateIDs) > graphCandidateArrayThreshold && scope.nodeFilter != nil {
		edgeWhere, args := buildEdgeWhere("e", f, 1)
		teWhere, nodeArgs, hasNode, needsAppJoin := buildGraphNodeWhereWithAliases(*scope.nodeFilter, "te", "ta", len(args)+1)
		if hasNode {
			seWhere, _, _, _ := buildGraphNodeWhereWithAliases(*scope.nodeFilter, "se", "sa", len(args)+1)
			args = append(args, nodeArgs...)
			joins := "JOIN api_endpoints te ON te.id = e.target_endpoint_id\nLEFT JOIN api_endpoints se ON se.id = e.source_endpoint_id"
			if needsAppJoin {
				joins += "\nLEFT JOIN applications ta ON ta.id = te.application_id\nLEFT JOIN applications sa ON sa.id = se.application_id"
			}
			where := fmt.Sprintf("%s AND (%s) AND (e.source_endpoint_id IS NULL OR (%s))", edgeWhere, teWhere, seWhere)
			if len(scope.excludedStaticIDs) > 0 {
				args = append(args, scope.excludedStaticIDs)
				idx := len(args)
				where += fmt.Sprintf(" AND NOT (e.target_endpoint_id = ANY($%d::uuid[])) AND (e.source_endpoint_id IS NULL OR NOT (e.source_endpoint_id = ANY($%d::uuid[])))", idx, idx)
			}
			args = append(args, limit)
			query := fmt.Sprintf(`
SELECT e.id
FROM api_call_edges e
%s
WHERE %s
ORDER BY e.call_count DESC, e.id
LIMIT $%d`, joins, where, len(args))
			return query, args, true
		}
	}

	where, args := buildEdgeWhere("", f, 1)
	if scope.candidateIDs != nil {
		args = append(args, scope.candidateIDs)
		idx := len(args)
		where += fmt.Sprintf(" AND target_endpoint_id = ANY($%d::uuid[]) AND (source_endpoint_id IS NULL OR source_endpoint_id = ANY($%d::uuid[]))", idx, idx)
	}
	args = append(args, limit)
	idOnly = shouldUseTwoPhaseEdgeFetch(f, scope)
	selectCols := graphEdgeColumns
	if idOnly {
		selectCols = "id"
	}
	query = fmt.Sprintf(`
SELECT %s
FROM api_call_edges WHERE %s ORDER BY call_count DESC, id LIMIT $%d`, selectCols, where, len(args))
	return query, args, idOnly
}

// applyGraphFilter 对原始图谱执行节点/边过滤并生成摘要统计（纯逻辑，不依赖数据库）。
func applyGraphFilter(raw *Graph, f GraphFilter) *Graph {
	if raw == nil {
		return &Graph{
			Nodes:   []GraphNode{},
			Edges:   []GraphEdge{},
			Summary: &GraphSummary{},
		}
	}
	summary := &GraphSummary{
		TotalNodes: len(raw.Nodes),
		TotalEdges: len(raw.Edges),
	}
	kw := strings.ToLower(strings.TrimSpace(f.Keyword))
	statusFilter := strings.ToUpper(strings.TrimSpace(f.Status))

	candidateNodes := make([]GraphNode, 0, len(raw.Nodes))
	allowedIDs := make(map[uuid.UUID]struct{}, len(raw.Nodes))
	for _, n := range raw.Nodes {
		isStaticNoise := isGraphStaticNoiseNode(n)
		if isStaticNoise {
			summary.StaticNoiseNodes++
		}
		isIgnored := strings.EqualFold(strings.TrimSpace(n.AssetStatus), "IGNORED")
		if isIgnored {
			summary.IgnoredNodes++
		}
		if f.ExcludeStatic && isStaticNoise {
			continue
		}
		if f.ExcludeIgnored && isIgnored {
			continue
		}
		if f.ApplicationID != nil {
			if n.ApplicationID == nil || *n.ApplicationID != *f.ApplicationID {
				continue
			}
		}
		if statusFilter != "" && !strings.EqualFold(strings.TrimSpace(n.AssetStatus), statusFilter) {
			continue
		}
		if kw != "" {
			hay := strings.ToLower(n.EndpointKey + " " + n.NormalizedPath + " " + n.ApplicationName + " " + n.Host)
			if !strings.Contains(hay, kw) {
				continue
			}
		}
		candidateNodes = append(candidateNodes, n)
		allowedIDs[n.ID] = struct{}{}
	}

	filteredEdges := make([]GraphEdge, 0, len(raw.Edges))
	connectedIDs := make(map[uuid.UUID]struct{}, len(candidateNodes))
	for _, e := range raw.Edges {
		if _, ok := allowedIDs[e.TargetEndpointID]; !ok {
			continue
		}
		if e.SourceEndpointID != nil {
			if _, ok := allowedIDs[*e.SourceEndpointID]; !ok {
				continue
			}
			connectedIDs[*e.SourceEndpointID] = struct{}{}
		}
		connectedIDs[e.TargetEndpointID] = struct{}{}
		filteredEdges = append(filteredEdges, e)
	}

	visibleNodes := make([]GraphNode, 0, len(candidateNodes))
	for _, n := range candidateNodes {
		_, connected := connectedIDs[n.ID]
		if !connected {
			summary.IsolatedNodes++
			if f.OnlyConnected {
				continue
			}
		}
		visibleNodes = append(visibleNodes, n)
	}
	summary.VisibleNodes = len(visibleNodes)
	summary.VisibleEdges = len(filteredEdges)

	return &Graph{
		Nodes:   visibleNodes,
		Edges:   filteredEdges,
		Summary: summary,
	}
}

// activeFindingsJoin 未闭环 findings 计数子查询（活动状态口径同 GetPosture），
// 供拓扑接口 LEFT JOIN 附带 open_findings_count（排除 endpoint_id IS NULL 行）。
const activeFindingsJoin = `
LEFT JOIN (
    SELECT endpoint_id, count(*) AS open_count FROM api_runtime_findings
    WHERE endpoint_id IS NOT NULL AND status IN ('NEW','CONFIRMED','IN_PROGRESS') GROUP BY endpoint_id
) f ON f.endpoint_id = e.id`

// ListGraph 全量节点与调用边（边按 DefaultGraphEdgeLimit 封顶；aitools.APISecurityReader 契约保持无参形态）。
func (s *Store) ListGraph(ctx context.Context) (*Graph, error) {
	return s.ListGraphWithFilter(ctx, GraphFilter{})
}

// ListGraphFiltered 全量节点 + 按 EdgeFilter 过滤后的调用边（保持既有签名兼容）。
func (s *Store) ListGraphFiltered(ctx context.Context, f EdgeFilter) (*Graph, error) {
	return s.ListGraphWithFilter(ctx, GraphFilter{EdgeFilter: f})
}

func (s *Store) loadGraphNodeSummary(ctx context.Context, q pgQueryer) (*GraphSummary, error) {
	summary := &GraphSummary{}
	var nonAPINoiseNodes int
	err := q.QueryRow(ctx, `
SELECT
    count(*)::int,
    count(*) FILTER (WHERE upper(btrim(asset_status)) = 'IGNORED')::int,
    count(*) FILTER (WHERE upper(btrim(asset_status)) <> 'CONFIRMED' AND NOT is_api)::int
FROM api_endpoints`).Scan(&summary.TotalNodes, &summary.IgnoredNodes, &nonAPINoiseNodes)
	if err != nil {
		return nil, err
	}
	summary.StaticNoiseNodes = nonAPINoiseNodes
	if summary.TotalNodes == 0 {
		return summary, nil
	}
	rows, err := q.Query(ctx, `
SELECT http_method, normalized_path
FROM api_endpoints
WHERE upper(btrim(asset_status)) <> 'CONFIRMED'
  AND is_api = TRUE
  AND upper(btrim(http_method)) IN ('', 'GET', 'HEAD', 'OPTIONS')
  AND normalized_path LIKE '%.%'`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	staticFilter := classifier.DefaultStaticFilter()
	for rows.Next() {
		var method, normPath string
		if err := rows.Scan(&method, &normPath); err != nil {
			return nil, err
		}
		if matched, _ := staticFilter.MatchStaticPath(method, normPath); matched {
			summary.StaticNoiseNodes++
		}
	}
	if err := rows.Err(); err != nil {
		return nil, err
	}
	return summary, nil
}

func (s *Store) queryFullGraphNodes(ctx context.Context, q pgQueryer, where string, args ...any) ([]GraphNode, error) {
	rows, err := q.Query(ctx, `
SELECT e.id, e.endpoint_key, e.http_method, e.normalized_path, e.application_id,
       COALESCE(a.name, ''), COALESCE(e.host, ''), COALESCE(e.protocol_type, 'REST'), e.is_api,
       e.asset_status, e.learning_status, e.hit_count
FROM api_endpoints e
LEFT JOIN applications a ON a.id = e.application_id
WHERE `+where+`
ORDER BY e.endpoint_key, e.host, e.id`, args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	nodes := []GraphNode{}
	for rows.Next() {
		var n GraphNode
		if err := rows.Scan(&n.ID, &n.EndpointKey, &n.HTTPMethod, &n.NormalizedPath,
			&n.ApplicationID, &n.ApplicationName, &n.Host, &n.ProtocolType, &n.IsAPI,
			&n.AssetStatus, &n.LearningStatus, &n.HitCount); err != nil {
			return nil, err
		}
		nodes = append(nodes, n)
	}
	return nodes, rows.Err()
}

func (s *Store) populateOpenFindingsCounts(ctx context.Context, q pgQueryer, nodes []GraphNode) error {
	if len(nodes) == 0 {
		return nil
	}
	var (
		rows pgx.Rows
		err  error
	)
	if len(nodes) <= findingsNodeIDBatchThreshold {
		ids := make([]uuid.UUID, len(nodes))
		for i := range nodes {
			ids[i] = nodes[i].ID
		}
		rows, err = q.Query(ctx, `
SELECT endpoint_id, count(*)
FROM api_runtime_findings
WHERE status IN ('NEW','CONFIRMED','IN_PROGRESS')
  AND endpoint_id = ANY($1::uuid[])
GROUP BY endpoint_id`, ids)
	} else {
		rows, err = q.Query(ctx, `
SELECT endpoint_id, count(*)
FROM api_runtime_findings
WHERE endpoint_id IS NOT NULL
  AND status IN ('NEW','CONFIRMED','IN_PROGRESS')
GROUP BY endpoint_id`)
	}
	if err != nil {
		return err
	}
	defer rows.Close()
	counts := make(map[uuid.UUID]int64, len(nodes))
	for rows.Next() {
		var epID uuid.UUID
		var cnt int64
		if err := rows.Scan(&epID, &cnt); err != nil {
			return err
		}
		counts[epID] = cnt
	}
	if err := rows.Err(); err != nil {
		return err
	}
	for i := range nodes {
		if cnt, ok := counts[nodes[i].ID]; ok {
			nodes[i].OpenFindingsCount = cnt
		}
	}
	return nil
}

func collectConnectedNodeIDs(edges []GraphEdge) ([]uuid.UUID, map[uuid.UUID]struct{}) {
	seen := make(map[uuid.UUID]struct{}, len(edges)*2)
	ids := make([]uuid.UUID, 0, len(edges)*2)
	for _, e := range edges {
		if _, ok := seen[e.TargetEndpointID]; !ok {
			seen[e.TargetEndpointID] = struct{}{}
			ids = append(ids, e.TargetEndpointID)
		}
		if e.SourceEndpointID != nil {
			if _, ok := seen[*e.SourceEndpointID]; !ok {
				seen[*e.SourceEndpointID] = struct{}{}
				ids = append(ids, *e.SourceEndpointID)
			}
		}
	}
	return ids, seen
}

func (s *Store) countEdgesWithQueryer(ctx context.Context, q pgQueryer, f EdgeFilter) (int, error) {
	where, args := buildEdgeWhere("", f, 1)
	var total int
	err := q.QueryRow(ctx, `SELECT count(*)::int FROM api_call_edges WHERE `+where, args...).Scan(&total)
	return total, err
}

func (s *Store) listEdgesWithQueryer(ctx context.Context, q pgQueryer, f EdgeFilter, scope edgeQueryScope) ([]GraphEdge, error) {
	if scope.candidateIDs != nil && len(scope.candidateIDs) == 0 {
		return []GraphEdge{}, nil
	}
	query, args, idOnly := buildListEdgesQuery(f, scope)
	if !idOnly {
		rows, err := q.Query(ctx, query, args...)
		if err != nil {
			return nil, err
		}
		defer rows.Close()
		out := []GraphEdge{}
		for rows.Next() {
			var e GraphEdge
			if err := rows.Scan(&e.ID, &e.CallerFingerprint, &e.SourceEndpointID,
				&e.TargetEndpointID, &e.CallCount, &e.IdentityCount, &e.FirstSeenAt, &e.LastSeenAt); err != nil {
				return nil, err
			}
			out = append(out, e)
		}
		return out, rows.Err()
	}

	// 两阶段窄排序：Step 1 仅对 (call_count DESC, id) 排序并取 id（避免 Sort 携带宽 caller_fingerprint 溢出 4MB work_mem），
	// Step 2 按主键 ANY($1::uuid[]) 无序回表并在 Go 侧按 Step 1 顺序恢复。
	idRows, err := q.Query(ctx, query, args...)
	if err != nil {
		return nil, err
	}
	defer idRows.Close()
	ids := []uuid.UUID{}
	for idRows.Next() {
		var id uuid.UUID
		if err := idRows.Scan(&id); err != nil {
			return nil, err
		}
		ids = append(ids, id)
	}
	if err := idRows.Err(); err != nil {
		return nil, err
	}
	idRows.Close()

	if len(ids) == 0 {
		return []GraphEdge{}, nil
	}

	detailRows, err := q.Query(ctx, buildListEdgesByIDsQuery(), ids)
	if err != nil {
		return nil, err
	}
	defer detailRows.Close()
	byID := make(map[uuid.UUID]GraphEdge, len(ids))
	for detailRows.Next() {
		var e GraphEdge
		if err := detailRows.Scan(&e.ID, &e.CallerFingerprint, &e.SourceEndpointID,
			&e.TargetEndpointID, &e.CallCount, &e.IdentityCount, &e.FirstSeenAt, &e.LastSeenAt); err != nil {
			return nil, err
		}
		byID[e.ID] = e
	}
	if err := detailRows.Err(); err != nil {
		return nil, err
	}
	return restoreGraphEdgeOrder(ids, byID), nil
}

// ListGraphWithFilter 节点与调用边按 GraphFilter SQL 下推过滤并返回过滤前后精确摘要统计。
func (s *Store) ListGraphWithFilter(ctx context.Context, f GraphFilter) (*Graph, error) {
	tx, err := s.db.BeginTx(ctx, pgx.TxOptions{
		IsoLevel:   pgx.RepeatableRead,
		AccessMode: pgx.ReadOnly,
	})
	if err != nil {
		return nil, err
	}
	defer func() { _ = tx.Rollback(ctx) }()

	edgeLimit := normalizeGraphEdgeLimit(f.Limit)
	nodeWhere, nodeArgs, hasNodeFilter, needsAppJoin := buildGraphNodeWhere(f)

	if !hasNodeFilter && !f.OnlyConnected {
		nodes, err := s.queryFullGraphNodes(ctx, tx, "TRUE")
		if err != nil {
			return nil, err
		}
		summary := &GraphSummary{TotalNodes: len(nodes)}
		for _, n := range nodes {
			if isGraphStaticNoiseNode(n) {
				summary.StaticNoiseNodes++
			}
			if strings.EqualFold(strings.TrimSpace(n.AssetStatus), "IGNORED") {
				summary.IgnoredNodes++
			}
		}
		edges, err := s.listEdgesWithQueryer(ctx, tx, f.EdgeFilter, edgeQueryScope{})
		if err != nil {
			return nil, err
		}
		if len(edges) < edgeLimit {
			summary.TotalEdges = len(edges)
		} else {
			summary.TotalEdges, err = s.countEdgesWithQueryer(ctx, tx, f.EdgeFilter)
			if err != nil {
				return nil, err
			}
		}
		_, connectedSet := collectConnectedNodeIDs(edges)
		for _, n := range nodes {
			if _, ok := connectedSet[n.ID]; !ok {
				summary.IsolatedNodes++
			}
		}
		summary.VisibleNodes = len(nodes)
		summary.VisibleEdges = len(edges)
		if err := s.populateOpenFindingsCounts(ctx, tx, nodes); err != nil {
			return nil, err
		}
		return &Graph{Nodes: nodes, Edges: edges, Summary: summary}, nil
	}

	summary, err := s.loadGraphNodeSummary(ctx, tx)
	if err != nil {
		return nil, err
	}
	if summary.TotalNodes == 0 {
		return &Graph{Nodes: []GraphNode{}, Edges: []GraphEdge{}, Summary: summary}, nil
	}

	if !hasNodeFilter && f.OnlyConnected {
		edges, err := s.listEdgesWithQueryer(ctx, tx, f.EdgeFilter, edgeQueryScope{})
		if err != nil {
			return nil, err
		}
		if len(edges) < edgeLimit {
			summary.TotalEdges = len(edges)
		} else {
			summary.TotalEdges, err = s.countEdgesWithQueryer(ctx, tx, f.EdgeFilter)
			if err != nil {
				return nil, err
			}
		}
		connectedIDs, _ := collectConnectedNodeIDs(edges)
		nodes := []GraphNode{}
		if len(connectedIDs) > 0 {
			nodes, err = s.queryFullGraphNodes(ctx, tx, "e.id = ANY($1::uuid[])", connectedIDs)
			if err != nil {
				return nil, err
			}
		}
		summary.VisibleNodes = len(nodes)
		summary.VisibleEdges = len(edges)
		summary.IsolatedNodes = summary.TotalNodes - len(nodes)
		if err := s.populateOpenFindingsCounts(ctx, tx, nodes); err != nil {
			return nil, err
		}
		return &Graph{Nodes: nodes, Edges: edges, Summary: summary}, nil
	}

	totalEdges, err := s.countEdgesWithQueryer(ctx, tx, f.EdgeFilter)
	if err != nil {
		return nil, err
	}
	summary.TotalEdges = totalEdges

	if !f.OnlyConnected {
		rawNodes, err := s.queryFullGraphNodes(ctx, tx, nodeWhere, nodeArgs...)
		if err != nil {
			return nil, err
		}
		nodes := make([]GraphNode, 0, len(rawNodes))
		candidateIDs := make([]uuid.UUID, 0, len(rawNodes))
		var excludedStaticIDs []uuid.UUID
		for _, n := range rawNodes {
			if f.ExcludeStatic && isGraphStaticNoiseNode(n) {
				excludedStaticIDs = append(excludedStaticIDs, n.ID)
				continue
			}
			nodes = append(nodes, n)
			candidateIDs = append(candidateIDs, n.ID)
		}
		edges, err := s.listEdgesWithQueryer(ctx, tx, f.EdgeFilter, edgeQueryScope{
			candidateIDs:      candidateIDs,
			excludedStaticIDs: excludedStaticIDs,
			nodeFilter:        &f,
		})
		if err != nil {
			return nil, err
		}
		_, connectedSet := collectConnectedNodeIDs(edges)
		for _, n := range nodes {
			if _, ok := connectedSet[n.ID]; !ok {
				summary.IsolatedNodes++
			}
		}
		summary.VisibleNodes = len(nodes)
		summary.VisibleEdges = len(edges)
		if err := s.populateOpenFindingsCounts(ctx, tx, nodes); err != nil {
			return nil, err
		}
		return &Graph{Nodes: nodes, Edges: edges, Summary: summary}, nil
	}

	// hasNodeFilter && f.OnlyConnected：轻量级筛选候选端点 ID，避免对大量孤立节点做应用 JOIN 与全字段拉取。
	candidateSQL := `SELECT e.id, e.http_method, e.normalized_path, e.is_api, e.asset_status FROM api_endpoints e`
	if needsAppJoin {
		candidateSQL += ` LEFT JOIN applications a ON a.id = e.application_id`
	}
	candidateSQL += ` WHERE ` + nodeWhere
	candRows, err := tx.Query(ctx, candidateSQL, nodeArgs...)
	if err != nil {
		return nil, err
	}
	defer candRows.Close()
	candidateIDs := []uuid.UUID{}
	var excludedStaticIDs []uuid.UUID
	for candRows.Next() {
		var (
			id       uuid.UUID
			method   string
			normPath string
			isAPI    bool
			status   string
		)
		if err := candRows.Scan(&id, &method, &normPath, &isAPI, &status); err != nil {
			return nil, err
		}
		if f.ExcludeStatic && isGraphStaticNoiseNode(GraphNode{
			HTTPMethod:     method,
			NormalizedPath: normPath,
			IsAPI:          isAPI,
			AssetStatus:    status,
		}) {
			excludedStaticIDs = append(excludedStaticIDs, id)
			continue
		}
		candidateIDs = append(candidateIDs, id)
	}
	if err := candRows.Err(); err != nil {
		return nil, err
	}
	candRows.Close()

	if len(candidateIDs) == 0 {
		return &Graph{Nodes: []GraphNode{}, Edges: []GraphEdge{}, Summary: summary}, nil
	}

	edges, err := s.listEdgesWithQueryer(ctx, tx, f.EdgeFilter, edgeQueryScope{
		candidateIDs:      candidateIDs,
		excludedStaticIDs: excludedStaticIDs,
		nodeFilter:        &f,
	})
	if err != nil {
		return nil, err
	}
	connectedIDs, _ := collectConnectedNodeIDs(edges)
	summary.IsolatedNodes = len(candidateIDs) - len(connectedIDs)

	nodes := []GraphNode{}
	if len(connectedIDs) > 0 {
		nodes, err = s.queryFullGraphNodes(ctx, tx, "e.id = ANY($1::uuid[])", connectedIDs)
		if err != nil {
			return nil, err
		}
	}
	summary.VisibleNodes = len(nodes)
	summary.VisibleEdges = len(edges)
	if err := s.populateOpenFindingsCounts(ctx, tx, nodes); err != nil {
		return nil, err
	}
	return &Graph{Nodes: nodes, Edges: edges, Summary: summary}, nil
}

// TopologyGroup 按应用分组的端点树节点。
type TopologyGroup struct {
	ApplicationID   *uuid.UUID  `json:"application_id,omitempty"`
	ApplicationName string      `json:"application_name"`
	Endpoints       []GraphNode `json:"endpoints"`
}

// Topology 调用拓扑（应用分组端点树 + 调用边）。
type Topology struct {
	Applications []TopologyGroup `json:"applications"`
	Edges        []GraphEdge     `json:"edges"`
}

// ListTopology 端点按应用分组，附调用边（边按 DefaultGraphEdgeLimit 封顶；契约同 ListGraph）。
func (s *Store) ListTopology(ctx context.Context) (*Topology, error) {
	return s.ListTopologyFiltered(ctx, EdgeFilter{})
}

// ListTopologyFiltered 端点按应用分组（节点附未闭环风险计数、Host 与协议），边按 EdgeFilter 过滤。
func (s *Store) ListTopologyFiltered(ctx context.Context, f EdgeFilter) (*Topology, error) {
	rows, err := s.db.Query(ctx, `
SELECT e.id, e.endpoint_key, e.http_method, e.normalized_path, e.application_id,
       COALESCE(a.name, ''), COALESCE(e.host, ''), COALESCE(e.protocol_type, 'REST'), e.is_api,
       e.asset_status, e.learning_status, e.hit_count, COALESCE(f.open_count, 0)
FROM api_endpoints e
LEFT JOIN applications a ON a.id = e.application_id`+activeFindingsJoin+`
ORDER BY e.application_id NULLS LAST, e.endpoint_key, e.host, e.id`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	t := &Topology{Applications: []TopologyGroup{}, Edges: []GraphEdge{}}
	// 按 application_id 保序聚合（查询已按应用排序）
	idx := map[string]int{}
	for rows.Next() {
		var n GraphNode
		if err := rows.Scan(&n.ID, &n.EndpointKey, &n.HTTPMethod, &n.NormalizedPath,
			&n.ApplicationID, &n.ApplicationName, &n.Host, &n.ProtocolType, &n.IsAPI,
			&n.AssetStatus, &n.LearningStatus, &n.HitCount, &n.OpenFindingsCount); err != nil {
			return nil, err
		}
		key := "none"
		if n.ApplicationID != nil {
			key = n.ApplicationID.String()
		}
		gi, ok := idx[key]
		if !ok {
			name := n.ApplicationName
			if name == "" {
				name = "未分组"
			}
			t.Applications = append(t.Applications, TopologyGroup{
				ApplicationID:   n.ApplicationID,
				ApplicationName: name,
				Endpoints:       []GraphNode{},
			})
			gi = len(t.Applications) - 1
			idx[key] = gi
		}
		t.Applications[gi].Endpoints = append(t.Applications[gi].Endpoints, n)
	}
	if err := rows.Err(); err != nil {
		return nil, err
	}

	edges, err := s.listEdges(ctx, f)
	if err != nil {
		return nil, err
	}
	t.Edges = edges
	return t, nil
}

// listEdges 按 EdgeFilter 过滤并受 DefaultGraphEdgeLimit/MaxGraphEdgeLimit 约束的调用边（按 call_count DESC, id 索引顺序返回）。
func (s *Store) listEdges(ctx context.Context, f EdgeFilter) ([]GraphEdge, error) {
	return s.listEdgesWithQueryer(ctx, s.db, f, edgeQueryScope{})
}

// ---------- 通用辅助 ----------

// countQuery 带可选过滤条件的计数（条件由调用方白名单拼接，值一律参数化）。
func (s *Store) countQuery(ctx context.Context, base string, args []any) (int64, error) {
	var total int64
	err := s.db.QueryRow(ctx, fmt.Sprintf("SELECT count(*) FROM %s", base), args...).Scan(&total)
	return total, err
}

// isNoRows 判断是否无记录。
func isNoRows(err error) bool { return errors.Is(err, pgx.ErrNoRows) }

// Package apisecurity 阶段8（WDSP）任务书 51.4 分类图谱 / 51.5 规范导入 / 51.6 风险运行时接口。
package apisecurity

import (
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
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
	ID             uuid.UUID  `json:"id"`
	EndpointKey    string     `json:"endpoint_key"`
	HTTPMethod     string     `json:"http_method"`
	NormalizedPath string     `json:"normalized_path"`
	ApplicationID  *uuid.UUID `json:"application_id,omitempty"`
	AssetStatus    string     `json:"asset_status"`
	LearningStatus string     `json:"learning_status"`
	HitCount       int64      `json:"hit_count"`
}

// GraphEdge 调用边（api_call_edges）。
type GraphEdge struct {
	ID                uuid.UUID  `json:"id"`
	CallerFingerprint string     `json:"caller_fingerprint"`
	SourceEndpointID  *uuid.UUID `json:"source_endpoint_id,omitempty"`
	TargetEndpointID  uuid.UUID  `json:"target_endpoint_id"`
	CallCount         int64      `json:"call_count"`
	FirstSeenAt       time.Time  `json:"first_seen_at"`
	LastSeenAt        time.Time  `json:"last_seen_at"`
}

// Graph 调用图谱（节点 + 调用边）。
type Graph struct {
	Nodes []GraphNode `json:"nodes"`
	Edges []GraphEdge `json:"edges"`
}

// ListGraph 全量节点与调用边。
func (s *Store) ListGraph(ctx context.Context) (*Graph, error) {
	g := &Graph{Nodes: []GraphNode{}, Edges: []GraphEdge{}}
	rows, err := s.db.Query(ctx, `
SELECT id, endpoint_key, http_method, normalized_path, application_id, asset_status, learning_status, hit_count
FROM api_endpoints ORDER BY endpoint_key`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	for rows.Next() {
		var n GraphNode
		if err := rows.Scan(&n.ID, &n.EndpointKey, &n.HTTPMethod, &n.NormalizedPath,
			&n.ApplicationID, &n.AssetStatus, &n.LearningStatus, &n.HitCount); err != nil {
			return nil, err
		}
		g.Nodes = append(g.Nodes, n)
	}
	if err := rows.Err(); err != nil {
		return nil, err
	}

	edges, err := s.listEdges(ctx)
	if err != nil {
		return nil, err
	}
	g.Edges = edges
	return g, nil
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

// ListTopology 端点按应用分组，附调用边。
func (s *Store) ListTopology(ctx context.Context) (*Topology, error) {
	rows, err := s.db.Query(ctx, `
SELECT e.id, e.endpoint_key, e.http_method, e.normalized_path, e.application_id,
       e.asset_status, e.learning_status, e.hit_count, COALESCE(a.name, '')
FROM api_endpoints e
LEFT JOIN applications a ON a.id = e.application_id
ORDER BY e.application_id NULLS LAST, e.endpoint_key`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	t := &Topology{Applications: []TopologyGroup{}, Edges: []GraphEdge{}}
	// 按 application_id 保序聚合（查询已按应用排序）
	idx := map[string]int{}
	for rows.Next() {
		var n GraphNode
		var appName string
		if err := rows.Scan(&n.ID, &n.EndpointKey, &n.HTTPMethod, &n.NormalizedPath,
			&n.ApplicationID, &n.AssetStatus, &n.LearningStatus, &n.HitCount, &appName); err != nil {
			return nil, err
		}
		key := "none"
		if n.ApplicationID != nil {
			key = n.ApplicationID.String()
		}
		gi, ok := idx[key]
		if !ok {
			name := appName
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

	edges, err := s.listEdges(ctx)
	if err != nil {
		return nil, err
	}
	t.Edges = edges
	return t, nil
}

// listEdges 全量调用边。
func (s *Store) listEdges(ctx context.Context) ([]GraphEdge, error) {
	rows, err := s.db.Query(ctx, `
SELECT id, caller_fingerprint, source_endpoint_id, target_endpoint_id, call_count, first_seen_at, last_seen_at
FROM api_call_edges ORDER BY call_count DESC`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := []GraphEdge{}
	for rows.Next() {
		var e GraphEdge
		if err := rows.Scan(&e.ID, &e.CallerFingerprint, &e.SourceEndpointID,
			&e.TargetEndpointID, &e.CallCount, &e.FirstSeenAt, &e.LastSeenAt); err != nil {
			return nil, err
		}
		out = append(out, e)
	}
	return out, rows.Err()
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

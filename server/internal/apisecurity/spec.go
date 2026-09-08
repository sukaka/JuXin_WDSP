// spec.go 任务书 51.5：OpenAPI 3 规范导入（解析 + 与运行时端点对比）。
// 解析/对比为纯逻辑（不依赖 DB），由 spec_test.go 覆盖。
package apisecurity

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"sort"
	"strings"
	"time"

	"github.com/google/uuid"
)

// 规范解析错误（HTTP 层统一映射为 400）。
var (
	// ErrSpecNotOpenAPI3 文档缺少 openapi 3.x 版本声明。
	ErrSpecNotOpenAPI3 = errors.New("not an OpenAPI 3 document")
	// ErrSpecNoPaths 文档缺少 paths 或 paths 不是对象。
	ErrSpecNoPaths = errors.New("invalid or empty paths in spec")
)

// 规范对比类型（api_spec_diffs.diff_type）。
const (
	DiffMissingInRuntime = "MISSING_IN_RUNTIME" // 规范有而运行时无
	DiffMissingInSpec    = "MISSING_IN_SPEC"    // 运行时有而规范无
	DiffChanged          = "CHANGED"            // 同名跨版本参数/类型/required 变化（W3-C）
)

// openAPI3Methods OpenAPI 3 Path Item 支持的 HTTP 方法（小写键）。
var openAPI3Methods = map[string]bool{
	"get": true, "put": true, "post": true, "delete": true,
	"options": true, "head": true, "patch": true, "trace": true,
}

// SpecEndpoint 规范解析出的单个端点。
type SpecEndpoint struct {
	Method string `json:"method"` // 大写 HTTP 方法
	Path   string `json:"path"`   // 原始路径，{param} 保留原样
	Key    string `json:"key"`    // METHOD + 空格 + path
}

// ParseOpenAPI3 解析 OpenAPI 3 文档（JSON 反序列化后的对象），
// 提取 paths 下每个 method 生成端点列表（按 endpoint_key 排序，保证确定性）。
// YAML 不在此支持：HTTP 层在 json.Unmarshal 失败时直接返回 400。
func ParseOpenAPI3(doc map[string]any) ([]SpecEndpoint, error) {
	// 版本校验：openapi 字段必须为 3.x
	version, _ := doc["openapi"].(string)
	if !strings.HasPrefix(version, "3.") {
		return nil, ErrSpecNotOpenAPI3
	}
	paths, ok := doc["paths"].(map[string]any)
	if !ok || len(paths) == 0 {
		return nil, ErrSpecNoPaths
	}
	out := make([]SpecEndpoint, 0, len(paths))
	for path, itemRaw := range paths {
		item, ok := itemRaw.(map[string]any)
		if !ok {
			continue // 非对象 Path Item 跳过
		}
		for method := range item {
			if !openAPI3Methods[strings.ToLower(method)] {
				continue // 跳过 parameters/summary/$ref 等非方法键
			}
			m := strings.ToUpper(method)
			out = append(out, SpecEndpoint{Method: m, Path: path, Key: m + " " + path})
		}
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Key < out[j].Key })
	return out, nil
}

// DiffEndpointKeys 对比规范端点键与运行时端点键：
// 规范有而运行时无 → MISSING_IN_RUNTIME；运行时有而规范无 → MISSING_IN_SPEC。
// 两个结果均按键排序，保证确定性。
func DiffEndpointKeys(specKeys, runtimeKeys []string) (missingInRuntime, missingInSpec []string) {
	runtimeSet := make(map[string]bool, len(runtimeKeys))
	for _, k := range runtimeKeys {
		runtimeSet[k] = true
	}
	specSet := make(map[string]bool, len(specKeys))
	for _, k := range specKeys {
		specSet[k] = true
		if !runtimeSet[k] {
			missingInRuntime = append(missingInRuntime, k)
		}
	}
	for _, k := range runtimeKeys {
		if !specSet[k] {
			missingInSpec = append(missingInSpec, k)
		}
	}
	sort.Strings(missingInRuntime)
	sort.Strings(missingInSpec)
	return missingInRuntime, missingInSpec
}

// HashSpecContent 计算规范内容的 SHA-256（十六进制小写）。
func HashSpecContent(content []byte) string {
	sum := sha256.Sum256(content)
	return hex.EncodeToString(sum[:])
}

// ---------- 规范存储 ----------

// ImportSpec 导入的规范（api_import_specs）。
// W3-C 起带版本状态机：name 为版本链标识，version_no 链内自增，
// status 为 DRAFT/ACTIVE/HISTORICAL/INVALID/ARCHIVED（同名唯一 ACTIVE）。
type ImportSpec struct {
	ID            uuid.UUID       `json:"id"`
	Name          string          `json:"name"`
	VersionNo     int             `json:"version_no"`
	Status        string          `json:"status"`
	ParentID      *uuid.UUID      `json:"parent_id,omitempty"`
	ActivatedAt   *time.Time      `json:"activated_at,omitempty"`
	Format        string          `json:"format"`
	FileName      string          `json:"file_name"`
	ContentHash   string          `json:"content_hash"`
	SpecJSON      json.RawMessage `json:"spec_json,omitempty"`
	EndpointCount int             `json:"endpoint_count"`
	ImportedBy    *uuid.UUID      `json:"imported_by,omitempty"`
	// Source 规范来源（UPLOAD/URL/SOURCE_CODE…，迁移 000072；SOURCE_CODE 由 apisrc 源码扫描工具产出）
	Source    string    `json:"source"`
	CreatedAt time.Time `json:"created_at"`
}

// SpecDiff 规范与运行时对比结果（api_spec_diffs）。
type SpecDiff struct {
	ID          uuid.UUID       `json:"id"`
	SpecID      uuid.UUID       `json:"spec_id"`
	DiffType    string          `json:"diff_type"`
	EndpointKey string          `json:"endpoint_key"`
	Detail      json.RawMessage `json:"detail"`
	CreatedAt   time.Time       `json:"created_at"`
}

// ImportSpecWithDiffs 事务写入规范新版本、对比结果并登记规范端点：
//   - 同名版本链加锁，version_no = 链内最大值 + 1，parent_id 指向原最高版本；
//   - 原 ACTIVE 版本降为 HISTORICAL，新版本以 ACTIVE 落库（activated_at=now）；
//   - diffs 含运行时键集对比（MISSING_*）与跨版本 CHANGED 明细；
//   - registerOps（MISSING_IN_RUNTIME 端点）幂等登记为 api_endpoints 候选。
//
// 任一失败整体回滚。返回新登记的端点数量。
func (s *Store) ImportSpecWithDiffs(ctx context.Context, spec *ImportSpec, diffs []SpecDiff, registerOps []SpecOperation) (int, error) {
	tx, err := s.db.Begin(ctx)
	if err != nil {
		return 0, err
	}
	defer func() { _ = tx.Rollback(ctx) }()
	// 版本链加锁，分配新版本号并降级旧 ACTIVE（并发重名导入由 (name, version_no) 唯一索引兜底）
	var prevID uuid.UUID
	var prevVersionNo int
	err = tx.QueryRow(ctx, `
SELECT id, version_no FROM api_import_specs WHERE name = $1 ORDER BY version_no DESC LIMIT 1 FOR UPDATE`,
		spec.Name).Scan(&prevID, &prevVersionNo)
	if err != nil && !isNoRows(err) {
		return 0, err
	}
	if err == nil {
		spec.ParentID = &prevID
		spec.VersionNo = prevVersionNo + 1
		if _, err := tx.Exec(ctx, `
UPDATE api_import_specs SET status = $2 WHERE name = $1 AND status = 'ACTIVE'`,
			spec.Name, SpecStatusHistorical); err != nil {
			return 0, err
		}
	} else {
		spec.VersionNo = 1
	}
	spec.Status = SpecStatusActive
	err = tx.QueryRow(ctx, `
INSERT INTO api_import_specs (name, version_no, status, parent_id, activated_at,
  format, file_name, content_hash, spec_json, endpoint_count, imported_by, source)
VALUES ($1, $2, 'ACTIVE', $3, now(), $4, $5, $6, $7, $8, $9, COALESCE(NULLIF($10,''),'UPLOAD'))
RETURNING id, created_at, activated_at`,
		spec.Name, spec.VersionNo, spec.ParentID,
		spec.Format, spec.FileName, spec.ContentHash, spec.SpecJSON, spec.EndpointCount, spec.ImportedBy, spec.Source).
		Scan(&spec.ID, &spec.CreatedAt, &spec.ActivatedAt)
	if err != nil {
		return 0, err
	}
	for i := range diffs {
		detail := diffs[i].Detail
		if len(detail) == 0 {
			detail = json.RawMessage(`{}`)
		}
		if err := tx.QueryRow(ctx, `
INSERT INTO api_spec_diffs (spec_id, diff_type, endpoint_key, detail)
VALUES ($1, $2, $3, $4)
RETURNING id, created_at`,
			spec.ID, diffs[i].DiffType, diffs[i].EndpointKey, detail).
			Scan(&diffs[i].ID, &diffs[i].CreatedAt); err != nil {
			return 0, err
		}
	}
	registered, err := registerSpecEndpointsTx(ctx, tx, registerOps)
	if err != nil {
		return 0, err
	}
	return registered, tx.Commit(ctx)
}

// ListSpecs 规范导入列表（分页，不含 spec_json 大字段；支持 name/status 过滤）。
func (s *Store) ListSpecs(ctx context.Context, name, status string, page, pageSize int) ([]ImportSpec, int64, error) {
	if page <= 0 {
		page = 1
	}
	if pageSize <= 0 {
		pageSize = 20
	}
	where := "1=1"
	args := []any{}
	if name != "" {
		args = append(args, name)
		where += fmt.Sprintf(" AND name = $%d", len(args))
	}
	if status != "" {
		args = append(args, status)
		where += fmt.Sprintf(" AND status = $%d", len(args))
	}
	var total int64
	if err := s.db.QueryRow(ctx, `SELECT count(*) FROM api_import_specs WHERE `+where, args...).Scan(&total); err != nil {
		return nil, 0, err
	}
	args = append(args, pageSize, (page-1)*pageSize)
	rows, err := s.db.Query(ctx, fmt.Sprintf(`
SELECT id, name, version_no, status, parent_id, activated_at, format, file_name, content_hash,
       endpoint_count, imported_by, created_at, source
FROM api_import_specs WHERE %s ORDER BY created_at DESC LIMIT $%d OFFSET $%d`,
		where, len(args)-1, len(args)), args...)
	if err != nil {
		return nil, 0, err
	}
	defer rows.Close()
	out := []ImportSpec{}
	for rows.Next() {
		var it ImportSpec
		if err := rows.Scan(&it.ID, &it.Name, &it.VersionNo, &it.Status, &it.ParentID, &it.ActivatedAt,
			&it.Format, &it.FileName, &it.ContentHash,
			&it.EndpointCount, &it.ImportedBy, &it.CreatedAt, &it.Source); err != nil {
			return nil, 0, err
		}
		out = append(out, it)
	}
	return out, total, rows.Err()
}

// GetSpec 规范详情（不含 spec_json 大字段）。
func (s *Store) GetSpec(ctx context.Context, id uuid.UUID) (*ImportSpec, error) {
	var it ImportSpec
	err := s.db.QueryRow(ctx, `
SELECT id, name, version_no, status, parent_id, activated_at, format, file_name, content_hash,
       endpoint_count, imported_by, created_at, source
FROM api_import_specs WHERE id = $1`, id).
		Scan(&it.ID, &it.Name, &it.VersionNo, &it.Status, &it.ParentID, &it.ActivatedAt,
			&it.Format, &it.FileName, &it.ContentHash, &it.EndpointCount, &it.ImportedBy, &it.CreatedAt, &it.Source)
	if err != nil {
		if isNoRows(err) {
			return nil, ErrNotFound
		}
		return nil, err
	}
	return &it, nil
}

// ListSpecDiffs 某次导入的对比结果。
func (s *Store) ListSpecDiffs(ctx context.Context, specID uuid.UUID) ([]SpecDiff, error) {
	rows, err := s.db.Query(ctx, `
SELECT id, spec_id, diff_type, endpoint_key, detail, created_at
FROM api_spec_diffs WHERE spec_id = $1 ORDER BY diff_type, endpoint_key`, specID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := []SpecDiff{}
	for rows.Next() {
		var d SpecDiff
		if err := rows.Scan(&d.ID, &d.SpecID, &d.DiffType, &d.EndpointKey, &d.Detail, &d.CreatedAt); err != nil {
			return nil, err
		}
		out = append(out, d)
	}
	return out, rows.Err()
}

// ListEndpointKeys 运行时现存全部端点键（规范对比用）。
func (s *Store) ListEndpointKeys(ctx context.Context) ([]string, error) {
	rows, err := s.db.Query(ctx, `SELECT endpoint_key FROM api_endpoints`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := []string{}
	for rows.Next() {
		var k string
		if err := rows.Scan(&k); err != nil {
			return nil, err
		}
		out = append(out, k)
	}
	return out, rows.Err()
}

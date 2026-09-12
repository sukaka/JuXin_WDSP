package apimodels

import (
	"context"
	"encoding/json"
	"errors"
	"sort"
	"strings"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
)

// ErrParameterNotFound 参数模型不存在。
var ErrParameterNotFound = errors.New("api parameter not found")

// Parameter 参数模型（api_parameter_models，任务书 50.3）。
type Parameter struct {
	ID                     uuid.UUID      `json:"id"`
	ModelVersionID         uuid.UUID      `json:"model_version_id"`
	Direction              string         `json:"direction"`
	Location               string         `json:"location"`
	StructuredPath         string         `json:"structured_path"`
	ParameterName          string         `json:"parameter_name"`
	BaseType               string         `json:"base_type"`
	SemanticType           string         `json:"semantic_type"`
	Required               bool           `json:"required"`
	Nullable               bool           `json:"nullable"`
	EmptyAllowed           bool           `json:"empty_allowed"`
	ObservedConstraints    map[string]any `json:"observed_constraints"`
	RecommendedConstraints map[string]any `json:"recommended_constraints"`
	ConfirmedConstraints   map[string]any `json:"confirmed_constraints"`
	SensitivityLevel       string         `json:"sensitivity_level"`
	Confidence             float64        `json:"confidence"`
	CreatedAt              time.Time      `json:"created_at"`
}

// ParameterConfirmInput 参数确认约束编辑输入。
// ConfirmedConstraints 为 nil 且 UpdateConstraints=false 时不改 confirmed_constraints 列
// （避免 PATCH 省略该字段时被写成 {} 清空既有约束）。
// SemanticType 为 nil 时不改 semantic_type 列；指向空串时显式清空。
type ParameterConfirmInput struct {
	Required             bool
	Nullable             bool
	EmptyAllowed         bool
	ConfirmedConstraints map[string]any
	UpdateConstraints    bool // true 时写入 ConfirmedConstraints（含显式 {} 清空）
	SensitivityLevel     string
	SemanticType         *string
}

// parameterColumns 参数模型全列（SELECT/RETURNING 共用，顺序与 scanParameter 一致）。
const parameterColumns = `id, model_version_id, direction, location, structured_path, parameter_name,
base_type, semantic_type, required, nullable, empty_allowed,
observed_constraints, recommended_constraints, confirmed_constraints,
sensitivity_level, confidence, created_at`

// scanParameter 按 parameterColumns 顺序扫描一行参数模型。
func scanParameter(row scanner) (*Parameter, error) {
	var p Parameter
	var observed, recommended, confirmed []byte
	err := row.Scan(&p.ID, &p.ModelVersionID, &p.Direction, &p.Location, &p.StructuredPath, &p.ParameterName,
		&p.BaseType, &p.SemanticType, &p.Required, &p.Nullable, &p.EmptyAllowed,
		&observed, &recommended, &confirmed,
		&p.SensitivityLevel, &p.Confidence, &p.CreatedAt)
	if err != nil {
		return nil, err
	}
	p.ObservedConstraints = decodeConstraints(observed)
	p.RecommendedConstraints = decodeConstraints(recommended)
	p.ConfirmedConstraints = decodeConstraints(confirmed)
	return &p, nil
}

// decodeConstraints 解析 JSONB 约束（空值按空对象处理）。
func decodeConstraints(raw []byte) map[string]any {
	m := map[string]any{}
	if len(raw) > 0 {
		_ = json.Unmarshal(raw, &m)
	}
	return m
}

// ListParametersByVersion 按模型版本列出全部参数（51.3，AI 工具等内部消费用）。
func (s *Store) ListParametersByVersion(ctx context.Context, versionID uuid.UUID) ([]Parameter, error) {
	list, _, err := s.ListParametersByVersionPage(ctx, versionID, 1, 10000)
	return list, err
}

// ListParametersByVersionPage 按模型版本分页列出参数（列表接口用）。
// page<=0 归一为 1；pageSize<=0 或 >10000 归一为 100。返回列表与总数。
func (s *Store) ListParametersByVersionPage(ctx context.Context, versionID uuid.UUID, page, pageSize int) ([]Parameter, int64, error) {
	if page <= 0 {
		page = 1
	}
	if pageSize <= 0 || pageSize > 10000 {
		pageSize = 100
	}
	var total int64
	if err := s.db.QueryRow(ctx,
		`SELECT count(*) FROM api_parameter_models WHERE model_version_id=$1`, versionID).Scan(&total); err != nil {
		return nil, 0, err
	}
	rows, err := s.db.Query(ctx, `
SELECT `+parameterColumns+`
FROM api_parameter_models
WHERE model_version_id=$1
ORDER BY direction, location, parameter_name
LIMIT $2 OFFSET $3`, versionID, pageSize, (page-1)*pageSize)
	if err != nil {
		return nil, 0, err
	}
	defer rows.Close()
	out := []Parameter{}
	for rows.Next() {
		p, err := scanParameter(rows)
		if err != nil {
			return nil, 0, err
		}
		out = append(out, *p)
	}
	return out, total, rows.Err()
}

// GetParameterByID 按 ID 读取参数模型。
func (s *Store) GetParameterByID(ctx context.Context, id uuid.UUID) (*Parameter, error) {
	p, err := scanParameter(s.db.QueryRow(ctx, `SELECT `+parameterColumns+` FROM api_parameter_models WHERE id=$1`, id))
	if errors.Is(err, pgx.ErrNoRows) {
		return nil, ErrParameterNotFound
	}
	if err != nil {
		return nil, err
	}
	return p, nil
}

// UpdateParameterConfirmed 更新参数确认约束（required/nullable/empty_allowed/sensitivity_level；
// confirmed_constraints 仅在 UpdateConstraints=true 时写入；semantic_type 指针为 nil 时保留原值）。
func (s *Store) UpdateParameterConfirmed(ctx context.Context, id uuid.UUID, in ParameterConfirmInput) (*Parameter, error) {
	if in.SensitivityLevel == "" {
		in.SensitivityLevel = "UNKNOWN"
	}
	var (
		p   *Parameter
		err error
	)
	if in.UpdateConstraints {
		if in.ConfirmedConstraints == nil {
			in.ConfirmedConstraints = map[string]any{}
		}
		raw, _ := json.Marshal(in.ConfirmedConstraints)
		p, err = scanParameter(s.db.QueryRow(ctx, `
UPDATE api_parameter_models
SET required=$2, nullable=$3, empty_allowed=$4, confirmed_constraints=$5, sensitivity_level=$6,
  semantic_type=COALESCE($7, semantic_type)
WHERE id=$1
RETURNING `+parameterColumns, id, in.Required, in.Nullable, in.EmptyAllowed, raw, in.SensitivityLevel, in.SemanticType))
	} else {
		// 省略 confirmed_constraints：保留库中既有确认约束，仅改必填/可空/敏感级别/语义类型
		p, err = scanParameter(s.db.QueryRow(ctx, `
UPDATE api_parameter_models
SET required=$2, nullable=$3, empty_allowed=$4, sensitivity_level=$5,
  semantic_type=COALESCE($6, semantic_type)
WHERE id=$1
RETURNING `+parameterColumns, id, in.Required, in.Nullable, in.EmptyAllowed, in.SensitivityLevel, in.SemanticType))
	}
	if errors.Is(err, pgx.ErrNoRows) {
		return nil, ErrParameterNotFound
	}
	if err != nil {
		return nil, err
	}
	return p, nil
}

// ErrEmptyRecommended 推荐约束为空，无法采纳为确认约束。
var ErrEmptyRecommended = errors.New("recommended constraints empty")

// ConfirmParameter 确认参数：confirmed_constraints 整体拷贝 recommended_constraints。
// 推荐为空时返回 ErrEmptyRecommended（避免「采纳成功」却仍无下发依据）。
// 000018 无独立确认标记列；下发侧以 required 或 confirmed_constraints 非空为准。
func (s *Store) ConfirmParameter(ctx context.Context, id uuid.UUID) (*Parameter, error) {
	p, err := scanParameter(s.db.QueryRow(ctx, `
UPDATE api_parameter_models
SET confirmed_constraints=recommended_constraints
WHERE id=$1 AND recommended_constraints <> '{}'::jsonb
RETURNING `+parameterColumns, id))
	if errors.Is(err, pgx.ErrNoRows) {
		// 区分「参数不存在」与「推荐为空」
		if _, gerr := s.GetParameterByID(ctx, id); errors.Is(gerr, ErrParameterNotFound) {
			return nil, ErrParameterNotFound
		} else if gerr != nil {
			return nil, gerr
		}
		return nil, ErrEmptyRecommended
	}
	if err != nil {
		return nil, err
	}
	return p, nil
}

// ---------- FORMAL 确认物化与下发查询（P0-2：参数约束经发布通道下发网关） ----------

// mapSchemaTypeToBaseType 版本 schema_json 类型词汇 → 参数 base_type
// （与网关一次解析器粗类型词表对齐：string|number|bool|object|array|null，
// 见 gateway/dynamic_security/parser/parse.go walkJSON）。
// 未识别词汇小写原样保留（网关约束检测对未知 base_type 不做取值约束）。
func mapSchemaTypeToBaseType(t string) string {
	switch strings.ToLower(strings.TrimSpace(t)) {
	case "integer", "number", "float", "double":
		return "number"
	case "boolean", "bool":
		return "bool"
	case "string":
		return "string"
	case "object":
		return "object"
	case "array":
		return "array"
	case "null":
		return "null"
	default:
		return strings.ToLower(strings.TrimSpace(t))
	}
}

// deriveParameterName 取结构化路径末段名（去数组元素标记 []）。
// "buyer.name" → "name"，"items[]" → "items"，"items[].sku" → "sku"。
func deriveParameterName(path string) string {
	if i := strings.LastIndex(path, "."); i >= 0 {
		path = path[i+1:]
	}
	return strings.TrimSuffix(path, "[]")
}

// materializeRequestParameters 由版本 schema_json 物化 REQUEST/BODY 参数行 +
// 由端点级观测物化 REQUEST/QUERY、REQUEST/PATH 参数行（约束三层均空，待人工确认）。
// BODY 幂等：身份键 (model_version_id, direction, location, structured_path) 先查后插
// （000028 唯一索引含 structured_path+parameter_name 兜底；Confirm 持有版本行
// FOR UPDATE 锁，同版本物化串行）。按 structured_path 幂等，避免嵌套同名叶字段
// （buyer.name / seller.name）被 parameter_name 误合并。
// schema 为空时跳过 BODY 物化（非错误）；QUERY/PATH 物化与 schema 无关，照常执行。
// 仅在 Confirm 事务内调用。
func materializeRequestParameters(ctx context.Context, tx pgx.Tx, versionID uuid.UUID, schema map[string]string) error {
	if len(schema) > 0 {
		fields := make([]string, 0, len(schema))
		for f := range schema {
			fields = append(fields, f)
		}
		sort.Strings(fields)
		for _, field := range fields {
			name := deriveParameterName(field)
			if name == "" {
				continue // 空字段名无身份可落，跳过
			}
			if _, err := tx.Exec(ctx, `
INSERT INTO api_parameter_models
  (model_version_id, direction, location, structured_path, parameter_name, base_type, confidence)
SELECT $1,'REQUEST','BODY',$2::varchar,$3::varchar,$4::varchar,1.0
WHERE NOT EXISTS (
    SELECT 1 FROM api_parameter_models
    WHERE model_version_id=$1 AND direction='REQUEST' AND location='BODY' AND structured_path=$2::varchar
)`, versionID, field, name, mapSchemaTypeToBaseType(schema[field])); err != nil {
				return err
			}
		}
	}
	return materializeObservedQueryPathParameters(ctx, tx, versionID)
}

// materializeObservedQueryPathParameters 由端点级脱敏观测物化 REQUEST/QUERY、REQUEST/PATH
// 参数行（P0-02 加深：修复孤儿观测断链）。
// schema_json 只描述 BODY，QUERY/PATH 参数行的来源是 api_parameter_value_obs
// （观测按 endpoint_key 归属、跨版本累积）：Confirm 时把当时已观测的 QUERY/PATH 参数
// 快照进该 FORMAL 版本，statistics 回填（statistics.go 1b 按 endpoint_key × location ×
// path × name JOIN；观测不经 model_version 维度，新版本 Confirm 后自然接回）由此闭合。
// HEADER/COOKIE 暂不物化：HEADER 默认不观测（网关噪声控制）、COOKIE 整头脱敏无解析值，
// 两侧都无观测数据源，物化只能凭空造行。
// base_type 与候选构建同口径（inferObservedBaseType：bool/number/string）。
// 幂等：000028 身份键 (model_version_id, direction, location, structured_path, parameter_name)。
func materializeObservedQueryPathParameters(ctx context.Context, tx pgx.Tx, versionID uuid.UUID) error {
	rows, err := tx.Query(ctx, `
SELECT o.location, o.structured_path, o.parameter_name,
       o.min_value, o.max_value, o.distinct_count, o.value_hashes
FROM api_parameter_value_obs o
JOIN api_model_versions v ON v.id = $1 AND v.endpoint_key = o.endpoint_key
WHERE o.location IN ('QUERY','PATH')
ORDER BY o.location, o.structured_path, o.parameter_name`, versionID)
	if err != nil {
		return err
	}
	defer rows.Close()
	type obsRow struct {
		loc, path, name string
		minVal, maxVal  *float64
		distinct        *int
		hashes          []string
	}
	list := []obsRow{}
	for rows.Next() {
		var o obsRow
		var hashesRaw []byte
		if err := rows.Scan(&o.loc, &o.path, &o.name, &o.minVal, &o.maxVal, &o.distinct, &hashesRaw); err != nil {
			return err
		}
		if len(hashesRaw) > 0 {
			_ = json.Unmarshal(hashesRaw, &o.hashes)
		}
		list = append(list, o)
	}
	rows.Close()
	if err := rows.Err(); err != nil {
		return err
	}
	// 先收集再插入：rows 打开期间同一事务连接不可再发命令（pgx conn busy）。
	for _, o := range list {
		baseType := inferObservedBaseType(o.minVal, o.maxVal, o.distinct, o.hashes)
		if sem := inferStringSemantic(o.name, o.path); isStringOnlySemantic(sem) {
			baseType = "string"
		}
		if _, err := tx.Exec(ctx, `
INSERT INTO api_parameter_models
  (model_version_id, direction, location, structured_path, parameter_name, base_type, confidence)
SELECT $1,'REQUEST',$2::varchar,$3::varchar,$4::varchar,$5::varchar,1.0
WHERE NOT EXISTS (
    SELECT 1 FROM api_parameter_models
    WHERE model_version_id=$1 AND direction='REQUEST' AND location=$2::varchar
      AND structured_path=$3::varchar AND parameter_name=$4::varchar
)`, versionID, o.loc, o.path, o.name, baseType); err != nil {
			return err
		}
	}
	return nil
}

// ParamConstraint 单参数确认约束（发布通道下发网关；JSON 契约与网关侧镜像一致）。
type ParamConstraint struct {
	Location     string         `json:"location"`      // QUERY / HEADER / BODY / PATH / COOKIE
	Name         string         `json:"name"`          // 参数名（QUERY/HEADER 键名；BODY 末段名）
	Path         string         `json:"path"`          // 结构化路径（BODY 点路径）
	BaseType     string         `json:"base_type"`     // string|number|bool|object|array|null
	Required     bool           `json:"required"`      // 必填（缺失产生 OBSERVE 级检测明细）
	SemanticType string         `json:"semantic_type"` // 语义类型（供对象标识联动）
	Constraints  map[string]any `json:"constraints"`   // 钉死词汇：min_length/max_length/minimum/maximum/enum
}

// ListFormalParameterConstraints 返回全部 FORMAL 端点的请求侧确认参数约束
// （endpoint_key → 参数约束列表），供发布通道下发网关。
// 端点选取语义与 ListFormalSchemas 一致（DISTINCT ON 取最近确认的 FORMAL 版本），
// 仅取 direction='REQUEST' 且「required=true 或 confirmed_constraints 非空」的参数行：
// 仅改必填、未写约束词的参数也必须下发，否则网关无法产生 schema.param_required。
func (s *Store) ListFormalParameterConstraints(ctx context.Context) (map[string][]ParamConstraint, error) {
	rows, err := s.db.Query(ctx, `
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
ORDER BY f.endpoint_key, p.location, p.parameter_name`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := map[string][]ParamConstraint{}
	for rows.Next() {
		var key string
		var pc ParamConstraint
		var raw []byte
		if err := rows.Scan(&key, &pc.Location, &pc.Name, &pc.Path, &pc.BaseType, &pc.Required, &pc.SemanticType, &raw); err != nil {
			return nil, err
		}
		pc.Constraints = decodeConstraints(raw)
		out[key] = append(out[key], pc)
	}
	return out, rows.Err()
}

// ConfirmParametersBatch 批量采纳推荐约束：recommended → confirmed（推荐为空的跳过）。
// 返回成功确认数与跳过数。
func (s *Store) ConfirmParametersBatch(ctx context.Context, versionID uuid.UUID, ids []uuid.UUID) (confirmed, skipped int, err error) {
	if len(ids) == 0 {
		// 版本内全部有 recommended 的参数
		rows, qerr := s.db.Query(ctx, `
SELECT id FROM api_parameter_models
WHERE model_version_id=$1 AND recommended_constraints <> '{}'::jsonb`, versionID)
		if qerr != nil {
			return 0, 0, qerr
		}
		for rows.Next() {
			var id uuid.UUID
			if err := rows.Scan(&id); err != nil {
				rows.Close()
				return confirmed, skipped, err
			}
			ids = append(ids, id)
		}
		rows.Close()
	}
	for _, id := range ids {
		p, err := s.ConfirmParameter(ctx, id)
		if err != nil {
			if errors.Is(err, ErrEmptyRecommended) || errors.Is(err, ErrParameterNotFound) {
				skipped++
				continue
			}
			return confirmed, skipped, err
		}
		if p != nil {
			confirmed++
		}
	}
	return confirmed, skipped, nil
}

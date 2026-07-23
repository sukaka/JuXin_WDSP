package apimodels

import (
	"context"
	"encoding/json"
	"errors"
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
type ParameterConfirmInput struct {
	Required             bool
	Nullable             bool
	EmptyAllowed         bool
	ConfirmedConstraints map[string]any
	SensitivityLevel     string
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

// ListParametersByVersion 按模型版本列出参数（51.3）。
func (s *Store) ListParametersByVersion(ctx context.Context, versionID uuid.UUID) ([]Parameter, error) {
	rows, err := s.db.Query(ctx, `
SELECT `+parameterColumns+`
FROM api_parameter_models
WHERE model_version_id=$1
ORDER BY direction, location, parameter_name`, versionID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := []Parameter{}
	for rows.Next() {
		p, err := scanParameter(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, *p)
	}
	return out, rows.Err()
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

// UpdateParameterConfirmed 更新参数确认约束（required/nullable/empty_allowed/confirmed_constraints/sensitivity_level）。
func (s *Store) UpdateParameterConfirmed(ctx context.Context, id uuid.UUID, in ParameterConfirmInput) (*Parameter, error) {
	if in.ConfirmedConstraints == nil {
		in.ConfirmedConstraints = map[string]any{}
	}
	if in.SensitivityLevel == "" {
		in.SensitivityLevel = "UNKNOWN"
	}
	raw, _ := json.Marshal(in.ConfirmedConstraints)
	p, err := scanParameter(s.db.QueryRow(ctx, `
UPDATE api_parameter_models
SET required=$2, nullable=$3, empty_allowed=$4, confirmed_constraints=$5, sensitivity_level=$6
WHERE id=$1
RETURNING `+parameterColumns, id, in.Required, in.Nullable, in.EmptyAllowed, raw, in.SensitivityLevel))
	if errors.Is(err, pgx.ErrNoRows) {
		return nil, ErrParameterNotFound
	}
	if err != nil {
		return nil, err
	}
	return p, nil
}

// ConfirmParameter 确认参数：confirmed_constraints 整体拷贝 recommended_constraints。
// 000018 无独立确认标记列，确认态以 confirmed_constraints 非空为准。
func (s *Store) ConfirmParameter(ctx context.Context, id uuid.UUID) (*Parameter, error) {
	p, err := scanParameter(s.db.QueryRow(ctx, `
UPDATE api_parameter_models
SET confirmed_constraints=recommended_constraints
WHERE id=$1
RETURNING `+parameterColumns, id))
	if errors.Is(err, pgx.ErrNoRows) {
		return nil, ErrParameterNotFound
	}
	if err != nil {
		return nil, err
	}
	return p, nil
}

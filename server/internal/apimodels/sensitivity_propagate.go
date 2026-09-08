// sensitivity_propagate.go 参数敏感级别自动标注（敏感字段台账 → 参数模型回写）。
//
// 背景：api_parameter_models.sensitivity_level 落库即默认 UNKNOWN，三条物化路径
// （schema 物化 / 观测物化 / 候选构建）均不写该列；网关敏感检测结果写在
// api_sensitive_fields（键 = endpoint_id + direction + structured_path，
// structured_path 形如 query.phone / json.user.email），两表原本无联动。
//
// 本文件提供两个回写来源，只补 UNKNOWN 不覆盖人工已定级别：
//  1. 敏感字段台账：按「参数名 = 台账 structured_path 末段 + 位置由首段映射」匹配，
//     data_type → 级别：credential/bank_card/id_card → HIGH，phone/email → MEDIUM，
//     其他非空 → LOW；同名参数被多个版本/端点台账行重复命中时取最高级
//     （聚合子查询一次 UPDATE，幂等可重跑）；
//  2. 语义兜底：semantic_type 已推断为 secret/token/id_card/bank_card → HIGH，
//     phone/email → MEDIUM（semantic_type 来源见 statistics.go 1c 或人工 PATCH）。
//
// 调用时机：learningjobs SweepOnce 在 RefreshParameterStatistics 之后整轮一次。
package apimodels

import (
	"context"
	"fmt"
)

// PropagateSensitivityLevels 敏感级别自动标注（幂等：仅 sensitivity_level='UNKNOWN'
// 的行参与更新，人工已设级别与 RESPONSE 方向参数不动）。返回两条来源合计更新行数。
func (s *Store) PropagateSensitivityLevels(ctx context.Context) (int64, error) {
	// 1. 敏感字段台账回写：台账 structured_path 末段对参数名、首段映射位置
	// （query→QUERY，json/body/form→BODY，header→HEADER，cookie→COOKIE；
	// 无法映射首段的行不匹配）。多版本/多端点重复命中取最高级后一次 UPDATE。
	tag, err := s.db.Exec(ctx, `
WITH matched AS (
    SELECT p.id AS parameter_id,
        CASE
            WHEN sf.data_type IN ('credential','bank_card','id_card') THEN 3
            WHEN sf.data_type IN ('phone','email') THEN 2
            ELSE 1
        END AS rank
    FROM api_sensitive_fields sf
    JOIN api_endpoints e ON e.id = sf.endpoint_id
    JOIN api_model_versions v ON v.api_endpoint_id = e.id
    JOIN api_parameter_models p ON p.model_version_id = v.id
    WHERE sf.direction = 'REQUEST'
      AND sf.data_type <> ''
      AND p.direction = 'REQUEST'
      AND p.sensitivity_level = 'UNKNOWN'
      AND p.parameter_name = regexp_replace(sf.structured_path, '^.*\.', '')
      AND CASE lower(split_part(sf.structured_path, '.', 1))
            WHEN 'query' THEN 'QUERY'
            WHEN 'json' THEN 'BODY'
            WHEN 'body' THEN 'BODY'
            WHEN 'form' THEN 'BODY'
            WHEN 'header' THEN 'HEADER'
            WHEN 'cookie' THEN 'COOKIE'
            ELSE ''
          END = p.location
),
best AS (
    SELECT parameter_id, max(rank) AS rank FROM matched GROUP BY parameter_id
)
UPDATE api_parameter_models p
SET sensitivity_level = CASE b.rank WHEN 3 THEN 'HIGH' WHEN 2 THEN 'MEDIUM' ELSE 'LOW' END
FROM best b
WHERE p.id = b.parameter_id AND p.sensitivity_level = 'UNKNOWN'`)
	if err != nil {
		return 0, fmt.Errorf("propagate sensitivity from sensitive fields: %w", err)
	}
	total := tag.RowsAffected()

	// 2. 语义兜底：semantic_type 已推断/人工设定的参数按语义映射级别。
	tag, err = s.db.Exec(ctx, `
UPDATE api_parameter_models
SET sensitivity_level = CASE
    WHEN semantic_type IN ('secret','token','id_card','bank_card') THEN 'HIGH'
    WHEN semantic_type IN ('phone','email') THEN 'MEDIUM'
    ELSE 'LOW'
END
WHERE sensitivity_level = 'UNKNOWN'
  AND semantic_type IN ('secret','token','id_card','bank_card','phone','email')`)
	if err != nil {
		return 0, fmt.Errorf("propagate sensitivity from semantic_type: %w", err)
	}
	return total + tag.RowsAffected(), nil
}

// statistics.go 参数统计画像写入方（三微模型框架 §四.5，第二批）：
// 学习样本离线聚合 → api_parameter_statistics（parameter_id 1:1 UPSERT，幂等可重算），
// 并依画像经纯函数重算 observed/recommended 约束（规则见 recommended.go）。
//
// 数据源（2026-08 三微模型增强批）：
//   - accepted 学习样本 → sample_count / example_hashes；
//   - api_parameter_value_obs（网关脱敏观测：length/hash/num）→ min/max_length、
//     min/max_value、distinct_count 回填；无观测行时对应列保持 NULL 不虚构。
package apimodels

import (
	"context"
	"encoding/json"
	"fmt"

	"github.com/google/uuid"
)

// RefreshParameterStatistics 全量重算参数统计画像（幂等：重复执行结果一致，可安全周期调用）。
//
// 目标集（学习状态满足条件的端点）：learning_status='LEARNED' 且存在 accepted
// 学习样本的端点，其最新 FORMAL 版本（选取语义同 ListFormalParameterConstraints）
// 的 REQUEST 参数行——参数行由 FORMAL 确认物化产生，样本集为端点级学习依据。
//
// 单事务多步：
//  1. UPSERT api_parameter_statistics：sample_count/example_hashes 重算覆盖；
//     可空统计列（长度/值域/基数）不触碰，留给未来真实数据源写入方；
//     1b 从 api_parameter_value_obs 回填长度/值域/基数；1c 空语义类型按词表启发式填充；
//     1d 字符串语义护栏（secret/token/email/phone/uuid 强制 base_type=string）；
//  2. 读回画像（字符串语义参数抑制数值上下界），经 RecommendedConstraints 重算
//     recommended_constraints（系统所有，每轮全量重算，内容变化才写避免行搅动）；
//  3. observed_constraints 仅在存在真实观测键时写入（观测事实只增不改语义，
//     当前无值观测数据源故不动该列）。
//
// confirmed_constraints 绝不触碰（人工定案与系统建议严格分离）。
// 返回本轮 UPSERT 的统计行数。
func (s *Store) RefreshParameterStatistics(ctx context.Context) (int, error) {
	tx, err := s.db.Begin(ctx)
	if err != nil {
		return 0, err
	}
	defer func() { _ = tx.Rollback(ctx) }()

	// 1. 聚合 accepted 样本 → UPSERT 统计画像（example_hashes 留最近 ExampleHashesCap 条）。
	rows, err := tx.Query(ctx, `
WITH formal AS (
    SELECT DISTINCT ON (v.api_endpoint_id) v.api_endpoint_id, v.id AS version_id
    FROM api_model_versions v
    JOIN api_endpoints e ON e.id = v.api_endpoint_id
    WHERE v.status = 'FORMAL' AND e.learning_status = 'LEARNED'
    ORDER BY v.api_endpoint_id, v.confirmed_at DESC NULLS LAST
),
scope AS (
    SELECT p.id AS parameter_id, f.api_endpoint_id
    FROM formal f
    JOIN api_parameter_models p ON p.model_version_id = f.version_id AND p.direction = 'REQUEST'
    WHERE EXISTS (
        SELECT 1 FROM api_learning_samples s
        WHERE s.api_endpoint_id = f.api_endpoint_id AND s.accepted
    )
),
agg AS (
    SELECT s.api_endpoint_id,
           count(*) AS sample_count,
           (SELECT jsonb_agg(t.sample_hash)
            FROM (SELECT s2.sample_hash FROM api_learning_samples s2
                  WHERE s2.api_endpoint_id = s.api_endpoint_id AND s2.accepted
                  ORDER BY s2.collected_at DESC, s2.id DESC LIMIT $1) t) AS example_hashes
    FROM api_learning_samples s
    WHERE s.accepted AND s.api_endpoint_id IN (SELECT api_endpoint_id FROM scope)
    GROUP BY s.api_endpoint_id
)
INSERT INTO api_parameter_statistics (parameter_id, sample_count, example_hashes, updated_at)
SELECT sc.parameter_id, a.sample_count, COALESCE(a.example_hashes, '[]'::jsonb), now()
FROM scope sc JOIN agg a ON a.api_endpoint_id = sc.api_endpoint_id
ON CONFLICT (parameter_id) DO UPDATE SET
  sample_count = EXCLUDED.sample_count,
  example_hashes = EXCLUDED.example_hashes,
  updated_at = now()
RETURNING parameter_id`, ExampleHashesCap)
	if err != nil {
		return 0, fmt.Errorf("upsert parameter statistics: %w", err)
	}
	parameterIDs := []uuid.UUID{}
	for rows.Next() {
		var id uuid.UUID
		if err := rows.Scan(&id); err != nil {
			rows.Close()
			return 0, err
		}
		parameterIDs = append(parameterIDs, id)
	}
	rows.Close()
	if err := rows.Err(); err != nil {
		return 0, err
	}
	if len(parameterIDs) == 0 {
		return 0, tx.Commit(ctx)
	}

	// 1b. 从 api_parameter_value_obs 回填长度/值域/基数（按 endpoint_key × location × path × name 匹配）
	if _, err := tx.Exec(ctx, `
UPDATE api_parameter_statistics st SET
  min_length = o.min_length,
  max_length = o.max_length,
  min_value = o.min_value,
  max_value = o.max_value,
  distinct_count = o.distinct_count,
  updated_at = now()
FROM api_parameter_models p
JOIN api_model_versions v ON v.id = p.model_version_id
JOIN api_parameter_value_obs o ON o.endpoint_key = v.endpoint_key
  AND o.location = p.location
  AND o.parameter_name = p.parameter_name
  AND (o.structured_path = p.structured_path OR (o.structured_path = '' AND p.structured_path = '')
       OR (p.location = 'BODY' AND o.structured_path = p.structured_path))
WHERE st.parameter_id = p.id AND st.parameter_id = ANY($1)`, parameterIDs); err != nil {
		return 0, fmt.Errorf("merge value observations into statistics: %w", err)
	}

	// 1c. 语义类型推断：空 semantic_type 时按参数名/路径启发式填充（不覆盖人工已设）。
	// 分支顺序敏感：captcha 必须先于 token/key 类（captchaKey 等不得误判为 token）。
	if _, err := tx.Exec(ctx, `
UPDATE api_parameter_models p SET semantic_type = x.inferred
FROM (
  SELECT id,
    CASE
      WHEN lower(parameter_name) IN ('id','uid','user_id','userid','account_id','order_id','resource_id','object_id')
        OR lower(parameter_name) LIKE '%_id' THEN
        CASE WHEN lower(parameter_name) LIKE '%uuid%' OR lower(structured_path) LIKE '%uuid%' THEN 'uuid' ELSE 'id' END
      WHEN lower(parameter_name) LIKE '%captcha%' THEN 'captcha'
      WHEN lower(parameter_name) IN ('email','mail','e_mail') OR lower(parameter_name) LIKE '%email%' THEN 'email'
      WHEN lower(parameter_name) IN ('username','user_name','nickname','login_name','account','account_name') THEN 'username'
      WHEN lower(parameter_name) LIKE '%idcard%' OR lower(parameter_name) LIKE '%id_card%'
        OR lower(parameter_name) LIKE '%sfz%' THEN 'id_card'
      WHEN lower(parameter_name) LIKE '%bank_card%' OR lower(parameter_name) LIKE '%card_no%'
        OR lower(parameter_name) LIKE '%cardno%' THEN 'bank_card'
      WHEN lower(parameter_name) IN ('phone','mobile','tel','telephone')
        OR lower(parameter_name) LIKE '%mobile%' OR lower(parameter_name) LIKE '%phone%' THEN 'phone'
      WHEN lower(parameter_name) IN ('token','access_token','refresh_token','api_key','apikey')
        OR lower(parameter_name) LIKE '%token%' OR lower(parameter_name) LIKE '%api_key%'
        OR lower(parameter_name) LIKE '%apikey%' THEN 'token'
      WHEN lower(parameter_name) IN ('password','passwd','pwd','secret')
        OR lower(parameter_name) LIKE '%password%' OR lower(parameter_name) LIKE '%passwd%' THEN 'secret'
      WHEN lower(parameter_name) IN ('amount','price','total','balance','fee') THEN 'money'
      ELSE ''
    END AS inferred
  FROM api_parameter_models WHERE id = ANY($1)
) x
WHERE p.id = x.id AND COALESCE(p.semantic_type,'') = '' AND x.inferred <> ''`, parameterIDs); err != nil {
		return 0, fmt.Errorf("infer semantic_type: %w", err)
	}

	// 1d. 字符串语义护栏：口令/令牌/邮箱/手机号/UUID 类参数本质上是字符串，
	// 观测值恰好全为数字时（如口令 "123456"）不得保持 number/bool——base_type 为
	// 系统学习产物（非人工编辑面），此处直接归正；数值上下界约束在步骤 2 读回画像时抑制。
	if _, err := tx.Exec(ctx, `
UPDATE api_parameter_models SET base_type = 'string'
WHERE id = ANY($1) AND semantic_type IN ('secret','token','email','phone','uuid')
  AND base_type IN ('number','bool')`, parameterIDs); err != nil {
		return 0, fmt.Errorf("normalize string-semantic base_type: %w", err)
	}

	// 2. 读回画像（含值观测回填的长度/值域/基数字段），逐参数重算约束。
	profiles, err := tx.Query(ctx, `
SELECT st.parameter_id, st.sample_count, st.min_length, st.max_length, st.min_value, st.max_value, st.distinct_count,
       p.parameter_name, p.structured_path, COALESCE(p.semantic_type,'')
FROM api_parameter_statistics st
JOIN api_parameter_models p ON p.id = st.parameter_id
WHERE st.parameter_id = ANY($1)`, parameterIDs)
	if err != nil {
		return 0, fmt.Errorf("load parameter statistics: %w", err)
	}
	type profileRow struct {
		id      uuid.UUID
		profile ParameterProfile
	}
	list := []profileRow{}
	for profiles.Next() {
		var r profileRow
		var name, path, sem string
		if err := profiles.Scan(&r.id, &r.profile.SampleCount,
			&r.profile.MinLength, &r.profile.MaxLength,
			&r.profile.MinValue, &r.profile.MaxValue, &r.profile.DistinctCount,
			&name, &path, &sem); err != nil {
			profiles.Close()
			return 0, err
		}
		// 字符串语义护栏：口令/令牌类参数的数值上下界无意义（口令可能是任意复杂
		// 字符串，观测样本恰好全为数字不应产生数值约束）；优先人工已确认语义，
		// 空语义按参数名/路径启发式兜底。长度统计保留。
		if sem == "" {
			sem = inferStringSemantic(name, path)
		}
		if isStringOnlySemantic(sem) {
			r.profile.MinValue = nil
			r.profile.MaxValue = nil
		}
		list = append(list, r)
	}
	profiles.Close()
	if err := profiles.Err(); err != nil {
		return 0, err
	}

	for _, r := range list {
		// recommended：系统所有，每轮全量重算；内容未变时不写（<> 比较避免行搅动）。
		recommended, _ := json.Marshal(RecommendedConstraints(r.profile))
		if _, err := tx.Exec(ctx, `
UPDATE api_parameter_models SET recommended_constraints=$2
WHERE id=$1 AND recommended_constraints <> $2::jsonb`, r.id, recommended); err != nil {
			return 0, fmt.Errorf("refresh recommended constraints: %w", err)
		}
		// observed：观测事实只增不改语义——仅在存在真实观测键时写入，无观测不动该列。
		if observed := ObservedConstraints(r.profile); len(observed) > 0 {
			raw, _ := json.Marshal(observed)
			if _, err := tx.Exec(ctx, `
UPDATE api_parameter_models SET observed_constraints=$2
WHERE id=$1 AND observed_constraints <> $2::jsonb`, r.id, raw); err != nil {
				return 0, fmt.Errorf("refresh observed constraints: %w", err)
			}
		}
	}
	return len(parameterIDs), tx.Commit(ctx)
}

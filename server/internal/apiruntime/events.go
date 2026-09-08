// Package apiruntime API 运行时主事件持久化。
package apiruntime

import (
	"context"
	"encoding/json"
	"fmt"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgxpool"
	dsctx "github.com/jiuzhang-waf/gateway/dynamic_security/context"
	"github.com/jiuzhang-waf/gateway/dynamic_security/events"
)

// Store 事件仓储。
type Store struct {
	db DBTX
}

// NewStore 创建。
func NewStore(db *pgxpool.Pool) *Store { return &Store{db: db} }

// WithDB 返回绑定到给定句柄的浅拷贝（W22 采集器批次事务化：句柄为该批次的
// pgx.Tx；SavePrimary/SaveSchemaViolations/SaveFindings 并入外层批次事务，
// 提交权归采集器，失败整体回滚、断点不前移、重放由幂等键兜底）。
func (s *Store) WithDB(db DBTX) *Store { return &Store{db: db} }

// SavePrimary 保存统一主事件。按 request_id 幂等：同一 Request ID 只生成一个主事件
// （任务书约束；采集器重放/重复上报时静默去重而非产生重复行）。
// 身份维度（identity_fingerprint/auth_type）随主事件落库，列定义见迁移 000029；
// response_status（0 = 网关未采集到状态码）列定义见迁移 000030，供行为画像聚合状态码分布；
// 审计维度（client_ip/method/raw_path/latency_ms/model_version/policy_version）列定义见
// 迁移 000035：旧版网关事件缺字段时为零值，空串/非正耗时落 NULL（不伪造 0 值审计数据）。
// jwt_verification（JWT 信任链验证摘要，WDSP P0-03）列定义见迁移 000127：
// 网关未上报/请求未经 jwt_trust 范围评估时落 NULL，历史事件不回填。
// final_decision（请求最终处置上下文，WDSP P0-04）列定义见迁移 000131：
// 网关未上报/处置事实未确定时落 NULL。request_id 幂等命中（重复上报/重放）时
// 按「已确认拦截优先」条件补全（契约 S4_DESIGN_BASELINE §2）：仅当现有行
// final_decision IS NULL，或现有行为 PENDING_CORRELATION 且未被确认执法
// （security_action 不在 BLOCK/TEMP_BLOCK/RATE_LIMIT/MASK_RESPONSE）且 incoming
// completion_status ∈ (COMPLETED, ABORTED) 时更新——已确认拦截不被晚到观察覆盖。
func (s *Store) SavePrimary(ctx context.Context, ev *PrimaryEvent) error {
	if ev == nil {
		return nil
	}
	if ev.ID == "" {
		ev.ID = uuid.New().String()
	}
	raw, _ := json.Marshal(ev.Details)
	id, err := uuid.Parse(ev.ID)
	if err != nil {
		id = uuid.New()
		ev.ID = id.String()
	}
	var jwtRaw any
	if ev.JWTVerification != nil {
		b, merr := json.Marshal(ev.JWTVerification)
		if merr != nil {
			return fmt.Errorf("marshal jwt_verification: %w", merr)
		}
		jwtRaw = b
	}
	// final_decision：校验合法 JSON 对象并取 completion_status（条件补全判定用）；
	// 非法内容显式报错，不静默落库（与 applyRiskPolicyEvent 同一纪律）
	var fdRaw any
	var fdCompletion string
	if len(ev.FinalDecision) > 0 {
		var probe struct {
			CompletionStatus string `json:"completion_status"`
		}
		if err := json.Unmarshal(ev.FinalDecision, &probe); err != nil {
			return fmt.Errorf("final_decision: invalid JSON: %w", err)
		}
		fdRaw = []byte(ev.FinalDecision)
		fdCompletion = probe.CompletionStatus
	}
	ct, err := s.db.Exec(ctx, `
INSERT INTO api_runtime_events (id, request_id, endpoint_key, risk_score, risk_level, final_action, details_json, occurred_at, identity_fingerprint, auth_type, response_status, client_ip, method, raw_path, latency_ms, model_version, policy_version, gateway_node, jwt_verification, final_decision)
SELECT $1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,$14,$15,$16,$17,$18,$19,$20
WHERE NOT EXISTS (SELECT 1 FROM api_runtime_events WHERE request_id = NULLIF($2::varchar, ''))`,
		id, ev.RequestID, ev.EndpointKey, ev.RiskScore, ev.RiskLevel, ev.FinalAction, raw, ev.OccurredAt,
		ev.IdentityFingerprint, ev.AuthType, ev.ResponseStatus,
		nullIfEmpty(ev.ClientIP), nullIfEmpty(ev.Method), nullIfEmpty(ev.RawPath), nullIfNonPositive(ev.LatencyMs),
		nullIfEmpty(ev.ModelVersion), nullIfEmpty(ev.PolicyVersion), nullIfEmpty(ev.GatewayNode), jwtRaw, fdRaw)
	if err != nil {
		return err
	}
	if ct.RowsAffected() == 0 && fdRaw != nil {
		// request_id 幂等命中（采集器重放/重复上报）：final_decision 条件补全
		_, err = s.db.Exec(ctx, `
UPDATE api_runtime_events SET final_decision = $2::jsonb
WHERE request_id = NULLIF($1::varchar, '')
  AND (final_decision IS NULL
       OR (final_decision->>'completion_status' = 'PENDING_CORRELATION'
           AND COALESCE(final_decision->>'security_action', 'NONE') NOT IN ('BLOCK','TEMP_BLOCK','RATE_LIMIT','MASK_RESPONSE')
           AND $3 IN ('COMPLETED','ABORTED')))`,
			ev.RequestID, fdRaw, fdCompletion)
		return err
	}
	return nil
}

// nullIfEmpty 空串转 NULL（可空审计列：未上报与空值语义一致，统一落 NULL）。
func nullIfEmpty(s string) any {
	if s == "" {
		return nil
	}
	return s
}

// nullIfNonPositive 非正数转 NULL（latency_ms：0 = 旧版网关未上报，非真实 0 毫秒耗时）。
func nullIfNonPositive(n int64) any {
	if n <= 0 {
		return nil
	}
	return n
}

// List 最近事件。
func (s *Store) List(ctx context.Context, page, pageSize int) ([]map[string]any, int64, error) {
	if page <= 0 {
		page = 1
	}
	if pageSize <= 0 {
		pageSize = 20
	}
	var total int64
	if err := s.db.QueryRow(ctx, `SELECT count(*) FROM api_runtime_events`).Scan(&total); err != nil {
		return nil, 0, err
	}
	rows, err := s.db.Query(ctx, `
SELECT id, request_id, endpoint_key, risk_score, risk_level, final_action, details_json, occurred_at, identity_fingerprint, auth_type,
       client_ip, method, raw_path, latency_ms, model_version, policy_version, jwt_verification
FROM api_runtime_events ORDER BY occurred_at DESC LIMIT $1 OFFSET $2`, pageSize, (page-1)*pageSize)
	if err != nil {
		return nil, 0, err
	}
	defer rows.Close()
	var out []map[string]any
	for rows.Next() {
		var id uuid.UUID
		var reqID, ek, rl, fa, idfp, authType string
		var score int
		var details []byte
		var at time.Time
		// 审计维度列可空（迁移 000035；旧版网关事件未上报即 NULL）
		var clientIP, method, rawPath, modelVersion, policyVersion *string
		var latencyMs *int64
		// jwt_verification 可空（迁移 000127；历史事件 NULL，不回填）
		var jwtRaw []byte
		if err := rows.Scan(&id, &reqID, &ek, &score, &rl, &fa, &details, &at, &idfp, &authType,
			&clientIP, &method, &rawPath, &latencyMs, &modelVersion, &policyVersion, &jwtRaw); err != nil {
			return nil, 0, err
		}
		var det []dsctx.DetectorMatch
		_ = json.Unmarshal(details, &det)
		var jwt any
		if len(jwtRaw) > 0 {
			var jv events.JWTVerification
			if err := json.Unmarshal(jwtRaw, &jv); err == nil {
				jwt = jv
			}
		}
		out = append(out, map[string]any{
			"id": id, "request_id": reqID, "endpoint_key": ek,
			"risk_score": score, "risk_level": rl, "final_action": fa,
			"details": det, "occurred_at": at,
			"identity_fingerprint": idfp, "auth_type": authType,
			"client_ip": clientIP, "method": method, "raw_path": rawPath,
			"latency_ms": latencyMs, "model_version": modelVersion, "policy_version": policyVersion,
			"jwt_verification": jwt,
		})
	}
	if out == nil {
		out = []map[string]any{}
	}
	return out, total, rows.Err()
}

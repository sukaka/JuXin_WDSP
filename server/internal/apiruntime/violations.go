// violations.go Schema 类检测明细专项落库（P0-2）：
// Collector 每条网关事件经 recordViolations 提取 detector=api_schema 的明细
// （schema 偏离与参数约束命中），交 ViolationSaver 写 api_schema_violations
// （request_id 幂等）；未注入 saver（nil）时零开销跳过。
//
// 脱敏纪律：落库字段只取 Evidence 中的安全键（field/want/got/type/constraint），
// 即字段名、粗类型词表与约束名；参数原始值永不落库（网关侧本就不写入证据）。
package apiruntime

import (
	"context"
	"errors"
	"log/slog"
	"unicode/utf8"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	dsctx "github.com/jiuzhang-waf/gateway/dynamic_security/context"
)

// SchemaDetector detector 名：schema 偏离与参数约束命中共用（gateway detectors/schema.go）。
const SchemaDetector = "api_schema"

// ViolationSaver Schema 违例落库接口（*Store 实现，可为 nil）。
type ViolationSaver interface {
	SaveSchemaViolations(ctx context.Context, in ViolationInput) error
}

// ViolationInput 一次请求的 schema 类违例落库输入（Matches 已过滤为 detector=api_schema）。
type ViolationInput struct {
	EndpointKey string
	RequestID   string
	FinalAction string
	Matches     []dsctx.DetectorMatch
}

// recordViolations schema 类明细专项落库（错误仅记录日志，不影响采集主流程，与落样同一纪律）。
// 空 request_id 跳过：无法幂等去重的违例不落库。
func (c *Collector) recordViolations(ctx context.Context, rec *Record) {
	if c.violations == nil || rec.RequestID == "" {
		return
	}
	var matches []dsctx.DetectorMatch
	for i := range rec.Details {
		if rec.Details[i].Detector == SchemaDetector {
			matches = append(matches, rec.Details[i])
		}
	}
	if len(matches) == 0 {
		return
	}
	if err := c.violations.SaveSchemaViolations(ctx, ViolationInput{
		EndpointKey: rec.EndpointKey,
		RequestID:   rec.RequestID,
		FinalAction: rec.FinalAction,
		Matches:     matches,
	}); err != nil {
		slog.Error("save schema violations failed",
			"collector", c.collectorID, "endpoint_key", rec.EndpointKey,
			"request_id", rec.RequestID, "error", err)
	}
}

// 违例列宽（迁移 000018：violation_type VARCHAR(64)、field_path VARCHAR(512)、
// expected/observed VARCHAR(128)）。
const (
	maxViolationTypeLen  = 64
	maxViolationFieldLen = 512
	maxViolationValueLen = 128
)

// SaveSchemaViolations 把一条请求的 schema 类检测明细写入 api_schema_violations。
// endpoint_id 按 endpoint_key 点查（未匹配留 NULL）；model_version_id 取当前 FORMAL
// 版本（无 FORMAL 留 NULL）。幂等：(request_id, violation_type, field_path) 已存在则
// 跳过，采集器重放/轮转重读不产生重复行。
// 证据映射只取安全字段：expected ← want（期望类型）| constraint（约束名）；
// observed ← got（实际粗类型）| type（未定义字段粗类型）。
func (s *Store) SaveSchemaViolations(ctx context.Context, in ViolationInput) error {
	if len(in.Matches) == 0 || in.RequestID == "" {
		return nil
	}
	var endpointID *uuid.UUID
	if in.EndpointKey != "" {
		var id uuid.UUID
		err := s.db.QueryRow(ctx, `SELECT id FROM api_endpoints WHERE endpoint_key=$1`, in.EndpointKey).Scan(&id)
		switch {
		case errors.Is(err, pgx.ErrNoRows):
		case err != nil:
			return err
		default:
			endpointID = &id
		}
	}
	var modelVersionID *uuid.UUID
	if in.EndpointKey != "" {
		var id uuid.UUID
		err := s.db.QueryRow(ctx, `
SELECT id FROM api_model_versions
WHERE endpoint_key=$1 AND status='FORMAL' ORDER BY confirmed_at DESC NULLS LAST LIMIT 1`,
			in.EndpointKey).Scan(&id)
		switch {
		case errors.Is(err, pgx.ErrNoRows):
		case err != nil:
			return err
		default:
			modelVersionID = &id
		}
	}
	action := in.FinalAction
	if action == "" {
		action = "OBSERVE"
	}
	for i := range in.Matches {
		m := in.Matches[i]
		if m.RuleID == "" {
			continue // 无规则标识的明细无法归类违例类型，跳过
		}
		violationType := truncateRunes(m.RuleID, maxViolationTypeLen)
		fieldPath := truncateRunes(m.Evidence["field"], maxViolationFieldLen)
		expected := truncateRunes(firstNonEmpty(m.Evidence["want"], m.Evidence["constraint"]), maxViolationValueLen)
		observed := truncateRunes(firstNonEmpty(m.Evidence["got"], m.Evidence["type"]), maxViolationValueLen)
		if _, err := s.db.Exec(ctx, `
INSERT INTO api_schema_violations
  (endpoint_id, model_version_id, request_id, violation_type, field_path, expected, observed, action_taken)
SELECT $1,$2,$3::varchar,$4::varchar,$5::varchar,$6::varchar,$7::varchar,$8::varchar
WHERE NOT EXISTS (
    SELECT 1 FROM api_schema_violations
    WHERE request_id=$3::varchar AND violation_type=$4::varchar AND field_path=$5::varchar
)`, endpointID, modelVersionID, in.RequestID, violationType, fieldPath, expected, observed, action); err != nil {
			return err
		}
	}
	return nil
}

// firstNonEmpty 取首个非空串。
func firstNonEmpty(vs ...string) string {
	for _, v := range vs {
		if v != "" {
			return v
		}
	}
	return ""
}

// truncateRunes 按字符数截断（rune 安全），与列宽对齐。
func truncateRunes(s string, n int) string {
	if utf8.RuneCountInString(s) <= n {
		return s
	}
	return string([]rune(s)[:n])
}

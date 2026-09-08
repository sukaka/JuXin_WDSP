// findings.go 运行时发现（Findings）生产化（P0-13 Risk 中心原料 / P0-11 Shadow-Zombie 断链修复）：
// Collector 每条含检测明细的网关事件经 recordFindings 按物化规则 v1 筛选明细，
// 交 FindingSaver upsert 进 api_runtime_findings（dedup_fingerprint 幂等去重）；
// 未注入 saver（nil）时零开销跳过，纯采集形态无行为变化。
//
// 脱敏纪律（与 violations.go 同一标准）：evidence_json 只存字段名/粗类型词表/约束名
// 等元信息，参数原始值永不落库；subject 只落指纹（身份指纹仅凭据派生，IP 为来源指纹），
// 不落明文 IP/凭据。
package apiruntime

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"sort"
	"strings"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	dsctx "github.com/jiuzhang-waf/gateway/dynamic_security/context"
)

// FindingSaver 风险发现物化写入接口（*Store 实现，可为 nil）。
type FindingSaver interface {
	SaveFindings(ctx context.Context, in []FindingInput) error
}

// FindingInput 一条待物化风险发现（由一条检测明细 + 事件上下文派生）。
type FindingInput struct {
	EndpointKey   string
	RequestID     string
	FindingType   string
	Severity      string
	Title         string
	Detail        map[string]any // 结构化上下文（detector/rule_id/message 等）
	Evidence      map[string]any // 已脱敏证据（键名 + 白名单安全键值）
	SubjectType   string         // IDENTITY / IP / 空（无主体信息）
	SubjectID     string         // 身份指纹或来源指纹（永不落明文）
	RiskScore     int            // 事件级风险计分（展示与排序用）
	RiskLevel     string         // 事件级风险等级
	ModelVersion  string         // 判定所用模型版本（未上报空串 → NULL）
	PolicyVersion string         // 判定所运行策略版本（未上报空串 → NULL）
}

// 风险等级词表与排序（INFO < LOW < MEDIUM < HIGH < CRITICAL；NONE 视同 INFO，
// 未识别词返回 -1，不参与「≥MEDIUM」判定）。
func severityRank(s string) int {
	switch strings.ToUpper(s) {
	case "INFO", "NONE":
		return 0
	case "LOW":
		return 1
	case "MEDIUM":
		return 2
	case "HIGH":
		return 3
	case "CRITICAL":
		return 4
	}
	return -1
}

// 物化规则 v1：明细 severity≥MEDIUM，或事件 final_action 非 ALLOW
// （被决策拦截/限速/观察的事件，其全部明细都是风险信号，含 severity 缺失的明细）。
func materializable(m *dsctx.DetectorMatch, finalAction string) bool {
	if severityRank(m.Severity) >= severityRank("MEDIUM") {
		return true
	}
	return finalAction != "" && finalAction != "ALLOW"
}

// findingTypeOverrides 语义覆盖表（规则 ID → 任务书风险类型词表，见
// api_runtime_findings.finding_type 注释：SHADOW / ZOMBIE / DEPRECATED / BOLA /
// BFLA / SCHEMA_DEVIATION / SENSITIVE_LEAK / ...）。规则 ID 全局唯一且自带
// 检测器前缀（如 lifecycle.new_endpoint），故键即规则 ID。
// 未覆盖的规则走机械映射：rule_id 大写下划线化（如 schema.param_length →
// SCHEMA_PARAM_LENGTH）；rule_id 缺失或非字母开头（如 WAF 数字规则号）时
// 以 detector 名兜底/加前缀，保证 finding_type 可读且稳定。
var findingTypeOverrides = map[string]string{
	"lifecycle.new_endpoint":                 "SHADOW",
	"lifecycle.deprecated_api_call":          "DEPRECATED",
	"resource.unauthenticated_object_access": "BOLA_UNAUTHENTICATED_OBJECT_ACCESS",
}

// findingTypeOf 由 Detector+RuleID 生成 finding_type（见上表注释的映射规则）。
func findingTypeOf(m *dsctx.DetectorMatch) string {
	if t, ok := findingTypeOverrides[m.RuleID]; ok {
		return t
	}
	slug := strings.ToUpper(strings.NewReplacer(".", "_", "-", "_").Replace(m.RuleID))
	if slug == "" {
		slug = strings.ToUpper(strings.NewReplacer(".", "_", "-", "_").Replace(m.Detector))
	}
	if slug == "" {
		return "UNKNOWN"
	}
	if c := slug[0]; c < 'A' || c > 'Z' {
		det := strings.ToUpper(strings.NewReplacer(".", "_", "-", "_").Replace(m.Detector))
		if det != "" {
			slug = det + "_" + slug
		}
	}
	return slug
}

// findingSubject 主体提取：有身份指纹 → IDENTITY（仅凭据派生，docs/API_MICRO_MODELS.md
// §2.2）；否则有来源指纹 → IP（HMAC 指纹，非明文）；两者皆无 → 空（匿名且无来源）。
func findingSubject(rec *Record) (subjectType, subjectID string) {
	if rec.IdentityFingerprint != "" {
		return "IDENTITY", rec.IdentityFingerprint
	}
	if rec.SourceFingerprint != "" {
		return "IP", rec.SourceFingerprint
	}
	return "", ""
}

// safeEvidenceKeys 证据白名单键：字段名/参数名/粗类型词表/约束名等元信息
// （与 violations.go 的 expected/observed 映射同一纪律）。白名单外的键只保留
// 键名（keys 列表），值一律丢弃——参数原始值永不落库。
var safeEvidenceKeys = map[string]bool{
	"field": true, "param": true, "name": true, "type": true,
	"want": true, "got": true, "constraint": true, "location": true,
	"object_type": true,
	// Parser 歧义检测（detector=api_parser）：参数名/出现次数/规则码/JSON 点路径均为
	// 元信息，原始值永不落库（raw_value/normalized_value 不在白名单，值一律丢弃）。
	"parameter_name": true, "value_count": true, "rule_code": true, "path": true,
}

// sanitizeEvidence 构建脱敏证据：keys 为全部证据键名（排序，便于审计知道网关
// 上报了哪些维度），白名单键附带值（截断 128 字符，与列宽纪律一致）。
func sanitizeEvidence(ev map[string]string) map[string]any {
	out := map[string]any{}
	keys := make([]string, 0, len(ev))
	for k, v := range ev {
		keys = append(keys, k)
		if safeEvidenceKeys[k] && v != "" {
			out[k] = truncateRunes(v, maxViolationValueLen)
		}
	}
	sort.Strings(keys)
	out["keys"] = keys
	return out
}

// 发现列宽（迁移 000018：finding_type VARCHAR(64)、title VARCHAR(255)）。
const (
	maxFindingTypeLen  = 64
	maxFindingTitleLen = 255
	maxFindingMsgLen   = 512
)

// recordFindings 风险发现物化（错误仅记录日志，不影响采集主流程，与落样同一纪律）。
func (c *Collector) recordFindings(ctx context.Context, rec *Record) {
	if c.findings == nil || len(rec.Details) == 0 {
		return
	}
	subjectType, subjectID := findingSubject(rec)
	var in []FindingInput
	for i := range rec.Details {
		m := rec.Details[i]
		if !materializable(&m, rec.FinalAction) {
			continue // INFO/LOW 且事件放行：不物化（降噪，物化规则 v1）
		}
		severity := strings.ToUpper(m.Severity)
		if severityRank(severity) < 0 {
			severity = "INFO" // 明细缺 severity 时按事件动作物化，等级保守落 INFO
		}
		title := truncateRunes(firstNonEmpty(m.Message, findingTypeOf(&m)), maxFindingTitleLen)
		in = append(in, FindingInput{
			EndpointKey: rec.EndpointKey,
			RequestID:   rec.RequestID,
			FindingType: truncateRunes(findingTypeOf(&m), maxFindingTypeLen),
			Severity:    severity,
			Title:       title,
			Detail: map[string]any{
				"detector":     m.Detector,
				"rule_id":      m.RuleID,
				"category":     m.Category,
				"message":      truncateRunes(m.Message, maxFindingMsgLen),
				"score_delta":  m.ScoreDelta,
				"final_action": rec.FinalAction,
				"endpoint_key": rec.EndpointKey,
			},
			Evidence:      sanitizeEvidence(m.Evidence),
			SubjectType:   subjectType,
			SubjectID:     subjectID,
			RiskScore:     rec.RiskScore,
			RiskLevel:     rec.RiskLevel,
			ModelVersion:  rec.ModelVersion,
			PolicyVersion: rec.PolicyVersion,
		})
	}
	if len(in) == 0 {
		return
	}
	if err := c.findings.SaveFindings(ctx, in); err != nil {
		slog.Error("save api runtime findings failed",
			"collector", c.collectorID, "endpoint_key", rec.EndpointKey,
			"request_id", rec.RequestID, "error", err)
	}
}

// dedupFingerprint 去重指纹：sha256(endpoint_id + finding_type + subject_id)，
// 以 US(\x1f) 分隔防拼接歧义（简单可靠：定长哈希输入无转义问题）。
// 端点未解析（发现 upsert 失败等异常）时以 "key:"+endpoint_key 兜底，
// 保证指纹稳定非空——空指纹会让 ON CONFLICT 永不命中（PG NULL 互不相等），
// 产生重复行。
func dedupFingerprint(endpointID *uuid.UUID, endpointKey, findingType, subjectID string) string {
	anchor := "key:" + endpointKey // 端点未解析时以 endpoint_key 兜底
	if endpointID != nil {
		anchor = endpointID.String()
	}
	sum := sha256.Sum256([]byte(anchor + "\x1f" + findingType + "\x1f" + subjectID))
	return hex.EncodeToString(sum[:])
}

// SaveFindings 把一批检测明细物化进 api_runtime_findings。
// 幂等：dedup_fingerprint 命中则 count+1 并刷新 last_seen_at/updated_at（不覆盖
// 首次证据与标题）；未命中插入 status=NEW 新行（000042 起风险状态机七态词表）。
// endpoint_id 按 endpoint_key 点查（批内缓存；未匹配留 NULL，与 violations 同一纪律）。
func (s *Store) SaveFindings(ctx context.Context, in []FindingInput) error {
	if len(in) == 0 {
		return nil
	}
	endpointIDs := map[string]*uuid.UUID{}
	resolve := func(key string) (*uuid.UUID, error) {
		if id, ok := endpointIDs[key]; ok {
			return id, nil
		}
		var out *uuid.UUID
		if key != "" {
			var id uuid.UUID
			err := s.db.QueryRow(ctx, `SELECT id FROM api_endpoints WHERE endpoint_key=$1`, key).Scan(&id)
			switch {
			case errors.Is(err, pgx.ErrNoRows):
			case err != nil:
				return nil, err
			default:
				out = &id
			}
		}
		endpointIDs[key] = out
		return out, nil
	}
	for i := range in {
		f := in[i]
		endpointID, err := resolve(f.EndpointKey)
		if err != nil {
			return err
		}
		detail, _ := json.Marshal(f.Detail)
		evidence, _ := json.Marshal(f.Evidence)
		fp := dedupFingerprint(endpointID, f.EndpointKey, f.FindingType, f.SubjectID)
		if _, err := s.db.Exec(ctx, `
INSERT INTO api_runtime_findings
  (endpoint_id, request_id, finding_type, severity, status, title, detail,
   subject_type, subject_id, risk_score, risk_level, count, evidence_json,
   model_version, policy_version, updated_at, dedup_fingerprint)
VALUES ($1,$2,$3,$4,'NEW',$5,$6,$7,$8,$9,$10,1,$11,$12,$13,now(),$14)
ON CONFLICT (dedup_fingerprint) DO UPDATE SET
  count = api_runtime_findings.count + 1,
  last_seen_at = now(),
  updated_at = now()`,
			endpointID, f.RequestID, f.FindingType, f.Severity, f.Title, detail,
			nullIfEmpty(f.SubjectType), nullIfEmpty(f.SubjectID), f.RiskScore, nullIfEmpty(f.RiskLevel), evidence,
			nullIfEmpty(f.ModelVersion), nullIfEmpty(f.PolicyVersion), fp); err != nil {
			return fmt.Errorf("upsert finding %s: %w", f.FindingType, err)
		}
	}
	return nil
}

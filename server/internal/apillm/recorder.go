// recorder.go LLM 观测采集写入（P2-04 落库通路）。
// 事件 llm_observation + details 中 llm.* 明细 → INSERT api_llm_observations：
// 幂等键由 request_id 确定性派生（sha256 截断置版本位 UUID），ON CONFLICT DO NOTHING，
// 采集重放/断点回退不产生重复行；request_id 缺失退化随机主键（防御路径，正常事件必带）。
//
// 缺失容忍：endpoint_key 空 / 观测零值（旧版网关事件无 llm_observation 键时
// 采集器不调用本接口）逐条跳过；findings 仅收录 llm.* 明细（证据纪律由网关保证：
// 规则名/消息序号/角色/模型名，不落原文）。
package apillm

import (
	"context"
	"crypto/sha256"
	"encoding/json"
	"fmt"
	"strings"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgxpool"
	dsctx "github.com/jiuzhang-waf/gateway/dynamic_security/context"
)

// 观测列宽兜底（迁移 000066：model VARCHAR(128)、endpoint_key VARCHAR(560)、
// prompt_len_bucket VARCHAR(16)、identity_fingerprint VARCHAR(128)；
// 迁移 000070：mcp_method VARCHAR(128)）。
// 网关提取期已截断；采集端再截断一次兜底（旧版/异常网关直送超长值的防御）。
const (
	maxLLMModelLen    = 128
	maxEndpointKeyLen = 560
	maxBucketLen      = 16
	maxFingerprintLen = 128
	maxMCPMethodLen   = 128
)

// ObsRecorder 观测入库接口（*ObsStore 实现，采集器装配时可注入）。
type ObsRecorder interface {
	RecordLLMObservation(ctx context.Context, in ObservationInput) error
}

// ObsStore pgx 实现。
type ObsStore struct {
	db DBTX
}

// NewObsStore 创建观测写入方。
func NewObsStore(db *pgxpool.Pool) *ObsStore { return &ObsStore{db: db} }

// WithDB 返回绑定到给定句柄的浅拷贝（W22 采集器批次事务化：句柄为该批次的
// pgx.Tx；RecordLLMObservation 并入外层批次事务，提交权归采集器）。
func (s *ObsStore) WithDB(db DBTX) *ObsStore { return &ObsStore{db: db} }

var _ ObsRecorder = (*ObsStore)(nil)

// RecordLLMObservation 落一条 LLM 观测（按 request_id 幂等：重复采集 DO NOTHING）。
// in.Observation 各字段缺失（空串/0/false）按零值落库（缺失容忍，不判不补）。
func (s *ObsStore) RecordLLMObservation(ctx context.Context, in ObservationInput) error {
	if s == nil || s.db == nil {
		return nil
	}
	endpointKey := truncateRunesLLM(strings.TrimSpace(in.EndpointKey), maxEndpointKeyLen)
	if endpointKey == "" {
		return nil // 无端点归属不产生观测行（与发现/资产通路同一纪律）
	}
	occurredAt := in.OccurredAt
	if occurredAt.IsZero() {
		occurredAt = time.Now().UTC() // 防御：正常路径网关必带事件时间
	}
	findings, err := json.Marshal(llmFindings(in.Details))
	if err != nil {
		return fmt.Errorf("marshal llm findings: %w", err)
	}
	if _, err := s.db.Exec(ctx, `
INSERT INTO api_llm_observations
  (id, occurred_at, endpoint_key, model, identity_fingerprint, prompt_len_bucket, total_tokens, stream, mcp_method, findings)
VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10::jsonb)
ON CONFLICT (id) DO NOTHING`,
		observationID(in.RequestID), occurredAt, endpointKey,
		truncateRunesLLM(strings.TrimSpace(in.Observation.Model), maxLLMModelLen),
		truncateRunesLLM(in.IdentityFingerprint, maxFingerprintLen),
		truncateRunesLLM(in.Observation.PromptLenBucket, maxBucketLen),
		in.Observation.TotalTokens, in.Observation.Stream,
		truncateRunesLLM(strings.TrimSpace(in.Observation.MCPMethod), maxMCPMethodLen),
		string(findings)); err != nil {
		return fmt.Errorf("insert llm observation: %w", err)
	}
	return nil
}

// llmFindings 提取 llm.* 检测明细（findings 口径：注入词表命中/未授权模型）；
// 明细经网关证据纪律脱敏（不落原文），此处原样透传；空归一为 []。
func llmFindings(details []dsctx.DetectorMatch) []dsctx.DetectorMatch {
	out := []dsctx.DetectorMatch{}
	for _, d := range details {
		if d.Detector == "llm" || strings.HasPrefix(d.RuleID, "llm.") {
			out = append(out, d)
		}
	}
	return out
}

// observationID 幂等主键：request_id 非空时确定性派生（sha256 截断 16 字节 +
// 版本/变体位成形 UUID v5 语义），采集重放同键 DO NOTHING；
// request_id 缺失退化随机 UUID（防御路径，无法幂等如实注释）。
func observationID(requestID string) uuid.UUID {
	if strings.TrimSpace(requestID) == "" {
		return uuid.New()
	}
	sum := sha256.Sum256([]byte("api_llm_observations|" + requestID))
	b := make([]byte, 16)
	copy(b, sum[:16])
	b[6] = (b[6] & 0x0f) | 0x50 // version 5
	b[8] = (b[8] & 0x3f) | 0x80 // variant RFC 4122
	id, err := uuid.FromBytes(b)
	if err != nil {
		return uuid.New() // 防御：定长字节不会失败
	}
	return id
}

// truncateRunesLLM 字符截断（防超长值越列宽；按 rune 防截断多字节字符）。
func truncateRunesLLM(s string, max int) string {
	r := []rune(s)
	if len(r) <= max {
		return s
	}
	return string(r[:max])
}

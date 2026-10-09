// Package validations 无副作用模拟（NG-COV-03 server 侧骨架）：
// 冻结策略与脱敏证据，在隔离的决策实例内重放，产出「若启用将如何动作」的报告，
// 并与策略/语料/输入摘要加强绑定（任何变更使旧报告标记 STALE）。
//
// 安全边界（RD_PLAN §5.3，结构性保证而非口头声明）：
//   - Simulator 零依赖字段（无网关客户端/Valkey/DB/HTTP），外部调用在类型层面不存在；
//   - 只经决策层重放（真实 decision 引擎）：不反代请求、不调用工具、不改真实流程/限速/重放状态；
//   - 缺原始输入时给出 CANNOT_REPRODUCE，绝不补造输入证明通过；
//   - 模拟不是 PROTECT 实测，报告不能单独满足上线条件。
package validations

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"sort"
	"time"

	dsctx "github.com/jiuzhang-waf/gateway/dynamic_security/context"
	"github.com/jiuzhang-waf/gateway/dynamic_security/decision"
)

// VerdictStatus 单条输入的模拟结论状态。
type VerdictStatus string

const (
	VerdictEvaluated            VerdictStatus = "EVALUATED"             // 已给出候选/最终动作（模拟语义，未执行）
	VerdictCannotReproduce      VerdictStatus = "CANNOT_REPRODUCE"      // 缺原始输入或协议不可复现（如实标记）
	VerdictEvidenceInsufficient VerdictStatus = "EVIDENCE_INSUFFICIENT" // 证据不足（无任何 Finding 输入）
)

// Verdict 单条输入的模拟结论。
type Verdict struct {
	InputID      string        `json:"input_id"`
	Status       VerdictStatus `json:"status"`
	Candidate    string        `json:"candidate_action,omitempty"` // 决策前候选（与最终动作分离）
	FinalAction  string        `json:"final_action,omitempty"`
	WouldBlock   bool          `json:"would_block"`             // 若启用将阻断（模拟语义）
	ExceptionHit bool          `json:"exception_hit,omitempty"` // 命中受限例外（证据保留）
	Notes        string        `json:"notes,omitempty"`
}

// Report 模拟报告：与策略摘要、语料摘要、输入摘要加强绑定。
type Report struct {
	ID           string    `json:"id"`
	PolicyDigest string    `json:"policy_digest"`
	CorpusDigest string    `json:"corpus_digest"`
	InputsDigest string    `json:"inputs_digest"`
	Status       string    `json:"status"` // COMPLETED / STALE
	Verdicts     []Verdict `json:"verdicts"`
	ResourceNote string    `json:"resource_note"`
	CreatedAt    time.Time `json:"created_at"`
}

// FindingBatch 一批脱敏 Finding 输入（决策层重放的最小单元）。
// Matches 为空且 MissingReason 非空时 → CANNOT_REPRODUCE；两者皆空 → EVIDENCE_INSUFFICIENT。
type FindingBatch struct {
	InputID       string                  `json:"input_id"`
	Matches       []dsctx.DetectorMatch   `json:"matches"`
	Exceptions    []decision.ExceptionRef `json:"exceptions,omitempty"`
	MissingReason string                  `json:"missing_reason,omitempty"` // 缺原始输入原因（协议不可复现/证据缺失）
}

// PolicyRef 策略引用（重放语义：模式 + 摘要；具体策略内容由发布链提供，模拟器不重新编译）。
type PolicyRef struct {
	Mode   decision.Mode
	Digest string // 策略内容摘要（发布链计算的不可变摘要；空串时由 simulate 时按 mode 计算占位摘要）
}

// Simulator 无副作用模拟器（零依赖字段：类型层面不存在外部调用）。
type Simulator struct{}

// NewSimulator 创建模拟器。
func NewSimulator() *Simulator { return &Simulator{} }

// Simulate 执行一批输入的决策层重放并产出报告。
func (s *Simulator) Simulate(policy PolicyRef, batches []FindingBatch) Report {
	now := time.Now().UTC()
	verdicts := make([]Verdict, 0, len(batches))
	for _, b := range batches {
		verdicts = append(verdicts, s.evalOne(policy, b))
	}
	return Report{
		ID:           reportID(now, policy.Digest, batches),
		PolicyDigest: policy.Digest,
		CorpusDigest: digestBatches(batches),
		InputsDigest: digestInputs(batches),
		Status:       "COMPLETED",
		Verdicts:     verdicts,
		ResourceNote: fmt.Sprintf("decision-layer replay only; %d inputs; no external IO", len(batches)),
		CreatedAt:    now,
	}
}

// evalOne 单条输入重放。
func (s *Simulator) evalOne(policy PolicyRef, b FindingBatch) Verdict {
	v := Verdict{InputID: b.InputID}
	if b.MissingReason != "" {
		v.Status = VerdictCannotReproduce
		v.Notes = b.MissingReason
		return v
	}
	if len(b.Matches) == 0 {
		v.Status = VerdictEvidenceInsufficient
		v.Notes = "无任何 Finding 输入"
		return v
	}
	ctx := dsctx.New("sim-"+b.InputID, dsctx.ParseLimits{})
	for _, m := range b.Matches {
		ctx.AddMatch(m)
	}
	before := decision.SnapshotMatches(ctx)
	for _, m := range before {
		if m.ScoreDelta > 0 {
			v.Candidate = "block"
			break
		}
	}
	if v.Candidate == "" {
		v.Candidate = "observe"
	}
	final := decision.Decide(ctx, decision.Input{Mode: policy.Mode, Exceptions: b.Exceptions})
	v.FinalAction = string(final)
	v.WouldBlock = final == dsctx.ActionBlock || final == dsctx.ActionTempBlock || final == dsctx.ActionRateLimit
	for _, m := range decision.SnapshotMatches(ctx) {
		if m.Excepted {
			v.ExceptionHit = true
			break
		}
	}
	v.Status = VerdictEvaluated
	return v
}

// MarkStale 若当前策略/语料摘要与报告绑定摘要不一致，则把报告标记为 STALE。
// 语义：策略或语料任何变更都使旧报告失效（NG-T-C08）；不允许用旧报告证明新策略。
func MarkStale(r *Report, policyDigest, corpusDigest string) bool {
	if r.PolicyDigest != policyDigest || r.CorpusDigest != corpusDigest {
		r.Status = "STALE"
		return true
	}
	return false
}

// digestBatches 语料摘要（输入集合的结构化摘要）。
func digestBatches(batches []FindingBatch) string {
	ids := make([]string, 0, len(batches))
	for _, b := range batches {
		ids = append(ids, b.InputID)
	}
	sort.Strings(ids)
	h := sha256.Sum256([]byte(fmt.Sprintf("%v", ids)))
	return hex.EncodeToString(h[:8])
}

// digestInputs 输入内容摘要（Finding 内容的规范化 JSON 摘要）。
func digestInputs(batches []FindingBatch) string {
	canonical := make([]string, 0, len(batches))
	for _, b := range batches {
		j, _ := json.Marshal(b)
		canonical = append(canonical, string(j))
	}
	sort.Strings(canonical)
	h := sha256.Sum256([]byte(fmt.Sprintf("%v", canonical)))
	return hex.EncodeToString(h[:8])
}

func reportID(now time.Time, policyDigest string, batches []FindingBatch) string {
	h := sha256.Sum256([]byte(fmt.Sprintf("%s|%s|%d|%s", now.UTC().Format(time.RFC3339Nano), policyDigest, len(batches), digestBatches(batches))))
	return "val-" + hex.EncodeToString(h[:8])
}

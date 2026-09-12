// evaluate.go BOLA 评估：信号采集（SQL/内存两套实现共用）+ 五档判定阶梯（纯函数）。
//
// 判定阶梯（自上而下，首条命中即返回）：
//  1. POLICY_CONFIRMED      有权属记录且匹配（该身份访问过自己权属内的对象）→ 允许；
//  2. HIGH_CONFIDENCE       该对象已有属主（权属记录存在）但访问者不是属主 → 越权；
//  3. LIKELY                该对象无权属记录，但该身份在本端点有权属基线 → 倾向允许；
//  4. LIKELY                该对象无权属记录，该身份在本端点无权属但有历史运行时访问 → 倾向允许；
//  5. POSSIBLE              端点已建立权属画像，但该身份与该对象均无记录
//     （仅能确认“有对象被枚举访问”这一信号）→ 倾向可疑；
//  6. INSUFFICIENT_EVIDENCE 以上皆无（端点无权属数据、身份无历史）→ 无法判定。
//
// 纪律：不仅凭 ID 变化定罪。对象 ID 不同本身不是越权证据——只有「对象已有属主
// 且访问者不是属主」（HIGH_CONFIDENCE）才输出越权结论；证据不足时输出
// POSSIBLE / INSUFFICIENT_EVIDENCE，交由运行时策略与人工研判处置。
// 匿名身份（identity 为空）不做权属匹配（匿名无身份可属），只走对象侧信号。
package apiauthz

import (
	"time"

	"github.com/google/uuid"
)

// EvaluateInput BOLA 评估输入（identity 允许为空串 = 匿名身份）。
type EvaluateInput struct {
	EndpointID uuid.UUID
	Identity   string // identity_fingerprint（空 = 匿名）
	ObjectID   string
}

// EvaluateEvidence 评估证据（各信号计数，供研判溯源）。
type EvaluateEvidence struct {
	OwnMatch              bool `json:"own_match"`               // (身份,对象) 权属记录存在
	ObjectOwnerCount      int  `json:"object_owner_count"`      // 该对象在本端点的权属记录数
	IdentityObjectCount   int  `json:"identity_object_count"`   // 该身份在本端点的权属对象数
	IdentityEventCount    int  `json:"identity_event_count"`    // 该身份在本端点的历史运行时事件数
	EndpointOwnershipRows int  `json:"endpoint_ownership_rows"` // 本端点权属记录总数
}

// EvaluateResult BOLA 评估结果。
type EvaluateResult struct {
	EndpointID  uuid.UUID         `json:"endpoint_id"`
	Identity    string            `json:"identity"`
	ObjectID    string            `json:"object_id"`
	Verdict     string            `json:"verdict"`    // 五档结论
	Allowed     *bool             `json:"allowed"`    // 倾向判定；INSUFFICIENT_EVIDENCE 为 null（无法判定）
	Confidence  float64           `json:"confidence"` // 结论置信度 0..1（档位固定值）
	Evidence    *EvaluateEvidence `json:"evidence"`
	Comment     string            `json:"comment"` // 中文结论说明
	EvaluatedAt time.Time         `json:"evaluated_at"`
}

// evalSignals 判定阶梯输入信号（store 实现负责采集，decideVerdict 纯函数判定）。
type evalSignals struct {
	ownMatch              bool
	objectOwnerCount      int
	identityObjectCount   int
	identityEventCount    int
	endpointOwnershipRows int
}

// boolPtr 允许倾向指针（INSUFFICIENT_EVIDENCE 时为 nil）。
func boolPtr(v bool) *bool { return &v }

// decideVerdict 五档判定阶梯（纯函数；规则见文件头注释，首条命中即返回）。
func decideVerdict(identity string, sig evalSignals) (verdict string, allowed *bool, confidence float64, comment string) {
	anonymous := identity == ""
	switch {
	case !anonymous && sig.ownMatch:
		return VerdictPolicyConfirmed, boolPtr(true), 1.0,
			"权属记录匹配：该身份访问过自己权属内的对象，判定允许"
	case sig.objectOwnerCount > 0:
		return VerdictHighConfidence, boolPtr(false), 0.9,
			"该对象已有属主且访问者不是属主，判定越权（高置信）"
	case !anonymous && sig.identityObjectCount > 0:
		return VerdictLikely, boolPtr(true), 0.7,
			"该对象无权属记录，但该身份在本端点有权属基线，倾向允许（疑似访问自己的新对象）"
	case !anonymous && sig.identityEventCount > 0:
		return VerdictLikely, boolPtr(true), 0.6,
			"无权属记录，但该身份在本端点有历史访问，倾向允许"
	case sig.endpointOwnershipRows > 0:
		return VerdictPossible, boolPtr(false), 0.4,
			"端点已建立权属画像，但该身份与该对象均无记录，仅有对象枚举信号，倾向可疑"
	default:
		return VerdictInsufficientEvidence, nil, 0,
			"无可用证据（端点无权属数据、身份无历史），无法判定"
	}
}

// buildEvaluateResult 组装评估结果（evidence 由信号透传）。
func buildEvaluateResult(in EvaluateInput, sig evalSignals) *EvaluateResult {
	verdict, allowed, confidence, comment := decideVerdict(in.Identity, sig)
	return &EvaluateResult{
		EndpointID: in.EndpointID,
		Identity:   in.Identity,
		ObjectID:   in.ObjectID,
		Verdict:    verdict,
		Allowed:    allowed,
		Confidence: confidence,
		Evidence: &EvaluateEvidence{
			OwnMatch:              sig.ownMatch,
			ObjectOwnerCount:      sig.objectOwnerCount,
			IdentityObjectCount:   sig.identityObjectCount,
			IdentityEventCount:    sig.identityEventCount,
			EndpointOwnershipRows: sig.endpointOwnershipRows,
		},
		Comment:     comment,
		EvaluatedAt: time.Now().UTC(),
	}
}

// gate.go 发布门禁评估（任务书 §7.2）：
//
//   - 模式 OFF（默认）：不检查、不记录，行为与门禁不存在一致；
//   - OBSERVE：计算并记录结论（gate_decisions 追加 RECORD），不阻断发布；
//   - ENFORCE：缺失/过期/撤销/强制用例不完整/验证失败均阻止发布；
//     门禁依赖不可用（策略或密钥登记读取失败、证据完整性检查失败）明确失败，
//     不静默放行。无 skip_gate 参数（HTTP 请求体 DisallowUnknownFields 兜底）。
//
// 证据绑定：候选配置指纹（cfgfpv1:<configuration_hash>，S0 契约 #6）——
// 相关内容变化即指纹变化、旧证据立即失效，不等待到期；另按策略有效期
// （默认 7 天）截止。
//
// 已知良好恢复通道（§7.3）：restore_channel=true（服务端历史快照重放，
// 即 GuardOverride 发布）时，证据「超过有效期」单独一项不阻止恢复；
// 缺失证据、密钥已撤销、核验失败、证据不完整仍明确阻止。
package regression

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"time"

	"github.com/google/uuid"
)

// GateStore 门禁读取/留痕接口（*Store 实现；单测注入 fake）。
type GateStore interface {
	GetPolicy(ctx context.Context) (*Policy, error)
	LatestVerifiedRunForFingerprint(ctx context.Context, fingerprint string) (*Run, error)
	RunObjects(ctx context.Context, runRef uuid.UUID) ([]ImportObjectRef, error)
	InsertGateDecision(ctx context.Context, d GateDecision) error
}

// ObjectExistenceChecker 证据对象落盘完整性核对（LocalEvidenceStore 实现：
// 存在 + 大小一致；完整哈希在导入/Open 时已校验，门禁只做存在性核对——
// 清理过期原始证据后报告即证据不完整，不能继续支撑新发布）。
type ObjectExistenceChecker interface {
	ObjectIntact(ctx context.Context, id uuid.UUID) (bool, error)
}

// GateInput 一次发布门禁评估输入。
type GateInput struct {
	Fingerprint    string
	PublishTaskID  *uuid.UUID
	VersionID      *uuid.UUID
	RestoreChannel bool
	Now            time.Time
}

// GateResult 评估结论。
type GateResult struct {
	Mode          string     `json:"mode"`
	Decision      string     `json:"decision"`
	Reasons       []string   `json:"reasons"`
	RunID         string     `json:"run_id,omitempty"`
	RunRef        *uuid.UUID `json:"run_ref,omitempty"`
	PolicyVersion int        `json:"policy_version"`
}

// Gate 发布门禁评估器。
type Gate struct {
	store   GateStore
	keys    SettingsReader
	objects ObjectExistenceChecker
}

// NewGate 创建评估器（keys 为管理配置读取适配；objects 可为 nil——nil 时跳过
// 落盘完整性核对并在 reasons 标注降级，仅限装配早期/测试；生产装配必须注入）。
func NewGate(store GateStore, keys SettingsReader, objects ObjectExistenceChecker) *Gate {
	return &Gate{store: store, keys: keys, objects: objects}
}

// levelRank 级别序（SMOKE 成功不能产生 FULL/RELEASE 通过结论，§5）。
func levelRank(level string) int {
	switch level {
	case LevelSmoke:
		return 1
	case LevelFull:
		return 2
	case LevelRelease:
		return 3
	}
	return 0
}

// Evaluate 评估并留痕（OFF 直接放行不记录）。返回 (result, 阻断错误)；
// 阻断错误为 ErrGateRejected（证据不满足）或 ErrGateUnavailable（依赖不可用），
// 仅 ENFORCE 返回非 nil 错误；OBSERVE 恒放行并把结论写入 reasons。
func (g *Gate) Evaluate(ctx context.Context, in GateInput) (*GateResult, error) {
	policy, err := g.store.GetPolicy(ctx)
	if err != nil {
		// 策略读取失败 = 门禁依赖不可用：无法判定模式，明确失败（不静默按 OFF 放行）
		return nil, fmt.Errorf("%w: read gate policy: %v", ErrGateUnavailable, err)
	}
	res := &GateResult{Mode: policy.Mode, Decision: DecisionAllow, PolicyVersion: policy.Version}
	if policy.Mode == ModeOff {
		return res, nil
	}
	now := in.Now
	if now.IsZero() {
		now = time.Now()
	}

	var blocking []string
	var notes []string
	fail := func(format string, args ...any) { blocking = append(blocking, fmt.Sprintf(format, args...)) }
	note := func(format string, args ...any) { notes = append(notes, fmt.Sprintf(format, args...)) }

	// 受信密钥登记（解析失败 = 依赖不可用）
	trustedKeys, kerr := LoadTrustedKeys(ctx, g.keys)
	if kerr != nil {
		return nil, g.record(ctx, in, res, DecisionBlock, append(notes, "受信密钥登记读取失败: "+kerr.Error()),
			fmt.Errorf("%w: %v", ErrGateUnavailable, kerr))
	}

	run, rerr := g.store.LatestVerifiedRunForFingerprint(ctx, in.Fingerprint)
	switch {
	case errors.Is(rerr, ErrNotFound):
		fail("缺少绑定当前候选指纹（%s）且服务端核验通过的回归证据", in.Fingerprint)
	case rerr != nil:
		return nil, g.record(ctx, in, res, DecisionBlock, append(notes, "证据查询失败: "+rerr.Error()),
			fmt.Errorf("%w: %v", ErrGateUnavailable, rerr))
	default:
		res.RunID = run.RunID
		res.RunRef = &run.ID
		// 级别：低于要求级别不可用（smoke 不支撑 full/release 发布）
		if levelRank(run.Level) < levelRank(policy.RequiredLevel) {
			fail("证据级别 %s 低于门禁要求 %s", run.Level, policy.RequiredLevel)
		}
		// 语料绑定
		if policy.RequiredCorpusID != "" && run.CorpusID != policy.RequiredCorpusID {
			fail("证据语料 %s 与门禁要求语料 %s 不一致", run.CorpusID, policy.RequiredCorpusID)
		}
		// 声明结论与强制用例完整性（客户端声明 PASS 不直接采信——服务端核验
		// PASSED 已由查询条件保证，此处再核对声明状态与强制项计数）
		if run.DeclaredStatus != StatusPass {
			fail("回归声明状态为 %s（非 PASS）", run.DeclaredStatus)
		}
		if run.Counts.Executed == 0 {
			fail("回归执行数为 0（执行不完整）")
		}
		if run.Counts.MandatoryFailed > 0 {
			fail("强制用例未全部通过（mandatory_failed=%d）", run.Counts.MandatoryFailed)
		}
		// 有效期（恢复通道仅记录不阻止，§7.3）
		if policy.EvidenceMaxAgeSeconds > 0 {
			age := now.Sub(run.CreatedAt)
			if age > time.Duration(policy.EvidenceMaxAgeSeconds)*time.Second {
				if in.RestoreChannel {
					note("证据已超有效期 %d 秒（登记于 %s）：已知良好恢复通道仅记录不阻止",
						policy.EvidenceMaxAgeSeconds, run.CreatedAt.UTC().Format(time.RFC3339))
				} else {
					fail("证据已超有效期 %d 秒（登记于 %s）", policy.EvidenceMaxAgeSeconds, run.CreatedAt.UTC().Format(time.RFC3339))
				}
			}
		}
		// 密钥撤销：撤销后历史报告保留但不能再支撑新发布（恢复通道同样阻止，§7.3）
		keyOK := false
		for _, k := range trustedKeys {
			if k.KeyID == run.SignatureKeyID {
				keyOK = k.Status == KeyStatusActive
				break
			}
		}
		if !keyOK {
			fail("签名密钥 %s 已撤销或未登记，历史报告不能再作为发布凭据", run.SignatureKeyID)
		}
		// 证据完整性（原始对象被清理后不能继续支撑新发布）
		if g.objects != nil {
			refs, oerr := g.store.RunObjects(ctx, run.ID)
			if oerr != nil {
				return nil, g.record(ctx, in, res, DecisionBlock, append(notes, "证据引用查询失败: "+oerr.Error()),
					fmt.Errorf("%w: %v", ErrGateUnavailable, oerr))
			}
			for _, ref := range refs {
				ok, cerr := g.objects.ObjectIntact(ctx, ref.ObjectID)
				if cerr != nil {
					return nil, g.record(ctx, in, res, DecisionBlock, append(notes, "证据完整性核对失败: "+cerr.Error()),
						fmt.Errorf("%w: %v", ErrGateUnavailable, cerr))
				}
				if !ok {
					fail("证据对象 %s（%s）已缺失或被清理，报告证据不完整", ref.ObjectID, ref.Role)
				}
			}
		} else {
			note("证据落盘完整性核对未装配（降级：仅核对登记元数据）")
		}
	}

	if len(blocking) > 0 {
		if policy.Mode == ModeEnforce {
			err := fmt.Errorf("%w: %v", ErrGateRejected, blocking)
			return res, g.record(ctx, in, res, DecisionBlock, append(notes, blocking...), err)
		}
		// OBSERVE：记录结论但不阻断
		return res, g.record(ctx, in, res, DecisionRecord, append(notes, blocking...), nil)
	}
	if in.RestoreChannel {
		note("已知良好恢复通道发布（restore_channel）")
	}
	return res, g.record(ctx, in, res, DecisionAllow, notes, nil)
}

// record 追加判定留痕（留痕失败在 ENFORCE 阻断时如实返回，放行路径记日志级
// 降级——判定事实不丢：阻断语义由返回错误保证）。返回传入的 err。
func (g *Gate) record(ctx context.Context, in GateInput, res *GateResult, decision string, reasons []string, err error) error {
	res.Decision = decision
	res.Reasons = reasons
	raw, merr := json.Marshal(reasons)
	if merr != nil {
		raw = []byte(`["reasons marshal failed"]`)
	}
	d := GateDecision{
		PublishTaskID:  in.PublishTaskID,
		VersionID:      in.VersionID,
		Fingerprint:    in.Fingerprint,
		Mode:           res.Mode,
		Decision:       decision,
		RestoreChannel: in.RestoreChannel,
		Reasons:        raw,
		RunRef:         res.RunRef,
		PolicyVersion:  res.PolicyVersion,
	}
	if rerr := g.store.InsertGateDecision(context.Background(), d); rerr != nil {
		if err != nil {
			// 阻断路径：判定事实由返回错误保证，留痕失败追加进错误信息如实上报
			return fmt.Errorf("%v (record gate decision failed: %v)", err, rerr)
		}
		// 放行路径（OBSERVE 记录/ALLOW）：留痕失败只记日志，不把 OBSERVE 变成阻断
		slog.Warn("record regression gate decision failed", "fingerprint", in.Fingerprint, "error", rerr)
	}
	return err
}

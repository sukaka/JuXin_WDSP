// Package machineid 机器身份（HTTP Message Signatures）网关执行链
// （NG-ID G1 批次 B2，docs/nextgen/NG-ID-g1-machine-identity.md §1.4 十步固定序
// +§1.5 重放链位+§1.6 水位资格+§1.8 UNKNOWN 红线+§1.13 覆盖；密码学与 SF
// 解析复用 parser/httpsig 纯库（批次 A））。
//
// 链序（§1.4 冻结；前步失败即短路，逐步独立 reason code）：
//  1. 头形态解析（MID-SIGNATURE-MALFORMED）→ 2. keyid 登记册精确查找
//     （身份 ENABLED 前提，MID-KEY-UNKNOWN）→ 3. 算法白名单+登记一致性
//     （MID-ALG-REJECTED）→ 4. 键状态机（REVOKED/RETIRED 窗口/生效域——
//     MID-KEY-REVOKED/MID-KEY-RETIRED-EXPIRED/MID-KEY-EXPIRED）→ 5. 证明时效
//     （created 未来偏移窗口/MID-CLOCK-SKEW、expires 过期与寿命上界 120s/
//     MID-PROOF-EXPIRED、nonce 8~64/MID-NONCE-INVALID）→ 6. 覆盖成分充分性
//     （MID-COVERAGE-INSUFFICIENT）→ 7. 目标绑定（成分不可得的局部可证不一致；
//     密码学不可分部分并入步 9——MID-TARGET-MISMATCH 的可证子集，登记偏差）
//     → 8. content-digest 重算（MID-DIGEST-MISMATCH；体不可读/超预算 →
//     UNKNOWN（不判无效——OBSERVE 放行披露/PROTECT 413））→ 9. 基线重构+验签
//     （MID-SIGNATURE-INVALID）→ 10. 重放原子检查（重复 → MID-REPLAY-DETECTED；
//     存储缺席 → UNAVAILABLE 不判无效严禁本机去重）。
//
// 全过后：principal_binding 一致性（声明且 JWT VERIFIED 不一致 →
// MID-PRINCIPAL-MISMATCH 401）；范围核对（G1 由绑定命中+ENABLED 查找前提天然
// 满足——MID-SCOPE-DENIED 防御分支在册，触发条件随身份行范围维度扩展激活，
// 403 形态与词表冻结在案）。
//
// UNKNOWN 恒不阻断（§1.8 红线）；证明存在≠授权通过（VERIFIED 照过授权/WAF/CC）。
package machineid

import (
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"net/http"
	"strconv"
	"strings"
	"time"

	dsctx "github.com/jiuzhang-waf/gateway/dynamic_security/context"
	"github.com/jiuzhang-waf/gateway/dynamic_security/coverage"
	"github.com/jiuzhang-waf/gateway/dynamic_security/httpsig"
	"github.com/jiuzhang-waf/gateway/dynamic_security/jwtverify"
	"github.com/jiuzhang-waf/gateway/dynamic_security/normalizer"
)

// 状态词表（jwtverify.VerificationResult 五态同形纪律）。
const (
	StatusVerified    = "VERIFIED"
	StatusInvalid     = "INVALID"
	StatusUnavailable = "UNAVAILABLE"
	StatusNotPresent  = "NOT_PRESENT"
	StatusOutOfScope  = "OUT_OF_SCOPE"
)

// 绑定 mode 词表（OBSERVE 缺省|PROTECT——与其他发布段同词表纪律）。
const (
	ModeObserve = "OBSERVE"
	ModeProtect = "PROTECT"
)

// 事件 reason 词表（§5 批次 B2 逐字冻结——17 个 + NARuleID + 覆盖 rule_id）。
const (
	ReasonSignatureMalformed   = "MID-SIGNATURE-MALFORMED"
	ReasonKeyUnknown           = "MID-KEY-UNKNOWN"
	ReasonAlgRejected          = "MID-ALG-REJECTED"
	ReasonKeyRevoked           = "MID-KEY-REVOKED"
	ReasonKeyRetiredExpired    = "MID-KEY-RETIRED-EXPIRED"
	ReasonKeyExpired           = "MID-KEY-EXPIRED"
	ReasonProofExpired         = "MID-PROOF-EXPIRED"
	ReasonClockSkew            = "MID-CLOCK-SKEW"
	ReasonNonceInvalid         = "MID-NONCE-INVALID"
	ReasonCoverageInsufficient = "MID-COVERAGE-INSUFFICIENT"
	ReasonTargetMismatch       = "MID-TARGET-MISMATCH"
	ReasonDigestMismatch       = "MID-DIGEST-MISMATCH"
	ReasonSignatureInvalid     = "MID-SIGNATURE-INVALID"
	ReasonReplayDetected       = "MID-REPLAY-DETECTED"
	ReasonScopeDenied          = "MID-SCOPE-DENIED"
	ReasonPrincipalMismatch    = "MID-PRINCIPAL-MISMATCH"
	ReasonBotExempt            = "MID-BOT-EXEMPT"
	NARuleUnsigned             = "MID-NA-UNSIGNED-001"
	CoverageRuleID             = "id.coverage_v1"
	DetectorName               = "machineid"
)

// 时效与重放冻结常量（§1.4-5/§1.5）。
const (
	DefaultClockSkewSeconds = 30  // 时钟偏移窗口缺省
	MaxClockSkewSeconds     = 120 // 夹紧上限（jwtverify 同纪律）
	MaxProofLifetimeSeconds = 120 // 证明寿命上界（expires-created；重放窗口上界）
	NonceMinLen             = 8
	NonceMaxLen             = 64
)

// KeyRecord 公钥登记行编译产物（发布段 keys[] 消费形态）。
type KeyRecord struct {
	Kid                string
	Alg                string
	PublicKeyPEM       []byte
	Status             string // ACTIVE|RETIRED|REVOKED
	NotBefore          *time.Time
	NotAfter           *time.Time
	RetireOverlapUntil *time.Time // RETIRED 重叠窗口终点（缺省/上限由 server 承载）
	RevokedSeq         int64      // 撤销水位值（溯源）
}

// Identity 机器身份行编译产物。
type Identity struct {
	Name               string
	TenantID           string               // 可空（跨租户共享身份为 NULL+显式——装配层归一空串）
	PrincipalBinding   string               // 可空：绑定 JWT VerifiedPrincipalID 指纹值（声明即强制一致，§1.1）
	Status             string               // ENABLED|DISABLED
	BotChallengeExempt bool                 // §1.7 精确豁免前提（缺省 false）
	Keys               map[string]KeyRecord // kid → 键行（装配期编译）
}

// Registry 登记册（装配期编译产物；Provision 后只读，热加载经实例整体替换）。
type Registry struct {
	byIdentity          map[string]*Identity
	byKeyID             map[string]registryHit // kid →（身份，键）；仅 ENABLED 身份入索引
	RegistryVersion     int64
	RevocationWatermark int64
}

type registryHit struct {
	identity *Identity
	key      *KeyRecord
}

// Binding 绑定行（selector=path_exact|path_prefix 二选一，jwt selector 同形）。
type Binding struct {
	ID            string // 合成绑定标识（application_id+path 事件引用——发布段无独立 ID 列）
	PathExact     string
	PathPrefix    string
	Mode          string // OBSERVE|PROTECT（装配归一）
	ProofRequired bool   // 绑定命中且 true 时未签名请求=拒绝（401）
}

// Config 执行配置（线契约冻结注释口径：per-app selector → {Registry, Mode,
// ProofRequired}；RegistryVersion/RevocationWatermark 随 Registry）。
// 装配层（Guard 单应用实例）按 AppID 过滤入 Apps——Config 仍持全量映射。
type Config struct {
	AppID        string
	Bindings     []Binding        // 本应用绑定行（装配期过滤）
	Registry     *Registry        // nil = 登记册缺席（SKIPPED(COV_NO_REGISTRY)——§1.8）
	SkewSeconds  int64            // 时钟偏移窗口（≤0 缺省 30；夹紧 ≤120）
	IdentitySalt string           // 身份指纹 HMAC 盐（identity_salt 同源——principal_binding/身份指纹共用域纪律）
	Now          func() time.Time // 时钟源（nil = 系统时钟；测试注入）
}

// Result 验证结果（§1.4 成功产出冻结——不可变值类型；不落签名原文/nonce 原文/
// 公钥原文/体原文——nonce 仅以 sha256 摘要参与存储与事件）。
type Result struct {
	Status          string
	ReasonCode      string
	MachineIDFP     string // 身份指纹（判定时非空）
	KeyID           string
	RegistryVersion int64
	Watermark       int64
	// BotExempt Bot 挑战豁免资格（§1.7 三重显式之链内两项：身份 exempt +
	// 绑定命中 + 验证链全步通过——bot_step 消费点再合绑定命中前提）
	BotExempt bool
	BindingID string // 命中绑定标识（豁免事件引用）
}

// BodyUnavailableExtension 挂点侧在请求体超保全上限（含 chunked 未知长度 >4MiB）或读取失败时
// 写入 RequestContext 的扩展键；Evaluate 检测到即按 UNAVAILABLE(body_unavailable) fail-closed，
// 防止大报文/分块流被当作空体绕过 content-digest 校验。
const BodyUnavailableExtension = "machineid.body_unavailable_reason"

// matchBinding 绑定选择器匹配（path_exact 优先；path_prefix 取最长规范化前缀并强制 '/'
// 路径段边界，使 "/api" 不会错误匹配 "/apiv2"；精确优先于前缀，前缀最长优先）。
func (c *Config) matchBinding(path string) *Binding {
	if c == nil {
		return nil
	}
	canonPath := normalizer.CanonicalPath(path)
	var best *Binding
	bestLen := -1
	for i := range c.Bindings {
		b := &c.Bindings[i]
		if b.PathExact != "" && canonPath == normalizer.CanonicalPath(b.PathExact) {
			return b
		}
		if b.PathPrefix != "" && normalizer.PrefixSegmentMatch(b.PathPrefix, canonPath) {
			pref := normalizer.CanonicalPath(b.PathPrefix)
			if pref != "/" {
				pref = strings.TrimSuffix(pref, "/")
			}
			if best == nil || len(pref) > bestLen {
				best = b
				bestLen = len(pref)
			}
		}
	}
	return best
}

// Evaluate 十步验证链（线契约逐字冻结签名，§5 批次 B2）：
// 绑定未命中 = nil（零行为，非候选无覆盖记录）；命中即产覆盖观测（五态如实，
// 每绑定命中请求一条 id.coverage_v1 INFO 双承载明细）。计算全在调用方
// goroutine（无后台任务）。
func Evaluate(ctx *dsctx.RequestContext, r *http.Request, body []byte, cfg *Config, replay *httpsig.ReplayStore, jwtRes *jwtverify.VerificationResult, engineProtect bool) *coverage.Observation {
	if ctx == nil || r == nil || cfg == nil {
		return nil
	}
	b := cfg.matchBinding(r.URL.Path)
	if b == nil {
		return nil
	}
	now := time.Now().UTC()
	if cfg.Now != nil {
		now = cfg.Now().UTC()
	}
	e := &evaluator{ctx: ctx, r: r, cfg: cfg, cov: baseCoverage(ctx, cfg), now: now, engineProtect: engineProtect}
	e.cov.Scope.Bytes = int64(len(body))
	e.result.BindingID = b.ID // 处置闸输入（全结局携带——含 INVALID/UNAVAILABLE）

	// 未签名请求（§1.8：proof_required=false → NOT_APPLICABLE 按普通流量；
	// proof_required=true → 401 准入策略判定（不是 UNKNOWN））
	input := strings.TrimSpace(r.Header.Get("Signature-Input"))
	sig := strings.TrimSpace(r.Header.Get("Signature"))
	if input == "" || sig == "" {
		if b.ProofRequired {
			e.invalid(StatusInvalid, ReasonSignatureMalformed, "signature_absent（proof_required 绑定未签名——准入策略判定非 UNKNOWN）", b)
			e.cov.Status = coverage.StatusFull // 判定完成（准入拒绝）即 FULL
			e.emitCoverage("full", "")
			return e.finish()
		}
		e.result.Status = StatusNotPresent // 未签名按普通流量（准入语义如实）
		e.cov.Status = coverage.StatusNotApplicable
		e.cov.ReasonCode = coverage.ReasonNAFrozenRule
		e.cov.NARuleID = NARuleUnsigned
		e.emitCoverage("not_applicable", "")
		return e.finish()
	}

	// 步 1：头形态解析（SF 子集；恰好一个标签；五参数齐全性）
	p, err := httpsig.ParseHeaders(input, sig, httpsig.DefaultBudgets())
	if err != nil {
		// 头预算触顶同样归入形态畸形族（401——§1.10 413 专属体预算；
		// 头预算随形态错误面，登记偏差）
		e.invalid(StatusInvalid, ReasonSignatureMalformed, err.Error(), b)
		e.emitCoverage("full", "")
		return e.finish()
	}
	e.keyID = p.KeyID
	e.result.KeyID = p.KeyID // 事件 kid 读数（含未登记场景如实）

	// 登记册门（§1.8：登记册缺席 → SKIPPED(COV_NO_REGISTRY)；OBSERVE 放行 /
	// PROTECT 503（依赖不可用不伪装签名错误））
	if cfg.Registry == nil {
		e.dependencyUnavailable("registry_absent", "COV_NO_REGISTRY", b)
		return e.finish()
	}
	e.result.RegistryVersion = cfg.Registry.RegistryVersion
	e.result.Watermark = cfg.Registry.RevocationWatermark

	// 步 2：keyid 登记册精确查找（身份 ENABLED 前提；keyid 只做登记册查找，
	// 任何 URL/URI 形态不触发抓取（§1.3 红线））
	hit, ok := cfg.Registry.lookupEnabled(p.KeyID)
	if !ok {
		e.invalid(StatusInvalid, ReasonKeyUnknown, "keyid 未登记或身份非 ENABLED", b)
		e.emitCoverage("full", "")
		return e.finish()
	}
	e.result.MachineIDFP = identityFingerprint(cfg.IdentitySalt, hit.identity.Name)
	// 步 3：算法白名单 + 登记一致性双重核对（§1.4-3）
	if !algAllowed(p.Alg) || p.Alg != hit.key.Alg {
		e.invalid(StatusInvalid, ReasonAlgRejected, "alg 词表外或与登记不符", b)
		e.emitCoverage("full", "")
		return e.finish()
	}
	// 步 4：键状态机（§1.2：REVOKED 即拒；RETIRED 窗口内放行窗口外拒；
	// not_before/not_after 生效域）
	if reason := keyStateReason(hit.key, now); reason != "" {
		e.invalid(StatusInvalid, reason, "密钥状态机拒绝", b)
		e.emitCoverage("full", "")
		return e.finish()
	}
	// 步 5：证明时效（created 未来偏移/expires 过期与寿命上界/nonce 形态）
	if reason := proofFreshnessReason(p, now, cfg.skewSeconds()); reason != "" {
		e.invalid(StatusInvalid, reason, "证明时效拒绝", b)
		e.emitCoverage("full", "")
		return e.finish()
	}

	// 步 6/7/8/9：覆盖充分性+目标绑定+体摘要+基线重构验签（httpsig 纯库）
	// 体不可读（保全失败、分块流超限或请求有体而未提供体字节）→ UNKNOWN 不判无效
	// （§1.8：OBSERVE 放行披露/PROTECT 413；覆盖 PARTIAL(COV_INPUT_TRUNCATED)）；
	// 无论客户端是否声明 content-digest 均不可当作空体放行（防 chunked >4MiB 绕过）。
	if reasonVal, hasExt := ctx.GetExtension(BodyUnavailableExtension); hasExt {
		reason, _ := reasonVal.(string)
		if reason == "" {
			reason = "body_too_large"
		}
		e.dependencyUnavailableBody("body_unavailable（"+reason+"——体保全失败或超 4MiB 预算，fail-closed）", b)
		return e.finish()
	}
	bodyUnreadable := (r.ContentLength > 0 && len(body) == 0) ||
		(r.ContentLength < 0 && r.Body != nil && r.Body != http.NoBody && len(body) == 0)
	if bodyUnreadable {
		e.dependencyUnavailableBody("body_unavailable（体保全失败——有体/分块请求未提供体字节，fail-closed）", b)
		return e.finish()
	}
	verr := httpsig.VerifySignatureBase(r, p, body, httpsig.Key{Kid: p.KeyID, Alg: hit.key.Alg, PublicKeyPEM: hit.key.PublicKeyPEM})
	if verr != nil {
		if errors.Is(verr, httpsig.ErrBudget) {
			// 体超预算 → UNKNOWN（不判无效——PROTECT 413 语义）
			e.dependencyUnavailableBody("body_budget_exceeded（体超 4MiB 预算——content-digest 未验不判无效）", b)
			return e.finish()
		}
		e.invalid(StatusInvalid, mapVerifyError(verr), "验签链拒绝", b)
		e.emitCoverage("full", "")
		return e.finish()
	}

	// 步 10：重放原子检查（§1.5：重复 → MID-REPLAY-DETECTED 401；存储缺席 →
	// UNAVAILABLE（§1.8/D8/D10，不判无效——严禁本机去重））
	if replay == nil {
		e.dependencyUnavailable("replay_store_absent", "COV_DEPENDENCY_UNAVAILABLE", b)
		return e.finish()
	}
	nonceDigest := sha256.Sum256([]byte(p.Nonce))
	ttl := proofTTL(p, now, cfg.skewSeconds())
	isReplay, rerr := replay.CheckAndSet(r.Context(), e.result.MachineIDFP, hex.EncodeToString(nonceDigest[:])[:32], ttl)
	if rerr != nil {
		e.dependencyUnavailable("replay_store_error: "+rerr.Error(), "COV_DEPENDENCY_UNAVAILABLE", b)
		return e.finish()
	}
	if isReplay {
		e.invalid(StatusInvalid, ReasonReplayDetected, "nonce 重放检出", b)
		e.emitCoverage("full", "")
		return e.finish()
	}

	// principal_binding 一致性（§1.1：身份行声明且 JWT 同请求 VERIFIED 时
	// 两者必须一致——不融合裁决不静默择优；JWT 缺席时机器身份独立成立）
	if hit.identity.PrincipalBinding != "" && jwtRes != nil && jwtRes.Status == jwtverify.StatusVerified {
		if principalFingerprint(cfg.IdentitySalt, jwtRes.VerifiedPrincipalID) != hit.identity.PrincipalBinding {
			e.invalid(StatusInvalid, ReasonPrincipalMismatch, "principal_binding 与 JWT VERIFIED 主体不一致", b)
			e.emitCoverage("full", "")
			return e.finish()
		}
	}

	// 范围核对（§1.4 末行；G1 由绑定命中+ENABLED 查找前提天然满足——
	// MID-SCOPE-DENIED 防御分支在册，词表与 403 形态冻结）
	if reason := e.scopeCheck(b, hit.identity); reason != "" {
		e.result.Status = StatusOutOfScope
		e.result.ReasonCode = reason
		e.cov.Status = coverage.StatusFull
		e.emitCoverage("full", "")
		return e.finish()
	}

	// 全部通过：VERIFIED（证明存在≠授权通过——后续授权/WAF/CC 照常）
	e.result.Status = StatusVerified
	e.result.BotExempt = hit.identity.BotChallengeExempt
	e.result.BindingID = b.ID
	e.cov.Status = coverage.StatusFull
	e.emitCoverage("full", "")
	return e.finish()
}

// Result 取评估结果（评估器内部承载——Evaluate 返回值是覆盖观测（冻结签名），
// 结果经此通道并行取出）。
// ResultFromEvaluate / Result 已废弃——结果经请求上下文扩展「machineid.result」
// 传递（ResultFromContext），Evaluate 各收口点统一写入。

// resultExtKey 验证结果上下文扩展键（compute-only 挂点的传递通道——
// jwtResultKey 同形纪律）。
const resultExtKey = "machineid.result"

// ResultFromContext 取本次评估结果（未评估为 nil——机器身份挂点零行为消费）。
func ResultFromContext(ctx *dsctx.RequestContext) *Result {
	if ctx == nil {
		return nil
	}
	v, ok := ctx.GetExtension(resultExtKey)
	if !ok {
		return nil
	}
	res, _ := v.(*Result)
	return res
}

// finish 收口统一出口：结果写上下文扩展 + 返回覆盖观测。
func (e *evaluator) finish() *coverage.Observation {
	res := e.result
	e.ctx.SetExtension(resultExtKey, &res)
	return e.cov
}

// evaluator 链评估器（单请求单次使用）。
type evaluator struct {
	ctx           *dsctx.RequestContext
	r             *http.Request
	cfg           *Config
	cov           *coverage.Observation
	now           time.Time
	engineProtect bool
	keyID         string
	result        Result
}

// invalid 证明未通过收口（401 语义；明细 OBSERVE/BLOCK 按双闸——machineid 的
// 实断定案不走统一决策引擎（独立处置点 serveNext 直写），明细 Category 仅记录
// 拟动作语义（PROTECT 将实断 → BLOCK，否则 OBSERVE））。
func (e *evaluator) invalid(status, reason, detail string, b *Binding) {
	e.result.Status = status
	e.result.ReasonCode = reason
	e.addFinding("machineid.failed", reason, detail, b)
	if e.cov.Status == "" {
		e.cov.Status = coverage.StatusFull // 判定完成即 FULL（拒绝亦是判定完成）
	}
}

// dependencyUnavailable 依赖缺席收口（§1.8：登记册/重放存储缺席 →
// UNAVAILABLE（OBSERVE 放行披露/PROTECT 503——不伪装证明错误））。
func (e *evaluator) dependencyUnavailable(detail, covReason string, b *Binding) {
	e.result.Status = StatusUnavailable
	e.result.ReasonCode = "" // UNAVAILABLE 是依赖状态非证明判定——reason 空置如实
	e.ctx.AddMatch(dsctx.DetectorMatch{
		Detector: DetectorName,
		RuleID:   "machineid.dependency_unavailable",
		Category: "OBSERVE",
		Severity: "HIGH",
		Message:  "machine identity dependency unavailable (fail-open OBSERVE / 503 PROTECT, not a proof failure)",
		Evidence: map[string]string{"dependency_unavailable": "true", "detail": detail, "keyid": e.keyID},
	})
	e.cov.Status = coverage.StatusSkipped
	switch covReason {
	case "COV_NO_REGISTRY":
		e.cov.ReasonCode = coverage.ReasonNoRegistry
	default:
		e.cov.ReasonCode = coverage.ReasonDependencyUnavailable
	}
	e.emitCoverage("skipped", strings.ToLower(strings.TrimPrefix(covReason, "COV_")))
}

// dependencyUnavailableBody 体不可读/超预算收口（§1.8：UNKNOWN 不判无效——
// OBSERVE 放行披露/PROTECT 413；覆盖 PARTIAL(COV_INPUT_TRUNCATED)）。
func (e *evaluator) dependencyUnavailableBody(detail string, b *Binding) {
	e.result.Status = StatusUnavailable
	e.result.ReasonCode = "" // 依赖/输入不可用非证明判定
	e.ctx.AddMatch(dsctx.DetectorMatch{
		Detector: DetectorName,
		RuleID:   "machineid.body_unavailable",
		Category: "OBSERVE",
		Severity: "HIGH",
		Message:  "machine identity content-digest not evaluated (body unreadable/over budget, not invalid)",
		Evidence: map[string]string{"dependency_unavailable": "true", "detail": detail, "keyid": e.keyID},
	})
	e.cov.Status = coverage.StatusPartial
	e.cov.ReasonCode = coverage.ReasonInputTruncated
	e.cov.Truncated = true
	e.emitCoverage("partial", "input_truncated")
}

// scopeCheck 范围核对（§1.4 末行；G1 由绑定命中+ENABLED 查找前提天然满足——
// 返回空串=通过；MID-SCOPE-DENIED 触发条件随身份行范围维度扩展激活，防御分支）。
func (e *evaluator) scopeCheck(_ *Binding, identity *Identity) string {
	if identity.Status != "ENABLED" {
		return ReasonScopeDenied // 防御：登记册索引前提被破坏（ENABLED 前提外泄）
	}
	return ""
}

// emitCoverage id.coverage_v1 INFO 明细（双承载之一；Emitter 由挂点侧发射）。
func (e *evaluator) emitCoverage(completion, skipReason string) {
	evidence := map[string]string{
		"direction":  "request",
		"completion": completion,
	}
	if skipReason != "" {
		evidence["skip_reason"] = skipReason
	}
	if e.result.MachineIDFP != "" {
		evidence["identity_fp"] = e.result.MachineIDFP
	}
	if e.keyID != "" {
		evidence["kid"] = truncateMid(e.keyID, 128)
	}
	if e.result.RegistryVersion != 0 {
		evidence["registry_version"] = strconv.FormatInt(e.result.RegistryVersion, 10)
	}
	if e.result.Watermark != 0 {
		evidence["watermark"] = strconv.FormatInt(e.result.Watermark, 10)
	}
	e.ctx.AddMatch(dsctx.DetectorMatch{
		Detector: DetectorName,
		RuleID:   CoverageRuleID,
		Category: "INFO",
		Severity: "INFO",
		Message:  "machine identity coverage",
		Evidence: evidence,
	})
}

// addFinding 失败判定明细（reason code 词表冻结；证据不落签名/nonce/公钥原文——
// nonce 仅以 sha256 摘要参与存储与事件（§1.10/§4.2-8 红线））。
func (e *evaluator) addFinding(ruleID, reason, detail string, b *Binding) {
	category := "OBSERVE"
	if b.Mode == "PROTECT" && e.engineProtect {
		category = "BLOCK"
	}
	evidence := map[string]string{
		"reason_code": reason,
		"detail":      truncateMid(detail, 256),
		"binding_id":  b.ID,
		"mode":        b.Mode,
	}
	if e.keyID != "" {
		evidence["kid"] = truncateMid(e.keyID, 128)
	}
	if e.result.MachineIDFP != "" {
		evidence["identity_fp"] = e.result.MachineIDFP
	}
	e.ctx.AddMatch(dsctx.DetectorMatch{
		Detector:   DetectorName,
		RuleID:     ruleID,
		Category:   category,
		Severity:   "HIGH",
		Confidence: 1.0,
		Evidence:   evidence,
	})
}

// baseCoverage 覆盖观测底座。
func baseCoverage(ctx *dsctx.RequestContext, cfg *Config) *coverage.Observation {
	return &coverage.Observation{
		RequestID: ctx.RequestID,
		Detector:  DetectorName,
		Phase:     coverage.PhaseRequest,
		Scope:     coverage.ScopeDeclared{Messages: 1, Direction: "request"},
	}
}

// truncateMid 证据字段截断。
func truncateMid(s string, max int) string {
	if len(s) > max {
		return s[:max]
	}
	return s
}

// MatchBindingPath 绑定命中判定（挂点侧零行为预检——Evaluate 内部同一选择器）。
func (c *Config) MatchBindingPath(path string) bool {
	return c.matchBinding(path) != nil
}

// BindingMode 按合成绑定标识取 mode（处置闸消费；未知空串）。
func (c *Config) BindingMode(id string) string {
	if c == nil {
		return ""
	}
	for i := range c.Bindings {
		if c.Bindings[i].ID == id {
			return c.Bindings[i].Mode
		}
	}
	return ""
}

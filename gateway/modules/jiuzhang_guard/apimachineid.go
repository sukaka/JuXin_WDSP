// apimachineid.go 机器身份（HTTP Message Signatures）网关装配与挂接
// （NG-ID G1 批次 B2，docs/nextgen/NG-ID-g1-machine-identity.md §1.2 登记模型
// 消费 + §1.6 水位 + §1.10 错误语义 + §1.11 能力 + §1.13 覆盖）。
//
// 装配纪律（jwt_trust.go:99-129 fail-closed 同纪律 + apimcpguard fail-safe 归一）：
//   - 三段全缺 = nil（全链零行为 NG-T-C01）；
//   - 绑定行 mode 词表外归一 OBSERVE+Warn、字段空缺跳行+Warn、公钥 PEM 解析失败
//     行拒装+Warn（fail-safe 不误断）——**含 PROTECT 绑定时任何装配缺陷拒绝整体
//     配置加载**（fail-closed：已存在 PROTECT 策略不得被静默降级）；
//   - 快照 revocation_watermark < 本应用已应用水位 → 拒绝该快照（fail-closed
//     保留旧配置——AUTHZ_WATERMARK_REGRESSION 先例同形态；普通策略回滚不复活
//     已撤销密钥，§1.6）；
//   - 身份 status 词表 ENABLED|DISABLED；键 status 词表 ACTIVE|RETIRED|REVOKED；
//     alg 词表 ed25519|ecdsa-p256-sha256|rsa-pss-sha512（hmac/rsa-v1_5 排除）；
//   - keyid 只做登记册精确查找，任何 URL/URI 形态 keyid 不触发抓取（§1.3 红线
//     ——热路径零网络 IO，纯 map 索引天然成立）。
package jiuzhang_guard

import (
	"context"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"net/http"
	"strconv"
	"strings"
	"sync"
	"time"

	dsctx "github.com/jiuzhang-waf/gateway/dynamic_security/context"
	"github.com/jiuzhang-waf/gateway/dynamic_security/coverage"
	"github.com/jiuzhang-waf/gateway/dynamic_security/detectors/machineid"
	"github.com/jiuzhang-waf/gateway/dynamic_security/httpsig"
	"github.com/jiuzhang-waf/gateway/dynamic_security/jwtverify"
	"github.com/jiuzhang-waf/gateway/dynamic_security/normalizer"
	"github.com/jiuzhang-waf/gateway/modules/jiuzhang_guard/clientip"
	"github.com/jiuzhang-waf/gateway/modules/jiuzhang_guard/events"
	"github.com/jiuzhang-waf/gateway/modules/jiuzhang_guard/identitybehavior"
	"go.uber.org/zap"
)

// ---------- 发布段 JSON（跨轨线契约逐字冻结——json tag 不得改名） ----------

// machineIdentityJSON 机器身份（api_machine_identities 数组项）。
type machineIdentityJSON struct {
	IdentityName       string                   `json:"identity_name"`
	TenantID           string                   `json:"tenant_id"`
	PrincipalBinding   string                   `json:"principal_binding"`
	Status             string                   `json:"status"`
	BotChallengeExempt bool                     `json:"bot_challenge_exempt"`
	Keys               []machineIdentityKeyJSON `json:"keys"`
}

// machineIdentityKeyJSON 公钥行（公钥非秘密，明文 PEM 合法；状态机 ACTIVE|
// RETIRED|REVOKED + 重叠窗口终点 + 生效域 + 撤销水位溯源）。
type machineIdentityKeyJSON struct {
	Kid                string     `json:"kid"`
	Alg                string     `json:"alg"`
	PublicKeyPEM       string     `json:"public_key_pem"`
	Status             string     `json:"status"`
	NotBefore          *time.Time `json:"not_before"`
	NotAfter           *time.Time `json:"not_after"`
	RetireOverlapUntil *time.Time `json:"retire_overlap_until"`
	RevokedSeq         int64      `json:"revoked_seq"`
}

// machineIDBindingJSON 绑定行（api_machine_identity_bindings 数组项）。
type machineIDBindingJSON struct {
	ApplicationID string `json:"application_id"`
	PathExact     string `json:"path_exact"`
	PathPrefix    string `json:"path_prefix"`
	Mode          string `json:"mode"`
	ProofRequired bool   `json:"proof_required"`
}

// machineIDMetaJSON 元数据（api_machine_identity_meta 段）。
type machineIDMetaJSON struct {
	RevocationWatermark int64 `json:"revocation_watermark"`
	RegistryVersion     int64 `json:"registry_version"`
}

// ---------- 撤销水位注册表（AUTHZ 先例同形态：进程级 per-app 已应用水位） ----------

// machineIDWatermarkRegistry 机器身份撤销水位注册表（本应用已应用水位记忆——
// 快照水位低于它即拒载（fail-closed，单调不下降，普通回滚不复活已撤销密钥））。
var machineIDWatermarkRegistry = struct {
	mu   sync.Mutex
	byID map[string]int64
}{byID: map[string]int64{}}

func machineIDAppliedWatermark(appID string) (int64, bool) {
	machineIDWatermarkRegistry.mu.Lock()
	defer machineIDWatermarkRegistry.mu.Unlock()
	v, ok := machineIDWatermarkRegistry.byID[appID]
	return v, ok
}

func registerMachineIDAppliedWatermark(appID string, watermark int64) {
	machineIDWatermarkRegistry.mu.Lock()
	defer machineIDWatermarkRegistry.mu.Unlock()
	machineIDWatermarkRegistry.byID[appID] = watermark
}

func resetMachineIDWatermarkForTest() {
	machineIDWatermarkRegistry.mu.Lock()
	defer machineIDWatermarkRegistry.mu.Unlock()
	machineIDWatermarkRegistry.byID = map[string]int64{}
}

// checkMachineIDWatermarkRegression 快照水位回退拒载（fail-closed——Provision
// 拒绝，Caddy 保留旧配置；MID_WATERMARK_REGRESSION 告警 zap+API 事件日志留痕，
// AUTHZ_WATERMARK_REGRESSION 同形态）。
func (g *Guard) checkMachineIDWatermarkRegression() error {
	if g.APIMachineIDMeta == nil {
		return nil // 无 meta 段（v1 兼容——不校验）
	}
	incoming := g.APIMachineIDMeta.RevocationWatermark
	prev, ok := machineIDAppliedWatermark(g.AppID)
	if !ok || incoming >= prev {
		return nil
	}
	g.logger.Error("MID_WATERMARK_REGRESSION: incoming machine identity snapshot watermark below applied, config load rejected (fail-closed)",
		zap.String("app_id", g.AppID),
		zap.Int64("incoming", incoming),
		zap.Int64("applied", prev))
	return fmt.Errorf("api_machine_identity_meta: revocation watermark regression (incoming=%d < applied=%d), config load rejected", incoming, prev)
}

// ---------- 装配 ----------

// buildMachineIDConfig 机器身份装配置装配（fail-safe 归一 + PROTECT 含缺陷
// fail-closed；nil = 三段全缺零行为）。
func (g *Guard) buildMachineIDConfig() (*machineid.Config, error) {
	if len(g.APIMachineIdentities) == 0 && len(g.APIMachineIDBindings) == 0 {
		return nil, nil
	}
	var defects int
	warn := func(msg string, kv ...zap.Field) {
		defects++
		kv = append([]zap.Field{zap.String("reason", msg)}, kv...)
		g.logger.Warn("api_machine_identity 装配缺陷（fail-safe 归一）", kv...)
	}
	// 身份与键编译
	identities := make([]machineid.Identity, 0, len(g.APIMachineIdentities))
	for i, ij := range g.APIMachineIdentities {
		name := strings.TrimSpace(ij.IdentityName)
		if name == "" || len(name) > 128 {
			warn("identity_name 空缺/超长跳行", zap.Int("index", i))
			continue
		}
		status := strings.ToUpper(strings.TrimSpace(ij.Status))
		if status != "ENABLED" && status != "DISABLED" {
			g.logger.Warn("api_machine_identities status 词表外按 DISABLED 处置（不误放）",
				zap.String("identity", name), zap.String("status", ij.Status))
			status = "DISABLED"
		}
		id := machineid.Identity{
			Name: name, TenantID: strings.TrimSpace(ij.TenantID),
			PrincipalBinding: strings.TrimSpace(ij.PrincipalBinding), Status: status,
			BotChallengeExempt: ij.BotChallengeExempt,
			Keys:               map[string]machineid.KeyRecord{},
		}
		for _, kj := range ij.Keys {
			kid := strings.TrimSpace(kj.Kid)
			if kid == "" || len(kid) > 128 {
				warn("kid 空缺/超长跳行", zap.String("identity", name))
				continue
			}
			alg := strings.TrimSpace(kj.Alg)
			switch alg {
			case httpsig.AlgEd25519, httpsig.AlgECDSAP256SHA256, httpsig.AlgRSAPSSSHA512:
			default:
				warn("alg 词表外跳行（hmac/rsa-v1_5 排除）", zap.String("identity", name), zap.String("kid", kid), zap.String("alg", kj.Alg))
				continue
			}
			// 公钥 PEM 解析校验（管理面导入时已校验，装配期复核——PEM 原文不落日志）
			pemRaw := strings.TrimSpace(kj.PublicKeyPEM)
			if pemRaw == "" {
				warn("public_key_pem 空缺跳行", zap.String("identity", name), zap.String("kid", kid))
				continue
			}
			blk, _ := pem.Decode([]byte(pemRaw))
			if blk == nil || !strings.Contains(blk.Type, "PUBLIC KEY") {
				warn("public_key_pem 形态非法拒装", zap.String("identity", name), zap.String("kid", kid))
				continue
			}
			pub, err := x509.ParsePKIXPublicKey(blk.Bytes)
			if err != nil || pub == nil {
				warn("public_key_pem 解析失败拒装", zap.String("identity", name), zap.String("kid", kid))
				continue
			}
			kStatus := strings.ToUpper(strings.TrimSpace(kj.Status))
			if kStatus != "ACTIVE" && kStatus != "RETIRED" && kStatus != "REVOKED" {
				g.logger.Warn("key status 词表外按 REVOKED 处置（不误放）", zap.String("identity", name), zap.String("kid", kid))
				kStatus = "REVOKED"
			}
			id.Keys[kid] = machineid.KeyRecord{
				Kid: kid, Alg: alg, PublicKeyPEM: []byte(pemRaw), Status: kStatus,
				NotBefore: kj.NotBefore, NotAfter: kj.NotAfter,
				RetireOverlapUntil: kj.RetireOverlapUntil, RevokedSeq: kj.RevokedSeq,
			}
		}
		identities = append(identities, id)
	}
	// 绑定归一（本应用行；selector 二选一校验——jwt selector 同形）
	var bindings []machineid.Binding
	hasProtect := false
	for i, bj := range g.APIMachineIDBindings {
		if strings.TrimSpace(bj.ApplicationID) != "" && bj.ApplicationID != g.AppID {
			continue // 他应用行（多应用同进程防御——Guard 单应用实例口径）
		}
		exact := strings.TrimSpace(bj.PathExact)
		prefix := strings.TrimSpace(bj.PathPrefix)
		if (exact == "") == (prefix == "") {
			warn("path_exact/path_prefix 须二选一", zap.Int("index", i))
			continue
		}
		if exact != "" && !strings.HasPrefix(exact, "/") || prefix != "" && !strings.HasPrefix(prefix, "/") {
			warn("selector 须 / 开头", zap.Int("index", i))
			continue
		}
		mode := strings.ToUpper(strings.TrimSpace(bj.Mode))
		if mode == "" {
			mode = machineid.ModeObserve
		}
		if mode != machineid.ModeObserve && mode != machineid.ModeProtect {
			warn("mode 词表外归一 OBSERVE", zap.Int("index", i), zap.String("mode", bj.Mode))
			mode = machineid.ModeObserve
		}
		sel := exact
		if sel == "" {
			sel = prefix
		}
		bindings = append(bindings, machineid.Binding{
			ID: g.AppID + "|" + sel, PathExact: exact, PathPrefix: prefix,
			Mode: mode, ProofRequired: bj.ProofRequired,
		})
		if mode == machineid.ModeProtect {
			hasProtect = true
		}
	}
	// fail-closed：含 PROTECT 绑定时任何装配缺陷拒绝整体配置加载
	// （jwt_trust.go:99-129 同纪律——已存在 PROTECT 策略不得被静默降级）
	if hasProtect && defects > 0 {
		return nil, fmt.Errorf("api_machine_identity: %d 装配缺陷且含 PROTECT 绑定，拒绝整体配置加载（fail-closed）", defects)
	}
	cfg := &machineid.Config{
		AppID: g.AppID, Bindings: bindings, IdentitySalt: g.IdentitySalt,
	}
	if len(identities) > 0 || g.APIMachineIDMeta != nil {
		var version, watermark int64
		if g.APIMachineIDMeta != nil {
			version = g.APIMachineIDMeta.RegistryVersion
			watermark = g.APIMachineIDMeta.RevocationWatermark
		}
		cfg.Registry = machineid.NewRegistry(identities, version, watermark)
	}
	// 绑定存在但登记册缺席（无身份段）：Registry nil——运行期 SKIPPED(COV_NO_REGISTRY)
	// OBSERVE 放行/PROTECT 503（依赖缺席不伪装证明错误——§1.8）
	return cfg, nil
}

// ---------- 验证点与处置点挂接 ----------

// machineIDOutcomeKey 机器身份评估结果请求上下文键（验证点写入，处置点/
// Bot 豁免/事件输出消费——jwtResultKey 同形纪律）。
type machineIDOutcomeKey struct{}

// machineIDOutcome 评估结果（验证点产出；Result + 明细 + 覆盖随行）。
type machineIDOutcome struct {
	Result   *machineid.Result
	Matches  []dsctx.DetectorMatch
	Coverage *coverage.Observation
}

// machineIDOutcomeFrom 取请求上下文中的机器身份评估结果。
func machineIDOutcomeFrom(ctx context.Context) *machineIDOutcome {
	v, _ := ctx.Value(machineIDOutcomeKey{}).(*machineIDOutcome)
	return v
}

// verifyMachineIdentity serveGuard 挂点（NG-ID G1：紧随 JWT 验证之后、身份观测
// 前——compute-only 入上下文（jwt_trust.go:206-224 同形挂点）。纯本地、热路径零
// 网络 IO；recover → UNAVAILABLE 不 panic（jwtverify Verifier.Verify 同纪律）；
// 体读取复用保全同源纪律（≤4MiB 读出即还原，内存重读零新增网络读取）。
// VERIFIED 时注入独立机器身份信号（identitybehavior.WithVerifiedMachineIdentity
// 同形机制——不改 identity_key/identity_type 语义，AGENTS.md 红线）。
func (g *Guard) verifyMachineIdentity(r *http.Request) {
	cfg := g.apiMachineID
	if cfg == nil {
		return
	}
	canonPath := normalizer.CanonicalPath(r.URL.Path)
	if !cfg.MatchBindingPath(canonPath) {
		return // 未命中绑定：零行为零覆盖（非候选）
	}
	requestID := r.Header.Get("X-Request-Id")
	rc := dsctx.New(requestID, dsctx.DefaultParseLimits())
	var body []byte
	// 仅携带签名头时才读体（零行为优先；体读取=保全同源纪律读出即还原）
	if r.Header.Get("Signature-Input") != "" || r.Header.Get("Signature") != "" {
		restore, bodySample, skipReason := preserveRequestBody(r)
		if restore != nil {
			body = bodySample
			restore() // 立即还原（后续 serveNext 保全重读为内存重读——零新增网络读取）
		} else {
			// 超 4MiB（含 chunked 未知长度）或读体失败：显式标记不可用，禁止当作空体放行（H-10）
			rc.SetExtension(machineid.BodyUnavailableExtension, skipReason)
		}
	}
	jwtRes, hasJWT := jwtResultFrom(r.Context())
	var jwtPtr *jwtverify.VerificationResult
	if hasJWT {
		jwtPtr = &jwtRes
	}
	cov := machineid.Evaluate(rc, r, body, cfg, g.machineIDReplay, jwtPtr, true)
	if cov != nil {
		cov.ApplicationID = g.AppID
		cov.NodeID = coverageNodeName()
		cov.PolicyVersion = g.APIPolicyVersion
		cov.EndpointKey = r.Method + " " + r.URL.Path
		if em := coverageEmitter(); em != nil {
			em.Emit(*cov)
		}
	}
	res := machineid.ResultFromContext(rc)
	*r = *r.WithContext(context.WithValue(r.Context(), machineIDOutcomeKey{}, &machineIDOutcome{
		Result: res, Matches: rc.CopyMatches(), Coverage: cov,
	}))
	if res != nil && res.Status == machineid.StatusVerified {
		// 独立信号注入（不改 identity_key/identity_type 语义——AGENTS.md 红线+
		// identity.go:63-70 先例；同请求可双 VERIFIED（JWT 主体+机器身份并存））
		*r = *r.WithContext(identitybehavior.WithVerifiedMachineIdentity(r.Context(), &identitybehavior.VerifiedMachineIdentity{
			MachineIDFP:     res.MachineIDFP,
			KeyID:           res.KeyID,
			RegistryVersion: res.RegistryVersion,
		}))
	}
}

// enforceMachineIdentity serveNext 处置点（与 enforceJWTTrust 同段——白名单/L7
// allow 不绕过（安全底线）；committed 直写不走 Caddy 错误链；401 不带
// WWW-Authenticate（RFC 9421 未注册标准 challenge 方案，自带即冒用，§1.10））。
// 返回 handled=true 表示已响应（401/403/503/413），err 恒为 nil。
func (g *Guard) enforceMachineIdentity(w http.ResponseWriter, r *http.Request) (bool, error) {
	if g.apiMachineID == nil {
		return false, nil
	}
	outcome := machineIDOutcomeFrom(r.Context())
	if outcome == nil || outcome.Result == nil {
		return false, nil
	}
	res := outcome.Result
	dispo := DispositionFrom(r.Context())
	switch res.Status {
	case machineid.StatusVerified:
		// VERIFIED 不产生全局放行（后续授权/WAF/CC 照常）——审计事件在册
		g.emitMachineIDEvent(r, events.MIDVerified, "OBSERVE", 0, outcome)
		return false, nil
	case machineid.StatusNotPresent, "":
		return false, nil // 未签名按普通流量（proof_required=false）
	case machineid.StatusInvalid:
		if !g.machineIDEnforces(res) {
			// OBSERVE 记录放行（拟动作保留）
			g.emitMachineIDEvent(r, events.MIDObserved, "OBSERVE", 0, outcome)
			dispo.RecordStep(ExecutorAPI, StepObserved, "machineid status=INVALID reason="+res.ReasonCode)
			return false, nil
		}
		// PROTECT 401 固定短语（不带 WWW-Authenticate——不冒用未注册方案）
		dispo.RecordTerminal(ExecutorAPI, DisActionBlock, http.StatusUnauthorized, true,
			[]string{res.ReasonCode}, nil)
		accessLogAnnotate(r.Context(), wafActionBlock)
		g.writeMachineIDAuthFailed(w, r.Header.Get("X-Request-Id"))
		g.emitMachineIDEvent(r, events.MIDAuthFailed, "REJECT", http.StatusUnauthorized, outcome)
		return true, nil
	case machineid.StatusOutOfScope:
		if !g.machineIDEnforces(res) {
			g.emitMachineIDEvent(r, events.MIDObserved, "OBSERVE", 0, outcome)
			return false, nil
		}
		// PROTECT 403（证明通过但越界——401≠403 形态区分，M01 同思想）
		dispo.RecordTerminal(ExecutorAPI, DisActionBlock, http.StatusForbidden, true,
			[]string{machineid.ReasonScopeDenied}, nil)
		accessLogAnnotate(r.Context(), wafActionBlock)
		g.writeMachineIDScopeDenied(w, r.Header.Get("X-Request-Id"))
		g.emitMachineIDEvent(r, events.MIDScopeDenied, "REJECT", http.StatusForbidden, outcome)
		return true, nil
	case machineid.StatusUnavailable:
		if !g.machineIDEnforces(res) {
			// OBSERVE 放行+披露（dependency_unavailable 明细已在评估期产出）
			g.emitMachineIDEvent(r, events.MIDObserved, "OBSERVE", 0, outcome)
			return false, nil
		}
		// PROTECT：依赖不可用 503（不伪装证明错误）/体预算 413（§1.10 分明）
		status := http.StatusServiceUnavailable
		if outcome.bodyBudget() {
			status = http.StatusRequestEntityTooLarge
		}
		dispo.RecordTerminal(ExecutorAPI, DisActionBlock, status, true,
			[]string{"MID_UNAVAILABLE"}, nil)
		accessLogAnnotate(r.Context(), wafActionBlock)
		g.writeMachineIDUnavailable(w, r.Header.Get("X-Request-Id"), status)
		g.emitMachineIDEvent(r, events.MIDUnavailable, "REJECT", status, outcome)
		return true, nil
	default:
		return false, nil
	}
}

// machineIDEnforces 处置闸（绑定 mode=PROTECT 即实断——机器身份为独立信任链
// （jwt_trust 同纪律：不经 API 引擎模式）；engineProtect 形参在验证点恒传 true
// （登记偏差——冻结签名的引擎闸在本链按绑定 mode 独立成立））。
func (g *Guard) machineIDEnforces(res *machineid.Result) bool {
	return res != nil && res.BindingID != "" && g.apiMachineID != nil &&
		g.apiMachineID.BindingMode(res.BindingID) == machineid.ModeProtect
}

// writeMachineIDAuthFailed 401 固定短语（§1.10：{"error":"machine_identity_failed",
// "request_id":...}——防探测；不携带 WWW-Authenticate）。
func (g *Guard) writeMachineIDAuthFailed(w http.ResponseWriter, requestID string) {
	g.writeMachineIDJSON(w, requestID, http.StatusUnauthorized, "machine_identity_failed")
}

// writeMachineIDScopeDenied 403 越界固定短语（证明通过但越界——401≠403 形态区分）。
func (g *Guard) writeMachineIDScopeDenied(w http.ResponseWriter, requestID string) {
	g.writeMachineIDJSON(w, requestID, http.StatusForbidden, "machine_identity_scope_denied")
}

// writeMachineIDUnavailable 依赖不可用固定短语（503 依赖/413 体预算——
// jwt_trust.go:340-352 先例，不伪装证明错误不带重试诱导）。
func (g *Guard) writeMachineIDUnavailable(w http.ResponseWriter, requestID string, status int) {
	g.writeMachineIDJSON(w, requestID, status, "machine_identity_unavailable")
}

// writeMachineIDJSON 固定 JSON 写出（committed 直写；键序字典序——
// error < request_id，响应体精确匹配测试依赖此序）。
func (g *Guard) writeMachineIDJSON(w http.ResponseWriter, requestID string, status int, errText string) {
	h := w.Header()
	h.Del("Content-Length")
	h.Set("Content-Type", "application/json; charset=utf-8")
	h.Set("X-Jiuzhang-Request-ID", requestID)
	body, _ := json.Marshal(map[string]string{"error": errText, "request_id": requestID})
	h.Set("Content-Length", strconv.Itoa(len(body)))
	w.WriteHeader(status)
	if _, err := w.Write(body); err != nil {
		g.logger.Warn("machine identity response write failed", zap.Error(err), zap.String("request_id", requestID))
	}
}

// emitMachineIDEvent 机器身份事件（access_control_events——JWT 事件同通道；
// 不落签名原文/nonce 原文/公钥原文/体原文（§1.10/§4.2-8 红线）——身份为
// HMAC 指纹，nonce 仅以 sha256 摘要参与存储）。
// emitMachineIDEvent 机器身份事件（access_control_events——JWT 事件同通道；
// 不落签名原文/nonce 原文/公钥原文/体原文（§1.10/§4.2-8 红线）——身份为
// HMAC 指纹，nonce 仅以 sha256 摘要参与存储）。UNAVAILABLE 的依赖披露明细
// 经 detail 随行（从评估期 dependency_unavailable 明细提取）。
func (g *Guard) emitMachineIDEvent(r *http.Request, t events.Type, action string, status int, outcome *machineIDOutcome) {
	res := outcome.Result
	ev := g.eventBase(r, r.Header.Get("X-Request-Id"), machineIDClientIPResult(r))
	detail := ""
	for _, m := range outcome.Matches {
		if m.Evidence["dependency_unavailable"] == "true" {
			detail = "dependency_unavailable:" + m.Evidence["detail"]
			break
		}
	}
	ev.MachineID = &events.MachineIDDetail{
		Status:          res.Status,
		ReasonCode:      res.ReasonCode,
		MachineIDFP:     res.MachineIDFP,
		KeyID:           res.KeyID,
		RegistryVersion: res.RegistryVersion,
		Watermark:       res.Watermark,
		Detail:          detail,
	}
	g.emit(ev, t, action, status)
}

// machineIDClientIPResult 事件 IP 字段取数（与 eventBase 同口径——
// 请求上下文已有 clientip.Result 时复用，缺席零值容忍）。
func machineIDClientIPResult(r *http.Request) clientip.Result {
	if res, ok := clientIPResultFrom(r.Context()); ok {
		return res
	}
	return clientip.Result{}
}

// machineIDBotExempt Bot 豁免判定（§1.7 三重显式：验证链 VERIFIED +
// 身份行 bot_challenge_exempt=true + 绑定命中（Evaluate 只在命中时产出））。
func (g *Guard) machineIDBotExempt(r *http.Request) bool {
	outcome := machineIDOutcomeFrom(r.Context())
	return outcome != nil && outcome.Result != nil &&
		outcome.Result.Status == machineid.StatusVerified && outcome.Result.BotExempt
}

// bodyBudget UNAVAILABLE 细分（体预算 → 413；依赖 → 503）。
func (o *machineIDOutcome) bodyBudget() bool {
	if o == nil {
		return false
	}
	for _, m := range o.Matches {
		if m.RuleID == "machineid.body_unavailable" {
			return true
		}
	}
	return false
}

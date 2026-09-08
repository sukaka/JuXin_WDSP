// 检测与事件映射：还原请求 → Coraza(DetectionOnly) → dynamic_security 统一管线 →
// api-runtime-events JSONL（apievents.Record 契约，服务端既有采集器原样入库）。
//
// 旁路铁律的实现：
//   - Coraza 以 SecRuleEngine DetectionOnly 运行（不产生任何阻断语义，只收集命中）；
//   - 统一管线以 decision.ModeObserve 运行（即便 BLOCK 类命中也只定 OBSERVE）；
//   - 事件 final_action 最终强制封顶 OBSERVE，管线原始判定记入 mirror.capture 证据。
//
// 镜像来源标注：Details 首位注入 detector="mirror" 的 INFO 级明细（mirror.capture）。
// 选此方式因为：决策引擎显式跳过 INFO 类明细（不参与定案）、服务端采集器对 details
// 为透传存储（无 detector 枚举校验）、字段契约零变化——不与任何现有消费方冲突。
package mirrorcap

import (
	"bytes"
	"fmt"
	"io"
	"net/http"
	"path"
	"strconv"
	"strings"
	"sync/atomic"
	"time"

	"github.com/corazawaf/coraza/v3"
	corazatypes "github.com/corazawaf/coraza/v3/types"
	"github.com/jiuzhang-waf/gateway/modules/jiuzhang_guard/apievents"

	dsctx "github.com/jiuzhang-waf/gateway/dynamic_security/context"
	"github.com/jiuzhang-waf/gateway/dynamic_security/decision"
	"github.com/jiuzhang-waf/gateway/dynamic_security/detectors"
	dsevents "github.com/jiuzhang-waf/gateway/dynamic_security/events"
	"github.com/jiuzhang-waf/gateway/dynamic_security/pipeline"
)

// maxWAFMatchDetails 单事件携带的 waf 命中明细上限（防超大事件撑爆日志卷）。
const maxWAFMatchDetails = 32

// maxMatchTags 单条命中明细携带的规则标签数上限（标签供攻击类型归因，如 attack-sqli）。
const maxMatchTags = 6

// Detector 旁路检测器：实现 RequestHandler，消费还原请求并输出事件。
type Detector struct {
	cfg    Config
	waf    coraza.WAF
	events *apievents.Logger
	stats  *Stats
	// discovery 站点发现聚合器（可选注入，nil 跳过；Supervisor 按发现启停动态
	// 注入/撤销，原子指针保证流 goroutine 热路径无锁读）。
	discovery atomic.Pointer[DiscoveryAggregator]
}

// SetDiscovery 实现 DiscoveryObserver：注入/撤销发现聚合器（agg=nil 撤销）。
// 检测路径顺带记发现——配置端口 HTTP 流量的 Host/四元组天然是站点资产证据。
func (d *Detector) SetDiscovery(agg *DiscoveryAggregator) {
	d.discovery.Store(agg)
}

// NewDetector 构建检测器：加载 Coraza/CRS 规则（目录布局与网关容器一致）。
func NewDetector(cfg Config, events *apievents.Logger, stats *Stats) (*Detector, error) {
	waf, err := coraza.NewWAF(coraza.NewWAFConfig().WithDirectives(mirrorDirectives(cfg.RulesDir)))
	if err != nil {
		return nil, fmt.Errorf("加载 Coraza 规则（%s）: %w", cfg.RulesDir, err)
	}
	return &Detector{cfg: cfg, waf: waf, events: events, stats: stats}, nil
}

// mirrorDirectives 生成与网关 Caddyfile coraza_waf 一致的指令序列（加载顺序保持），
// 唯一差异：SecRuleEngine 固定 DetectionOnly——旁路模式绝不产生阻断语义。
func mirrorDirectives(rulesDir string) string {
	d := strings.TrimRight(rulesDir, "/")
	return strings.Join([]string{
		"SecRuleEngine DetectionOnly",
		"Include " + d + "/coraza.conf",
		"Include " + d + "/crs/crs-setup.conf",
		"Include " + d + "/crs/plugins/*/plugins/*-config.conf",
		"Include " + d + "/crs/plugins/*/plugins/*-before.conf",
		"Include " + d + "/exclusions/before-crs.conf",
		"Include " + d + "/crs/rules/*.conf",
		"Include " + d + "/contrib/*/*.conf",
		"Include " + d + "/crs/plugins/*/plugins/*-after.conf",
		"Include " + d + "/exclusions/after-crs.conf",
		"Include " + d + "/jiuzhang/jiuzhang-custom.conf",
		"Include " + d + "/jiuzhang/post-contrib-blocking.conf",
	}, "\n")
}

// HandleRequest 实现 RequestHandler：单请求完整走「Coraza → 统一管线 → 事件」。
// 任何步骤失败只计数/告警，绝不影响其他流（旁路无熔断语义）。
func (d *Detector) HandleRequest(req *http.Request, meta FlowMeta, bodyTruncated bool) {
	start := time.Now()
	// Request ID 兜底（正常由流层注入；直接调用本方法时保证事件仍可关联）
	if req.Header.Get("X-Request-Id") == "" {
		req.Header.Set("X-Request-Id", "mirror-"+randHex16())
	}
	// 站点资产顺带发现：与检测结论无关（即便后续检测失败/跳过，资产证据已成立）
	if agg := d.discovery.Load(); agg != nil {
		agg.Observe(hostOnly(req.Host), meta, protoHTTP)
	}
	// Body 已在流层截断到 BodyMax：读出供 Coraza 使用后复位，供统一管线再次解析
	var body []byte
	if req.Body != nil {
		b, err := io.ReadAll(req.Body)
		if err != nil {
			if d.stats != nil {
				d.stats.RequestErrors.Add(1)
			}
			return
		}
		body = b
		_ = req.Body.Close()
		req.Body = io.NopCloser(bytes.NewReader(body))
	}
	wafMatches := d.runCoraza(req, meta, body)

	res, err := pipeline.Process(req, pipeline.Config{
		Enabled:      true,
		Mode:         decision.ModeObserve, // 旁路：BLOCK 类命中也只定 OBSERVE
		IdentitySalt: d.cfg.IdentitySalt,
	}, wafMatches)
	if err != nil {
		if d.stats != nil {
			d.stats.RequestErrors.Add(1)
		}
		return
	}
	if res == nil || res.Skipped {
		return
	}
	d.emit(req, meta, res, bodyTruncated, time.Since(start))
}

// runCoraza 请求相位（1/2）检测；命中规则转为 waf 检测明细（脱敏：不含命中载荷值）。
func (d *Detector) runCoraza(req *http.Request, meta FlowMeta, body []byte) []dsctx.DetectorMatch {
	tx := d.waf.NewTransaction()
	defer tx.Close()
	tx.ProcessConnection(meta.SrcIP, int(meta.SrcPort), meta.DstIP, int(meta.DstPort))
	uri := req.URL.RequestURI()
	if uri == "" {
		uri = req.RequestURI
	}
	tx.ProcessURI(uri, req.Method, req.Proto)
	for k, vs := range req.Header {
		for _, v := range vs {
			tx.AddRequestHeader(k, v)
		}
	}
	// 与 coraza-caddy processRequest 对齐（旁路还原保真度 = 在线检测一致性）：
	// Host 被 Go 提升为字段不在 Header 中，需显式补回（否则 CRS 920280 等误报）
	if req.Host != "" {
		tx.AddRequestHeader("Host", req.Host)
		tx.SetServerName(hostOnly(req.Host))
	}
	// Transfer-Encoding 同样被 Go 移出 Header，补回以保真（如 CRS 920171 走私检测）
	for _, te := range req.TransferEncoding {
		tx.AddRequestHeader("Transfer-Encoding", te)
	}
	tx.ProcessRequestHeaders()
	if len(body) > 0 {
		if _, _, err := tx.WriteRequestBody(body); err == nil {
			// 旁路忽略中断对象（DetectionOnly 本不产生；防御性忽略）
			_, _ = tx.ProcessRequestBody()
		}
	} else {
		_, _ = tx.ProcessRequestBody()
	}
	// 落审计日志（SecAuditEngine On 时；与在线路径 coraza-caddy 的收尾一致）
	tx.ProcessLogging()
	matched := tx.MatchedRules()
	out := make([]dsctx.DetectorMatch, 0, min(len(matched), maxWAFMatchDetails)) // min 为内建函数
	for _, mr := range matched {
		rule := mr.Rule()
		// 仅收录带严重度声明的检测型规则；CRS 初始化/标记规则（无 severity）自然过滤
		if rule.Severity() == corazatypes.RuleSeverityUnset {
			continue
		}
		if len(out) >= maxWAFMatchDetails {
			break
		}
		sev, delta := wafSeverity(rule.Severity())
		out = append(out, dsctx.DetectorMatch{
			Detector:   "waf",
			RuleID:     strconv.Itoa(rule.ID()),
			Category:   wafCategory(sev),
			Severity:   sev,
			Message:    mr.Message(),
			ScoreDelta: delta,
			Evidence: map[string]string{
				"engine":    "coraza",
				"phase":     strconv.Itoa(int(rule.Phase())),
				"rule_file": path.Base(rule.File()),
				"tags":      joinTags(rule.Tags(), maxMatchTags),
			},
		})
	}
	return out
}

// wafSeverity Coraza 严重度 → 事件严重度/风险分值（与决策引擎档位对齐：
// detector=waf 且 sev≥HIGH 或 delta≥50 在决策引擎中构成 BLOCK 类命中，OBSERVE 模式下定 OBSERVE）。
func wafSeverity(rs corazatypes.RuleSeverity) (severity string, delta int) {
	switch rs {
	case corazatypes.RuleSeverityEmergency, corazatypes.RuleSeverityAlert, corazatypes.RuleSeverityCritical:
		return "CRITICAL", 50
	case corazatypes.RuleSeverityError:
		return "HIGH", 40
	case corazatypes.RuleSeverityWarning:
		return "MEDIUM", 25
	case corazatypes.RuleSeverityNotice:
		return "LOW", 10
	default:
		return "INFO", 0
	}
}

// wafCategory 命中类别：CRITICAL/HIGH 记 BLOCK 类（决策引擎按模式封顶），其余 OBSERVE。
func wafCategory(severity string) string {
	if severity == "CRITICAL" || severity == "HIGH" {
		return "BLOCK"
	}
	return "OBSERVE"
}

// emit 构建并输出 api-runtime-events 记录（字段与 jiuzhang_guard.emitAPIEvent 对齐）。
func (d *Detector) emit(req *http.Request, meta FlowMeta, res *pipeline.Result, bodyTruncated bool, elapsed time.Duration) {
	pe := dsevents.BuildPrimary("", res.Context, res.EndpointKey)
	rec := apievents.Record{
		RequestID:     pe.RequestID,
		OccurredAt:    pe.OccurredAt,
		EndpointKey:   pe.EndpointKey,
		RiskScore:     pe.RiskScore,
		RiskLevel:     pe.RiskLevel,
		IsAPI:         res.API.IsAPI,
		APIConfidence: res.API.Confidence,
		// 旁路铁律：final_action 强制封顶 OBSERVE（原始判定见 mirror.capture 证据）
		FinalAction: string(dsctx.ActionObserve),
		// 镜像只还原请求侧：无真实响应状态码（契约 0 = 未采集）
		ResponseStatus: 0,
		LatencyMS:      elapsed.Milliseconds(),
	}
	// 镜像来源标注：INFO 级明细注入首位（决策引擎跳过 INFO；消费方透传存储，零冲突）
	rec.Details = append([]dsctx.DetectorMatch{
		mirrorCaptureMatch(res.FinalAction, meta, bodyTruncated),
	}, pe.Details...)
	if res.Parsed != nil {
		rec.Method = res.Parsed.Method
		rec.PathTemplate = res.Parsed.NormalizedPath
		rec.RawPath = res.Parsed.RawPath
	}
	rec.Domain = hostOnly(req.Host)
	// 来源/身份指纹：四元组源即真实客户端（旁路无代理头伪造面）；
	// 统一 HMAC-SHA256 截断指纹（盐来自 MIRROR_IDENTITY_SALT，空走固定域分隔）。
	rec.ClientIP = meta.SrcIP
	rec.SourceFingerprint = detectors.Fingerprint(d.cfg.IdentitySalt, meta.SrcIP)
	// 身份指纹仅凭据派生；无凭据为匿名置空（IP 不得冒充身份）
	rec.IdentityFingerprint = detectors.CredentialKey(req, d.cfg.IdentitySalt)
	rec.AuthType = res.Context.AuthenticationType
	if res.API.IsAPI && res.Parsed != nil {
		// 隐私增强接线：值指纹 HMAC 加盐（MIRROR_IDENTITY_SALT）+ 默认敏感键名
		// 抑制原值/哈希；旁路无发布通道值级规则（nil），编译失败保守回退兼容入口
		if patterns, err := detectors.CompileSensitivePatterns(nil); err == nil {
			rec.ParamObservations = detectors.CollectParamObservationsSecure(res.Parsed, d.cfg.IdentitySalt, patterns, nil)
		} else {
			rec.ParamObservations = detectors.CollectParamObservations(res.Parsed)
		}
	}
	if err := d.events.Emit(rec); err != nil {
		if d.stats != nil {
			d.stats.EventErrors.Add(1)
		}
		return
	}
	if d.stats != nil {
		d.stats.EventsEmitted.Add(1)
	}
}

// mirrorCaptureMatch 镜像来源标注明细（INFO 级，不参与定案）。
func mirrorCaptureMatch(pipelineDecision dsctx.FinalAction, meta FlowMeta, bodyTruncated bool) dsctx.DetectorMatch {
	ev := map[string]string{
		"source":            "mirror",
		"pipeline_decision": string(pipelineDecision), // 封顶前原始判定（OBSERVE 模式下至多 OBSERVE）
		"server":            meta.DstIP + ":" + strconv.Itoa(int(meta.DstPort)),
	}
	if bodyTruncated {
		ev["body_truncated"] = "true"
	}
	return dsctx.DetectorMatch{
		Detector:   "mirror",
		RuleID:     "mirror.capture",
		Category:   "INFO",
		Severity:   "INFO",
		Confidence: 1.0,
		Message:    "request passively reconstructed from mirrored traffic (SPAN/tap); detect-only, enforcement not possible",
		Evidence:   ev,
	}
}

// hostOnly 取 Host 去端口小写（域名归属；与 jiuzhang_guard.requestHost 同规则）。
func hostOnly(h string) string {
	if i := strings.LastIndex(h, ":"); i > 0 {
		if _, err := strconv.Atoi(h[i+1:]); err == nil {
			h = h[:i]
		}
	}
	return strings.ToLower(h)
}

// joinTags 截断拼接规则标签（供攻击类型归因；长度有界）。
func joinTags(tags []string, max int) string {
	if len(tags) > max {
		tags = tags[:max]
	}
	s := strings.Join(tags, ",")
	if len(s) > 200 {
		s = s[:200]
	}
	return s
}

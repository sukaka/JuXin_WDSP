// publisher_smoke.go 阶段5 §十七 发布后流量验证（功能性冒烟）。
//
// 现状缺口：verifyPublish 只做 Caddy Ping + 配置规范化哈希一致性校验，回答的是
// 「配置被加载了吗」，回答不了「防护链对新配置真的生效了吗」。本文件在配置一致性
// 通过之后，向网关数据面发送不会误伤的合成探针请求，按 STAGE_5 §十七 的
// 真实IP → 黑白名单 → CC 顺序做功能性冒烟：
//
//   - 探针路径固定在 Bot 保留命名空间下（/_wdsp/bot/v1/publish-smoke）：该命名空间
//     未知子路径由 jiuzhang_guard 本地返回 404 墓碑（正文恰为 "404 not found" 且
//     Cache-Control: no-store），结构上绝不反向代理到源站；墓碑位于 Bot 判定步骤，
//     在真实IP/人工封禁/黑白名单/L7/自动封禁/风险/配额/CC 全部通过之后才会到达，
//     因此收到墓碑即证明完整 guard 链路对该应用流量已生效；
//   - 探针全部携带 X-Jiuzhang-Publish-Smoke 标记头，便于在访问日志中识别与过滤；
//   - 黑名单探针使用发布快照中的真实黑名单单 IP 合成 X-Forwarded-For：仅当探针源
//     （默认 127.0.0.1）在可信代理链内时 XFF 才会被采信并触发 403——这是可用的
//     功能验证；未采信（真实 IP 防护行为同样正确）时如实记 SKIP 而非谎报 PASS；
//   - CC 探针只发 3 次合成请求（远低于任何合理阈值），验证 CC 步骤正常执行；
//     若实测收到 429/403 处置响应同样判 PASS（限速/封禁真实生效），绝不主动
//     打满阈值，避免把探针源打进自动封禁；
//   - CC_EXACT 精确计数探针（第四探针）对唯一合成来源（2001:db8::/32 + 随机位）
//     打满可验证策略的阈值 N，经网关 debug 回显端点验证计数递增与第 N+1 次 429；
//     端点未启用/策略不可验证/合成 XFF 未采信时如实 SKIP（详见函数注释）。
//
// 判定纪律：
//   - 只有拿到「响应内容与预期不符」的正面证据（防护链未接管/网关 5xx）才判 FAIL，
//     FAIL 走既有验证失败自动回滚路径（VERIFY_FAILED）；
//   - 传输层不可达（数据面地址无法拨号，如管理面与网关分主机部署）属于「探针不可用」，
//     按任务要求降级为既有配置一致性校验结果，原因写入发布记录与版本状态，不静默跳过；
//   - 冒烟结果落 gateway_validation_results 明细行 + gateway_config_versions.
//     validation_result（SMOKE_PASS/SMOKE_FAIL/SMOKE_SKIPPED），并并入任务
//     result_summary，前端版本列表可见。
package gatewayconfig

import (
	"context"
	"crypto/rand"
	"crypto/tls"
	"encoding/json"
	"fmt"
	"io"
	"log/slog"
	"net"
	"net/http"
	"net/netip"
	"net/url"
	"os"
	"regexp"
	"strings"
	"time"

	"github.com/google/uuid"
	"github.com/jiuzhang-waf/server/internal/applications"
)

// 冒烟探针步骤词表（gateway_validation_results.validation_step）。
const (
	SmokeProbeRealIP    = "REAL_IP"
	SmokeProbeBlacklist = "BLACKLIST"
	SmokeProbeCC        = "CC"
	SmokeProbeCCExact   = "CC_EXACT"
)

// 冒烟探针结果词表（gateway_validation_results.result）。
const (
	SmokeResultPass = "PASS"
	SmokeResultFail = "FAIL"
	SmokeResultSkip = "SKIP"
)

// 版本 validation_result 词表（gateway_config_versions.validation_result；空串 = 历史版本未冒烟）。
const (
	VersionSmokePass    = "SMOKE_PASS"
	VersionSmokeFail    = "SMOKE_FAIL"
	VersionSmokeSkipped = "SMOKE_SKIPPED"
)

const (
	// smokeProbePath 探针路径：Bot 保留命名空间下的未知子路径，网关本地 404 墓碑，
	// 不反向代理、不触发挑战签发（非浏览器文档导航）。
	smokeProbePath = "/_wdsp/bot/v1/publish-smoke"
	// SmokeMarkerHeader 探针标记头（供访问日志识别/过滤合成流量）。
	SmokeMarkerHeader = "X-Jiuzhang-Publish-Smoke"
	// smokeRealIPSpoofXFF 真实 IP 探针的合成 XFF：TEST-NET-2 文档前缀（RFC 5737），
	// 全网不可路由，绝不对应真实客户端。
	smokeRealIPSpoofXFF = "198.51.100.77"
	// smokeCCBurst CC 探针突发请求数：远低于任何合理 CC 阈值，仅验证计数步骤执行。
	smokeCCBurst = 3
	// smokeDebugCCCounterPath 网关 CC 计数调试回显端点（jiuzhang_guard
	// debug_cc_counter 段，仅本机/内网连接源可访问；未启用时探针如实 SKIP）。
	smokeDebugCCCounterPath = "/_wdsp/debug/v1/cc-counter"
	// smokeCCExactMaxLimit CC_EXACT 探针可接受的策略阈值上限：N=配置阈值次合成
	// 请求，阈值过大时不为探针打满（控制合成流量总量），如实 SKIP。
	smokeCCExactMaxLimit = 50
	// smokeMaxTargets 单次发布最多探针的应用数（控制发布耗时与合成流量总量）。
	smokeMaxTargets = 3
	// smokeRequestTimeout 单次探针请求超时。
	smokeRequestTimeout = 3 * time.Second
	// smokeBodyReadLimit 探针响应正文读取上限（判定只需墓碑短句）。
	smokeBodyReadLimit = 4096
	// smokePersistTimeout 冒烟结果落库超时（背景 ctx，与 markAC 同口径避免请求取消丢失）。
	smokePersistTimeout = 10 * time.Second
)

// smokeTarget 一个可探针的应用数据面目标。
type smokeTarget struct {
	appCode string
	scheme  string // http / https
	host    string // Host 头与 TLS SNI（应用域名；泛域名已替换为 smoke. 前缀）
	port    int
}

// smokeProbeResult 单条探针结果。
type smokeProbeResult struct {
	Probe   string
	AppCode string
	Result  string // PASS / FAIL / SKIP
	Message string
}

// smokeReport 一次发布后冒烟的汇总。
type smokeReport struct {
	probes        []smokeProbeResult
	degraded      bool   // 探针不可用，已降级为配置一致性校验
	degradeReason string // 降级原因（如实记录）
}

// failed 是否有探针拿到「与预期不符」的正面证据（触发自动回滚）。
func (r *smokeReport) failed() bool {
	for _, pr := range r.probes {
		if pr.Result == SmokeResultFail {
			return true
		}
	}
	return false
}

// versionResult 版本 validation_result 落库词。
func (r *smokeReport) versionResult() string {
	switch {
	case r.failed():
		return VersionSmokeFail
	case r.degraded:
		return VersionSmokeSkipped
	default:
		return VersionSmokePass
	}
}

// failureDetail 验证失败摘要（进入任务 failure_message 与回滚原因）。
func (r *smokeReport) failureDetail() string {
	var parts []string
	for _, pr := range r.probes {
		if pr.Result == SmokeResultFail {
			parts = append(parts, fmt.Sprintf("[%s/%s] %s", pr.AppCode, pr.Probe, pr.Message))
		}
	}
	return strings.Join(parts, "；")
}

// summary 成功路径并入任务 result_summary 的一行摘要。
func (r *smokeReport) summary() string {
	if r.degraded {
		return "流量验证降级：" + r.degradeReason + "（按配置一致性校验完成验证）"
	}
	pass, skip := 0, 0
	var skips []string
	for _, pr := range r.probes {
		switch pr.Result {
		case SmokeResultPass:
			pass++
		case SmokeResultSkip:
			skip++
			skips = append(skips, fmt.Sprintf("%s/%s：%s", pr.AppCode, pr.Probe, pr.Message))
		}
	}
	s := fmt.Sprintf("流量验证通过（%d 项探针 PASS", pass)
	if skip > 0 {
		s += fmt.Sprintf("，%d 项 SKIP：%s", skip, strings.Join(skips, "；"))
	}
	return s + "）"
}

// resolveSmokeTargets 从发布快照选出可探针目标。仅防护链含 guard 的应用可探：
// BYPASS 透传与 MIRROR 镜像旁路不注入 jiuzhang_guard，探针无判定依据。
func resolveSmokeTargets(appsData []AppData, guardCfg *GuardConfig) ([]smokeTarget, string) {
	if guardCfg == nil {
		return nil, "本次发布未下发访问控制配置（无 guard 段），流量冒烟不适用"
	}
	var targets []smokeTarget
	for _, app := range appsData {
		if len(targets) >= smokeMaxTargets {
			break
		}
		if app.DeploymentMode == applications.DeployModeMirror {
			continue
		}
		if app.ProtectionMode == applications.ModeBypass {
			continue
		}
		for _, d := range app.Domains {
			host := smokeableHostname(d.NormalizedHostname)
			if host == "" {
				continue
			}
			// HTTP 跳 HTTPS 时 80 端口仅返回 308 静态重定向（不经 guard），须探 HTTPS
			switch {
			case d.HTTPSEnabled && d.HTTPSPort != nil && (d.RedirectHTTPToHTTPS || !d.HTTPEnabled || d.HTTPPort == nil):
				targets = append(targets, smokeTarget{appCode: app.Code, scheme: "https", host: host, port: *d.HTTPSPort})
			case d.HTTPEnabled && d.HTTPPort != nil:
				targets = append(targets, smokeTarget{appCode: app.Code, scheme: "http", host: host, port: *d.HTTPPort})
			default:
				continue
			}
			break // 每应用取第一个可用域名
		}
	}
	if len(targets) == 0 {
		return nil, "无可用探针目标（应用均为透传/镜像模式或未声明数据面端口）"
	}
	return targets, ""
}

// smokeableHostname 泛域名替换为确定子域（Host 头不允许 * 字符）。
func smokeableHostname(host string) string {
	host = strings.TrimSpace(host)
	if strings.HasPrefix(host, "*.") {
		return "smoke." + host[2:]
	}
	return host
}

// smokeDialAddress 探针拨号地址：显式注入 > 环境变量 > 默认回环。
// 环境变量 GATEWAY_PUBLISH_SMOKE_ADDR 用于管理面与网关分主机部署
// （值形如 http://10.0.0.5:8080 或 10.0.0.5:8080；仅取拨号地址，Host/SNI 仍用应用域名）。
func (p *Publisher) smokeDialAddress(t smokeTarget) string {
	addr := p.smokeDialAddr
	if addr == "" {
		addr = os.Getenv("GATEWAY_PUBLISH_SMOKE_ADDR")
	}
	if addr != "" {
		if u := strings.TrimPrefix(strings.TrimPrefix(addr, "http://"), "https://"); u != addr {
			addr = u
		}
		addr = strings.TrimSuffix(addr, "/")
		if addr != "" {
			return addr
		}
	}
	return net.JoinHostPort("127.0.0.1", fmt.Sprintf("%d", t.port))
}

// smokeClientFor 构造探针客户端：URL 主机名用应用域名（Host/SNI 正确路由进应用链），
// 拨号重定向到数据面地址。TLS 跳过证书校验——探针验证的是防护行为，证书有效性
// 属证书管理面职责；SNI 仍按域名发送以命中 tls_connection_policies。
func (p *Publisher) smokeClientFor(t smokeTarget) *http.Client {
	if p.smokeClient != nil {
		return p.smokeClient
	}
	dialAddr := p.smokeDialAddress(t)
	dialer := &net.Dialer{Timeout: smokeRequestTimeout}
	return &http.Client{
		Timeout: smokeRequestTimeout,
		Transport: &http.Transport{
			DialContext: func(ctx context.Context, network, _ string) (net.Conn, error) {
				return dialer.DialContext(ctx, network, dialAddr)
			},
			TLSClientConfig: &tls.Config{InsecureSkipVerify: true}, //nolint:gosec // 探针语义见函数注释
		},
	}
}

// smokeResponse 一次探针响应的判定要素。
type smokeResponse struct {
	status int
	header http.Header
	body   string
}

// doSmokeRequest 发送一次合成探针请求。
func (p *Publisher) doSmokeRequest(ctx context.Context, client *http.Client, t smokeTarget, probe string, extraHeaders map[string]string) (*smokeResponse, error) {
	reqURL := fmt.Sprintf("%s://%s%s", t.scheme, net.JoinHostPort(t.host, fmt.Sprintf("%d", t.port)), smokeProbePath)
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, reqURL, nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set(SmokeMarkerHeader, probe)
	for k, v := range extraHeaders {
		req.Header.Set(k, v)
	}
	resp, err := client.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(io.LimitReader(resp.Body, smokeBodyReadLimit))
	return &smokeResponse{status: resp.StatusCode, header: resp.Header, body: string(body)}, nil
}

// smokeVerdict 探针响应分类。
type smokeVerdict int

const (
	verdictUnexpected     smokeVerdict = iota // 与防护链预期不符（源站响应/网关 5xx/未知形态）
	verdictGuardTombstone                     // guard 本地 404 墓碑：完整防护链执行且未触发阻断
	verdictGuardBlock                         // guard/WAF 主动处置（403 阻断页或 429 限速，带 Request ID）
)

// classifySmokeResponse 判定探针响应形态。墓碑的三重判据（保留命名路径 + 精确正文
// + no-store）与处置响应的 Request ID 头均为网关侧不可伪造给源站的标记。
func classifySmokeResponse(r *smokeResponse) smokeVerdict {
	if r.status == http.StatusNotFound &&
		strings.Contains(r.header.Get("Cache-Control"), "no-store") &&
		strings.TrimSpace(r.body) == "404 not found" {
		return verdictGuardTombstone
	}
	if (r.status == http.StatusForbidden || r.status == http.StatusTooManyRequests) &&
		r.header.Get("X-Jiuzhang-Request-ID") != "" {
		return verdictGuardBlock
	}
	return verdictUnexpected
}

// firstPlainDenyIP 取发布快照中第一条单 IP 黑名单条目（全局优先，其次本应用）。
// CIDR 条目无法合成单一来源探针，跳过。
func firstPlainDenyIP(guardCfg *GuardConfig, appCode string) string {
	pick := func(rules []GuardRule) string {
		for _, r := range rules {
			if strings.Contains(r.Address, "/") {
				continue
			}
			if ip := net.ParseIP(strings.TrimSpace(r.Address)); ip != nil {
				return ip.String()
			}
		}
		return ""
	}
	if ip := pick(guardCfg.GlobalDeny); ip != "" {
		return ip
	}
	if ar, ok := guardCfg.AppRules[appCode]; ok && ar != nil {
		return pick(ar.Deny)
	}
	return ""
}

// probeTarget 对单个应用目标按真实IP→黑名单→CC 顺序执行探针。
// 返回 available=false 表示传输层不可达（该目标探针不可用，记 SKIP 不判 FAIL）。
func (p *Publisher) probeTarget(ctx context.Context, t smokeTarget, guardCfg *GuardConfig) (results []smokeProbeResult, available bool) {
	client := p.smokeClientFor(t)

	// 1. 真实 IP 识别探针：合成不可路由 XFF，验证真实 IP 识别与防护链接管。
	realIP, err := p.doSmokeRequest(ctx, client, t, SmokeProbeRealIP, map[string]string{
		"X-Forwarded-For": smokeRealIPSpoofXFF,
	})
	if err != nil {
		return []smokeProbeResult{{
			Probe: SmokeProbeRealIP, AppCode: t.appCode, Result: SmokeResultSkip,
			Message: fmt.Sprintf("数据面探针不可达：%v", err),
		}}, false
	}
	switch classifySmokeResponse(realIP) {
	case verdictGuardTombstone:
		results = append(results, smokeProbeResult{Probe: SmokeProbeRealIP, AppCode: t.appCode, Result: SmokeResultPass,
			Message: "合成 XFF 探针经完整防护链处理（本地墓碑 404，未采信伪造头亦未异常）"})
	case verdictGuardBlock:
		results = append(results, smokeProbeResult{Probe: SmokeProbeRealIP, AppCode: t.appCode, Result: SmokeResultPass,
			Message: fmt.Sprintf("合成 XFF 探针被防护链主动处置（status=%d，伪造头防护生效）", realIP.status)})
	default:
		results = append(results, smokeProbeResult{Probe: SmokeProbeRealIP, AppCode: t.appCode, Result: SmokeResultFail,
			Message: fmt.Sprintf("探针响应与防护链预期不符（status=%d），guard 未生效或路由错误", realIP.status)})
	}

	// 2. 黑名单命中探针：用发布快照中的真实黑名单单 IP 合成 XFF。
	denyIP := firstPlainDenyIP(guardCfg, t.appCode)
	if denyIP == "" {
		results = append(results, smokeProbeResult{Probe: SmokeProbeBlacklist, AppCode: t.appCode, Result: SmokeResultSkip,
			Message: "本次发布快照无单 IP 黑名单条目，无法合成命中探针"})
	} else {
		bl, berr := p.doSmokeRequest(ctx, client, t, SmokeProbeBlacklist, map[string]string{
			"X-Forwarded-For": denyIP,
		})
		switch {
		case berr != nil:
			results = append(results, smokeProbeResult{Probe: SmokeProbeBlacklist, AppCode: t.appCode, Result: SmokeResultSkip,
				Message: fmt.Sprintf("黑名单探针请求失败：%v", berr)})
		case classifySmokeResponse(bl) == verdictGuardBlock && bl.status == http.StatusForbidden:
			results = append(results, smokeProbeResult{Probe: SmokeProbeBlacklist, AppCode: t.appCode, Result: SmokeResultPass,
				Message: fmt.Sprintf("合成黑名单来源 %s 被 403 处置，黑名单经流量验证命中", denyIP)})
		case classifySmokeResponse(bl) == verdictGuardTombstone:
			results = append(results, smokeProbeResult{Probe: SmokeProbeBlacklist, AppCode: t.appCode, Result: SmokeResultSkip,
				Message: "合成 XFF 未被采信（探针源不在可信代理链或命中白名单），黑名单未经流量触发；真实 IP 防护行为正确"})
		case classifySmokeResponse(bl) == verdictGuardBlock:
			results = append(results, smokeProbeResult{Probe: SmokeProbeBlacklist, AppCode: t.appCode, Result: SmokeResultPass,
				Message: fmt.Sprintf("合成黑名单来源被防护链处置（status=%d）", bl.status)})
		default:
			results = append(results, smokeProbeResult{Probe: SmokeProbeBlacklist, AppCode: t.appCode, Result: SmokeResultFail,
				Message: fmt.Sprintf("黑名单探针响应与预期不符（status=%d）", bl.status)})
		}
	}

	// 3. CC 计数探针：小突发合成请求（放最后：若实测触发处置，不影响前序探针）。
	rateLimited := false
	for i := 0; i < smokeCCBurst; i++ {
		cc, cerr := p.doSmokeRequest(ctx, client, t, SmokeProbeCC, nil)
		if cerr != nil {
			results = append(results, smokeProbeResult{Probe: SmokeProbeCC, AppCode: t.appCode, Result: SmokeResultFail,
				Message: fmt.Sprintf("CC 探针第 %d 次请求失败（数据面此前可达）：%v", i+1, cerr)})
			rateLimited = true // 已落结果，结束突发
			break
		}
		switch classifySmokeResponse(cc) {
		case verdictGuardTombstone:
			continue
		case verdictGuardBlock:
			results = append(results, smokeProbeResult{Probe: SmokeProbeCC, AppCode: t.appCode, Result: SmokeResultPass,
				Message: fmt.Sprintf("CC 探针第 %d 次请求实测防护处置（status=%d，限速/封禁生效）", i+1, cc.status)})
			rateLimited = true
		default:
			results = append(results, smokeProbeResult{Probe: SmokeProbeCC, AppCode: t.appCode, Result: SmokeResultFail,
				Message: fmt.Sprintf("CC 探针响应与防护链预期不符（status=%d）", cc.status)})
			rateLimited = true
		}
		if rateLimited {
			break
		}
	}
	if !rateLimited {
		results = append(results, smokeProbeResult{Probe: SmokeProbeCC, AppCode: t.appCode, Result: SmokeResultPass,
			Message: fmt.Sprintf("CC 探针 %d 次合成请求均经防护链放行（计数步骤正常，未触发阈值、不误伤探针源）", smokeCCBurst)})
	}

	// 4. CC 精确计数探针：唯一合成来源打满阈值 N，经网关 debug 回显端点验证
	// 计数递增与第 N+1 次 429（探针不可用/策略不可验证时如实 SKIP）。
	results = append(results, p.probeCCExact(ctx, client, t, guardCfg))
	return results, true
}

// ---------- 第四探针：CC 精确计数（CC_EXACT） ----------
//
// 既有 CC 探针只发 3 次请求，只能验证「触发了 429」，验证不了「第 N 次才拦截」的
// 精确阈值语义。本探针对唯一合成来源发 N 次请求（N=配置阈值），经网关
// /_wdsp/debug/v1/cc-counter 回显端点（jiuzhang_guard debug_cc_counter 段）验证
// 计数递增，并断言第 N+1 次请求 429。
//
// 安全与诚实纪律：
//   - 合成来源固定取 IPv6 文档前缀 2001:db8::/32（RFC 3849，全网不可路由，绝不
//     对应真实客户端）+ 64 位随机位，计数键唯一，不污染真实客户端统计；阈值打满
//     触发的封禁/429 也只作用于合成来源；
//   - 先发 1 次校准请求并回显验证计数递增，确认合成 XFF 被采信后才继续打满——
//     探针源不在可信代理链时 XFF 不采信，如实 SKIP（不拿真实来源 IP 打满阈值，
//     避免把管理主机打进自动封禁）；
//   - 回显端点不可达/未启用（debug_cc_counter 未下发）、计数引擎故障、策略不可
//     精确验证（阈值过大/窗口过短/维度非 CLIENT_IP/非实断动作）一律如实 SKIP，
//     不误判 FAIL 触发回滚；只有拿到「计数不递增」「阈值+1 未 429」「响应形态
//     与防护链不符」的正面证据才判 FAIL。

// ccCounterEcho 回显端点响应（与网关 debug_cccounter.go 的 JSON 契约一致）。
type ccCounterEcho struct {
	PolicyID      string `json:"policy_id"`
	Found         bool   `json:"found"`
	Count         int64  `json:"count"`
	Limit         int64  `json:"limit"`
	WindowSeconds int    `json:"window_seconds"`
}

// ccPolicyEffectiveNow 策略当前是否生效（与网关 compilePolicies 的 RFC3339 口径一致；
// 时间不可解析按不生效处理——网关装配期已拒绝非法值，此处防御性跳过）。
func ccPolicyEffectiveNow(p *GuardPolicy, now time.Time) bool {
	if p.EffectiveFrom != "" {
		t, err := time.Parse(time.RFC3339, p.EffectiveFrom)
		if err != nil || now.Before(t) {
			return false
		}
	}
	if p.EffectiveUntil != "" {
		t, err := time.Parse(time.RFC3339, p.EffectiveUntil)
		if err != nil || !now.Before(t) {
			return false
		}
	}
	return true
}

// ccPolicyMatchesPath 策略 URI 匹配判定（与网关 matchURI 同口径；REGEX 即 RE2）。
func ccPolicyMatchesPath(p *GuardPolicy, path string) bool {
	switch p.URIMatchType {
	case "", "ALL":
		return true
	case "EXACT":
		return path == p.URIPattern
	case "PREFIX":
		return strings.HasPrefix(path, p.URIPattern)
	case "REGEX":
		re, err := regexp.Compile(p.URIPattern)
		return err == nil && re.MatchString(path)
	}
	return false
}

// ccExactEligibility 策略是否可精确验证（返回空串 = 可验证，否则为不可验证原因）。
// 窗口下限是突发时长预算启发式：N 次合成请求必须在同一窗口内完成，
// 令牌桶额外要求低速率（refill 不得在突发期间补回整令牌导致第 N+1 次误放行）。
func ccExactEligibility(p *GuardPolicy, now time.Time) string {
	if p.ObserveOnly || p.Action != "REJECT" {
		return "动作非 REJECT 实断（OBSERVE/LOG/TEMP_BLOCK 不做阈值精确断言）"
	}
	if p.Dimension != "CLIENT_IP" {
		return "维度非 CLIENT_IP（合成来源无法构造唯一计数键）"
	}
	if !ccPolicyEffectiveNow(p, now) {
		return "策略当前不在生效窗口内"
	}
	if !ccPolicyMatchesPath(p, smokeProbePath) {
		return "URI 不匹配探针路径（不向业务路径打满阈值）"
	}
	if p.RequestsLimit < 1 || p.RequestsLimit > smokeCCExactMaxLimit {
		return fmt.Sprintf("阈值 %d 超出探针预算 [1,%d]（不为探针打满过大阈值）", p.RequestsLimit, smokeCCExactMaxLimit)
	}
	n := int(p.RequestsLimit)
	switch p.Algorithm {
	case "SLIDING_WINDOW":
		if p.WindowSeconds < n+5 {
			return fmt.Sprintf("窗口 %ds 过短（阈值 %d 次突发须落在同一窗口内）", p.WindowSeconds, n)
		}
	case "TOKEN_BUCKET":
		if p.BurstCapacity > p.RequestsLimit {
			return "令牌桶 burst_capacity > 阈值（拦截点由容量决定，N+1 断言不成立）"
		}
		if p.WindowSeconds < 3*n {
			return fmt.Sprintf("令牌桶窗口 %ds 相对阈值 %d 过短（refill 可能在突发期间补回令牌）", p.WindowSeconds, n)
		}
	default:
		return "未知算法 " + p.Algorithm
	}
	return ""
}

// ccExactTargetPolicy 选取可精确验证的 CC 策略（全局优先于应用仅为枚举顺序；
// 多候选取阈值最小者——探针请求数最少，且其它匹配策略不会先于它触发）。
func ccExactTargetPolicy(guardCfg *GuardConfig, appCode string, now time.Time) (*GuardPolicy, string) {
	var best *GuardPolicy
	var reasons []string
	consider := func(pol *GuardPolicy) {
		if reason := ccExactEligibility(pol, now); reason != "" {
			reasons = append(reasons, fmt.Sprintf("%s：%s", pol.ID, reason))
			return
		}
		if best == nil || pol.RequestsLimit < best.RequestsLimit {
			cp := *pol
			best = &cp
		}
	}
	for i := range guardCfg.GlobalPolicies {
		consider(&guardCfg.GlobalPolicies[i])
	}
	if ar, ok := guardCfg.AppRules[appCode]; ok && ar != nil {
		for i := range ar.Policies {
			consider(&ar.Policies[i])
		}
	}
	if best != nil {
		return best, ""
	}
	if len(reasons) == 0 {
		return nil, "本次发布快照无 CC 策略"
	}
	return nil, strings.Join(reasons, "；")
}

// newSmokeSyntheticIP 生成探针唯一合成来源：IPv6 文档前缀 2001:db8::/32 + 64 位
// crypto/rand（跨次发布唯一、全网不可路由、绝不对应真实客户端）。
func newSmokeSyntheticIP() (string, error) {
	var b [16]byte
	b[0], b[1], b[2], b[3] = 0x20, 0x01, 0x0d, 0xb8
	if _, err := rand.Read(b[8:]); err != nil {
		return "", fmt.Errorf("rand: %w", err)
	}
	return netip.AddrFrom16(b).String(), nil
}

// peekCCCounter 查询网关 debug 回显端点。status 非 200 时 echo 为 nil
// （端点未启用/来源门禁/引擎故障均由调用方如实降级）。
func (p *Publisher) peekCCCounter(ctx context.Context, client *http.Client, t smokeTarget, policyID, ip string) (*ccCounterEcho, int, error) {
	reqURL := fmt.Sprintf("%s://%s%s?policy_id=%s&ip=%s",
		t.scheme, net.JoinHostPort(t.host, fmt.Sprintf("%d", t.port)),
		smokeDebugCCCounterPath, url.QueryEscape(policyID), url.QueryEscape(ip))
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, reqURL, nil)
	if err != nil {
		return nil, 0, err
	}
	req.Header.Set(SmokeMarkerHeader, SmokeProbeCCExact)
	resp, err := client.Do(req)
	if err != nil {
		return nil, 0, err
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(io.LimitReader(resp.Body, smokeBodyReadLimit))
	if resp.StatusCode != http.StatusOK {
		return nil, resp.StatusCode, nil
	}
	var echo ccCounterEcho
	if err := json.Unmarshal(body, &echo); err != nil {
		return nil, resp.StatusCode, fmt.Errorf("echo not JSON: %w", err)
	}
	if echo.PolicyID != policyID {
		return nil, resp.StatusCode, fmt.Errorf("echo policy_id mismatch: %q", echo.PolicyID)
	}
	return &echo, resp.StatusCode, nil
}

// probeCCExact 第四探针（CC 精确计数）：校准（XFF 采信 + 计数递增）→ 打满阈值 N
// → 回显验证递增 → 第 N+1 次断言 429。
func (p *Publisher) probeCCExact(ctx context.Context, client *http.Client, t smokeTarget, guardCfg *GuardConfig) smokeProbeResult {
	result := func(res, format string, args ...interface{}) smokeProbeResult {
		return smokeProbeResult{Probe: SmokeProbeCCExact, AppCode: t.appCode, Result: res, Message: fmt.Sprintf(format, args...)}
	}
	pol, reason := ccExactTargetPolicy(guardCfg, t.appCode, time.Now())
	if pol == nil {
		return result(SmokeResultSkip, "无可精确验证的 CC 策略（%s）", reason)
	}
	ip, err := newSmokeSyntheticIP()
	if err != nil {
		return result(SmokeResultSkip, "合成探针来源生成失败：%v", err)
	}
	echo0, status, err := p.peekCCCounter(ctx, client, t, pol.ID, ip)
	switch {
	case err != nil:
		return result(SmokeResultSkip, "debug 回显端点请求失败：%v", err)
	case status != http.StatusOK:
		return result(SmokeResultSkip, "debug 回显端点不可用（status=%d；debug_cc_counter 未启用或探针源非本机/内网），CC 精确计数未验证", status)
	case echo0.Found && echo0.Count > 0:
		return result(SmokeResultSkip, "合成来源计数键非空（count=%d，键冲突），放弃验证避免误判", echo0.Count)
	}

	burst := func(i int) (*smokeResponse, smokeProbeResult, bool) {
		resp, err := p.doSmokeRequest(ctx, client, t, SmokeProbeCCExact, map[string]string{"X-Forwarded-For": ip})
		if err != nil {
			return nil, result(SmokeResultFail, "CC_EXACT 第 %d 次请求失败（数据面此前可达）：%v", i, err), false
		}
		switch classifySmokeResponse(resp) {
		case verdictGuardTombstone:
			return resp, smokeProbeResult{}, true
		case verdictGuardBlock:
			return resp, result(SmokeResultSkip,
				"第 %d 次请求提前触发处置（status=%d），可能存在更小阈值的匹配策略，精确阈值未验证", i, resp.status), false
		default:
			return resp, result(SmokeResultFail, "CC_EXACT 第 %d 次请求响应与防护链预期不符（status=%d）", i, resp.status), false
		}
	}

	// 校准：1 次合成请求 + 回显递增，确认 XFF 采信（不采信则如实 SKIP，
	// 不拿真实探针源继续打满）
	if _, r, ok := burst(1); !ok {
		return r
	}
	echo1, status, err := p.peekCCCounter(ctx, client, t, pol.ID, ip)
	switch {
	case err != nil:
		return result(SmokeResultSkip, "校准后回显失败：%v", err)
	case status != http.StatusOK:
		return result(SmokeResultSkip, "校准后回显端点不可用（status=%d）", status)
	case echo1.Count <= echo0.Count:
		return result(SmokeResultSkip,
			"合成 XFF 未被采信（探针源不在可信代理链，计数 %d→%d 未递增），CC 精确计数未经流量验证；真实 IP 防护行为正确",
			echo0.Count, echo1.Count)
	}

	n := int(pol.RequestsLimit)
	for i := 2; i <= n; i++ {
		if _, r, ok := burst(i); !ok {
			return r
		}
	}
	echoN, status, err := p.peekCCCounter(ctx, client, t, pol.ID, ip)
	switch {
	case err != nil:
		return result(SmokeResultSkip, "突发后回显失败：%v", err)
	case status != http.StatusOK:
		return result(SmokeResultSkip, "突发后回显端点不可用（status=%d）", status)
	case echoN.Count <= echo1.Count:
		return result(SmokeResultFail, "CC 计数未随探针突发递增（%d→%d），计数引擎未生效", echo1.Count, echoN.Count)
	}

	// 第 N+1 次：必须被阈值拦截
	resp, err := p.doSmokeRequest(ctx, client, t, SmokeProbeCCExact, map[string]string{"X-Forwarded-For": ip})
	if err != nil {
		return result(SmokeResultFail, "CC_EXACT 第 %d 次（阈值+1）请求失败：%v", n+1, err)
	}
	switch {
	case resp.status == http.StatusTooManyRequests && classifySmokeResponse(resp) == verdictGuardBlock:
		return result(SmokeResultPass,
			"CC 策略 %s 阈值 %d 精确验证：合成来源计数 %d→%d，第 %d 次请求 429 限速", pol.ID, n, echo0.Count, echoN.Count, n+1)
	case classifySmokeResponse(resp) == verdictGuardBlock:
		return result(SmokeResultPass,
			"CC 策略 %s 阈值 %d 验证：第 %d 次请求被防护链处置（status=%d）", pol.ID, n, n+1, resp.status)
	case classifySmokeResponse(resp) == verdictGuardTombstone:
		return result(SmokeResultFail, "第 %d 次（阈值 %d+1）请求仍放行，CC 阈值未生效", n+1, n)
	default:
		return result(SmokeResultFail, "CC_EXACT 第 %d 次请求响应与防护链预期不符（status=%d）", n+1, resp.status)
	}
}

// runPublishSmoke 发布后流量验证入口（verifyPublish 配置一致性通过后调用）。// 返回报告永不返回 nil；FAIL 由调用方并入 verifyErr 走既有自动回滚路径。
func (p *Publisher) runPublishSmoke(ctx context.Context, taskID, versionID uuid.UUID, appsData []AppData, guardCfg *GuardConfig) *smokeReport {
	rep := &smokeReport{}
	targets, reason := resolveSmokeTargets(appsData, guardCfg)
	if len(targets) == 0 {
		rep.degraded = true
		rep.degradeReason = reason
		p.persistSmokeReport(taskID, versionID, rep)
		slog.Warn("post-publish smoke degraded", "task", taskID, "version", versionID, "reason", reason)
		return rep
	}
	available := 0
	var lastErr string
	for _, t := range targets {
		results, ok := p.probeTarget(ctx, t, guardCfg)
		rep.probes = append(rep.probes, results...)
		if ok {
			available++
		} else {
			lastErr = results[0].Message
		}
	}
	if available == 0 {
		// 全部目标传输层不可达：探针不可用（如管理面与网关分主机、数据面端口被管理
		// 主机防火墙拦截），降级为配置一致性校验并如实记录，不误判为防护失效。
		rep.degraded = true
		rep.degradeReason = fmt.Sprintf("全部 %d 个探针目标数据面不可达（%s）", len(targets), lastErr)
	}
	p.persistSmokeReport(taskID, versionID, rep)
	if rep.failed() {
		slog.Warn("post-publish smoke failed", "task", taskID, "version", versionID, "detail", rep.failureDetail())
	} else {
		slog.Info("post-publish smoke done", "task", taskID, "version", versionID,
			"result", rep.versionResult(), "degraded", rep.degraded)
	}
	return rep
}

// persistSmokeReport 冒烟结果落库：版本 validation_result 汇总 + validation_results
// 明细行。落库失败只告警不翻转发布结论（记录通道故障不改变已观测的探针事实，
// 但绝不静默吞掉）。
func (p *Publisher) persistSmokeReport(taskID, versionID uuid.UUID, rep *smokeReport) {
	if p.db == nil {
		return // 单测无库注入
	}
	ctx, cancel := context.WithTimeout(context.Background(), smokePersistTimeout)
	defer cancel()
	if _, err := p.db.Exec(ctx,
		`UPDATE gateway_config_versions SET validation_result=$1 WHERE id=$2`,
		rep.versionResult(), versionID); err != nil {
		slog.Warn("persist smoke version result failed", "version", versionID, "error", err)
	}
	rows := rep.probes
	if len(rows) == 0 {
		// 降级且无明细：落一行 SKIP 记录原因，不静默跳过
		rows = []smokeProbeResult{{
			Probe: "SMOKE", AppCode: "", Result: SmokeResultSkip, Message: rep.degradeReason,
		}}
	}
	for _, pr := range rows {
		errCode := ""
		switch pr.Result {
		case SmokeResultFail:
			errCode = "SMOKE_PROBE_FAILED"
		case SmokeResultSkip:
			errCode = "SMOKE_SKIPPED"
		}
		if _, err := p.db.Exec(ctx, `
INSERT INTO gateway_validation_results (publish_task_id, validation_type, validation_step, result, error_code, message, details_summary)
VALUES ($1, 'POST_PUBLISH_SMOKE', $2, $3, $4, $5, $6)`,
			taskID, pr.Probe, pr.Result, errCode, pr.Message, pr.AppCode); err != nil {
			slog.Warn("persist smoke validation row failed", "task", taskID, "probe", pr.Probe, "error", err)
		}
	}
}

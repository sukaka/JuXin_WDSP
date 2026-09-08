// engine.go 扫描引擎适配层 + 内置轻量探针引擎（设计稿 §6）。
//
// 引擎可替换：Engine 接口收敛执行语义（ProbeSets + Run），内置引擎基于 net/http
// （不引第三方扫描框架）；外部引擎后续以结果导入方式接入（适配器解析导入
// api_scan_findings）。引擎只做探测与判定，结论统一收敛为 ProbeResult 经 emit 回调
// 交由管理面落库——引擎不直接写库（与统一引擎"检测器不定案"纪律同构）。
//
// 安全红线（设计稿 §十一 / 任务书 §137）：
//   - 探针集白名单制：词表外探针一律拒绝；
//   - 默认禁用高风险方法主动探测（DELETE/PUT/PATCH/TRACE/CONNECT 一律不发送，
//     v1 无放宽入口；METHOD_ENUM 仅经 OPTIONS 的 Allow 头观察方法面）；
//   - 速率/并发/时间窗/allowlist 由 worker 解析进 ProbeTask，引擎侧硬约束执行；
//   - 每端点批次发包前回调 Guard 复查（授权撤销/过期/任务停止即刻中止）。
package apiscan

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/google/uuid"
)

// Engine 扫描引擎适配器抽象（设计稿 §6.1）。
type Engine interface {
	// ProbeSets 返回该引擎支持的探针集清单。
	ProbeSets() []string
	// Run 执行一个任务：逐端点探测，命中经 emit 回调 ProbeResult；
	// 受 ctx 取消、Guard 复查与限额约束。单端点错误不阻断任务（计入 RunSummary）。
	Run(ctx context.Context, task *ProbeTask, emit func(*ProbeResult) error) (RunSummary, error)
}

// ProbeTask 一次扫描任务的执行输入（worker 由目标/授权/任务解析装配）。
type ProbeTask struct {
	JobID          uuid.UUID
	BaseURL        string   // 目标根地址（http/https）
	Paths          []string // 待探测路径（来自目标 allowed_paths，逐一作为具体路径）
	ProbeSets      []string // 本次执行的探针集（已按授权画像过滤的词表子集）
	MaxQPS         int      // 速率上限（≤0 按 1 计）
	MaxConcurrency int      // 端点级并发上限（≤0 按 1 计）
	Signer         *Signer  // 隔离签名器（nil 时不携带签名头）
	// Guard 每端点批次发包前复查（授权状态/时间窗/任务停止）；返回非 nil 即中止整个任务。
	Guard func(context.Context) error
	// OnEndpointDone 每端点完成回调（done=已完成端点数；进度落库用，可为 nil）。
	OnEndpointDone func(done, total int)
	// HTTPClient 可注入 HTTP 客户端；nil 用默认（10s 超时、不跟随重定向）。
	// worker 执行路径恒注入拨号复检客户端（dial_guard.go：授权快照比对，防 DNS 重绑定）。
	HTTPClient *http.Client
}

// ProbeResult 引擎统一输出：命中端点 + 探针集 + 脱敏样本 + 结论要素。
type ProbeResult struct {
	Template       string         // 探针集
	EndpointKey    string         // "METHOD /path"
	Category       string         // AUTHN / AUTHZ / LIFECYCLE / SENSITIVE / SCHEMA
	Severity       string         // INFO / LOW / MEDIUM / HIGH / CRITICAL
	Confidence     float64        // 0~1
	Evidence       map[string]any // 脱敏证据（规则/状态码/字段名/哈希）
	RequestSample  string         // 已脱敏截断
	ResponseSample string         // 已脱敏截断（敏感探针为空）
}

// RunSummary 一次任务执行汇总（不静默吞错：单点错误计数并保留首个错误）。
type RunSummary struct {
	EndpointsDone   int
	EndpointsFailed int // 全部探针均错误的端点数（全量失败时任务应判 FAILED）
	Requests        int
	Findings        int
	Errors          int
	LastError       string
}

// dangerousMethods 高风险方法（默认禁用主动探测：一律不发送，仅可经 OPTIONS Allow 头观察）。
var dangerousMethods = map[string]bool{
	"DELETE": true, "PUT": true, "PATCH": true, "TRACE": true, "CONNECT": true,
}

// BuiltinEngine 内置轻量探针引擎（net/http 实现，v1 唯一引擎）。
type BuiltinEngine struct {
	client *http.Client
}

// NewBuiltinEngine 创建内置引擎（client 可为 nil：默认 10s 超时、不跟随重定向——
// 不跟随是为避免登录重定向被误判为"未认证可访问"）。
func NewBuiltinEngine(client *http.Client) *BuiltinEngine {
	if client == nil {
		client = &http.Client{
			Timeout: 10 * time.Second,
			CheckRedirect: func(_ *http.Request, _ []*http.Request) error {
				return http.ErrUseLastResponse
			},
		}
	}
	return &BuiltinEngine{client: client}
}

// ProbeSets 内置引擎支持的探针集（全部六个）。
func (e *BuiltinEngine) ProbeSets() []string { return AllProbeSets() }

// Run 执行任务：限速 + 并发 + Guard 复查下的逐端点探测。
func (e *BuiltinEngine) Run(ctx context.Context, task *ProbeTask, emit func(*ProbeResult) error) (RunSummary, error) {
	var summary RunSummary
	if task == nil {
		return summary, errors.New("apiscan: 空任务")
	}
	base, err := url.Parse(task.BaseURL)
	if err != nil || base.Scheme == "" || base.Host == "" {
		return summary, fmt.Errorf("apiscan: 目标 base_url 非法: %q", task.BaseURL)
	}
	if base.Scheme != "http" && base.Scheme != "https" {
		return summary, fmt.Errorf("apiscan: 目标 base_url 仅支持 http/https: %q", task.BaseURL)
	}
	// 探针集白名单校验（词表外一律拒绝，白名单制红线）
	sets := make([]string, 0, len(task.ProbeSets))
	for _, s := range task.ProbeSets {
		if !IsValidProbeSet(s) {
			return summary, fmt.Errorf("apiscan: 词表外探针集: %q", s)
		}
		sets = append(sets, s)
	}
	client := task.HTTPClient
	if client == nil {
		client = e.client
	}
	run := &engineRun{
		ctx:      ctx,
		task:     task,
		client:   client,
		base:     base,
		emit:     emit,
		limiter:  newRateLimiter(task.MaxQPS),
		sem:      make(chan struct{}, max(1, task.MaxConcurrency)),
		sets:     sets,
		requests: &summary.Requests,
	}

	var wg sync.WaitGroup
	var mu sync.Mutex // 保护 summary 汇总与首个错误
	var guardErr error
	var guardOnce sync.Once

loop:
	for _, path := range task.Paths {
		// 派发前复查（串行侧早退：撤销/停止尽快生效）
		if err := run.guard(); err != nil {
			guardOnce.Do(func() { guardErr = err })
			break
		}
		select {
		case <-ctx.Done():
			guardOnce.Do(func() { guardErr = ctx.Err() })
			break loop
		case run.sem <- struct{}{}:
		}
		wg.Add(1)
		go func(path string) {
			defer wg.Done()
			defer func() { <-run.sem }()
			if err := run.guard(); err != nil {
				guardOnce.Do(func() { guardErr = err })
				return
			}
			res := run.probeEndpoint(path)
			mu.Lock()
			summary.EndpointsDone++
			done := summary.EndpointsDone
			summary.Errors += res.errors
			if res.errors > 0 && res.findings == 0 {
				summary.EndpointsFailed++
			}
			if res.firstErr != "" && summary.LastError == "" {
				summary.LastError = res.firstErr
			}
			summary.Findings += res.findings
			mu.Unlock()
			if task.OnEndpointDone != nil {
				task.OnEndpointDone(done, len(task.Paths))
			}
		}(path)
	}
	wg.Wait()
	if guardErr != nil {
		return summary, guardErr
	}
	return summary, nil
}

// endpointResult 单端点探测汇总。
type endpointResult struct {
	findings int
	errors   int
	firstErr string
}

// engineRun 一次任务执行的内部状态。
type engineRun struct {
	ctx     context.Context
	task    *ProbeTask
	client  *http.Client
	base    *url.URL
	emit    func(*ProbeResult) error
	limiter *rateLimiter
	sem     chan struct{}
	sets    []string

	requests *int
	reqMu    sync.Mutex
}

// guard 发包前复查（无 Guard 配置时仅看 ctx）。
func (r *engineRun) guard() error {
	if err := r.ctx.Err(); err != nil {
		return err
	}
	if r.task.Guard != nil {
		return r.task.Guard(r.ctx)
	}
	return nil
}

// probeEndpoint 对单端点依次执行探针集（emit 失败即中止：发现落库失败不静默）。
func (r *engineRun) probeEndpoint(path string) endpointResult {
	var out endpointResult
	for _, set := range r.sets {
		if err := r.guard(); err != nil {
			// Guard 中止由外层汇总（此处停做本端点剩余探针）
			return out
		}
		result, err := r.probe(set, path)
		if err != nil {
			out.errors++
			if out.firstErr == "" {
				out.firstErr = fmt.Sprintf("%s %s: %v", set, path, err)
			}
			continue
		}
		if result == nil {
			continue
		}
		if err := r.emit(result); err != nil {
			out.errors++
			out.firstErr = fmt.Sprintf("%s %s: 发现落库失败: %v", set, path, err)
			return out
		}
		out.findings++
	}
	return out
}

// probe 分发单个探针集。
func (r *engineRun) probe(set, path string) (*ProbeResult, error) {
	switch set {
	case ProbeAuthRequired:
		return r.probeAuthRequired(path)
	case ProbeDeprecatedAlive:
		return r.probeDeprecatedAlive(path)
	case ProbeSensitiveExposure:
		return r.probeSensitiveExposure(path)
	case ProbeSchemaConform:
		return r.probeSchemaConform(path)
	case ProbeBolaCompare:
		return r.probeBolaCompare(path)
	case ProbeMethodEnum:
		return r.probeMethodEnum(path)
	}
	return nil, fmt.Errorf("apiscan: 词表外探针集: %q", set)
}

// httpResp 一次探测请求的最小观测。
type httpResp struct {
	status int
	body   []byte
	header http.Header
	req    *http.Request
}

// do 执行一次探测请求：限速等待 → 携带隔离签名头 → 发送 → 限量读体。
func (r *engineRun) do(method, path string) (*httpResp, error) {
	if err := r.limiter.wait(r.ctx); err != nil {
		return nil, err
	}
	u := r.base.ResolveReference(&url.URL{Path: path})
	// ResolveReference 对含查询串的路径需保留 RawQuery
	if idx := strings.IndexByte(path, '?'); idx >= 0 {
		u.Path = path[:idx]
		u.RawQuery = path[idx+1:]
	}
	req, err := http.NewRequestWithContext(r.ctx, method, u.String(), nil)
	if err != nil {
		return nil, err
	}
	if r.task.Signer != nil {
		req.Header.Set(ScanHeader, r.task.Signer.Sign(r.task.JobID))
	}
	req.Header.Set("User-Agent", "JiuZhang-APIScan/1.0")
	r.reqMu.Lock()
	*r.requests++
	r.reqMu.Unlock()
	resp, err := r.client.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	body, err := io.ReadAll(io.LimitReader(resp.Body, maxResponseBodyRead))
	if err != nil {
		return nil, err
	}
	return &httpResp{status: resp.StatusCode, body: body, header: resp.Header, req: req}, nil
}

// ---------- 探针集实现（判定规则收敛于管理面语义；负结果返回 nil 不产生发现） ----------

// probeAuthRequired AUTH_REQUIRED：无凭据重放，2xx = 未认证可访问（HIGH/AUTHN）；
// 401/403 = 被正确拒绝（负结果）；3xx 多为登录跳转，保守不作结论。
func (r *engineRun) probeAuthRequired(path string) (*ProbeResult, error) {
	resp, err := r.do(http.MethodGet, path)
	if err != nil {
		return nil, err
	}
	if resp.status >= 200 && resp.status < 300 {
		return &ProbeResult{
			Template:    ProbeAuthRequired,
			EndpointKey: "GET " + path,
			Category:    CategoryAuthn,
			Severity:    SeverityHigh,
			Confidence:  0.9,
			Evidence: map[string]any{
				"rule":        "unauthenticated_request_returned_2xx",
				"status_code": resp.status,
			},
			RequestSample:  buildRequestSample(resp.req),
			ResponseSample: buildResponseSample(resp.status, resp.body),
		}, nil
	}
	return nil, nil
}

// probeDeprecatedAlive DEPRECATED_ALIVE：2xx/3xx = 已下线端点仍可访问（MEDIUM/LIFECYCLE）；
// 404/410 = 已关闭（负结果）。
func (r *engineRun) probeDeprecatedAlive(path string) (*ProbeResult, error) {
	resp, err := r.do(http.MethodGet, path)
	if err != nil {
		return nil, err
	}
	if (resp.status >= 200 && resp.status < 400) && resp.status != http.StatusNotFound && resp.status != http.StatusGone {
		return &ProbeResult{
			Template:    ProbeDeprecatedAlive,
			EndpointKey: "GET " + path,
			Category:    CategoryLifecycle,
			Severity:    SeverityMedium,
			Confidence:  0.8,
			Evidence: map[string]any{
				"rule":        "deprecated_endpoint_still_responding",
				"status_code": resp.status,
			},
			RequestSample:  buildRequestSample(resp.req),
			ResponseSample: buildResponseSample(resp.status, resp.body),
		}, nil
	}
	return nil, nil
}

// probeSensitiveExposure SENSITIVE_EXPOSURE：2xx 响应体按敏感字段名词表判定；
// 只落命中字段名（不落响应原文——response_sample 恒空）。
func (r *engineRun) probeSensitiveExposure(path string) (*ProbeResult, error) {
	resp, err := r.do(http.MethodGet, path)
	if err != nil {
		return nil, err
	}
	if resp.status < 200 || resp.status >= 300 {
		return nil, nil
	}
	fields := scanSensitiveFields(resp.body)
	if len(fields) == 0 {
		return nil, nil
	}
	return &ProbeResult{
		Template:    ProbeSensitiveExposure,
		EndpointKey: "GET " + path,
		Category:    CategorySensitive,
		Severity:    SeverityHigh,
		Confidence:  0.7,
		Evidence: map[string]any{
			"rule":             "response_contains_sensitive_field_names",
			"status_code":      resp.status,
			"sensitive_fields": fields,
		},
		RequestSample:  buildRequestSample(resp.req),
		ResponseSample: "", // 敏感探针不落响应原文（脱敏红线）
	}, nil
}

// probeSchemaConform SCHEMA_CONFORM：基线请求 vs 边界参数请求对比。
// 边界参数（超长随机值）被接受（2xx）= 未观察到入参边界校验（LOW/SCHEMA，低置信）；
// 400/422 = 校验生效（负结果）；基线非 2xx = 端点不可达，不作结论。
// v1 简化：不耦合 FORMAL schema 编译产物，以通用边界值近似（见报告说明）。
func (r *engineRun) probeSchemaConform(path string) (*ProbeResult, error) {
	base, err := r.do(http.MethodGet, path)
	if err != nil {
		return nil, err
	}
	if base.status < 200 || base.status >= 300 {
		return nil, nil
	}
	sep := "?"
	if strings.Contains(path, "?") {
		sep = "&"
	}
	boundary := path + sep + "jz_boundary=" + strings.Repeat("A", 256)
	probe, err := r.do(http.MethodGet, boundary)
	if err != nil {
		return nil, err
	}
	if probe.status >= 200 && probe.status < 300 {
		return &ProbeResult{
			Template:    ProbeSchemaConform,
			EndpointKey: "GET " + path,
			Category:    CategorySchema,
			Severity:    SeverityLow,
			Confidence:  0.3,
			Evidence: map[string]any{
				"rule":                "boundary_param_accepted",
				"baseline_status":     base.status,
				"boundary_status":     probe.status,
				"boundary_param":      "jz_boundary",
				"boundary_value_size": 256,
			},
			RequestSample:  buildRequestSample(probe.req),
			ResponseSample: buildResponseSample(probe.status, probe.body),
		}, nil
	}
	return nil, nil
}

// probeBolaCompare BOLA_COMPARE：路径尾段为数字标识时，请求 id 与 id+1 对比响应。
// 两者均 2xx 且响应体不同 = 相邻对象可匿名枚举的迹象（INFO/AUTHZ，仅 OBSERVE 证据，
// 不落响应原文——证据只落状态码与体哈希前缀）。v1 无双低权凭据（凭据管理不在本波），
// 结论仅供人工复核，不自动定案。
func (r *engineRun) probeBolaCompare(path string) (*ProbeResult, error) {
	idx := strings.LastIndexByte(path, '/')
	if idx < 0 || idx == len(path)-1 {
		return nil, nil
	}
	tail := path[idx+1:]
	id, err := strconv.ParseInt(tail, 10, 64)
	if err != nil {
		return nil, nil // 尾段非数字标识：本探针不适用
	}
	self, err := r.do(http.MethodGet, path)
	if err != nil {
		return nil, err
	}
	other, err := r.do(http.MethodGet, fmt.Sprintf("%s%d", path[:idx+1], id+1))
	if err != nil {
		return nil, err
	}
	both2xx := self.status >= 200 && self.status < 300 && other.status >= 200 && other.status < 300
	if !both2xx {
		return nil, nil
	}
	selfDigest := bodyDigest(self.body)
	otherDigest := bodyDigest(other.body)
	if selfDigest == otherDigest {
		return nil, nil // 响应一致（如空列表/同错误页）：无可观察差异
	}
	return &ProbeResult{
		Template:    ProbeBolaCompare,
		EndpointKey: "GET " + path,
		Category:    CategoryAuthz,
		Severity:    SeverityInfo,
		Confidence:  0.3,
		Evidence: map[string]any{
			"rule":                "adjacent_object_ids_return_different_bodies",
			"observe_only":        true,
			"self_status":         self.status,
			"other_status":        other.status,
			"other_path":          fmt.Sprintf("%s%d", path[:idx+1], id+1),
			"self_body_sha256_8":  selfDigest,
			"other_body_sha256_8": otherDigest,
		},
		RequestSample:  buildRequestSample(self.req),
		ResponseSample: "", // 越权对比不落响应原文（脱敏红线）
	}, nil
}

// probeMethodEnum METHOD_ENUM：OPTIONS 枚举允许方法集；Allow 头宣告高风险方法
// （DELETE/PUT/TRACE 等）= 方法面暴露（LOW/AUTHZ）。本探针只发 OPTIONS，
// 高风险方法一律不主动发送（安全红线，v1 无放宽入口）。
func (r *engineRun) probeMethodEnum(path string) (*ProbeResult, error) {
	resp, err := r.do(http.MethodOptions, path)
	if err != nil {
		return nil, err
	}
	allow := strings.TrimSpace(resp.header.Get("Allow"))
	if allow == "" {
		return nil, nil
	}
	methods := make([]string, 0, 8)
	dangerous := make([]string, 0, 4)
	for _, m := range strings.Split(allow, ",") {
		m = strings.ToUpper(strings.TrimSpace(m))
		if m == "" {
			continue
		}
		methods = append(methods, m)
		if dangerousMethods[m] {
			dangerous = append(dangerous, m)
		}
	}
	if len(dangerous) == 0 {
		return nil, nil
	}
	sort.Strings(methods)
	sort.Strings(dangerous)
	return &ProbeResult{
		Template:    ProbeMethodEnum,
		EndpointKey: "OPTIONS " + path,
		Category:    CategoryAuthz,
		Severity:    SeverityLow,
		Confidence:  0.5,
		Evidence: map[string]any{
			"rule":              "options_allow_advertises_dangerous_methods",
			"status_code":       resp.status,
			"allowed_methods":   methods,
			"dangerous_methods": dangerous,
		},
		RequestSample:  buildRequestSample(resp.req),
		ResponseSample: buildResponseSample(resp.status, resp.body),
	}, nil
}

// ---------- 限速器 ----------

// rateLimiter 简单间隔限速器（并发安全）：请求间隔 ≥ 1s/qps。
type rateLimiter struct {
	mu       sync.Mutex
	interval time.Duration
	next     time.Time
}

func newRateLimiter(qps int) *rateLimiter {
	if qps <= 0 {
		qps = 1
	}
	return &rateLimiter{interval: time.Second / time.Duration(qps)}
}

// wait 等待下一个发送窗口（ctx 取消即返回）。
func (l *rateLimiter) wait(ctx context.Context) error {
	l.mu.Lock()
	now := time.Now()
	if l.next.Before(now) {
		l.next = now
	}
	at := l.next
	l.next = l.next.Add(l.interval)
	l.mu.Unlock()
	if d := time.Until(at); d > 0 {
		t := time.NewTimer(d)
		defer t.Stop()
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-t.C:
		}
	}
	return nil
}

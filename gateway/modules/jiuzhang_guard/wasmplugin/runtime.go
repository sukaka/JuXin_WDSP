// runtime.go 实现 Wasm 自定义检测插件沙箱的编译装配、每请求隔离执行、超时中止与生命周期清理。
package wasmplugin

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/jiuzhang-waf/gateway/dynamic_security/normalizer"
	"github.com/tetratelabs/wazero"
	"github.com/tetratelabs/wazero/api"
)

// Verdict 引擎对单个请求的最终汇总裁决。
type Verdict string

const (
	VerdictAllow      Verdict = "ALLOW"
	VerdictBlock      Verdict = "BLOCK"
	VerdictRateLimit  Verdict = "RATE_LIMIT"
	VerdictFailClosed Verdict = "FAIL_CLOSED"
)

// PluginOutcome 单个插件单次执行的脱敏结果摘要（绝不含原始请求体或凭据）。
type PluginOutcome struct {
	PluginID      string
	PluginName    string
	PluginVersion int
	ABIVersion    string
	Mode          string
	SHA256        string
	FailPolicy    string
	ActionCode    int32
	ScoreDelta    int
	RuleID        string
	Reason        string
	LatencyMS     int64
	ActionTaken   string
	Errored       bool
	Error         string
}

// EvalResult Engine.Evaluate 的汇总结果。
// FinalAction == VerdictAllow 时下游 A2A / API 动态防护 / Coraza WAF 必须照常执行（ALLOW 绝不绕过）。
type EvalResult struct {
	FinalAction Verdict
	Blocking    *PluginOutcome
	Signals     []PluginOutcome
	Errors      []PluginOutcome
}

type compiledPlugin struct {
	cfg          PluginConfig
	pathPrefixes []string
	rt           wazero.Runtime
	compiled     wazero.CompiledModule
}

// Engine Wasm 自定义检测插件沙箱引擎（Provision 期预编译，热路径无锁并发安全，Cleanup 关闭全部运行时）。
type Engine struct {
	mu      sync.RWMutex
	closed  bool
	appID   string
	plugins []*compiledPlugin
}

// newPluginRuntime 创建单个插件专属的零 WASI、解释器模式、带内存上限与上下文中止的 wazero.Runtime。
func newPluginRuntime(ctx context.Context, pages uint32) (wazero.Runtime, error) {
	rCfg := wazero.NewRuntimeConfigInterpreter().
		WithCloseOnContextDone(true).
		WithMemoryLimitPages(pages)
	rt := wazero.NewRuntimeWithConfig(ctx, rCfg)
	if err := registerWDSPEnvHost(ctx, rt); err != nil {
		_ = rt.Close(ctx)
		return nil, err
	}
	return rt, nil
}

// compileAndVerifyPlugin 编译单个 Wasm 插件并验证导出符号与只读导入白名单（零 WASI）。
func compileAndVerifyPlugin(ctx context.Context, cfg PluginConfig) (*compiledPlugin, error) {
	rt, err := newPluginRuntime(ctx, cfg.MemoryLimitPages())
	if err != nil {
		return nil, fmt.Errorf("plugin %q: %w", cfg.Name, err)
	}
	compiled, err := rt.CompileModule(ctx, cfg.WasmBytes)
	if err != nil {
		_ = rt.Close(ctx)
		return nil, fmt.Errorf("plugin %q compile failed: %w", cfg.Name, err)
	}

	if err := verifyCompiledContract(compiled); err != nil {
		_ = compiled.Close(ctx)
		_ = rt.Close(ctx)
		return nil, fmt.Errorf("plugin %q contract check failed: %w", cfg.Name, err)
	}

	prefixes := normalizePathPrefixes(cfg.PathPrefixes)
	return &compiledPlugin{
		cfg:          cfg,
		pathPrefixes: prefixes,
		rt:           rt,
		compiled:     compiled,
	}, nil
}

// verifyCompiledContract 校验预编译模块的导出与导入契约：
//   - 必须导出线性内存 "memory"；
//   - 必须导出入口函数 "wdsp_on_request"（0 参数，0 返回值或单 i32 返回值）；
//   - 禁止导入任何内存，禁止导入非 "wdsp_env" 模块（彻底阻断 WASI 等特权导入），
//     且仅允许导入 "wdsp_env" 暴露的 6 个只读/结果函数。
func verifyCompiledContract(compiled wazero.CompiledModule) error {
	if _, ok := compiled.ExportedMemories()[ExportMemoryName]; !ok {
		return fmt.Errorf("missing required exported memory %q", ExportMemoryName)
	}
	fnDef, ok := compiled.ExportedFunctions()[ExportEntrypointName]
	if !ok {
		return fmt.Errorf("missing required exported function %q", ExportEntrypointName)
	}
	if len(fnDef.ParamTypes()) != 0 {
		return fmt.Errorf("exported %q must take 0 parameters, got %d", ExportEntrypointName, len(fnDef.ParamTypes()))
	}
	resTypes := fnDef.ResultTypes()
	if len(resTypes) > 1 || (len(resTypes) == 1 && resTypes[0] != api.ValueTypeI32) {
		return fmt.Errorf("exported %q must return () or (i32)", ExportEntrypointName)
	}
	if len(compiled.ImportedMemories()) > 0 {
		return errors.New("importing host memory is forbidden")
	}
	for _, imp := range compiled.ImportedFunctions() {
		modName, fnName, imported := imp.Import()
		if !imported {
			continue
		}
		if modName != HostModuleName {
			return fmt.Errorf("forbidden import module %q.%q (only %q is allowed; WASI is disabled)", modName, fnName, HostModuleName)
		}
		if _, allowed := allowedHostFunctions[fnName]; !allowed {
			return fmt.Errorf("unknown import function %q.%q", modName, fnName)
		}
	}
	return nil
}

// ValidateCompiled 供 Caddy Validate 预检阶段使用：对已校验配置中的每个非 OFF 插件执行完整编译与契约检查并立即释放运行时。
func ValidateCompiled(cfg *Config) error {
	if cfg == nil {
		return errors.New("wasmplugin: nil config")
	}
	if err := ValidateConfig(cfg); err != nil {
		return err
	}
	ctx := context.Background()
	for _, p := range cfg.Plugins {
		// 即使 mode==OFF 也校验 Wasm 结构与导入导出契约，保证管理面保存/网关验证/开启运行口径一致。
		cp, err := compileAndVerifyPlugin(ctx, p)
		if err != nil {
			return err
		}
		_ = cp.compiled.Close(ctx)
		_ = cp.rt.Close(ctx)
	}
	return nil
}

// NewEngine 从已校验 Config 预编译并装配沙箱运行时引擎。
// 仅保留非 OFF 插件按 priority 升序执行（OFF 插件同样校验结构合法性，但不在运行期驻留内存）。
func NewEngine(cfg *Config) (*Engine, error) {
	if cfg == nil {
		return nil, errors.New("wasmplugin: nil config")
	}
	if err := ValidateConfig(cfg); err != nil {
		return nil, err
	}

	ctx := context.Background()
	active := make([]*compiledPlugin, 0, len(cfg.Plugins))
	cleanupAll := func() {
		for _, cp := range active {
			_ = cp.compiled.Close(ctx)
			_ = cp.rt.Close(ctx)
		}
	}

	for _, p := range cfg.Plugins {
		cp, err := compileAndVerifyPlugin(ctx, p)
		if err != nil {
			cleanupAll()
			return nil, err
		}
		if p.Mode == ModeOff {
			_ = cp.compiled.Close(ctx)
			_ = cp.rt.Close(ctx)
			continue
		}
		active = append(active, cp)
	}

	sort.SliceStable(active, func(i, j int) bool {
		if active[i].cfg.Priority != active[j].cfg.Priority {
			return active[i].cfg.Priority < active[j].cfg.Priority
		}
		if active[i].cfg.Name != active[j].cfg.Name {
			return active[i].cfg.Name < active[j].cfg.Name
		}
		return active[i].cfg.ID < active[j].cfg.ID
	})

	return &Engine{
		appID:   cfg.ApplicationID,
		plugins: active,
	}, nil
}

// ActiveCount 返回当前激活（OBSERVE/PROTECT）的插件数量。
func (e *Engine) ActiveCount() int {
	if e == nil {
		return 0
	}
	e.mu.RLock()
	defer e.mu.RUnlock()
	if e.closed {
		return 0
	}
	return len(e.plugins)
}

// NeedsBodyForPath 返回命中 reqPath 的全部激活插件所需的最大请求体字节数：
//   - 返回 -1 表示无任何激活插件匹配该路径（调用方可零开销跳过请求体读取与引擎调用）；
//   - 返回 0 表示存在匹配插件但均不读取请求体（max_body_bytes == 0）；
//   - 返回 >0 表示最大需要的请求体前缀字节数（<= 65536）。
func (e *Engine) NeedsBodyForPath(reqPath string) int {
	if e == nil {
		return -1
	}
	e.mu.RLock()
	defer e.mu.RUnlock()
	if e.closed || len(e.plugins) == 0 {
		return -1
	}
	canon := normalizer.CanonicalPath(reqPath)
	matched := false
	maxBytes := 0
	for _, cp := range e.plugins {
		if !cp.matchesPath(canon) {
			continue
		}
		matched = true
		if cp.cfg.MaxBodyBytes > maxBytes {
			maxBytes = cp.cfg.MaxBodyBytes
		}
	}
	if !matched {
		return -1
	}
	return maxBytes
}

// Evaluate 按优先级依次执行匹配请求路径的全部激活插件。
//   - 每插件每次调用实例化全新隔离模块并在 defer 关闭（零跨请求线性内存泄漏）；
//   - 每插件调用受 context.WithTimeout(ctx, timeout_ms) 硬超时约束；
//   - PROTECT 模式下首个 BLOCK / RATE_LIMIT（或 FAIL_CLOSED 故障）立即终止迭代；
//   - OBSERVE 模式仅收集信号，绝不实断；
//   - ALLOW 绝不跳过后续插件，也不得绕过下游 API 动态防护或 Coraza WAF。
func (e *Engine) Evaluate(ctx context.Context, req *http.Request, body []byte) EvalResult {
	res := EvalResult{FinalAction: VerdictAllow}
	if e == nil || req == nil {
		return res
	}
	e.mu.RLock()
	defer e.mu.RUnlock()
	if e.closed || len(e.plugins) == 0 {
		return res
	}
	if ctx == nil {
		ctx = context.Background()
	}

	rawPath := ""
	rawQuery := ""
	if req.URL != nil {
		rawPath = req.URL.Path
		rawQuery = req.URL.RawQuery
	}
	canonPath := normalizer.CanonicalPath(rawPath)

	for _, cp := range e.plugins {
		if !cp.matchesPath(canonPath) {
			continue
		}
		outcome := cp.execute(ctx, req, canonPath, rawQuery, body)
		if outcome.Errored {
			if cp.cfg.Mode == ModeProtect && cp.cfg.FailPolicy == FailClosed {
				outcome.ActionTaken = "fail_closed_503"
				cpOut := outcome
				res.FinalAction = VerdictFailClosed
				res.Blocking = &cpOut
				return res
			}
			outcome.ActionTaken = "fail_open_error"
			res.Errors = append(res.Errors, outcome)
			continue
		}

		switch outcome.ActionCode {
		case ActionAllow:
			// ALLOW 仅表示本插件未命中；继续评估后续插件且绝不绕过下游防护。
			continue
		case ActionObserve:
			outcome.ActionTaken = "observed"
			res.Signals = append(res.Signals, outcome)
		case ActionBlock:
			if cp.cfg.Mode == ModeProtect {
				outcome.ActionTaken = "blocked"
				cpOut := outcome
				res.FinalAction = VerdictBlock
				res.Blocking = &cpOut
				return res
			}
			outcome.ActionTaken = "would_block"
			res.Signals = append(res.Signals, outcome)
		case ActionRateLimit:
			if cp.cfg.Mode == ModeProtect {
				outcome.ActionTaken = "rate_limited"
				cpOut := outcome
				res.FinalAction = VerdictRateLimit
				res.Blocking = &cpOut
				return res
			}
			outcome.ActionTaken = "would_rate_limit"
			res.Signals = append(res.Signals, outcome)
		}
	}

	return res
}

// Close 幂等关闭引擎持有的全部 wazero 运行时与预编译模块（等待在途请求结束后安全释放，无数据竞态）。
func (e *Engine) Close() error {
	if e == nil {
		return nil
	}
	e.mu.Lock()
	defer e.mu.Unlock()
	if e.closed {
		return nil
	}
	e.closed = true
	ctx := context.Background()
	var errs []error
	for _, cp := range e.plugins {
		if cp.compiled != nil {
			errs = append(errs, cp.compiled.Close(ctx))
		}
		if cp.rt != nil {
			errs = append(errs, cp.rt.Close(ctx))
		}
	}
	return errors.Join(errs...)
}

func (cp *compiledPlugin) matchesPath(canonPath string) bool {
	if len(cp.pathPrefixes) == 0 {
		return true
	}
	for _, pfx := range cp.pathPrefixes {
		if normalizer.PrefixSegmentMatch(pfx, canonPath) {
			return true
		}
	}
	return false
}

func (cp *compiledPlugin) execute(ctx context.Context, req *http.Request, canonPath, rawQuery string, body []byte) PluginOutcome {
	start := time.Now()
	out := PluginOutcome{
		PluginID:      cp.cfg.ID,
		PluginName:    cp.cfg.Name,
		PluginVersion: cp.cfg.Version,
		ABIVersion:    cp.cfg.ABIVersion,
		Mode:          cp.cfg.Mode,
		SHA256:        cp.cfg.SHA256,
		FailPolicy:    cp.cfg.FailPolicy,
		ActionCode:    ActionAllow,
	}

	boundedBody := body
	if cp.cfg.MaxBodyBytes <= 0 {
		boundedBody = nil
	} else if len(boundedBody) > cp.cfg.MaxBodyBytes {
		boundedBody = boundedBody[:cp.cfg.MaxBodyBytes]
	}

	st := &invocationState{
		method:    req.Method,
		canonPath: canonPath,
		rawQuery:  rawQuery,
		host:      req.Host,
		headers:   req.Header,
		body:      boundedBody,
	}

	callCtx, cancel := context.WithTimeout(ctx, time.Duration(cp.cfg.TimeoutMS)*time.Millisecond)
	defer cancel()
	callCtx = withInvocationState(callCtx, st)

	// 匿名实例化 + 禁用 _start：每请求独立线性内存，零跨请求共享状态。
	modCfg := wazero.NewModuleConfig().WithName("").WithStartFunctions()
	mod, err := cp.rt.InstantiateModule(callCtx, cp.compiled, modCfg)
	if err != nil {
		out.LatencyMS = time.Since(start).Milliseconds()
		out.Errored = true
		out.Error = classifyExecError(callCtx, err)
		return out
	}
	defer func() {
		_ = mod.Close(context.Background())
	}()

	fn := mod.ExportedFunction(ExportEntrypointName)
	if fn == nil {
		out.LatencyMS = time.Since(start).Milliseconds()
		out.Errored = true
		out.Error = "missing entrypoint " + ExportEntrypointName
		return out
	}

	if _, err := fn.Call(callCtx); err != nil {
		out.LatencyMS = time.Since(start).Milliseconds()
		out.Errored = true
		out.Error = classifyExecError(callCtx, err)
		return out
	}
	if st.abiErr != nil {
		out.LatencyMS = time.Since(start).Milliseconds()
		out.Errored = true
		out.Error = sanitizeText(st.abiErr.Error(), 256)
		return out
	}

	out.LatencyMS = time.Since(start).Milliseconds()
	if st.hasResult {
		out.ActionCode = st.actionCode
		out.ScoreDelta = int(st.scoreDelta)
		out.RuleID = st.ruleID
		out.Reason = st.reason
	}
	return out
}

func classifyExecError(callCtx context.Context, err error) string {
	if errors.Is(err, context.DeadlineExceeded) ||
		errors.Is(callCtx.Err(), context.DeadlineExceeded) ||
		strings.Contains(err.Error(), "context deadline exceeded") {
		return "execution timeout exceeded"
	}
	if errors.Is(err, context.Canceled) || errors.Is(callCtx.Err(), context.Canceled) {
		return "execution canceled"
	}
	return sanitizeText(err.Error(), 256)
}

func normalizePathPrefixes(in []string) []string {
	if len(in) == 0 {
		return nil
	}
	seen := make(map[string]struct{}, len(in))
	out := make([]string, 0, len(in))
	for _, pfx := range in {
		c := normalizer.CanonicalPath(strings.TrimSpace(pfx))
		if len(c) > 1 {
			c = strings.TrimRight(c, "/")
			if c == "" {
				c = "/"
			}
		}
		if _, dup := seen[c]; dup {
			continue
		}
		seen[c] = struct{}{}
		out = append(out, c)
	}
	return out
}

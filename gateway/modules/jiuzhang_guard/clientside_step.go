// clientside_step.go Phase 9B 客户端供应链安全（Magecart 防护 / PCI DSS 4.0 6.4.3 & 11.6.1）
// 在 jiuzhang_guard 的挂点实现：
//   - 配置段 client_side_policy 严格解码（DisallowUnknownFields）+ 全量校验，fail-closed 拒载；
//   - 保留本地命名空间 /_wdsp/csp/v1/ 与 /_wdsp/cs/v1/ 一律本地处理，绝不反向代理；
//   - 未配置或 mode==OFF 时请求链路零包装零开销直通（保留端点仍本地墓碑保护，不劫持业务路径）；
//   - OBSERVE / PROTECT 模式包装 2xx HTML 响应：注入 CSP 响应头、有界 <=1MiB 未压缩 HTML 扫描与
//     可选未授权脚本剥离、敏感路径防窃取探针脚本注入，全部事件统一落 access_control_events。
package jiuzhang_guard

import (
	"net/http"
	"strconv"

	"github.com/jiuzhang-waf/gateway/modules/jiuzhang_guard/clientip"
	"github.com/jiuzhang-waf/gateway/modules/jiuzhang_guard/clientside"
	"github.com/jiuzhang-waf/gateway/modules/jiuzhang_guard/events"
	"go.uber.org/zap"
)

func (g *Guard) validateClientSidePolicy() error {
	if len(g.ClientSidePolicy) == 0 {
		return nil
	}
	_, err := clientside.ParseAndValidatePolicy(g.ClientSidePolicy)
	return err
}

func (g *Guard) assembleClientSide() error {
	if len(g.ClientSidePolicy) == 0 {
		g.clientSide = nil
		return nil
	}
	pol, err := clientside.ParseAndValidatePolicy(g.ClientSidePolicy)
	if err != nil {
		return err
	}
	if pol.Mode == clientside.ModeOff {
		g.clientSide = nil
		return nil
	}
	eng, err := clientside.NewEngine(pol, clientside.EngineOptions{})
	if err != nil {
		return err
	}
	g.clientSide = eng
	if g.logger != nil {
		cspHeader, _ := eng.CSPHeader()
		g.logger.Info("client side security policy loaded",
			zap.String("app_id", pol.ApplicationID),
			zap.String("mode", pol.Mode),
			zap.Int("policy_version", pol.Version),
			zap.String("csp_mode", pol.CSPMode),
			zap.String("csp_header", cspHeader),
			zap.Bool("probe_enabled", pol.ProbeEnabled),
			zap.Bool("strip_unauthorized_scripts", pol.StripUnauthorizedScripts),
			zap.Int("sensitive_paths", len(pol.SensitivePaths)),
			zap.Int("authorized_scripts", len(pol.AuthorizedScripts)))
	}
	return nil
}

// serveClientSideReportNamespace 本地处理保留命名空间 /_wdsp/csp/v1/（绝不反向代理）。
//   - 策略开启时：POST /_wdsp/csp/v1/report 解析 CSP 报告/Reporting API/探针告警并上报事件，返回 204；
//     非 POST 返回 405；未知子路径返回本地 404。
//   - 策略关闭/未配置时：本地墓碑响应（非 POST /_wdsp/csp/v1/report 返回 405，其余返回 404），绝不转发源站。
func (g *Guard) serveClientSideReportNamespace(w http.ResponseWriter, r *http.Request, canonPath string, base events.Event, res clientip.Result) error {
	dispo := DispositionFrom(r.Context())
	if canonPath != clientside.CSPReportPath {
		writeClientSideLocalTombstone(w, r, http.StatusNotFound, "")
		dispo.RecordTerminal(ExecutorBot, DisActionNone, http.StatusNotFound, true,
			[]string{"CLIENT_SIDE_LOCAL_NOT_FOUND"}, g.clientSideRuleRefs())
		return nil
	}
	if g.clientSide == nil {
		status := http.StatusNotFound
		allow := ""
		if r.Method != http.MethodPost {
			status = http.StatusMethodNotAllowed
			allow = http.MethodPost
		}
		writeClientSideLocalTombstone(w, r, status, allow)
		dispo.RecordTerminal(ExecutorBot, DisActionNone, status, true,
			[]string{"CLIENT_SIDE_REPORT_TOMBSTONE"}, nil)
		return nil
	}

	outcome := g.clientSide.ServeReportRequest(w, r, res.ClientIP.String())
	disAction := DisActionNone
	reason := "CLIENT_SIDE_REPORT_ACCEPTED"
	switch outcome.Status {
	case http.StatusTooManyRequests:
		disAction = DisActionRateLimit
		reason = "CLIENT_SIDE_REPORT_RATE_LIMITED"
	case http.StatusRequestEntityTooLarge:
		reason = "CLIENT_SIDE_REPORT_TOO_LARGE"
	case http.StatusMethodNotAllowed:
		reason = "CLIENT_SIDE_REPORT_METHOD_NOT_ALLOWED"
	case http.StatusBadRequest:
		reason = "CLIENT_SIDE_REPORT_BAD_REQUEST"
	}
	dispo.RecordTerminal(ExecutorBot, disAction, outcome.Status, true, []string{reason}, g.clientSideRuleRefs())

	pol := g.clientSide.Policy()
	for _, rep := range outcome.Events {
		evType := events.ClientSideCSPViolation
		if rep.ViolationType == clientside.ViolationProbeAlert {
			evType = events.ClientSideProbeAlert
		}
		ev := base
		ev.ClientSide = &events.ClientSideDetail{
			PolicyVersion:     pol.Version,
			Mode:              pol.Mode,
			ViolationType:     rep.ViolationType,
			ScriptURL:         rep.ScriptURL,
			ScriptOrigin:      rep.ScriptOrigin,
			PagePath:          rep.PagePath,
			ViolatedDirective: rep.ViolatedDirective,
			BlockedURI:        rep.BlockedURI,
			ActionTaken:       rep.ActionTaken,
			Reason:            rep.Reason,
		}
		g.emit(ev, evType, rep.ActionTaken, outcome.Status)
	}
	return nil
}

// serveClientSideProbeNamespace 本地处理保留命名空间 /_wdsp/cs/v1/（绝不反向代理）。
//   - 策略开启且 probe_enabled == true 时：GET/HEAD /_wdsp/cs/v1/probe.js 返回嵌入式探针脚本（200），
//     非 GET/HEAD 返回 405；未知子路径返回本地 404。
//   - 策略关闭/未配置或 probe_enabled == false 时：本地 404 墓碑响应，绝不转发源站。
func (g *Guard) serveClientSideProbeNamespace(w http.ResponseWriter, r *http.Request, canonPath string) error {
	dispo := DispositionFrom(r.Context())
	if canonPath == clientside.ProbeScriptPath && g.clientSide != nil && g.clientSide.Policy().ProbeEnabled {
		status := clientside.ServeProbeScript(w, r)
		dispo.RecordTerminal(ExecutorBot, DisActionNone, status, true,
			[]string{"CLIENT_SIDE_PROBE_SERVED"}, g.clientSideRuleRefs())
		return nil
	}
	writeClientSideLocalTombstone(w, r, http.StatusNotFound, "")
	dispo.RecordTerminal(ExecutorBot, DisActionNone, http.StatusNotFound, true,
		[]string{"CLIENT_SIDE_PROBE_TOMBSTONE"}, g.clientSideRuleRefs())
	return nil
}

func writeClientSideLocalTombstone(w http.ResponseWriter, r *http.Request, status int, allow string) {
	w.Header().Set("Cache-Control", "no-store")
	w.Header().Set("Content-Type", "text/plain; charset=utf-8")
	if allow != "" {
		w.Header().Set("Allow", allow)
	}
	w.WriteHeader(status)
	if r.Method == http.MethodHead {
		return
	}
	if status == http.StatusMethodNotAllowed {
		_, _ = w.Write([]byte("405 method not allowed"))
		return
	}
	_, _ = w.Write([]byte("404 not found"))
}

// wrapClientSideResponse 包装下游响应，在 2xx text/html 回程执行 CSP 头注入、
// 有界脚本扫描、篡改检测、可选未授权脚本剥离与敏感路径探针注入。
func (g *Guard) wrapClientSideResponse(w http.ResponseWriter, r *http.Request, canonPath string, base events.Event) *clientside.HTMLResponseWrapper {
	pol := g.clientSide.Policy()
	return g.clientSide.NewHTMLResponseWrapper(w, r, canonPath, func(findings []clientside.ScanFinding) {
		if g.events == nil {
			return
		}
		for _, f := range findings {
			evType := events.ClientSideScriptObserved
			switch f.ViolationType {
			case clientside.ViolationUnauthorizedScript:
				evType = events.ClientSideUnauthorizedScript
			case clientside.ViolationScriptTampered:
				evType = events.ClientSideScriptTampered
			}
			ev := base
			ev.ClientSide = &events.ClientSideDetail{
				PolicyVersion: pol.Version,
				Mode:          pol.Mode,
				ViolationType: f.ViolationType,
				ScriptURL:     f.ScriptURL,
				ScriptOrigin:  f.ScriptOrigin,
				ScriptType:    f.ScriptType,
				ExpectedSRI:   f.ExpectedSRI,
				ObservedSRI:   f.ObservedSRI,
				PagePath:      f.PagePath,
				ActionTaken:   f.ActionTaken,
				Reason:        f.Reason,
			}
			g.emit(ev, evType, f.ActionTaken, http.StatusOK)
		}
	})
}

func (g *Guard) clientSideRuleRefs() []string {
	if g.clientSide == nil {
		return nil
	}
	return []string{"client-side-policy:v" + strconv.Itoa(g.clientSide.Policy().Version)}
}

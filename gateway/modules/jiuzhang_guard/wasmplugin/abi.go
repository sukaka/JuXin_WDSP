// abi.go 定义并注册暴露给 Wasm 客体的唯一只读宿主模块 "wdsp_env"。
//
// 安全红线：
//   - 仅注册 6 个受控只读/结果上报函数：get_method、get_path、get_query、get_header、get_body、set_result；
//   - 绝不注册 WASI、文件系统、网络、环境变量、时钟或随机数宿主函数；
//   - get_header 对 Authorization / Cookie / Proxy-Authorization / DPoP / X-Api-Key
//     恒返回 -1，防止第三方插件窃取凭据；
//   - 每请求状态通过 context.Context 传递（零共享可变宿主状态，天然并发安全无竞态）。
package wasmplugin

import (
	"context"
	"fmt"
	"net/http"
	"strings"

	"github.com/tetratelabs/wazero"
	"github.com/tetratelabs/wazero/api"
)

const (
	hostFnGetMethod = "get_method"
	hostFnGetPath   = "get_path"
	hostFnGetQuery  = "get_query"
	hostFnGetHeader = "get_header"
	hostFnGetBody   = "get_body"
	hostFnSetResult = "set_result"

	maxHeaderNameReadLen = 256
	maxGuestTextReadLen  = 1024
)

// allowedHostFunctions 客体允许从 "wdsp_env" 导入的全部宿主函数白名单。
var allowedHostFunctions = map[string]struct{}{
	hostFnGetMethod: {},
	hostFnGetPath:   {},
	hostFnGetQuery:  {},
	hostFnGetHeader: {},
	hostFnGetBody:   {},
	hostFnSetResult: {},
}

// blockedCredentialHeaders 严格禁止暴露给 Wasm 插件的凭据类请求头（小写归一化）。
// get_header 命中任意一项均恒返回 -1（如同不存在），杜绝插件窃取令牌、Cookie 或 API Key。
var blockedCredentialHeaders = map[string]struct{}{
	"authorization":       {},
	"cookie":              {},
	"proxy-authorization": {},
	"dpop":                {},
	"x-api-key":           {},
}

// isBlockedCredentialHeader 判断请求头名是否属于严格屏蔽的凭据头（大小写不敏感）。
func isBlockedCredentialHeader(name string) bool {
	_, blocked := blockedCredentialHeaders[strings.ToLower(strings.TrimSpace(name))]
	return blocked
}

type invocationCtxKey struct{}

// invocationState 单次请求单次插件调用的隔离上下文（随 callCtx 传入宿主函数，零跨请求共享）。
type invocationState struct {
	method    string
	canonPath string
	rawQuery  string
	host      string
	headers   http.Header
	body      []byte

	hasResult  bool
	actionCode int32
	scoreDelta int32
	ruleID     string
	reason     string
	abiErr     error
}

func withInvocationState(ctx context.Context, st *invocationState) context.Context {
	return context.WithValue(ctx, invocationCtxKey{}, st)
}

func invocationStateFrom(ctx context.Context) *invocationState {
	if ctx == nil {
		return nil
	}
	st, _ := ctx.Value(invocationCtxKey{}).(*invocationState)
	return st
}

// registerWDSPEnvHost 在独立 wazero.Runtime 上仅注册只读宿主模块 "wdsp_env"。
func registerWDSPEnvHost(ctx context.Context, rt wazero.Runtime) error {
	_, err := rt.NewHostModuleBuilder(HostModuleName).
		NewFunctionBuilder().
		WithFunc(hostGetMethod).
		Export(hostFnGetMethod).
		NewFunctionBuilder().
		WithFunc(hostGetPath).
		Export(hostFnGetPath).
		NewFunctionBuilder().
		WithFunc(hostGetQuery).
		Export(hostFnGetQuery).
		NewFunctionBuilder().
		WithFunc(hostGetHeader).
		Export(hostFnGetHeader).
		NewFunctionBuilder().
		WithFunc(hostGetBody).
		Export(hostFnGetBody).
		NewFunctionBuilder().
		WithFunc(hostSetResult).
		Export(hostFnSetResult).
		Instantiate(ctx)
	if err != nil {
		return fmt.Errorf("register host module %q: %w", HostModuleName, err)
	}
	return nil
}

func hostGetMethod(ctx context.Context, mod api.Module, ptr, maxLen int32) int32 {
	st := invocationStateFrom(ctx)
	if st == nil {
		return -1
	}
	return writeToGuestMemory(mod, ptr, maxLen, []byte(st.method))
}

func hostGetPath(ctx context.Context, mod api.Module, ptr, maxLen int32) int32 {
	st := invocationStateFrom(ctx)
	if st == nil {
		return -1
	}
	return writeToGuestMemory(mod, ptr, maxLen, []byte(st.canonPath))
}

func hostGetQuery(ctx context.Context, mod api.Module, ptr, maxLen int32) int32 {
	st := invocationStateFrom(ctx)
	if st == nil {
		return -1
	}
	return writeToGuestMemory(mod, ptr, maxLen, []byte(st.rawQuery))
}

func hostGetHeader(ctx context.Context, mod api.Module, namePtr, nameLen, outPtr, outMaxLen int32) int32 {
	st := invocationStateFrom(ctx)
	if st == nil || nameLen <= 0 || nameLen > maxHeaderNameReadLen {
		return -1
	}
	nameBytes, ok := readFromGuestMemory(mod, namePtr, nameLen, maxHeaderNameReadLen)
	if !ok {
		return -1
	}
	headerName := strings.TrimSpace(string(nameBytes))
	if headerName == "" || hasControlChars(headerName) {
		return -1
	}
	// 严格凭据隔离：Authorization / Cookie / Proxy-Authorization / DPoP / X-Api-Key 恒返回 -1。
	if isBlockedCredentialHeader(headerName) {
		return -1
	}
	vals := st.headers.Values(headerName)
	if len(vals) == 0 {
		if strings.EqualFold(headerName, "host") && st.host != "" {
			return writeToGuestMemory(mod, outPtr, outMaxLen, []byte(st.host))
		}
		return -1
	}
	return writeToGuestMemory(mod, outPtr, outMaxLen, []byte(strings.Join(vals, ", ")))
}

func hostGetBody(ctx context.Context, mod api.Module, ptr, maxLen int32) int32 {
	st := invocationStateFrom(ctx)
	if st == nil {
		return -1
	}
	return writeToGuestMemory(mod, ptr, maxLen, st.body)
}

func hostSetResult(ctx context.Context, mod api.Module, actionCode, scoreDelta, rulePtr, ruleLen, reasonPtr, reasonLen int32) {
	st := invocationStateFrom(ctx)
	if st == nil {
		return
	}
	if actionCode < ActionAllow || actionCode > ActionRateLimit {
		st.abiErr = fmt.Errorf("invalid action_code %d", actionCode)
		return
	}
	if scoreDelta < 0 {
		scoreDelta = 0
	} else if scoreDelta > MaxScoreDelta {
		scoreDelta = MaxScoreDelta
	}

	var ruleID, reason string
	if ruleLen > 0 {
		if b, ok := readFromGuestMemory(mod, rulePtr, ruleLen, maxGuestTextReadLen); ok {
			ruleID = sanitizeText(string(b), MaxRuleLen)
		}
	}
	if reasonLen > 0 {
		if b, ok := readFromGuestMemory(mod, reasonPtr, reasonLen, maxGuestTextReadLen); ok {
			reason = sanitizeText(string(b), MaxReasonLen)
		}
	}

	st.hasResult = true
	st.actionCode = actionCode
	st.scoreDelta = scoreDelta
	st.ruleID = ruleID
	st.reason = reason
}

func writeToGuestMemory(mod api.Module, ptr, maxLen int32, data []byte) int32 {
	if mod == nil || ptr < 0 || maxLen < 0 {
		return -1
	}
	mem := mod.Memory()
	if mem == nil {
		return -1
	}
	if maxLen == 0 || len(data) == 0 {
		return 0
	}
	n := len(data)
	if n > int(maxLen) {
		n = int(maxLen)
	}
	if !mem.Write(uint32(ptr), data[:n]) {
		return -1
	}
	return int32(n)
}

func readFromGuestMemory(mod api.Module, ptr, length int32, hardCap int) ([]byte, bool) {
	if mod == nil || ptr < 0 || length < 0 {
		return nil, false
	}
	if length == 0 {
		return nil, true
	}
	mem := mod.Memory()
	if mem == nil {
		return nil, false
	}
	n := int(length)
	if hardCap > 0 && n > hardCap {
		n = hardCap
	}
	buf, ok := mem.Read(uint32(ptr), uint32(n))
	if !ok {
		return nil, false
	}
	out := make([]byte, len(buf))
	copy(out, buf)
	return out, true
}

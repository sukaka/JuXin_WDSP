// democommon P1-01 A1 演示合成业务共享常量与纯函数校验。
// 纪律：
//   - 场景开关（正常/慢 SQL/异常）只存在于本测试业务，默认关闭
//     （DEMO_SCENARIOS_ENABLED 非 "true" 时一律按正常处理，不返回错误）；
//   - 全部输入做有界白名单校验：场景枚举、演示请求 ID 形态、商品 ID 范围；
//     任何外部输入都不会拼进 SQL 或 URL（SQL 为代码内常量，服务 B 地址来自环境变量）。
package democommon

import (
	"regexp"
	"strconv"
)

const (
	// HeaderScenario 场景选择请求头（仅 DEMO_SCENARIOS_ENABLED=true 时生效）。
	HeaderScenario = "X-Demo-Scenario"
	// HeaderDemoRequestID 演示侧请求标识请求头（与网关内部 request_id 无关，
	// 仅用于演示造流与断言对账；网关联调用网关响应头 X-Jiuzhang-Request-ID）。
	HeaderDemoRequestID = "X-Demo-Request-Id"
	// HeaderTraceID 响应头：服务自身 span 的 W3C trace ID（遥测降级时缺省）。
	HeaderTraceID = "X-Demo-Trace-Id"
	// HeaderScenarioApplied 响应头：实际执行的场景（开关关闭时恒为 normal）。
	HeaderScenarioApplied = "X-Demo-Scenario-Applied"

	// ScenarioSlowSQL / ScenarioException 为允许的场景枚举；正常 = 不带场景头。
	ScenarioSlowSQL   = "slow-sql"
	ScenarioException = "exception"
	ScenarioNormal    = "normal"

	// ItemIDMin/Max 演示商品 ID 闭区间（db-init 预置 1..100 行）。
	ItemIDMin = 1
	ItemIDMax = 100
)

var demoRequestIDRe = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9_-]{0,63}$`)

// ScenariosEnabled 场景开关（默认关闭；显式 "true" 才开启）。
func ScenariosEnabled(getenv func(string) string) bool {
	return getenv("DEMO_SCENARIOS_ENABLED") == "true"
}

// TelemetryDisabled 应用遥测关停开关（A4「仅网关观测」场景）：采用 OTel 标准
// 环境变量 OTEL_SDK_DISABLED=true 语义；关闭时业务照常运行但不产生任何 Span，
// 用于如实演示「只有网关侧数据、SQL/代码级不可用」。
func TelemetryDisabled(getenv func(string) string) bool {
	return getenv("OTEL_SDK_DISABLED") == "true"
}

// ParseScenario 解析场景头。开关关闭时忽略任何取值返回 normal；
// 开启时仅接受白名单枚举，未知取值返回 ok=false（调用方回 400，不猜测执行）。
func ParseScenario(enabled bool, header string) (scenario string, ok bool) {
	if !enabled {
		return ScenarioNormal, true
	}
	switch header {
	case "", ScenarioNormal:
		return ScenarioNormal, true
	case ScenarioSlowSQL:
		return ScenarioSlowSQL, true
	case ScenarioException:
		return ScenarioException, true
	default:
		return "", false
	}
}

// ValidDemoRequestID 演示请求 ID 形态校验（1..64 位字母数字-_，首字符字母数字）。
func ValidDemoRequestID(id string) bool {
	return demoRequestIDRe.MatchString(id)
}

// ParseItemID 商品 ID 解析与闭区间校验（1..100；越界 ok=false）。
func ParseItemID(raw string) (int, bool) {
	n, err := strconv.Atoi(raw)
	if err != nil || n < ItemIDMin || n > ItemIDMax {
		return 0, false
	}
	return n, true
}

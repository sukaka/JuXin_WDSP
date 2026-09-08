package middleware

import "net/http"

// EnvironmentHeader 在全部 API 响应上携带环境标识（X-Jiuzhang-Environment，取值 APP_ENV）。
// 独立测试工程的安全门禁（docs/INDEPENDENT_REGRESSION_TEST_AUTOMATION_DESIGN.md §7.1 第 3 层，
// 产品配合项 P-T1）在登录前据此识别目标环境：值为 test 才允许执行，prod/缺失一律终止。
// 该头只暴露部署环境标识（operator 配置的 APP_ENV），不含任何敏感信息。
func EnvironmentHeader(env string) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if env != "" {
				w.Header().Set("X-Jiuzhang-Environment", env)
			}
			next.ServeHTTP(w, r)
		})
	}
}
